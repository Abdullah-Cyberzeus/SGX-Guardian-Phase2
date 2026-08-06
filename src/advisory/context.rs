use crate::advisory::errors::AdvisoryResult;
use crate::advisory::model::{AnomalyContext, CveFinding, DeviceContext};
use crate::discovery::connected_device::{ConnectedDevice, ScriptResult};
use std::path::Path;

pub fn anomaly_context_lines(anomaly: Option<&AnomalyContext>) -> Vec<String> {
    let Some(anomaly) = anomaly else {
        return Vec::new();
    };

    let mut lines = vec![format!(
        "Anomaly score {:.2}: {}",
        normalize_anomaly_score(anomaly.score),
        anomaly
            .model_version
            .as_deref()
            .unwrap_or("deterministic local detector")
    )];

    for (feature, contribution) in anomaly.topk.iter().take(5) {
        lines.push(format!(
            "Anomaly: {} contribution {:.2} ({})",
            feature,
            contribution,
            feature_hint(feature)
        ));
    }

    lines
}

pub fn device_context_lines(device: Option<&DeviceContext>) -> Vec<String> {
    let Some(device) = device else {
        return Vec::new();
    };

    let mut lines = vec![format!("Device context: {}", device_label(device))];
    lines.extend(device.risk_reasons.iter().take(5).cloned());
    for finding in device.cves.iter().take(5) {
        match finding.cvss {
            Some(cvss) => lines.push(format!("Device has {} (CVSS {:.1})", finding.cve, cvss)),
            None => lines.push(format!("Device has {}", finding.cve)),
        }
    }
    lines
}

pub fn cve_references(device: Option<&DeviceContext>) -> Vec<String> {
    device
        .into_iter()
        .flat_map(|device| device.cves.iter())
        .take(10)
        .map(|finding| format!("https://nvd.nist.gov/vuln/detail/{}", finding.cve))
        .collect()
}

pub fn normalize_anomaly_score(score: f32) -> f32 {
    if score > 1.0 {
        (score / 100.0).clamp(0.0, 1.0)
    } else {
        score.clamp(0.0, 1.0)
    }
}

pub fn load_device_context_for_alert_ip(
    inventory_path: &Path,
    src_ip: &str,
    dst_ip: &str,
) -> AdvisoryResult<Option<DeviceContext>> {
    if !inventory_path.exists() {
        return Ok(None);
    }

    let bytes = std::fs::read(inventory_path)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    let devices: Vec<ConnectedDevice> = serde_json::from_slice(&bytes)?;
    Ok(devices
        .into_iter()
        .find(|device| device.ip == src_ip || device.ip == dst_ip)
        .map(device_context_from_connected_device))
}

pub fn device_context_from_connected_device(device: ConnectedDevice) -> DeviceContext {
    let mut risk_reasons = Vec::new();
    if !device.open_ports.is_empty() {
        let mut ports: Vec<String> = device
            .open_ports
            .iter()
            .take(8)
            .map(|port| format!("{}/{}", port.port, port.protocol))
            .collect();
        ports.sort();
        risk_reasons.push(format!("Open ports observed: {}", ports.join(", ")));
    }
    if device.status != crate::discovery::connected_device::DeviceStatus::Approved {
        risk_reasons.push(format!("Device status is {:?}", device.status));
    }
    if let Some(os) = device.os_fingerprint.as_deref() {
        risk_reasons.push(format!("OS fingerprint: {}", os));
    }

    let mut cves = Vec::new();
    for script in device.host_scripts.iter().chain(
        device
            .open_ports
            .iter()
            .flat_map(|port| port.scripts.iter()),
    ) {
        cves.extend(cves_from_script(script));
    }
    cves.sort_by(|a, b| a.cve.cmp(&b.cve));
    cves.dedup_by(|a, b| a.cve == b.cve);

    DeviceContext {
        ip: device.ip,
        hostname: device.hostname,
        vendor: device.vendor,
        risk_reasons,
        cves,
    }
}

fn cves_from_script(script: &ScriptResult) -> Vec<CveFinding> {
    script
        .output
        .split_whitespace()
        .enumerate()
        .filter_map(|(idx, token)| {
            let cve = token
                .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-')
                .to_ascii_uppercase();
            if !is_cve(&cve) {
                return None;
            }
            let cvss = script
                .output
                .split_whitespace()
                .skip(idx + 1)
                .take(4)
                .find_map(|value| {
                    value
                        .trim_matches(|c: char| !c.is_ascii_digit() && c != '.')
                        .parse::<f32>()
                        .ok()
                        .filter(|score| (0.0..=10.0).contains(score))
                });
            Some(CveFinding { cve, cvss })
        })
        .collect()
}

fn is_cve(value: &str) -> bool {
    let mut parts = value.split('-');
    matches!(parts.next(), Some("CVE"))
        && parts
            .next()
            .is_some_and(|year| year.len() == 4 && year.chars().all(|c| c.is_ascii_digit()))
        && parts
            .next()
            .is_some_and(|id| id.len() >= 4 && id.chars().all(|c| c.is_ascii_digit()))
}

fn feature_hint(feature: &str) -> &'static str {
    match feature {
        "flow_rate" => "traffic spike",
        "cmd_entropy" => "unusual command mix",
        "peer_diversity" => "unusual peer spread",
        "attest_jitter" => "attestation timing drift",
        "modbus_fc_mix" => "unusual Modbus function-code mix",
        _ => "unusual local signal",
    }
}

fn device_label(device: &DeviceContext) -> String {
    match (device.hostname.as_deref(), device.vendor.as_deref()) {
        (Some(hostname), Some(vendor)) => format!("{} ({}, {})", device.ip, hostname, vendor),
        (Some(hostname), None) => format!("{} ({})", device.ip, hostname),
        (None, Some(vendor)) => format!("{} ({})", device.ip, vendor),
        (None, None) => device.ip.clone(),
    }
}
