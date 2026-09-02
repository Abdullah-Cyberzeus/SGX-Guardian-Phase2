use crate::advisory::errors::AdvisoryResult;
use crate::advisory::model::{
    AnomalyContext, AnomalyContributor, AnomalyDecision, CveFinding, DeviceContext,
};
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

    if let Some(runtime) = anomaly.scoring_runtime.as_ref() {
        let mode = if runtime.fallback {
            "heuristic fallback"
        } else {
            "trained runtime"
        };
        lines.push(format!(
            "Anomaly runtime: {} via {}",
            mode, runtime.scorer_source
        ));
        if let Some(baseline) = runtime.baseline.as_ref() {
            let baseline_mode = match baseline.selection_mode {
                crate::advisory::AnomalyBaselineSelectionMode::Global => "global",
                crate::advisory::AnomalyBaselineSelectionMode::PerNode => "per-node",
            };
            lines.push(format!(
                "Baseline provenance: {} selection from {}",
                baseline_mode, baseline.source
            ));
        }
    }

    for contributor in anomaly_contributors(anomaly).iter().take(5) {
        lines.push(format!(
            "Anomaly: {} contribution {:.2} ({})",
            contributor.feature, contributor.contribution, contributor.reason
        ));
    }

    lines
}

pub fn anomaly_decision(anomaly: Option<&AnomalyContext>) -> Option<AnomalyDecision> {
    let anomaly = anomaly?;
    if let Some(decision) = &anomaly.decision {
        return Some(hydrate_anomaly_decision(decision.clone(), anomaly));
    }

    let normalized_score = normalize_anomaly_score(anomaly.score);
    let thresholds = crate::task1_ai::Task1ThresholdSettings::default_settings();
    let detector = anomaly
        .model_version
        .clone()
        .unwrap_or_else(|| "deterministic local detector".to_string());

    Some(AnomalyDecision {
        detected: normalized_score >= thresholds.detection_threshold,
        score: normalized_score,
        threshold: thresholds.detection_threshold,
        high_threshold: thresholds.high_threshold,
        critical_threshold: thresholds.critical_threshold,
        risk_level: thresholds.risk_level(normalized_score),
        normalized_score,
        confidence: None,
        detector,
        scoring_runtime: anomaly.scoring_runtime.clone(),
        source: anomaly.source.clone(),
        top_signature: anomaly.top_signature.clone(),
        category: anomaly.category.clone(),
        computed_at: anomaly.computed_at,
        window_secs: anomaly.window_secs,
        contributors: anomaly_contributors(anomaly),
    })
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
        "alert_count" => "rolling alert volume",
        "signature_repeat" => "dominant signature repeat rate",
        "burst_density" => "alert burst density",
        "source_score" => "normalized composite score",
        _ => "unusual local signal",
    }
}

fn anomaly_contributors(anomaly: &AnomalyContext) -> Vec<AnomalyContributor> {
    if !anomaly.contributors.is_empty() {
        return anomaly.contributors.clone();
    }

    anomaly
        .topk
        .iter()
        .map(|(feature, contribution)| AnomalyContributor {
            feature: feature.clone(),
            contribution: *contribution,
            reason: feature_hint(feature).to_string(),
        })
        .collect()
}

fn hydrate_anomaly_decision(
    mut decision: AnomalyDecision,
    anomaly: &AnomalyContext,
) -> AnomalyDecision {
    if decision.source.is_none() {
        decision.source = anomaly.source.clone();
    }
    if decision.scoring_runtime.is_none() {
        decision.scoring_runtime = anomaly.scoring_runtime.clone();
    }
    if decision.top_signature.is_none() {
        decision.top_signature = anomaly.top_signature.clone();
    }
    if decision.category.is_none() {
        decision.category = anomaly.category.clone();
    }
    if decision.computed_at.is_none() {
        decision.computed_at = anomaly.computed_at;
    }
    if decision.window_secs.is_none() {
        decision.window_secs = anomaly.window_secs;
    }
    if decision.contributors.is_empty() {
        decision.contributors = anomaly_contributors(anomaly);
    }
    decision
}

fn device_label(device: &DeviceContext) -> String {
    match (device.hostname.as_deref(), device.vendor.as_deref()) {
        (Some(hostname), Some(vendor)) => format!("{} ({}, {})", device.ip, hostname, vendor),
        (Some(hostname), None) => format!("{} ({})", device.ip, hostname),
        (None, Some(vendor)) => format!("{} ({})", device.ip, vendor),
        (None, None) => device.ip.clone(),
    }
}

#[cfg(test)]
mod tests {
    use crate::advisory::{AnomalySource, AnomalyTopSignature};

    use super::*;
    use crate::discovery::connected_device::{
        ConnectedDevice, DeviceStatus, OpenPort, ScriptResult,
    };
    use chrono::TimeZone;

    #[test]
    fn normalize_anomaly_score_scales_and_clamps() {
        assert_eq!(normalize_anomaly_score(145.0), 1.0);
        assert_eq!(normalize_anomaly_score(0.72), 0.72);
        assert_eq!(normalize_anomaly_score(-0.25), 0.0);
    }

    #[test]
    fn anomaly_context_lines_limit_to_five_entries_and_use_default_model_name() {
        assert!(anomaly_context_lines(None).is_empty());

        let anomaly = AnomalyContext {
            score: 145.0,
            topk: vec![
                ("flow_rate".into(), 0.91),
                ("cmd_entropy".into(), 0.82),
                ("peer_diversity".into(), 0.73),
                ("attest_jitter".into(), 0.64),
                ("modbus_fc_mix".into(), 0.55),
                ("mystery_signal".into(), 0.44),
            ],
            model_version: None,
            scoring_runtime: None,
            source: Some(AnomalySource {
                ip: "203.0.113.10".into(),
                alert_count: 8,
            }),
            top_signature: Some(AnomalyTopSignature {
                id: 9100001,
                count: 5,
            }),
            category: Some("anomaly".into()),
            computed_at: None,
            window_secs: Some(300),
            contributors: Vec::new(),
            decision: None,
        };

        let lines = anomaly_context_lines(Some(&anomaly));

        assert_eq!(lines.len(), 6);
        assert_eq!(lines[0], "Anomaly score 1.00: deterministic local detector");
        assert!(lines[1].contains("flow_rate contribution 0.91 (traffic spike)"));
        assert!(
            lines[5].contains("modbus_fc_mix contribution 0.55 (unusual Modbus function-code mix)")
        );
        assert!(lines.iter().all(|line| !line.contains("mystery_signal")));
    }

    #[test]
    fn anomaly_decision_falls_back_to_context_fields() {
        let anomaly = AnomalyContext {
            score: 0.72,
            topk: vec![("flow_rate".into(), 0.42)],
            model_version: Some("fallback-model".into()),
            scoring_runtime: None,
            source: Some(AnomalySource {
                ip: "192.168.1.9".into(),
                alert_count: 6,
            }),
            top_signature: Some(AnomalyTopSignature { id: 2201, count: 4 }),
            category: Some("exploit".into()),
            computed_at: Some(
                chrono::Utc
                    .with_ymd_and_hms(2026, 8, 28, 9, 30, 0)
                    .single()
                    .expect("fixed timestamp"),
            ),
            window_secs: Some(120),
            contributors: Vec::new(),
            decision: None,
        };

        let decision = anomaly_decision(Some(&anomaly)).expect("decision");

        assert!(decision.detected);
        assert_eq!(decision.detector, "fallback-model");
        assert_eq!(
            decision.threshold,
            crate::task1_ai::DEFAULT_DETECTION_THRESHOLD
        );
        assert_eq!(decision.contributors.len(), 1);
        assert_eq!(decision.contributors[0].feature, "flow_rate");
        assert_eq!(
            decision.source,
            Some(AnomalySource {
                ip: "192.168.1.9".into(),
                alert_count: 6
            })
        );
        assert_eq!(
            decision.top_signature,
            Some(AnomalyTopSignature { id: 2201, count: 4 })
        );
    }

    #[test]
    fn device_context_lines_format_variants_and_truncate_lists() {
        assert!(device_context_lines(None).is_empty());

        let both = DeviceContext {
            ip: "10.0.0.1".into(),
            hostname: Some("edge".into()),
            vendor: Some("Acme".into()),
            risk_reasons: vec![
                "reason-0".into(),
                "reason-1".into(),
                "reason-2".into(),
                "reason-3".into(),
                "reason-4".into(),
                "reason-5".into(),
            ],
            cves: vec![
                CveFinding {
                    cve: "CVE-2024-0001".into(),
                    cvss: Some(9.8),
                },
                CveFinding {
                    cve: "CVE-2024-0002".into(),
                    cvss: None,
                },
                CveFinding {
                    cve: "CVE-2024-0003".into(),
                    cvss: Some(7.1),
                },
                CveFinding {
                    cve: "CVE-2024-0004".into(),
                    cvss: Some(6.1),
                },
                CveFinding {
                    cve: "CVE-2024-0005".into(),
                    cvss: Some(5.1),
                },
                CveFinding {
                    cve: "CVE-2024-0006".into(),
                    cvss: Some(4.1),
                },
            ],
        };

        let lines = device_context_lines(Some(&both));

        assert_eq!(lines[0], "Device context: 10.0.0.1 (edge, Acme)");
        assert_eq!(lines.len(), 11);
        assert_eq!(lines[1], "reason-0");
        assert_eq!(lines[5], "reason-4");
        assert_eq!(lines[6], "Device has CVE-2024-0001 (CVSS 9.8)");
        assert_eq!(lines[7], "Device has CVE-2024-0002");
        assert_eq!(lines[10], "Device has CVE-2024-0005 (CVSS 5.1)");

        let hostname_only = DeviceContext {
            ip: "10.0.0.2".into(),
            hostname: Some("edge".into()),
            vendor: None,
            risk_reasons: vec![],
            cves: vec![],
        };
        assert_eq!(
            device_context_lines(Some(&hostname_only))[0],
            "Device context: 10.0.0.2 (edge)"
        );

        let vendor_only = DeviceContext {
            ip: "10.0.0.3".into(),
            hostname: None,
            vendor: Some("Acme".into()),
            risk_reasons: vec![],
            cves: vec![],
        };
        assert_eq!(
            device_context_lines(Some(&vendor_only))[0],
            "Device context: 10.0.0.3 (Acme)"
        );

        let bare = DeviceContext {
            ip: "10.0.0.4".into(),
            hostname: None,
            vendor: None,
            risk_reasons: vec![],
            cves: vec![],
        };
        assert_eq!(
            device_context_lines(Some(&bare))[0],
            "Device context: 10.0.0.4"
        );
    }

    #[test]
    fn device_context_from_connected_device_extracts_risks_and_dedups_cves() {
        let device = ConnectedDevice {
            device_id: "device-1".into(),
            ip: "10.0.0.9".into(),
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            vendor: Some("Acme".into()),
            hostname: Some("edge".into()),
            os_fingerprint: Some("Linux 5.x".into()),
            os_cpe: vec![],
            open_ports: vec![
                OpenPort {
                    port: 80,
                    protocol: "tcp".into(),
                    service: None,
                    product_version: None,
                    cpe: vec![],
                    scripts: vec![ScriptResult {
                        id: "http-title".into(),
                        output: "banner CVE-2024-1000 9.8".into(),
                    }],
                },
                OpenPort {
                    port: 22,
                    protocol: "tcp".into(),
                    service: None,
                    product_version: None,
                    cpe: vec![],
                    scripts: vec![ScriptResult {
                        id: "ssh-banner".into(),
                        output: "CVE-2023-2222 5.4 CVE-2024-1000 7.7".into(),
                    }],
                },
            ],
            host_scripts: vec![ScriptResult {
                id: "host-vuln".into(),
                output: "CVE-2024-1000 9.8".into(),
            }],
            status: DeviceStatus::Unauthorized,
            first_seen: "2026-08-24T12:00:00Z".into(),
            last_seen: "2026-08-24T12:05:00Z".into(),
            vuln_triaged: false,
            last_scan_intensity: None,
        };

        let context = device_context_from_connected_device(device);

        assert_eq!(context.ip, "10.0.0.9");
        assert_eq!(context.hostname.as_deref(), Some("edge"));
        assert_eq!(context.vendor.as_deref(), Some("Acme"));
        assert_eq!(
            context.risk_reasons,
            vec![
                "Open ports observed: 22/tcp, 80/tcp".to_string(),
                "Device status is Unauthorized".to_string(),
                "OS fingerprint: Linux 5.x".to_string(),
            ]
        );
        assert_eq!(context.cves.len(), 2);
        assert_eq!(context.cves[0].cve, "CVE-2023-2222");
        assert_eq!(context.cves[0].cvss, Some(5.4));
        assert_eq!(context.cves[1].cve, "CVE-2024-1000");
        assert_eq!(context.cves[1].cvss, Some(9.8));
    }

    #[test]
    fn cve_references_limit_to_ten_entries_and_format_links() {
        let device = DeviceContext {
            ip: "10.0.0.99".into(),
            hostname: None,
            vendor: None,
            risk_reasons: vec![],
            cves: (0..12)
                .map(|idx| CveFinding {
                    cve: format!("CVE-2024-{:04}", idx),
                    cvss: Some(7.0),
                })
                .collect(),
        };

        let references = cve_references(Some(&device));

        assert_eq!(references.len(), 10);
        assert_eq!(
            references[0],
            "https://nvd.nist.gov/vuln/detail/CVE-2024-0000"
        );
        assert_eq!(
            references[9],
            "https://nvd.nist.gov/vuln/detail/CVE-2024-0009"
        );
        assert!(cve_references(None).is_empty());
    }
}
