use crate::devices::scoring::RiskBand;
use crate::discovery::{ConnectedDevice, DeviceStatus};

pub const HIGH_RISK_PORTS: &[u16] = &[
    21, 22, 23, 25, 111, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 8000, 8080, 8443,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoreResult {
    pub score: Option<u8>,
    pub reasons: Vec<String>,
}

pub fn security_score(device: &ConnectedDevice, band: &RiskBand) -> ScoreResult {
    if device.open_ports.is_empty() && device.os_fingerprint.is_none() {
        return ScoreResult {
            score: None,
            reasons: vec!["insufficient data: no open ports or OS fingerprint observed".into()],
        };
    }

    let mut score: i16 = 100;
    let mut reasons = Vec::new();

    match device.status {
        DeviceStatus::Unauthorized => {
            score -= 35;
            reasons.push("unauthorized device: -35".into());
        }
        DeviceStatus::Drifted => {
            score -= 25;
            reasons.push("approved device drifted from whitelist baseline: -25".into());
        }
        DeviceStatus::Stale => {
            score -= 10;
            reasons.push("device stale in inventory: -10".into());
        }
        DeviceStatus::Approved => {}
    }

    for port in &device.open_ports {
        if HIGH_RISK_PORTS.contains(&port.port) {
            score -= 8;
            reasons.push(format!("risky port {} exposed: -8", port.port));
        } else {
            score -= 2;
            reasons.push(format!("open port {} observed: -2", port.port));
        }
    }

    let max_cvss = max_cvss(device);
    if let Some(cvss) = max_cvss {
        let deduction = if cvss >= 9.0 {
            45
        } else if cvss >= 7.0 {
            30
        } else if cvss >= 4.0 {
            15
        } else {
            5
        };
        score -= deduction;
        reasons.push(format!("highest observed CVSS {:.1}: -{}", cvss, deduction));
    }

    if !device.os_cpe.is_empty() {
        score -= 5;
        reasons.push("OS CPE fingerprint exposed: -5".into());
    }

    if band.level == "critical" && max_cvss.unwrap_or_default() >= 9.0 {
        reasons.push("critical band confirmed by vulnerability findings".into());
    }

    ScoreResult {
        score: Some(score.clamp(0, 100) as u8),
        reasons,
    }
}

pub fn bucket_to_risk_level(score: u8, risk_level: &str) -> u8 {
    match risk_level {
        "critical" => score.min(20),
        "high" => score.clamp(21, 50),
        "medium" => score.clamp(51, 75),
        "low" => score.clamp(76, 100),
        _ => score,
    }
}

fn max_cvss(device: &ConnectedDevice) -> Option<f32> {
    device
        .open_ports
        .iter()
        .flat_map(|port| port.scripts.iter())
        .chain(device.host_scripts.iter())
        .filter(|script| script.id == "vulners")
        .flat_map(|script| cvss_values(&script.output))
        .max_by(|left, right| left.total_cmp(right))
}

fn cvss_values(output: &str) -> Vec<f32> {
    output
        .split(|ch: char| ch.is_whitespace() || matches!(ch, ',' | ';' | ')' | '(' | '[' | ']'))
        .filter_map(|token| {
            let trimmed = token.trim_matches(|ch: char| ch == ':' || ch == '=');
            let value = trimmed.parse::<f32>().ok()?;
            if (0.0..=10.0).contains(&value) {
                Some(value)
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::{OpenPort, ScriptResult};

    fn device_with_vuln() -> ConnectedDevice {
        ConnectedDevice {
            device_id: "dev-a".into(),
            ip: "192.168.1.20".into(),
            mac: Some("AA:BB:CC:DD:EE:FF".into()),
            vendor: Some("Acme".into()),
            hostname: Some("lab".into()),
            os_fingerprint: Some("Linux".into()),
            os_cpe: vec!["cpe:/o:linux:linux_kernel:5".into()],
            open_ports: vec![OpenPort {
                port: 22,
                protocol: "tcp".into(),
                service: Some("ssh".into()),
                product_version: Some("OpenSSH".into()),
                cpe: Vec::new(),
                scripts: vec![ScriptResult {
                    id: "vulners".into(),
                    output: "CVE-2023-38408 9.8".into(),
                }],
            }],
            host_scripts: Vec::new(),
            status: DeviceStatus::Unauthorized,
            first_seen: "2026-07-01T00:00:00Z".into(),
            last_seen: "2026-07-01T00:00:00Z".into(),
            vuln_triaged: false,
            last_scan_intensity: Some("aggressive".into()),
        }
    }

    #[test]
    fn cvss_critical_finding_drives_critical_score() {
        let device = device_with_vuln();
        let band = crate::devices::scoring::risk_band(&device);
        let score = security_score(&device, &band);
        assert!(score.score.unwrap() <= 20);
        assert!(score.reasons.iter().any(|reason| reason.contains("9.8")));
    }

    #[test]
    fn no_signals_returns_insufficient_data() {
        let mut device = device_with_vuln();
        device.open_ports.clear();
        device.os_fingerprint = None;
        let band = crate::devices::scoring::risk_band(&device);
        let score = security_score(&device, &band);
        assert_eq!(score.score, None);
        assert!(score.reasons[0].contains("insufficient data"));
    }
}
