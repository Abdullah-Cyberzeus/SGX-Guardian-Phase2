pub mod privacy;
pub mod security;

use crate::devices::model::DeviceScores;
use crate::discovery::ConnectedDevice;
use chrono::Utc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskBand {
    pub level: &'static str,
    pub reasons: Vec<String>,
    pub flagged_ports: Vec<u16>,
}

pub fn risk_band(device: &ConnectedDevice) -> RiskBand {
    let mut reasons: Vec<String> = Vec::new();
    let mut flagged_ports: Vec<u16> = Vec::new();

    let unauthorized = matches!(
        device.status,
        crate::discovery::DeviceStatus::Unauthorized | crate::discovery::DeviceStatus::Drifted
    );
    let has_vulns = device.open_ports.iter().any(|port| {
        port.scripts
            .iter()
            .any(|script| script.id == "vulners" && !script.output.trim().is_empty())
    }) || device
        .host_scripts
        .iter()
        .any(|script| script.id == "vulners" && !script.output.trim().is_empty());
    let risky = device
        .open_ports
        .iter()
        .filter(|port| security::HIGH_RISK_PORTS.contains(&port.port))
        .map(|port| port.port)
        .collect::<Vec<_>>();

    if unauthorized {
        reasons.push("unauthorized device".to_string());
    }
    if has_vulns {
        reasons.push("vulnerability findings detected".to_string());
    }
    if !risky.is_empty() {
        reasons.push(format!(
            "risky ports exposed: {}",
            risky
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
        flagged_ports.extend_from_slice(&risky);
    }

    let level = if unauthorized && has_vulns {
        "critical"
    } else if unauthorized && !risky.is_empty() {
        "high"
    } else if device.open_ports.is_empty() && device.os_fingerprint.is_none() {
        "unknown"
    } else if device.open_ports.is_empty() {
        "low"
    } else if matches!(device.status, crate::discovery::DeviceStatus::Approved)
        && !device.open_ports.is_empty()
    {
        "medium"
    } else {
        "low"
    };

    RiskBand {
        level,
        reasons,
        flagged_ports,
    }
}

pub fn score_device(device: &ConnectedDevice) -> DeviceScores {
    let band = risk_band(device);
    let mut security = security::security_score(device, &band);
    let privacy = privacy::privacy_score(device);
    let bucketed_security = security
        .score
        .map(|score| security::bucket_to_risk_level(score, band.level));

    if bucketed_security != security.score {
        security.reasons.push(format!(
            "security score bucket adjusted to match authoritative risk level '{}'",
            band.level
        ));
    }

    DeviceScores {
        security_score: bucketed_security,
        security_reasons: security.reasons,
        privacy_score: privacy.score,
        privacy_reasons: privacy.reasons,
        privacy_basis: "network-observable".to_string(),
        risk_level: band.level.to_string(),
        computed_at: Utc::now().to_rfc3339(),
    }
}
