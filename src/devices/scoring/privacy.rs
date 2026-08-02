use crate::discovery::ConnectedDevice;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyScore {
    pub score: Option<u8>,
    pub reasons: Vec<String>,
}

pub fn privacy_score(device: &ConnectedDevice) -> PrivacyScore {
    if device.open_ports.is_empty()
        && device.os_fingerprint.is_none()
        && device.vendor.is_none()
        && device.hostname.is_none()
    {
        return PrivacyScore {
            score: None,
            reasons: vec!["insufficient data for network-observable privacy scoring".into()],
        };
    }

    let mut score: i16 = 100;
    let mut reasons = Vec::new();

    for port in &device.open_ports {
        match port.port {
            21 | 23 | 80 | 161 => {
                score -= 18;
                reasons.push(format!(
                    "cleartext or weak management service on port {}: -18",
                    port.port
                ));
            }
            1900 | 5353 => {
                score -= 10;
                reasons.push(format!(
                    "broadcast discovery service on port {}: -10",
                    port.port
                ));
            }
            8080 | 8443 | 3389 | 5900 => {
                score -= 12;
                reasons.push(format!(
                    "remote administration surface on port {}: -12",
                    port.port
                ));
            }
            _ => {}
        }

        let service = port
            .service
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if matches!(service.as_str(), "upnp" | "ssdp" | "mdns") {
            score -= 8;
            reasons.push(format!("chatty discovery service '{}': -8", service));
        }
    }

    if looks_sensitive_class(device) {
        score -= 20;
        reasons.push("sensitive-data-capable device class inferred: -20".into());
    }

    if device
        .vendor
        .as_deref()
        .is_none_or(|vendor| vendor.trim().is_empty())
    {
        score -= 10;
        reasons.push("unknown vendor: -10".into());
    }

    PrivacyScore {
        score: Some(score.clamp(0, 100) as u8),
        reasons,
    }
}

fn looks_sensitive_class(device: &ConnectedDevice) -> bool {
    let haystack = [
        device.vendor.as_deref().unwrap_or_default(),
        device.hostname.as_deref().unwrap_or_default(),
        device.os_fingerprint.as_deref().unwrap_or_default(),
    ]
    .join(" ")
    .to_ascii_lowercase();

    [
        "camera",
        "cam",
        "nas",
        "microphone",
        "voice",
        "alexa",
        "echo",
        "nvr",
    ]
    .iter()
    .any(|needle| haystack.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::{DeviceStatus, OpenPort};

    fn base_device() -> ConnectedDevice {
        ConnectedDevice {
            device_id: "dev-p".into(),
            ip: "192.168.1.30".into(),
            mac: None,
            vendor: Some("Kitchen Camera".into()),
            hostname: Some("cam-1".into()),
            os_fingerprint: Some("embedded".into()),
            os_cpe: Vec::new(),
            open_ports: vec![
                OpenPort {
                    port: 23,
                    protocol: "tcp".into(),
                    service: Some("telnet".into()),
                    product_version: None,
                    cpe: Vec::new(),
                    scripts: Vec::new(),
                },
                OpenPort {
                    port: 1900,
                    protocol: "udp".into(),
                    service: Some("ssdp".into()),
                    product_version: None,
                    cpe: Vec::new(),
                    scripts: Vec::new(),
                },
            ],
            host_scripts: Vec::new(),
            status: DeviceStatus::Unauthorized,
            first_seen: "2026-07-01T00:00:00Z".into(),
            last_seen: "2026-07-01T00:00:00Z".into(),
            vuln_triaged: false,
            last_scan_intensity: None,
        }
    }

    #[test]
    fn privacy_rubric_flags_cleartext_camera_and_chattiness() {
        let score = privacy_score(&base_device());
        assert!(score.score.unwrap() < 60);
        assert!(score
            .reasons
            .iter()
            .any(|reason| reason.contains("cleartext")));
        assert!(score
            .reasons
            .iter()
            .any(|reason| reason.contains("sensitive")));
        assert!(score
            .reasons
            .iter()
            .any(|reason| reason.contains("discovery")));
    }
}
