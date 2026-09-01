use sgx_guardian_client::advisory::context::{
    anomaly_context_lines, cve_references, device_context_from_connected_device,
    device_context_lines, load_device_context_for_alert_ip, normalize_anomaly_score,
};
use sgx_guardian_client::advisory::model::{AnomalyContext, CveFinding, DeviceContext};
use sgx_guardian_client::discovery::connected_device::{
    ConnectedDevice, DeviceStatus, OpenPort, ScriptResult,
};

fn device(status: DeviceStatus) -> ConnectedDevice {
    ConnectedDevice {
        device_id: "dev-1".into(),
        ip: "10.0.0.10".into(),
        mac: Some("aa:bb:cc:dd:ee:ff".into()),
        vendor: Some("Acme".into()),
        hostname: Some("plc-1".into()),
        os_fingerprint: Some("Linux".into()),
        os_cpe: vec![],
        open_ports: vec![OpenPort {
            port: 22,
            protocol: "tcp".into(),
            service: Some("ssh".into()),
            product_version: None,
            cpe: vec![],
            scripts: vec![ScriptResult {
                id: "vulners".into(),
                output: "CVE-2024-1111 score 9.8 duplicate CVE-2024-1111 CVE-2024-2222 5.5".into(),
            }],
        }],
        host_scripts: vec![ScriptResult {
            id: "host-vuln".into(),
            output: "(CVE-2023-9999) cvss: 7.2".into(),
        }],
        status,
        first_seen: "2026-01-01T00:00:00Z".into(),
        last_seen: "2026-01-01T00:00:00Z".into(),
        vuln_triaged: false,
        last_scan_intensity: Some("aggressive".into()),
    }
}

fn ctx() -> DeviceContext {
    DeviceContext {
        ip: "10.0.0.20".into(),
        hostname: Some("host".into()),
        vendor: Some("vendor".into()),
        risk_reasons: (0..7).map(|idx| format!("risk-{idx}")).collect(),
        cves: (0..7)
            .map(|idx| CveFinding {
                cve: format!("CVE-2026-{idx:04}"),
                cvss: if idx % 2 == 0 { Some(5.0 + idx as f32) } else { None },
            })
            .collect(),
    }
}

#[test]
fn normalize_negative_score_to_zero() {
    assert_eq!(normalize_anomaly_score(-0.1), 0.0);
}

#[test]
fn normalize_zero_score_stays_zero() {
    assert_eq!(normalize_anomaly_score(0.0), 0.0);
}

#[test]
fn normalize_fraction_score_stays_fraction() {
    assert_eq!(normalize_anomaly_score(0.45), 0.45);
}

#[test]
fn normalize_one_score_stays_one() {
    assert_eq!(normalize_anomaly_score(1.0), 1.0);
}

#[test]
fn normalize_percent_score_is_scaled() {
    assert_eq!(normalize_anomaly_score(75.0), 0.75);
}

#[test]
fn normalize_large_percent_score_is_clamped() {
    assert_eq!(normalize_anomaly_score(250.0), 1.0);
}

#[test]
fn anomaly_lines_none_is_empty() {
    assert!(anomaly_context_lines(None).is_empty());
}

#[test]
fn anomaly_lines_use_default_model_label() {
    let lines = anomaly_context_lines(Some(&AnomalyContext {
        score: 0.4,
        topk: vec![],
        model_version: None,
    }));
    assert_eq!(lines[0], "Anomaly score 0.40: deterministic local detector");
}

#[test]
fn anomaly_lines_use_model_version() {
    let lines = anomaly_context_lines(Some(&AnomalyContext {
        score: 80.0,
        topk: vec![],
        model_version: Some("model-a".into()),
    }));
    assert_eq!(lines[0], "Anomaly score 0.80: model-a");
}

#[test]
fn anomaly_lines_include_known_feature_hint() {
    let lines = anomaly_context_lines(Some(&AnomalyContext {
        score: 0.1,
        topk: vec![("flow_rate".into(), 0.9)],
        model_version: None,
    }));
    assert!(lines[1].contains("traffic spike"));
}

#[test]
fn anomaly_lines_include_unknown_feature_hint() {
    let lines = anomaly_context_lines(Some(&AnomalyContext {
        score: 0.1,
        topk: vec![("custom".into(), 0.9)],
        model_version: None,
    }));
    assert!(lines[1].contains("unusual local signal"));
}

#[test]
fn anomaly_lines_limit_topk_to_five() {
    let lines = anomaly_context_lines(Some(&AnomalyContext {
        score: 0.1,
        topk: (0..8).map(|idx| (format!("f{idx}"), idx as f32)).collect(),
        model_version: None,
    }));
    assert_eq!(lines.len(), 6);
}

#[test]
fn device_lines_none_is_empty() {
    assert!(device_context_lines(None).is_empty());
}

#[test]
fn device_lines_label_includes_ip_hostname_and_vendor() {
    let lines = device_context_lines(Some(&ctx()));
    assert_eq!(lines[0], "Device context: 10.0.0.20 (host, vendor)");
}

#[test]
fn device_lines_label_handles_hostname_only() {
    let device = DeviceContext {
        vendor: None,
        ..ctx()
    };
    assert_eq!(device_context_lines(Some(&device))[0], "Device context: 10.0.0.20 (host)");
}

#[test]
fn device_lines_label_handles_vendor_only() {
    let device = DeviceContext {
        hostname: None,
        ..ctx()
    };
    assert_eq!(device_context_lines(Some(&device))[0], "Device context: 10.0.0.20 (vendor)");
}

#[test]
fn device_lines_label_handles_ip_only() {
    let device = DeviceContext {
        hostname: None,
        vendor: None,
        ..ctx()
    };
    assert_eq!(device_context_lines(Some(&device))[0], "Device context: 10.0.0.20");
}

#[test]
fn device_lines_limit_risk_reasons_and_cves() {
    let lines = device_context_lines(Some(&ctx()));
    assert_eq!(lines.iter().filter(|line| line.starts_with("risk-")).count(), 5);
    assert_eq!(lines.iter().filter(|line| line.contains("CVE-")).count(), 5);
}

#[test]
fn device_lines_format_cvss_when_present() {
    assert!(device_context_lines(Some(&ctx()))
        .iter()
        .any(|line| line.contains("CVSS 5.0")));
}

#[test]
fn cve_references_none_is_empty() {
    assert!(cve_references(None).is_empty());
}

#[test]
fn cve_references_limit_to_ten() {
    let device = DeviceContext {
        cves: (0..12)
            .map(|idx| CveFinding {
                cve: format!("CVE-2026-{idx:04}"),
                cvss: None,
            })
            .collect(),
        ..ctx()
    };
    assert_eq!(cve_references(Some(&device)).len(), 10);
}

#[test]
fn connected_device_conversion_extracts_risk_reasons() {
    let converted = device_context_from_connected_device(device(DeviceStatus::Drifted));
    assert!(converted.risk_reasons.iter().any(|line| line.contains("Open ports")));
    assert!(converted.risk_reasons.iter().any(|line| line.contains("Drifted")));
    assert!(converted.risk_reasons.iter().any(|line| line.contains("Linux")));
}

#[test]
fn connected_device_conversion_deduplicates_and_sorts_cves() {
    let converted = device_context_from_connected_device(device(DeviceStatus::Approved));
    let cves: Vec<_> = converted.cves.iter().map(|finding| finding.cve.as_str()).collect();
    assert_eq!(cves, vec!["CVE-2023-9999", "CVE-2024-1111", "CVE-2024-2222"]);
}

#[test]
fn connected_device_conversion_ignores_invalid_cve_tokens() {
    let mut input = device(DeviceStatus::Approved);
    input.host_scripts = vec![ScriptResult {
        id: "bad".into(),
        output: "CVE-20-1 CVE-2026-ABC CVE-2026-123".into(),
    }];
    input.open_ports.clear();
    assert!(device_context_from_connected_device(input).cves.is_empty());
}

#[test]
fn load_device_context_missing_file_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let loaded = load_device_context_for_alert_ip(&dir.path().join("missing.json"), "a", "b").unwrap();
    assert!(loaded.is_none());
}

#[test]
fn load_device_context_empty_file_returns_none() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let loaded = load_device_context_for_alert_ip(file.path(), "a", "b").unwrap();
    assert!(loaded.is_none());
}

#[test]
fn load_device_context_malformed_file_errors() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), b"not-json").unwrap();
    assert!(load_device_context_for_alert_ip(file.path(), "a", "b").is_err());
}

#[test]
fn load_device_context_matches_src_or_dst_ip() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), serde_json::to_vec(&vec![device(DeviceStatus::Approved)]).unwrap())
        .unwrap();
    assert!(load_device_context_for_alert_ip(file.path(), "10.0.0.10", "x")
        .unwrap()
        .is_some());
    assert!(load_device_context_for_alert_ip(file.path(), "x", "10.0.0.10")
        .unwrap()
        .is_some());
}
