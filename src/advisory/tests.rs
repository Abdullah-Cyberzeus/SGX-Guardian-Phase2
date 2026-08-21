use super::*;
use crate::advisory::context::device_context_from_connected_device;
use crate::advisory::generate::generate;
use crate::advisory::kb::RecommendationRules;
use crate::discovery::connected_device::{ConnectedDevice, DeviceStatus, OpenPort, ScriptResult};
use crate::threat::threat_alert::{Severity, ThreatAlert, ThreatCategory};
use chrono::Utc;

fn alert(category: ThreatCategory, severity: Severity) -> ThreatAlert {
    ThreatAlert {
        alert_id: "alert-1".into(),
        timestamp: Utc::now(),
        src_ip: "192.168.50.10".into(),
        src_port: 51514,
        dst_ip: "192.168.50.20".into(),
        dst_port: 443,
        protocol: "TCP".into(),
        signature_id: 2024001,
        signature: "ET MALWARE Possible C2 Checkin".into(),
        category,
        severity,
        rev: 1,
        gid: 1,
        event_type: "alert".into(),
        blocked: false,
    }
}

#[test]
fn matched_rule_generates_recommendation() {
    let rules = RecommendationRules::default_rules();
    let rec = generate(
        &alert(ThreatCategory::Malware, Severity::High),
        None,
        None,
        &rules,
    );

    assert_eq!(rec.source, "signature-kb");
    assert_eq!(rec.severity, "high");
    assert!(rec.title.contains("malware"));
    assert!(!rec.steps.is_empty());
    assert!(rec.context.iter().any(|line| line.contains("Signature:")));
}

#[test]
fn fallback_generates_recommendation_for_every_alert() {
    let rules = RecommendationRules::default_rules();
    let rec = generate(
        &alert(ThreatCategory::Other, Severity::Info),
        None,
        None,
        &rules,
    );

    assert_eq!(rec.source, "fallback");
    assert_eq!(rec.title, rules.fallback.title);
    assert!(!rec.steps.is_empty());
}

#[test]
fn anomaly_topk_and_device_cves_enrich_context() {
    let rules = RecommendationRules::default_rules();
    let anomaly = AnomalyContext {
        score: 0.8,
        topk: vec![("flow_rate".into(), 0.42), ("cmd_entropy".into(), 0.31)],
        model_version: Some("test-model".into()),
    };
    let device = device_context_from_connected_device(ConnectedDevice {
        device_id: "dev-1".into(),
        ip: "192.168.50.20".into(),
        mac: None,
        vendor: Some("Acme".into()),
        hostname: Some("plc-1".into()),
        os_fingerprint: Some("Linux 5.x".into()),
        os_cpe: Vec::new(),
        open_ports: vec![OpenPort {
            port: 22,
            protocol: "tcp".into(),
            service: Some("ssh".into()),
            product_version: None,
            cpe: Vec::new(),
            scripts: vec![ScriptResult {
                id: "vulners".into(),
                output: "CVE-2023-38408 9.8".into(),
            }],
        }],
        host_scripts: Vec::new(),
        status: DeviceStatus::Drifted,
        first_seen: "2026-01-01T00:00:00Z".into(),
        last_seen: "2026-01-01T00:00:00Z".into(),
        vuln_triaged: false,
        last_scan_intensity: Some("aggressive".into()),
    });

    let rec = generate(
        &alert(ThreatCategory::Malware, Severity::Critical),
        Some(&anomaly),
        Some(&device),
        &rules,
    );

    assert!(rec
        .context
        .iter()
        .any(|line| line.contains("flow_rate contribution 0.42")));
    assert!(rec
        .context
        .iter()
        .any(|line| line.contains("CVE-2023-38408 (CVSS 9.8)")));
    assert!(rec
        .references
        .iter()
        .any(|reference| reference.ends_with("CVE-2023-38408")));
    assert!(rec.confidence > 0.8);
}

#[test]
fn missing_rules_file_is_seeded_with_defaults() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("advisory/recommendation_rules.json");

    assert!(!path.exists());

    let seeded = RecommendationRules::seed_default_if_missing(&path).expect("seed rules");
    assert!(seeded);
    assert!(path.exists());

    let loaded = RecommendationRules::load_verified(&path).expect("load seeded rules");
    assert_eq!(loaded, RecommendationRules::default_rules());

    let seeded_again = RecommendationRules::seed_default_if_missing(&path).expect("seed rules");
    assert!(!seeded_again);
}
