use chrono::Utc;
use sgx_guardian_client::advisory::generate::generate;
use sgx_guardian_client::advisory::kb::RecommendationRules;
use sgx_guardian_client::advisory::model::{
    AnomalyContext, CveFinding, DeviceContext, RemediationRecommendation,
};
use sgx_guardian_client::threat::threat_alert::{Severity, ThreatAlert, ThreatCategory};

fn sample_alert(
    category: ThreatCategory,
    severity: Severity,
    sig: &str,
    sid: u32,
) -> ThreatAlert {
    ThreatAlert {
        alert_id: ThreatAlert::compute_id(sid, "192.168.1.50", "10.0.0.1"),
        timestamp: Utc::now(),
        src_ip: "192.168.1.50".into(),
        src_port: 49152,
        dst_ip: "10.0.0.1".into(),
        dst_port: 443,
        protocol: "TCP".into(),
        signature_id: sid,
        signature: sig.into(),
        category,
        severity,
        rev: 1,
        gid: 1,
        event_type: "alert".into(),
        blocked: false,
    }
}

#[test]
fn test_advisory_generation_malware_rule_match() {
    let kb = RecommendationRules::default_rules();
    let alert = sample_alert(
        ThreatCategory::Malware,
        Severity::High,
        "ET MALWARE Suspicious C2 Domain",
        2001001,
    );

    let rec = generate(&alert, None, None, &kb);

    assert_eq!(rec.source, "signature-kb");
    assert!(rec.title.contains("malware"));
    assert_eq!(rec.steps.len(), 3);
    assert!(rec.steps[0].automatable);
    assert_eq!(rec.steps[0].order, 1);
    assert!(rec.references.contains(&"suricata:sid:2001001".to_string()));
}

#[test]
fn test_advisory_generation_with_device_cves() {
    let kb = RecommendationRules::default_rules();
    let alert = sample_alert(
        ThreatCategory::Exploit,
        Severity::Medium,
        "ET EXPLOIT Apache Struts Remote Code Execution",
        2002002,
    );

    let device_ctx = DeviceContext {
        ip: "192.168.1.50".into(),
        hostname: Some("web-server-01".into()),
        vendor: Some("Apache".into()),
        risk_reasons: vec!["unpatched CVEs".into()],
        cves: vec![CveFinding {
            cve: "CVE-2023-12345".into(),
            cvss: Some(9.8),
        }],
    };

    let rec = generate(&alert, None, Some(&device_ctx), &kb);

    assert_eq!(rec.source, "signature-kb");
    assert!(rec.title.contains("exploit"));
    assert!(rec
        .references
        .contains(&"https://nvd.nist.gov/vuln/detail/CVE-2023-12345".to_string()));
    assert!(rec.context.iter().any(|c| c.contains("web-server-01")));
}

#[test]
fn test_advisory_generation_fallback_and_anomaly() {
    let kb = RecommendationRules::default_rules();

    // Alert with no matching category in rules
    let alert = sample_alert(
        ThreatCategory::Other,
        Severity::Low,
        "GENERIC Protocol Anomaly Detected",
        2003003,
    );

    // Fallback without anomaly
    let rec_fallback = generate(&alert, None, None, &kb);
    assert_eq!(rec_fallback.source, "fallback");
    assert_eq!(rec_fallback.title, kb.fallback.title);

    // Fallback with anomaly score
    let anomaly_ctx = AnomalyContext {
        score: 0.85,
        topk: vec![("port_scan".into(), 0.75)],
        model_version: Some("v2.1".into()),
    };

    let rec_anomaly = generate(&alert, Some(&anomaly_ctx), None, &kb);
    assert_eq!(rec_anomaly.source, "anomaly-kb");
    assert!(rec_anomaly.context.iter().any(|c| c.contains("0.85")));
}

#[test]
fn test_remediation_recommendation_serde_roundtrip() {
    let kb = RecommendationRules::default_rules();
    let alert = sample_alert(
        ThreatCategory::Reconnaissance,
        Severity::Low,
        "ET SCAN Nmap Scripting Engine Traffic",
        2004004,
    );

    let rec = generate(&alert, None, None, &kb);
    let serialized = serde_json::to_string(&rec).expect("serialize recommendation");
    let deserialized: RemediationRecommendation =
        serde_json::from_str(&serialized).expect("deserialize recommendation");

    assert_eq!(deserialized.rec_id, rec.rec_id);
    assert_eq!(deserialized.alert_id, rec.alert_id);
    assert_eq!(deserialized.steps.len(), rec.steps.len());
    assert_eq!(deserialized.source, "signature-kb");
}
