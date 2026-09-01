use chrono::{TimeZone, Utc};
use sgx_guardian_client::advisory::generate::generate;
use sgx_guardian_client::advisory::kb::{
    RecommendationRule, RecommendationRules, RecommendationTemplate, RuleMatch, RuleStep,
};
use sgx_guardian_client::advisory::model::{AnomalyContext, CveFinding, DeviceContext};
use sgx_guardian_client::threat::threat_alert::{Severity, ThreatAlert, ThreatCategory};

fn alert(category: ThreatCategory, severity: Severity) -> ThreatAlert {
    ThreatAlert {
        alert_id: format!("alert-{}-{}", category.as_str(), severity.as_str()),
        timestamp: Utc.with_ymd_and_hms(2026, 2, 3, 4, 5, 6).unwrap(),
        src_ip: "10.0.0.1".into(),
        src_port: 1234,
        dst_ip: "10.0.0.2".into(),
        dst_port: 443,
        protocol: "TCP".into(),
        signature_id: 4242,
        signature: "ET MALWARE C2 beacon".into(),
        category,
        severity,
        rev: 1,
        gid: 1,
        event_type: "alert".into(),
        blocked: false,
    }
}

fn rules() -> RecommendationRules {
    RecommendationRules {
        rules: vec![RecommendationRule {
            rule_match: RuleMatch {
                category: Some("malware".into()),
                signature_contains: Some("C2".into()),
                severity_at_least: Some("medium".into()),
            },
            title: "matched title".into(),
            summary: "matched summary".into(),
            steps: vec![RuleStep {
                action: "matched action".into(),
                rationale: "matched rationale".into(),
                automatable: true,
            }],
            references: vec!["signature".into(), "signature".into()],
        }],
        fallback: RecommendationTemplate {
            title: "fallback title".into(),
            summary: "fallback summary".into(),
            steps: vec![RuleStep {
                action: "fallback action".into(),
                rationale: "fallback rationale".into(),
                automatable: false,
            }],
            references: vec!["fallback".into()],
        },
        signature_sha256: None,
    }
}

fn anomaly(score: f32) -> AnomalyContext {
    AnomalyContext {
        score,
        topk: vec![("flow_rate".into(), 0.3)],
        model_version: Some("detector-v1".into()),
    }
}

fn device() -> DeviceContext {
    DeviceContext {
        ip: "10.0.0.2".into(),
        hostname: Some("dst".into()),
        vendor: Some("vendor".into()),
        risk_reasons: vec!["risk".into()],
        cves: vec![
            CveFinding {
                cve: "CVE-2026-0002".into(),
                cvss: Some(8.0),
            },
            CveFinding {
                cve: "CVE-2026-0001".into(),
                cvss: None,
            },
        ],
    }
}

#[test]
fn matched_rule_uses_signature_kb_source() {
    assert_eq!(
        generate(&alert(ThreatCategory::Malware, Severity::High), None, None, &rules()).source,
        "signature-kb"
    );
}

#[test]
fn matched_rule_uses_rule_title_summary_and_step() {
    let rec = generate(&alert(ThreatCategory::Malware, Severity::High), None, None, &rules());
    assert_eq!(rec.title, "matched title");
    assert_eq!(rec.summary, "matched summary");
    assert_eq!(rec.steps[0].action, "matched action");
}

#[test]
fn fallback_without_anomaly_uses_fallback_source() {
    assert_eq!(
        generate(&alert(ThreatCategory::Other, Severity::Info), None, None, &rules()).source,
        "fallback"
    );
}

#[test]
fn fallback_with_anomaly_uses_anomaly_source() {
    assert_eq!(
        generate(
            &alert(ThreatCategory::Other, Severity::Info),
            Some(&anomaly(0.9)),
            None,
            &rules()
        )
        .source,
        "anomaly-kb"
    );
}

#[test]
fn recommendation_id_is_deterministic_for_same_input() {
    let first = generate(&alert(ThreatCategory::Other, Severity::Info), None, None, &rules());
    let second = generate(&alert(ThreatCategory::Other, Severity::Info), None, None, &rules());
    assert_eq!(first.rec_id, second.rec_id);
}

#[test]
fn recommendation_id_changes_with_source() {
    let fallback = generate(&alert(ThreatCategory::Other, Severity::Info), None, None, &rules());
    let anomaly_rec = generate(
        &alert(ThreatCategory::Other, Severity::Info),
        Some(&anomaly(0.1)),
        None,
        &rules(),
    );
    assert_ne!(fallback.rec_id, anomaly_rec.rec_id);
}

#[test]
fn recommendation_preserves_alert_id_and_timestamp() {
    let input = alert(ThreatCategory::Other, Severity::Low);
    let rec = generate(&input, None, None, &rules());
    assert_eq!(rec.alert_id, input.alert_id);
    assert_eq!(rec.generated_at, input.timestamp);
}

#[test]
fn recommendation_context_includes_signature_flow_and_category() {
    let rec = generate(&alert(ThreatCategory::Other, Severity::Low), None, None, &rules());
    assert!(rec.context.iter().any(|line| line.contains("Signature:")));
    assert!(rec.context.iter().any(|line| line.contains("10.0.0.1:1234 -> 10.0.0.2:443 TCP")));
    assert!(rec.context.iter().any(|line| line == "Category: other"));
}

#[test]
fn recommendation_adds_suricata_reference() {
    let rec = generate(&alert(ThreatCategory::Other, Severity::Low), None, None, &rules());
    assert!(rec.references.contains(&"suricata:sid:4242".to_string()));
}

#[test]
fn recommendation_sorts_and_deduplicates_references() {
    let rec = generate(
        &alert(ThreatCategory::Malware, Severity::High),
        None,
        Some(&device()),
        &rules(),
    );
    let mut sorted = rec.references.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(rec.references, sorted);
}

#[test]
fn recommendation_extends_context_with_anomaly() {
    let rec = generate(
        &alert(ThreatCategory::Other, Severity::Low),
        Some(&anomaly(0.7)),
        None,
        &rules(),
    );
    assert!(rec.context.iter().any(|line| line.contains("detector-v1")));
}

#[test]
fn recommendation_extends_context_with_device() {
    let rec = generate(
        &alert(ThreatCategory::Other, Severity::Low),
        None,
        Some(&device()),
        &rules(),
    );
    assert!(rec.context.iter().any(|line| line.contains("Device context")));
}

#[test]
fn recommendation_extends_references_with_device_cves() {
    let rec = generate(
        &alert(ThreatCategory::Other, Severity::Low),
        None,
        Some(&device()),
        &rules(),
    );
    assert!(rec.references.iter().any(|value| value.ends_with("CVE-2026-0001")));
}

#[test]
fn info_confidence_without_anomaly_is_expected() {
    assert_eq!(
        generate(&alert(ThreatCategory::Other, Severity::Info), None, None, &rules()).confidence,
        0.35
    );
}

#[test]
fn low_confidence_without_anomaly_is_expected() {
    assert_eq!(
        generate(&alert(ThreatCategory::Other, Severity::Low), None, None, &rules()).confidence,
        0.55
    );
}

#[test]
fn medium_confidence_without_anomaly_is_expected() {
    assert_eq!(
        generate(&alert(ThreatCategory::Other, Severity::Medium), None, None, &rules()).confidence,
        0.72
    );
}

#[test]
fn high_confidence_without_anomaly_is_expected() {
    assert_eq!(
        generate(&alert(ThreatCategory::Other, Severity::High), None, None, &rules()).confidence,
        0.88
    );
}

#[test]
fn critical_confidence_without_anomaly_is_expected() {
    assert_eq!(
        generate(&alert(ThreatCategory::Other, Severity::Critical), None, None, &rules()).confidence,
        0.95
    );
}

#[test]
fn anomaly_score_blends_with_signature_confidence() {
    let rec = generate(
        &alert(ThreatCategory::Other, Severity::High),
        Some(&anomaly(0.5)),
        None,
        &rules(),
    );
    assert!((rec.confidence - 0.766).abs() < 0.001);
}

#[test]
fn anomaly_percent_score_is_normalized_before_blending() {
    let rec = generate(
        &alert(ThreatCategory::Other, Severity::High),
        Some(&anomaly(50.0)),
        None,
        &rules(),
    );
    assert!((rec.confidence - 0.766).abs() < 0.001);
}

#[test]
fn negative_anomaly_score_is_clamped_before_blending() {
    let rec = generate(
        &alert(ThreatCategory::Other, Severity::Low),
        Some(&anomaly(-1.0)),
        None,
        &rules(),
    );
    assert!((rec.confidence - 0.385).abs() < 0.001);
}

#[test]
fn large_anomaly_score_is_clamped_before_blending() {
    let rec = generate(
        &alert(ThreatCategory::Other, Severity::Low),
        Some(&anomaly(250.0)),
        None,
        &rules(),
    );
    assert!((rec.confidence - 0.685).abs() < 0.001);
}

#[test]
fn unmatched_due_low_severity_uses_fallback() {
    let rec = generate(&alert(ThreatCategory::Malware, Severity::Low), None, None, &rules());
    assert_eq!(rec.title, "fallback title");
}

#[test]
fn unmatched_due_category_uses_fallback() {
    let rec = generate(&alert(ThreatCategory::Exploit, Severity::High), None, None, &rules());
    assert_eq!(rec.title, "fallback title");
}

#[test]
fn severity_field_uses_alert_severity_string() {
    let rec = generate(&alert(ThreatCategory::Other, Severity::Critical), None, None, &rules());
    assert_eq!(rec.severity, "critical");
}

#[test]
fn fallback_steps_are_numbered() {
    let rec = generate(&alert(ThreatCategory::Other, Severity::Info), None, None, &rules());
    assert_eq!(rec.steps[0].order, 1);
}
