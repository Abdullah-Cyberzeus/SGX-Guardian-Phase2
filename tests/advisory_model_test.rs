use chrono::{TimeZone, Utc};
use sgx_guardian_client::advisory::model::{
    AnomalyContext, CveFinding, DeviceContext, RemediationRecommendation, RemediationStep,
};

fn ts() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap()
}

fn step(order: u8) -> RemediationStep {
    RemediationStep {
        order,
        action: format!("action-{order}"),
        rationale: format!("reason-{order}"),
        automatable: order % 2 == 0,
    }
}

fn recommendation() -> RemediationRecommendation {
    RemediationRecommendation {
        rec_id: "rec-1".into(),
        alert_id: "alert-1".into(),
        title: "title".into(),
        summary: "summary".into(),
        severity: "high".into(),
        confidence: 0.88,
        steps: vec![step(1), step(2)],
        context: vec!["ctx".into()],
        references: vec!["ref".into()],
        source: "signature-kb".into(),
        generated_at: ts(),
    }
}

#[test]
fn remediation_step_round_trips_json() {
    let original = step(7);
    let encoded = serde_json::to_string(&original).unwrap();
    assert_eq!(serde_json::from_str::<RemediationStep>(&encoded).unwrap(), original);
}

#[test]
fn remediation_step_clone_preserves_fields() {
    let original = step(3);
    let cloned = original.clone();
    assert_eq!(cloned.order, 3);
    assert_eq!(cloned.action, "action-3");
    assert!(!cloned.automatable);
}

#[test]
fn remediation_step_accepts_zero_order_boundary() {
    let item = RemediationStep {
        order: 0,
        ..step(1)
    };
    assert_eq!(serde_json::to_value(&item).unwrap()["order"], 0);
}

#[test]
fn remediation_step_accepts_u8_max_order_boundary() {
    let item = RemediationStep {
        order: u8::MAX,
        ..step(1)
    };
    assert_eq!(serde_json::to_value(&item).unwrap()["order"], 255);
}

#[test]
fn remediation_step_requires_action_when_deserializing() {
    let err = serde_json::from_str::<RemediationStep>(
        r#"{"order":1,"rationale":"why","automatable":true}"#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("missing field"));
}

#[test]
fn remediation_step_rejects_out_of_range_order() {
    let err = serde_json::from_str::<RemediationStep>(
        r#"{"order":256,"action":"a","rationale":"r","automatable":false}"#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("invalid value") || err.to_string().contains("number"));
}

#[test]
fn anomaly_context_round_trips_json() {
    let original = AnomalyContext {
        score: 0.42,
        topk: vec![("flow_rate".into(), 0.2)],
        model_version: Some("v1".into()),
    };
    let encoded = serde_json::to_string(&original).unwrap();
    assert_eq!(serde_json::from_str::<AnomalyContext>(&encoded).unwrap(), original);
}

#[test]
fn anomaly_context_defaults_topk_and_model_version() {
    let parsed: AnomalyContext = serde_json::from_str(r#"{"score":0.1}"#).unwrap();
    assert_eq!(parsed.score, 0.1);
    assert!(parsed.topk.is_empty());
    assert_eq!(parsed.model_version, None);
}

#[test]
fn anomaly_context_preserves_negative_score_for_later_normalization() {
    let parsed: AnomalyContext = serde_json::from_str(r#"{"score":-2.5}"#).unwrap();
    assert_eq!(parsed.score, -2.5);
}

#[test]
fn anomaly_context_preserves_large_score_for_later_normalization() {
    let parsed: AnomalyContext = serde_json::from_str(r#"{"score":250.0}"#).unwrap();
    assert_eq!(parsed.score, 250.0);
}

#[test]
fn anomaly_context_requires_score() {
    assert!(serde_json::from_str::<AnomalyContext>(r#"{"topk":[]}"#).is_err());
}

#[test]
fn anomaly_context_rejects_wrong_topk_shape() {
    assert!(serde_json::from_str::<AnomalyContext>(
        r#"{"score":0.5,"topk":[{"feature":"x","score":1.0}]}"#
    )
    .is_err());
}

#[test]
fn cve_finding_round_trips_with_cvss() {
    let original = CveFinding {
        cve: "CVE-2026-0001".into(),
        cvss: Some(9.8),
    };
    let encoded = serde_json::to_string(&original).unwrap();
    assert_eq!(serde_json::from_str::<CveFinding>(&encoded).unwrap(), original);
}

#[test]
fn cve_finding_round_trips_without_cvss() {
    let original = CveFinding {
        cve: "CVE-2026-0002".into(),
        cvss: None,
    };
    let value = serde_json::to_value(&original).unwrap();
    assert!(value["cvss"].is_null());
}

#[test]
fn cve_finding_requires_cve() {
    assert!(serde_json::from_str::<CveFinding>(r#"{"cvss":5.0}"#).is_err());
}

#[test]
fn device_context_round_trips_full_payload() {
    let original = DeviceContext {
        ip: "10.0.0.2".into(),
        hostname: Some("host".into()),
        vendor: Some("vendor".into()),
        risk_reasons: vec!["risk".into()],
        cves: vec![CveFinding {
            cve: "CVE-2026-0003".into(),
            cvss: Some(7.1),
        }],
    };
    let encoded = serde_json::to_string(&original).unwrap();
    assert_eq!(serde_json::from_str::<DeviceContext>(&encoded).unwrap(), original);
}

#[test]
fn device_context_defaults_optional_collections() {
    let parsed: DeviceContext = serde_json::from_str(r#"{"ip":"10.0.0.3"}"#).unwrap();
    assert_eq!(parsed.hostname, None);
    assert_eq!(parsed.vendor, None);
    assert!(parsed.risk_reasons.is_empty());
    assert!(parsed.cves.is_empty());
}

#[test]
fn device_context_requires_ip() {
    assert!(serde_json::from_str::<DeviceContext>(r#"{"hostname":"h"}"#).is_err());
}

#[test]
fn recommendation_round_trips_json() {
    let original = recommendation();
    let encoded = serde_json::to_string(&original).unwrap();
    assert_eq!(
        serde_json::from_str::<RemediationRecommendation>(&encoded).unwrap(),
        original
    );
}

#[test]
fn recommendation_clone_preserves_nested_steps() {
    let cloned = recommendation().clone();
    assert_eq!(cloned.steps.len(), 2);
    assert_eq!(cloned.steps[1].action, "action-2");
}

#[test]
fn recommendation_requires_rec_id() {
    let mut value = serde_json::to_value(recommendation()).unwrap();
    value.as_object_mut().unwrap().remove("rec_id");
    assert!(serde_json::from_value::<RemediationRecommendation>(value).is_err());
}

#[test]
fn recommendation_requires_alert_id() {
    let mut value = serde_json::to_value(recommendation()).unwrap();
    value.as_object_mut().unwrap().remove("alert_id");
    assert!(serde_json::from_value::<RemediationRecommendation>(value).is_err());
}

#[test]
fn recommendation_requires_generated_at() {
    let mut value = serde_json::to_value(recommendation()).unwrap();
    value.as_object_mut().unwrap().remove("generated_at");
    assert!(serde_json::from_value::<RemediationRecommendation>(value).is_err());
}

#[test]
fn recommendation_accepts_empty_vectors() {
    let item = RemediationRecommendation {
        steps: Vec::new(),
        context: Vec::new(),
        references: Vec::new(),
        ..recommendation()
    };
    assert!(serde_json::to_string(&item).unwrap().contains("\"steps\":[]"));
}

#[test]
fn recommendation_preserves_zero_confidence_boundary() {
    let item = RemediationRecommendation {
        confidence: 0.0,
        ..recommendation()
    };
    assert_eq!(
        serde_json::from_value::<RemediationRecommendation>(serde_json::to_value(&item).unwrap())
            .unwrap()
            .confidence,
        0.0
    );
}

#[test]
fn recommendation_preserves_one_confidence_boundary() {
    let item = RemediationRecommendation {
        confidence: 1.0,
        ..recommendation()
    };
    assert_eq!(
        serde_json::from_value::<RemediationRecommendation>(serde_json::to_value(&item).unwrap())
            .unwrap()
            .confidence,
        1.0
    );
}
