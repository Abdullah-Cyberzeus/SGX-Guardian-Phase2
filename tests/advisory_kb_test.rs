use sgx_guardian_client::advisory::kb::{
    RecommendationRule, RecommendationRules, RecommendationTemplate, RuleMatch, RuleStep,
};
use sgx_guardian_client::advisory::AdvisoryError;
use sgx_guardian_client::threat::threat_alert::Severity;
use sha2::{Digest, Sha256};

fn rule() -> RecommendationRule {
    RecommendationRule {
        rule_match: RuleMatch {
            category: Some("malware".into()),
            signature_contains: Some("c2".into()),
            severity_at_least: Some("medium".into()),
        },
        title: "title".into(),
        summary: "summary".into(),
        steps: vec![RuleStep {
            action: "act".into(),
            rationale: "why".into(),
            automatable: true,
        }],
        references: vec!["ref".into()],
    }
}

fn rules() -> RecommendationRules {
    RecommendationRules {
        rules: vec![rule()],
        fallback: RecommendationTemplate {
            title: "fallback".into(),
            summary: "fallback summary".into(),
            steps: vec![RuleStep {
                action: "fallback act".into(),
                rationale: "fallback why".into(),
                automatable: false,
            }],
            references: vec!["fallback-ref".into()],
        },
        signature_sha256: None,
    }
}

fn sign(mut rules: RecommendationRules) -> RecommendationRules {
    let bytes = serde_json::to_vec(&rules).unwrap();
    rules.signature_sha256 = Some(hex::encode(Sha256::digest(bytes)));
    rules
}

#[test]
fn default_rules_include_expected_rule_count() {
    assert_eq!(RecommendationRules::default_rules().rules.len(), 4);
}

#[test]
fn default_rules_have_fallback_steps() {
    assert!(!RecommendationRules::default_rules()
        .fallback
        .steps
        .is_empty());
}

#[test]
fn rule_matches_all_conditions() {
    assert!(rule().matches("malware", "ET C2 beacon", Severity::High));
}

#[test]
fn rule_category_match_is_case_insensitive() {
    assert!(rule().matches("MALWARE", "et c2 beacon", Severity::High));
}

#[test]
fn rule_signature_contains_is_case_insensitive() {
    assert!(rule().matches("malware", "ET c2 BEACON", Severity::High));
}

#[test]
fn rule_rejects_wrong_category() {
    assert!(!rule().matches("exploit", "ET C2 beacon", Severity::High));
}

#[test]
fn rule_rejects_missing_signature_fragment() {
    assert!(!rule().matches("malware", "benign", Severity::High));
}

#[test]
fn rule_rejects_below_minimum_severity() {
    assert!(!rule().matches("malware", "c2", Severity::Low));
}

#[test]
fn rule_accepts_equal_minimum_severity() {
    assert!(rule().matches("malware", "c2", Severity::Medium));
}

#[test]
fn rule_without_conditions_matches_anything() {
    let mut item = rule();
    item.rule_match = RuleMatch {
        category: None,
        signature_contains: None,
        severity_at_least: None,
    };
    assert!(item.matches("other", "", Severity::Info));
}

#[test]
fn unknown_minimum_severity_behaves_as_lowest_rank() {
    let mut item = rule();
    item.rule_match.severity_at_least = Some("unknown".into());
    assert!(item.matches("malware", "c2", Severity::Info));
}

#[test]
fn critical_minimum_only_accepts_critical() {
    let mut item = rule();
    item.rule_match.severity_at_least = Some("critical".into());
    assert!(!item.matches("malware", "c2", Severity::High));
    assert!(item.matches("malware", "c2", Severity::Critical));
}

#[test]
fn steps_are_numbered_from_one() {
    assert_eq!(rule().steps()[0].order, 1);
}

#[test]
fn template_steps_are_numbered_from_one() {
    assert_eq!(rules().fallback.steps()[0].order, 1);
}

#[test]
fn steps_preserve_action_rationale_and_automation() {
    let step = rule().steps().remove(0);
    assert_eq!(step.action, "act");
    assert_eq!(step.rationale, "why");
    assert!(step.automatable);
}

#[test]
fn step_order_saturates_at_u8_max() {
    let mut item = rule();
    item.steps = (0..260)
        .map(|idx| RuleStep {
            action: format!("a{idx}"),
            rationale: "r".into(),
            automatable: false,
        })
        .collect();
    assert_eq!(item.steps().last().unwrap().order, u8::MAX);
}

#[test]
fn unsigned_rules_validate_successfully() {
    assert!(rules().validate_signature().is_ok());
}

#[test]
fn signed_rules_validate_successfully() {
    assert!(sign(rules()).validate_signature().is_ok());
}

#[test]
fn signature_validation_is_case_insensitive() {
    let mut signed = sign(rules());
    signed.signature_sha256 = signed.signature_sha256.map(|value| value.to_uppercase());
    assert!(signed.validate_signature().is_ok());
}

#[test]
fn tampered_signed_rules_fail_validation() {
    let mut signed = sign(rules());
    signed.fallback.title = "tampered".into();
    assert!(matches!(
        signed.validate_signature(),
        Err(AdvisoryError::InvalidRules(_))
    ));
}

#[test]
fn rules_round_trip_json() {
    let encoded = serde_json::to_string(&rules()).unwrap();
    assert_eq!(
        serde_json::from_str::<RecommendationRules>(&encoded).unwrap(),
        rules()
    );
}

#[test]
fn serde_defaults_missing_rule_vectors() {
    let parsed: RecommendationRules =
        serde_json::from_str(r#"{"fallback":{"title":"f","summary":"s"}}"#).unwrap();
    assert!(parsed.rules.is_empty());
    assert!(parsed.fallback.steps.is_empty());
    assert!(parsed.fallback.references.is_empty());
}

#[test]
fn load_verified_missing_file_returns_io_error() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        RecommendationRules::load_verified(&dir.path().join("missing.json")),
        Err(sgx_guardian_client::advisory::AdvisoryError::Io(_))
    ));
}

#[test]
fn load_verified_malformed_json_returns_json_error() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), b"{").unwrap();
    assert!(matches!(
        RecommendationRules::load_verified(file.path()),
        Err(sgx_guardian_client::advisory::AdvisoryError::Json(_))
    ));
}

#[test]
fn load_or_default_falls_back_for_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        RecommendationRules::load_or_default(&dir.path().join("missing.json")),
        RecommendationRules::default_rules()
    );
}

#[test]
fn save_atomic_and_load_verified_round_trip_signed_rules() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested").join("rules.json");
    let signed = sign(rules());
    signed.save_atomic(&path).unwrap();
    assert_eq!(RecommendationRules::load_verified(&path).unwrap(), signed);
}
