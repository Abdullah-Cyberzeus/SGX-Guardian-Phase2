use sgx_guardian_client::key_manager::KeyManager;
use sgx_guardian_client::rules::{store, Condition, RuleDraft, RulePatch, RuleRegistry};

#[test]
fn signed_registry_round_trips_and_tamper_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = dir.path().join("device_nodeA.key");
    let km = KeyManager::load_or_generate(key_path.to_str().expect("key path")).expect("key");

    let rule = store::create_rule(
        dir.path(),
        "nodeA",
        &km,
        RuleDraft {
            name: Some("Critical alerts".to_string()),
            condition: Some(Condition::SeverityAtLeast("critical".to_string())),
            ..RuleDraft::default()
        },
    )
    .expect("create rule");

    let loaded = store::load_registry_with_key(dir.path(), "nodeA", &km).expect("load signed");
    assert_eq!(loaded.sequence, 1);
    assert_eq!(loaded.rules[0].rule_id, rule.rule_id);
    assert!(!loaded.proof.proof_value.is_empty());

    let mut tampered: RuleRegistry = serde_json::from_slice(
        &std::fs::read(dir.path().join("rules.json")).expect("read registry"),
    )
    .expect("parse registry");
    tampered.rules[0].name = "Tampered".to_string();
    std::fs::write(
        dir.path().join("rules.json"),
        serde_json::to_vec_pretty(&tampered).expect("serialize tamper"),
    )
    .expect("write tamper");

    assert!(store::load_registry_with_key(dir.path(), "nodeA", &km).is_err());
}

#[test]
fn patch_and_delete_preserve_signed_registry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = dir.path().join("device_nodeA.key");
    let km = KeyManager::load_or_generate(key_path.to_str().expect("key path")).expect("key");
    let rule = store::create_rule(
        dir.path(),
        "nodeA",
        &km,
        RuleDraft {
            name: Some("Editable".to_string()),
            ..RuleDraft::default()
        },
    )
    .expect("create rule");

    let edited = store::edit_rule(
        dir.path(),
        "nodeA",
        &km,
        &rule.rule_id,
        RulePatch {
            enabled: Some(false),
            ..RulePatch::default()
        },
    )
    .expect("edit rule");
    assert!(!edited.enabled);

    assert!(store::delete_rule(dir.path(), "nodeA", &km, &rule.rule_id).expect("delete"));
    let loaded = store::load_registry_with_key(dir.path(), "nodeA", &km).expect("load signed");
    assert!(loaded.rules.is_empty());
}
