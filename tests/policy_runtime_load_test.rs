use sgx_guardian_client::policy::{get_active_policy, load_policy_runtime};

#[test]
fn runtime_policy_load_and_readback() {
    // Minimal valid policy YAML
    let yaml = r#"
policy_id: "runtime-test"
version: "1.0.0"
rules:
  - id: "rule-allow-all"
    action: "ALLOW"
    src: "0.0.0.0/0"
    dst: "0.0.0.0/0"
    protocol: "ALL"
"#;

    // Load policy into runtime cache
    load_policy_runtime(yaml).expect("Failed to load policy into runtime cache");

    // Read policy back
    let active = get_active_policy();
    assert!(active.is_some(), "Active policy should be present");

    let policy = active.unwrap();

    // Validate contents
    assert_eq!(policy.policy_id, "runtime-test");
    assert_eq!(policy.version, "1.0.0");
    assert_eq!(policy.rules.len(), 1);
    assert_eq!(policy.rules[0].action, "ALLOW");
}
