use sgx_guardian_client::policy::validate_policy;

#[test]
fn test_validate_policy_success() {
    let yaml = r#"
policy_id: test_policy
version: "1"
rules:
  - id: r1
    action: allow
    src: "10.0.0.1"
    dst: "10.0.0.2"
    protocol: tcp
    port: 80
"#;

    let p = validate_policy(yaml).expect("Policy should parse successfully");

    assert_eq!(p.policy_id, "test_policy");
    assert_eq!(p.version, "1");
    assert_eq!(p.rules.len(), 1);

    let r = &p.rules[0];
    assert_eq!(r.id, "r1");
    assert_eq!(r.action, "allow");
    assert_eq!(r.port, Some(80));
}

#[test]
fn test_validate_policy_missing_fields_fail() {
    let yaml = r#"
policy_id: only_id
"#;

    let result = validate_policy(yaml);
    assert!(
        result.is_err(),
        "Missing fields must cause YAML parse error"
    );
}

#[test]
fn test_validate_policy_invalid_yaml_fail() {
    let yaml = "invalid: [::::] yaml: ???";

    assert!(
        validate_policy(yaml).is_err(),
        "Invalid YAML must fail to parse"
    );
}

#[test]
fn test_validate_policy_no_port_field() {
    let yaml = r#"
policy_id: pol1
version: "1"
rules:
  - id: rule_x
    action: deny
    src: "1.1.1.1"
    dst: "2.2.2.2"
    protocol: udp
"#;

    let p = validate_policy(yaml).expect("YAML should parse successfully");

    let r = &p.rules[0];
    assert_eq!(r.port, None, "Port should be None when omitted");
}
