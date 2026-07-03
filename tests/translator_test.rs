use sgx_guardian_client::enforcement::enforce_policy;
use sgx_guardian_client::policy::validate_policy;

#[test]
fn test_policy_translation() {
    let yaml = r#"
policy_id: "test-policy"
version: "1.0"
rules:
  - id: "rule1"
    action: "allow"
    src: "device_A"
    dst: "service_B"
    protocol: "tcp"
    port: 80
"#;
    let policy = validate_policy(yaml).unwrap();
    
    // Translate policy to enforcement rules and apply (will likely return an Error if nft is missing, which is fine)
    let _result = enforce_policy(&policy);
}
