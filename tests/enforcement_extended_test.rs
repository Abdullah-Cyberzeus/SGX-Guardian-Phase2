// tests/enforcement_extended_test.rs
// Integration tests for src/enforcement (validator and translator error paths)

use sgx_guardian_client::enforcement::apply_policy;
use sgx_guardian_client::policy::{Policy, Rule};

#[test]
fn test_apply_policy_empty_rules_fails_validation() {
    let policy = Policy {
        policy_id: "test".into(),
        version: "1".into(),
        rules: vec![],
    };
    let result = apply_policy(&policy);
    assert!(result.is_err());
    assert!(format!("{:#}", result.unwrap_err()).contains("contains no enforcement rules"));
}

#[test]
fn test_apply_policy_missing_action_fails_validation() {
    let policy = Policy {
        policy_id: "test".into(),
        version: "1".into(),
        rules: vec![Rule {
            id: "r1".into(),
            action: "  ".into(), // empty/whitespace
            protocol: "tcp".into(),
            src: "any".into(),
            dst: "any".into(),
            port: Some(80),
        }],
    };
    let result = apply_policy(&policy);
    assert!(result.is_err());
    assert!(format!("{:#}", result.unwrap_err()).contains("missing action"));
}

#[test]
fn test_apply_policy_missing_protocol_fails_validation() {
    let policy = Policy {
        policy_id: "test".into(),
        version: "1".into(),
        rules: vec![Rule {
            id: "r2".into(),
            action: "allow".into(),
            protocol: "".into(),
            src: "any".into(),
            dst: "any".into(),
            port: Some(80),
        }],
    };
    let result = apply_policy(&policy);
    assert!(result.is_err());
    assert!(format!("{:#}", result.unwrap_err()).contains("missing protocol"));
}

#[test]
fn test_apply_policy_missing_src_fails_validation() {
    let policy = Policy {
        policy_id: "test".into(),
        version: "1".into(),
        rules: vec![Rule {
            id: "r3".into(),
            action: "allow".into(),
            protocol: "tcp".into(),
            src: "".into(),
            dst: "any".into(),
            port: Some(80),
        }],
    };
    let result = apply_policy(&policy);
    assert!(result.is_err());
    assert!(format!("{:#}", result.unwrap_err()).contains("missing source address"));
}

#[test]
fn test_apply_policy_missing_dst_fails_validation() {
    let policy = Policy {
        policy_id: "test".into(),
        version: "1".into(),
        rules: vec![Rule {
            id: "r4".into(),
            action: "allow".into(),
            protocol: "tcp".into(),
            src: "any".into(),
            dst: "".into(),
            port: Some(80),
        }],
    };
    let result = apply_policy(&policy);
    assert!(result.is_err());
    assert!(format!("{:#}", result.unwrap_err()).contains("missing destination address"));
}

#[test]
fn test_apply_policy_invalid_port_0_fails_validation() {
    let policy = Policy {
        policy_id: "test".into(),
        version: "1".into(),
        rules: vec![Rule {
            id: "r5".into(),
            action: "allow".into(),
            protocol: "tcp".into(),
            src: "any".into(),
            dst: "any".into(),
            port: Some(0),
        }],
    };
    let result = apply_policy(&policy);
    assert!(result.is_err());
    assert!(format!("{:#}", result.unwrap_err()).contains("invalid port 0"));
}

#[test]
fn test_apply_policy_invalid_action_fails_translation() {
    let policy = Policy {
        policy_id: "test".into(),
        version: "1".into(),
        rules: vec![Rule {
            id: "r6".into(),
            action: "magical_allow".into(), // unsupported
            protocol: "tcp".into(),
            src: "any".into(),
            dst: "any".into(),
            port: Some(80),
        }],
    };
    let result = apply_policy(&policy);
    assert!(result.is_err());
    assert!(format!("{:#}", result.unwrap_err()).contains("unsupported action"));
}

#[test]
fn test_apply_policy_invalid_protocol_fails_translation() {
    let policy = Policy {
        policy_id: "test".into(),
        version: "1".into(),
        rules: vec![Rule {
            id: "r7".into(),
            action: "allow".into(),
            protocol: "http".into(), // unsupported (only tcp/udp)
            src: "any".into(),
            dst: "any".into(),
            port: Some(80),
        }],
    };
    let result = apply_policy(&policy);
    assert!(result.is_err());
    assert!(format!("{:#}", result.unwrap_err()).contains("unsupported protocol"));
}
