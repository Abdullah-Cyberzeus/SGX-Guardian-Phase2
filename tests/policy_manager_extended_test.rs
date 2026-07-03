// tests/policy_manager_extended_test.rs
// Integration tests for src/policy_manager.rs (error paths and basic handling)

use base64::Engine;
use sgx_guardian_client::policy_manager;
use std::fs;
use tempfile::NamedTempFile;

#[test]
fn test_verify_signed_policy_missing_file() {
    let result = policy_manager::verify_signed_policy("/tmp/nonexistent-policy.json");
    assert!(result.is_err());
    let err_str = result.unwrap_err().to_string();
    assert!(err_str.contains("Failed to read signed policy file"));
}

#[test]
fn test_verify_signed_policy_invalid_json() {
    let tmp = NamedTempFile::new().unwrap();
    fs::write(tmp.path(), b"not-a-json-object").unwrap();
    let result = policy_manager::verify_signed_policy(tmp.path().to_str().unwrap());
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Invalid signed policy JSON"));
}

#[test]
fn test_verify_signed_policy_unsupported_version() {
    let tmp = NamedTempFile::new().unwrap();
    // Valid JSON structure but version != 1
    let content = r#"{
        "version": 2,
        "policy_b64": "",
        "digest_hex": "",
        "signature_b64": "",
        "signing_pubkey_b64": ""
    }"#;
    fs::write(tmp.path(), content).unwrap();
    
    let result = policy_manager::verify_signed_policy(tmp.path().to_str().unwrap());
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Unsupported policy version"));
}

#[test]
fn test_verify_signed_policy_invalid_base64_policy() {
    let tmp = NamedTempFile::new().unwrap();
    let content = r#"{
        "version": 1,
        "policy_b64": "invalid-base64!!!",
        "digest_hex": "",
        "signature_b64": "",
        "signing_pubkey_b64": ""
    }"#;
    fs::write(tmp.path(), content).unwrap();
    
    let result = policy_manager::verify_signed_policy(tmp.path().to_str().unwrap());
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Failed to decode policy base64"));
}

#[test]
fn test_verify_signed_policy_digest_mismatch() {
    let tmp = NamedTempFile::new().unwrap();
    
    // Create base64 of "some policy"
    let policy_b64 = base64::engine::general_purpose::STANDARD.encode(b"some policy");
    
    let content = format!(r#"{{
        "version": 1,
        "policy_b64": "{}",
        "digest_hex": "deadbeef",
        "signature_b64": "",
        "signing_pubkey_b64": ""
    }}"#, policy_b64);
    
    fs::write(tmp.path(), content).unwrap();
    
    let result = policy_manager::verify_signed_policy(tmp.path().to_str().unwrap());
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Policy digest mismatch"));
}
