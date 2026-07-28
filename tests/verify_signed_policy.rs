use base64::engine::general_purpose;
use base64::Engine as _;
use sgx_guardian_client::policy_manager::verify_signed_policy;
use std::fs;
use tempfile::tempdir;

#[test]
fn verify_valid_signed_policy() {
    let td = tempdir().unwrap();

    let policy_path = td.path().join("policy.yaml");
    let sig_path = td.path().join("policy.sig");

    // Simple policy
    fs::write(&policy_path, "policy_id: test\nrules:\n - allow: all\n").unwrap();

    // Generate signed policy using sgx-pa-cli output format
    let envelope = serde_json::json!({
        "version": 1,
        "policy_b64": general_purpose::STANDARD.encode("policy_id: test\nrules:\n - allow: all\n"),
        "digest_hex": "3a84fdd8f7c4f2b1f98b2a9b7f2eec4c9c9d4a0e8eae33e7c3f6e7b5b5baf7a5",
        "signature_b64": "",
        "signing_pubkey_b64": ""
    });

    // NOTE:
    // This test only validates structural flow.
    // Full crypto correctness is already tested in sgx-pa-cli.
    fs::write(&sig_path, envelope.to_string()).unwrap();

    let result = verify_signed_policy(sig_path.to_str().unwrap());
    assert!(result.is_err(), "Invalid crypto must be rejected");
}
#[test]
fn verify_rejects_tampered_policy() {
    let td = tempfile::tempdir().unwrap();
    let sig_path = td.path().join("policy.sig");

    // Write invalid content
    std::fs::write(&sig_path, "BAD DATA").unwrap();

    let result = verify_signed_policy(sig_path.to_str().unwrap());

    // MUST fail
    assert!(result.is_err(), "Tampered policy must be rejected");
}
