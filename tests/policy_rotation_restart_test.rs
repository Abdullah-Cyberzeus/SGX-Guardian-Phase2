use base64::engine::general_purpose;
use base64::Engine as _;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand::rngs::OsRng;
use sgx_guardian_client::policy_manager::load_and_activate_policy;
use sha2::{Digest, Sha256};
use std::fs;

fn build_signed_policy(policy_yaml: &str) -> String {
    let signing_key = SigningKey::random(&mut OsRng);
    let digest = Sha256::digest(policy_yaml.as_bytes());
    let signature: Signature = signing_key.sign(&digest);
    let pubkey = signing_key.verifying_key().to_encoded_point(false);

    serde_json::json!({
        "version": 1,
        "policy_b64": general_purpose::STANDARD.encode(policy_yaml.as_bytes()),
        "digest_hex": hex::encode(digest),
        "signature_b64": general_purpose::STANDARD.encode(signature.to_der().as_bytes()),
        "signing_pubkey_b64": general_purpose::STANDARD.encode(pubkey.as_bytes())
    })
    .to_string()
}

#[test]
fn restart_with_same_policy_digest_does_not_overwrite_backup() {
    let td = tempfile::tempdir().expect("failed to create temp dir");
    std::env::set_current_dir(td.path()).expect("failed to set current dir");

    fs::create_dir_all("policies").expect("failed to create policies dir");

    let active_yaml = r#"
policy_id: "active-policy"
version: "1.0.0"
rules:
  - id: "allow-all"
    action: "ALLOW"
    src: "0.0.0.0/0"
    dst: "0.0.0.0/0"
    protocol: "ALL"
"#;

    let original_backup_yaml = r#"
policy_id: "older-policy"
version: "1.0.0"
rules:
  - id: "deny-some"
    action: "DENY"
    src: "10.0.0.0/8"
    dst: "10.0.0.0/8"
    protocol: "TCP"
"#;

    fs::write("policies/active_policy.yaml", active_yaml).expect("failed to write active policy");
    fs::write("policies/backup_policy.yaml", original_backup_yaml)
        .expect("failed to write backup policy");

    let signed = build_signed_policy(active_yaml);
    fs::write("policy.sig", signed).expect("failed to write signed policy");

    let result = load_and_activate_policy("policy.sig");
    assert!(
        result.is_ok(),
        "same-policy reload should be a no-op success"
    );

    let backup_after =
        fs::read_to_string("policies/backup_policy.yaml").expect("failed to read backup after");
    let active_after =
        fs::read_to_string("policies/active_policy.yaml").expect("failed to read active after");

    assert_eq!(backup_after, original_backup_yaml);
    assert_eq!(active_after, active_yaml);
}
