use base64::engine::general_purpose;
use base64::Engine as _;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand::rngs::OsRng;
use sgx_guardian_client::policy_manager::load_and_activate_policy;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::path::Path;

struct EnvVarGuard {
    key: &'static str,
    prev: Option<OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &Path) -> Self {
        let prev = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, prev }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(v) = self.prev.take() {
            std::env::set_var(self.key, v);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

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
    let policies_dir = td.path().join("policies");
    let _policy_dir = EnvVarGuard::set("SGX_GUARDIAN_POLICY_DIR", &policies_dir);

    fs::create_dir_all(&policies_dir).expect("failed to create policies dir");

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

    let active_path = policies_dir.join("active_policy.yaml");
    let backup_path = policies_dir.join("backup_policy.yaml");
    let sig_path = td.path().join("policy.sig");

    fs::write(&active_path, active_yaml).expect("failed to write active policy");
    fs::write(&backup_path, original_backup_yaml).expect("failed to write backup policy");

    let signed = build_signed_policy(active_yaml);
    fs::write(&sig_path, signed).expect("failed to write signed policy");

    let result = load_and_activate_policy(sig_path.to_str().expect("utf8 path"));
    assert!(
        result.is_ok(),
        "same-policy reload should be a no-op success"
    );

    let backup_after = fs::read_to_string(&backup_path).expect("failed to read backup after");
    let active_after = fs::read_to_string(&active_path).expect("failed to read active after");

    assert_eq!(backup_after, original_backup_yaml);
    assert_eq!(active_after, active_yaml);
}
