use sgx_guardian_client::policy_manager::load_and_activate_policy;
use std::fs;
use tempfile::tempdir;

#[test]
fn atomic_policy_load_success() {
    let td = tempdir().unwrap();
    std::env::set_current_dir(td.path()).unwrap();

    // Fake signed policy (already verified logic tested earlier)
    let signed = r#"
{
  "version": 1,
  "policy_b64": "cG9saWN5X2lkOiAidGVzdCI=",
  "digest_hex": "9f86d081884c7d659a2feaa0c55ad015",
  "signature_b64": "MEUCIQDUMMY",
  "signing_pubkey_b64": "BBDUMMY"
}
"#;
    fs::write("policy.sig", signed).unwrap();

    // This will fail verification, but should NOT create active_policy.yaml
    let result = load_and_activate_policy("policy.sig");
    assert!(result.is_err());
    assert!(!std::path::Path::new("policies/active_policy.yaml").exists());
}
