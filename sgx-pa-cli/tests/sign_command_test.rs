use assert_cmd::cargo::cargo_bin_cmd;
use std::fs;
use tempfile::tempdir;

#[test]
fn cli_sign_produces_output() {
    let td = tempdir().unwrap();

    let policy = td.path().join("policy.yaml");
    let key = td.path().join("guardian_private.key");
    let _out = td.path().join("policy.sig");

    // 1) Create sample policy YAML
    fs::write(&policy, "policy_id: test\nrules:\n - allow: all").unwrap();

    // 2) Generate a REAL raw 32-byte ECDSA private key (matches your sign.rs)
    use base64::engine::general_purpose;
    use base64::Engine as _;
    use p256::ecdsa::SigningKey;
    use rand_core::OsRng;

    let sk = SigningKey::random(&mut OsRng);
    let raw_key = sk.to_bytes(); // 32-byte secret key
    let raw_b64 = general_purpose::STANDARD.encode(raw_key);

    // 3) Write base64-encoded key to guardian_private.key
    fs::write(&key, raw_b64).unwrap();

    // 4) Run CLI sign command

    let mut cmd = cargo_bin_cmd!("sgx-pa-cli");

    cmd.args(["sign", policy.to_str().unwrap()]);

    // 5) Expect success
    cmd.assert().success();

    // 6) Output file must exist
    let sig_path = std::path::Path::new("policy.sig");
    assert!(sig_path.exists(), "policy.sig was not created");
}
