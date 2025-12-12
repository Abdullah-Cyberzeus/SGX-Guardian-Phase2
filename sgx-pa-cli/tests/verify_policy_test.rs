use std::fs;
use tempfile::tempdir;

#[test]
fn verify_signed_policy_success() {
    let td = tempdir().unwrap();
    let policy_path = td.path().join("policy.yaml");
    let key_path = td.path().join("guardian_private.key");
    let sig_path = td.path().join("policy.sig");

    // 1) Create sample policy YAML
    fs::write(&policy_path, "policy_id: test\nrules:\n - allow: all\n").unwrap();

    // 2) Generate a valid 32-byte ECDSA key and write BASE64 to guardian_private.key
    use base64::engine::general_purpose;
    use base64::Engine as _;
    use p256::ecdsa::SigningKey;
    use rand_core::OsRng;

    let sk = SigningKey::random(&mut OsRng);
    let raw_key = sk.to_bytes();
    let raw_b64 = general_purpose::STANDARD.encode(raw_key);
    fs::write(&key_path, raw_b64).unwrap();

    // 3) Run CLI signing command
    let mut sign = assert_cmd::cargo::cargo_bin_cmd!("sgx-pa-cli");
    sign.args(["sign", policy_path.to_str().unwrap()]);
    sign.assert().success();

    // Move generated "policy.sig" into temporary test directory (cross-device safe)
    fs::copy("policy.sig", &sig_path).expect("Failed to copy policy.sig into temp dir");
    let _ = fs::remove_file("policy.sig"); // cleanup original (ignore error if any)

    // 4) Run verification command
    let mut verify = assert_cmd::cargo::cargo_bin_cmd!("sgx-pa-cli");
    verify.args(["verify", "--signed", sig_path.to_str().unwrap()]);

    // 5) Expect successful verification
    verify.assert().success();
}
