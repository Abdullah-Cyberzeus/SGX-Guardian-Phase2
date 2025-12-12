use sgx_pa_cli::policy_signer::compute_policy_digest;

#[test]
fn test_digest_stability() {
    let yaml1 = "policy_id: test\nrules:\n - allow: all\n";
    let yaml2 = "policy_id: test\r\nrules:\r\n - allow: all\r\n";

    let d1 = compute_policy_digest(yaml1);
    let d2 = compute_policy_digest(yaml2);

    // They differ ONLY in Windows line endings.
    assert_eq!(d1, d2, "Digest must ignore line-ending differences");
}
