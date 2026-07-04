use super::*;

#[test]
fn list_upsert_dedups_by_entry_id() {
    let _lock = TEST_LOCK.lock().expect("test lock");
    let issuer = test_did("issuer");
    let mut crl = CertificateRevocationList::new(&issuer, issue::DEFAULT_CIRCLE_ID);
    let entry = build_entry(
        &test_did("target"),
        &issuer,
        issue::DEFAULT_CIRCLE_ID,
        RevocationReason::Compromised,
        Severity::Critical,
        RevokerRole::Owner,
    );
    assert!(crl.upsert(entry.clone()).expect("insert"));
    assert!(!crl.upsert(entry).expect("dedup"));
}

#[test]
fn list_upsert_rejects_already_revoked_did() {
    let _lock = TEST_LOCK.lock().expect("test lock");
    let issuer = test_did("issuer");
    let mut crl = CertificateRevocationList::new(&issuer, issue::DEFAULT_CIRCLE_ID);
    let first = build_entry(
        &test_did("target"),
        &issuer,
        issue::DEFAULT_CIRCLE_ID,
        RevocationReason::Compromised,
        Severity::Critical,
        RevokerRole::Owner,
    );
    let second = build_entry(
        &test_did("target"),
        &issuer,
        issue::DEFAULT_CIRCLE_ID,
        RevocationReason::Stolen,
        Severity::High,
        RevokerRole::Owner,
    );
    crl.upsert(first).expect("insert");
    let err = crl.upsert(second).expect_err("already revoked");
    assert!(matches!(err, CrlError::AlreadyRevoked(_)));
}

#[test]
fn list_contains_returns_correct_bool() {
    let _lock = TEST_LOCK.lock().expect("test lock");
    let issuer = test_did("issuer");
    let mut crl = CertificateRevocationList::new(&issuer, issue::DEFAULT_CIRCLE_ID);
    let entry = build_entry(
        &test_did("target"),
        &issuer,
        issue::DEFAULT_CIRCLE_ID,
        RevocationReason::Compromised,
        Severity::Critical,
        RevokerRole::Owner,
    );
    crl.upsert(entry).expect("insert");
    assert!(crl.contains(&test_did("target")));
    assert!(!crl.contains(&test_did("missing")));
}

#[test]
fn list_recompute_root_is_deterministic() {
    let _lock = TEST_LOCK.lock().expect("test lock");
    let issuer = test_did("issuer");
    let entry_a = build_entry(
        &test_did("alpha"),
        &issuer,
        issue::DEFAULT_CIRCLE_ID,
        RevocationReason::Compromised,
        Severity::Critical,
        RevokerRole::Owner,
    );
    let entry_b = build_entry(
        &test_did("beta"),
        &issuer,
        issue::DEFAULT_CIRCLE_ID,
        RevocationReason::Stolen,
        Severity::High,
        RevokerRole::Owner,
    );

    let mut list_one = CertificateRevocationList::new(&issuer, issue::DEFAULT_CIRCLE_ID);
    list_one.upsert(entry_a.clone()).expect("insert a");
    list_one.upsert(entry_b.clone()).expect("insert b");
    list_one.recompute_root();

    let mut list_two = CertificateRevocationList::new(&issuer, issue::DEFAULT_CIRCLE_ID);
    list_two.upsert(entry_b).expect("insert b");
    list_two.upsert(entry_a).expect("insert a");
    list_two.recompute_root();

    assert_eq!(list_one.merkle_root, list_two.merkle_root);
}
