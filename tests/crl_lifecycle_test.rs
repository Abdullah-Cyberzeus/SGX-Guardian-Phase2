use sgx_guardian_client::crl::entry::{
    CrlEntry, RevocationReason, RevokerRole, Severity, UnrevokeTombstone, CRL_CONTEXT_CORE,
    CRL_CONTEXT_SGX, CRL_UNREVOKE_TOMBSTONE_TYPE,
};
use sgx_guardian_client::crl::errors::CrlError;
use sgx_guardian_client::crl::list::CertificateRevocationList;
use sgx_guardian_client::did::document::Proof;

fn make_entry(id: &str, did: &str, reason: RevocationReason, severity: Severity) -> CrlEntry {
    CrlEntry {
        context: vec![CRL_CONTEXT_CORE.into(), CRL_CONTEXT_SGX.into()],
        id: format!("urn:uuid:{}", id),
        r#type: vec!["VerifiableCredential".into(), "RevocationCredential".into()],
        revoked_did: did.into(),
        device_id: Some("dev-node-1".into()),
        user_id: None,
        circle_id: "circle-secure-corp".into(),
        reason,
        severity,
        timestamp: "2026-01-15T10:00:00Z".into(),
        revoker_did: "did:guardian:owner-1".into(),
        revoker_role: RevokerRole::Owner,
        evidence: None,
        proof: Proof::default(),
        peers_notified: vec!["did:guardian:peer-a".into()],
        propagated: false,
    }
}

fn make_tombstone(id: &str, did: &str, orig_id: &str) -> UnrevokeTombstone {
    UnrevokeTombstone {
        context: vec![CRL_CONTEXT_CORE.into()],
        id: format!("urn:uuid:{}", id),
        r#type: vec!["VerifiableCredential".into(), CRL_UNREVOKE_TOMBSTONE_TYPE.into()],
        revoked_did: did.into(),
        original_entry_id: format!("urn:uuid:{}", orig_id),
        owner_did: "did:guardian:owner-1".into(),
        sequence: 10,
        timestamp: "2026-01-15T12:00:00Z".into(),
        proof: Proof::default(),
        peers_notified: vec![],
        propagated: false,
    }
}

#[test]
fn test_crl_full_lifecycle_and_binary_search_sorting() {
    let mut crl = CertificateRevocationList::new("did:guardian:owner-1", "circle-secure-corp");
    assert_eq!(crl.entries.len(), 0);
    assert_eq!(crl.sequence, 0);

    // Insert multiple DIDs out of order
    let entry_c = make_entry(
        "1003",
        "did:guardian:charlie",
        RevocationReason::Lost,
        Severity::Medium,
    );
    let entry_a = make_entry(
        "1001",
        "did:guardian:alice",
        RevocationReason::Compromised,
        Severity::Critical,
    );
    let entry_b = make_entry(
        "1002",
        "did:guardian:bob",
        RevocationReason::PolicyViolation,
        Severity::High,
    );

    assert!(crl.upsert(entry_c).unwrap());
    assert!(crl.upsert(entry_a).unwrap());
    assert!(crl.upsert(entry_b).unwrap());

    // Verify binary-search sorted ordering by revoked_did
    assert_eq!(crl.entries.len(), 3);
    assert_eq!(crl.entries[0].revoked_did, "did:guardian:alice");
    assert_eq!(crl.entries[1].revoked_did, "did:guardian:bob");
    assert_eq!(crl.entries[2].revoked_did, "did:guardian:charlie");

    // All DIDs must report contained
    assert!(crl.contains("did:guardian:alice"));
    assert!(crl.contains("did:guardian:bob"));
    assert!(crl.contains("did:guardian:charlie"));
    assert!(!crl.contains("did:guardian:david"));
}

#[test]
fn test_crl_duplicate_and_conflict_enforcement() {
    let mut crl = CertificateRevocationList::new("did:guardian:owner-1", "circle-secure-corp");

    let entry1 = make_entry(
        "1001",
        "did:guardian:alice",
        RevocationReason::Compromised,
        Severity::Critical,
    );
    assert!(crl.upsert(entry1.clone()).unwrap());

    // Same entry again -> returns Ok(false) (idempotent no-op)
    assert!(!crl.upsert(entry1).unwrap());

    // Different entry ID but same revoked_did -> returns AlreadyRevoked error
    let entry1_alt = make_entry(
        "9999",
        "did:guardian:alice",
        RevocationReason::Lost,
        Severity::High,
    );
    assert!(matches!(
        crl.upsert(entry1_alt),
        Err(CrlError::AlreadyRevoked(_))
    ));
}

#[test]
fn test_crl_unrevoke_and_reactivation_cycle() {
    let mut crl = CertificateRevocationList::new("did:guardian:owner-1", "circle-secure-corp");

    let entry = make_entry(
        "1001",
        "did:guardian:alice",
        RevocationReason::Compromised,
        Severity::Critical,
    );
    crl.upsert(entry).unwrap();
    assert!(crl.contains("did:guardian:alice"));

    // Tombstone alice -> unrevokes her
    let tombstone = make_tombstone("t101", "did:guardian:alice", "1001");
    assert!(crl.upsert_tombstone(tombstone));

    // Alice is no longer in active revocations
    assert!(!crl.contains("did:guardian:alice"));
    assert!(crl.tombstone("did:guardian:alice").is_some());

    // Re-revoking Alice later removes the tombstone and puts her back into active revocations
    let new_entry = make_entry(
        "2001",
        "did:guardian:alice",
        RevocationReason::Stolen,
        Severity::Critical,
    );
    assert!(crl.upsert(new_entry).unwrap());
    assert!(crl.contains("did:guardian:alice"));
    assert!(crl.tombstone("did:guardian:alice").is_none());
}

#[test]
fn test_crl_merkle_root_computation_and_serde_roundtrip() {
    let mut crl = CertificateRevocationList::new("did:guardian:owner-1", "circle-secure-corp");
    crl.recompute_root();
    let initial_root = crl.merkle_root.clone();

    let entry = make_entry(
        "1001",
        "did:guardian:alice",
        RevocationReason::Compromised,
        Severity::Critical,
    );
    crl.upsert(entry).unwrap();
    crl.recompute_root();
    let updated_root = crl.merkle_root.clone();

    // Merkle root must change on new entry
    assert_ne!(initial_root, updated_root);

    // Serialization roundtrip
    let serialized = serde_json::to_string(&crl).expect("serialize CRL");
    let deserialized: CertificateRevocationList =
        serde_json::from_str(&serialized).expect("deserialize CRL");

    assert_eq!(deserialized.issuer, crl.issuer);
    assert_eq!(deserialized.circle_id, crl.circle_id);
    assert_eq!(deserialized.merkle_root, crl.merkle_root);
    assert_eq!(deserialized.entries.len(), 1);
    assert_eq!(deserialized.entries[0].revoked_did, "did:guardian:alice");
}
