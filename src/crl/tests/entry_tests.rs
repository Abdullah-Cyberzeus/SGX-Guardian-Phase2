use super::*;

#[test]
fn entry_fingerprint_is_stable_across_resigning() {
    let _lock = test_lock();
    let entry_one = build_entry(
        &test_did("target"),
        &test_did("issuer"),
        issue::DEFAULT_CIRCLE_ID,
        RevocationReason::Compromised,
        Severity::Critical,
        RevokerRole::Owner,
    );
    let mut entry_two = entry_one.clone();
    entry_two.proof = Proof {
        proof_type: "DataIntegrityProof".to_string(),
        cryptosuite: "ecdsa-2019".to_string(),
        verification_method: format!("{}#dkp-v2", test_did("issuer")),
        created: Utc::now().to_rfc3339(),
        proof_purpose: "assertionMethod".to_string(),
        proof_value: "different".to_string(),
    };
    entry_two.peers_notified.push(test_did("peerB"));
    entry_two.propagated = false;

    assert_eq!(entry_one.fingerprint(), entry_two.fingerprint());
}

#[test]
fn round_trip_serde_preserves_all_fields() {
    let _lock = test_lock();
    let entry = build_entry(
        &test_did("target"),
        &test_did("issuer"),
        issue::DEFAULT_CIRCLE_ID,
        RevocationReason::Stolen,
        Severity::High,
        RevokerRole::Member,
    );

    let json = serde_json::to_string(&entry).expect("serialize");
    let parsed: CrlEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        serde_json::to_value(&entry).expect("entry value"),
        serde_json::to_value(&parsed).expect("parsed value")
    );
}

#[test]
fn legacy_entry_without_evidence_field_still_parses() {
    let _lock = test_lock();
    let json = serde_json::json!({
        "@context": [CRL_CONTEXT_CORE, CRL_CONTEXT_SGX],
        "id": "urn:uuid:legacy",
        "type": ["VerifiableCredential", "RevocationCredential"],
        "revoked_did": test_did("target"),
        "device_id": null,
        "user_id": null,
        "circle_id": issue::DEFAULT_CIRCLE_ID,
        "reason": "compromised",
        "severity": "critical",
        "timestamp": Utc::now().to_rfc3339(),
        "revoker_did": test_did("issuer"),
        "revoker_role": "owner",
        "proof": Proof::default(),
        "peers_notified": [],
        "propagated": false
    });

    let entry: CrlEntry = serde_json::from_value(json).expect("parse");
    assert!(entry.evidence.is_none());
}

#[test]
fn tombstone_fingerprint_is_stable_across_resigning() {
    let _lock = test_lock();
    let tombstone_one = build_tombstone(
        &test_did("target"),
        "urn:uuid:revocation-a",
        &test_did("issuer"),
        4,
    );
    let mut tombstone_two = tombstone_one.clone();
    tombstone_two.proof = Proof {
        proof_type: "DataIntegrityProof".to_string(),
        cryptosuite: "ecdsa-2019".to_string(),
        verification_method: format!("{}#dkp-v2", test_did("issuer")),
        created: Utc::now().to_rfc3339(),
        proof_purpose: "assertionMethod".to_string(),
        proof_value: "different".to_string(),
    };
    tombstone_two.peers_notified.push(test_did("peerB"));
    tombstone_two.propagated = false;

    assert_eq!(tombstone_one.fingerprint(), tombstone_two.fingerprint());
    assert_ne!(
        tombstone_one.state_fingerprint(),
        tombstone_one.fingerprint()
    );
}
