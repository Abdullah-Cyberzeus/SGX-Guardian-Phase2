use super::*;

#[test]
fn verify_list_passes_for_signed_entry() {
    let _lock = test_lock();
    let env = TestEnv::new();
    let issuer = make_did_record(&test_did("verifyowner"), 1);
    let key_path = env.key_path("node-verify-owner");
    let km = make_key_manager(&key_path);
    let owner_vc = make_membership_vc(
        &issuer.did,
        CredentialRole::Owner,
        issue::DEFAULT_CIRCLE_ID,
        &issuer.did,
        0,
    );
    save_own_membership_vc(&owner_vc);
    seed_peer_document(&issuer, &km, "nodeA");

    issue::issue_revocation(
        &issuer,
        RevokerRole::Owner,
        &km,
        IssueRequest {
            revoked_did: &test_did("verifyTarget"),
            reason: RevocationReason::Compromised,
            severity: Severity::Critical,
            circle_id: issue::DEFAULT_CIRCLE_ID,
            device_id: None,
            user_id: None,
            evidence: None,
        },
    )
    .expect("issue revoke");

    let crl = crate::crl::persistence::load_crl()
        .expect("load crl")
        .expect("crl exists");
    let resolver = crate::did::Resolver::new(crate::did::ResolverConfig::default());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    runtime
        .block_on(async {
            crate::crl::verify::verify_list(&crl, &resolver, issue::DEFAULT_CIRCLE_ID).await
        })
        .expect("verify list");
}

#[test]
fn verify_list_rejects_forged_signature() {
    let _lock = test_lock();
    let env = TestEnv::new();
    let issuer = make_did_record(&test_did("forgedowner"), 1);
    let signer = make_did_record(&test_did("forgedSigner"), 1);
    let issuer_km = make_key_manager(&env.key_path("node-forged-owner"));
    let signer_km = make_key_manager(&env.key_path("node-forged-signer"));
    let owner_vc = make_membership_vc(
        &issuer.did,
        CredentialRole::Owner,
        issue::DEFAULT_CIRCLE_ID,
        &issuer.did,
        0,
    );
    save_own_membership_vc(&owner_vc);
    seed_peer_document(&issuer, &issuer_km, "nodeA");
    seed_peer_document(&signer, &signer_km, "node-forged-signer");

    let mut forged = build_entry(
        &test_did("forgedTarget"),
        &issuer.did,
        issue::DEFAULT_CIRCLE_ID,
        RevocationReason::Compromised,
        Severity::Critical,
        RevokerRole::Owner,
    );
    sign_entry_with_key(
        &mut forged,
        &signer_km,
        &format!("{}#dkp-v1", test_did("forgedSigner")),
    )
    .expect("sign forged entry");

    let mut crl = CertificateRevocationList::new(&issuer.did, issue::DEFAULT_CIRCLE_ID);
    crl.upsert(forged).expect("upsert forged entry");
    crl.recompute_root();

    let resolver = crate::did::Resolver::new(crate::did::ResolverConfig::default());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let error = runtime
        .block_on(async {
            crate::crl::verify::verify_list(&crl, &resolver, issue::DEFAULT_CIRCLE_ID).await
        })
        .expect_err("forged proof rejected");
    assert!(matches!(error, CrlError::InvalidProof(_)));
}

#[test]
fn verify_list_rejects_merkle_root_mismatch() {
    let _lock = test_lock();
    let env = TestEnv::new();
    let issuer = make_did_record(&test_did("merkleowner"), 1);
    let km = make_key_manager(&env.key_path("node-merkle-owner"));
    let owner_vc = make_membership_vc(
        &issuer.did,
        CredentialRole::Owner,
        issue::DEFAULT_CIRCLE_ID,
        &issuer.did,
        0,
    );
    save_own_membership_vc(&owner_vc);
    seed_peer_document(&issuer, &km, "nodeA");

    let entry = issue::issue_revocation(
        &issuer,
        RevokerRole::Owner,
        &km,
        IssueRequest {
            revoked_did: &test_did("merkleTarget"),
            reason: RevocationReason::Compromised,
            severity: Severity::Critical,
            circle_id: issue::DEFAULT_CIRCLE_ID,
            device_id: None,
            user_id: None,
            evidence: None,
        },
    )
    .expect("issue revoke");

    let mut crl = CertificateRevocationList::new(&issuer.did, issue::DEFAULT_CIRCLE_ID);
    crl.upsert(entry).expect("upsert");
    crl.recompute_root();
    crl.merkle_root = "deadbeef".to_string();

    let resolver = crate::did::Resolver::new(crate::did::ResolverConfig::default());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let error = runtime
        .block_on(async {
            crate::crl::verify::verify_list(&crl, &resolver, issue::DEFAULT_CIRCLE_ID).await
        })
        .expect_err("merkle mismatch rejected");
    assert!(matches!(error, CrlError::MerkleRootMismatch));
}

#[test]
fn verify_rejects_member_claiming_owner() {
    let _lock = test_lock();
    let env = TestEnv::new();
    let member = make_did_record(&test_did("forgingMember"), 1);
    let owner_did = test_did("realOwnerForForgeTest");
    let member_km = make_key_manager(&env.key_path("node-forging-member"));

    // Member holds a valid, active Member VC in this circle — cached locally
    // as it would be after real verification (see attestation_service.rs).
    let member_vc = make_membership_vc(
        &member.did,
        CredentialRole::Member,
        issue::DEFAULT_CIRCLE_ID,
        &owner_did,
        0,
    );
    crate::vc::persistence::save_peer(&member.did, &member_vc).expect("cache member vc");
    seed_peer_document(&member, &member_km, "node-forging-member");

    // Member forges revoker_role: Owner on a self-issued entry to bypass the
    // Member-only reason/severity guards (the S1 exploit).
    let forged = build_entry(
        &test_did("forgeryTarget"),
        &member.did,
        issue::DEFAULT_CIRCLE_ID,
        RevocationReason::AdministrativeRemoval,
        Severity::Low,
        RevokerRole::Owner,
    );

    let resolver = crate::did::Resolver::new(crate::did::ResolverConfig::default());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let error = runtime
        .block_on(async {
            crate::crl::verify::verify_entry(&forged, &resolver, issue::DEFAULT_CIRCLE_ID).await
        })
        .expect_err("member claiming owner role must be rejected");
    assert!(matches!(error, CrlError::InvalidStructure(_)));
}

#[test]
fn verify_rejects_member_revoking_owner() {
    let _lock = test_lock();
    let env = TestEnv::new();

    // Owner — tagged "nodeA" so known_ca_did() resolves to it.
    let owner = make_did_record(&test_did("realOwnerForOwnerRevokeTest"), 1);
    let owner_km = make_key_manager(&env.key_path("node-owner-revoke-test"));
    seed_peer_document(&owner, &owner_km, "nodeA");

    // A genuine Member with a valid, active Member VC.
    let member = make_did_record(&test_did("memberAttemptingOwnerRevoke"), 1);
    let member_km = make_key_manager(&env.key_path("node-member-revoke-test"));
    let member_vc = make_membership_vc(
        &member.did,
        CredentialRole::Member,
        issue::DEFAULT_CIRCLE_ID,
        &owner.did,
        0,
    );
    crate::vc::persistence::save_peer(&member.did, &member_vc).expect("cache member vc");
    seed_peer_document(&member, &member_km, "node-member-revoke-test");

    // Member issues an otherwise-legitimate entry (correct wire role,
    // security-critical reason/severity) but targets the Owner's DID.
    let entry = build_entry(
        &owner.did,
        &member.did,
        issue::DEFAULT_CIRCLE_ID,
        RevocationReason::Compromised,
        Severity::Critical,
        RevokerRole::Member,
    );

    let resolver = crate::did::Resolver::new(crate::did::ResolverConfig::default());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let error = runtime
        .block_on(async {
            crate::crl::verify::verify_entry(&entry, &resolver, issue::DEFAULT_CIRCLE_ID).await
        })
        .expect_err("member revoking owner must be rejected");
    assert!(
        matches!(error, CrlError::InvalidStructure(ref msg) if msg.contains("cannot revoke Owner"))
    );
}
