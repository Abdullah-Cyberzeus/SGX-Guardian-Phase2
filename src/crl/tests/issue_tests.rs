use super::*;

#[test]
fn member_with_medium_severity_rejected() {
    let _lock = test_lock();
    let env = TestEnv::new();
    let member = make_did_record(&test_did("memberA"), 1);
    let key_path = env.key_path("node-member-a");
    let km = make_key_manager(&key_path);
    let membership_vc = make_membership_vc(
        &member.did,
        CredentialRole::Member,
        issue::DEFAULT_CIRCLE_ID,
        &member.did,
        1,
    );
    save_own_membership_vc(&membership_vc);

    let error = issue::issue_revocation(
        &member,
        RevokerRole::Member,
        &km,
        IssueRequest {
            revoked_did: &test_did("target"),
            reason: RevocationReason::Compromised,
            severity: Severity::Medium,
            circle_id: issue::DEFAULT_CIRCLE_ID,
            device_id: None,
            user_id: None,
            evidence: None,
        },
    )
    .expect_err("member severity should be rejected");

    assert!(matches!(
        error,
        CrlError::MemberSeverityTooLow(Severity::Medium)
    ));
}

#[test]
fn member_with_non_critical_reason_rejected() {
    let _lock = test_lock();
    let env = TestEnv::new();
    let member = make_did_record(&test_did("memberB"), 1);
    let key_path = env.key_path("node-member-b");
    let km = make_key_manager(&key_path);
    let membership_vc = make_membership_vc(
        &member.did,
        CredentialRole::Member,
        issue::DEFAULT_CIRCLE_ID,
        &member.did,
        1,
    );
    save_own_membership_vc(&membership_vc);

    let error = issue::issue_revocation(
        &member,
        RevokerRole::Member,
        &km,
        IssueRequest {
            revoked_did: &test_did("target"),
            reason: RevocationReason::VoluntaryDeparture,
            severity: Severity::Critical,
            circle_id: issue::DEFAULT_CIRCLE_ID,
            device_id: None,
            user_id: None,
            evidence: None,
        },
    )
    .expect_err("member reason should be rejected");

    assert!(matches!(
        error,
        CrlError::MemberReasonNotCritical(reason) if reason == "voluntary_departure"
    ));
}

#[test]
fn self_revocation_rejected() {
    let _lock = test_lock();
    let env = TestEnv::new();
    let issuer = make_did_record(&test_did("self"), 1);
    let key_path = env.key_path("node-self");
    let km = make_key_manager(&key_path);
    let membership_vc = make_membership_vc(
        &issuer.did,
        CredentialRole::Owner,
        issue::DEFAULT_CIRCLE_ID,
        &issuer.did,
        0,
    );
    save_own_membership_vc(&membership_vc);

    let error = issue::issue_revocation(
        &issuer,
        RevokerRole::Owner,
        &km,
        IssueRequest {
            revoked_did: &issuer.did,
            reason: RevocationReason::Compromised,
            severity: Severity::Critical,
            circle_id: issue::DEFAULT_CIRCLE_ID,
            device_id: None,
            user_id: None,
            evidence: None,
        },
    )
    .expect_err("self revocation must be rejected");

    assert!(matches!(error, CrlError::SelfRevocation));
}

#[test]
fn owner_revocation_flips_status_list_for_issued_vc() {
    let _lock = test_lock();
    let env = TestEnv::new();
    let issuer = make_did_record(&test_did("owner"), 1);
    let key_path = env.key_path("node-owner");
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

    let target_vc = make_membership_vc(
        &test_did("target"),
        CredentialRole::Member,
        issue::DEFAULT_CIRCLE_ID,
        &issuer.did,
        7,
    );
    save_issued_vc(&target_vc);

    let entry = issue::issue_revocation(
        &issuer,
        RevokerRole::Owner,
        &km,
        IssueRequest {
            revoked_did: target_vc.subject_did(),
            reason: RevocationReason::Compromised,
            severity: Severity::Critical,
            circle_id: issue::DEFAULT_CIRCLE_ID,
            device_id: None,
            user_id: None,
            evidence: None,
        },
    )
    .expect("owner revoke");

    let crl = crate::crl::persistence::load_crl()
        .expect("load crl")
        .expect("crl exists");
    assert!(crl.contains(target_vc.subject_did()));
    assert_eq!(crl.entries.first().expect("entry").id, entry.id);

    let status_list = StatusListManager::load_or_create(&issuer, &km).expect("status list");
    assert!(status_list.is_revoked(7).expect("status bit"));
}

#[test]
fn persistence_survives_reload() {
    let _lock = test_lock();
    let env = TestEnv::new();
    let issuer = make_did_record(&test_did("ownerPersist"), 1);
    let key_path = env.key_path("node-persist");
    let km = make_key_manager(&key_path);
    let owner_vc = make_membership_vc(
        &issuer.did,
        CredentialRole::Owner,
        issue::DEFAULT_CIRCLE_ID,
        &issuer.did,
        0,
    );
    save_own_membership_vc(&owner_vc);

    let target_did = test_did("targetPersist");
    issue::issue_revocation(
        &issuer,
        RevokerRole::Owner,
        &km,
        IssueRequest {
            revoked_did: &target_did,
            reason: RevocationReason::Stolen,
            severity: Severity::High,
            circle_id: issue::DEFAULT_CIRCLE_ID,
            device_id: None,
            user_id: None,
            evidence: None,
        },
    )
    .expect("issue revoke");

    let loaded = crate::crl::persistence::load_crl()
        .expect("reload crl")
        .expect("crl exists");
    assert!(loaded.contains(&target_did));
    assert!(crate::crl::is_revoked(&target_did));
}

#[test]
fn owner_unrevoke_removes_entry_and_restores_status_list() {
    let _lock = test_lock();
    let env = TestEnv::new();
    let issuer = make_did_record(&test_did("ownerUnrevoke"), 1);
    let key_path = env.key_path("node-owner-unrevoke");
    let km = make_key_manager(&key_path);
    let owner_vc = make_membership_vc(
        &issuer.did,
        CredentialRole::Owner,
        issue::DEFAULT_CIRCLE_ID,
        &issuer.did,
        0,
    );
    save_own_membership_vc(&owner_vc);

    let target_vc = make_membership_vc(
        &test_did("unrevokeTarget"),
        CredentialRole::Member,
        issue::DEFAULT_CIRCLE_ID,
        &issuer.did,
        9,
    );
    save_issued_vc(&target_vc);

    issue::issue_revocation(
        &issuer,
        RevokerRole::Owner,
        &km,
        IssueRequest {
            revoked_did: target_vc.subject_did(),
            reason: RevocationReason::Compromised,
            severity: Severity::Critical,
            circle_id: issue::DEFAULT_CIRCLE_ID,
            device_id: None,
            user_id: None,
            evidence: None,
        },
    )
    .expect("owner revoke");
    assert!(crate::crl::is_revoked(target_vc.subject_did()));

    let status_list = StatusListManager::load_or_create(&issuer, &km).expect("status list");
    assert!(status_list.is_revoked(9).expect("status bit set"));

    let tombstone =
        issue::unrevoke_revocation(&issuer, RevokerRole::Owner, &km, target_vc.subject_did())
            .expect("owner unrevoke");

    assert!(!crate::crl::is_revoked(target_vc.subject_did()));
    let crl = crate::crl::persistence::load_crl()
        .expect("load crl")
        .expect("crl exists");
    assert!(!crl.contains(target_vc.subject_did()));
    assert_eq!(crl.tombstones.len(), 1);
    assert_eq!(crl.tombstones[0].id, tombstone.id);
    assert_eq!(
        crl.tombstones[0].original_entry_id,
        tombstone.original_entry_id
    );

    let status_list = StatusListManager::load_or_create(&issuer, &km).expect("status list");
    assert!(!status_list.is_revoked(9).expect("status bit restored"));
}

#[test]
fn owner_unrevoke_tombstone_beats_stale_gossip_and_survives_restart() {
    let _lock = test_lock();
    let env = TestEnv::new();

    let owner = make_did_record(&test_did("owner-node-a"), 1);
    let owner_km = make_key_manager(&env.key_path("node-owner-a"));
    let member_b = make_did_record(&test_did("member-node-b"), 1);
    let member_b_km = make_key_manager(&env.key_path("node-member-b"));
    let member_c = make_did_record(&test_did("member-node-c"), 1);
    let member_c_km = make_key_manager(&env.key_path("node-member-c"));

    seed_peer_document(&owner, &owner_km, "nodeA");
    seed_peer_document(&member_b, &member_b_km, "nodeB");
    seed_peer_document(&member_c, &member_c_km, "nodeC");

    let owner_vc = make_membership_vc(
        &owner.did,
        CredentialRole::Owner,
        issue::DEFAULT_CIRCLE_ID,
        &owner.did,
        0,
    );
    save_own_membership_vc(&owner_vc);

    let member_c_vc = make_membership_vc(
        &member_c.did,
        CredentialRole::Member,
        issue::DEFAULT_CIRCLE_ID,
        &owner.did,
        1,
    );
    crate::vc::persistence::save_peer(&member_c.did, &member_c_vc).expect("cache member C vc");

    let node_a = NodeCrlBase::new();
    let node_b = NodeCrlBase::new();
    let node_c = NodeCrlBase::new();
    let target_did = test_did("resurrection-target");

    let resolver = crate::did::Resolver::new(crate::did::ResolverConfig::default());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let verify_and_merge =
        |base: &NodeCrlBase,
         record: &crate::did::DidRecord,
         km: &crate::key_manager::KeyManager,
         entries: &[crate::crl::CrlEntry],
         tombstones: &[crate::crl::UnrevokeTombstone]| {
            base.activate();
            for entry in entries {
                runtime
                    .block_on(async {
                        crate::crl::verify::verify_entry(entry, &resolver, issue::DEFAULT_CIRCLE_ID)
                            .await
                    })
                    .expect("verify revoke");
            }
            for tombstone in tombstones {
                runtime
                    .block_on(async {
                        crate::crl::verify::verify_tombstone(tombstone, &resolver).await
                    })
                    .expect("verify tombstone");
            }
            crate::crl::gossip::store::merge_verified_records(
                record,
                km,
                issue::DEFAULT_CIRCLE_ID,
                entries,
                tombstones,
            )
            .expect("merge verified records")
        };

    node_c.activate();
    let revoke = issue::issue_revocation(
        &member_c,
        RevokerRole::Member,
        &member_c_km,
        IssueRequest {
            revoked_did: &target_did,
            reason: RevocationReason::Compromised,
            severity: Severity::Critical,
            circle_id: issue::DEFAULT_CIRCLE_ID,
            device_id: None,
            user_id: None,
            evidence: None,
        },
    )
    .expect("member C revoke");

    let outcome_a = verify_and_merge(
        &node_a,
        &owner,
        &owner_km,
        std::slice::from_ref(&revoke),
        &[],
    );
    let outcome_b = verify_and_merge(
        &node_b,
        &member_b,
        &member_b_km,
        std::slice::from_ref(&revoke),
        &[],
    );
    assert_eq!(outcome_a.added, 1);
    assert_eq!(outcome_b.added, 1);

    for node in [&node_a, &node_b, &node_c] {
        node.activate();
        assert!(crate::crl::is_revoked(&target_did));
    }

    node_a.activate();
    let tombstone = issue::unrevoke_revocation(&owner, RevokerRole::Owner, &owner_km, &target_did)
        .expect("owner unrevoke");
    assert!(!crate::crl::is_revoked(&target_did));

    let outcome_b = verify_and_merge(
        &node_b,
        &member_b,
        &member_b_km,
        &[],
        std::slice::from_ref(&tombstone),
    );
    let outcome_c = verify_and_merge(
        &node_c,
        &member_c,
        &member_c_km,
        &[],
        std::slice::from_ref(&tombstone),
    );
    assert_eq!(outcome_b.replaced, 1);
    assert_eq!(outcome_c.replaced, 1);

    for node in [&node_a, &node_b, &node_c] {
        node.activate();
        assert!(!crate::crl::is_revoked(&target_did));
        let crl = crate::crl::persistence::load_crl()
            .expect("reload crl")
            .expect("crl exists");
        assert!(crl.tombstone(&target_did).is_some());
    }

    let stale_a = verify_and_merge(
        &node_a,
        &owner,
        &owner_km,
        std::slice::from_ref(&revoke),
        &[],
    );
    let stale_b = verify_and_merge(
        &node_b,
        &member_b,
        &member_b_km,
        std::slice::from_ref(&revoke),
        &[],
    );
    let stale_c = verify_and_merge(&node_c, &member_c, &member_c_km, &[revoke], &[]);
    assert_eq!(stale_a.skipped, 1);
    assert_eq!(stale_b.skipped, 1);
    assert_eq!(stale_c.skipped, 1);

    for node in [&node_a, &node_b, &node_c] {
        node.activate();
        assert!(!crate::crl::is_revoked(&target_did));
    }
}

#[test]
fn member_cannot_unrevoke() {
    let _lock = test_lock();
    let env = TestEnv::new();
    let issuer = make_did_record(&test_did("ownerForMemberUnrevoke"), 1);
    let owner_key_path = env.key_path("node-owner-for-member-unrevoke");
    let owner_km = make_key_manager(&owner_key_path);
    let owner_vc = make_membership_vc(
        &issuer.did,
        CredentialRole::Owner,
        issue::DEFAULT_CIRCLE_ID,
        &issuer.did,
        0,
    );
    save_own_membership_vc(&owner_vc);

    let target_did = test_did("memberUnrevokeTarget");
    issue::issue_revocation(
        &issuer,
        RevokerRole::Owner,
        &owner_km,
        IssueRequest {
            revoked_did: &target_did,
            reason: RevocationReason::Compromised,
            severity: Severity::Critical,
            circle_id: issue::DEFAULT_CIRCLE_ID,
            device_id: None,
            user_id: None,
            evidence: None,
        },
    )
    .expect("owner revoke");

    let member = make_did_record(&test_did("memberAttemptingUnrevoke"), 1);
    let member_key_path = env.key_path("node-member-attempting-unrevoke");
    let member_km = make_key_manager(&member_key_path);

    let error = issue::unrevoke_revocation(&member, RevokerRole::Member, &member_km, &target_did)
        .expect_err("member unrevoke must be rejected");
    assert!(matches!(error, CrlError::UnrevokeRequiresOwner));
    assert!(crate::crl::is_revoked(&target_did));
}

#[test]
fn unrevoke_of_non_revoked_did_rejected() {
    let _lock = test_lock();
    let env = TestEnv::new();
    let issuer = make_did_record(&test_did("ownerNothingToUnrevoke"), 1);
    let key_path = env.key_path("node-owner-nothing-to-unrevoke");
    let km = make_key_manager(&key_path);

    let error =
        issue::unrevoke_revocation(&issuer, RevokerRole::Owner, &km, &test_did("neverRevoked"))
            .expect_err("unrevoking a never-revoked DID must fail");
    assert!(matches!(error, CrlError::NotRevoked(_)));
}
