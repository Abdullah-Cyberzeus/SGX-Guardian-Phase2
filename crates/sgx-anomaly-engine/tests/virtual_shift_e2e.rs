//! Task 2 Issue #11: end-to-end Virtual Shift lifecycle regression suite.
//!
//! This composes the same APIs used by the runtime/demo flow: owner review,
//! policy candidate/signing, VSHIFT alert, gossip, member verification, atomic
//! apply, VirtualID rotation, re-attestation, audit, final verification, and
//! authorized false-positive override.

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use sgx_anomaly_engine::{
    roles::RoleRegistry,
    virtual_shift::{
        build_candidate_from_approved_review, set_policy_targets, sign_approved_policy,
        verify_signed_policy, vshift_alert_from_signed_policy, write_built_candidate,
        write_gossip_receipt, write_recommendation, write_signed_policy, write_vshift_alert,
        ActiveVirtualShiftPolicy, AiRemediationAction, AiRemediationPlan, AnomalyEvidence,
        AnomalyType, ApprovalService, AuditService, FinalHardeningVerifier, GossipTopology,
        GossipTransport, GuardianKeyManager, IdentityRotationStatus, InMemoryGossipTransport,
        ManualOverrideService, MemberAlertVerifier, MemberIdentityRotator, MemberPolicyApplier,
        MockAttestationConnector, MockAttestationOutcome, PolicyApplyStatus, PolicyRecommendation,
        ReAttestationService, ReAttestationStatus, RecommendationStatus, ReviewQueue, ReviewStatus,
        RiskLevel, VShiftAlert, VerificationStatus, VS01_TO_VS09_PROPOSALS, VS10_VS11_REVIEWS,
        VS12_CANDIDATES, VS13_SIGNED_POLICIES, VS14_ALERTS, VS15_GOSSIP, VS16_MEMBER_VERIFICATION,
        VS17_MEMBER_POLICY_STATE, VS18_MEMBER_IDENTITY_STATE, VS19_OVERRIDES,
    },
};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn now_ms() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn unique_root(case: &str) -> Result<PathBuf> {
    let root = std::env::temp_dir().join(format!(
        "sgx_vshift_e2e_{case}_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root)?;
    Ok(root)
}

fn write_fixture_configs(root: &Path) -> Result<(PathBuf, PathBuf, PathBuf, PathBuf, PathBuf)> {
    let config = root.join("config");
    let data = root.join("data").join("virtual_shift");
    std::fs::create_dir_all(&config)?;
    std::fs::create_dir_all(&data)?;

    let roles = config.join("node_roles.json");
    std::fs::write(
        &roles,
        r#"{"nodeA":"admin","nodeB":"member","nodeC":"member"}"#,
    )?;

    let topology = config.join("circle_gossip_topology.json");
    std::fs::write(
        &topology,
        serde_json::json!({
            "schema_version": 1,
            "circle_id": "circle-main",
            "members": ["nodeA", "nodeB", "nodeC"],
            "links": [["nodeA", "nodeB"], ["nodeB", "nodeC"]]
        })
        .to_string(),
    )?;

    let active_policy = config.join("active_virtual_shift_policy.json");
    std::fs::write(
        &active_policy,
        serde_json::to_string_pretty(&ActiveVirtualShiftPolicy {
            schema_version: 1,
            policy_id: "policy-active-v21".into(),
            circle_id: "circle-main".into(),
            policy_version: 21,
            actions: vec![],
            rules: vec![],
            applicable_members: vec!["nodeA".into()],
        })?,
    )?;

    let signer = config.join("guardian_signer.json");
    std::fs::write(
        &signer,
        r#"{"schema_version":1,"guardian_id":"guardian-test","algorithm":"ed25519"}"#,
    )?;

    Ok((data, roles, topology, active_policy, signer))
}

fn write_authorization(
    authorization: &Path,
    active_policy: &Path,
    public_key_path: &Path,
) -> Result<()> {
    std::fs::write(
        authorization,
        serde_json::json!({
            "schema_version": 1,
            "circle_id": "circle-main",
            "active_policy_path": active_policy,
            "authorized_guardians": [{
                "guardian_id": "guardian-test",
                "public_key_path": public_key_path
            }]
        })
        .to_string(),
    )?;
    Ok(())
}

fn approved_ai_plan(plan_id: &str) -> AiRemediationPlan {
    AiRemediationPlan {
        plan_id: plan_id.to_owned(),
        anomaly_id: format!("anom-{plan_id}"),
        source_node: "nodeA".into(),
        anomaly_score: 0.93,
        model_confidence: 0.9,
        severity: "High".into(),
        anomaly_metadata: serde_json::json!({"detector": "e2e_suite"}),
        justification:
            "Task 1 detected a high-confidence anomaly for the Issue #11 regression suite.".into(),
        created_at_ms: now_ms().unwrap(),
        requires_approval: true,
        auto_execute: false,
        actions: vec![AiRemediationAction {
            action_type: "tighten_firewall_rules".into(),
            target: "nodeA".into(),
            parameters: serde_json::json!({"action": "DENY_OR_RATE_LIMIT", "port": 3389}),
            requires_approval: true,
            reason: "e2e regression fixture".into(),
        }],
    }
}

fn write_matching_recommendation(
    data_root: &Path,
    recommendation_id: &str,
    anomaly_id: &str,
) -> Result<()> {
    let recommendation = PolicyRecommendation {
        recommendation_id: recommendation_id.to_owned(),
        anomaly_id: anomaly_id.to_owned(),
        source_node: "nodeA".into(),
        anomaly_type: AnomalyType::TrafficFlood,
        risk_level: RiskLevel::High,
        candidate_actions: vec![],
        anomaly_score: 0.93,
        confidence: 0.9,
        affected_peers: vec![],
        evidence: vec![AnomalyEvidence {
            feature: "conn_rate".into(),
        }],
        source_reason: "e2e regression fixture".into(),
        source_recommendation: "virtual_shift: tighten policy for nodeA;".into(),
        source_action: None,
        status: RecommendationStatus::PendingReview,
        created_at_ms: now_ms()?,
    };
    write_recommendation(data_root.join(VS01_TO_VS09_PROPOSALS), &recommendation)?;

    // Production Task2 persists the owner-review proposal under this exact
    // filename. Keep the E2E fixture identical to the production evidence
    // layout consumed by VS19/VS20.
    let production_proposal = data_root
        .join(VS01_TO_VS09_PROPOSALS)
        .join(recommendation_id)
        .join("virtual_shift_proposal.json");

    std::fs::create_dir_all(
        production_proposal
            .parent()
            .expect("production proposal directory"),
    )?;

    std::fs::write(
        production_proposal,
        serde_json::to_string_pretty(&recommendation)?,
    )?;

    Ok(())
}

#[test]
fn full_success_path_links_recommendation_through_final_lifecycle_verification() -> Result<()> {
    let root = unique_root("success")?;
    let (data_root, roles, topology, active_policy, signer_config) = write_fixture_configs(&root)?;
    let owner = "nodeA";
    let plan_id = format!("airp-nodeA-e2e-success-{}", now_ms()?);
    let plan = approved_ai_plan(&plan_id);
    let anomaly_id = plan.anomaly_id.clone();

    let queue = ReviewQueue::new(
        data_root.join(VS10_VS11_REVIEWS),
        RoleRegistry::from_path(roles.to_str().expect("fixture role path is UTF-8"))?,
    );
    let (pending, handoff) = queue.enqueue_ai_remediation_plan(plan, "e2e-suite")?;
    assert_eq!(pending.recommendation_id, plan_id);
    assert_eq!(pending.anomaly_id, anomaly_id);
    assert!(!handoff.duplicate);
    write_matching_recommendation(&data_root, &plan_id, &anomaly_id)?;

    let decided = ApprovalService::new(queue).approve(
        owner,
        &pending.recommendation_id,
        Some("e2e regression: owner approved".into()),
        now_ms()?,
    )?;
    assert_eq!(decided.status, ReviewStatus::Approved);

    let active = ActiveVirtualShiftPolicy::from_path(&active_policy)?;
    let mut built = build_candidate_from_approved_review(&active, &decided)?;
    let target_members = vec!["nodeB".to_owned(), "nodeC".to_owned()];
    set_policy_targets(&mut built, &target_members)?;
    assert_eq!(built.candidate.source_recommendation_id, plan_id);
    write_built_candidate(data_root.join(VS12_CANDIDATES), &built)?;

    let key_root = data_root.join("guardian_keys");
    let keys = GuardianKeyManager::from_config(&signer_config, &key_root)?;
    let authorization = root
        .join("config")
        .join("circle_guardian_authorization.json");
    write_authorization(
        &authorization,
        &active_policy,
        &key_root.join("guardian-test.ed25519.public"),
    )?;
    let signed = sign_approved_policy(&keys, &decided, &built, now_ms()?)?;
    verify_signed_policy(&signed)?;
    write_signed_policy(data_root.join(VS13_SIGNED_POLICIES), &signed)?;

    let issued_at_ms = now_ms()?;
    let alert_id = format!("vsa-e2e-{plan_id}");
    let decoded = VShiftAlert::decode(
        &vshift_alert_from_signed_policy(
            &decided,
            &signed,
            alert_id.clone(),
            issued_at_ms,
            issued_at_ms + 300_000,
        )?
        .encode()?,
    )?;
    assert_eq!(decoded.recommendation_id, plan_id);
    assert_eq!(decoded.anomaly_id, anomaly_id);
    write_vshift_alert(data_root.join(VS14_ALERTS), &decoded)?;

    let mut tampered = decoded.clone();
    tampered.policy_blob.push(0);
    assert!(tampered.validate().is_err());

    let mut gossip = InMemoryGossipTransport::new(GossipTopology::from_path(&topology)?)?;
    let receipt = gossip.broadcast_vshift_alert(owner, &decoded)?;
    write_gossip_receipt(data_root.join(VS15_GOSSIP), &receipt)?;
    assert_eq!(
        receipt
            .delivered
            .iter()
            .map(|delivery| delivery.node_id.clone())
            .collect::<Vec<_>>(),
        target_members
    );
    assert_ne!(
        gossip.broadcast_vshift_alert(owner, &decoded)?.status,
        "delivered"
    );

    let verification_root = data_root.join(VS16_MEMBER_VERIFICATION);
    let verifier = MemberAlertVerifier::from_config(&authorization, &verification_root)?;
    let verification_results = receipt
        .delivered
        .iter()
        .map(|delivery| verifier.verify_and_record(&delivery.node_id, &decoded, now_ms()?))
        .collect::<Result<Vec<_>>>()?;
    for result in &verification_results {
        assert_eq!(result.status, VerificationStatus::VerifiedNotApplied);
    }
    assert_eq!(
        verifier
            .verify_and_record(&receipt.delivered[0].node_id, &decoded, now_ms()?)?
            .status,
        VerificationStatus::AlreadyVerified
    );

    let apply_root = data_root.join(VS17_MEMBER_POLICY_STATE);
    let applier = MemberPolicyApplier::new(&active_policy, &verification_root, &apply_root);
    assert_eq!(
        applier
            .apply_verified_alert("nodeA", &decoded, now_ms()?)?
            .status,
        PolicyApplyStatus::Rejected
    );
    let apply_results = verification_results
        .iter()
        .map(|result| applier.apply_verified_alert(&result.member_id, &decoded, now_ms()?))
        .collect::<Result<Vec<_>>>()?;
    for result in &apply_results {
        assert_eq!(result.status, PolicyApplyStatus::Applied);
        assert!(result.backup_path.is_some());
    }

    let identity_root = data_root.join(VS18_MEMBER_IDENTITY_STATE);
    let rotator = MemberIdentityRotator::new(&apply_root, &identity_root);
    let rotation_results = apply_results
        .iter()
        .map(|result| rotator.rotate_after_applied_policy(&result.member_id, &decoded, now_ms()?))
        .collect::<Result<Vec<_>>>()?;
    for result in &rotation_results {
        assert_eq!(
            result.status,
            IdentityRotationStatus::RotatedReAttestationRequired
        );
    }

    let reattest = ReAttestationService::new(&identity_root);
    let trusted_member = rotation_results[0].member_id.clone();
    let degraded_member = rotation_results[1].member_id.clone();
    let trusted_result = reattest.complete_after_rotation(
        &trusted_member,
        &decoded,
        "mock-board",
        &MockAttestationConnector::new(MockAttestationOutcome::Pass),
        now_ms()?,
    )?;
    assert_eq!(trusted_result.status, ReAttestationStatus::Trusted);
    let degraded_result = reattest.complete_after_rotation(
        &degraded_member,
        &decoded,
        "mock-board",
        &MockAttestationConnector::new(MockAttestationOutcome::Fail),
        now_ms()?,
    )?;
    assert_eq!(degraded_result.status, ReAttestationStatus::Failed);

    let hardening = FinalHardeningVerifier::new(&data_root);
    let trusted_report = hardening.verify_and_write(&trusted_member, &decoded, now_ms()?)?;
    let degraded_report = hardening.verify_and_write(&degraded_member, &decoded, now_ms()?)?;
    assert_eq!(trusted_report.status, "pass");
    assert_eq!(degraded_report.status, "incomplete_or_failed");

    assert_eq!(
        reattest
            .complete_after_rotation(
                &trusted_member,
                &decoded,
                "mock-board",
                &MockAttestationConnector::new(MockAttestationOutcome::Pass),
                now_ms()?,
            )?
            .status,
        ReAttestationStatus::Rejected
    );
    assert_eq!(
        rotator
            .rotate_after_applied_policy(&trusted_member, &decoded, now_ms()?)?
            .status,
        IdentityRotationStatus::Rejected
    );

    let audit =
        AuditService::new(&data_root).build_and_write(&trusted_member, &decoded, now_ms()?)?;
    assert!(
        audit.steps.iter().all(|step| step.present),
        "linked audit trail is missing evidence: {:?}",
        audit
            .steps
            .iter()
            .filter(|step| !step.present)
            .collect::<Vec<_>>()
    );

    let override_root = data_root
        .join(VS19_OVERRIDES)
        .join(&decoded.recommendation_id);
    let override_service = ManualOverrideService::from_role_config(
        &apply_root,
        &override_root,
        roles.to_str().unwrap(),
    )?;
    let override_record = override_service.create_signed_revert(
        owner,
        &trusted_member,
        &decoded,
        "e2e regression: false positive",
        now_ms()?,
        &keys,
    )?;
    assert_eq!(override_record.original_alert_id, alert_id);
    assert_eq!(
        override_record.replacement_policy_version,
        override_record.original_policy_version + 1
    );
    assert!(Path::new(&override_record.signed_policy_path).is_file());
    assert!(override_service
        .create_signed_revert(
            "nodeB",
            &trusted_member,
            &decoded,
            "unauthorized attempt",
            now_ms()?,
            &keys,
        )
        .is_err());

    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn owner_rejection_blocks_the_entire_policy_pipeline() -> Result<()> {
    let root = unique_root("reject")?;
    let (data_root, roles, _topology, _active_policy, _signer_config) =
        write_fixture_configs(&root)?;
    let owner = "nodeA";
    let plan_id = format!("airp-nodeA-e2e-reject-{}", now_ms()?);
    let plan = approved_ai_plan(&plan_id);

    let queue = ReviewQueue::new(
        data_root.join(VS10_VS11_REVIEWS),
        RoleRegistry::from_path(roles.to_str().expect("fixture role path is UTF-8"))?,
    );
    let (pending, _handoff) = queue.enqueue_ai_remediation_plan(plan, "e2e-suite")?;
    let decided = ApprovalService::new(queue).reject(
        owner,
        &pending.recommendation_id,
        Some("e2e regression: owner rejected".into()),
        now_ms()?,
    )?;
    assert_eq!(decided.status, ReviewStatus::Rejected);

    assert!(!data_root.join(VS12_CANDIDATES).join(&plan_id).exists());
    assert!(!data_root.join(VS13_SIGNED_POLICIES).join(&plan_id).exists());

    let _ = std::fs::remove_dir_all(root);
    Ok(())
}
