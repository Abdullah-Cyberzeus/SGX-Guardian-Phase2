//! Friendly single-item walkthrough for the implemented Virtual Shift flow.
//! It consumes an existing Task 1 recommendation JSON; Task 1 scoring is not
//! rerun here.  `--decision approve` represents an explicit authorised owner
//! decision for this demo, never an automatic AI approval.

use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use sgx_anomaly_engine::{
    policy::PolicyTemplates,
    policy_candidate::read_task1_recommendations,
    virtual_shift::{
        aggregate_recommendations, anomaly_event_from_task1_record,
        attestation_recommendation_from_policy, build_candidate_from_approved_review,
        canonical_policy_bytes, firewall_recommendations_from_event, justification_from_aggregate,
        logging_recommendation_from_policy, quarantine_recommendation_from_policy,
        recommendation_from_event, sha256_hex, sign_approved_policy,
        vshift_alert_from_signed_policy, write_built_candidate, write_gossip_receipt,
        write_signed_policy, write_vshift_alert, ActiveVirtualShiftPolicy, ApprovalService,
        AttestationProposalResult, AuditService, FinalHardeningVerifier, FirewallProposalResult,
        GossipTopology, GossipTransport, GuardianKeyManager, InMemoryGossipTransport,
        LoggingProposalResult, MemberAlertVerifier, MemberIdentityRotator, MemberPolicyApplier,
        MemberVerificationState, MockAttestationConnector, MockAttestationOutcome,
        PolicyApplyStatus, ProposalStageNote, QuarantineProposalResult, ReAttestationService,
        ReAttestationStatus, ReviewQueue, TriggerDecision, VShiftAlert, VerificationStatus,
        VirtualShiftTriggerConfig, VirtualShiftTriggerManager, VS01_TO_VS09_PROPOSALS,
        VS10_VS11_REVIEWS, VS12_CANDIDATES, VS13_SIGNED_POLICIES, VS14_ALERTS, VS15_GOSSIP,
        VS16_MEMBER_VERIFICATION, VS17_MEMBER_POLICY_STATE, VS18_MEMBER_IDENTITY_STATE,
    },
};

fn value(args: &[String], flag: &str) -> Result<Option<String>> {
    let Some(index) = args.iter().position(|item| item == flag) else {
        return Ok(None);
    };
    let result = args
        .get(index + 1)
        .ok_or_else(|| anyhow::anyhow!("{flag} needs a value"))?
        .trim();
    if result.is_empty() {
        anyhow::bail!("{flag} must not be empty");
    }
    Ok(Some(result.to_owned()))
}

fn now_ms() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn line() {
    println!("+--------------------------+------------------------------------------------------------------+");
}
fn row(left: &str, right: impl AsRef<str>) {
    println!("| {left:<24} | {:<64} |", right.as_ref());
}

fn source_path(node: &str, run: &str) -> PathBuf {
    Path::new("data")
        .join("recommendation_records")
        .join(node)
        .join(run)
        .join("recommendations.json")
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let node = args.first().ok_or_else(|| anyhow::anyhow!(
        "usage: cargo run --example run_virtual_shift_lifecycle_demo -- <nodeA|nodeB> <run_001> [--row N] [--owner nodeA] [--decision approve|reject] [--trusted-peer nodeC] [--member nodeB] [--min-confidence 0..1] [--board-like] [--stop-after-approval] [--stop-before-apply] [--simulate-apply-failure]"
    ))?;
    let run = args
        .get(1)
        .ok_or_else(|| anyhow::anyhow!("a Task 1 run folder is required"))?;
    let source = source_path(node, run);
    let row_number: Option<usize> = value(&args, "--row")?.map(|raw| raw.parse()).transpose()?;
    let owner = value(&args, "--owner")?.unwrap_or_else(|| "nodeA".into());
    let decision = value(&args, "--decision")?.unwrap_or_else(|| "approve".into());
    let trusted_peer = value(&args, "--trusted-peer")?.unwrap_or_else(|| "nodeC".into());
    let board_like = args.iter().any(|argument| argument == "--board-like");
    let stop_after_approval = args
        .iter()
        .any(|argument| argument == "--stop-after-approval");
    let stop_before_apply = args
        .iter()
        .any(|argument| argument == "--stop-before-apply");
    let simulate_apply_failure = args
        .iter()
        .any(|argument| argument == "--simulate-apply-failure");
    if !matches!(decision.as_str(), "approve" | "reject") {
        anyhow::bail!("--decision must be approve or reject");
    }

    let task1 = read_task1_recommendations(&source)?;
    let member = value(&args, "--member")?.unwrap_or_else(|| task1.node.clone());
    if task1.node != *node {
        anyhow::bail!(
            "requested node '{node}' does not match Task 1 JSON node '{}'",
            task1.node
        );
    }
    let record = task1
        .recommendations
        .iter()
        .find(|item| {
            item.decision == "ANOMALY"
                && row_number.map_or(true, |wanted| wanted == item.display_row)
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no Task 1 ANOMALY row matched; supply --row with an anomaly row number"
            )
        })?;

    let mut event =
        anomaly_event_from_task1_record(&task1.node, record, vec![trusted_peer.clone()])?;
    // This run-qualified ID keeps a Task 1 replay traceable and avoids mixing separate saved runs.
    event.anomaly_id = format!("{run}-{}", event.anomaly_id);
    let mut trigger_config = VirtualShiftTriggerConfig::default();
    if let Some(raw) = value(&args, "--min-confidence")? {
        trigger_config.min_confidence = raw.parse()?;
    }
    trigger_config.validate()?;
    let mut trigger = VirtualShiftTriggerManager::new(trigger_config.clone())?;
    let trigger_decision = trigger.consider(&event)?;
    if !matches!(trigger_decision, TriggerDecision::Triggered) {
        anyhow::bail!(
            "selected row did not pass VS2: {trigger_decision:?}; choose a different row/run"
        );
    }

    let stamp = now_ms()?;
    let recommendation =
        recommendation_from_event(format!("vsr-{node}-{}-{stamp}", event.anomaly_id), &event);
    let templates = PolicyTemplates::from_path("config/policy_action_templates.json")?;
    let (firewall, firewall_actions, vs4) =
        match firewall_recommendations_from_event(&event, &templates)? {
            FirewallProposalResult::Proposed(values) => (
                serde_json::json!({"status":"proposed","proposals":values}),
                values,
                "bounded firewall proposal created".to_owned(),
            ),
            FirewallProposalResult::NoProposal { reason } => (
                serde_json::json!({"status":"not_proposed","reason":reason}),
                vec![],
                reason,
            ),
        };
    let (attestation, attestation_actions, vs5) =
        match attestation_recommendation_from_policy(&recommendation, &templates)? {
            AttestationProposalResult::Proposed(value) => (
                serde_json::json!({"status":"proposed","proposal":value}),
                vec![value],
                "bounded re-attestation proposal created".to_owned(),
            ),
            AttestationProposalResult::NoProposal { reason } => (
                serde_json::json!({"status":"not_proposed","reason":reason}),
                vec![],
                reason,
            ),
        };
    let (logging, logging_actions, vs6) =
        match logging_recommendation_from_policy(&recommendation, &templates)? {
            LoggingProposalResult::Proposed(value) => (
                serde_json::json!({"status":"proposed","proposal":value}),
                vec![value],
                "temporary focused logging proposal created".to_owned(),
            ),
            LoggingProposalResult::NoProposal { reason } => (
                serde_json::json!({"status":"not_proposed","reason":reason}),
                vec![],
                reason,
            ),
        };
    let (quarantine, quarantine_actions, vs7) =
        match quarantine_recommendation_from_policy(&recommendation, &trusted_peer, &templates)? {
            QuarantineProposalResult::Proposed(value) => (
                serde_json::json!({"status":"proposed","proposal":value}),
                vec![value],
                "reversible quarantine proposal created".to_owned(),
            ),
            QuarantineProposalResult::NoProposal { reason } => (
                serde_json::json!({"status":"not_proposed","reason":reason}),
                vec![],
                reason,
            ),
        };
    let aggregate = aggregate_recommendations(
        &recommendation,
        firewall_actions,
        attestation_actions,
        logging_actions,
        quarantine_actions,
    );
    let notes = vec![
        ProposalStageNote {
            stage: "VS4".into(),
            result: vs4.clone(),
        },
        ProposalStageNote {
            stage: "VS5".into(),
            result: vs5.clone(),
        },
        ProposalStageNote {
            stage: "VS6".into(),
            result: vs6.clone(),
        },
        ProposalStageNote {
            stage: "VS7".into(),
            result: vs7.clone(),
        },
    ];
    let justification = justification_from_aggregate(&recommendation, &aggregate, notes)?;
    if aggregate.actions.is_empty() {
        anyhow::bail!("this Task 1 row produced no safe VS8 action; choose another anomaly row");
    }

    let proposal_dir = Path::new("data/virtual_shift")
        .join(VS01_TO_VS09_PROPOSALS)
        .join(&recommendation.recommendation_id);
    std::fs::create_dir_all(&proposal_dir)?;
    let proposal_path = proposal_dir.join("virtual_shift_proposal.json");
    std::fs::write(
        &proposal_path,
        serde_json::to_string_pretty(&serde_json::json!({
            "schema_version": 1,
            "source_task1_recommendations_json": source,
            "source_task1_row": record.display_row,
            "vs1": {"status":"valid"}, "vs2": {"status":"triggered"},
            "vs3": recommendation, "vs4": firewall, "vs5": attestation, "vs6": logging,
            "vs7": quarantine, "vs8": aggregate, "vs9": justification,
            "approval_status": "pending_review", "advisory_only": true
        }))?,
    )?;
    let queue = ReviewQueue::from_role_config(
        Path::new("data/virtual_shift").join(VS10_VS11_REVIEWS),
        "config/node_roles.json",
    )?;
    let pending = queue.enqueue_from_proposal(&proposal_path)?;

    println!("\n============================================================================");
    println!("VIRTUAL SHIFT - FRIENDLY END-TO-END DEMO (VS1 TO VS20)");
    println!("============================================================================");
    if board_like {
        println!("BOARD-LIKE PRODUCTION SIMULATION");
        line();
        row("Telemetry source", format!("{node} Guardian / board agent"));
        row("Policy authority", format!("authorised owner: {owner}"));
        row(
            "Receiving member",
            format!("{member} Guardian / board agent"),
        );
        row("Circle transport", "simulated Nebula mTLS gossip adapter");
        row(
            "Policy enforcement",
            "safe local policy-state adapter (no OS firewall command)",
        );
        row(
            "Re-attestation",
            "mock board connector (replace with SGX/TPM connector later)",
        );
        line();
    }
    line();
    row("Task 1 node / run", format!("{node} / {run}"));
    row("Task 1 anomaly row", record.display_row.to_string());
    row("Task 1 score", format!("{:.3}", record.score));
    row(
        "Task 1 confidence",
        format!("{:.1}%", record.confidence.unwrap_or_default() * 100.0),
    );
    row(
        "Task 1 action",
        record
            .proposed_action
            .as_ref()
            .map(|action| action.kind.as_str())
            .unwrap_or("recommendation only"),
    );
    row(
        "VS1",
        "VALID — saved node, score, confidence and evidence are usable",
    );
    row(
        "VS2",
        format!(
            "TRIGGERED - score >= {:.2}, confidence >= {:.0}%; not duplicate/cooldown",
            trigger_config.min_score,
            trigger_config.min_confidence * 100.0
        ),
    );
    row(
        "VS3",
        format!(
            "{:?} risk; recommendation created",
            recommendation.risk_level
        ),
    );
    row("VS4", &vs4);
    row("VS5", &vs5);
    row("VS6", &vs6);
    row("VS7", &vs7);
    row(
        "VS8",
        format!(
            "{} final safe action(s); duplicates/conflicts resolved",
            aggregate.actions.len()
        ),
    );
    row(
        "VS9",
        "score, confidence, evidence and action reasons saved together",
    );
    row(
        "VS10",
        format!("PENDING review saved for authorised owner {owner}"),
    );
    line();
    println!("\nADMIN DECISION (explicit demo input; it is not made by the model)");
    line();
    row("Owner", &owner);
    row("Decision", &decision);
    row("Recommendation ID", &pending.recommendation_id);
    line();

    let service = ApprovalService::new(queue.clone());
    let review = if decision == "approve" {
        service.approve(
            &owner,
            &pending.recommendation_id,
            Some("Demo: authorised owner reviewed evidence.".into()),
            now_ms()?,
        )?
    } else {
        service.reject(
            &owner,
            &pending.recommendation_id,
            Some("Demo: owner rejected this proposal.".into()),
            now_ms()?,
        )?
    };
    if decision == "reject" {
        println!("\nVS11 RESULT: REJECTED. Workflow safely stops: no policy is built, signed, broadcast or applied.");
        println!(
            "Review JSON: data/virtual_shift/VS10_VS11_REVIEWS/{}/review.json",
            review.recommendation_id
        );
        return Ok(());
    }
    if stop_after_approval {
        println!("\nVS11 RESULT: APPROVED. Workflow intentionally stops here.");
        println!(
            "No candidate policy, signature, alert, verification or policy apply was created."
        );
        println!(
            "Review JSON: data/virtual_shift/VS10_VS11_REVIEWS/{}/review.json",
            review.recommendation_id
        );
        return Ok(());
    }

    // Continue from this receiving member's locally active policy when the
    // demo is run again. On a first run it uses the configured v21 policy.
    // This avoids trying to apply v22 repeatedly after that member already
    // accepted v22 in an earlier lifecycle.
    let member_root = Path::new("data")
        .join("virtual_shift")
        .join(VS17_MEMBER_POLICY_STATE)
        .join(&member);
    let canonical_member_active = member_root.join("policies").join("active_policy.json");
    let member_active = if canonical_member_active.is_file() {
        canonical_member_active
    } else {
        member_root.join("active_policy.json")
    };
    let active = if member_active.is_file() {
        ActiveVirtualShiftPolicy::from_path(&member_active)?
    } else {
        ActiveVirtualShiftPolicy::from_path("config/active_virtual_shift_policy.json")?
    };
    let mut built = build_candidate_from_approved_review(&active, &review)?;
    // A previous alert may have been verified but deliberately not applied.
    // The next candidate must still be newer than that member's latest
    // verified version, otherwise VS16 correctly rejects it as stale.
    let verification_state = Path::new("data")
        .join("virtual_shift")
        .join(VS16_MEMBER_VERIFICATION)
        .join(&member)
        .join("verification_state.json");
    let latest_verified = std::fs::read_to_string(&verification_state)
        .ok()
        .and_then(|text| serde_json::from_str::<MemberVerificationState>(&text).ok())
        .map(|state| state.latest_verified_policy_version)
        .unwrap_or(0);
    if built.candidate.policy_version <= latest_verified {
        let next_version = latest_verified
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("policy version overflow"))?;
        built.candidate.policy_version = next_version;
        built.candidate.policy_id = format!(
            "vshift-{}-v{}-{}",
            built.candidate.circle_id, next_version, built.candidate.source_recommendation_id
        );
        built.candidate.canonical_sha256.clear();
        built.canonical_bytes = canonical_policy_bytes(&built.candidate)?;
        built.candidate.canonical_sha256 = sha256_hex(&built.canonical_bytes);
    }
    let candidate_path = write_built_candidate(
        Path::new("data/virtual_shift").join(VS12_CANDIDATES),
        &built,
    )?;
    let keys = GuardianKeyManager::from_config(
        "config/guardian_signer.json",
        "data/virtual_shift/guardian_keys",
    )?;
    let signed = sign_approved_policy(&keys, &review, &built, now_ms()?)?;
    let signed_path = write_signed_policy(
        Path::new("data/virtual_shift").join(VS13_SIGNED_POLICIES),
        &signed,
    )?;
    let issued = now_ms()?;
    let alert = vshift_alert_from_signed_policy(
        &review,
        &signed,
        format!("vsa-{}-{issued}", built.candidate.policy_id),
        issued,
        issued + 300_000,
    )?;
    let _wire: VShiftAlert = VShiftAlert::decode(&alert.encode()?)?;
    let (alert_json, _alert_pb) =
        write_vshift_alert(Path::new("data/virtual_shift").join(VS14_ALERTS), &alert)?;
    let topology = GossipTopology::from_path("config/circle_gossip_topology.json")?;
    let mut gossip = InMemoryGossipTransport::new(topology)?;
    let receipt = gossip.broadcast_vshift_alert("nodeA", &alert)?;
    let receipt_path =
        write_gossip_receipt(Path::new("data/virtual_shift").join(VS15_GOSSIP), &receipt)?;

    println!("\nAPPROVED PATH");
    line();
    row("VS11", "APPROVED — authorised owner decision recorded");
    row(
        "VS12",
        format!(
            "candidate policy v{} built; active policy remains unchanged",
            built.candidate.policy_version
        ),
    );
    row(
        "VS13",
        format!(
            "Guardian {} signed the exact SHA-256 policy bytes",
            signed.signer_id
        ),
    );
    row(
        "VS14",
        format!("VSHIFT_ALERT created and protobuf encode/decode verified"),
    );
    row(
        "VS15",
        format!(
            "gossip simulated: delivered to {} member(s)",
            receipt.delivered.len()
        ),
    );

    // VS16-VS20 use the same durable evidence locations as the individual
    // demos. This is intentionally safe: no firewall/OS command or real
    // board call is made here.
    let verifier = MemberAlertVerifier::from_config(
        "config/circle_guardian_authorization.json",
        Path::new("data/virtual_shift").join(VS16_MEMBER_VERIFICATION),
    )?;
    let verification = verifier.verify_and_record(&member, &alert, now_ms()?)?;
    if verification.status != VerificationStatus::VerifiedNotApplied {
        anyhow::bail!(
            "VS16 rejected the alert for {member}: {}",
            verification.reason
        );
    }
    if stop_before_apply {
        println!("\nVS16 RESULT: VERIFIED, NOT APPLIED.");
        println!("Workflow intentionally stops before VS17. The policy is signed and verified, but no local policy state changed.");
        println!(
            "Verification JSON: data/virtual_shift/VS16_MEMBER_VERIFICATION/{}/{}/verification.json",
            member, alert.alert_id
        );
        return Ok(());
    }

    let applier = MemberPolicyApplier::new(
        "config/active_virtual_shift_policy.json",
        Path::new("data/virtual_shift").join(VS16_MEMBER_VERIFICATION),
        Path::new("data/virtual_shift").join(VS17_MEMBER_POLICY_STATE),
    );
    let applier = if simulate_apply_failure {
        applier.with_simulated_activation_failure()
    } else {
        applier
    };
    let apply = applier.apply_verified_alert(&member, &alert, now_ms()?)?;
    if apply.status != PolicyApplyStatus::Applied {
        if simulate_apply_failure && apply.status == PolicyApplyStatus::RolledBack {
            println!("\nVS17 RESULT: ROLLED BACK.");
            println!("A simulated activation failure occurred after backup; the previous local policy was restored.");
            println!(
                "Backup JSON: {}",
                apply.backup_path.as_deref().unwrap_or("not created")
            );
            println!(
                "Apply JSON : data/virtual_shift/VS17_MEMBER_POLICY_STATE/{}/{}/apply_result.json",
                member, alert.alert_id
            );
            return Ok(());
        }
        anyhow::bail!(
            "VS17 did not apply the policy for {member}: {}",
            apply.reason
        );
    }

    let rotator = MemberIdentityRotator::new(
        Path::new("data/virtual_shift").join(VS17_MEMBER_POLICY_STATE),
        Path::new("data/virtual_shift").join(VS18_MEMBER_IDENTITY_STATE),
    );
    let rotation = rotator.rotate_after_applied_policy(&member, &alert, now_ms()?)?;
    let re_attestation =
        ReAttestationService::new(Path::new("data/virtual_shift").join(VS18_MEMBER_IDENTITY_STATE))
            .complete_after_rotation(
                &member,
                &alert,
                "mock_attestation_connector",
                &MockAttestationConnector::new(MockAttestationOutcome::Pass),
                now_ms()?,
            )?;
    if re_attestation.status != ReAttestationStatus::Trusted {
        anyhow::bail!(
            "VS18 re-attestation did not make {member} trusted: {}",
            re_attestation.reason
        );
    }

    let audit =
        AuditService::new("data/virtual_shift").build_and_write(&member, &alert, now_ms()?)?;
    let final_report = FinalHardeningVerifier::new("data/virtual_shift").verify_and_write(
        &member,
        &alert,
        now_ms()?,
    )?;

    println!("\nRECEIVING MEMBER PATH ({member})");
    line();
    row(
        "VS16",
        "VERIFIED - Circle, guardian key, signature, hash, version and freshness passed",
    );
    row(
        "VS17",
        format!(
            "APPLIED - policy v{} saved locally with a backup",
            apply.policy_version
        ),
    );
    row(
        "VS18",
        format!(
            "VirtualID rotated: {} -> {}",
            rotation.old_virtual_id.as_deref().unwrap_or("-"),
            rotation.new_virtual_id.as_deref().unwrap_or("-")
        ),
    );
    row(
        "Re-attestation",
        "TRUSTED - mock connector accepted fresh proof",
    );
    row(
        "VS19",
        format!(
            "audit timeline saved: {} evidence stage(s)",
            audit.steps.len()
        ),
    );
    row(
        "VS20",
        format!(
            "{} - signature, evidence, apply and trust state checked",
            final_report.status.to_ascii_uppercase()
        ),
    );
    line();
    line();
    println!("\nSAVED EVIDENCE");
    println!("  VS1-VS9 proposal : {}", proposal_path.display());
    println!(
        "  VS10/VS11 review : data/virtual_shift/VS10_VS11_REVIEWS/{}/review.json",
        review.recommendation_id
    );
    println!("  VS12 candidate   : {}", candidate_path.display());
    println!("  VS13 signature   : {}", signed_path.display());
    println!("  VS14 alert       : {}", alert_json.display());
    println!("  VS15 receipt     : {}", receipt_path.display());
    println!(
        "  VS16 proof       : data/virtual_shift/VS16_MEMBER_VERIFICATION/{}/{}/verification.json",
        member, alert.alert_id
    );
    println!(
        "  VS17 apply       : data/virtual_shift/VS17_MEMBER_POLICY_STATE/{}/{}/apply_result.json",
        member, alert.alert_id
    );
    println!(
        "  VS18 identity    : data/virtual_shift/VS18_MEMBER_IDENTITY_STATE/{}/identity_state.json",
        member
    );
    println!(
        "  VS19 audit       : data/virtual_shift/VS19_AUDIT/{}/{}/audit_trail.json",
        member, alert.alert_id
    );
    println!(
        "  VS20 verification: data/virtual_shift/VS20_FINAL_VERIFICATION/{}/{}/vs20_report.json",
        member, alert.alert_id
    );
    println!("\nFINAL LIFECYCLE STATUS");
    line();
    row("Receiving member", &member);
    row(
        "Policy applied",
        if final_report.policy_applied {
            "YES - local signed policy is active"
        } else {
            "NO"
        },
    );
    row(
        "Member trusted",
        if final_report.re_attestation_trusted {
            "YES - mock re-attestation passed"
        } else {
            "NO"
        },
    );
    row(
        "Final verification",
        final_report.status.to_ascii_uppercase(),
    );
    line();
    Ok(())
}
