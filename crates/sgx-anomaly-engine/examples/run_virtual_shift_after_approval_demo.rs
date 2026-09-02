//! One-command continuation of Task 2 after an authorised owner has already
//! approved a VS10/VS11 review.  It deliberately does not make an approval
//! decision: VS12 through VS20 are performed from that durable review record.

use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use sgx_anomaly_engine::virtual_shift::{
    add_owner_selected_rules, build_candidate_from_approved_review, canonical_policy_bytes,
    set_policy_targets, sha256_hex, sign_approved_policy, vshift_alert_from_signed_policy,
    write_built_candidate, write_gossip_receipt, write_signed_policy, write_vshift_alert,
    ActiveVirtualShiftPolicy, AdminNetworkRuleTemplates, AuditService, FinalHardeningVerifier,
    GossipTopology, GossipTransport, GuardianKeyManager, InMemoryGossipTransport,
    MemberAlertVerifier, MemberIdentityRotator, MemberPolicyApplier, MemberVerificationState,
    MockAttestationConnector, MockAttestationOutcome, NetworkRuleAction, PolicyApplyStatus,
    ReAttestationService, ReAttestationStatus, ReviewQueue, VShiftAlert, VerificationStatus,
    VS10_VS11_REVIEWS, VS12_CANDIDATES, VS13_SIGNED_POLICIES, VS14_ALERTS, VS15_GOSSIP,
    VS16_MEMBER_VERIFICATION, VS17_MEMBER_POLICY_STATE, VS18_MEMBER_IDENTITY_STATE,
};

fn option(args: &[String], name: &str) -> Result<Option<String>> {
    let Some(index) = args.iter().position(|value| value == name) else {
        return Ok(None);
    };
    let value = args
        .get(index + 1)
        .ok_or_else(|| anyhow::anyhow!("{name} needs a value"))?
        .trim();
    if value.is_empty() {
        anyhow::bail!("{name} must not be empty");
    }
    Ok(Some(value.to_owned()))
}

fn option_values(args: &[String], name: &str) -> Result<Vec<String>> {
    let mut values = Vec::new();
    for (index, value) in args.iter().enumerate() {
        if value == name {
            let selected = args
                .get(index + 1)
                .ok_or_else(|| anyhow::anyhow!("{name} needs a value"))?
                .trim();
            if selected.is_empty() {
                anyhow::bail!("{name} must not be empty");
            }
            values.push(selected.to_owned());
        }
    }
    Ok(values)
}

fn now_ms() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}
fn line() {
    println!("+----------------------+------------------------------------------------------------------+");
}
fn row(label: &str, value: impl AsRef<str>) {
    println!("| {label:<20} | {:<64} |", value.as_ref());
}

fn compact(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let short: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{short}...")
    } else {
        short
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let recommendation_id = args.first().ok_or_else(|| anyhow::anyhow!(
        "usage: cargo run --example run_virtual_shift_after_approval_demo -- <approved-recommendation-id> [--owner nodeA] [--member nodeA] [--target-member nodeA]... [--origin nodeA] [--trusted-peer nodeC] [--use-suggested-rules] [--rule-id rule-id]..."
    ))?;
    let owner = option(&args, "--owner")?.unwrap_or_else(|| "nodeA".into());
    let member = option(&args, "--member")?.unwrap_or_else(|| owner.clone());
    let origin = option(&args, "--origin")?.unwrap_or_else(|| owner.clone());
    let trusted_peer = option(&args, "--trusted-peer")?.unwrap_or_else(|| "nodeC".into());
    let mut selected_rule_ids = option_values(&args, "--rule-id")?;
    let mut target_members = option_values(&args, "--target-member")?;
    if target_members.is_empty() {
        target_members.push(member.clone());
    }
    let use_suggested_rules = args.iter().any(|value| value == "--use-suggested-rules");

    let queue = ReviewQueue::from_role_config(
        Path::new("data/virtual_shift").join(VS10_VS11_REVIEWS),
        "config/node_roles.json",
    )?;
    let review = queue.show(&owner, recommendation_id)?;
    if !matches!(
        review.status,
        sgx_anomaly_engine::virtual_shift::ReviewStatus::Approved
    ) {
        anyhow::bail!("'{recommendation_id}' is {:?}; first approve it with the separate VS11 owner-decision demo", review.status);
    }
    if use_suggested_rules {
        let suggested = review
            .proposal
            .get("policy_for_owner_approval")
            // Backward compatibility for old pending records created before
            // the owner-facing JSON was renamed.
            .or_else(|| review.proposal.get("system_network_policy_draft"))
            .and_then(|draft| draft.get("suggested_rule_ids"))
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("this review has no system-suggested network rules; use --rule-id for an owner manual selection"))?;
        selected_rule_ids.extend(
            suggested
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned),
        );
    }
    selected_rule_ids.sort();
    selected_rule_ids.dedup();

    // The next policy starts from this receiving member's locally active version.
    let member_root = Path::new("data")
        .join("virtual_shift")
        .join(VS17_MEMBER_POLICY_STATE)
        .join(&member);
    // Prefer the simplified current policy layout.  The older `policies/`
    // path is read only as backwards-compatible evidence from prior demos.
    let current_active = member_root.join("active_policy.json");
    let legacy_active = member_root.join("policies").join("active_policy.json");
    let active_path = if current_active.is_file() {
        current_active
    } else {
        legacy_active
    };
    let active = if active_path.is_file() {
        ActiveVirtualShiftPolicy::from_path(&active_path)?
    } else {
        ActiveVirtualShiftPolicy::from_path("config/active_virtual_shift_policy.json")?
    };
    let mut built = build_candidate_from_approved_review(&active, &review)?;
    let state_path = Path::new("data")
        .join("virtual_shift")
        .join(VS16_MEMBER_VERIFICATION)
        .join(&member)
        .join("verification_state.json");
    let latest_verified = std::fs::read_to_string(state_path)
        .ok()
        .and_then(|text| serde_json::from_str::<MemberVerificationState>(&text).ok())
        .map(|state| state.latest_verified_policy_version)
        .unwrap_or(0);
    if built.candidate.policy_version <= latest_verified {
        let next = latest_verified
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("policy version overflow"))?;
        built.candidate.policy_version = next;
        built.candidate.policy_id = format!(
            "vshift-{}-v{}-{}",
            built.candidate.circle_id, next, built.candidate.source_recommendation_id
        );
        built.candidate.canonical_sha256.clear();
        built.canonical_bytes = canonical_policy_bytes(&built.candidate)?;
        built.candidate.canonical_sha256 = sha256_hex(&built.canonical_bytes);
    }
    set_policy_targets(&mut built, &target_members)?;
    if !selected_rule_ids.is_empty() {
        let templates =
            AdminNetworkRuleTemplates::from_path("config/admin_network_rule_templates.json")?;
        add_owner_selected_rules(&mut built, &templates, &selected_rule_ids)?;
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
        issued + 1_800_000,
    )?;
    let _: VShiftAlert = VShiftAlert::decode(&alert.encode()?)?;
    let (alert_path, _) =
        write_vshift_alert(Path::new("data/virtual_shift").join(VS14_ALERTS), &alert)?;
    let mut gossip = InMemoryGossipTransport::new(GossipTopology::from_path(
        "config/circle_gossip_topology.json",
    )?)?;
    let receipt = gossip.broadcast_vshift_alert(&origin, &alert)?;
    let receipt_path =
        write_gossip_receipt(Path::new("data/virtual_shift").join(VS15_GOSSIP), &receipt)?;
    let verifier = MemberAlertVerifier::from_config(
        "config/circle_guardian_authorization.json",
        Path::new("data/virtual_shift").join(VS16_MEMBER_VERIFICATION),
    )?;
    let verification = verifier.verify_and_record(&member, &alert, now_ms()?)?;
    if verification.status != VerificationStatus::VerifiedNotApplied {
        anyhow::bail!("VS16 rejected the fresh alert: {}", verification.reason);
    }
    let apply = MemberPolicyApplier::new(
        "config/active_virtual_shift_policy.json",
        Path::new("data/virtual_shift").join(VS16_MEMBER_VERIFICATION),
        Path::new("data/virtual_shift").join(VS17_MEMBER_POLICY_STATE),
    )
    .apply_verified_alert(&member, &alert, now_ms()?)?;
    if apply.status != PolicyApplyStatus::Applied {
        anyhow::bail!("VS17 did not apply: {}", apply.reason);
    }
    let received_at_ms = if member == origin {
        alert.issued_at_ms
    } else {
        receipt
            .delivery_timings
            .iter()
            .find(|timing| timing.node_id == member)
            .map(|timing| timing.received_at_ms)
            .ok_or_else(|| {
                anyhow::anyhow!("selected receiving member {member} was not delivered this alert")
            })?
    };
    let timing_report = serde_json::json!({
        "schema_version": 1,
        "purpose": "Per-member policy broadcast, verification and apply timing. Standalone values are local simulation timings; a real transport records real network receipt times.",
        "alert_id": alert.alert_id,
        "origin_node": origin,
        "broadcast_started_at_ms": receipt.broadcast_started_at_ms,
        "broadcast_completed_at_ms": receipt.broadcast_completed_at_ms,
        "all_member_delivery_timings": &receipt.delivery_timings,
        "selected_member": member,
        "selected_member_received_at_ms": received_at_ms,
        "selected_member_delivery_time_ms": received_at_ms.saturating_sub(alert.issued_at_ms),
        "verified_at_ms": verification.verified_at_ms,
        "verification_time_after_receive_ms": verification.verified_at_ms.saturating_sub(received_at_ms),
        "applied_at_ms": apply.applied_at_ms,
        "apply_time_after_verification_ms": apply.applied_at_ms.saturating_sub(verification.verified_at_ms),
        "end_to_end_time_from_broadcast_ms": apply.applied_at_ms.saturating_sub(alert.issued_at_ms)
    });
    let timing_path = receipt_path
        .parent()
        .expect("receipt parent")
        .join("member_policy_timing.json");
    std::fs::write(&timing_path, serde_json::to_string_pretty(&timing_report)?)?;
    let _rotation = MemberIdentityRotator::new(
        Path::new("data/virtual_shift").join(VS17_MEMBER_POLICY_STATE),
        Path::new("data/virtual_shift").join(VS18_MEMBER_IDENTITY_STATE),
    )
    .rotate_after_applied_policy(&member, &alert, now_ms()?)?;
    let attestation =
        ReAttestationService::new(Path::new("data/virtual_shift").join(VS18_MEMBER_IDENTITY_STATE))
            .complete_after_rotation(
                &member,
                &alert,
                "mock_attestation_connector",
                &MockAttestationConnector::new(MockAttestationOutcome::Pass),
                now_ms()?,
            )?;
    if attestation.status != ReAttestationStatus::Trusted {
        anyhow::bail!("VS18 did not make member trusted: {}", attestation.reason);
    }
    let audit =
        AuditService::new("data/virtual_shift").build_and_write(&member, &alert, now_ms()?)?;
    let final_report = FinalHardeningVerifier::new("data/virtual_shift").verify_and_write(
        &member,
        &alert,
        now_ms()?,
    )?;

    // Human-friendly explanation of what the applied policy allows or
    // denies.  This is separate from the canonical signed policy: it helps a
    // human understand the safe decision, but never changes enforcement.
    let rule_recommendations: Vec<serde_json::Value> = built
        .candidate
        .rules
        .iter()
        .map(|rule| {
            let action = match rule.action {
                NetworkRuleAction::Allow => "ALLOW",
                NetworkRuleAction::Deny => "DENY",
            };
            let (decision, user_recommendation) = match rule.action {
                NetworkRuleAction::Allow => (
                    format!(
                        "Allowed {} traffic from {} to {} on port {}.",
                        rule.protocol, rule.src, rule.dst, rule.port
                    ),
                    "Keep this access limited to the approved source range; review it if the service is no longer required.".to_string(),
                ),
                NetworkRuleAction::Deny => (
                    format!(
                        "Denied {} traffic from {} to {} on port {}.",
                        rule.protocol, rule.src, rule.dst, rule.port
                    ),
                    "Confirm that the blocked service is not required. If it is required, create a narrower owner-approved ALLOW rule instead of removing this protection.".to_string(),
                ),
            };
            serde_json::json!({
                "rule_id": rule.id,
                "action": action,
                "source": rule.src,
                "destination": rule.dst,
                "protocol": rule.protocol,
                "port": rule.port,
                "why_this_policy_decision": rule.reason,
                "decision_explanation": decision,
                "user_recommendation": user_recommendation,
            })
        })
        .collect();
    let post_policy_recommendations = serde_json::json!({
        "schema_version": 1,
        "purpose": "Human-readable explanation of applied ALLOW/DENY policy rules for the node owner.",
        "source_recommendation_id": review.recommendation_id,
        "source_anomaly_id": review.anomaly_id,
        "member": member,
        "policy_id": apply.policy_id,
        "policy_version": apply.policy_version,
        "policy_status": "applied",
        "rules": rule_recommendations,
    });
    let post_policy_dir = Path::new("data")
        .join("virtual_shift")
        .join("12_POST_POLICY_RECOMMENDATIONS")
        .join(&member)
        .join(&alert.alert_id);
    std::fs::create_dir_all(&post_policy_dir)?;
    let post_policy_path = post_policy_dir.join("allow_deny_explanations.json");
    std::fs::write(
        &post_policy_path,
        serde_json::to_string_pretty(&post_policy_recommendations)?,
    )?;

    println!("\n========================================================================");
    println!("TASK 2 - APPROVED POLICY LIFECYCLE (VS12 TO VS20)");
    println!("========================================================================");
    println!("\n1. APPROVED INPUT — owner already approved this group");
    line();
    row("Approved group", &review.recommendation_id);
    row("Source node", &review.source_node);
    row("Receiving member", &member);
    row(
        "Policy targets",
        built.candidate.applicable_members.join(", "),
    );
    row("Trusted peer", &trusted_peer);
    row(
        "Starting policy",
        format!("v{} (read-only before VS17)", active.policy_version),
    );
    line();

    println!("\n2. ADMIN-SELECTED NETWORK RULES — explicit, not guessed by AI");
    line();
    let system_rule_ids = if selected_rule_ids.is_empty() {
        "none".to_string()
    } else {
        selected_rule_ids.join(", ")
    };
    let retained_count = built
        .candidate
        .rules
        .iter()
        .filter(|rule| !selected_rule_ids.contains(&rule.id))
        .count();
    row("System-matched rules", compact(&system_rule_ids, 55));
    row("New matched count", selected_rule_ids.len().to_string());
    row("Retained active rules", retained_count.to_string());
    row(
        "Policy total rules",
        built.candidate.rules.len().to_string(),
    );
    row(
        "Safety boundary",
        "Owner template values only; no AI-invented IP/port.",
    );
    line();

    println!("\n3. BUILD, SIGN AND SEND — no member policy changes yet");
    line();
    row(
        "VS12",
        format!("policy v{} candidate built", built.candidate.policy_version),
    );
    row(
        "VS13",
        format!("Guardian {} signed candidate", signed.signer_id),
    );
    row("VS14", "fresh signed VSHIFT_ALERT created");
    row(
        "VS15",
        format!(
            "gossip delivered to {} circle member(s)",
            receipt.delivered.len()
        ),
    );
    row(
        "Delivery time",
        format!(
            "{} ms to selected member (local simulation)",
            received_at_ms.saturating_sub(alert.issued_at_ms)
        ),
    );
    line();

    println!("\n4. RECEIVER SAFETY — member checks before applying");
    line();
    row(
        "VS16",
        "member signature, hash, version and expiry verified",
    );
    row(
        "VS17",
        format!(
            "policy v{} active; backup/history saved",
            apply.policy_version
        ),
    );
    row(
        "VS18",
        format!(
            "VirtualID rotated; re-attestation: {:?}",
            attestation.status
        ),
    );
    line();

    println!("\n5. WHAT WAS ALLOWED OR DENIED — owner explanation");
    line();
    if built.candidate.rules.is_empty() {
        row(
            "Network rules",
            "No network ALLOW/DENY rule was part of this policy.",
        );
    } else {
        for rule in &built.candidate.rules {
            let action = match rule.action {
                NetworkRuleAction::Allow => "ALLOW",
                NetworkRuleAction::Deny => "DENY",
            };
            let source = if selected_rule_ids.contains(&rule.id) {
                "NEW"
            } else {
                "RETAINED"
            };
            row(
                &format!("{source} {action}"),
                format!(
                    "{} | {}:{} | {} -> {}",
                    rule.id, rule.protocol, rule.port, rule.src, rule.dst
                ),
            );
            row("Why", compact(&rule.reason, 57));
            let next_action = match rule.action {
                NetworkRuleAction::Allow => {
                    "Keep only for this approved source/service; review if no longer needed."
                }
                NetworkRuleAction::Deny => {
                    "Keep blocked; if business requires it, add a narrower owner-approved ALLOW rule."
                }
            };
            row("Owner next action", compact(next_action, 57));
        }
    }
    row("Saved explanation", post_policy_path.display().to_string());
    line();

    println!("\n6. FINAL CHECK — evidence is saved and lifecycle is complete");
    line();
    row(
        "VS19",
        format!("{} linked audit stage(s) recorded", audit.steps.len()),
    );
    row(
        "VS20",
        format!(
            "final verification: {}",
            final_report.status.to_ascii_uppercase()
        ),
    );
    row("Final result", "APPLIED + TRUSTED (mock board connector)");
    line();
    println!("\nSAVED EVIDENCE");
    println!("  VS12 candidate : {}", candidate_path.display());
    println!("  VS13 signature : {}", signed_path.display());
    println!("  VS14 alert     : {}", alert_path.display());
    println!("  VS15 receipt   : {}", receipt_path.display());
    println!("  Delivery timing: {}", timing_path.display());
    println!("  Active policy                  : data/virtual_shift/09_MEMBER_ACTIVE_POLICIES/{member}/active_policy.json");
    println!("  Previous policy history         : data/virtual_shift/09_MEMBER_ACTIVE_POLICIES/{member}/backup_history/");
    println!("  Policy state summary            : data/virtual_shift/09_MEMBER_ACTIVE_POLICIES/{member}/policy_state_summary.json");
    println!(
        "  ALLOW/DENY explanation          : {}",
        post_policy_path.display()
    );
    println!("  Final lifecycle report          : data/virtual_shift/13_FINAL_POLICY_LIFECYCLE_CHECKS/{member}/{}/vs20_report.json", alert.alert_id);
    Ok(())
}
