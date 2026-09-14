//! Focused D12 proof: Task3 handoff -> Task2 review -> fresh Task2 trust ->
//! a new Task3 decision. The local summary fixture represents the authoritative
//! Task2 routing-summary contract; Task3 only reads it.

use anyhow::Result;
use sgx_anomaly_engine::network_ai::{
    persist_decision_audit, DecisionAuditPaths, DecisionAuditRecord, DecisionEvidenceLinks,
    RouteCandidateInventory, RouteHistoryStore, RoutePredictor, RouteReward, RouteSwitchState,
    SimpleRouteQualityPredictor,
};
use sgx_anomaly_engine::network_ai::{
    read_task2_trust_summary, write_post_task2_decision_audit, EligibilityFilter,
    RuntimeRouteApplyRequest, RuntimeRouteState, SafeRuntimeRouteController,
    SensitiveRouteHandoffService, SensitiveRouteReason, Task3PostTask2DecisionAudit, TrafficClass,
};
use sgx_anomaly_engine::virtual_shift::{
    ActiveVirtualShiftPolicy, ApprovalService, AttestationState, MemberPolicyApplyResult,
    PolicyApplyStatus, ReviewQueue, RoutingTrustSummaryWriter, VirtualIdentityState,
};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(value)?)?;
    Ok(())
}

fn produce_authoritative_task2_summary(
    branch_dir: &Path,
    node: &str,
    applicable_members: Vec<&str>,
    review_id: &str,
    updated_at_ms: u64,
) -> Result<PathBuf> {
    let policy_root = branch_dir.join("task2_policy_state");
    let identity_root = branch_dir.join("task2_identity_state");
    let summary_root = branch_dir.join("task2_routing_trust_state");
    let policy_id = format!("task2-review-{review_id}");
    let active_path = policy_root.join(node).join("active_policy.json");
    let apply_path = policy_root.join(node).join("latest_apply_result.json");
    let identity_path = identity_root.join(node).join("identity_state.json");
    write_json(
        &active_path,
        &ActiveVirtualShiftPolicy {
            schema_version: 1,
            policy_id: policy_id.clone(),
            circle_id: "task3-d12-proof-circle".to_string(),
            policy_version: 1,
            actions: vec![],
            rules: vec![],
            applicable_members: applicable_members.into_iter().map(str::to_string).collect(),
        },
    )?;
    write_json(
        &apply_path,
        &MemberPolicyApplyResult {
            schema_version: 1,
            member_id: node.to_string(),
            alert_id: format!("task2-review-alert-{review_id}"),
            policy_id: Some(policy_id),
            policy_version: 1,
            applied_at_ms: updated_at_ms,
            status: PolicyApplyStatus::Applied,
            reason: "Task2 lifecycle state for D12 fresh-read proof.".to_string(),
            backup_path: None,
            active_policy_path: active_path.display().to_string(),
        },
    )?;
    write_json(
        &identity_path,
        &VirtualIdentityState {
            schema_version: 1,
            member_id: node.to_string(),
            current_virtual_id: format!("virtual-{node}"),
            invalidated_virtual_ids: BTreeSet::new(),
            last_policy_version: 1,
            processed_alert_ids: BTreeSet::new(),
            attestation_state: AttestationState::Trusted,
            updated_at_ms,
        },
    )?;
    RoutingTrustSummaryWriter::new(&policy_root, &identity_root, &summary_root)
        .write_for_member(node, updated_at_ms)?;
    Ok(summary_root.join(node).join("routing_trust_summary.json"))
}

fn run_branch(
    out_dir: &Path,
    review_root: &Path,
    route_id: &str,
    timestamp: u64,
    approve: bool,
) -> Result<Task3PostTask2DecisionAudit> {
    let branch = if approve { "approved" } else { "rejected" };
    let branch_dir = out_dir.join(branch);
    let handoff = SensitiveRouteHandoffService::new(review_root, "config/node_roles.json")
        .handoff(
            timestamp,
            "nodeA",
            "nodeB",
            route_id,
            SensitiveRouteReason::NewUntrustedRelay,
            0.85,
            0.90,
            branch_dir.join("task3_handoff.json"),
        )?;
    let queue = ReviewQueue::from_role_config(review_root, "config/node_roles.json")?;
    let approval = ApprovalService::new(queue);
    let review = if approve {
        approval.approve(
            "nodeA",
            &handoff.plan_id,
            Some("Task2 owner approved the trusted relay recovery.".to_string()),
            timestamp + 10,
        )?
    } else {
        approval.reject(
            "nodeA",
            &handoff.plan_id,
            Some("Task2 owner rejected this untrusted relay.".to_string()),
            timestamp + 10,
        )?
    };

    // The existing Task2 RoutingTrustSummaryWriter produces the new
    // authoritative summary read by this subsequent Task3 cycle.
    let relay = if approve { "nodeZ" } else { "nodeY" };
    let summary_path = produce_authoritative_task2_summary(
        &branch_dir,
        "nodeB",
        if approve { vec![relay] } else { vec![] },
        &review.recommendation_id,
        timestamp + 20,
    )?;
    let latest_summary = read_task2_trust_summary(&summary_path)?;
    let inventory = RouteCandidateInventory::from_relays(
        "nodeA",
        "nodeB",
        TrafficClass::SecurityControl,
        [relay],
    );
    let eligible = EligibilityFilter.filter_at(
        inventory.candidates,
        &latest_summary.to_trust_snapshot(),
        timestamp + 21,
    );
    let requested_is_eligible = eligible
        .eligible
        .iter()
        .any(|candidate| candidate.route_id == route_id);
    let mut state = RuntimeRouteState::from_switch_state(&RouteSwitchState {
        current_route_id: "direct-nodeA-nodeB".to_string(),
        current_route_started_ms: timestamp.saturating_sub(60_000),
        last_switch_ms: Some(timestamp.saturating_sub(30_000)),
        switch_timestamps_ms: vec![timestamp.saturating_sub(30_000)],
    });
    let runtime = SafeRuntimeRouteController::default().apply_and_persist(
        &mut state,
        &eligible,
        &RuntimeRouteApplyRequest {
            ts_ms: timestamp + 21,
            requested_route_id: route_id.to_string(),
            current_score: 40.0,
            candidate_score: 60.0,
            current_route_failed: false,
            transport_apply_succeeds: true,
            selected_by: "task3-fresh-task2-state-cycle".to_string(),
            observed_rtt_ms: 12.0,
            observed_packet_loss_pct: 0.2,
            observed_throughput_mbps: 60.0,
            observed_bandwidth_utilization_pct: 35.0,
            observed_reward: Some(8.0),
        },
        branch_dir.join("current_route_state.json"),
        branch_dir.join("runtime_route_apply_result.json"),
        branch_dir.join("route_transition_audit.jsonl"),
        branch_dir.join("route_outcomes.jsonl"),
    )?;
    // D14 audit is written after the fresh Task2 trust read. It records the
    // same handoff/review IDs and whether this later Task3 cycle applied it.
    let history = RouteHistoryStore::new(0.5, 16);
    let predictions = SimpleRouteQualityPredictor::default().predict(&eligible.eligible, &history);
    let rewards = predictions
        .predictions
        .iter()
        .map(|prediction| {
            RouteReward::from_prediction_with_weights(
                prediction,
                1,
                true,
                false,
                &Default::default(),
            )
        })
        .collect::<Vec<_>>();
    let mut d14 = DecisionAuditRecord::from_engine_outputs(
        format!("task3-d24-{branch}-{}", timestamp + 21),
        timestamp + 21,
        &eligible,
        &predictions,
        &rewards,
        vec![],
        None,
        Some(latest_summary.clone()),
        DecisionEvidenceLinks {
            route_history_path: branch_dir
                .join("current_route_state.json")
                .display()
                .to_string(),
            observed_outcomes_path: branch_dir
                .join("route_outcomes.jsonl")
                .display()
                .to_string(),
            rewards_path: branch_dir.join("rewards.jsonl").display().to_string(),
            degradation_events_path: "not-applicable-d24".to_string(),
            task1_source_path: None,
            task2_trust_source_path: Some(summary_path.display().to_string()),
            task2_trust_version: Some(latest_summary.to_trust_snapshot().version),
        },
    );
    d14.selected_route_id = Some(route_id.to_string());
    d14.selected_reason = format!(
        "D24 handoff_plan_id={}; Task2 review_id={} status={:?}; fresh Task3 eligibility={} applied={}",
        handoff.plan_id, review.recommendation_id, review.status,
        requested_is_eligible, runtime.audit.apply_result.applied,
    );
    persist_decision_audit(&d14, &DecisionAuditPaths::under(&branch_dir))?;
    let decision = Task3PostTask2DecisionAudit {
        schema_version: "task3-d12-lifecycle-proof-v1".to_string(),
        handoff_plan_id: handoff.plan_id,
        task2_review_id: review.recommendation_id,
        task2_review_status: review.status,
        task2_trust_state_version: latest_summary.to_trust_snapshot().version,
        task2_trust_summary_path: summary_path.display().to_string(),
        later_task3_decision_id: format!("task3-next-cycle-{branch}-{}", timestamp + 21),
        requested_route_id: route_id.to_string(),
        route_eligible: requested_is_eligible,
        route_applied: runtime.audit.apply_result.applied,
        outcome: runtime.audit.apply_result.reason,
    };
    write_post_task2_decision_audit(branch_dir.join("later_task3_decision.json"), &decision)?;
    Ok(decision)
}

fn main() -> Result<()> {
    let out_dir = PathBuf::from("data/network_ai/task3_deliverable_12_lifecycle_proof");
    let review_root = out_dir.join("task2_owner_review_queue");
    let base_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let approved = run_branch(
        &out_dir,
        &review_root,
        "relay-nodeA-via-nodeZ-nodeB",
        base_timestamp,
        true,
    )?;
    let rejected = run_branch(
        &out_dir,
        &review_root,
        "relay-nodeA-via-nodeY-nodeB",
        base_timestamp.saturating_add(100_000),
        false,
    )?;
    anyhow::ensure!(
        approved.route_eligible && approved.route_applied,
        "approved route was not applied in fresh Task3 cycle"
    );
    anyhow::ensure!(
        !rejected.route_eligible && !rejected.route_applied,
        "rejected route was not blocked in fresh Task3 cycle"
    );

    println!("==========================================================================");
    println!("TASK 3 D12 - TASK2 DECISION TO FRESH TASK3 CYCLE PROOF");
    println!("==========================================================================");
    println!("Approved Task2 review : {:?}", approved.task2_review_status);
    println!(
        "Approved route eligible/applied: {}/{}",
        approved.route_eligible, approved.route_applied
    );
    println!("Rejected Task2 review : {:?}", rejected.task2_review_status);
    println!(
        "Rejected route eligible/applied: {}/{}",
        rejected.route_eligible, rejected.route_applied
    );
    println!("Evidence root: {}", out_dir.display());
    Ok(())
}
