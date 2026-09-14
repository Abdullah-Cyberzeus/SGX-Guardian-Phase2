//! D23 bounded proof: trusted direct -> relay then relay -> relay safe switches.
use anyhow::Result;
use serde::Serialize;
use sgx_anomaly_engine::network_ai::{
    persist_decision_audit, ContextualBanditPolicy, DecisionAuditPaths, DecisionAuditRecord,
    DecisionEvidenceLinks, NetworkAiRuntimeMode, RouteHistoryEntry, RouteHistoryStore,
    RoutePredictor, RouteReward, RuntimeModeController, SimpleRouteQualityPredictor,
};
use sgx_anomaly_engine::network_ai::{
    EligibilityFilter, RouteCandidateInventory, RouteSafetyGuard, RouteSwitchState,
    RuntimeRouteApplyRequest, RuntimeRouteState, SafeRuntimeRouteController, TrafficClass,
    TrustStateSnapshot,
};
use std::fs;
use std::path::PathBuf;

fn request(
    ts_ms: u64,
    route: &str,
    current_score: f64,
    candidate_score: f64,
) -> RuntimeRouteApplyRequest {
    RuntimeRouteApplyRequest {
        ts_ms,
        requested_route_id: route.into(),
        current_score,
        candidate_score,
        current_route_failed: false,
        transport_apply_succeeds: true,
        selected_by: "d23-real-predictor-rl".into(),
        observed_rtt_ms: 12.0,
        observed_packet_loss_pct: 0.2,
        observed_throughput_mbps: 60.0,
        observed_bandwidth_utilization_pct: 35.0,
        observed_reward: Some(candidate_score),
    }
}

#[derive(Serialize)]
struct D23Evidence {
    schema_version: &'static str,
    mode: &'static str,
    direct_to_relay_applied: bool,
    relay_to_relay_applied: bool,
    old_route: String,
    selected_routes: Vec<String>,
    final_route: String,
    expected_improvement_scores: Vec<f64>,
    safety_verdicts: Vec<String>,
    rollback_ready: bool,
    route_history_updated: bool,
    d14_current_decision_written: bool,
    task2_trust_version: String,
    predictions: usize,
    rewards: usize,
    rl_decision: String,
}
fn main() -> Result<()> {
    let root = PathBuf::from("data/network_ai/d23_active_safe_switch_demo");
    fs::create_dir_all(&root)?;
    let inventory = RouteCandidateInventory::from_relays(
        "nodeA",
        "nodeB",
        TrafficClass::Operational,
        ["nodeC", "nodeD"],
    );
    let routes = EligibilityFilter.filter_at(
        inventory.candidates.clone(),
        &TrustStateSnapshot::new("task2-trusted-demo")
            .trust_peer("nodeB")
            .trust_peer("nodeC")
            .trust_peer("nodeD"),
        100_000,
    );
    let mut history = RouteHistoryStore::new(0.5, 32);
    history.record(RouteHistoryEntry {
        ts_ms: 99_000,
        route_id: "direct-nodeA-nodeB".into(),
        rtt_ms: 80.0,
        packet_loss_pct: 2.0,
        throughput_mbps: 20.0,
        bandwidth_utilization_pct: 70.0,
        route_available: true,
        route_healthy: true,
        switched_route: false,
    });
    history.record(RouteHistoryEntry {
        ts_ms: 99_000,
        route_id: "relay-nodeA-via-nodeC-nodeB".into(),
        rtt_ms: 18.0,
        packet_loss_pct: 0.2,
        throughput_mbps: 75.0,
        bandwidth_utilization_pct: 35.0,
        route_available: true,
        route_healthy: true,
        switched_route: false,
    });
    history.record(RouteHistoryEntry {
        ts_ms: 99_000,
        route_id: "relay-nodeA-via-nodeD-nodeB".into(),
        rtt_ms: 10.0,
        packet_loss_pct: 0.1,
        throughput_mbps: 90.0,
        bandwidth_utilization_pct: 40.0,
        route_available: true,
        route_healthy: true,
        switched_route: false,
    });
    let predictions = SimpleRouteQualityPredictor::default().predict(&routes.eligible, &history);
    let rewards: Vec<_> = predictions
        .predictions
        .iter()
        .map(|p| RouteReward::from_prediction_with_weights(p, 1, true, false, &Default::default()))
        .collect();
    let mut policy = ContextualBanditPolicy::new(0.1, 0.0);
    for reward in &rewards {
        policy.update_with_reward(reward);
    }
    let rl = policy.choose_exploit(&predictions);
    let score = |id: &str| {
        predictions
            .predictions
            .iter()
            .find(|p| p.route_id == id)
            .map(|p| p.quality_score)
            .unwrap_or(0.0)
    };
    let mut state = RuntimeRouteState::from_switch_state(&RouteSwitchState {
        current_route_id: "direct-nodeA-nodeB".into(),
        current_route_started_ms: 0,
        last_switch_ms: None,
        switch_timestamps_ms: vec![],
    });
    let controller = RuntimeModeController {
        route_controller: SafeRuntimeRouteController {
            safety_guard: RouteSafetyGuard::default(),
        },
    };
    let a = controller
        .execute_and_persist(
            NetworkAiRuntimeMode::Active,
            &mut state,
            &routes,
            &request(
                100_000,
                "relay-nodeA-via-nodeC-nodeB",
                score("direct-nodeA-nodeB"),
                score("relay-nodeA-via-nodeC-nodeB"),
            ),
            root.join("state.json"),
            root.join("apply1.json"),
            root.join("transitions.jsonl"),
            root.join("outcomes.jsonl"),
        )?
        .route_result
        .ok_or_else(|| anyhow::anyhow!("D23 Active mode did not invoke D11"))?;
    let b = controller
        .execute_and_persist(
            NetworkAiRuntimeMode::Active,
            &mut state,
            &routes,
            &request(
                130_000,
                "relay-nodeA-via-nodeD-nodeB",
                score("relay-nodeA-via-nodeC-nodeB"),
                score("relay-nodeA-via-nodeD-nodeB"),
            ),
            root.join("state.json"),
            root.join("apply2.json"),
            root.join("transitions.jsonl"),
            root.join("outcomes.jsonl"),
        )?
        .route_result
        .ok_or_else(|| anyhow::anyhow!("D23 Active mode did not invoke D11"))?;
    fs::write(
        root.join("predictions.json"),
        serde_json::to_vec_pretty(&predictions)?,
    )?;
    fs::write(
        root.join("rewards.json"),
        serde_json::to_vec_pretty(&rewards)?,
    )?;
    fs::write(
        root.join("rl_decision.json"),
        serde_json::to_vec_pretty(&rl)?,
    )?;
    let task2_path = root.join("task2_trust_evidence.json");
    fs::write(
        &task2_path,
        serde_json::to_vec_pretty(
            &serde_json::json!({"trust_state_version":routes.trust_state_version,"trusted_peers":["nodeB","nodeC","nodeD"],"rejected_routes":routes.rejected}),
        )?,
    )?;
    let mut d14 = DecisionAuditRecord::from_engine_outputs(
        "d23-active-safe-switch",
        130_000,
        &routes,
        &predictions,
        &rewards,
        vec![],
        None,
        None,
        DecisionEvidenceLinks {
            route_history_path: root.join("state.json").display().to_string(),
            observed_outcomes_path: root.join("outcomes.jsonl").display().to_string(),
            rewards_path: root.join("rewards.json").display().to_string(),
            degradation_events_path: "not-applicable-d23".into(),
            task1_source_path: None,
            task2_trust_source_path: Some(task2_path.display().to_string()),
            task2_trust_version: Some(routes.trust_state_version.clone()),
        },
    );
    d14.selected_route_id = Some(b.audit.requested_route_id.clone());
    d14.selected_reason = format!(
        "Active D10/D11 applied trusted direct->relay then relay->relay; final safety {:?}",
        b.audit.safety_decision.verdict
    );
    persist_decision_audit(&d14, &DecisionAuditPaths::under(&root))?;
    let evidence = D23Evidence {
        schema_version: "network-ai-d23-v1",
        mode: "Active",
        direct_to_relay_applied: a.audit.apply_result.applied,
        relay_to_relay_applied: b.audit.apply_result.applied,
        old_route: "direct-nodeA-nodeB".into(),
        selected_routes: vec![
            a.audit.requested_route_id.clone(),
            b.audit.requested_route_id.clone(),
        ],
        final_route: state.active_route_id.clone(),
        expected_improvement_scores: vec![
            a.audit.safety_decision.improvement_pct,
            b.audit.safety_decision.improvement_pct,
        ],
        safety_verdicts: vec![
            format!("{:?}", a.audit.safety_decision.verdict),
            format!("{:?}", b.audit.safety_decision.verdict),
        ],
        rollback_ready: b.audit.apply_result.rollback_route_id.is_some(),
        route_history_updated: root.join("outcomes.jsonl").exists(),
        d14_current_decision_written: root.join("current_decision.json").exists(),
        task2_trust_version: routes.trust_state_version.clone(),
        predictions: predictions.predictions.len(),
        rewards: rewards.len(),
        rl_decision: rl.decision_mode,
    };
    fs::write(
        root.join("d23_evidence.json"),
        serde_json::to_vec_pretty(&evidence)?,
    )?;
    println!("D23 Active safe switch: direct->relay applied={}, relay->relay applied={}, active={}, safety={:?}/{:?}, predictions={}, rewards={}",a.audit.apply_result.applied,b.audit.apply_result.applied,state.active_route_id,a.audit.safety_decision.verdict,b.audit.safety_decision.verdict,predictions.predictions.len(),rewards.len());
    Ok(())
}
