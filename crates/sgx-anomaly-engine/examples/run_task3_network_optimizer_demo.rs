use anyhow::{Context, Result};
use serde::Serialize;
use sgx_anomaly_engine::network_ai::{
    append_degradation_prediction_jsonl, append_observation_jsonl, persist_current_observation,
    persist_decision_audit, read_task1_route_signal, read_task2_trust_summary,
    ContextualBanditPolicy, DecisionAuditPaths, DecisionAuditRecord, DecisionEvidenceLinks,
    DegradationPredictor, EligibilityFilter, EligibleRouteSet, MultiRelayLoadBalancer,
    NetworkTelemetryAdapter, NetworkTelemetryContext, RouteCandidateInventory, RouteHistoryEntry,
    RouteHistoryStore, RouteKind, RouteReward, RouteSwitchState, RuntimeRouteApplyRequest,
    RuntimeRouteState, SafeRuntimeRouteController, SimpleDegradationPredictor,
    SimpleRouteQualityPredictor, Task1RouteSignal, Task2RoutingTrustSummary, TrafficClass,
    TrustStateSnapshot,
};
use sgx_anomaly_engine::telemetry::RawSample;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
struct CandidateInventoryReport {
    source_node: String,
    destination_node: String,
    traffic_class: TrafficClass,
    candidates: Vec<sgx_anomaly_engine::network_ai::RouteCandidate>,
}

#[derive(Debug, Serialize)]
struct IntegrationBridgeAudit {
    task1_signal: Option<Task1RouteSignal>,
    task2_trust_summary: Option<Task2RoutingTrustSummary>,
    bridge_result: String,
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|window| window[0] == flag)
        .map(|window| window[1].clone())
}

fn parse_traffic_class(value: &str) -> TrafficClass {
    match value.to_ascii_lowercase().as_str() {
        "security-control" | "security" | "control" | "policy" | "vshift_alert" => {
            TrafficClass::SecurityControl
        }
        _ => TrafficClass::Operational,
    }
}

fn print_kv(label: &str, value: impl std::fmt::Display) {
    println!("{:<30}: {}", label, value);
}

fn write_json(path: impl AsRef<Path>, value: &impl Serialize) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(value)?;
    fs::write(path, json).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn route_status_line(route_id: &str, status: &str, reason: &str) {
    println!("{:<48} {:<8} {}", route_id, status, reason);
}

fn print_eligible_routes(routes: &EligibleRouteSet) {
    println!();
    println!("4. TRUST ELIGIBILITY FILTER - runs before AI scoring");
    println!("{:<48} {:<8} Reason", "Route", "Status");
    println!("{}", "-".repeat(82));

    for route in &routes.eligible {
        route_status_line(&route.route_id, "PASS", "trusted/healthy/allowed");
    }

    for rejected in &routes.rejected {
        route_status_line(
            &rejected.route_id,
            "REJECT",
            &format!("{:?}", rejected.reason),
        );
    }
}

fn usage() {
    eprintln!(
        "Usage: cargo run --example run_task3_network_optimizer_demo -- [--traffic-class operational|security-control] [--source-node nodeA] [--destination-node nodeB] [--out-dir data/network_ai] [--task1-recommendation path] [--task2-trust-state path] [--current-route-failed]"
    );
}

fn latest_task1_recommendation(node: &str) -> Option<PathBuf> {
    let root = PathBuf::from(format!("data/recommendation_records/{node}"));
    let entries = fs::read_dir(root).ok()?;
    let mut candidates = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path().join("recommendations.json"))
        .filter(|path| path.exists())
        .filter_map(|path| {
            let modified = fs::metadata(&path).ok()?.modified().ok()?;
            Some((modified, path))
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|(modified, _)| *modified);
    candidates.pop().map(|(_, path)| path)
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        usage();
        return Ok(());
    }

    let source_node = arg_value(&args, "--source-node").unwrap_or_else(|| "nodeA".to_string());
    let destination_node =
        arg_value(&args, "--destination-node").unwrap_or_else(|| "nodeB".to_string());
    let traffic_class = arg_value(&args, "--traffic-class")
        .map(|value| parse_traffic_class(&value))
        .unwrap_or(TrafficClass::SecurityControl);
    let current_route_failed = args.iter().any(|arg| arg == "--current-route-failed");
    let out_dir = PathBuf::from(
        arg_value(&args, "--out-dir")
            .unwrap_or_else(|| "data/network_ai/task3_deliverable_1_2_demo".to_string()),
    );
    let task1_recommendation_path = arg_value(&args, "--task1-recommendation")
        .map(PathBuf::from)
        .or_else(|| latest_task1_recommendation(&source_node));
    let task2_trust_state_path = arg_value(&args, "--task2-trust-state")
        .map(PathBuf::from)
        .or_else(|| {
            let path = PathBuf::from(format!(
                "data/virtual_shift/15_ROUTING_TRUST_STATE/{destination_node}/routing_trust_summary.json"
            ));
            path.exists().then_some(path)
        });

    let task1_signal = task1_recommendation_path
        .as_ref()
        .filter(|path| path.exists())
        .map(read_task1_route_signal)
        .transpose()?;
    let task2_trust_summary = task2_trust_state_path
        .as_ref()
        .filter(|path| path.exists())
        .map(read_task2_trust_summary)
        .transpose()?;

    let raw = RawSample {
        ts_ms: 1788433000000,
        nebula_mbps: 42.0,
        relay_ratio: 0.25,
        cot_latency_avg_ms: 18.5,
        conn_total: 7,
        ..Default::default()
    };

    let telemetry_ctx = NetworkTelemetryContext {
        traffic_class,
        route_kind: RouteKind::DirectP2p,
        packet_loss_pct: 1.2,
        bandwidth_capacity_mbps: Some(100.0),
        ..NetworkTelemetryContext::operational(
            &source_node,
            &destination_node,
            &destination_node,
            format!("direct-{source_node}-{destination_node}"),
        )
    };

    let adapter = NetworkTelemetryAdapter::default();
    let observation = adapter.observe(&raw, telemetry_ctx);

    let mut inventory = RouteCandidateInventory::from_relays(
        &source_node,
        &destination_node,
        traffic_class,
        ["nodeC", "nodeD"],
    );

    // Synthetic demo health: nodeD path is present but cannot be used because
    // Task2 trust state quarantines nodeD below. This proves that route
    // discovery and eligibility are separate stages.
    for candidate in &mut inventory.candidates {
        if candidate.relay_ids.iter().any(|relay| relay == "nodeD") {
            candidate.observed_available = true;
            candidate.observed_healthy = true;
        }
    }

    let trust_state = task2_trust_summary
        .as_ref()
        .map(Task2RoutingTrustSummary::to_trust_snapshot)
        .unwrap_or_else(|| TrustStateSnapshot::missing("task2-routing-trust-state-missing"));
    let trust_state = if task2_trust_summary.is_some() {
        trust_state.trust_peer("nodeC").quarantine_peer("nodeD")
    } else {
        trust_state
    };
    for candidate in &mut inventory.candidates {
        candidate.metadata.trust_state_version_seen = Some(trust_state.version.clone());
    }

    let eligible_routes =
        EligibilityFilter.filter_at(inventory.candidates.clone(), &trust_state, raw.ts_ms);

    let observation_path = out_dir.join("current_observation.json");
    let history_path = out_dir.join("route_observations.jsonl");
    let candidates_path = out_dir.join("candidate_inventory.json");
    let eligible_path = out_dir.join("eligible_routes.json");
    let route_history_path = out_dir.join("route_history_store.json");
    let route_outcomes_path = out_dir.join("route_outcomes.jsonl");
    let prediction_path = out_dir.join("route_predictions.json");
    let degradation_path = out_dir.join("degradation_predictions.json");
    let degradation_events_path = out_dir.join("degradation_predictions.jsonl");
    let rewards_path = out_dir.join("route_rewards.json");
    let rl_policy_path = out_dir.join("rl_policy.json");
    let rl_decision_path = out_dir.join("rl_decision.json");
    let safety_decision_path = out_dir.join("route_safety_decision.json");
    let apply_result_path = out_dir.join("route_apply_result.json");
    let runtime_route_state_path = out_dir.join("current_route_state.json");
    let runtime_apply_result_path = out_dir.join("runtime_route_apply_result.json");
    let route_transition_audit_path = out_dir.join("route_transition_audit.jsonl");
    let relay_weights_path = out_dir.join("relay_weights.json");
    let task1_signal_path = out_dir.join("task1_route_signal.json");
    let task2_trust_summary_path = out_dir.join("task2_trust_summary.json");
    let integration_audit_path = out_dir.join("task3_integration_audit.json");
    let decision_audit_paths = DecisionAuditPaths::under(&out_dir);

    persist_current_observation(&observation_path, &observation)?;
    append_observation_jsonl(&history_path, &observation)?;
    write_json(
        &candidates_path,
        &CandidateInventoryReport {
            source_node: source_node.clone(),
            destination_node: destination_node.clone(),
            traffic_class,
            candidates: inventory.candidates.clone(),
        },
    )?;
    write_json(&eligible_path, &eligible_routes)?;

    let mut history_store = RouteHistoryStore::new(0.5, 20);
    history_store.record_observation(&observation);
    history_store.record(RouteHistoryEntry {
        ts_ms: raw.ts_ms + 1000,
        route_id: format!("direct-{source_node}-{destination_node}"),
        rtt_ms: 34.0,
        packet_loss_pct: 3.8,
        throughput_mbps: 28.0,
        bandwidth_utilization_pct: 42.0,
        route_available: true,
        route_healthy: true,
        switched_route: false,
    });
    history_store.record(RouteHistoryEntry {
        ts_ms: raw.ts_ms + 1000,
        route_id: format!("relay-{source_node}-via-nodeC-{destination_node}"),
        rtt_ms: 14.0,
        packet_loss_pct: 0.4,
        throughput_mbps: 55.0,
        bandwidth_utilization_pct: 58.0,
        route_available: true,
        route_healthy: true,
        switched_route: true,
    });
    history_store.record(RouteHistoryEntry {
        ts_ms: raw.ts_ms + 2000,
        route_id: format!("relay-{source_node}-via-nodeC-{destination_node}"),
        rtt_ms: 17.0,
        packet_loss_pct: 0.7,
        throughput_mbps: 52.0,
        bandwidth_utilization_pct: 92.0,
        route_available: true,
        route_healthy: true,
        switched_route: false,
    });
    history_store.record(RouteHistoryEntry {
        ts_ms: raw.ts_ms + 1000,
        route_id: format!("relay-{source_node}-via-nodeD-{destination_node}"),
        rtt_ms: 0.0,
        packet_loss_pct: 100.0,
        throughput_mbps: 0.0,
        bandwidth_utilization_pct: 100.0,
        route_available: false,
        route_healthy: false,
        switched_route: false,
    });
    history_store.save_json(&route_history_path)?;

    let predictor = SimpleRouteQualityPredictor::default();
    let predictions = predictor.predict_with_task1_signal(
        &eligible_routes.eligible,
        &history_store,
        task1_signal.as_ref(),
        raw.ts_ms + 2_000,
    );
    write_json(&prediction_path, &predictions)?;

    let degradation_predictor = SimpleDegradationPredictor::default();
    let degradation_predictions = history_store
        .entries_by_route
        .iter()
        .map(|(route_id, entries)| degradation_predictor.predict(route_id, entries))
        .collect::<Vec<_>>();
    write_json(&degradation_path, &degradation_predictions)?;
    for prediction in &degradation_predictions {
        append_degradation_prediction_jsonl(&degradation_events_path, prediction)?;
    }

    let rewards = predictions
        .predictions
        .iter()
        .map(|prediction| {
            let hop_count = inventory
                .candidates
                .iter()
                .find(|candidate| candidate.route_id == prediction.route_id)
                .map(|candidate| candidate.hop_count)
                .unwrap_or(0);
            RouteReward::from_prediction(prediction, hop_count, true, false)
        })
        .collect::<Vec<_>>();
    write_json(&rewards_path, &rewards)?;

    let mut rl_policy = ContextualBanditPolicy::default();
    for reward in &rewards {
        rl_policy.update_with_reward(reward);
    }
    let rl_decision = rl_policy.choose_exploit(&predictions);
    rl_policy.save_json(&rl_policy_path)?;
    write_json(&rl_decision_path, &rl_decision)?;

    let current_route_id = format!("direct-{source_node}-{destination_node}");
    let current_score = predictions
        .predictions
        .iter()
        .find(|prediction| prediction.route_id == current_route_id)
        .map(|prediction| prediction.quality_score)
        .unwrap_or(0.0);
    let candidate_score = rl_decision
        .selected_route_id
        .as_ref()
        .and_then(|route_id| {
            predictions
                .predictions
                .iter()
                .find(|prediction| prediction.route_id == *route_id)
        })
        .map(|prediction| prediction.quality_score)
        .unwrap_or(current_score);
    let switch_state = RouteSwitchState {
        current_route_id: current_route_id.clone(),
        current_route_started_ms: raw.ts_ms.saturating_sub(60_000),
        last_switch_ms: Some(raw.ts_ms.saturating_sub(30_000)),
        switch_timestamps_ms: vec![raw.ts_ms.saturating_sub(30_000)],
    };
    let requested_route_id = rl_decision
        .selected_route_id
        .clone()
        .unwrap_or_else(|| current_route_id.clone());
    let selected_reward = rewards
        .iter()
        .find(|reward| reward.route_id == requested_route_id)
        .map(|reward| reward.total_reward);
    let mut runtime_state = RuntimeRouteState::from_switch_state(&switch_state);
    let runtime_result = SafeRuntimeRouteController::default().apply_and_persist(
        &mut runtime_state,
        &eligible_routes,
        &RuntimeRouteApplyRequest {
            ts_ms: raw.ts_ms,
            requested_route_id,
            current_score,
            candidate_score,
            current_route_failed,
            transport_apply_succeeds: true,
            selected_by: rl_decision.decision_mode.clone(),
            observed_rtt_ms: observation.rtt_ms,
            observed_packet_loss_pct: observation.packet_loss_pct,
            observed_throughput_mbps: observation.throughput_mbps,
            observed_bandwidth_utilization_pct: observation.bandwidth_utilization_pct,
            observed_reward: selected_reward,
        },
        &runtime_route_state_path,
        &runtime_apply_result_path,
        &route_transition_audit_path,
        &route_outcomes_path,
    )?;
    let safety_decision = runtime_result.audit.safety_decision.clone();
    let apply_result = runtime_result.audit.apply_result.clone();
    write_json(&safety_decision_path, &safety_decision)?;
    write_json(&apply_result_path, &apply_result)?;
    let relay_weights =
        MultiRelayLoadBalancer::default().calculate(&eligible_routes.eligible, &predictions);
    write_json(&relay_weights_path, &relay_weights)?;
    if let Some(signal) = &task1_signal {
        write_json(&task1_signal_path, signal)?;
    }
    if let Some(summary) = &task2_trust_summary {
        write_json(&task2_trust_summary_path, summary)?;
    }
    let bridge_result = if task1_signal.is_some() || task2_trust_summary.is_some() {
        "Task3 consumed available Task1/Task2 JSON signals read-only; Task2 state was not mutated."
    } else {
        "No Task1/Task2 JSON paths were available; Task3 used safe defaults and did not select a route."
    };
    write_json(
        &integration_audit_path,
        &IntegrationBridgeAudit {
            task1_signal: task1_signal.clone(),
            task2_trust_summary: task2_trust_summary.clone(),
            bridge_result: bridge_result.to_string(),
        },
    )?;
    let decision_audit = DecisionAuditRecord::from_engine_outputs(
        format!(
            "task3-decision-{source_node}-{destination_node}-{}",
            raw.ts_ms
        ),
        raw.ts_ms,
        &eligible_routes,
        &predictions,
        &rewards,
        degradation_predictions.clone(),
        task1_signal.clone(),
        task2_trust_summary.clone(),
        DecisionEvidenceLinks {
            route_history_path: route_history_path.display().to_string(),
            observed_outcomes_path: route_outcomes_path.display().to_string(),
            rewards_path: rewards_path.display().to_string(),
            degradation_events_path: degradation_events_path.display().to_string(),
            task1_source_path: task1_recommendation_path
                .as_ref()
                .map(|path| path.display().to_string()),
            task2_trust_source_path: task2_trust_state_path
                .as_ref()
                .map(|path| path.display().to_string()),
            task2_trust_version: Some(eligible_routes.trust_state_version.clone()),
        },
    );
    persist_decision_audit(&decision_audit, &decision_audit_paths)?;

    println!("==========================================================================");
    println!(
        "TASK 3 - NETWORK OPTIMIZER DEMO (DELIVERABLE 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9 + 10 + 11)"
    );
    println!("==========================================================================");

    println!();
    println!("1. TRAFFIC CLASSIFICATION");
    print_kv("Source node", &source_node);
    print_kv("Destination node", &destination_node);
    print_kv("Traffic class", format!("{:?}", observation.traffic_class));
    print_kv("Priority", format!("{:?}", observation.priority_class));

    println!();
    println!("2. NETWORK OBSERVATION - Task1-compatible metrics reused");
    print_kv("Current route", &observation.current_route_id);
    print_kv("RTT / latency", format!("{:.1} ms", observation.rtt_ms));
    print_kv(
        "Packet loss",
        format!("{:.1} %", observation.packet_loss_pct),
    );
    print_kv(
        "Throughput",
        format!("{:.1} Mbps", observation.throughput_mbps),
    );
    print_kv(
        "Bandwidth utilization",
        format!("{:.1} %", observation.bandwidth_utilization_pct),
    );
    print_kv("Relay hops", observation.relay_hops);
    print_kv(
        "Live attestation required",
        observation.live_attestation_required,
    );
    print_kv(
        "Task1 metrics reused",
        observation
            .task1_reused_metrics
            .iter()
            .map(|metric| metric.name.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    );

    println!();
    println!("3. ROUTE CANDIDATE INVENTORY");
    println!("{:<48} {:<14} {:<6} Health", "Route", "Kind", "Hops");
    println!("{}", "-".repeat(82));
    for candidate in &inventory.candidates {
        println!(
            "{:<48} {:<14} {:<6} available={}, healthy={}",
            candidate.route_id,
            format!("{:?}", candidate.kind),
            candidate.hop_count,
            candidate.observed_available,
            candidate.observed_healthy
        );
    }

    print_eligible_routes(&eligible_routes);

    println!();
    println!("5. HISTORICAL ROUTE PERFORMANCE STORE");
    println!(
        "{:<48} {:<8} {:<10} {:<10} {:<11} Success",
        "Route", "Samples", "EWMA RTT", "EWMA Loss", "EWMA Mbps"
    );
    println!("{}", "-".repeat(100));
    for stats in history_store.stats_by_route.values() {
        println!(
            "{:<48} {:<8} {:<10.1} {:<10.1} {:<11.1} {:.0}%",
            stats.route_id,
            stats.sample_count,
            stats.ewma_latency_ms,
            stats.ewma_loss_pct,
            stats.ewma_throughput_mbps,
            stats.success_rate * 100.0
        );
    }

    println!();
    println!("6. ROUTE QUALITY PREDICTION MODEL");
    println!(
        "{:<48} {:<8} {:<10} {:<10} {:<11} {:<10} Reason",
        "Route", "Score", "Latency", "Loss", "Throughput", "Confidence"
    );
    println!("{}", "-".repeat(140));
    for prediction in &predictions.predictions {
        println!(
            "{:<48} {:<8.2} {:<10.1} {:<10.1} {:<11.1} {:<10} {}",
            prediction.route_id,
            prediction.quality_score,
            prediction.expected_latency_ms,
            prediction.expected_loss_pct,
            prediction.expected_throughput_mbps,
            format!("{:.0}%", prediction.confidence * 100.0),
            prediction.reason
        );
    }
    print_kv(
        "Selected best eligible route",
        predictions
            .selected_route_id
            .as_deref()
            .unwrap_or("no eligible route"),
    );
    print_kv("Predictor version", &predictions.model_version);

    println!();
    println!("7. NETWORK DEGRADATION PREDICTOR");
    println!(
        "{:<48} {:<12} {:<10} Contributors",
        "Route", "Probability", "Horizon"
    );
    println!("{}", "-".repeat(110));
    for prediction in &degradation_predictions {
        println!(
            "{:<48} {:<12} {:<10} {}",
            prediction.route_id,
            format!("{:.0}%", prediction.probability * 100.0),
            format!("{}s", prediction.horizon_seconds),
            prediction.contributors.join(", ")
        );
    }

    println!();
    println!("8. REWARD + CONTEXTUAL BANDIT POLICY");
    println!("{:<48} {:<10} Reason", "Route", "Reward");
    println!("{}", "-".repeat(120));
    for reward in &rewards {
        println!(
            "{:<48} {:<10.2} {}",
            reward.route_id, reward.total_reward, reward.reason
        );
    }
    print_kv(
        "RL selected route",
        rl_decision
            .selected_route_id
            .as_deref()
            .unwrap_or("no eligible route"),
    );
    print_kv("RL version", &rl_decision.rl_version);
    print_kv("RL mode", &rl_decision.decision_mode);

    println!();
    println!("9. SAFETY GUARD AND SAFE ROUTE SWITCHING");
    print_kv("Current route", &safety_decision.current_route_id);
    print_kv(
        "Candidate route",
        safety_decision
            .candidate_route_id
            .as_deref()
            .unwrap_or("none"),
    );
    print_kv("Safety verdict", format!("{:?}", safety_decision.verdict));
    print_kv("Allowed", safety_decision.allowed);
    print_kv("Hard failover", safety_decision.hard_failover);
    print_kv("Recent switches", safety_decision.recent_switches_in_window);
    print_kv(
        "Improvement",
        format!("{:.1}%", safety_decision.improvement_pct),
    );
    print_kv("Reason", &safety_decision.reason);
    print_kv("Applied", apply_result.applied);
    print_kv("Active route", &apply_result.active_route_id);
    print_kv(
        "Rollback route",
        apply_result.rollback_route_id.as_deref().unwrap_or("none"),
    );

    println!();
    println!("10. MULTI-RELAY LOAD BALANCING");
    println!("{:<48} {:<10} Reason", "Relay route", "Weight");
    println!("{}", "-".repeat(115));
    if relay_weights.weights.is_empty() {
        println!("No eligible relay routes available for weighting.");
    } else {
        for weight in &relay_weights.weights {
            println!(
                "{:<48} {:<10.2} {}",
                weight.route_id, weight.weight, weight.reason
            );
        }
    }

    println!();
    println!("11. TASK1 + TASK2 INTEGRATION BRIDGES");
    print_kv(
        "Task1 signal source",
        task1_recommendation_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "not supplied/found".to_string()),
    );
    if let Some(signal) = &task1_signal {
        print_kv("Task1 node", &signal.node);
        print_kv("Task1 recommendations", signal.recommendation_count);
        print_kv(
            "Max anomaly score",
            signal
                .max_anomaly_score
                .map(|value| format!("{value:.3}"))
                .unwrap_or_else(|| "n/a".to_string()),
        );
        print_kv(
            "Task1 evidence",
            if signal.top_evidence_features.is_empty() {
                "none".to_string()
            } else {
                signal.top_evidence_features.join(", ")
            },
        );
    }
    print_kv(
        "Task2 trust source",
        task2_trust_state_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "not supplied/found".to_string()),
    );
    if let Some(summary) = &task2_trust_summary {
        print_kv("Task2 node", &summary.node_id);
        print_kv("Task2 trust", &summary.trust_status);
        print_kv("Routing allowed", summary.routing_allowed);
        print_kv(
            "Active policy",
            summary.active_policy_id.as_deref().unwrap_or("none"),
        );
        print_kv("Applicable members", summary.applicable_members.join(", "));
    }
    print_kv("Bridge result", bridge_result);

    println!();
    println!("12. GUARDED RUNTIME ROUTE CONTROLLER");
    print_kv(
        "Transition",
        format!("{:?}", runtime_result.audit.transition),
    );
    print_kv(
        "Already eligible",
        runtime_result.audit.requested_route_was_eligible,
    );
    print_kv(
        "Owner approval",
        "not required for safe runtime route change",
    );
    print_kv(
        "Runtime active route",
        &runtime_result.state.active_route_id,
    );
    print_kv(
        "Outcome reward fed",
        selected_reward
            .map(|v| format!("{v:.2}"))
            .unwrap_or_else(|| "none".to_string()),
    );

    println!();
    println!("SAVED EVIDENCE");
    print_kv("Observation JSON", observation_path.display());
    print_kv("Observation history", history_path.display());
    print_kv("Candidate inventory", candidates_path.display());
    print_kv("Eligible routes", eligible_path.display());
    print_kv("Route history store", route_history_path.display());
    print_kv("Observed route outcomes", route_outcomes_path.display());
    print_kv("Route predictions", prediction_path.display());
    print_kv("Degradation predictions", degradation_path.display());
    print_kv("Degradation event log", degradation_events_path.display());
    print_kv("Route rewards", rewards_path.display());
    print_kv("RL policy", rl_policy_path.display());
    print_kv("RL decision", rl_decision_path.display());
    print_kv("Safety decision", safety_decision_path.display());
    print_kv("Apply result", apply_result_path.display());
    print_kv("Runtime route state", runtime_route_state_path.display());
    print_kv("Runtime apply result", runtime_apply_result_path.display());
    print_kv("Transition audit", route_transition_audit_path.display());
    print_kv("Relay weights", relay_weights_path.display());
    print_kv("Integration audit", integration_audit_path.display());
    print_kv(
        "D14 current decision",
        decision_audit_paths.current_decision.display(),
    );
    print_kv(
        "D14 decision history",
        decision_audit_paths.decisions_jsonl.display(),
    );
    print_kv(
        "D14 linked rewards",
        decision_audit_paths.rewards_jsonl.display(),
    );
    print_kv(
        "D14 linked degradation",
        decision_audit_paths.degradation_events_jsonl.display(),
    );
    if task1_signal.is_some() {
        print_kv("Task1 route signal", task1_signal_path.display());
    }
    if task2_trust_summary.is_some() {
        print_kv("Task2 trust summary", task2_trust_summary_path.display());
    }

    Ok(())
}
