use anyhow::{Context, Result};
use serde::Serialize;
use sgx_anomaly_engine::network_ai::{
    append_degradation_prediction_jsonl, append_observation_jsonl, persist_current_observation,
    persist_decision_audit, read_optional_task1_route_signal, read_optional_task2_trust_summary,
    ContextualBanditPolicy, DecisionAuditPaths, DecisionAuditRecord, DecisionEvidenceLinks,
    EligibilityFilter, EligibleRouteSet, MultiRelayLoadBalancer, NetworkAiConfig,
    NetworkAiRuntimeMode, NetworkTelemetryAdapter, NetworkTelemetryContext, ObservedRewardInput,
    RelayRuntimeHealth, RouteCandidateInventory, RouteHistoryStore, RouteKind,
    RouteObservationInput, RouteReward, RouteSafetyGuard, RouteSwitchState, RuntimeModeController,
    RuntimeRouteApplyRequest, RuntimeRouteState, SafeRuntimeRouteController,
    SimpleDegradationPredictor, SimpleRouteQualityPredictor, Task1RouteSignal,
    Task2RoutingTrustSummary, TrafficClass, TrustStateSnapshot,
};
use sgx_anomaly_engine::telemetry::RawSample;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static LAST_RUNTIME_TIMESTAMP_MS: AtomicU64 = AtomicU64::new(0);
static NEXT_DECISION_SEQUENCE: AtomicU64 = AtomicU64::new(0);

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
    task1_bridge_status: String,
    task2_trust_summary: Option<Task2RoutingTrustSummary>,
    task2_bridge_status: String,
    bridge_result: String,
}

#[derive(Debug, Serialize)]
struct EffectiveNetworkAiConfigEvidence {
    config_source: String,
    effective_mode: NetworkAiRuntimeMode,
    config: NetworkAiConfig,
}

/// Small, senior-readable D21 view. Detailed model/audit JSON remains
/// available separately; this file answers only what Shadow selected and why.
#[derive(Debug, Serialize)]
struct ShadowRouteDecision {
    schema_version: &'static str,
    decision_id: String,
    mode: NetworkAiRuntimeMode,
    traffic_class: TrafficClass,
    priority: String,
    task2_trust_version: String,
    task2_bridge_status: String,
    eligible_route_ids: Vec<String>,
    rejected_routes: Vec<ShadowRejectedRoute>,
    selected_route_id: Option<String>,
    expected_latency_ms: Option<f64>,
    expected_loss_pct: Option<f64>,
    expected_throughput_mbps: Option<f64>,
    confidence: Option<f64>,
    selection_reason: String,
    degradation_probability: Option<f64>,
    degradation_contributors: Vec<String>,
    applied: bool,
    operator_next_step: &'static str,
}

#[derive(Debug, Serialize)]
struct ShadowRejectedRoute {
    route_id: String,
    reason: String,
}

/// D22 is advisory-only. The safety verdict is evaluated read-only so an
/// operator can see whether Active mode would be permitted, without applying.
#[derive(Debug, Serialize)]
struct AdvisoryRouteRecommendation {
    schema_version: &'static str,
    recommendation_id: String,
    mode: NetworkAiRuntimeMode,
    current_route_id: String,
    recommended_route_id: Option<String>,
    expected_improvement_pct: f64,
    confidence: Option<f64>,
    reason: String,
    safety_verdict: String,
    safety_allowed_if_activated: bool,
    safety_reason: String,
    applied: bool,
    operator_next_step: &'static str,
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|window| window[0] == flag)
        .map(|window| window[1].clone())
}

/// Real wall-clock time for normal demo/runtime execution. The atomic floor
/// prevents two rapid decisions from receiving the same millisecond ID.
fn runtime_now_ms() -> u64 {
    let wall_clock_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0);
    let mut last = LAST_RUNTIME_TIMESTAMP_MS.load(Ordering::Relaxed);
    loop {
        let next = wall_clock_ms.max(last.saturating_add(1));
        match LAST_RUNTIME_TIMESTAMP_MS.compare_exchange_weak(
            last,
            next,
            Ordering::SeqCst,
            Ordering::Relaxed,
        ) {
            Ok(_) => return next,
            Err(current) => last = current,
        }
    }
}

fn decision_id(
    source_node: &str,
    destination_node: &str,
    issued_at_ms: u64,
    sequence: u64,
) -> String {
    format!("task3-decision-{source_node}-{destination_node}-{issued_at_ms}-{sequence}")
}

/// Production decision IDs deliberately use runtime issuance time rather than
/// caller-supplied telemetry time, which can be fixed during deterministic replay.
fn next_runtime_decision_id(source_node: &str, destination_node: &str) -> String {
    decision_id(
        source_node,
        destination_node,
        runtime_now_ms(),
        NEXT_DECISION_SEQUENCE.fetch_add(1, Ordering::SeqCst),
    )
}

/// Reads externally supplied measured route outcomes. JSON may be one object,
/// an array, or JSONL; the optimizer never invents these measurements itself.
fn load_route_observation_inputs(path: &Path) -> Result<Vec<RouteObservationInput>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading route observations {}", path.display()))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if trimmed.starts_with('[') {
        return serde_json::from_str(trimmed)
            .with_context(|| format!("parsing route observation array {}", path.display()));
    }
    let rows = trimmed
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    if rows.len() == 1 {
        return Ok(vec![serde_json::from_str(rows[0]).with_context(|| {
            format!("parsing route observation {}", path.display())
        })?]);
    }
    rows.into_iter()
        .map(|row| {
            serde_json::from_str(row)
                .with_context(|| format!("parsing route observation row in {}", path.display()))
        })
        .collect()
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
        "Usage: cargo run --example run_task3_network_optimizer_demo -- [--config path] [--mode shadow|advisory|active] [--traffic-class operational|security-control] [--source-node nodeA] [--destination-node nodeB] [--out-dir data/network_ai] [--task1-recommendation path] [--task2-trust-state path] [--history-store path] [--rl-policy-store path] [--route-observations path] [--timestamp-ms ms] [--current-route-failed]"
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
    let config_path = arg_value(&args, "--config").map(PathBuf::from);
    let network_config = match &config_path {
        Some(path) => NetworkAiConfig::load_json(path)?,
        None => NetworkAiConfig::default(),
    };
    let requested_mode = match arg_value(&args, "--mode") {
        Some(value) => NetworkAiRuntimeMode::parse(&value).ok_or_else(|| {
            anyhow::anyhow!("invalid --mode '{value}'; use shadow, advisory, or active")
        })?,
        None => network_config.mode,
    };
    let runtime_mode = if network_config.enabled {
        requested_mode
    } else {
        NetworkAiRuntimeMode::Shadow
    };
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

    let task1_bridge = read_optional_task1_route_signal(
        task1_recommendation_path
            .as_deref()
            .filter(|path| path.exists()),
    );
    let task1_signal = task1_bridge.signal.clone();
    let task2_bridge = read_optional_task2_trust_summary(task2_trust_state_path.as_deref());
    let task2_trust_summary = task2_bridge.summary.clone();

    let timestamp_ms = arg_value(&args, "--timestamp-ms")
        .map(|value| {
            value
                .parse::<u64>()
                .context("--timestamp-ms must be an unsigned integer")
        })
        .transpose()?
        .unwrap_or_else(runtime_now_ms);
    let raw = RawSample {
        ts_ms: timestamp_ms,
        nebula_mbps: 42.0,
        relay_ratio: 0.25,
        cot_latency_avg_ms: 18.5,
        conn_total: 7,
        ..Default::default()
    };
    let runtime_decision_id = next_runtime_decision_id(&source_node, &destination_node);

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

    // Discovery is independent from eligibility. The latest Task2 summary is
    // the only authority deciding which relays are trusted or quarantined.
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
    for candidate in &mut inventory.candidates {
        candidate.metadata.trust_state_version_seen = Some(trust_state.version.clone());
    }

    let eligible_routes =
        EligibilityFilter.filter_at(inventory.candidates.clone(), &trust_state, raw.ts_ms);

    let observation_path = out_dir.join("current_observation.json");
    let history_path = out_dir.join("route_observations.jsonl");
    let candidates_path = out_dir.join("candidate_inventory.json");
    let eligible_path = out_dir.join("eligible_routes.json");
    let route_history_path = arg_value(&args, "--history-store")
        .map(PathBuf::from)
        .unwrap_or_else(|| out_dir.join("route_history_store.json"));
    let route_observation_input_path = arg_value(&args, "--route-observations").map(PathBuf::from);
    let route_outcomes_path = out_dir.join("route_outcomes.jsonl");
    let prediction_path = out_dir.join("route_predictions.json");
    let degradation_path = out_dir.join("degradation_predictions.json");
    let degradation_events_path = out_dir.join("degradation_predictions.jsonl");
    let rewards_path = out_dir.join("route_rewards.json");
    let rl_policy_path = arg_value(&args, "--rl-policy-store")
        .map(PathBuf::from)
        .unwrap_or_else(|| out_dir.join("rl_policy.json"));
    let rl_decision_path = out_dir.join("rl_decision.json");
    let safety_decision_path = out_dir.join("route_safety_decision.json");
    let apply_result_path = out_dir.join("route_apply_result.json");
    let runtime_route_state_path = out_dir.join("current_route_state.json");
    let runtime_apply_result_path = out_dir.join("runtime_route_apply_result.json");
    let route_transition_audit_path = out_dir.join("route_transition_audit.jsonl");
    let relay_weights_path = out_dir.join("relay_weights.json");
    let task1_signal_path = out_dir.join("task1_route_signal.json");
    let task1_bridge_path = out_dir.join("task1_bridge_status.json");
    let task2_trust_summary_path = out_dir.join("task2_trust_summary.json");
    let task2_bridge_path = out_dir.join("task2_bridge_status.json");
    let integration_audit_path = out_dir.join("task3_integration_audit.json");
    let runtime_mode_path = out_dir.join("runtime_mode_decision.json");
    let shadow_decision_path = out_dir.join("shadow_route_decision.json");
    let advisory_recommendation_path = out_dir.join("advisory_route_recommendation.json");
    let effective_config_path = out_dir.join("effective_network_ai_config.json");
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

    let history_loaded = route_history_path.exists();
    let mut history_store = RouteHistoryStore::load_or_new(
        &route_history_path,
        0.5,
        network_config.history_window_entries,
    )?;
    let supplied_route_observations = route_observation_input_path
        .as_deref()
        .map(load_route_observation_inputs)
        .transpose()?;
    history_store.record_observation(&observation);
    for supplied in supplied_route_observations.as_ref().into_iter().flatten() {
        history_store.record_measured_observation(supplied.clone());
    }
    history_store.save_json(&route_history_path)?;

    let predictor = SimpleRouteQualityPredictor::default();
    let predictions = predictor.predict_with_task1_signal(
        &eligible_routes.eligible,
        &history_store,
        task1_signal.as_ref(),
        raw.ts_ms + 2_000,
    );
    write_json(&prediction_path, &predictions)?;

    let degradation_predictor = SimpleDegradationPredictor {
        high_probability_threshold: network_config.degradation_probability_threshold,
        ..SimpleDegradationPredictor::default()
    };
    let degradation_predictions = degradation_predictor.predict_all_routes(&history_store);
    write_json(&degradation_path, &degradation_predictions)?;
    for prediction in &degradation_predictions {
        append_degradation_prediction_jsonl(&degradation_events_path, prediction)?;
    }

    let current_route_id = format!("direct-{source_node}-{destination_node}");
    let current_hop_count = inventory
        .candidates
        .iter()
        .find(|candidate| candidate.route_id == current_route_id)
        .map(|candidate| candidate.hop_count)
        .unwrap_or(0);
    let mut rl_policy = ContextualBanditPolicy::load_or_new(
        &rl_policy_path,
        network_config.rl_learning_rate,
        network_config.rl_epsilon,
    )?;
    rl_policy.learning_rate = network_config.rl_learning_rate;
    rl_policy.epsilon = network_config.rl_epsilon;
    // A failed active route is actual feedback. Apply it before choosing the
    // next route so its Q-value cannot continue to win on predicted quality.
    let failed_current_reward = current_route_failed.then(|| {
        RouteReward::from_observed_outcome_with_weights(
            &ObservedRewardInput {
                route_id: current_route_id.clone(),
                rtt_ms: Some(observation.rtt_ms),
                packet_loss_pct: Some(observation.packet_loss_pct),
                throughput_mbps: Some(observation.throughput_mbps),
                bandwidth_utilization_pct: Some(observation.bandwidth_utilization_pct),
                hop_count: current_hop_count,
                switched_route: false,
                route_failed: true,
            },
            &network_config.reward_weights,
        )
    });
    if let Some(reward) = &failed_current_reward {
        rl_policy.update_with_reward(reward);
    }
    let rl_decision = rl_policy.choose_exploit(&predictions);

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
    let requested_hop_count = inventory
        .candidates
        .iter()
        .find(|candidate| candidate.route_id == requested_route_id)
        .map(|candidate| candidate.hop_count)
        .unwrap_or(0);
    let observed_reward = RouteReward::from_observed_outcome_with_weights(
        &ObservedRewardInput {
            route_id: requested_route_id.clone(),
            rtt_ms: Some(observation.rtt_ms),
            packet_loss_pct: Some(observation.packet_loss_pct),
            throughput_mbps: Some(observation.throughput_mbps),
            bandwidth_utilization_pct: Some(observation.bandwidth_utilization_pct),
            hop_count: requested_hop_count,
            switched_route: requested_route_id != current_route_id,
            route_failed: false,
        },
        &network_config.reward_weights,
    );
    let mut runtime_state = RuntimeRouteState::from_switch_state(&switch_state);
    let apply_request = RuntimeRouteApplyRequest {
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
        observed_reward: (runtime_mode == NetworkAiRuntimeMode::Active)
            .then_some(observed_reward.total_reward),
    };
    let advisory_safety = RouteSafetyGuard {
        config: network_config.safety.clone(),
    }
    .evaluate_with_route_health(
        raw.ts_ms,
        &switch_state,
        Some(&apply_request.requested_route_id),
        current_score,
        candidate_score,
        current_route_failed,
    );
    let mode_execution = RuntimeModeController {
        route_controller: SafeRuntimeRouteController {
            safety_guard: RouteSafetyGuard {
                config: network_config.safety.clone(),
            },
        },
    }
    .execute_and_persist(
        runtime_mode,
        &mut runtime_state,
        &eligible_routes,
        &apply_request,
        &runtime_route_state_path,
        &runtime_apply_result_path,
        &route_transition_audit_path,
        &route_outcomes_path,
    )?;
    write_json(&runtime_mode_path, &mode_execution.decision)?;
    write_json(
        &effective_config_path,
        &EffectiveNetworkAiConfigEvidence {
            config_source: config_path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "built-in safe defaults".to_string()),
            effective_mode: runtime_mode,
            config: network_config.clone(),
        },
    )?;
    let runtime_result = mode_execution.route_result;
    let mut rewards = failed_current_reward.into_iter().collect::<Vec<_>>();
    if let Some(result) = &runtime_result {
        // Only an attempted, safety-allowed Active decision has a post-action
        // outcome. A Shadow/Advisory recommendation must not train the bandit.
        if result.audit.safety_decision.allowed {
            let actual = if result.audit.apply_result.applied {
                observed_reward.clone()
            } else {
                RouteReward::from_observed_outcome_with_weights(
                    &ObservedRewardInput {
                        route_id: apply_request.requested_route_id.clone(),
                        rtt_ms: Some(apply_request.observed_rtt_ms),
                        packet_loss_pct: Some(apply_request.observed_packet_loss_pct),
                        throughput_mbps: Some(apply_request.observed_throughput_mbps),
                        bandwidth_utilization_pct: Some(
                            apply_request.observed_bandwidth_utilization_pct,
                        ),
                        hop_count: requested_hop_count,
                        switched_route: apply_request.requested_route_id != current_route_id,
                        route_failed: true,
                    },
                    &network_config.reward_weights,
                )
            };
            if !(current_route_failed && apply_request.requested_route_id == current_route_id) {
                rl_policy.update_with_reward(&actual);
                rewards.push(actual);
            }
        }
    }
    write_json(&rewards_path, &rewards)?;
    rl_policy.save_json(&rl_policy_path)?;
    write_json(&rl_decision_path, &rl_decision)?;
    if let Some(result) = &runtime_result {
        write_json(&safety_decision_path, &result.audit.safety_decision)?;
        write_json(&apply_result_path, &result.audit.apply_result)?;
    }
    let runtime_health = eligible_routes
        .eligible
        .iter()
        .filter(|route| matches!(route.kind, RouteKind::Relay | RouteKind::MultiHopRelay))
        .map(|route| RelayRuntimeHealth {
            route_id: route.route_id.clone(),
            available: route.observed_available,
            healthy: route.observed_healthy,
            utilization_pct: Some(observation.bandwidth_utilization_pct),
            recovered_at_ms: None,
        })
        .collect::<Vec<_>>();
    let relay_weights = MultiRelayLoadBalancer::default().calculate_with_health(
        &eligible_routes.eligible,
        &predictions,
        traffic_class,
        &runtime_health,
        raw.ts_ms,
    );
    write_json(&relay_weights_path, &relay_weights)?;
    if runtime_mode == NetworkAiRuntimeMode::Shadow {
        let selected_prediction = predictions.predictions.iter().find(|prediction| {
            Some(&prediction.route_id) == rl_decision.selected_route_id.as_ref()
        });
        let selected_degradation = rl_decision.selected_route_id.as_ref().and_then(|route_id| {
            degradation_predictions
                .iter()
                .find(|prediction| prediction.route_id == *route_id)
        });
        write_json(
            &shadow_decision_path,
            &ShadowRouteDecision {
                schema_version: "network-ai-shadow-decision-v1",
                decision_id: format!("task3-shadow-{runtime_decision_id}"),
                mode: runtime_mode,
                traffic_class,
                priority: format!("{:?}", observation.priority_class),
                task2_trust_version: eligible_routes.trust_state_version.clone(),
                task2_bridge_status: task2_bridge.status.clone(),
                eligible_route_ids: eligible_routes
                    .eligible
                    .iter()
                    .map(|route| route.route_id.clone())
                    .collect(),
                rejected_routes: eligible_routes
                    .rejected
                    .iter()
                    .map(|route| ShadowRejectedRoute {
                        route_id: route.route_id.clone(),
                        reason: format!("{:?}", route.reason),
                    })
                    .collect(),
                selected_route_id: rl_decision.selected_route_id.clone(),
                expected_latency_ms: selected_prediction.map(|value| value.expected_latency_ms),
                expected_loss_pct: selected_prediction.map(|value| value.expected_loss_pct),
                expected_throughput_mbps: selected_prediction
                    .map(|value| value.expected_throughput_mbps),
                confidence: selected_prediction.map(|value| value.confidence),
                selection_reason: selected_prediction
                    .map(|value| value.reason.clone())
                    .unwrap_or_else(|| "no eligible trusted route was selected".to_string()),
                degradation_probability: selected_degradation.map(|value| value.probability),
                degradation_contributors: selected_degradation
                    .map(|value| value.contributors.clone())
                    .unwrap_or_default(),
                applied: false,
                operator_next_step: "Review this shadow recommendation; no route was changed.",
            },
        )?;
    }
    if runtime_mode == NetworkAiRuntimeMode::Advisory {
        let selected_prediction = predictions.predictions.iter().find(|prediction| {
            Some(&prediction.route_id) == rl_decision.selected_route_id.as_ref()
        });
        write_json(
            &advisory_recommendation_path,
            &AdvisoryRouteRecommendation {
                schema_version: "network-ai-advisory-recommendation-v1",
                recommendation_id: format!("task3-advisory-{runtime_decision_id}"),
                mode: runtime_mode,
                current_route_id: current_route_id.clone(),
                recommended_route_id: rl_decision.selected_route_id.clone(),
                expected_improvement_pct: advisory_safety.improvement_pct,
                confidence: selected_prediction.map(|value| value.confidence),
                reason: selected_prediction
                    .map(|value| value.reason.clone())
                    .unwrap_or_else(|| "no eligible trusted route was selected".to_string()),
                safety_verdict: format!("{:?}", advisory_safety.verdict),
                safety_allowed_if_activated: advisory_safety.allowed,
                safety_reason: advisory_safety.reason.clone(),
                applied: false,
                operator_next_step: "Review recommendation and explicitly enable Active mode only when operationally approved.",
            },
        )?;
    }
    if let Some(signal) = &task1_signal {
        write_json(&task1_signal_path, signal)?;
    }
    write_json(&task1_bridge_path, &task1_bridge)?;
    if let Some(summary) = &task2_trust_summary {
        write_json(&task2_trust_summary_path, summary)?;
    }
    write_json(&task2_bridge_path, &task2_bridge)?;
    let bridge_result = if task1_signal.is_some() || task2_trust_summary.is_some() {
        "Task3 consumed available Task1/Task2 JSON signals read-only; Task2 state was not mutated."
    } else {
        "No Task1/Task2 JSON paths were available; Task3 used safe defaults and did not select a route."
    };
    write_json(
        &integration_audit_path,
        &IntegrationBridgeAudit {
            task1_signal: task1_signal.clone(),
            task1_bridge_status: task1_bridge.status.clone(),
            task2_trust_summary: task2_trust_summary.clone(),
            task2_bridge_status: task2_bridge.status.clone(),
            bridge_result: bridge_result.to_string(),
        },
    )?;
    let decision_audit = DecisionAuditRecord::from_engine_outputs(
        runtime_decision_id,
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
    print_kv("Config version", &network_config.config_version);
    print_kv(
        "Config source",
        config_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "built-in safe defaults".to_string()),
    );
    print_kv("Task3 enabled", network_config.enabled);

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
    print_kv("History loaded from disk", history_loaded);
    print_kv(
        "Supplied observations",
        supplied_route_observations
            .as_ref()
            .map(Vec::len)
            .unwrap_or(0),
    );
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
    print_kv("Runtime mode", format!("{:?}", runtime_mode));
    if let Some(result) = &runtime_result {
        let safety_decision = &result.audit.safety_decision;
        let apply_result = &result.audit.apply_result;
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
    } else {
        print_kv("Current route", &runtime_state.active_route_id);
        print_kv("Recommended route", &apply_request.requested_route_id);
        print_kv("Applied", false);
        print_kv("Reason", &mode_execution.decision.reason);
    }

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
    print_kv("Task1 bridge status", &task1_bridge.status);
    print_kv("Task2 bridge status", &task2_bridge.status);

    println!();
    println!("12. GUARDED RUNTIME ROUTE CONTROLLER");
    if let Some(result) = &runtime_result {
        print_kv("Transition", format!("{:?}", result.audit.transition));
        print_kv(
            "Already eligible",
            result.audit.requested_route_was_eligible,
        );
        print_kv(
            "Owner approval",
            "not required for safe runtime route change",
        );
        print_kv("Runtime active route", &result.state.active_route_id);
    } else {
        print_kv("Controller status", "not invoked outside Active mode");
        print_kv("Runtime active route", &runtime_state.active_route_id);
    }
    print_kv(
        "Outcome reward fed",
        rewards
            .first()
            .map(|reward| format!("{:.2}", reward.total_reward))
            .unwrap_or_else(|| "none (no Active post-decision outcome)".to_string()),
    );

    if runtime_mode == NetworkAiRuntimeMode::Shadow {
        println!();
        println!("13. D21 SHADOW DECISION");
        print_kv(
            "Selected route",
            rl_decision.selected_route_id.as_deref().unwrap_or("none"),
        );
        print_kv("Applied", false);
        print_kv(
            "Operator next step",
            "Review recommendation; no route was changed.",
        );
    }
    if runtime_mode == NetworkAiRuntimeMode::Advisory {
        println!();
        println!("14. D22 ADVISORY RECOMMENDATION");
        print_kv(
            "Recommended route",
            rl_decision.selected_route_id.as_deref().unwrap_or("none"),
        );
        print_kv(
            "Expected improvement",
            format!("{:.1}%", advisory_safety.improvement_pct),
        );
        print_kv("Safety verdict", format!("{:?}", advisory_safety.verdict));
        print_kv("Applied", false);
        print_kv(
            "Operator next step",
            "Review and explicitly enable Active mode if approved.",
        );
    }

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
    print_kv("Runtime mode decision", runtime_mode_path.display());
    if runtime_mode == NetworkAiRuntimeMode::Shadow {
        print_kv("D21 shadow decision", shadow_decision_path.display());
    }
    if runtime_mode == NetworkAiRuntimeMode::Advisory {
        print_kv(
            "D22 advisory recommendation",
            advisory_recommendation_path.display(),
        );
    }
    print_kv("Effective Task3 config", effective_config_path.display());
    if runtime_result.is_some() {
        print_kv("Safety decision", safety_decision_path.display());
        print_kv("Apply result", apply_result_path.display());
        print_kv("Runtime route state", runtime_route_state_path.display());
        print_kv("Runtime apply result", runtime_apply_result_path.display());
        print_kv("Transition audit", route_transition_audit_path.display());
    }
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
    print_kv("Task1 bridge status", task1_bridge_path.display());
    if task2_trust_summary.is_some() {
        print_kv("Task2 trust summary", task2_trust_summary_path.display());
    }
    print_kv("Task2 bridge status", task2_bridge_path.display());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::decision_id;

    #[test]
    fn deterministic_decision_ids_are_distinguishable_within_one_millisecond() {
        let first = decision_id("nodeA", "nodeB", 1_789_000_000_000, 0);
        let second = decision_id("nodeA", "nodeB", 1_789_000_000_000, 1);
        assert_ne!(first, second);
        assert_eq!(first, "task3-decision-nodeA-nodeB-1789000000000-0");
    }
}
