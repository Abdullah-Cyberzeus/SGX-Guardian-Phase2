//! Task 3 Deliverable 17: bounded Guardian-facing runtime integration.
//!
//! The surrounding Guardian process supplies fresh, already Task2-filtered
//! inputs each tick. This runtime owns only Task3's start/stop state and mode
//! enforcement; it never writes Task2 trust or policy state.

use super::{
    persist_decision_audit, read_optional_task1_route_signal, read_optional_task2_trust_summary,
    ContextualBanditPolicy, DecisionAuditPaths, DecisionAuditRecord, DecisionEvidenceLinks,
    DegradationPredictor, EligibilityFilter, EligibleRouteSet, NetworkAiConfig,
    NetworkAiRuntimeMode, NetworkTelemetryAdapter, NetworkTelemetryContext,
    RouteCandidateInventory, RouteHistoryStore, RouteReward, RouteSafetyGuard,
    RuntimeModeController, RuntimeModeDecision, RuntimeRouteApplyRequest, RuntimeRouteState,
    SafeRuntimeRouteController, SimpleDegradationPredictor, SimpleRouteQualityPredictor,
    TrafficClass,
};
use crate::telemetry::RawSample;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::Duration;

pub const NETWORK_AI_RUNTIME_VERSION: &str = "network-ai-runtime-v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkAiRuntimeState {
    pub schema_version: String,
    pub config_version: String,
    pub enabled: bool,
    pub mode: NetworkAiRuntimeMode,
    pub running: bool,
    pub tick_count: u64,
    pub last_tick_ms: Option<u64>,
    pub latest_mode_decision: Option<RuntimeModeDecision>,
}

#[derive(Debug, Clone)]
pub struct NetworkAiRuntimeTickInput {
    /// Must be rebuilt by the Guardian integration for this cycle from the
    /// latest authoritative Task2 trust/policy state before reaching Task3.
    pub fresh_eligible_routes: EligibleRouteSet,
    pub apply_request: RuntimeRouteApplyRequest,
}

/// Production-facing source contract: no caller-supplied eligibility set or
/// final route decision. The runtime builds them through existing D1-D16 code.
#[derive(Debug, Clone)]
pub struct NetworkAiSourceTickInput {
    pub raw: RawSample,
    pub source_node: String,
    pub destination_node: String,
    pub relay_nodes: Vec<String>,
    pub traffic_class: TrafficClass,
    pub task1_recommendation_path: Option<std::path::PathBuf>,
    pub task2_trust_summary_path: Option<std::path::PathBuf>,
    pub evidence_root: std::path::PathBuf,
    pub requested_route_id: Option<String>,
    pub sensitive_handoff: Option<super::SensitiveRouteHandoffContext>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkAiRuntimeTickResult {
    pub runtime_state: NetworkAiRuntimeState,
    pub applied: bool,
    pub active_route_id: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct NetworkAiRuntime {
    pub config: NetworkAiConfig,
    pub state: NetworkAiRuntimeState,
    pub route_state: RuntimeRouteState,
    mode_controller: RuntimeModeController,
}

impl NetworkAiRuntime {
    pub fn new(config: NetworkAiConfig, route_state: RuntimeRouteState) -> Self {
        let mode = if config.enabled {
            config.mode
        } else {
            NetworkAiRuntimeMode::Shadow
        };
        let mode_controller = RuntimeModeController {
            route_controller: SafeRuntimeRouteController {
                safety_guard: RouteSafetyGuard {
                    config: config.safety.clone(),
                },
            },
        };
        Self {
            state: NetworkAiRuntimeState {
                schema_version: NETWORK_AI_RUNTIME_VERSION.to_string(),
                config_version: config.config_version.clone(),
                enabled: config.enabled,
                mode,
                running: false,
                tick_count: 0,
                last_tick_ms: None,
                latest_mode_decision: None,
            },
            config,
            route_state,
            mode_controller,
        }
    }

    pub fn start(&mut self) {
        self.state.running = self.state.enabled;
    }

    pub fn stop(&mut self) {
        self.state.running = false;
    }

    pub fn tick(&mut self, input: NetworkAiRuntimeTickInput) -> NetworkAiRuntimeTickResult {
        if !self.state.running {
            return NetworkAiRuntimeTickResult {
                runtime_state: self.state.clone(),
                applied: false,
                active_route_id: self.route_state.active_route_id.clone(),
                reason: "Task3 runtime is stopped or disabled; no route action taken".to_string(),
            };
        }
        let execution = self.mode_controller.execute(
            self.state.mode,
            &mut self.route_state,
            &input.fresh_eligible_routes,
            &input.apply_request,
        );
        self.state.tick_count += 1;
        self.state.last_tick_ms = Some(input.apply_request.ts_ms);
        self.state.latest_mode_decision = Some(execution.decision.clone());
        NetworkAiRuntimeTickResult {
            runtime_state: self.state.clone(),
            applied: execution.decision.applied,
            active_route_id: self.route_state.active_route_id.clone(),
            reason: execution.decision.reason,
        }
    }

    /// Host integration uses the existing D14 record produced by the shared
    /// Task3 pipeline, then atomically updates latest decision plus JSONL.
    pub fn tick_and_persist_audit(
        &mut self,
        input: NetworkAiRuntimeTickInput,
        audit: &DecisionAuditRecord,
        paths: &DecisionAuditPaths,
    ) -> Result<NetworkAiRuntimeTickResult> {
        let result = self.tick(input);
        persist_decision_audit(audit, paths)?;
        Ok(result)
    }

    pub fn tick_from_sources(
        &mut self,
        input: NetworkAiSourceTickInput,
    ) -> Result<NetworkAiRuntimeTickResult> {
        let now = input.raw.ts_ms;
        let task1 = read_optional_task1_route_signal(input.task1_recommendation_path.as_deref());
        let task2 = read_optional_task2_trust_summary(input.task2_trust_summary_path.as_deref());
        let observation = NetworkTelemetryAdapter::default().observe(
            &input.raw,
            NetworkTelemetryContext::operational(
                &input.source_node,
                &input.destination_node,
                &input.destination_node,
                format!("direct-{}-{}", input.source_node, input.destination_node),
            ),
        );
        let inventory = RouteCandidateInventory::from_relays(
            &input.source_node,
            &input.destination_node,
            input.traffic_class,
            input.relay_nodes.iter().map(String::as_str),
        );
        let trust = task2
            .summary
            .as_ref()
            .map(|v| v.to_trust_snapshot())
            .unwrap_or_else(|| {
                super::TrustStateSnapshot::missing("task2-routing-trust-state-missing")
            });
        let eligible = EligibilityFilter.filter_at(inventory.candidates, &trust, now);
        let mut history = RouteHistoryStore::new(0.5, self.config.history_window_entries);
        history.record_observation(&observation);
        let predictions = SimpleRouteQualityPredictor::default().predict_with_task1_signal(
            &eligible.eligible,
            &history,
            task1.signal.as_ref(),
            now,
        );
        let degradation = eligible
            .eligible
            .iter()
            .map(|route| {
                SimpleDegradationPredictor {
                    high_probability_threshold: self.config.degradation_probability_threshold,
                    ..Default::default()
                }
                .predict(
                    &route.route_id,
                    history
                        .entries_by_route
                        .get(&route.route_id)
                        .map(Vec::as_slice)
                        .unwrap_or(&[]),
                )
            })
            .collect::<Vec<_>>();
        let rewards = predictions
            .predictions
            .iter()
            .map(|prediction| {
                RouteReward::from_prediction_with_weights(
                    prediction,
                    0,
                    true,
                    false,
                    &self.config.reward_weights,
                )
            })
            .collect::<Vec<_>>();
        let mut policy =
            ContextualBanditPolicy::new(self.config.rl_learning_rate, self.config.rl_epsilon);
        for reward in &rewards {
            policy.update_with_reward(reward);
        }
        let chosen = policy.choose_exploit(&predictions);
        let current = self.route_state.active_route_id.clone();
        let current_score = predictions
            .predictions
            .iter()
            .find(|p| p.route_id == current)
            .map(|p| p.quality_score)
            .unwrap_or(0.0);
        let candidate_score = chosen
            .selected_route_id
            .as_ref()
            .and_then(|id| predictions.predictions.iter().find(|p| &p.route_id == id))
            .map(|p| p.quality_score)
            .unwrap_or(current_score);
        let requested = input
            .requested_route_id
            .clone()
            .unwrap_or_else(|| chosen.selected_route_id.clone().unwrap_or(current.clone()));
        let request = RuntimeRouteApplyRequest {
            ts_ms: now,
            requested_route_id: requested.clone(),
            current_score,
            candidate_score,
            current_route_failed: false,
            transport_apply_succeeds: true,
            selected_by: chosen.decision_mode,
            observed_rtt_ms: observation.rtt_ms,
            observed_packet_loss_pct: observation.packet_loss_pct,
            observed_throughput_mbps: observation.throughput_mbps,
            observed_bandwidth_utilization_pct: observation.bandwidth_utilization_pct,
            observed_reward: None,
        };
        let mut audit = DecisionAuditRecord::from_engine_outputs(
            format!("runtime-source-{}", now),
            now,
            &eligible,
            &predictions,
            &rewards,
            degradation,
            task1.signal,
            task2.summary,
            DecisionEvidenceLinks {
                route_history_path: "runtime-memory".into(),
                observed_outcomes_path: "runtime-route-outcomes.jsonl".into(),
                rewards_path: "rewards.jsonl".into(),
                degradation_events_path: "degradation_events.jsonl".into(),
                task1_source_path: input
                    .task1_recommendation_path
                    .map(|p| p.display().to_string()),
                task2_trust_source_path: input
                    .task2_trust_summary_path
                    .map(|p| p.display().to_string()),
                task2_trust_version: Some(eligible.trust_state_version.clone()),
            },
        );
        let execution = self.mode_controller.execute_with_sensitive_handoff(
            self.state.mode,
            &mut self.route_state,
            &eligible,
            &request,
            input.sensitive_handoff.as_ref(),
        )?;
        self.state.tick_count += 1;
        self.state.last_tick_ms = Some(now);
        self.state.latest_mode_decision = Some(execution.decision.clone());
        if let Some(handoff) = &execution.sensitive_handoff {
            audit.selected_route_id = Some(requested);
            audit.selected_reason = format!(
                "D12 sensitive handoff: {}",
                handoff.audit_record.ai_justification
            );
            std::fs::write(
                input.evidence_root.join("runtime_sensitive_handoff.json"),
                serde_json::to_vec_pretty(&handoff.audit_record)?,
            )?;
        }
        persist_decision_audit(&audit, &DecisionAuditPaths::under(&input.evidence_root))?;
        Ok(NetworkAiRuntimeTickResult {
            runtime_state: self.state.clone(),
            applied: execution.decision.applied,
            active_route_id: self.route_state.active_route_id.clone(),
            reason: execution.decision.reason,
        })
    }

    /// Guardian-facing bounded periodic loop. Production startup can provide
    /// a continuing input stream; demos/tests use a finite vector so no
    /// background process is left running.
    pub async fn run_for_ticks(
        &mut self,
        inputs: Vec<NetworkAiRuntimeTickInput>,
    ) -> Vec<NetworkAiRuntimeTickResult> {
        let mut interval =
            tokio::time::interval(Duration::from_secs(self.config.sample_interval_seconds));
        let mut results = Vec::with_capacity(inputs.len());
        for input in inputs {
            interval.tick().await;
            results.push(self.tick(input));
        }
        results
    }

    pub fn save_state_json(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating runtime directory {}", parent.display()))?;
        }
        let temporary = path.with_extension("json.tmp");
        fs::write(
            &temporary,
            serde_json::to_vec_pretty(&self.state).context("serializing Task3 runtime state")?,
        )?;
        fs::rename(&temporary, path)
            .with_context(|| format!("activating Task3 runtime state {}", path.display()))?;
        Ok(())
    }

    pub fn load_state_json(path: impl AsRef<Path>) -> Result<NetworkAiRuntimeState> {
        let path = path.as_ref();
        serde_json::from_str(
            &fs::read_to_string(path)
                .with_context(|| format!("reading Task3 runtime state {}", path.display()))?,
        )
        .context("parsing Task3 runtime state")
    }

    pub fn load_from_state_json(
        config: NetworkAiConfig,
        route_state: RuntimeRouteState,
        path: impl AsRef<Path>,
    ) -> Result<Self> {
        let saved = Self::load_state_json(path)?;
        if saved.config_version != config.config_version {
            anyhow::bail!("saved Task3 runtime config version does not match active configuration");
        }
        let mut runtime = Self::new(config, route_state);
        runtime.state = saved;
        Ok(runtime)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_ai::{
        EligibilityFilter, RouteCandidateInventory, RouteSwitchState, SensitiveRouteHandoffContext,
        TrafficClass, TrustStateSnapshot,
    };

    fn route_state() -> RuntimeRouteState {
        RuntimeRouteState::from_switch_state(&RouteSwitchState {
            current_route_id: "direct-nodeA-nodeB".into(),
            current_route_started_ms: 0,
            last_switch_ms: None,
            switch_timestamps_ms: vec![],
        })
    }
    fn input(ts_ms: u64) -> NetworkAiRuntimeTickInput {
        let routes = RouteCandidateInventory::from_relays(
            "nodeA",
            "nodeB",
            TrafficClass::Operational,
            ["nodeC"],
        )
        .candidates;
        NetworkAiRuntimeTickInput {
            fresh_eligible_routes: EligibilityFilter.filter_at(
                routes,
                &TrustStateSnapshot::new("fresh-task2")
                    .trust_peer("nodeB")
                    .trust_peer("nodeC"),
                ts_ms,
            ),
            apply_request: RuntimeRouteApplyRequest {
                ts_ms,
                requested_route_id: "relay-nodeA-via-nodeC-nodeB".into(),
                current_score: 10.0,
                candidate_score: 30.0,
                current_route_failed: false,
                transport_apply_succeeds: true,
                selected_by: "runtime-test".into(),
                observed_rtt_ms: 10.0,
                observed_packet_loss_pct: 0.1,
                observed_throughput_mbps: 50.0,
                observed_bandwidth_utilization_pct: 20.0,
                observed_reward: None,
            },
        }
    }

    #[test]
    fn bounded_ticks_respect_shadow_start_stop_and_restart_state() {
        let mut runtime = NetworkAiRuntime::new(NetworkAiConfig::default(), route_state());
        runtime.start();
        let first = runtime.tick(input(100_000));
        let second = runtime.tick(input(101_000));
        assert!(!first.applied && !second.applied);
        assert_eq!(runtime.state.tick_count, 2);
        assert_eq!(runtime.route_state.active_route_id, "direct-nodeA-nodeB");
        runtime.stop();
        assert!(!runtime.tick(input(102_000)).applied);
        let path =
            std::env::temp_dir().join(format!("network-ai-runtime-{}.json", std::process::id()));
        runtime.save_state_json(&path).unwrap();
        assert_eq!(
            NetworkAiRuntime::load_state_json(&path).unwrap().tick_count,
            2
        );
        assert_eq!(
            NetworkAiRuntime::load_from_state_json(
                NetworkAiConfig::default(),
                runtime.route_state.clone(),
                &path
            )
            .unwrap()
            .state
            .tick_count,
            2
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn active_tick_still_requires_fresh_task2_eligibility_and_safety() {
        let mut config = NetworkAiConfig::default();
        config.mode = NetworkAiRuntimeMode::Active;
        let mut runtime = NetworkAiRuntime::new(config, route_state());
        runtime.start();
        let result = runtime.tick(input(100_000));
        assert!(result.applied);
        assert_eq!(result.active_route_id, "relay-nodeA-via-nodeC-nodeB");
    }

    #[test]
    fn tick_persists_existing_d14_audit_chain() {
        use crate::network_ai::{DecisionEvidenceLinks, RoutePredictionSet};
        let root =
            std::env::temp_dir().join(format!("network-ai-runtime-audit-{}", std::process::id()));
        let mut runtime = NetworkAiRuntime::new(NetworkAiConfig::default(), route_state());
        runtime.start();
        let eligible = input(100_000).fresh_eligible_routes;
        let audit = DecisionAuditRecord::from_engine_outputs(
            "runtime-audit",
            100_000,
            &eligible,
            &RoutePredictionSet {
                model_version: "test".into(),
                feature_schema_version: "network-ai-v1".into(),
                predictions: vec![],
                selected_route_id: None,
            },
            &[],
            vec![],
            None,
            None,
            DecisionEvidenceLinks {
                route_history_path: "x".into(),
                observed_outcomes_path: "x".into(),
                rewards_path: "x".into(),
                degradation_events_path: "x".into(),
                task1_source_path: None,
                task2_trust_source_path: None,
                task2_trust_version: Some("fresh-task2".into()),
            },
        );
        let result = runtime
            .tick_and_persist_audit(input(100_000), &audit, &DecisionAuditPaths::under(&root))
            .unwrap();
        assert!(!result.applied);
        assert!(root.join("current_decision.json").exists());
        assert!(root.join("decisions.jsonl").exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn source_driven_active_sensitive_route_creates_d12_handoff_and_d14_audit() {
        let root =
            std::env::temp_dir().join(format!("network-ai-source-handoff-{}", std::process::id()));
        let roles = root.join("roles.json");
        let trust = root.join("routing_trust_summary.json");
        fs::create_dir_all(&root).unwrap();
        fs::write(&roles, r#"{"nodeA":"admin"}"#).unwrap();
        fs::write(&trust, r#"{"schema_version":1,"node_id":"nodeB","trust_status":"trusted","routing_allowed":true,"policy_status":"applied","active_policy_id":"policy-1","active_policy_version":1,"applicable_members":["nodeB"],"policy_restrictions":[],"last_alert_id":null,"attestation_state":"trusted","updated_at_ms":1789000000000}"#).unwrap();
        let mut config = NetworkAiConfig::default();
        config.mode = NetworkAiRuntimeMode::Active;
        let mut runtime = NetworkAiRuntime::new(config, route_state());
        runtime.start();
        let handoff_path = root.join("runtime_sensitive_handoff.json");
        let result = runtime
            .tick_from_sources(NetworkAiSourceTickInput {
                raw: RawSample {
                    ts_ms: 1_789_000_000_000,
                    nebula_mbps: 40.0,
                    relay_ratio: 0.2,
                    cot_latency_avg_ms: 12.0,
                    ..Default::default()
                },
                source_node: "nodeA".into(),
                destination_node: "nodeB".into(),
                relay_nodes: vec!["nodeZ".into()],
                traffic_class: TrafficClass::Operational,
                task1_recommendation_path: None,
                task2_trust_summary_path: Some(trust),
                evidence_root: root.clone(),
                requested_route_id: Some("relay-nodeA-via-nodeZ-nodeB".into()),
                sensitive_handoff: Some(SensitiveRouteHandoffContext {
                    task2_review_root: root.join("task2_reviews"),
                    task2_role_config: roles.display().to_string(),
                    audit_path: handoff_path.clone(),
                    source_node: "nodeA".into(),
                    destination_node: "nodeB".into(),
                    anomaly_score: 0.8,
                    model_confidence: 0.9,
                }),
            })
            .unwrap();
        assert!(!result.applied);
        assert_eq!(result.runtime_state.mode, NetworkAiRuntimeMode::Active);
        let handoff: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&handoff_path).unwrap()).unwrap();
        assert_eq!(handoff["requested_route_id"], "relay-nodeA-via-nodeZ-nodeB");
        assert_eq!(handoff["direct_apply_blocked"], true);
        assert!(handoff["task2_pending_review_path"]
            .as_str()
            .unwrap()
            .contains("task2_reviews"));
        let current = fs::read_to_string(root.join("current_decision.json")).unwrap();
        let history = fs::read_to_string(root.join("decisions.jsonl")).unwrap();
        assert!(current.contains("D12 sensitive handoff"));
        assert!(history.contains("D12 sensitive handoff"));
        let _ = fs::remove_dir_all(root);
    }
}
