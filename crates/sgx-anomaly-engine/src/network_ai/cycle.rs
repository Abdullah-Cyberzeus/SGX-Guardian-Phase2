//! Reusable Task3 AI cycle: Task2 eligibility, prediction, degradation,
//! contextual-bandit selection, and relay weighting in one canonical order.

use super::{
    ContextualBanditPolicy, DecisionAuditRecord, DecisionEvidenceLinks, DegradationPrediction,
    EligibilityFilter, EligibleRouteSet, MultiRelayLoadBalancer, NetworkAiConfig,
    NetworkAiRewardWeights, ObservedRewardInput, RelayRuntimeHealth, RelayWeightSet,
    RouteCandidate, RouteHistoryStore, RouteLearningDecision, RoutePredictionSet, RouteReward,
    RouteSafetyDecision, RouteSafetyGuard, RouteSwitchState, RuntimeModeExecution,
    RuntimeRouteApplyRequest, SimpleDegradationPredictor, SimpleRouteQualityPredictor,
    Task1RouteSignal, Task2RoutingTrustSummary, TrafficClass, TrustStateSnapshot,
};
use anyhow::Result;

pub struct NetworkAiCycleInput<'a> {
    pub now_ms: u64,
    pub traffic_class: TrafficClass,
    pub candidates: Vec<RouteCandidate>,
    pub history: &'a RouteHistoryStore,
    pub task1_signal: Option<&'a Task1RouteSignal>,
    pub trust_state: TrustStateSnapshot,
    pub relay_health: Vec<RelayRuntimeHealth>,
}

#[derive(Debug, Clone)]
pub struct NetworkAiCycleOutput {
    pub eligible_routes: EligibleRouteSet,
    pub predictions: RoutePredictionSet,
    pub degradation_predictions: Vec<DegradationPrediction>,
    pub rl_decision: RouteLearningDecision,
    pub relay_weights: RelayWeightSet,
}

/// Result of the canonical learning phase. Feedback is applied before the
/// returned policy decision, so a failed active route cannot be selected on
/// the strength of stale Q-values.
#[derive(Debug, Clone)]
pub struct NetworkAiFeedbackCycleOutput {
    pub cycle: NetworkAiCycleOutput,
    pub rewards: Vec<RouteReward>,
}

/// A safety-checked route action ready for the runtime transport adapter.
#[derive(Debug, Clone)]
pub struct NetworkAiRouteActionPlan {
    pub request: RuntimeRouteApplyRequest,
    pub safety_decision: RouteSafetyDecision,
}

/// Output of the complete reusable production decision sequence.
#[derive(Debug, Clone)]
pub struct NetworkAiCompleteCycleOutput {
    pub cycle: NetworkAiCycleOutput,
    pub action: NetworkAiRouteActionPlan,
    pub execution: RuntimeModeExecution,
    pub rewards: Vec<RouteReward>,
    pub audit: DecisionAuditRecord,
}

pub struct NetworkAiEngine {
    predictor: SimpleRouteQualityPredictor,
    degradation_predictor: SimpleDegradationPredictor,
    load_balancer: MultiRelayLoadBalancer,
    safety_guard: RouteSafetyGuard,
}

impl NetworkAiEngine {
    pub fn new(config: &NetworkAiConfig) -> Self {
        Self {
            predictor: SimpleRouteQualityPredictor::default(),
            degradation_predictor: SimpleDegradationPredictor {
                high_probability_threshold: config.degradation_probability_threshold,
                ..Default::default()
            },
            load_balancer: MultiRelayLoadBalancer::default(),
            safety_guard: RouteSafetyGuard {
                config: config.safety.clone(),
            },
        }
    }

    /// Runs only core AI processing. Callers retain responsibility for input
    /// acquisition, durable history/policy storage, route application, and
    /// evidence persistence.
    pub fn run(
        &self,
        input: NetworkAiCycleInput<'_>,
        policy: &ContextualBanditPolicy,
    ) -> NetworkAiCycleOutput {
        let eligible_routes =
            EligibilityFilter.filter_at(input.candidates, &input.trust_state, input.now_ms);
        let predictions = self.predictor.predict_with_task1_signal(
            &eligible_routes.eligible,
            input.history,
            input.task1_signal,
            input.now_ms,
        );
        let degradation_predictions = self.degradation_predictor.predict_all_routes(input.history);
        let rl_decision = policy.choose_exploit(&predictions);
        let relay_weights = self.load_balancer.calculate_with_health(
            &eligible_routes.eligible,
            &predictions,
            input.traffic_class,
            &input.relay_health,
            input.now_ms,
        );
        NetworkAiCycleOutput {
            eligible_routes,
            predictions,
            degradation_predictions,
            rl_decision,
            relay_weights,
        }
    }

    pub fn run_with_observed_feedback(
        &self,
        input: NetworkAiCycleInput<'_>,
        policy: &mut ContextualBanditPolicy,
        observed_feedback: &[ObservedRewardInput],
        reward_weights: &NetworkAiRewardWeights,
    ) -> NetworkAiFeedbackCycleOutput {
        let rewards = observed_feedback
            .iter()
            .map(|feedback| {
                let reward =
                    RouteReward::from_observed_outcome_with_weights(feedback, reward_weights);
                policy.update_with_reward(&reward);
                reward
            })
            .collect();
        let cycle = self.run(input, policy);
        NetworkAiFeedbackCycleOutput { cycle, rewards }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_route_action(
        &self,
        cycle: &NetworkAiCycleOutput,
        state: &RouteSwitchState,
        requested_override: Option<String>,
        current_route_failed: bool,
        now_ms: u64,
        observation: &ObservedRewardInput,
        transport_apply_succeeds: bool,
    ) -> NetworkAiRouteActionPlan {
        let requested_route_id = requested_override
            .or_else(|| cycle.rl_decision.selected_route_id.clone())
            .unwrap_or_else(|| state.current_route_id.clone());
        let current_score = cycle
            .predictions
            .predictions
            .iter()
            .find(|item| item.route_id == state.current_route_id)
            .map(|item| item.quality_score)
            .unwrap_or(0.0);
        let candidate_score = cycle
            .predictions
            .predictions
            .iter()
            .find(|item| item.route_id == requested_route_id)
            .map(|item| item.quality_score)
            .unwrap_or(current_score);
        let safety_decision = self.safety_guard.evaluate_with_route_health(
            now_ms,
            state,
            Some(&requested_route_id),
            current_score,
            candidate_score,
            current_route_failed,
        );
        NetworkAiRouteActionPlan {
            request: RuntimeRouteApplyRequest {
                ts_ms: now_ms,
                requested_route_id,
                current_score,
                candidate_score,
                current_route_failed,
                transport_apply_succeeds,
                selected_by: cycle.rl_decision.decision_mode.clone(),
                observed_rtt_ms: observation.rtt_ms.unwrap_or(0.0),
                observed_packet_loss_pct: observation.packet_loss_pct.unwrap_or(0.0),
                observed_throughput_mbps: observation.throughput_mbps.unwrap_or(0.0),
                observed_bandwidth_utilization_pct: observation
                    .bandwidth_utilization_pct
                    .unwrap_or(0.0),
                observed_reward: None,
            },
            safety_decision,
        }
    }

    pub fn build_decision_audit(
        &self,
        decision_id: String,
        now_ms: u64,
        cycle: &NetworkAiCycleOutput,
        rewards: &[RouteReward],
        task1_signal: Option<Task1RouteSignal>,
        task2_summary: Option<Task2RoutingTrustSummary>,
        evidence: DecisionEvidenceLinks,
    ) -> DecisionAuditRecord {
        DecisionAuditRecord::from_engine_outputs(
            decision_id,
            now_ms,
            &cycle.eligible_routes,
            &cycle.predictions,
            rewards,
            cycle.degradation_predictions.clone(),
            task1_signal,
            task2_summary,
            evidence,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_complete_cycle<E, P>(
        &self,
        input: NetworkAiCycleInput<'_>,
        policy: &mut ContextualBanditPolicy,
        observed_feedback: &[ObservedRewardInput],
        reward_weights: &NetworkAiRewardWeights,
        route_state: &RouteSwitchState,
        requested_override: Option<String>,
        current_route_failed: bool,
        observation: &ObservedRewardInput,
        transport_apply_succeeds: bool,
        decision_id: String,
        task1_signal: Option<Task1RouteSignal>,
        task2_summary: Option<Task2RoutingTrustSummary>,
        evidence: DecisionEvidenceLinks,
        execute_action: E,
        persist_audit: P,
    ) -> Result<NetworkAiCompleteCycleOutput>
    where
        E: FnOnce(&EligibleRouteSet, &RuntimeRouteApplyRequest) -> Result<RuntimeModeExecution>,
        P: FnOnce(&DecisionAuditRecord) -> Result<()>,
    {
        let now_ms = input.now_ms;
        let mut feedback =
            self.run_with_observed_feedback(input, policy, observed_feedback, reward_weights);
        let action = self.prepare_route_action(
            &feedback.cycle,
            route_state,
            requested_override,
            current_route_failed,
            now_ms,
            observation,
            transport_apply_succeeds,
        );
        let execution = execute_action(&feedback.cycle.eligible_routes, &action.request)?;
        if let Some(route_result) = &execution.route_result {
            if route_result.audit.safety_decision.allowed
                && !(current_route_failed
                    && action.request.requested_route_id == route_state.current_route_id)
            {
                let hop_count = feedback
                    .cycle
                    .eligible_routes
                    .eligible
                    .iter()
                    .find(|route| route.route_id == action.request.requested_route_id)
                    .map(|route| route.hop_count)
                    .unwrap_or(0);
                let actual = RouteReward::from_observed_outcome_with_weights(
                    &ObservedRewardInput {
                        route_id: action.request.requested_route_id.clone(),
                        rtt_ms: observation.rtt_ms,
                        packet_loss_pct: observation.packet_loss_pct,
                        throughput_mbps: observation.throughput_mbps,
                        bandwidth_utilization_pct: observation.bandwidth_utilization_pct,
                        hop_count,
                        switched_route: action.request.requested_route_id
                            != route_state.current_route_id,
                        route_failed: !route_result.audit.apply_result.applied,
                    },
                    reward_weights,
                );
                policy.update_with_reward(&actual);
                feedback.rewards.push(actual);
            }
        }
        let mut audit = self.build_decision_audit(
            decision_id,
            action.request.ts_ms,
            &feedback.cycle,
            &feedback.rewards,
            task1_signal,
            task2_summary,
            evidence,
        );
        if let Some(handoff) = &execution.sensitive_handoff {
            audit.selected_route_id = Some(action.request.requested_route_id.clone());
            audit.selected_reason = format!(
                "D12 sensitive handoff: {}",
                handoff.audit_record.ai_justification
            );
        }
        persist_audit(&audit)?;
        Ok(NetworkAiCompleteCycleOutput {
            cycle: feedback.cycle,
            action,
            execution,
            rewards: feedback.rewards,
            audit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_ai::{
        persist_decision_audit, DecisionAuditPaths, NetworkAiRuntimeMode, RouteCandidateInventory,
        RouteHistoryEntry, RuntimeModeDecision,
    };

    #[test]
    fn cycle_applies_task2_filter_before_prediction_and_rl() {
        let candidates = RouteCandidateInventory::from_relays(
            "nodeA",
            "nodeB",
            TrafficClass::Operational,
            ["nodeC"],
        )
        .candidates;
        let mut history = RouteHistoryStore::new(1.0, 8);
        history.record(RouteHistoryEntry {
            ts_ms: 1_000,
            route_id: "direct-nodeA-nodeB".into(),
            rtt_ms: 20.0,
            packet_loss_pct: 1.0,
            throughput_mbps: Some(40.0),
            bandwidth_utilization_pct: Some(30.0),
            route_available: true,
            route_healthy: true,
            switched_route: false,
        });
        let output = NetworkAiEngine::new(&NetworkAiConfig::default()).run(
            NetworkAiCycleInput {
                now_ms: 2_000,
                traffic_class: TrafficClass::Operational,
                candidates,
                history: &history,
                task1_signal: None,
                trust_state: TrustStateSnapshot::new("task2-test").trust_peer("nodeB"),
                relay_health: vec![],
            },
            &ContextualBanditPolicy::new(0.25, 0.0),
        );
        assert!(!output.eligible_routes.eligible.is_empty());
        assert_eq!(
            output.predictions.predictions.len(),
            output.eligible_routes.eligible.len()
        );
        assert!(output.rl_decision.selected_route_id.is_some());
    }

    #[test]
    fn failed_feedback_is_applied_before_route_selection() {
        let candidates = RouteCandidateInventory::from_relays(
            "nodeA",
            "nodeB",
            TrafficClass::Operational,
            ["nodeC"],
        )
        .candidates;
        let history = RouteHistoryStore::new(1.0, 8);
        let mut policy = ContextualBanditPolicy::new(1.0, 0.0);
        let output = NetworkAiEngine::new(&NetworkAiConfig::default()).run_with_observed_feedback(
            NetworkAiCycleInput {
                now_ms: 2_000,
                traffic_class: TrafficClass::Operational,
                candidates,
                history: &history,
                task1_signal: None,
                trust_state: TrustStateSnapshot::new("task2-test")
                    .trust_peer("nodeB")
                    .trust_peer("nodeC"),
                relay_health: vec![],
            },
            &mut policy,
            &[ObservedRewardInput {
                route_id: "direct-nodeA-nodeB".into(),
                rtt_ms: Some(500.0),
                packet_loss_pct: Some(100.0),
                throughput_mbps: Some(0.0),
                bandwidth_utilization_pct: Some(100.0),
                hop_count: 0,
                switched_route: false,
                route_failed: true,
            }],
            &NetworkAiConfig::default().reward_weights,
        );
        assert!(output.rewards[0].total_reward < 0.0);
        assert!(policy.action_values["direct-nodeA-nodeB"].q_value < 0.0);
        assert_ne!(
            output.cycle.rl_decision.selected_route_id.as_deref(),
            Some("direct-nodeA-nodeB")
        );
    }

    #[test]
    fn complete_cycle_orders_feedback_safety_action_and_d14_persistence() {
        let root =
            std::env::temp_dir().join(format!("network-ai-complete-cycle-{}", std::process::id()));
        let paths = DecisionAuditPaths::under(&root);
        let candidates = RouteCandidateInventory::from_relays(
            "nodeA",
            "nodeB",
            TrafficClass::Operational,
            ["nodeC"],
        )
        .candidates;
        let history = RouteHistoryStore::new(1.0, 8);
        let mut policy = ContextualBanditPolicy::new(1.0, 0.0);
        let observation = ObservedRewardInput {
            route_id: "direct-nodeA-nodeB".into(),
            rtt_ms: Some(500.0),
            packet_loss_pct: Some(100.0),
            throughput_mbps: Some(0.0),
            bandwidth_utilization_pct: Some(100.0),
            hop_count: 0,
            switched_route: false,
            route_failed: false,
        };
        let output = NetworkAiEngine::new(&NetworkAiConfig::default())
            .run_complete_cycle(
                NetworkAiCycleInput {
                    now_ms: 2_000,
                    traffic_class: TrafficClass::Operational,
                    candidates,
                    history: &history,
                    task1_signal: None,
                    trust_state: TrustStateSnapshot::new("fresh")
                        .trust_peer("nodeB")
                        .trust_peer("nodeC"),
                    relay_health: vec![],
                },
                &mut policy,
                &[ObservedRewardInput {
                    route_failed: true,
                    ..observation.clone()
                }],
                &NetworkAiConfig::default().reward_weights,
                &RouteSwitchState {
                    current_route_id: "direct-nodeA-nodeB".into(),
                    current_route_started_ms: 0,
                    last_switch_ms: None,
                    switch_timestamps_ms: vec![],
                },
                None,
                true,
                &observation,
                true,
                "complete-cycle-1".into(),
                None,
                None,
                DecisionEvidenceLinks {
                    route_history_path: "history.json".into(),
                    observed_outcomes_path: "outcomes.jsonl".into(),
                    rewards_path: paths.rewards_jsonl.display().to_string(),
                    degradation_events_path: paths.degradation_events_jsonl.display().to_string(),
                    task1_source_path: None,
                    task2_trust_source_path: None,
                    task2_trust_version: Some("fresh".into()),
                },
                |_, request| {
                    Ok(RuntimeModeExecution {
                        decision: RuntimeModeDecision {
                            schema_version: "test".into(),
                            mode: NetworkAiRuntimeMode::Shadow,
                            current_route_id: "direct-nodeA-nodeB".into(),
                            selected_route_id: request.requested_route_id.clone(),
                            applied: false,
                            reason: "adapter invoked after safety plan".into(),
                        },
                        route_result: None,
                        sensitive_handoff: None,
                    })
                },
                |audit| persist_decision_audit(audit, &paths),
            )
            .unwrap();
        assert!(policy.action_values["direct-nodeA-nodeB"].q_value < 0.0);
        assert!(
            output.action.safety_decision.hard_failover || !output.action.safety_decision.allowed
        );
        assert_eq!(output.audit.decision_id, "complete-cycle-1");
        assert!(paths.current_decision.exists() && paths.rewards_jsonl.exists());
        let _ = std::fs::remove_dir_all(root);
    }
}
