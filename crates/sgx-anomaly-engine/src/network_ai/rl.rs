//! Task 3 Deliverable 6: safe contextual bandit route policy.
//!
//! V1 keeps a deterministic Q-value table over discrete route IDs. It does not
//! override eligibility/safety; callers must pass only eligible routes.

use super::predictor::RoutePredictionSet;
use super::reward::RouteReward;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub const NETWORK_AI_RL_VERSION: &str = "contextual-bandit-v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteActionValue {
    pub route_id: String,
    pub q_value: f64,
    pub update_count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteLearningDecision {
    pub rl_version: String,
    pub selected_route_id: Option<String>,
    pub decision_mode: String,
    pub reason: String,
    pub action_values: Vec<RouteActionValue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextualBanditPolicy {
    pub rl_version: String,
    pub learning_rate: f64,
    pub epsilon: f64,
    pub action_values: BTreeMap<String, RouteActionValue>,
}

impl ContextualBanditPolicy {
    pub fn new(learning_rate: f64, epsilon: f64) -> Self {
        assert!(
            learning_rate > 0.0 && learning_rate <= 1.0,
            "learning_rate must be in (0, 1]"
        );
        assert!(
            epsilon >= 0.0 && epsilon <= 1.0,
            "epsilon must be in [0, 1]"
        );
        Self {
            rl_version: NETWORK_AI_RL_VERSION.to_string(),
            learning_rate,
            epsilon,
            action_values: BTreeMap::new(),
        }
    }

    pub fn choose_exploit(&self, predictions: &RoutePredictionSet) -> RouteLearningDecision {
        let mut ranked = predictions
            .predictions
            .iter()
            .map(|prediction| {
                // An unseen eligible route must not be permanently suppressed
                // just because another route already has a learned positive Q-value.
                // Use the current deterministic route-quality prediction as its
                // initial prior until real rewards create a learned action value.
                let q_value = self
                    .action_values
                    .get(&prediction.route_id)
                    .map(|value| value.q_value)
                    .unwrap_or(prediction.quality_score);
                (
                    prediction.route_id.clone(),
                    q_value,
                    prediction.quality_score,
                )
            })
            .collect::<Vec<_>>();

        ranked.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal))
                .then_with(|| a.0.cmp(&b.0))
        });

        let selected_route_id = ranked.first().map(|entry| entry.0.clone());
        RouteLearningDecision {
            rl_version: self.rl_version.clone(),
            selected_route_id: selected_route_id.clone(),
            decision_mode: "exploit_best_q_value".to_string(),
            reason: selected_route_id
                .as_ref()
                .map(|route| {
                    format!("selected {route} from eligible predictions using saved Q-values")
                })
                .unwrap_or_else(|| "no eligible prediction available".to_string()),
            action_values: self.action_values.values().cloned().collect(),
        }
    }

    /// Bounded epsilon exploration. `sample` is supplied by the caller so a
    /// replay can be deterministic; epsilon=0 always performs reproducible exploitation.
    pub fn choose_with_epsilon(
        &self,
        predictions: &RoutePredictionSet,
        sample: f64,
    ) -> RouteLearningDecision {
        let bounded_sample = if sample.is_finite() {
            sample.clamp(0.0, 1.0)
        } else {
            1.0
        };
        if self.epsilon <= 0.0
            || bounded_sample >= self.epsilon
            || predictions.predictions.is_empty()
        {
            return self.choose_exploit(predictions);
        }
        let mut choices = predictions.predictions.iter().collect::<Vec<_>>();
        choices.sort_by(|a, b| a.route_id.cmp(&b.route_id));
        let scaled = (bounded_sample / self.epsilon).clamp(0.0, 0.999_999);
        let index = (scaled * choices.len() as f64) as usize;
        let selected = choices[index].route_id.clone();
        RouteLearningDecision {
            rl_version: self.rl_version.clone(),
            selected_route_id: Some(selected.clone()),
            decision_mode: "bounded_epsilon_exploration".to_string(),
            reason: format!(
                "selected {selected} from eligible routes using bounded epsilon={:.3}",
                self.epsilon
            ),
            action_values: self.action_values.values().cloned().collect(),
        }
    }

    pub fn update_with_reward(&mut self, reward: &RouteReward) -> RouteActionValue {
        let entry = self
            .action_values
            .entry(reward.route_id.clone())
            .or_insert_with(|| RouteActionValue {
                route_id: reward.route_id.clone(),
                q_value: 0.0,
                update_count: 0,
            });

        entry.q_value = entry.q_value + self.learning_rate * (reward.total_reward - entry.q_value);
        entry.update_count += 1;
        entry.clone()
    }

    pub fn save_json(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating RL policy directory {}", parent.display()))?;
        }
        let json = serde_json::to_string_pretty(self).context("serializing RL policy")?;
        fs::write(path, json).with_context(|| format!("writing RL policy {}", path.display()))?;
        Ok(())
    }

    pub fn load_json(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let json = fs::read_to_string(path)
            .with_context(|| format!("reading RL policy {}", path.display()))?;
        serde_json::from_str(&json).context("parsing RL policy")
    }

    /// Restores durable Q-values after a process restart, or creates the
    /// initial policy for a route pair that has not been observed before.
    pub fn load_or_new(path: impl AsRef<Path>, learning_rate: f64, epsilon: f64) -> Result<Self> {
        let path = path.as_ref();
        if path.exists() {
            Self::load_json(path)
        } else {
            Ok(Self::new(learning_rate, epsilon))
        }
    }
}

impl Default for ContextualBanditPolicy {
    fn default() -> Self {
        Self::new(0.25, 0.05)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_ai::{
        RoutePrediction, RoutePredictionSet, RouteQualityComponents, RouteReward,
        NETWORK_AI_PREDICTOR_VERSION,
    };

    fn prediction(route_id: &str, score: f64) -> RoutePrediction {
        RoutePrediction {
            route_id: route_id.to_string(),
            model_version: NETWORK_AI_PREDICTOR_VERSION.to_string(),
            expected_latency_ms: 20.0,
            expected_loss_pct: 1.0,
            expected_throughput_mbps: 40.0,
            confidence: 0.8,
            quality_score: score,
            components: RouteQualityComponents {
                latency_component: score,
                throughput_component: 0.0,
                loss_penalty: 0.0,
                hop_penalty: 0.0,
                failure_penalty: 0.0,
                availability_penalty: 0.0,
                task1_anomaly_component: 0.0,
                total_score: score,
            },
            features: crate::network_ai::NetworkAiFeatureVector {
                schema_version: "network-ai-v1".to_string(),
                route_id: route_id.to_string(),
                normalized_latency: 0.0,
                normalized_loss: 0.0,
                normalized_throughput: 0.0,
                normalized_utilization: 0.0,
                normalized_hops: 0.0,
                normalized_success_rate: 0.0,
                normalized_failure_rate: 0.0,
                normalized_route_age: 0.0,
                priority: 0.0,
                task1_anomaly_score: 0.0,
                missing_history: true,
                explainability: vec![],
            },
            reason: "test".to_string(),
        }
    }

    fn prediction_set() -> RoutePredictionSet {
        RoutePredictionSet {
            model_version: NETWORK_AI_PREDICTOR_VERSION.to_string(),
            feature_schema_version: "network-ai-v1".to_string(),
            predictions: vec![prediction("route-a", 10.0), prediction("route-b", 20.0)],
            selected_route_id: Some("route-b".to_string()),
        }
    }

    #[test]
    fn starts_with_prediction_score_when_no_rewards_exist() {
        let policy = ContextualBanditPolicy::default();
        let decision = policy.choose_exploit(&prediction_set());

        assert_eq!(decision.selected_route_id.as_deref(), Some("route-b"));
    }

    #[test]
    fn reward_updates_q_value() {
        let mut policy = ContextualBanditPolicy::new(0.5, 0.0);
        let reward = RouteReward {
            reward_version: "test".to_string(),
            route_id: "route-a".to_string(),
            total_reward: 40.0,
            components: crate::network_ai::RewardComponents {
                latency_reward: 40.0,
                throughput_reward: 0.0,
                packet_loss_penalty: 0.0,
                congestion_penalty: 0.0,
                hop_penalty: 0.0,
                route_switch_penalty: 0.0,
                failure_penalty: 0.0,
            },
            reason: "test".to_string(),
        };

        let value = policy.update_with_reward(&reward);

        assert_eq!(value.update_count, 1);
        assert!((value.q_value - 20.0).abs() < 1e-9);
    }

    #[test]
    fn observed_outcome_reward_updates_q_value_not_prediction_estimate() {
        let mut policy = ContextualBanditPolicy::new(1.0, 0.0);
        let observed =
            RouteReward::from_observed_outcome(&crate::network_ai::ObservedRewardInput {
                route_id: "route-a".to_string(),
                rtt_ms: Some(95.0),
                packet_loss_pct: Some(40.0),
                throughput_mbps: Some(2.0),
                bandwidth_utilization_pct: Some(95.0),
                hop_count: 1,
                switched_route: true,
                route_failed: true,
            });

        let value = policy.update_with_reward(&observed);

        assert_eq!(value.q_value, observed.total_reward);
        assert!(value.q_value < 0.0);
    }

    #[test]
    fn failed_current_route_is_penalized_before_later_route_selection() {
        let predictions = RoutePredictionSet {
            model_version: NETWORK_AI_PREDICTOR_VERSION.to_string(),
            feature_schema_version: "network-ai-v1".to_string(),
            predictions: vec![
                prediction("failed-direct", 20.0),
                prediction("healthy-relay", 10.0),
            ],
            selected_route_id: Some("failed-direct".to_string()),
        };
        let mut policy = ContextualBanditPolicy::new(1.0, 0.0);
        assert_eq!(
            policy
                .choose_exploit(&predictions)
                .selected_route_id
                .as_deref(),
            Some("failed-direct")
        );

        let failed = RouteReward::from_observed_outcome(&crate::network_ai::ObservedRewardInput {
            route_id: "failed-direct".to_string(),
            rtt_ms: Some(95.0),
            packet_loss_pct: Some(40.0),
            throughput_mbps: Some(2.0),
            bandwidth_utilization_pct: Some(95.0),
            hop_count: 0,
            switched_route: false,
            route_failed: true,
        });
        assert!(failed.components.failure_penalty > 0.0);
        let updated = policy.update_with_reward(&failed);
        assert!(updated.q_value < 0.0);
        assert_eq!(
            policy
                .choose_exploit(&predictions)
                .selected_route_id
                .as_deref(),
            Some("healthy-relay")
        );
    }

    #[test]
    fn load_or_new_preserves_q_values_and_update_counts_across_restarts() {
        let root =
            std::env::temp_dir().join(format!("network-ai-rl-restart-{}", std::process::id()));
        let path = root.join("rl_policy.json");
        let reward = RouteReward::from_observed_outcome(&crate::network_ai::ObservedRewardInput {
            route_id: "route-a".to_string(),
            rtt_ms: Some(20.0),
            packet_loss_pct: Some(1.0),
            throughput_mbps: Some(40.0),
            bandwidth_utilization_pct: Some(30.0),
            hop_count: 1,
            switched_route: false,
            route_failed: false,
        });

        let mut first = ContextualBanditPolicy::load_or_new(&path, 0.5, 0.0).unwrap();
        let first_value = first.update_with_reward(&reward);
        first.save_json(&path).unwrap();

        let mut restarted = ContextualBanditPolicy::load_or_new(&path, 0.5, 0.0).unwrap();
        let restored = restarted.action_values.get("route-a").unwrap();
        assert_eq!(restored.update_count, 1);
        assert_eq!(restored.q_value, first_value.q_value);
        let evolved = restarted.update_with_reward(&reward);
        assert_eq!(evolved.update_count, 2);
        assert_ne!(evolved.q_value, first_value.q_value);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn saved_policy_produces_reproducible_exploit_decision() {
        let tmp_root =
            std::env::temp_dir().join(format!("network-ai-rl-test-{}", std::process::id()));
        let path = tmp_root.join("rl_policy.json");
        let mut policy = ContextualBanditPolicy::new(1.0, 0.20);
        policy.update_with_reward(&RouteReward {
            reward_version: "test".to_string(),
            route_id: "route-a".to_string(),
            total_reward: 50.0,
            components: crate::network_ai::RewardComponents {
                latency_reward: 50.0,
                throughput_reward: 0.0,
                packet_loss_penalty: 0.0,
                congestion_penalty: 0.0,
                hop_penalty: 0.0,
                route_switch_penalty: 0.0,
                failure_penalty: 0.0,
            },
            reason: "test".to_string(),
        });
        policy.save_json(&path).unwrap();

        let loaded = ContextualBanditPolicy::load_json(&path).unwrap();
        let decision = loaded.choose_exploit(&prediction_set());

        assert_eq!(decision.selected_route_id.as_deref(), Some("route-a"));
        assert_eq!(loaded.epsilon, 0.20);

        let _ = std::fs::remove_dir_all(tmp_root);
    }

    #[test]
    fn bounded_epsilon_exploration_is_deterministic_and_never_uses_ineligible_route() {
        let policy = ContextualBanditPolicy::new(0.25, 0.20);
        let explored = policy.choose_with_epsilon(&prediction_set(), 0.10);
        assert_eq!(explored.decision_mode, "bounded_epsilon_exploration");
        assert!(matches!(
            explored.selected_route_id.as_deref(),
            Some("route-a") | Some("route-b")
        ));
        let replay = policy.choose_with_epsilon(&prediction_set(), 0.10);
        assert_eq!(explored, replay);
        let exploit = policy.choose_with_epsilon(&prediction_set(), 0.90);
        assert_eq!(exploit.decision_mode, "exploit_best_q_value");
    }
}
