//! Task 3 Deliverable 6: reward function for route learning.

use super::{config::NetworkAiRewardWeights, predictor::RoutePrediction};
use serde::{Deserialize, Serialize};

pub const NETWORK_AI_REWARD_VERSION: &str = "route-reward-v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RewardComponents {
    pub latency_reward: f64,
    pub throughput_reward: f64,
    pub packet_loss_penalty: f64,
    pub congestion_penalty: f64,
    pub hop_penalty: f64,
    pub route_switch_penalty: f64,
    pub failure_penalty: f64,
}

impl RewardComponents {
    pub fn total(&self) -> f64 {
        self.latency_reward + self.throughput_reward
            - self.packet_loss_penalty
            - self.congestion_penalty
            - self.hop_penalty
            - self.route_switch_penalty
            - self.failure_penalty
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteReward {
    pub reward_version: String,
    pub route_id: String,
    pub total_reward: f64,
    pub components: RewardComponents,
    pub reason: String,
}

/// Actual route outcome supplied after an attempted route decision. This is
/// the reward input intended to train/update contextual-bandit Q values;
/// prediction rewards remain estimates for pre-decision ranking.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservedRewardInput {
    pub route_id: String,
    pub rtt_ms: Option<f64>,
    pub packet_loss_pct: Option<f64>,
    pub throughput_mbps: Option<f64>,
    pub bandwidth_utilization_pct: Option<f64>,
    pub hop_count: u8,
    pub switched_route: bool,
    pub route_failed: bool,
}

impl RouteReward {
    pub fn from_prediction(
        prediction: &RoutePrediction,
        hop_count: u8,
        switched_route: bool,
        route_failed: bool,
    ) -> Self {
        Self::from_prediction_with_weights(
            prediction,
            hop_count,
            switched_route,
            route_failed,
            &NetworkAiRewardWeights::default(),
        )
    }

    pub fn from_prediction_with_weights(
        prediction: &RoutePrediction,
        hop_count: u8,
        switched_route: bool,
        route_failed: bool,
        weights: &NetworkAiRewardWeights,
    ) -> Self {
        Self::from_metrics_with_weights(
            &prediction.route_id,
            prediction.expected_latency_ms,
            prediction.expected_loss_pct,
            prediction.expected_throughput_mbps,
            0.0,
            hop_count,
            switched_route,
            route_failed,
            weights,
            "estimated prediction",
        )
    }

    pub fn from_observed_outcome(input: &ObservedRewardInput) -> Self {
        Self::from_observed_outcome_with_weights(input, &NetworkAiRewardWeights::default())
    }

    pub fn from_observed_outcome_with_weights(
        input: &ObservedRewardInput,
        weights: &NetworkAiRewardWeights,
    ) -> Self {
        let latency_reward = input
            .rtt_ms
            .map(|latency_ms| {
                (100.0 - latency_ms.min(100.0)).max(0.0) * weights.latency_reward_weight
            })
            .unwrap_or(0.0);

        let throughput_reward = input
            .throughput_mbps
            .map(|throughput_mbps| throughput_mbps.min(100.0) * weights.throughput_reward_weight)
            .unwrap_or(0.0);

        let packet_loss_penalty = input
            .packet_loss_pct
            .map(|packet_loss_pct| packet_loss_pct.min(100.0) * weights.packet_loss_penalty_weight)
            .unwrap_or(0.0);

        let congestion_observed = input
            .throughput_mbps
            .map(|throughput_mbps| throughput_mbps < 10.0)
            .unwrap_or(false)
            || input
                .bandwidth_utilization_pct
                .map(|utilization_pct| utilization_pct >= 85.0)
                .unwrap_or(false);

        let congestion_penalty = if congestion_observed {
            weights.congestion_penalty
        } else {
            0.0
        };

        let hop_penalty = input.hop_count as f64 * weights.hop_penalty_weight;
        let route_switch_penalty = if input.switched_route {
            weights.route_switch_penalty
        } else {
            0.0
        };
        let failure_penalty = if input.route_failed {
            weights.failure_penalty
        } else {
            0.0
        };

        let components = RewardComponents {
            latency_reward,
            throughput_reward,
            packet_loss_penalty,
            congestion_penalty,
            hop_penalty,
            route_switch_penalty,
            failure_penalty,
        };
        let total_reward = components.total();

        Self {
            reward_version: NETWORK_AI_REWARD_VERSION.to_string(),
            route_id: input.route_id.clone(),
            total_reward,
            components,
            reason: format!(
                "actual observed outcome reward={total_reward:.2}; only available measured metrics contributed; loss/congestion/hops/switch/failure penalized"
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn from_metrics_with_weights(
        route_id: &str,
        latency_ms: f64,
        packet_loss_pct: f64,
        throughput_mbps: f64,
        bandwidth_utilization_pct: f64,
        hop_count: u8,
        switched_route: bool,
        route_failed: bool,
        weights: &NetworkAiRewardWeights,
        source: &str,
    ) -> Self {
        let latency_reward =
            (100.0 - latency_ms.min(100.0)).max(0.0) * weights.latency_reward_weight;
        let throughput_reward = throughput_mbps.min(100.0) * weights.throughput_reward_weight;
        let packet_loss_penalty = packet_loss_pct.min(100.0) * weights.packet_loss_penalty_weight;
        let congestion_penalty = if throughput_mbps < 10.0 || bandwidth_utilization_pct >= 85.0 {
            weights.congestion_penalty
        } else {
            0.0
        };
        let hop_penalty = hop_count as f64 * weights.hop_penalty_weight;
        let route_switch_penalty = if switched_route {
            weights.route_switch_penalty
        } else {
            0.0
        };
        let failure_penalty = if route_failed {
            weights.failure_penalty
        } else {
            0.0
        };

        let components = RewardComponents {
            latency_reward,
            throughput_reward,
            packet_loss_penalty,
            congestion_penalty,
            hop_penalty,
            route_switch_penalty,
            failure_penalty,
        };
        let total_reward = components.total();

        Self {
            reward_version: NETWORK_AI_REWARD_VERSION.to_string(),
            route_id: route_id.to_string(),
            total_reward,
            components,
            reason: format!(
                "{source} reward={total_reward:.2}; low latency and high throughput rewarded; loss/congestion/hops/switch/failure penalized"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_ai::{
        RoutePrediction, RouteQualityComponents, NETWORK_AI_PREDICTOR_VERSION,
    };

    fn prediction(route_id: &str, latency: f64, loss: f64, throughput: f64) -> RoutePrediction {
        RoutePrediction {
            route_id: route_id.to_string(),
            model_version: NETWORK_AI_PREDICTOR_VERSION.to_string(),
            expected_latency_ms: latency,
            expected_loss_pct: loss,
            expected_throughput_mbps: throughput,
            confidence: 0.8,
            quality_score: 1.0,
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
            components: RouteQualityComponents {
                latency_component: 1.0,
                throughput_component: 1.0,
                loss_penalty: 0.0,
                hop_penalty: 0.0,
                failure_penalty: 0.0,
                availability_penalty: 0.0,
                task1_anomaly_component: 0.0,
                total_score: 1.0,
            },
            reason: "test".to_string(),
        }
    }

    #[test]
    fn low_latency_high_throughput_gets_better_reward() {
        let good =
            RouteReward::from_prediction(&prediction("good", 15.0, 0.2, 70.0), 1, false, false);
        let bad = RouteReward::from_prediction(&prediction("bad", 90.0, 10.0, 5.0), 3, true, false);

        assert!(good.total_reward > bad.total_reward);
    }

    #[test]
    fn route_failure_is_heavily_penalized() {
        let ok = RouteReward::from_prediction(&prediction("r1", 20.0, 1.0, 40.0), 1, false, false);
        let failed =
            RouteReward::from_prediction(&prediction("r1", 20.0, 1.0, 40.0), 1, false, true);

        assert!(failed.total_reward < ok.total_reward);
        assert_eq!(failed.components.failure_penalty, 50.0);
    }

    #[test]
    fn observed_bad_route_is_penalized_even_when_prediction_was_optimistic() {
        let optimistic =
            RouteReward::from_prediction(&prediction("relay", 10.0, 0.1, 90.0), 1, false, false);
        let actual = RouteReward::from_observed_outcome(&ObservedRewardInput {
            route_id: "relay".to_string(),
            rtt_ms: Some(95.0),
            packet_loss_pct: Some(40.0),
            throughput_mbps: Some(2.0),
            bandwidth_utilization_pct: Some(95.0),
            hop_count: 1,
            switched_route: true,
            route_failed: false,
        });

        assert!(actual.total_reward < optimistic.total_reward);
        assert!(actual.components.congestion_penalty > 0.0);
        assert!(actual.reason.contains("actual observed outcome"));
    }

    #[test]
    fn observed_good_route_is_rewarded_even_when_prediction_was_conservative() {
        let conservative =
            RouteReward::from_prediction(&prediction("relay", 90.0, 10.0, 5.0), 1, false, false);
        let actual = RouteReward::from_observed_outcome(&ObservedRewardInput {
            route_id: "relay".to_string(),
            rtt_ms: Some(12.0),
            packet_loss_pct: Some(0.1),
            throughput_mbps: Some(85.0),
            bandwidth_utilization_pct: Some(30.0),
            hop_count: 1,
            switched_route: false,
            route_failed: false,
        });

        assert!(actual.total_reward > conservative.total_reward);
    }

    #[test]
    fn observed_missing_metrics_are_not_fabricated() {
        let actual = RouteReward::from_observed_outcome(&ObservedRewardInput {
            route_id: "direct-nodeA-nodeB".to_string(),
            rtt_ms: Some(12.0),
            packet_loss_pct: Some(0.2),
            throughput_mbps: None,
            bandwidth_utilization_pct: None,
            hop_count: 0,
            switched_route: false,
            route_failed: false,
        });

        assert!(actual.components.latency_reward > 0.0);
        assert_eq!(actual.components.throughput_reward, 0.0);
        assert_eq!(actual.components.congestion_penalty, 0.0);
        assert_eq!(actual.components.failure_penalty, 0.0);
    }

    #[test]
    fn observed_transport_failure_needs_no_fake_performance_metrics() {
        let actual = RouteReward::from_observed_outcome(&ObservedRewardInput {
            route_id: "direct-nodeA-nodeB".to_string(),
            rtt_ms: None,
            packet_loss_pct: None,
            throughput_mbps: None,
            bandwidth_utilization_pct: None,
            hop_count: 0,
            switched_route: true,
            route_failed: true,
        });

        assert_eq!(actual.components.latency_reward, 0.0);
        assert_eq!(actual.components.throughput_reward, 0.0);
        assert_eq!(actual.components.packet_loss_penalty, 0.0);
        assert_eq!(actual.components.congestion_penalty, 0.0);
        assert!(actual.components.failure_penalty > 0.0);
    }
}
