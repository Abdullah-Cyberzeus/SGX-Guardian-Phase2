//! Task 3 Deliverable 6: reward function for route learning.

use super::predictor::RoutePrediction;
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

impl RouteReward {
    pub fn from_prediction(
        prediction: &RoutePrediction,
        hop_count: u8,
        switched_route: bool,
        route_failed: bool,
    ) -> Self {
        let latency_reward = (100.0 - prediction.expected_latency_ms.min(100.0)).max(0.0) * 0.35;
        let throughput_reward = prediction.expected_throughput_mbps.min(100.0) * 0.30;
        let packet_loss_penalty = prediction.expected_loss_pct.min(100.0) * 0.25;
        let congestion_penalty = if prediction.expected_throughput_mbps < 10.0 {
            8.0
        } else {
            0.0
        };
        let hop_penalty = hop_count as f64 * 1.5;
        let route_switch_penalty = if switched_route { 2.0 } else { 0.0 };
        let failure_penalty = if route_failed { 50.0 } else { 0.0 };

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
            route_id: prediction.route_id.clone(),
            total_reward,
            components,
            reason: format!(
                "reward={total_reward:.2}; low latency and high throughput rewarded; loss/congestion/hops/switch/failure penalized"
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
}
