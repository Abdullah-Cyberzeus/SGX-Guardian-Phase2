//! Task 3 Deliverable 4: interpretable route quality prediction model.
//!
//! V1 is intentionally lightweight and deterministic. It is an interpretable
//! predictor over already-eligible routes, not a hidden black-box claim.

use super::candidates::RouteCandidate;
use super::features::{
    NetworkAiFeatureBuilder, NetworkAiFeatureVector, NETWORK_AI_FEATURE_SCHEMA_VERSION,
};
use super::history::RouteHistoryStore;
use super::task1_bridge::Task1RouteSignal;
use serde::{Deserialize, Serialize};

pub const NETWORK_AI_PREDICTOR_VERSION: &str = "route-quality-v1-interpretable";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteQualityComponents {
    pub latency_component: f64,
    pub throughput_component: f64,
    pub loss_penalty: f64,
    pub hop_penalty: f64,
    pub failure_penalty: f64,
    pub availability_penalty: f64,
    pub task1_anomaly_component: f64,
    pub total_score: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoutePrediction {
    pub route_id: String,
    pub model_version: String,
    pub expected_latency_ms: f64,
    pub expected_loss_pct: f64,
    pub expected_throughput_mbps: f64,
    pub confidence: f64,
    pub quality_score: f64,
    pub features: NetworkAiFeatureVector,
    pub components: RouteQualityComponents,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoutePredictionSet {
    pub model_version: String,
    pub feature_schema_version: String,
    pub predictions: Vec<RoutePrediction>,
    pub selected_route_id: Option<String>,
}

pub trait RoutePredictor {
    fn predict(
        &self,
        candidates: &[RouteCandidate],
        history: &RouteHistoryStore,
    ) -> RoutePredictionSet;
}

#[derive(Debug, Clone)]
pub struct SimpleRouteQualityPredictor {
    pub feature_schema_version: String,
    pub default_latency_ms: f64,
    pub default_loss_pct: f64,
    pub default_throughput_mbps: f64,
}

impl Default for SimpleRouteQualityPredictor {
    fn default() -> Self {
        Self {
            feature_schema_version: "network-ai-v1".to_string(),
            default_latency_ms: 75.0,
            default_loss_pct: 2.0,
            default_throughput_mbps: 25.0,
        }
    }
}

impl RoutePredictor for SimpleRouteQualityPredictor {
    fn predict(
        &self,
        candidates: &[RouteCandidate],
        history: &RouteHistoryStore,
    ) -> RoutePredictionSet {
        let mut predictions: Vec<RoutePrediction> = candidates
            .iter()
            .map(|candidate| self.predict_one(candidate, history, None, 0))
            .collect();

        predictions.sort_by(|a, b| {
            b.quality_score
                .partial_cmp(&a.quality_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.route_id.cmp(&b.route_id))
        });

        let selected_route_id = predictions
            .first()
            .map(|prediction| prediction.route_id.clone());

        RoutePredictionSet {
            model_version: NETWORK_AI_PREDICTOR_VERSION.to_string(),
            feature_schema_version: NETWORK_AI_FEATURE_SCHEMA_VERSION.to_string(),
            predictions,
            selected_route_id,
        }
    }
}

impl SimpleRouteQualityPredictor {
    pub fn predict_with_task1_signal(
        &self,
        candidates: &[RouteCandidate],
        history: &RouteHistoryStore,
        task1_signal: Option<&Task1RouteSignal>,
        now_ms: u64,
    ) -> RoutePredictionSet {
        let mut predictions: Vec<RoutePrediction> = candidates
            .iter()
            .map(|candidate| self.predict_one(candidate, history, task1_signal, now_ms))
            .collect();
        predictions.sort_by(|a, b| {
            b.quality_score
                .partial_cmp(&a.quality_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.route_id.cmp(&b.route_id))
        });
        RoutePredictionSet {
            model_version: NETWORK_AI_PREDICTOR_VERSION.to_string(),
            feature_schema_version: NETWORK_AI_FEATURE_SCHEMA_VERSION.to_string(),
            selected_route_id: predictions
                .first()
                .map(|prediction| prediction.route_id.clone()),
            predictions,
        }
    }

    fn predict_one(
        &self,
        candidate: &RouteCandidate,
        history: &RouteHistoryStore,
        task1_signal: Option<&Task1RouteSignal>,
        now_ms: u64,
    ) -> RoutePrediction {
        let stats = history.stats_for(&candidate.route_id);
        let features =
            NetworkAiFeatureBuilder::build(candidate, history, stats, task1_signal, now_ms);
        let expected_latency_ms = stats
            .map(|s| s.ewma_latency_ms)
            .unwrap_or(self.default_latency_ms + candidate.hop_count as f64 * 12.0);
        let expected_loss_pct = stats
            .map(|s| s.ewma_loss_pct)
            .unwrap_or(self.default_loss_pct);
        let expected_throughput_mbps = stats
            .map(|s| s.ewma_throughput_mbps)
            .unwrap_or((self.default_throughput_mbps - candidate.hop_count as f64 * 3.0).max(1.0));
        let success_rate = stats.map(|s| s.success_rate).unwrap_or(0.50);
        let sample_count = stats.map(|s| s.sample_count).unwrap_or(0);

        let latency_component = (100.0 - expected_latency_ms.min(100.0)).max(0.0) * 0.40;
        let throughput_component = expected_throughput_mbps.min(100.0) * 0.35;
        let loss_penalty = expected_loss_pct.min(100.0) * 0.45;
        let hop_penalty = candidate.hop_count as f64 * 2.5;
        let failure_penalty = (1.0 - success_rate).clamp(0.0, 1.0) * 20.0;
        let availability_penalty = if candidate.observed_available && candidate.observed_healthy {
            0.0
        } else {
            100.0
        };
        // Task1 signal is risk/priority context, never an eligibility bypass.
        let task1_anomaly_component = features.task1_anomaly_score * features.priority * 5.0;

        let total_score = latency_component + throughput_component
            - loss_penalty
            - hop_penalty
            - failure_penalty
            - availability_penalty
            + task1_anomaly_component;

        let confidence = if sample_count == 0 {
            0.35
        } else {
            (0.45 + (sample_count as f64 / 10.0).min(0.40) + success_rate * 0.15).min(0.95)
        };

        RoutePrediction {
            route_id: candidate.route_id.clone(),
            model_version: NETWORK_AI_PREDICTOR_VERSION.to_string(),
            expected_latency_ms,
            expected_loss_pct,
            expected_throughput_mbps,
            confidence,
            quality_score: total_score,
            features: features.clone(),
            components: RouteQualityComponents {
                latency_component,
                throughput_component,
                loss_penalty,
                hop_penalty,
                failure_penalty,
                availability_penalty,
                task1_anomaly_component,
                total_score,
            },
            reason: format!(
                "score={:.2}; latency={:.1}ms, loss={:.1}%, throughput={:.1}Mbps, hops={}, history_samples={}, task1_anomaly={:.3}",
                total_score,
                expected_latency_ms,
                expected_loss_pct,
                expected_throughput_mbps,
                candidate.hop_count,
                sample_count,
                features.task1_anomaly_score
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_ai::{
        RouteCandidateInventory, RouteHistoryEntry, RouteHistoryStore, TrafficClass,
    };

    fn history() -> RouteHistoryStore {
        let mut store = RouteHistoryStore::new(0.5, 20);
        store.record(RouteHistoryEntry {
            ts_ms: 1000,
            route_id: "direct-nodeA-nodeB".to_string(),
            rtt_ms: 60.0,
            packet_loss_pct: 4.0,
            throughput_mbps: 20.0,
            bandwidth_utilization_pct: 30.0,
            route_available: true,
            route_healthy: true,
            switched_route: false,
        });
        store.record(RouteHistoryEntry {
            ts_ms: 1000,
            route_id: "relay-nodeA-via-nodeC-nodeB".to_string(),
            rtt_ms: 25.0,
            packet_loss_pct: 0.5,
            throughput_mbps: 50.0,
            bandwidth_utilization_pct: 30.0,
            route_available: true,
            route_healthy: true,
            switched_route: false,
        });
        store
    }

    #[test]
    fn scores_all_candidates_and_selects_best_quality_route() {
        let inventory = RouteCandidateInventory::from_relays(
            "nodeA",
            "nodeB",
            TrafficClass::Operational,
            ["nodeC"],
        );
        let predictions =
            SimpleRouteQualityPredictor::default().predict(&inventory.candidates, &history());

        assert_eq!(predictions.predictions.len(), 2);
        assert_eq!(
            predictions.selected_route_id.as_deref(),
            Some("relay-nodeA-via-nodeC-nodeB")
        );
    }

    #[test]
    fn same_input_is_deterministic() {
        let inventory = RouteCandidateInventory::from_relays(
            "nodeA",
            "nodeB",
            TrafficClass::Operational,
            ["nodeC"],
        );
        let predictor = SimpleRouteQualityPredictor::default();
        let h = history();

        let first = predictor.predict(&inventory.candidates, &h);
        let second = predictor.predict(&inventory.candidates, &h);

        assert_eq!(first, second);
    }

    #[test]
    fn prediction_exposes_components_and_model_metadata() {
        let inventory = RouteCandidateInventory::from_relays(
            "nodeA",
            "nodeB",
            TrafficClass::Operational,
            ["nodeC"],
        );
        let predictions =
            SimpleRouteQualityPredictor::default().predict(&inventory.candidates, &history());
        let first = predictions.predictions.first().unwrap();

        assert_eq!(first.model_version, NETWORK_AI_PREDICTOR_VERSION);
        assert_eq!(predictions.feature_schema_version, "network-ai-v1");
        assert!(first.confidence > 0.0);
        assert!(first.reason.contains("latency"));
        assert!(first.components.total_score.is_finite());
    }
}
