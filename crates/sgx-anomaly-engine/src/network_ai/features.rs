//! Stable, normalized Task 3 route features used by the interpretable scorer.

use super::candidates::RouteCandidate;
use super::history::{RouteHistoryStore, RoutePerformanceStats};
use super::task1_bridge::Task1RouteSignal;
use super::telemetry_adapter::TrafficClass;
use serde::{Deserialize, Serialize};

pub const NETWORK_AI_FEATURE_SCHEMA_VERSION: &str = "network-ai-v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkAiFeatureVector {
    pub schema_version: String,
    pub route_id: String,
    pub normalized_latency: f64,
    pub normalized_loss: f64,
    pub normalized_throughput: f64,
    pub normalized_utilization: f64,
    pub normalized_hops: f64,
    pub normalized_success_rate: f64,
    pub normalized_failure_rate: f64,
    pub normalized_route_age: f64,
    pub priority: f64,
    pub task1_anomaly_score: f64,
    pub missing_history: bool,
    pub explainability: Vec<String>,
}

pub struct NetworkAiFeatureBuilder;

impl NetworkAiFeatureBuilder {
    pub fn build(
        candidate: &RouteCandidate,
        history: &RouteHistoryStore,
        stats: Option<&RoutePerformanceStats>,
        task1_signal: Option<&Task1RouteSignal>,
        now_ms: u64,
    ) -> NetworkAiFeatureVector {
        let safe = |value: f64| {
            if value.is_finite() {
                value.max(0.0)
            } else {
                0.0
            }
        };
        let missing_history = stats.is_none();
        let (latency, loss, throughput, success_rate, failure_rate, utilization) = stats
            .map(|s| {
                let utilization = history
                    .entries_by_route
                    .get(&candidate.route_id)
                    .and_then(|entries| entries.last())
                    .map(|entry| entry.bandwidth_utilization_pct)
                    .unwrap_or(0.0);
                (
                    s.ewma_latency_ms,
                    s.ewma_loss_pct,
                    s.ewma_throughput_mbps,
                    s.success_rate,
                    if s.sample_count == 0 {
                        0.0
                    } else {
                        s.failure_count as f64 / s.sample_count as f64
                    },
                    utilization,
                )
            })
            .unwrap_or((75.0, 2.0, 25.0, 0.5, 0.0, 0.0));
        let route_age_ms = history
            .entries_by_route
            .get(&candidate.route_id)
            .and_then(|entries| entries.first())
            .map(|entry| now_ms.saturating_sub(entry.ts_ms))
            .unwrap_or(0);
        let anomaly = task1_signal
            .and_then(|signal| signal.max_anomaly_score)
            .filter(|score| score.is_finite())
            .unwrap_or(0.0)
            .clamp(0.0, 1.0);
        let priority = match candidate.traffic_class {
            TrafficClass::SecurityControl => 1.0,
            TrafficClass::Operational => 0.25,
        };
        let mut explainability = vec![format!(
            "feature_schema={NETWORK_AI_FEATURE_SCHEMA_VERSION}"
        )];
        if missing_history {
            explainability.push("missing_history_safe_defaults".to_string());
        }
        if anomaly > 0.0 {
            explainability.push(format!("task1_anomaly_score={anomaly:.3}"));
        }

        NetworkAiFeatureVector {
            schema_version: NETWORK_AI_FEATURE_SCHEMA_VERSION.to_string(),
            route_id: candidate.route_id.clone(),
            normalized_latency: (safe(latency) / 250.0).min(1.0),
            normalized_loss: (safe(loss) / 100.0).min(1.0),
            normalized_throughput: (safe(throughput) / 100.0).min(1.0),
            normalized_utilization: (safe(utilization) / 100.0).min(1.0),
            normalized_hops: (candidate.hop_count as f64 / 5.0).min(1.0),
            normalized_success_rate: safe(success_rate).min(1.0),
            normalized_failure_rate: safe(failure_rate).min(1.0),
            normalized_route_age: (route_age_ms as f64 / 3_600_000.0).min(1.0),
            priority,
            task1_anomaly_score: anomaly,
            missing_history,
            explainability,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_ai::{RouteHistoryEntry, RouteHistoryStore, TrafficClass};

    #[test]
    fn emits_stable_safe_vector_and_includes_task1_anomaly_score() {
        let candidate = RouteCandidate::direct("nodeA", "nodeB", TrafficClass::SecurityControl);
        let mut history = RouteHistoryStore::new(0.5, 5);
        history.record(RouteHistoryEntry {
            ts_ms: 1_000,
            route_id: candidate.route_id.clone(),
            rtt_ms: 50.0,
            packet_loss_pct: 2.0,
            throughput_mbps: 30.0,
            bandwidth_utilization_pct: 20.0,
            route_available: true,
            route_healthy: true,
            switched_route: false,
        });
        let signal = Task1RouteSignal {
            source_path: "test".to_string(),
            run_id: Some("run-test".to_string()),
            node: "nodeA".to_string(),
            recommendation_count: 1,
            recommendation_ids: vec!["rec-test".to_string()],
            max_anomaly_score: Some(0.8),
            max_model_confidence: None,
            max_advisory_confidence: None,
            top_evidence_features: vec![],
            model_metadata_traceable: true,
        };
        let vector = NetworkAiFeatureBuilder::build(
            &candidate,
            &history,
            history.stats_for(&candidate.route_id),
            Some(&signal),
            2_000,
        );
        assert_eq!(vector.schema_version, NETWORK_AI_FEATURE_SCHEMA_VERSION);
        assert_eq!(vector.task1_anomaly_score, 0.8);
        assert!(vector.normalized_latency.is_finite());
        assert!(!vector.missing_history);
    }
}
