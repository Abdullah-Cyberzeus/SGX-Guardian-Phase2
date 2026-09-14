//! Task 3 Deliverable 5: network degradation prediction.
//!
//! This predictor warns before a route reaches a hard failure threshold. It is
//! deterministic and emits contributor labels so the decision remains auditable.

use super::history::RouteHistoryEntry;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

pub const NETWORK_AI_DEGRADATION_MODEL_VERSION: &str = "degradation-v1-interpretable";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DegradationPrediction {
    pub model_version: String,
    pub route_id: String,
    pub probability: f64,
    pub horizon_seconds: u64,
    pub contributors: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct SimpleDegradationPredictor {
    pub horizon_seconds: u64,
    pub high_probability_threshold: f64,
}

pub trait DegradationPredictor {
    fn predict(&self, route_id: &str, recent: &[RouteHistoryEntry]) -> DegradationPrediction;
}

impl Default for SimpleDegradationPredictor {
    fn default() -> Self {
        Self {
            horizon_seconds: 60,
            high_probability_threshold: 0.75,
        }
    }
}

impl DegradationPredictor for SimpleDegradationPredictor {
    fn predict(&self, route_id: &str, recent: &[RouteHistoryEntry]) -> DegradationPrediction {
        if recent.len() < 2 {
            return DegradationPrediction {
                model_version: NETWORK_AI_DEGRADATION_MODEL_VERSION.to_string(),
                route_id: route_id.to_string(),
                probability: 0.10,
                horizon_seconds: self.horizon_seconds,
                contributors: vec!["insufficient_history".to_string()],
                reason: "insufficient route history; degradation kept low-confidence".to_string(),
            };
        }

        let first = recent.first().expect("len checked");
        let last = recent.last().expect("len checked");
        let mut probability: f64 = 0.05;
        let mut contributors = Vec::new();

        if last.rtt_ms > first.rtt_ms * 1.25 && last.rtt_ms - first.rtt_ms > 10.0 {
            probability += 0.30;
            contributors.push("rising_rtt".to_string());
        }

        if last.packet_loss_pct > first.packet_loss_pct + 2.0 || last.packet_loss_pct >= 5.0 {
            probability += 0.25;
            contributors.push("rising_packet_loss".to_string());
        }

        if first.throughput_mbps > 0.0 && last.throughput_mbps < first.throughput_mbps * 0.75 {
            probability += 0.25;
            contributors.push("falling_throughput".to_string());
        }

        if last.bandwidth_utilization_pct >= 85.0 {
            probability += 0.20;
            contributors.push("high_relay_utilization".to_string());
        }

        let failure_count = recent
            .iter()
            .filter(|entry| !entry.route_available || !entry.route_healthy)
            .count();
        if failure_count > 0 {
            probability += (failure_count as f64 * 0.15).min(0.30);
            contributors.push("recent_route_failure".to_string());
        }

        if contributors.is_empty() {
            contributors.push("stable_route".to_string());
        }

        let probability = probability.min(0.95);
        let severity = if probability >= self.high_probability_threshold {
            "high"
        } else if probability >= 0.40 {
            "medium"
        } else {
            "low"
        };

        DegradationPrediction {
            model_version: NETWORK_AI_DEGRADATION_MODEL_VERSION.to_string(),
            route_id: route_id.to_string(),
            probability,
            horizon_seconds: self.horizon_seconds,
            reason: format!(
                "{severity} degradation risk over next {}s; contributors: {}",
                self.horizon_seconds,
                contributors.join(", ")
            ),
            contributors,
        }
    }
}

/// Appends a predictor result as runtime evidence; callers do not need to own persistence.
pub fn append_degradation_prediction_jsonl(
    path: impl AsRef<Path>,
    prediction: &DegradationPrediction,
) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating degradation directory {}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening degradation evidence {}", path.display()))?;
    writeln!(
        file,
        "{}",
        serde_json::to_string(prediction).context("serializing degradation prediction")?
    )
    .with_context(|| format!("writing degradation evidence {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ts_ms: u64, rtt_ms: f64, loss: f64, throughput: f64) -> RouteHistoryEntry {
        RouteHistoryEntry {
            ts_ms,
            route_id: "direct-nodeA-nodeB".to_string(),
            rtt_ms,
            packet_loss_pct: loss,
            throughput_mbps: throughput,
            bandwidth_utilization_pct: 30.0,
            route_available: true,
            route_healthy: true,
            switched_route: false,
        }
    }

    #[test]
    fn emits_low_probability_for_stable_route() {
        let predictor = SimpleDegradationPredictor::default();
        let prediction = predictor.predict(
            "direct-nodeA-nodeB",
            &[entry(1000, 20.0, 0.5, 40.0), entry(2000, 21.0, 0.6, 41.0)],
        );

        assert!(prediction.probability < 0.40);
        assert!(prediction
            .contributors
            .contains(&"stable_route".to_string()));
    }

    #[test]
    fn detects_rising_rtt_loss_and_falling_throughput() {
        let predictor = SimpleDegradationPredictor::default();
        let prediction = predictor.predict(
            "direct-nodeA-nodeB",
            &[entry(1000, 20.0, 0.5, 60.0), entry(2000, 45.0, 6.0, 30.0)],
        );

        assert!(prediction.probability >= 0.75);
        assert!(prediction.contributors.contains(&"rising_rtt".to_string()));
        assert!(prediction
            .contributors
            .contains(&"rising_packet_loss".to_string()));
        assert!(prediction
            .contributors
            .contains(&"falling_throughput".to_string()));
        assert_eq!(
            prediction.model_version,
            NETWORK_AI_DEGRADATION_MODEL_VERSION
        );
    }

    #[test]
    fn detects_recent_route_failure() {
        let predictor = SimpleDegradationPredictor::default();
        let mut failed = entry(2000, 0.0, 100.0, 0.0);
        failed.route_available = false;
        failed.route_healthy = false;
        let prediction = predictor.predict(
            "relay-nodeA-via-nodeC-nodeB",
            &[entry(1000, 20.0, 1.0, 30.0), failed],
        );

        assert!(prediction
            .contributors
            .contains(&"recent_route_failure".to_string()));
    }

    #[test]
    fn insufficient_history_is_safe_low_confidence() {
        let predictor = SimpleDegradationPredictor::default();
        let prediction = predictor.predict("direct-nodeA-nodeB", &[entry(1000, 20.0, 1.0, 30.0)]);

        assert_eq!(prediction.probability, 0.10);
        assert!(prediction
            .contributors
            .contains(&"insufficient_history".to_string()));
    }

    #[test]
    fn flags_high_relay_utilization_and_persists_prediction() {
        let tmp_root = std::env::temp_dir().join(format!(
            "network-ai-degradation-test-{}",
            std::process::id()
        ));
        let path = tmp_root.join("degradation.jsonl");
        let mut saturated = entry(2_000, 21.0, 0.6, 41.0);
        saturated.bandwidth_utilization_pct = 92.0;
        let prediction = SimpleDegradationPredictor::default().predict(
            "direct-nodeA-nodeB",
            &[entry(1_000, 20.0, 0.5, 40.0), saturated],
        );
        assert!(prediction
            .contributors
            .contains(&"high_relay_utilization".to_string()));
        append_degradation_prediction_jsonl(&path, &prediction).unwrap();
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("high_relay_utilization"));
        let _ = std::fs::remove_dir_all(tmp_root);
    }
}
