//! Task 3 Deliverable 5: network degradation prediction.
//!
//! This predictor warns before a route reaches a hard failure threshold. It is
//! deterministic and emits contributor labels so the decision remains auditable.

use super::history::{RouteHistoryEntry, RouteHistoryStore};
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

impl SimpleDegradationPredictor {
    /// Evaluates every route from the retained history store so degradation
    /// detection can survive optimizer restarts.
    pub fn predict_all_routes(&self, history: &RouteHistoryStore) -> Vec<DegradationPrediction> {
        history
            .entries_by_route
            .iter()
            .map(|(route_id, entries)| self.predict(route_id, entries))
            .collect()
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

        // D8: evaluate current degradation over a bounded recent window rather
        // than trusting only the final sample. Real multi-probe measurements
        // can legitimately alternate between degraded and clean observations.
        //
        // Preserve the original first-vs-last semantics for short histories
        // while making retained production history robust to a single clean
        // sample immediately following sustained degradation.
        const RECENT_SIGNAL_WINDOW: usize = 5;
        const MIN_DEGRADED_SAMPLES: usize = 2;

        let signal_window = &recent[recent.len().saturating_sub(RECENT_SIGNAL_WINDOW)..];

        let elevated_rtt_samples = signal_window
            .iter()
            .filter(|entry| {
                entry.rtt_ms > first.rtt_ms * 1.25 && entry.rtt_ms - first.rtt_ms > 10.0
            })
            .count();

        if (last.rtt_ms > first.rtt_ms * 1.25 && last.rtt_ms - first.rtt_ms > 10.0)
            || elevated_rtt_samples >= MIN_DEGRADED_SAMPLES
        {
            probability += 0.30;
            contributors.push("rising_rtt".to_string());
        }

        let elevated_loss_samples = signal_window
            .iter()
            .filter(|entry| {
                entry.packet_loss_pct > first.packet_loss_pct + 2.0 || entry.packet_loss_pct >= 5.0
            })
            .count();

        if last.packet_loss_pct > first.packet_loss_pct + 2.0
            || last.packet_loss_pct >= 5.0
            || elevated_loss_samples >= MIN_DEGRADED_SAMPLES
        {
            probability += 0.25;
            contributors.push("rising_packet_loss".to_string());
        }

        if let Some(first_throughput) = first.throughput_mbps {
            if first_throughput > 0.0 {
                let falling_throughput_samples = signal_window
                    .iter()
                    .filter_map(|entry| entry.throughput_mbps)
                    .filter(|throughput| *throughput < first_throughput * 0.75)
                    .count();

                if last
                    .throughput_mbps
                    .is_some_and(|throughput| throughput < first_throughput * 0.75)
                    || falling_throughput_samples >= MIN_DEGRADED_SAMPLES
                {
                    probability += 0.25;
                    contributors.push("falling_throughput".to_string());
                }
            }
        }

        let high_utilization_samples = signal_window
            .iter()
            .filter(|entry| {
                entry
                    .bandwidth_utilization_pct
                    .is_some_and(|utilization| utilization >= 85.0)
            })
            .count();

        if last
            .bandwidth_utilization_pct
            .is_some_and(|utilization| utilization >= 85.0)
            || high_utilization_samples >= MIN_DEGRADED_SAMPLES
        {
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
            throughput_mbps: Some(throughput),
            bandwidth_utilization_pct: Some(30.0),
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
        saturated.bandwidth_utilization_pct = Some(92.0);
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

    #[test]
    fn retained_history_changes_degradation_prediction_after_restart() {
        let root = std::env::temp_dir().join(format!(
            "network-ai-retained-degradation-{}",
            std::process::id()
        ));
        let path = root.join("route_history_store.json");
        let predictor = SimpleDegradationPredictor::default();
        let mut first_cycle = RouteHistoryStore::new(0.5, 10);
        first_cycle.record(entry(1_000, 20.0, 0.5, 60.0));
        first_cycle.record(entry(2_000, 21.0, 0.6, 61.0));
        first_cycle.save_json(&path).unwrap();

        let mut second_cycle = RouteHistoryStore::load_json(&path).unwrap();
        let before = predictor
            .predict_all_routes(&second_cycle)
            .into_iter()
            .find(|prediction| prediction.route_id == "direct-nodeA-nodeB")
            .unwrap()
            .probability;
        second_cycle.record(entry(3_000, 50.0, 6.0, 30.0));
        let after = predictor
            .predict_all_routes(&second_cycle)
            .into_iter()
            .find(|prediction| prediction.route_id == "direct-nodeA-nodeB")
            .unwrap();

        assert!(after.probability > before);
        assert!(after.contributors.contains(&"rising_rtt".to_string()));
        assert!(after
            .contributors
            .contains(&"falling_throughput".to_string()));
        let _ = std::fs::remove_dir_all(root);
    }
}
