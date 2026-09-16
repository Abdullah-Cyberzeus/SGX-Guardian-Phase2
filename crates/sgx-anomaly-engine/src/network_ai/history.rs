//! Task 3 Deliverable 3: restart-safe historical route performance store.

use super::telemetry_adapter::NetworkObservation;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteHistoryEntry {
    pub ts_ms: u64,
    pub route_id: String,
    pub rtt_ms: f64,
    pub packet_loss_pct: f64,
    pub throughput_mbps: Option<f64>,
    pub bandwidth_utilization_pct: Option<f64>,
    pub route_available: bool,
    pub route_healthy: bool,
    pub switched_route: bool,
}

/// A measured route outcome supplied by the telemetry/runtime boundary.
///
/// This deliberately contains no predictor or demo defaults: callers provide
/// the observation that was actually measured for the route.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteObservationInput {
    pub ts_ms: u64,
    pub route_id: String,
    pub rtt_ms: f64,
    pub packet_loss_pct: f64,
    pub throughput_mbps: Option<f64>,
    pub bandwidth_utilization_pct: Option<f64>,
    pub route_available: bool,
    pub route_healthy: bool,
    pub switched_route: bool,
}

impl From<RouteObservationInput> for RouteHistoryEntry {
    fn from(value: RouteObservationInput) -> Self {
        Self {
            ts_ms: value.ts_ms,
            route_id: value.route_id,
            rtt_ms: value.rtt_ms,
            packet_loss_pct: value.packet_loss_pct,
            throughput_mbps: value.throughput_mbps,
            bandwidth_utilization_pct: value.bandwidth_utilization_pct,
            route_available: value.route_available,
            route_healthy: value.route_healthy,
            switched_route: value.switched_route,
        }
    }
}

/// An append-only record of the outcome observed after a route decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservedRouteOutcome {
    pub schema_version: String,
    pub ts_ms: u64,
    pub route_id: String,
    pub previous_route_id: Option<String>,
    pub selected_by: String,
    pub applied: bool,
    pub switched_route: bool,
    pub route_available: bool,
    pub route_healthy: bool,
    pub rtt_ms: f64,
    pub packet_loss_pct: f64,
    pub throughput_mbps: f64,
    pub bandwidth_utilization_pct: f64,
    pub reward: Option<f64>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoutePerformanceStats {
    pub route_id: String,
    pub sample_count: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub switch_count: u64,
    pub ewma_latency_ms: f64,
    pub ewma_loss_pct: f64,
    pub ewma_throughput_mbps: f64,
    pub success_rate: f64,
    pub last_seen_ts_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteHistoryStore {
    pub schema_version: String,
    pub ewma_alpha: f64,
    pub max_entries_per_route: usize,
    pub stats_by_route: BTreeMap<String, RoutePerformanceStats>,
    pub entries_by_route: BTreeMap<String, Vec<RouteHistoryEntry>>,
}

impl RouteHistoryStore {
    pub fn new(ewma_alpha: f64, max_entries_per_route: usize) -> Self {
        assert!(
            ewma_alpha > 0.0 && ewma_alpha <= 1.0,
            "ewma_alpha must be in (0, 1]"
        );
        assert!(
            max_entries_per_route > 0,
            "max_entries_per_route must be greater than zero"
        );
        Self {
            schema_version: "network-ai-route-history-v1".to_string(),
            ewma_alpha,
            max_entries_per_route,
            stats_by_route: BTreeMap::new(),
            entries_by_route: BTreeMap::new(),
        }
    }

    pub fn record_observation(
        &mut self,
        observation: &NetworkObservation,
    ) -> RoutePerformanceStats {
        self.record(RouteHistoryEntry {
            ts_ms: observation.ts_ms,
            route_id: observation.current_route_id.clone(),
            rtt_ms: observation.rtt_ms,
            packet_loss_pct: observation.packet_loss_pct,
            throughput_mbps: Some(observation.throughput_mbps),
            bandwidth_utilization_pct: Some(observation.bandwidth_utilization_pct),
            route_available: observation.route_available,
            route_healthy: observation.rtt_ms.is_finite()
                && observation.packet_loss_pct.is_finite()
                && observation.throughput_mbps.is_finite(),
            switched_route: false,
        })
    }

    /// Records one externally supplied, measured route observation.
    pub fn record_measured_observation(
        &mut self,
        observation: RouteObservationInput,
    ) -> RoutePerformanceStats {
        self.record(observation.into())
    }

    pub fn record(&mut self, entry: RouteHistoryEntry) -> RoutePerformanceStats {
        let success = entry.route_available && entry.route_healthy && entry.packet_loss_pct < 50.0;
        let route_id = entry.route_id.clone();
        let stats = self
            .stats_by_route
            .entry(route_id.clone())
            .or_insert_with(|| RoutePerformanceStats {
                route_id: route_id.clone(),
                sample_count: 0,
                success_count: 0,
                failure_count: 0,
                switch_count: 0,
                ewma_latency_ms: entry.rtt_ms,
                ewma_loss_pct: entry.packet_loss_pct,
                ewma_throughput_mbps: entry.throughput_mbps.unwrap_or(0.0),
                success_rate: 0.0,
                last_seen_ts_ms: entry.ts_ms,
            });

        if stats.sample_count == 0 {
            stats.ewma_latency_ms = entry.rtt_ms;
            stats.ewma_loss_pct = entry.packet_loss_pct;
            if let Some(throughput) = entry.throughput_mbps {
                stats.ewma_throughput_mbps = throughput;
            }
        } else {
            let alpha = self.ewma_alpha;
            stats.ewma_latency_ms = alpha * entry.rtt_ms + (1.0 - alpha) * stats.ewma_latency_ms;
            stats.ewma_loss_pct =
                alpha * entry.packet_loss_pct + (1.0 - alpha) * stats.ewma_loss_pct;
            if let Some(throughput) = entry.throughput_mbps {
                stats.ewma_throughput_mbps =
                    alpha * throughput + (1.0 - alpha) * stats.ewma_throughput_mbps;
            }
        }

        stats.sample_count += 1;
        if success {
            stats.success_count += 1;
        } else {
            stats.failure_count += 1;
        }
        if entry.switched_route {
            stats.switch_count += 1;
        }
        stats.success_rate = stats.success_count as f64 / stats.sample_count as f64;
        stats.last_seen_ts_ms = entry.ts_ms;

        let entries = self.entries_by_route.entry(route_id).or_default();
        entries.push(entry);
        if entries.len() > self.max_entries_per_route {
            let overflow = entries.len() - self.max_entries_per_route;
            entries.drain(0..overflow);
        }

        stats.clone()
    }

    pub fn stats_for(&self, route_id: &str) -> Option<&RoutePerformanceStats> {
        self.stats_by_route.get(route_id)
    }

    pub fn save_json(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("creating route history directory {}", parent.display())
            })?;
        }
        let json = serde_json::to_string_pretty(self).context("serializing route history store")?;
        fs::write(path, json)
            .with_context(|| format!("writing route history {}", path.display()))?;
        Ok(())
    }

    pub fn load_json(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let json = fs::read_to_string(path)
            .with_context(|| format!("reading route history {}", path.display()))?;
        serde_json::from_str(&json).context("parsing route history store")
    }

    /// Restores the durable per-route learning state when it already exists,
    /// otherwise creates a fresh store for the first optimizer run.
    pub fn load_or_new(
        path: impl AsRef<Path>,
        ewma_alpha: f64,
        max_entries_per_route: usize,
    ) -> Result<Self> {
        let path = path.as_ref();
        if path.exists() {
            Self::load_json(path)
        } else {
            Ok(Self::new(ewma_alpha, max_entries_per_route))
        }
    }

    /// Persists one applied/observed outcome without rewriting existing audit rows.
    pub fn append_observed_outcome_jsonl(
        path: impl AsRef<Path>,
        outcome: &ObservedRouteOutcome,
    ) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("creating route outcome directory {}", parent.display())
            })?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("opening route outcome log {}", path.display()))?;
        writeln!(
            file,
            "{}",
            serde_json::to_string(outcome).context("serializing route outcome")?
        )
        .with_context(|| format!("writing route outcome {}", path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(
        route_id: &str,
        ts_ms: u64,
        rtt_ms: f64,
        loss: f64,
        throughput: f64,
    ) -> RouteHistoryEntry {
        RouteHistoryEntry {
            ts_ms,
            route_id: route_id.to_string(),
            rtt_ms,
            packet_loss_pct: loss,
            throughput_mbps: Some(throughput),
            bandwidth_utilization_pct: Some(25.0),
            route_available: true,
            route_healthy: true,
            switched_route: false,
        }
    }

    #[test]
    fn records_per_route_ewma_and_success_rate() {
        let mut store = RouteHistoryStore::new(0.5, 10);
        store.record(entry("direct-nodeA-nodeB", 1000, 20.0, 1.0, 40.0));
        let stats = store.record(entry("direct-nodeA-nodeB", 2000, 30.0, 3.0, 20.0));

        assert_eq!(stats.sample_count, 2);
        assert_eq!(stats.success_count, 2);
        assert_eq!(stats.failure_count, 0);
        assert!((stats.ewma_latency_ms - 25.0).abs() < 1e-9);
        assert!((stats.ewma_loss_pct - 2.0).abs() < 1e-9);
        assert!((stats.ewma_throughput_mbps - 30.0).abs() < 1e-9);
        assert_eq!(stats.success_rate, 1.0);
    }

    #[test]
    fn load_or_new_preserves_learning_across_optimizer_restarts() {
        let root =
            std::env::temp_dir().join(format!("network-ai-history-restart-{}", std::process::id()));
        let path = root.join("route_history_store.json");
        let mut first = RouteHistoryStore::load_or_new(&path, 0.5, 10).unwrap();
        first.record(entry("route-a", 100, 20.0, 1.0, 50.0));
        first.save_json(&path).unwrap();

        let mut restarted = RouteHistoryStore::load_or_new(&path, 0.5, 10).unwrap();
        assert_eq!(restarted.stats_for("route-a").unwrap().sample_count, 1);
        assert_eq!(
            restarted.stats_for("route-a").unwrap().ewma_latency_ms,
            20.0
        );
        restarted.record(entry("route-a", 200, 40.0, 3.0, 30.0));
        assert_eq!(restarted.stats_for("route-a").unwrap().sample_count, 2);
        assert_eq!(
            restarted.stats_for("route-a").unwrap().ewma_latency_ms,
            30.0
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn records_caller_supplied_measured_route_observation() {
        let mut store = RouteHistoryStore::new(0.5, 10);
        let stats = store.record_measured_observation(RouteObservationInput {
            ts_ms: 321,
            route_id: "relay-measured".to_string(),
            rtt_ms: 12.5,
            packet_loss_pct: 0.2,
            throughput_mbps: Some(88.0),
            bandwidth_utilization_pct: Some(61.0),
            route_available: true,
            route_healthy: true,
            switched_route: true,
        });

        assert_eq!(stats.route_id, "relay-measured");
        assert_eq!(stats.sample_count, 1);
        assert_eq!(stats.ewma_latency_ms, 12.5);
        assert_eq!(stats.switch_count, 1);
    }

    #[test]
    fn records_failures_when_route_is_unavailable() {
        let mut store = RouteHistoryStore::new(0.5, 10);
        let mut failed = entry("relay-nodeA-via-nodeC-nodeB", 1000, 0.0, 100.0, 0.0);
        failed.route_available = false;

        let stats = store.record(failed);

        assert_eq!(stats.sample_count, 1);
        assert_eq!(stats.success_count, 0);
        assert_eq!(stats.failure_count, 1);
        assert_eq!(stats.success_rate, 0.0);
    }

    #[test]
    fn retention_is_bounded_per_route() {
        let mut store = RouteHistoryStore::new(1.0, 2);
        store.record(entry("r1", 1000, 1.0, 0.0, 10.0));
        store.record(entry("r1", 2000, 2.0, 0.0, 10.0));
        store.record(entry("r1", 3000, 3.0, 0.0, 10.0));

        let entries = store.entries_by_route.get("r1").unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].ts_ms, 2000);
        assert_eq!(entries[1].ts_ms, 3000);
    }

    #[test]
    fn save_and_load_is_restart_safe() {
        let tmp_root =
            std::env::temp_dir().join(format!("network-ai-history-test-{}", std::process::id()));
        let path = tmp_root.join("route_history_store.json");
        let mut store = RouteHistoryStore::new(0.4, 5);
        store.record(entry("direct-nodeA-nodeB", 1000, 20.0, 1.0, 40.0));
        store.save_json(&path).unwrap();

        let loaded = RouteHistoryStore::load_json(&path).unwrap();
        let stats = loaded.stats_for("direct-nodeA-nodeB").unwrap();
        assert_eq!(stats.sample_count, 1);
        assert_eq!(stats.last_seen_ts_ms, 1000);

        let _ = std::fs::remove_dir_all(tmp_root);
    }

    #[test]
    fn records_switch_count_and_persists_observed_outcome() {
        let tmp_root =
            std::env::temp_dir().join(format!("network-ai-outcome-test-{}", std::process::id()));
        let path = tmp_root.join("route_outcomes.jsonl");
        let mut store = RouteHistoryStore::new(0.5, 5);
        let mut switched = entry("relay-nodeA-via-nodeC-nodeB", 1000, 25.0, 1.0, 30.0);
        switched.switched_route = true;
        let stats = store.record(switched);
        assert_eq!(stats.switch_count, 1);

        RouteHistoryStore::append_observed_outcome_jsonl(
            &path,
            &ObservedRouteOutcome {
                schema_version: "network-ai-route-outcome-v1".to_string(),
                ts_ms: 1000,
                route_id: "relay-nodeA-via-nodeC-nodeB".to_string(),
                previous_route_id: Some("direct-nodeA-nodeB".to_string()),
                selected_by: "network-ai-v1".to_string(),
                applied: true,
                switched_route: true,
                route_available: true,
                route_healthy: true,
                rtt_ms: 25.0,
                packet_loss_pct: 1.0,
                throughput_mbps: 30.0,
                bandwidth_utilization_pct: 25.0,
                reward: Some(0.8),
                reason: "verified route outcome".to_string(),
            },
        )
        .unwrap();
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("relay-nodeA-via-nodeC-nodeB"));
        let _ = std::fs::remove_dir_all(tmp_root);
    }
}
