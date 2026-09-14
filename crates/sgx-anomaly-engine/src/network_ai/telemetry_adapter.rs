//! Task 3 Deliverable 1: network telemetry schema and shared adapter.
//!
//! This module intentionally depends only on the existing Task 1 raw telemetry
//! shape. Trust/attestation filtering is a later layer: the adapter records
//! route telemetry but does not call attestation services and does not mutate
//! Task 2 trust state.

use crate::telemetry::RawSample;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::Path;

pub const NETWORK_AI_OBSERVATION_SCHEMA_VERSION: &str = "network-ai-observation-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrafficClass {
    /// Telemetry, heartbeat, runtime metrics, health/status and network stats.
    Operational,
    /// VSHIFT_ALERT, signed policy delivery, verification, attestation,
    /// revocation and trust-state/control messages.
    SecurityControl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkMessageType {
    VshiftAlert,
    SignedPolicyDelivery,
    PolicyVerification,
    Attestation,
    Revocation,
    TrustStateUpdate,
    VirtualShiftControl,
    Telemetry,
    Heartbeat,
    RuntimeMetrics,
    HealthStatus,
    NetworkStats,
    BulkSync,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PriorityClass {
    Normal,
    High,
}

pub fn classify_message_type(value: &str) -> (NetworkMessageType, TrafficClass, PriorityClass) {
    let normalized = value.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    let message_type = match normalized.as_str() {
        "vshift_alert" | "virtual_shift_alert" => NetworkMessageType::VshiftAlert,
        "signed_policy_delivery" | "policy_delivery" => NetworkMessageType::SignedPolicyDelivery,
        "policy_verification" | "member_policy_verification" => {
            NetworkMessageType::PolicyVerification
        }
        "attestation" | "attestation_challenge" | "attestation_response" => {
            NetworkMessageType::Attestation
        }
        "revocation" | "crl" => NetworkMessageType::Revocation,
        "trust_state_update" | "trust_update" => NetworkMessageType::TrustStateUpdate,
        "virtual_shift_control" | "vshift_control" => NetworkMessageType::VirtualShiftControl,
        "telemetry" => NetworkMessageType::Telemetry,
        "heartbeat" => NetworkMessageType::Heartbeat,
        "runtime_metrics" | "metrics" => NetworkMessageType::RuntimeMetrics,
        "health_status" | "health" => NetworkMessageType::HealthStatus,
        "network_stats" | "network_statistics" => NetworkMessageType::NetworkStats,
        "bulk_sync" => NetworkMessageType::BulkSync,
        _ => NetworkMessageType::Unknown,
    };

    match message_type {
        NetworkMessageType::VshiftAlert
        | NetworkMessageType::SignedPolicyDelivery
        | NetworkMessageType::PolicyVerification
        | NetworkMessageType::Attestation
        | NetworkMessageType::Revocation
        | NetworkMessageType::TrustStateUpdate
        | NetworkMessageType::VirtualShiftControl => (
            message_type,
            TrafficClass::SecurityControl,
            PriorityClass::High,
        ),
        NetworkMessageType::Telemetry
        | NetworkMessageType::Heartbeat
        | NetworkMessageType::RuntimeMetrics
        | NetworkMessageType::HealthStatus
        | NetworkMessageType::NetworkStats
        | NetworkMessageType::BulkSync
        | NetworkMessageType::Unknown => (
            message_type,
            TrafficClass::Operational,
            PriorityClass::Normal,
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteKind {
    DirectP2p,
    Relay,
    MultiHopRelay,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Task1MetricEvidence {
    pub name: String,
    pub value: f64,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkObservation {
    pub schema_version: String,
    pub ts_ms: u64,

    pub source_node: String,
    pub destination_node: String,
    pub peer_id: String,

    pub traffic_class: TrafficClass,
    pub priority_class: PriorityClass,

    pub current_route_id: String,
    pub route_kind: RouteKind,
    pub relay_ids: Vec<String>,
    pub relay_hops: u8,
    pub route_available: bool,

    pub rtt_ms: f64,
    pub packet_loss_pct: f64,
    pub throughput_mbps: f64,
    pub bandwidth_utilization_pct: f64,

    pub conn_rate_hint: f64,
    pub relay_ratio: f64,
    pub task1_feature_schema: String,
    pub task1_reused_metrics: Vec<Task1MetricEvidence>,

    /// Explicit proof for Issue 1 acceptance: telemetry collection has no live
    /// attestation dependency. Trust filtering is handled before future route
    /// application, not inside this telemetry adapter.
    pub live_attestation_required: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NetworkTelemetryContext {
    pub source_node: String,
    pub destination_node: String,
    pub peer_id: String,
    pub traffic_class: TrafficClass,
    pub current_route_id: String,
    pub route_kind: RouteKind,
    pub relay_ids: Vec<String>,
    pub relay_hops: u8,
    pub route_available: bool,
    pub packet_loss_pct: f64,
    pub bandwidth_capacity_mbps: Option<f64>,
}

impl NetworkTelemetryContext {
    pub fn operational(
        source_node: impl Into<String>,
        destination_node: impl Into<String>,
        peer_id: impl Into<String>,
        current_route_id: impl Into<String>,
    ) -> Self {
        Self {
            source_node: source_node.into(),
            destination_node: destination_node.into(),
            peer_id: peer_id.into(),
            traffic_class: TrafficClass::Operational,
            current_route_id: current_route_id.into(),
            route_kind: RouteKind::DirectP2p,
            relay_ids: Vec::new(),
            relay_hops: 0,
            route_available: true,
            packet_loss_pct: 0.0,
            bandwidth_capacity_mbps: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkTelemetryAdapter {
    pub task1_feature_schema: String,
}

impl Default for NetworkTelemetryAdapter {
    fn default() -> Self {
        Self {
            task1_feature_schema: "task1-feature-schema-v1".to_string(),
        }
    }
}

impl NetworkTelemetryAdapter {
    pub fn observe(&self, raw: &RawSample, ctx: NetworkTelemetryContext) -> NetworkObservation {
        let priority_class = match ctx.traffic_class {
            TrafficClass::Operational => PriorityClass::Normal,
            TrafficClass::SecurityControl => PriorityClass::High,
        };

        let throughput_mbps = raw.nebula_mbps.max(0.0);
        let bandwidth_utilization_pct = ctx
            .bandwidth_capacity_mbps
            .filter(|capacity| *capacity > 0.0)
            .map(|capacity| ((throughput_mbps / capacity) * 100.0).clamp(0.0, 100.0))
            .unwrap_or(0.0);

        NetworkObservation {
            schema_version: NETWORK_AI_OBSERVATION_SCHEMA_VERSION.to_string(),
            ts_ms: raw.ts_ms,
            source_node: ctx.source_node,
            destination_node: ctx.destination_node,
            peer_id: ctx.peer_id,
            traffic_class: ctx.traffic_class,
            priority_class,
            current_route_id: ctx.current_route_id,
            route_kind: ctx.route_kind,
            relay_ids: ctx.relay_ids,
            relay_hops: ctx.relay_hops,
            route_available: ctx.route_available,
            rtt_ms: raw.cot_latency_avg_ms.max(0.0),
            packet_loss_pct: ctx.packet_loss_pct.clamp(0.0, 100.0),
            throughput_mbps,
            bandwidth_utilization_pct,
            conn_rate_hint: raw.conn_total as f64,
            relay_ratio: raw.relay_ratio.clamp(0.0, 1.0),
            task1_feature_schema: self.task1_feature_schema.clone(),
            task1_reused_metrics: task1_metric_evidence(raw),
            live_attestation_required: false,
        }
    }
}

pub fn task1_metric_evidence(raw: &RawSample) -> Vec<Task1MetricEvidence> {
    vec![
        Task1MetricEvidence {
            name: "nebula_mbps".to_string(),
            value: raw.nebula_mbps,
            source: "Task1 RawSample".to_string(),
        },
        Task1MetricEvidence {
            name: "relay_ratio".to_string(),
            value: raw.relay_ratio,
            source: "Task1 RawSample".to_string(),
        },
        Task1MetricEvidence {
            name: "cot_latency_avg_ms".to_string(),
            value: raw.cot_latency_avg_ms,
            source: "Task1 RawSample".to_string(),
        },
        Task1MetricEvidence {
            name: "conn_total".to_string(),
            value: raw.conn_total as f64,
            source: "Task1 RawSample".to_string(),
        },
    ]
}

pub fn persist_current_observation(path: impl AsRef<Path>, obs: &NetworkObservation) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        create_dir_all(parent)
            .with_context(|| format!("creating network AI state directory {parent:?}"))?;
    }
    let json = serde_json::to_string_pretty(obs).context("serializing network observation")?;
    std::fs::write(path, json).with_context(|| format!("writing network observation {path:?}"))?;
    Ok(())
}

pub fn append_observation_jsonl(path: impl AsRef<Path>, obs: &NetworkObservation) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        create_dir_all(parent)
            .with_context(|| format!("creating network AI history directory {parent:?}"))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening network observation history {path:?}"))?;
    let json = serde_json::to_string(obs).context("serializing network observation jsonl")?;
    writeln!(file, "{json}").with_context(|| format!("appending network observation {path:?}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_sample() -> RawSample {
        RawSample {
            ts_ms: 12345,
            nebula_mbps: 42.0,
            relay_ratio: 0.25,
            cot_latency_avg_ms: 18.5,
            conn_total: 7,
            ..Default::default()
        }
    }

    #[test]
    fn operational_traffic_becomes_normal_priority_observation() {
        let adapter = NetworkTelemetryAdapter::default();
        let ctx = NetworkTelemetryContext {
            bandwidth_capacity_mbps: Some(100.0),
            ..NetworkTelemetryContext::operational("nodeA", "nodeB", "nodeB", "direct-nodeA-nodeB")
        };

        let obs = adapter.observe(&raw_sample(), ctx);

        assert_eq!(obs.schema_version, NETWORK_AI_OBSERVATION_SCHEMA_VERSION);
        assert_eq!(obs.ts_ms, 12345);
        assert_eq!(obs.traffic_class, TrafficClass::Operational);
        assert_eq!(obs.priority_class, PriorityClass::Normal);
        assert_eq!(obs.current_route_id, "direct-nodeA-nodeB");
        assert_eq!(obs.route_kind, RouteKind::DirectP2p);
        assert_eq!(obs.relay_hops, 0);
        assert_eq!(obs.rtt_ms, 18.5);
        assert_eq!(obs.packet_loss_pct, 0.0);
        assert_eq!(obs.throughput_mbps, 42.0);
        assert_eq!(obs.bandwidth_utilization_pct, 42.0);
        assert_eq!(obs.relay_ratio, 0.25);
        assert!(!obs.live_attestation_required);
    }

    #[test]
    fn security_control_traffic_becomes_high_priority_and_preserves_route_metadata() {
        let adapter = NetworkTelemetryAdapter::default();
        let ctx = NetworkTelemetryContext {
            traffic_class: TrafficClass::SecurityControl,
            current_route_id: "relay-nodeA-nodeC-nodeB".to_string(),
            route_kind: RouteKind::Relay,
            relay_ids: vec!["nodeC".to_string()],
            relay_hops: 1,
            packet_loss_pct: 1.7,
            bandwidth_capacity_mbps: Some(50.0),
            ..NetworkTelemetryContext::operational("nodeA", "nodeB", "nodeB", "unused")
        };

        let obs = adapter.observe(&raw_sample(), ctx);

        assert_eq!(obs.traffic_class, TrafficClass::SecurityControl);
        assert_eq!(obs.priority_class, PriorityClass::High);
        assert_eq!(obs.current_route_id, "relay-nodeA-nodeC-nodeB");
        assert_eq!(obs.route_kind, RouteKind::Relay);
        assert_eq!(obs.relay_ids, vec!["nodeC"]);
        assert_eq!(obs.relay_hops, 1);
        assert_eq!(obs.packet_loss_pct, 1.7);
        assert_eq!(obs.bandwidth_utilization_pct, 84.0);
    }

    #[test]
    fn task1_metrics_are_reused_as_audit_evidence() {
        let evidence = task1_metric_evidence(&raw_sample());
        let names: Vec<_> = evidence.iter().map(|item| item.name.as_str()).collect();

        assert!(names.contains(&"nebula_mbps"));
        assert!(names.contains(&"relay_ratio"));
        assert!(names.contains(&"cot_latency_avg_ms"));
        assert!(names.contains(&"conn_total"));
    }

    #[test]
    fn persistence_writes_current_json_and_history_jsonl() {
        let tmp_root =
            std::env::temp_dir().join(format!("network-ai-d1-test-{}", std::process::id()));
        let current = tmp_root.join("current_observation.json");
        let history = tmp_root.join("route_observations.jsonl");

        let adapter = NetworkTelemetryAdapter::default();
        let obs = adapter.observe(
            &raw_sample(),
            NetworkTelemetryContext::operational("nodeA", "nodeB", "nodeB", "direct-nodeA-nodeB"),
        );

        persist_current_observation(&current, &obs).unwrap();
        append_observation_jsonl(&history, &obs).unwrap();
        append_observation_jsonl(&history, &obs).unwrap();

        let current_json = std::fs::read_to_string(&current).unwrap();
        assert!(current_json.contains("direct-nodeA-nodeB"));

        let history_jsonl = std::fs::read_to_string(&history).unwrap();
        assert_eq!(history_jsonl.lines().count(), 2);

        let _ = std::fs::remove_dir_all(tmp_root);
    }

    #[test]
    fn classifies_security_control_messages_as_high_priority() {
        for message in ["VSHIFT_ALERT", "attestation", "policy-verification", "crl"] {
            let (_, traffic, priority) = classify_message_type(message);
            assert_eq!(traffic, TrafficClass::SecurityControl);
            assert_eq!(priority, PriorityClass::High);
        }
    }

    #[test]
    fn classifies_operational_and_unknown_messages_as_normal_safe_default() {
        for message in [
            "telemetry",
            "heartbeat",
            "runtime_metrics",
            "unknown-new-type",
        ] {
            let (_, traffic, priority) = classify_message_type(message);
            assert_eq!(traffic, TrafficClass::Operational);
            assert_eq!(priority, PriorityClass::Normal);
        }
    }
}
