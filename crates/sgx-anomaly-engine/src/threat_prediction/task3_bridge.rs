//! Task 4 Deliverable 11: read-only Task 3 network-context contract.
//!
//! The adapter converts canonical Task 3 degradation audit rows into bounded
//! Task 4 evidence.  It neither imports route controllers nor has any route
//! mutation capability.

use super::event::MAX_NODE_ID_BYTES;
use super::{
    validate_unit_interval, EventSeverity, EvidenceSource, SecurityEvent, SecurityEventType,
    ThreatPredictionError, SECURITY_EVENT_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Read};
use std::path::Path;

pub const TASK3_NETWORK_CONTEXT_SCHEMA_VERSION: u32 = 1;
const MAX_DECISION_ID_BYTES: usize = 160;
const MAX_ROUTE_ID_BYTES: usize = 160;
const MAX_MODEL_VERSION_BYTES: usize = 160;
const MAX_REASON_BYTES: usize = 4_096;
const MAX_CONTRIBUTORS: usize = 16;
const MAX_CONTRIBUTOR_BYTES: usize = 160;
const MAX_DEGRADATION_HORIZON_SECONDS: u64 = 24 * 60 * 60;
const MAX_JSONL_LINE_BYTES: usize = 16 * 1_024;
const DEFAULT_MAX_CONTEXT_AGE_MINUTES: u32 = 30;
const DEFAULT_MAX_CONTEXT_EVENTS: usize = 256;

/// Explicit, bounded freshness and input limits for optional Task 3 context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Task3ContextConfig {
    pub max_context_age_minutes: u32,
    pub max_events: usize,
}

impl Default for Task3ContextConfig {
    fn default() -> Self {
        Self {
            max_context_age_minutes: DEFAULT_MAX_CONTEXT_AGE_MINUTES,
            max_events: DEFAULT_MAX_CONTEXT_EVENTS,
        }
    }
}

impl Task3ContextConfig {
    pub fn validate(&self) -> Result<(), ThreatPredictionError> {
        if self.max_context_age_minutes == 0 || self.max_context_age_minutes > 24 * 60 {
            return Err(ThreatPredictionError::InvalidConfig(
                "Task3 context max_context_age_minutes must be between 1 and 1440".into(),
            ));
        }
        if self.max_events == 0 || self.max_events > 10_000 {
            return Err(ThreatPredictionError::InvalidConfig(
                "Task3 context max_events must be between 1 and 10000".into(),
            ));
        }
        Ok(())
    }

    fn maximum_age_ms(&self) -> u64 {
        u64::from(self.max_context_age_minutes) * 60_000
    }
}

/// Normalized, read-only network degradation context supplied by Task 3.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Task3NetworkContext {
    pub schema_version: u32,
    pub decision_id: String,
    pub observed_at_ms: u64,
    pub node_id: String,
    pub peer_id: Option<String>,
    pub route_id: String,
    pub degradation_probability: f64,
    pub degradation_horizon_seconds: u64,
    pub model_version: String,
    pub contributors: Vec<String>,
    pub reason: String,
}

impl Task3NetworkContext {
    pub fn validate(&self) -> Result<(), ThreatPredictionError> {
        if self.schema_version != TASK3_NETWORK_CONTEXT_SCHEMA_VERSION {
            return Err(ThreatPredictionError::MalformedEvent(
                "unsupported Task3 network context schema version".into(),
            ));
        }
        validate_text(
            "Task3 decision ID",
            &self.decision_id,
            MAX_DECISION_ID_BYTES,
        )?;
        validate_text("Task3 node ID", &self.node_id, MAX_NODE_ID_BYTES)?;
        if let Some(peer_id) = &self.peer_id {
            validate_text("Task3 peer ID", peer_id, MAX_NODE_ID_BYTES)?;
        }
        validate_text("Task3 route ID", &self.route_id, MAX_ROUTE_ID_BYTES)?;
        validate_text(
            "Task3 model version",
            &self.model_version,
            MAX_MODEL_VERSION_BYTES,
        )?;
        validate_text("Task3 degradation reason", &self.reason, MAX_REASON_BYTES)?;
        if self.observed_at_ms == 0 {
            return Err(ThreatPredictionError::InvalidTimestamp(
                "Task3 context observed_at_ms must be greater than zero".into(),
            ));
        }
        validate_unit_interval(
            "Task3 degradation probability",
            self.degradation_probability,
            false,
        )?;
        if self.degradation_horizon_seconds == 0
            || self.degradation_horizon_seconds > MAX_DEGRADATION_HORIZON_SECONDS
        {
            return Err(ThreatPredictionError::InvalidHorizon(format!(
                "Task3 degradation horizon must be between 1 and {MAX_DEGRADATION_HORIZON_SECONDS} seconds"
            )));
        }
        if self.contributors.len() > MAX_CONTRIBUTORS {
            return Err(ThreatPredictionError::AttributeLimitExceeded(format!(
                "Task3 context supports at most {MAX_CONTRIBUTORS} contributors"
            )));
        }
        for contributor in &self.contributors {
            validate_text(
                "Task3 degradation contributor",
                contributor,
                MAX_CONTRIBUTOR_BYTES,
            )?;
        }
        Ok(())
    }

    /// Converts a fresh Task 3 audit context into Task 4 evidence. Future and
    /// stale context is ignored before it can affect any Task 4 feature.
    pub fn to_security_event_at(
        &self,
        evaluated_at_ms: u64,
        config: &Task3ContextConfig,
    ) -> Result<Option<SecurityEvent>, ThreatPredictionError> {
        self.validate()?;
        config.validate()?;
        if self.observed_at_ms > evaluated_at_ms
            || evaluated_at_ms.saturating_sub(self.observed_at_ms) > config.maximum_age_ms()
        {
            return Ok(None);
        }
        let mut event = SecurityEvent {
            schema_version: SECURITY_EVENT_SCHEMA_VERSION,
            event_id: "task3-network-context-pending".into(),
            observed_at_ms: self.observed_at_ms,
            source: EvidenceSource::NetworkAi,
            node_id: self.node_id.clone(),
            peer_id: self.peer_id.clone(),
            source_ip: None,
            destination_ip: None,
            source_port: None,
            destination_port: None,
            event_type: SecurityEventType::RouteDegradation,
            severity: severity_for_probability(self.degradation_probability),
            // Task3 publishes a bounded degradation probability, rather than a
            // separate confidence value.  It is preserved unchanged as the
            // normalized source-signal confidence; no new confidence is invented.
            confidence: self.degradation_probability,
            attributes: BTreeMap::from([
                ("task3_decision_id".into(), self.decision_id.clone()),
                ("task3_route_id".into(), self.route_id.clone()),
                (
                    "task3_degradation_probability".into(),
                    self.degradation_probability.to_string(),
                ),
                (
                    "task3_degradation_horizon_seconds".into(),
                    self.degradation_horizon_seconds.to_string(),
                ),
                ("task3_model_version".into(), self.model_version.clone()),
                (
                    "task3_contributors".into(),
                    serde_json::to_string(&self.contributors)
                        .map_err(|error| ThreatPredictionError::Serialization(error.to_string()))?,
                ),
                ("task3_reason".into(), self.reason.clone()),
            ]),
        };
        event.event_id = event.deterministic_event_id();
        event.validate()?;
        Ok(Some(event))
    }
}

/// Reads Task 3's canonical `degradation_events.jsonl`.  Absence of this
/// optional context is safe and produces no Task 4 event; corrupt available
/// context is rejected rather than guessed.
pub fn read_task3_degradation_events_at(
    path: impl AsRef<Path>,
    node_id: &str,
    peer_id: Option<&str>,
    evaluated_at_ms: u64,
    config: &Task3ContextConfig,
) -> Result<Vec<SecurityEvent>, ThreatPredictionError> {
    let path = path.as_ref();
    config.validate()?;
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(ThreatPredictionError::Io(format!(
                "{}: {error}",
                path.display()
            )))
        }
    };
    let mut reader = BufReader::new(file);
    let mut events = Vec::new();
    let mut line_number = 0_usize;
    loop {
        let mut bytes = Vec::with_capacity(MAX_JSONL_LINE_BYTES + 1);
        let read = reader
            .by_ref()
            .take((MAX_JSONL_LINE_BYTES + 1) as u64)
            .read_until(b'\n', &mut bytes)
            .map_err(|error| ThreatPredictionError::Io(format!("{}: {error}", path.display())))?;
        if read == 0 {
            break;
        }
        line_number += 1;
        if bytes.len() > MAX_JSONL_LINE_BYTES {
            return Err(ThreatPredictionError::AttributeLimitExceeded(format!(
                "Task3 degradation row {line_number} exceeds {MAX_JSONL_LINE_BYTES} bytes"
            )));
        }
        let line = std::str::from_utf8(&bytes).map_err(|error| {
            ThreatPredictionError::Serialization(format!(
                "Task3 degradation row {line_number}: {error}"
            ))
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let row: Task3DegradationAuditRow = serde_json::from_str(line).map_err(|error| {
            ThreatPredictionError::Serialization(format!(
                "Task3 degradation row {}: {error}",
                line_number
            ))
        })?;
        let context = Task3NetworkContext {
            schema_version: TASK3_NETWORK_CONTEXT_SCHEMA_VERSION,
            decision_id: row.decision_id,
            observed_at_ms: row.ts_ms,
            node_id: node_id.to_string(),
            peer_id: peer_id.map(str::to_string),
            route_id: row.prediction.route_id,
            degradation_probability: row.prediction.probability,
            degradation_horizon_seconds: row.prediction.horizon_seconds,
            model_version: row.prediction.model_version,
            contributors: row.prediction.contributors,
            reason: row.prediction.reason,
        };
        if let Some(event) = context.to_security_event_at(evaluated_at_ms, config)? {
            events.push(event);

            // `max_events` bounds the Task 3 context exposed to Task 4, not
            // the lifetime size of Task 3's append-only audit history.
            //
            // Keep only the newest fresh context events while preserving the
            // canonical Task 3 JSONL file unchanged. This prevents a
            // long-running Guardian from failing merely because its audit
            // history has grown beyond the context window.
            if events.len() > config.max_events {
                let excess = events.len() - config.max_events;
                events.drain(..excess);
            }
        }
    }

    // Task 3's audit log is expected to be chronological, but explicitly
    // ordering the bounded result makes the bridge deterministic even when
    // valid rows were written slightly out of order.
    events.sort_by_key(|event| event.observed_at_ms);

    Ok(events)
}

#[derive(Debug, Deserialize)]
struct Task3DegradationAuditRow {
    decision_id: String,
    ts_ms: u64,
    prediction: Task3DegradationPrediction,
}

#[derive(Debug, Deserialize)]
struct Task3DegradationPrediction {
    model_version: String,
    route_id: String,
    probability: f64,
    horizon_seconds: u64,
    contributors: Vec<String>,
    reason: String,
}

fn severity_for_probability(probability: f64) -> EventSeverity {
    if probability >= 0.85 {
        EventSeverity::Critical
    } else if probability >= 0.70 {
        EventSeverity::High
    } else if probability >= 0.50 {
        EventSeverity::Medium
    } else {
        EventSeverity::Low
    }
}

fn validate_text(field: &str, value: &str, max_bytes: usize) -> Result<(), ThreatPredictionError> {
    if value.trim().is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(ThreatPredictionError::MalformedEvent(format!(
            "{field} must be non-empty, non-control text within {max_bytes} bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat_prediction::{TemporalFeatureConfig, TemporalFeatureEngine};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn context() -> Task3NetworkContext {
        Task3NetworkContext {
            schema_version: TASK3_NETWORK_CONTEXT_SCHEMA_VERSION,
            decision_id: "task3-decision-nodeA-nodeB-001".into(),
            observed_at_ms: 1_000_000,
            node_id: "nodeB".into(),
            peer_id: Some("nodeA".into()),
            route_id: "relay-nodeA-nodeB".into(),
            degradation_probability: 0.82,
            degradation_horizon_seconds: 60,
            model_version: "degradation-v1-interpretable".into(),
            contributors: vec!["latency_rising".into(), "high_packet_loss".into()],
            reason: "high degradation risk on the retained route history".into(),
        }
    }

    #[test]
    fn canonical_task3_context_is_normalized_and_affects_temporal_features() {
        let event = context()
            .to_security_event_at(1_000_001, &Task3ContextConfig::default())
            .unwrap()
            .unwrap();
        let expected_event = event.clone();
        assert_eq!(event.source, EvidenceSource::NetworkAi);
        assert_eq!(event.event_type, SecurityEventType::RouteDegradation);
        assert_eq!(
            event.attributes["task3_decision_id"],
            "task3-decision-nodeA-nodeB-001"
        );
        assert_eq!(event.attributes["task3_route_id"], "relay-nodeA-nodeB");

        let mut temporal = TemporalFeatureEngine::new(TemporalFeatureConfig::default()).unwrap();
        assert!(temporal.ingest(event).unwrap());
        let features = temporal.features_for_node_at("nodeB", 1_000_001);
        assert_eq!(
            features.windows[&5].network_degradation_rate_per_minute,
            1.0 / 5.0
        );
        assert_eq!(
            features.windows[&5].network_degradation_probability_max,
            Some(0.82)
        );

        let repeated = context()
            .to_security_event_at(1_000_001, &Task3ContextConfig::default())
            .unwrap()
            .unwrap();
        assert_eq!(repeated, expected_event);
    }

    #[test]
    fn missing_context_is_safe_and_malformed_context_is_rejected() {
        let missing = std::env::temp_dir().join(format!(
            "task4-task3-missing-{}-{}",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(read_task3_degradation_events_at(
            &missing,
            "nodeB",
            Some("nodeA"),
            1_000_001,
            &Task3ContextConfig::default(),
        )
        .unwrap()
        .is_empty());

        let mut malformed = context();
        malformed.degradation_probability = f64::NAN;
        assert!(malformed
            .to_security_event_at(1_000_001, &Task3ContextConfig::default())
            .is_err());
        malformed = context();
        malformed.decision_id.clear();
        assert!(malformed
            .to_security_event_at(1_000_001, &Task3ContextConfig::default())
            .is_err());
    }

    #[test]
    fn canonical_task3_jsonl_is_read_without_route_mutation() {
        let path = std::env::temp_dir().join(format!(
            "task4-task3-context-{}-{}.jsonl",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(
            &path,
            r#"{"decision_id":"task3-decision-001","ts_ms":1000000,"prediction":{"model_version":"degradation-v1-interpretable","route_id":"direct-nodeA-nodeB","probability":0.75,"horizon_seconds":60,"contributors":["packet_loss_rising"],"reason":"network degradation detected"}}"#,
        )
        .unwrap();
        let events = read_task3_degradation_events_at(
            &path,
            "nodeB",
            Some("nodeA"),
            1_000_001,
            &Task3ContextConfig::default(),
        )
        .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].node_id, "nodeB");
        assert_eq!(events[0].attributes["task3_route_id"], "direct-nodeA-nodeB");
        assert_eq!(
            events[0].attributes["task3_decision_id"],
            "task3-decision-001"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn stale_and_future_task3_context_is_ignored_before_feature_processing() {
        let config = Task3ContextConfig::default();
        let evaluated_at_ms = config.maximum_age_ms() * 2;
        let mut stale = context();
        stale.observed_at_ms = evaluated_at_ms - config.maximum_age_ms() - 1;
        assert!(stale
            .to_security_event_at(evaluated_at_ms, &config)
            .unwrap()
            .is_none());

        let mut future = context();
        future.observed_at_ms = evaluated_at_ms + 1;
        assert!(future
            .to_security_event_at(evaluated_at_ms, &config)
            .unwrap()
            .is_none());
    }

    #[test]
    fn bounded_task3_jsonl_rejects_oversized_input() {
        let path = std::env::temp_dir().join(format!(
            "task4-task3-bounded-{}-{}.jsonl",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let row = r#"{"decision_id":"task3-decision-001","ts_ms":1000000,"prediction":{"model_version":"degradation-v1-interpretable","route_id":"direct-nodeA-nodeB","probability":0.75,"horizon_seconds":60,"contributors":["packet_loss_rising"],"reason":"network degradation detected"}}"#;
        fs::write(&path, format!("{row}\n{row}\n{row}\n")).unwrap();
        let config = Task3ContextConfig {
            max_context_age_minutes: 30,
            max_events: 2,
        };
        let bounded =
            read_task3_degradation_events_at(&path, "nodeB", Some("nodeA"), 1_000_001, &config)
                .unwrap();
        assert_eq!(bounded.len(), 2);

        fs::write(&path, "x".repeat(MAX_JSONL_LINE_BYTES + 1)).unwrap();
        assert!(matches!(
            read_task3_degradation_events_at(&path, "nodeB", Some("nodeA"), 1_000_001, &config),
            Err(ThreatPredictionError::AttributeLimitExceeded(_))
        ));
        let _ = fs::remove_file(path);
    }
}
