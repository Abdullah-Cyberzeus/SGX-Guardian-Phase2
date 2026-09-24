//! Task 4 Deliverable 4: bounded, deterministic temporal features.

use super::{EventSeverity, SecurityEvent, SecurityEventType, ThreatPredictionError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const MINUTE_MS: u64 = 60_000;
const HOUR_MS: u64 = 60 * MINUTE_MS;
const DEFAULT_MAX_EVENTS: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalFeatureConfig {
    pub history_retention_minutes: u32,
    pub window_minutes: Vec<u32>,
    pub timezone_offset_minutes: i32,
    pub max_events: usize,
}

impl Default for TemporalFeatureConfig {
    fn default() -> Self {
        Self {
            history_retention_minutes: 7 * 24 * 60,
            window_minutes: vec![5, 15, 30, 60, 120, 360, 1_440],
            timezone_offset_minutes: 0,
            max_events: DEFAULT_MAX_EVENTS,
        }
    }
}

impl TemporalFeatureConfig {
    pub fn validate(&self) -> Result<(), ThreatPredictionError> {
        if self.history_retention_minutes < 24 * 60 {
            return Err(ThreatPredictionError::InvalidConfig(
                "temporal history retention must cover at least the previous 24 hours".to_string(),
            ));
        }
        if self.max_events == 0 {
            return Err(ThreatPredictionError::InvalidConfig(
                "temporal max_events must be greater than zero".to_string(),
            ));
        }
        if !(-14 * 60..=14 * 60).contains(&self.timezone_offset_minutes) {
            return Err(ThreatPredictionError::InvalidConfig(
                "temporal timezone offset must be between -840 and 840 minutes".to_string(),
            ));
        }
        for required in [5, 15, 30, 1_440] {
            if !self.window_minutes.contains(&required) {
                return Err(ThreatPredictionError::InvalidConfig(format!(
                    "temporal windows must include {required} minutes"
                )));
            }
        }
        if self.window_minutes.iter().any(|window| *window == 0) {
            return Err(ThreatPredictionError::InvalidConfig(
                "temporal windows must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TemporalWindowFeatures {
    pub window_minutes: u32,
    pub event_count: u64,
    pub event_rate_per_minute: f64,
    pub alert_rate_per_minute: f64,
    pub critical_alert_rate_per_minute: f64,
    pub connection_rate_per_minute: f64,
    pub connection_rate_delta_per_minute: f64,
    pub unique_source_count: u64,
    pub unique_destination_count: u64,
    pub unique_destination_port_count: u64,
    pub failed_auth_rate_per_minute: f64,
    pub scan_velocity_per_minute: f64,
    pub traffic_bytes_rate_per_minute: f64,
    pub traffic_growth_rate_per_minute: f64,
    pub anomaly_score_mean: Option<f64>,
    pub anomaly_score_max: Option<f64>,
    pub attestation_failure_rate_per_minute: f64,
    pub peer_trust_failure_rate_per_minute: f64,
    pub policy_change_rate_per_minute: f64,
    pub network_degradation_rate_per_minute: f64,
    pub network_degradation_probability_max: Option<f64>,
    pub new_device_rate_per_minute: f64,
    pub new_open_port_rate_per_minute: f64,
    pub vulnerable_service_count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimeOfDayBaseline {
    pub hour_of_day: u8,
    pub day_of_week: u8,
    pub weekday: bool,
    pub current_window_rate_per_minute: f64,
    pub same_hour_historical_mean: f64,
    pub same_hour_historical_stddev: f64,
    pub seasonal_deviation_score: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TemporalFeatures {
    pub reference_time_ms: u64,
    pub history_start_ms: u64,
    pub history_event_count: u64,
    pub windows: BTreeMap<u32, TemporalWindowFeatures>,
    pub time_of_day: TimeOfDayBaseline,
}

#[derive(Debug, Clone)]
pub struct TemporalFeatureEngine {
    config: TemporalFeatureConfig,
    events: Vec<SecurityEvent>,
}

impl TemporalFeatureEngine {
    pub fn new(config: TemporalFeatureConfig) -> Result<Self, ThreatPredictionError> {
        config.validate()?;
        Ok(Self {
            config,
            events: Vec::new(),
        })
    }

    /// Returns false for a replay whose canonical Task 4 event key already
    /// exists. The engine never reclassifies or duplicates source evidence.
    pub fn ingest(&mut self, event: SecurityEvent) -> Result<bool, ThreatPredictionError> {
        event.validate()?;
        validate_temporal_attributes(&event)?;
        let key = event.deduplication_key();
        if self
            .events
            .iter()
            .any(|existing| existing.deduplication_key() == key)
        {
            return Ok(false);
        }
        self.events.push(event);
        self.events.sort_by_key(|event| event.observed_at_ms);
        if self.events.len() > self.config.max_events {
            let excess = self.events.len() - self.config.max_events;
            self.events.drain(..excess);
        }
        Ok(true)
    }

    /// Bulk-loads canonical Task4 events for prediction-cycle replay.
    ///
    /// This preserves the validation, deduplication, chronological ordering,
    /// and max_events retention semantics of `ingest`, while avoiding a full
    /// vector sort after every historical event.
    ///
    /// Existing `ingest()` behavior is intentionally unchanged for live
    /// incremental callers.
    pub fn ingest_replay<I>(&mut self, events: I) -> Result<usize, ThreatPredictionError>
    where
        I: IntoIterator<Item = SecurityEvent>,
    {
        use std::collections::BTreeSet;

        let mut existing_keys = self
            .events
            .iter()
            .map(SecurityEvent::deduplication_key)
            .collect::<BTreeSet<_>>();

        let mut accepted = 0usize;

        for event in events {
            event.validate()?;
            validate_temporal_attributes(&event)?;

            let key = event.deduplication_key();
            if !existing_keys.insert(key) {
                continue;
            }

            self.events.push(event);
            accepted = accepted.saturating_add(1);
        }

        // Same final chronological ordering as repeated ingest(), but once.
        self.events.sort_by_key(|event| event.observed_at_ms);

        // Same max_events retention rule: retain the newest events.
        if self.events.len() > self.config.max_events {
            let excess = self.events.len() - self.config.max_events;
            self.events.drain(..excess);
        }

        Ok(accepted)
    }

    /// Produces deterministic features at a caller-provided timestamp. Events
    /// later than `reference_time_ms` are deliberately excluded.
    pub fn features_at(&self, reference_time_ms: u64) -> TemporalFeatures {
        self.features_for_node_internal(None, reference_time_ms)
    }

    /// Produces a node-specific history/profile so one node's activity never
    /// contributes to another node's time-of-day baseline.
    pub fn features_for_node_at(&self, node_id: &str, reference_time_ms: u64) -> TemporalFeatures {
        self.features_for_node_internal(Some(node_id), reference_time_ms)
    }

    fn features_for_node_internal(
        &self,
        node_id: Option<&str>,
        reference_time_ms: u64,
    ) -> TemporalFeatures {
        let retention_ms = u64::from(self.config.history_retention_minutes) * MINUTE_MS;
        let history_start_ms = reference_time_ms.saturating_sub(retention_ms);
        let history: Vec<&SecurityEvent> = self
            .events
            .iter()
            .filter(|event| {
                event.observed_at_ms >= history_start_ms
                    && event.observed_at_ms <= reference_time_ms
                    && node_id.is_none_or(|node_id| event.node_id == node_id)
            })
            .collect();
        let mut windows = BTreeMap::new();
        for &minutes in &self.config.window_minutes {
            windows.insert(
                minutes,
                window_features(&history, reference_time_ms, minutes),
            );
        }
        let current_rate = windows
            .get(&30)
            .expect("validated 30-minute window")
            .event_rate_per_minute;
        TemporalFeatures {
            reference_time_ms,
            history_start_ms,
            history_event_count: history.len() as u64,
            windows,
            time_of_day: time_of_day_baseline(
                &history,
                reference_time_ms,
                self.config.timezone_offset_minutes,
                current_rate,
            ),
        }
    }
}

fn window_features(
    history: &[&SecurityEvent],
    reference_time_ms: u64,
    minutes: u32,
) -> TemporalWindowFeatures {
    let duration_ms = u64::from(minutes) * MINUTE_MS;
    let start_ms = reference_time_ms.saturating_sub(duration_ms);
    let current: Vec<&SecurityEvent> = history
        .iter()
        .copied()
        .filter(|event| {
            event.observed_at_ms > start_ms && event.observed_at_ms <= reference_time_ms
        })
        .collect();
    let previous: Vec<&SecurityEvent> = history
        .iter()
        .copied()
        .filter(|event| {
            event.observed_at_ms > start_ms.saturating_sub(duration_ms)
                && event.observed_at_ms <= start_ms
        })
        .collect();
    let divisor = f64::from(minutes);
    let connections = count_connections(&current);
    let previous_connections = count_connections(&previous);
    let traffic = sum_attribute(&current, "traffic_bytes");
    let previous_traffic = sum_attribute(&previous, "traffic_bytes");
    let scores: Vec<f64> = current
        .iter()
        .filter_map(|event| event.attributes.get("task1_anomaly_score"))
        .filter_map(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite() && (0.0..=1.0).contains(value))
        .collect();

    TemporalWindowFeatures {
        window_minutes: minutes,
        event_count: current.len() as u64,
        event_rate_per_minute: current.len() as f64 / divisor,
        alert_rate_per_minute: current
            .iter()
            .filter(|event| event.severity >= EventSeverity::Medium)
            .count() as f64
            / divisor,
        critical_alert_rate_per_minute: current
            .iter()
            .filter(|event| event.severity == EventSeverity::Critical)
            .count() as f64
            / divisor,
        connection_rate_per_minute: connections / divisor,
        connection_rate_delta_per_minute: (connections - previous_connections) / divisor,
        unique_source_count: current
            .iter()
            .filter_map(|event| event.source_ip.as_deref())
            .collect::<BTreeSet<_>>()
            .len() as u64,
        unique_destination_count: current
            .iter()
            .filter_map(|event| event.destination_ip.as_deref())
            .collect::<BTreeSet<_>>()
            .len() as u64,
        unique_destination_port_count: current
            .iter()
            .filter_map(|event| event.destination_port)
            .collect::<BTreeSet<_>>()
            .len() as u64,
        failed_auth_rate_per_minute: count_type(&current, SecurityEventType::AuthenticationFailure)
            / divisor,
        scan_velocity_per_minute: (count_type(&current, SecurityEventType::Reconnaissance)
            + count_type(&current, SecurityEventType::PortDiscovery))
            / divisor,
        traffic_bytes_rate_per_minute: traffic / divisor,
        traffic_growth_rate_per_minute: (traffic - previous_traffic) / divisor,
        anomaly_score_mean: (!scores.is_empty())
            .then(|| scores.iter().sum::<f64>() / scores.len() as f64),
        anomaly_score_max: scores.iter().copied().reduce(f64::max),
        attestation_failure_rate_per_minute: count_type(
            &current,
            SecurityEventType::AttestationFailure,
        ) / divisor,
        peer_trust_failure_rate_per_minute: count_type(
            &current,
            SecurityEventType::TrustDegradation,
        ) / divisor,
        policy_change_rate_per_minute: count_type(
            &current,
            SecurityEventType::PolicyLifecycleChange,
        ) / divisor,
        network_degradation_rate_per_minute: count_type(
            &current,
            SecurityEventType::RouteDegradation,
        ) / divisor,
        network_degradation_probability_max: current
            .iter()
            .filter(|event| event.event_type == SecurityEventType::RouteDegradation)
            .filter_map(|event| attribute_number(event, "task3_degradation_probability"))
            .filter(|value| (0.0..=1.0).contains(value))
            .reduce(f64::max),
        new_device_rate_per_minute: current
            .iter()
            .filter_map(|event| event.attributes.get("new_device_id"))
            .collect::<BTreeSet<_>>()
            .len() as f64
            / divisor,
        new_open_port_rate_per_minute: count_type(&current, SecurityEventType::ExposureDiscovery)
            / divisor,
        vulnerable_service_count: current
            .iter()
            .filter_map(vulnerable_service_identity)
            .collect::<BTreeSet<_>>()
            .len() as u64,
    }
}

fn count_type(events: &[&SecurityEvent], kind: SecurityEventType) -> f64 {
    events
        .iter()
        .filter(|event| event.event_type == kind)
        .count() as f64
}

fn count_connections(events: &[&SecurityEvent]) -> f64 {
    events
        .iter()
        .map(|event| attribute_number(event, "connection_count").unwrap_or(0.0))
        .sum()
}

fn sum_attribute(events: &[&SecurityEvent], key: &str) -> f64 {
    events
        .iter()
        .map(|event| attribute_number(event, key).unwrap_or(0.0))
        .sum()
}

fn attribute_number(event: &SecurityEvent, key: &str) -> Option<f64> {
    event
        .attributes
        .get(key)
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value >= 0.0)
}

fn validate_temporal_attributes(event: &SecurityEvent) -> Result<(), ThreatPredictionError> {
    for key in ["connection_count", "traffic_bytes", "max_cvss"] {
        let Some(value) = event.attributes.get(key) else {
            continue;
        };
        if value
            .parse::<f64>()
            .ok()
            .filter(|number| number.is_finite() && *number >= 0.0)
            .is_none()
        {
            return Err(ThreatPredictionError::MalformedEvent(format!(
                "temporal attribute '{key}' must be a finite non-negative number"
            )));
        }
    }
    Ok(())
}

fn vulnerable_service_identity(event: &&SecurityEvent) -> Option<String> {
    if let Some(identity) = event.attributes.get("vulnerable_service_id") {
        return Some(identity.clone());
    }
    let context = event.attributes.get("task1_port_security_context")?;
    let context: Value = serde_json::from_str(context).ok()?;
    let finding = context.get("nmap_finding")?;
    let cvss = finding
        .get("max_cvss")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let explicitly_vulnerable = finding
        .get("vulnerable")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if cvss <= 0.0 && !explicitly_vulnerable {
        return None;
    }
    let ip = finding
        .get("ip")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let port = finding
        .get("port")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let service = finding
        .get("service")
        .and_then(Value::as_str)
        .unwrap_or_default();
    Some(format!("{ip}:{port}:{service}"))
}

fn time_of_day_baseline(
    history: &[&SecurityEvent],
    reference_time_ms: u64,
    offset_minutes: i32,
    current_rate: f64,
) -> TimeOfDayBaseline {
    let (hour_of_day, day_of_week) = local_clock(reference_time_ms, offset_minutes);
    let current_hour_start = reference_time_ms / HOUR_MS * HOUR_MS;
    let mut bucket_counts: BTreeMap<u64, u64> = BTreeMap::new();
    for event in history
        .iter()
        .copied()
        .filter(|event| event.observed_at_ms < current_hour_start)
    {
        let (event_hour, _) = local_clock(event.observed_at_ms, offset_minutes);
        if event_hour == hour_of_day {
            *bucket_counts
                .entry(event.observed_at_ms / HOUR_MS)
                .or_default() += 1;
        }
    }
    let samples: Vec<f64> = bucket_counts
        .values()
        .map(|count| *count as f64 / 60.0)
        .collect();
    let mean = if samples.is_empty() {
        0.0
    } else {
        samples.iter().sum::<f64>() / samples.len() as f64
    };
    let stddev = if samples.len() < 2 {
        0.0
    } else {
        (samples
            .iter()
            .map(|sample| (sample - mean).powi(2))
            .sum::<f64>()
            / samples.len() as f64)
            .sqrt()
    };
    TimeOfDayBaseline {
        hour_of_day,
        day_of_week,
        weekday: day_of_week < 5,
        current_window_rate_per_minute: current_rate,
        same_hour_historical_mean: mean,
        same_hour_historical_stddev: stddev,
        seasonal_deviation_score: if stddev > 0.0 {
            (current_rate - mean) / stddev
        } else {
            0.0
        },
    }
}

fn local_clock(timestamp_ms: u64, offset_minutes: i32) -> (u8, u8) {
    let local_minutes = (timestamp_ms / MINUTE_MS) as i64 + i64::from(offset_minutes);
    let hour = local_minutes.div_euclid(60).rem_euclid(24) as u8;
    // Unix epoch was Thursday; Monday is represented as zero.
    let day = (local_minutes.div_euclid(60 * 24) + 3).rem_euclid(7) as u8;
    (hour, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat_prediction::{EvidenceSource, SECURITY_EVENT_SCHEMA_VERSION};
    use std::collections::BTreeMap;

    fn event(id: &str, observed_at_ms: u64, kind: SecurityEventType) -> SecurityEvent {
        SecurityEvent {
            schema_version: SECURITY_EVENT_SCHEMA_VERSION,
            event_id: id.to_string(),
            observed_at_ms,
            source: EvidenceSource::Task1Anomaly,
            node_id: "nodeB".to_string(),
            peer_id: None,
            source_ip: Some("10.0.0.10".to_string()),
            destination_ip: Some("10.0.0.20".to_string()),
            source_port: Some(45_000),
            destination_port: Some(443),
            event_type: kind,
            severity: EventSeverity::High,
            confidence: 0.8,
            attributes: BTreeMap::from([
                ("task1_anomaly_score".to_string(), "0.8".to_string()),
                ("connection_count".to_string(), "12".to_string()),
                ("traffic_bytes".to_string(), "2400".to_string()),
            ]),
        }
    }

    fn event_for_node(
        id: &str,
        node_id: &str,
        observed_at_ms: u64,
        kind: SecurityEventType,
    ) -> SecurityEvent {
        let mut event = event(id, observed_at_ms, kind);
        event.node_id = node_id.to_string();
        event
    }

    #[test]
    fn fixed_reference_output_is_deterministic_and_uses_24_hour_context() {
        let reference = 2 * 24 * HOUR_MS;
        let mut engine = TemporalFeatureEngine::new(TemporalFeatureConfig::default()).unwrap();
        engine
            .ingest(event(
                "task1-1",
                reference - 10 * MINUTE_MS,
                SecurityEventType::Reconnaissance,
            ))
            .unwrap();
        engine
            .ingest(event(
                "task1-2",
                reference - 20 * MINUTE_MS,
                SecurityEventType::AuthenticationFailure,
            ))
            .unwrap();
        let first = engine.features_at(reference);
        let second = engine.features_at(reference);
        assert_eq!(first, second);
        assert_eq!(first.windows[&30].event_count, 2);
        assert_eq!(first.windows[&1_440].event_count, 2);
        assert_eq!(first.windows[&30].scan_velocity_per_minute, 1.0 / 30.0);
    }

    #[test]
    fn future_events_never_leak_into_fixed_time_features() {
        let reference = 24 * HOUR_MS;
        let mut engine = TemporalFeatureEngine::new(TemporalFeatureConfig::default()).unwrap();
        engine
            .ingest(event(
                "past",
                reference - MINUTE_MS,
                SecurityEventType::TrafficAnomaly,
            ))
            .unwrap();
        let before = engine.features_at(reference);
        engine
            .ingest(event(
                "future",
                reference + MINUTE_MS,
                SecurityEventType::TrafficFlood,
            ))
            .unwrap();
        assert_eq!(before, engine.features_at(reference));
    }

    #[test]
    fn history_is_bounded_and_replays_do_not_duplicate_features() {
        let reference = 9 * 24 * HOUR_MS;
        let mut config = TemporalFeatureConfig::default();
        config.max_events = 2;
        let mut engine = TemporalFeatureEngine::new(config).unwrap();
        assert!(engine
            .ingest(event(
                "old",
                reference - 8 * 24 * HOUR_MS,
                SecurityEventType::TrafficAnomaly
            ))
            .unwrap());
        assert!(engine
            .ingest(event(
                "current",
                reference - MINUTE_MS,
                SecurityEventType::TrafficAnomaly
            ))
            .unwrap());
        assert!(!engine
            .ingest(event(
                "current",
                reference - MINUTE_MS,
                SecurityEventType::TrafficAnomaly
            ))
            .unwrap());
        assert!(engine
            .ingest(event(
                "newest",
                reference - 2 * MINUTE_MS,
                SecurityEventType::TrafficAnomaly
            ))
            .unwrap());
        let features = engine.features_at(reference);
        assert_eq!(features.history_event_count, 2);
        assert_eq!(features.windows[&5].event_count, 2);
    }

    #[test]
    fn every_required_historical_window_counts_only_its_own_history() {
        let reference = 30 * 24 * HOUR_MS;
        let mut engine = TemporalFeatureEngine::new(TemporalFeatureConfig::default()).unwrap();
        for (id, offset_minutes) in [
            ("w5", 4),
            ("w15", 14),
            ("w30", 29),
            ("w60", 59),
            ("w120", 119),
            ("w360", 359),
            ("w1440", 1_439),
        ] {
            engine
                .ingest(event(
                    id,
                    reference - offset_minutes * MINUTE_MS,
                    SecurityEventType::TrafficAnomaly,
                ))
                .unwrap();
        }
        let windows = engine.features_at(reference).windows;
        for (window, count) in [
            (5, 1),
            (15, 2),
            (30, 3),
            (60, 4),
            (120, 5),
            (360, 6),
            (1_440, 7),
        ] {
            assert_eq!(windows[&window].event_count, count, "{window}m window");
        }
    }

    #[test]
    fn timezone_and_time_of_day_baselines_are_explicit_and_node_isolated() {
        let reference = 10 * 24 * HOUR_MS + 2 * HOUR_MS;
        let mut config = TemporalFeatureConfig::default();
        config.timezone_offset_minutes = 120;
        let mut engine = TemporalFeatureEngine::new(config).unwrap();
        engine
            .ingest(event_for_node(
                "node-a-history",
                "nodeA",
                reference - 24 * HOUR_MS,
                SecurityEventType::TrafficAnomaly,
            ))
            .unwrap();
        engine
            .ingest(event_for_node(
                "node-b-current",
                "nodeB",
                reference - MINUTE_MS,
                SecurityEventType::TrafficAnomaly,
            ))
            .unwrap();
        let node_b = engine.features_for_node_at("nodeB", reference);
        assert_eq!(node_b.history_event_count, 1);
        assert_eq!(node_b.time_of_day.hour_of_day, 4);
        assert_eq!(node_b.time_of_day.same_hour_historical_mean, 0.0);
    }

    #[test]
    fn new_device_and_vulnerable_service_features_are_deterministic() {
        let reference = 24 * HOUR_MS;
        let mut first = event(
            "device-1",
            reference - MINUTE_MS,
            SecurityEventType::TrafficAnomaly,
        );
        first
            .attributes
            .insert("new_device_id".to_string(), "device-x".to_string());
        first.attributes.insert(
            "vulnerable_service_id".to_string(),
            "nodeB:443:https".to_string(),
        );
        let mut second = event(
            "device-2",
            reference - 2 * MINUTE_MS,
            SecurityEventType::TrafficAnomaly,
        );
        second
            .attributes
            .insert("new_device_id".to_string(), "device-x".to_string());
        second.attributes.insert(
            "vulnerable_service_id".to_string(),
            "nodeB:443:https".to_string(),
        );
        let mut engine = TemporalFeatureEngine::new(TemporalFeatureConfig::default()).unwrap();
        engine.ingest(first).unwrap();
        engine.ingest(second).unwrap();
        let features = &engine.features_at(reference).windows[&5];
        assert_eq!(features.new_device_rate_per_minute, 1.0 / 5.0);
        assert_eq!(features.vulnerable_service_count, 1);
    }

    #[test]
    fn missing_or_malformed_temporal_attributes_are_safe() {
        let reference = 24 * HOUR_MS;
        let mut missing = event(
            "missing",
            reference - MINUTE_MS,
            SecurityEventType::TrafficAnomaly,
        );
        missing.attributes.clear();
        let mut engine = TemporalFeatureEngine::new(TemporalFeatureConfig::default()).unwrap();
        engine.ingest(missing).unwrap();
        assert_eq!(
            engine.features_at(reference).windows[&5].traffic_bytes_rate_per_minute,
            0.0
        );

        let mut malformed = event(
            "malformed",
            reference - 2 * MINUTE_MS,
            SecurityEventType::TrafficAnomaly,
        );
        malformed
            .attributes
            .insert("traffic_bytes".to_string(), "not-a-number".to_string());
        assert!(matches!(
            engine.ingest(malformed),
            Err(ThreatPredictionError::MalformedEvent(_))
        ));
    }
}
