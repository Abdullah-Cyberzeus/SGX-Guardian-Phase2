use super::{validate_unit_interval, ThreatPredictionError};
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SECURITY_EVENT_SCHEMA_VERSION: u32 = 1;
pub const MAX_EVENT_ID_BYTES: usize = 160;
pub const MAX_NODE_ID_BYTES: usize = 128;
pub const MAX_ATTRIBUTES: usize = 32;
pub const MAX_ATTRIBUTE_KEY_BYTES: usize = 64;
/// Evidence adapters may preserve compact structured source context (for
/// example Task 1 port-security evidence) while retaining a strict bound.
pub const MAX_ATTRIBUTE_VALUE_BYTES: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    Task1Anomaly,
    Suricata,
    NmapDiscovery,
    GuardianThreat,
    Attestation,
    CircleTrust,
    NetworkAi,
    GeoThreatIntel,
    PolicyLifecycle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventType {
    TrafficFlood,
    Reconnaissance,
    PortDiscovery,
    AuthenticationFailure,
    ProtocolViolation,
    TrafficAnomaly,
    PeerCompromiseIndicator,
    TrustDegradation,
    PolicyLifecycleChange,
    RouteDegradation,
    AttestationFailure,
    ExposureDiscovery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub schema_version: u32,
    pub event_id: String,
    pub observed_at_ms: u64,
    pub source: EvidenceSource,
    pub node_id: String,
    pub peer_id: Option<String>,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub event_type: SecurityEventType,
    pub severity: EventSeverity,
    pub confidence: f64,
    pub attributes: BTreeMap<String, String>,
}

impl SecurityEvent {
    pub fn validate(&self) -> Result<(), ThreatPredictionError> {
        if self.schema_version != SECURITY_EVENT_SCHEMA_VERSION {
            return Err(ThreatPredictionError::MalformedEvent(format!(
                "unsupported schema_version '{}'",
                self.schema_version
            )));
        }
        validate_identifier("event_id", &self.event_id, MAX_EVENT_ID_BYTES)?;
        validate_identifier("node_id", &self.node_id, MAX_NODE_ID_BYTES)?;
        if let Some(peer_id) = &self.peer_id {
            validate_identifier("peer_id", peer_id, MAX_NODE_ID_BYTES)?;
        }
        if self.observed_at_ms == 0 {
            return Err(ThreatPredictionError::InvalidTimestamp(
                "observed_at_ms must be greater than zero".to_string(),
            ));
        }
        validate_unit_interval("event confidence", self.confidence, false)?;
        if self.attributes.len() > MAX_ATTRIBUTES {
            return Err(ThreatPredictionError::AttributeLimitExceeded(format!(
                "at most {MAX_ATTRIBUTES} attributes are allowed"
            )));
        }
        for (key, value) in &self.attributes {
            validate_identifier("attribute key", key, MAX_ATTRIBUTE_KEY_BYTES)?;
            if value.len() > MAX_ATTRIBUTE_VALUE_BYTES {
                return Err(ThreatPredictionError::AttributeLimitExceeded(format!(
                    "attribute value for '{}' exceeds {MAX_ATTRIBUTE_VALUE_BYTES} bytes",
                    key
                )));
            }
        }
        Ok(())
    }

    pub fn validate_at(&self, latest_allowed_ms: u64) -> Result<(), ThreatPredictionError> {
        self.validate()?;
        if self.observed_at_ms > latest_allowed_ms {
            return Err(ThreatPredictionError::InvalidTimestamp(format!(
                "observed_at_ms {} is later than allowed reference {}",
                self.observed_at_ms, latest_allowed_ms
            )));
        }
        Ok(())
    }

    /// Stable key for replay-safe deduplication of the same normalized event.
    pub fn deduplication_key(&self) -> String {
        // NMAP PortDiscovery is an observation, not a permanent endpoint fact.
        //
        // Replays/repeated publication of the same observation within a short
        // window must deduplicate, while a genuinely later production scan
        // must remain eligible as fresh temporal precursor evidence.
        if self.source == EvidenceSource::NmapDiscovery
            && self.event_type == SecurityEventType::PortDiscovery
        {
            const NMAP_OBSERVATION_BUCKET_MS: u64 = 5 * 60 * 1_000;

            let protocol = self
                .attributes
                .get("nmap_protocol")
                .map(String::as_str)
                .unwrap_or("");

            let observation_bucket = self.observed_at_ms / NMAP_OBSERVATION_BUCKET_MS;

            let payload = format!(
                "{}|{}|{}|{}|{}|{}",
                self.node_id,
                self.destination_ip.as_deref().unwrap_or(""),
                self.destination_port
                    .map_or_else(String::new, |value| value.to_string()),
                protocol,
                self.schema_version,
                observation_bucket
            );

            return format!("task4-event-dedup-nmap-port-v2:{}", hex_sha256(&payload));
        }

        format!(
            "task4-event-dedup-v1:{}",
            hex_sha256(&self.canonical_payload())
        )
    }

    /// Stable ID for adapters that receive an event without a durable source ID.
    pub fn deterministic_event_id(&self) -> String {
        format!("task4-event-v1:{}", hex_sha256(&self.canonical_payload()))
    }

    fn canonical_payload(&self) -> String {
        let mut fields = vec![
            self.schema_version.to_string(),
            format!("{:?}", self.source),
            self.observed_at_ms.to_string(),
            self.node_id.clone(),
            self.peer_id.clone().unwrap_or_default(),
            self.source_ip.clone().unwrap_or_default(),
            self.destination_ip.clone().unwrap_or_default(),
            self.source_port
                .map_or_else(String::new, |value| value.to_string()),
            self.destination_port
                .map_or_else(String::new, |value| value.to_string()),
            format!("{:?}", self.event_type),
            format!("{:?}", self.severity),
            self.confidence.to_bits().to_string(),
        ];
        for (key, value) in &self.attributes {
            fields.push(key.clone());
            fields.push(value.clone());
        }
        fields.join("\u{1f}")
    }
}

fn validate_identifier(
    field: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), ThreatPredictionError> {
    if value.trim().is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(ThreatPredictionError::MalformedEvent(format!(
            "{field} must be non-empty, non-control text within {max_bytes} bytes"
        )));
    }
    Ok(())
}

fn hex_sha256(value: &str) -> String {
    digest(&SHA256, value.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_event() -> SecurityEvent {
        SecurityEvent {
            schema_version: SECURITY_EVENT_SCHEMA_VERSION,
            event_id: "suricata-nodeb-recon-001".to_string(),
            observed_at_ms: 1_000_000,
            source: EvidenceSource::Suricata,
            node_id: "nodeB".to_string(),
            peer_id: Some("nodeA".to_string()),
            source_ip: Some("10.0.0.10".to_string()),
            destination_ip: Some("10.0.0.20".to_string()),
            source_port: Some(45_000),
            destination_port: Some(22),
            event_type: SecurityEventType::Reconnaissance,
            severity: EventSeverity::High,
            confidence: 0.88,
            attributes: BTreeMap::from([("signature".to_string(), "SCAN SSH".to_string())]),
        }
    }

    #[test]
    fn normalized_event_round_trip_and_deduplication_are_deterministic() {
        let event = valid_event();
        event.validate().unwrap();
        let round_trip: SecurityEvent =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(round_trip, event);
        assert_eq!(event.deduplication_key(), round_trip.deduplication_key());
        assert_eq!(
            event.deterministic_event_id(),
            round_trip.deterministic_event_id()
        );
    }

    #[test]
    fn meaningful_event_change_produces_new_deduplication_key() {
        let event = valid_event();
        let mut changed = event.clone();
        changed.destination_port = Some(443);
        assert_ne!(event.deduplication_key(), changed.deduplication_key());
    }

    #[test]
    fn malformed_future_and_unbounded_events_are_rejected_safely() {
        let mut event = valid_event();
        event.node_id.clear();
        assert!(matches!(
            event.validate(),
            Err(ThreatPredictionError::MalformedEvent(_))
        ));

        let event = valid_event();
        assert!(matches!(
            event.validate_at(999_999),
            Err(ThreatPredictionError::InvalidTimestamp(_))
        ));

        let mut event = valid_event();
        for index in 0..=MAX_ATTRIBUTES {
            event
                .attributes
                .insert(format!("key-{index}"), "value".to_string());
        }
        assert!(matches!(
            event.validate(),
            Err(ThreatPredictionError::AttributeLimitExceeded(_))
        ));
    }
}
