//! Stable, validated data contracts for Virtual Shift.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::alert::Severity;
use crate::features::FEATURE_NAMES;
use crate::rules::ActionDefinition;

use super::errors::VirtualShiftError;

/// Maximum number of peer identifiers carried by one event.  This bounds the
/// future recommendation and gossip payload.  An empty list is valid: Task 1
/// telemetry may identify an affected node but have no trusted peer identity.
pub const MAX_AFFECTED_PEERS: usize = 32;

/// Evidence is limited to the locked Task 1 feature schema.
pub const MAX_EVIDENCE_ITEMS: usize = FEATURE_NAMES.len();

/// A portable classification inferred from Task 1's existing structured
/// recommendation action.  It is informational at VS1; risk/action policy
/// selection belongs to later Virtual Shift deliverables.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyType {
    ConnectionScan,
    TrafficFlood,
    ResourceExhaustion,
    ProtocolViolation,
    PeerAnomaly,
    Generic,
}

/// One evidence feature reported by Task 1.  No raw packet payload or guessed
/// identity is introduced at this boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnomalyEvidence {
    pub feature: String,
}

/// Validated hand-off from the existing anomaly engine into Virtual Shift.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyEvent {
    pub anomaly_id: String,
    pub source_node: String,
    pub anomaly_type: AnomalyType,
    pub score: f64,
    pub confidence: f64,
    pub severity: Severity,
    #[serde(default)]
    pub affected_peers: Vec<String>,
    pub observed_at_ms: u64,
    pub evidence: Vec<AnomalyEvidence>,
    pub reason: String,
    pub recommendation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposed_action: Option<ActionDefinition>,
}

impl AnomalyEvent {
    /// Validate the security boundary before downstream recommendation logic
    /// sees the event.  This does not re-score or retune Task 1.
    pub fn validate(&self) -> Result<(), VirtualShiftError> {
        if self.anomaly_id.trim().is_empty() {
            return Err(VirtualShiftError::EmptyAnomalyId);
        }
        if self.source_node.trim().is_empty() {
            return Err(VirtualShiftError::EmptyNodeId);
        }
        if !self.score.is_finite() || !(0.0..=1.0).contains(&self.score) {
            return Err(VirtualShiftError::InvalidScore);
        }
        if !self.confidence.is_finite() || !(0.0..=1.0).contains(&self.confidence) {
            return Err(VirtualShiftError::InvalidConfidence);
        }
        if self.observed_at_ms == 0 {
            return Err(VirtualShiftError::InvalidTimestamp);
        }
        if self.affected_peers.len() > MAX_AFFECTED_PEERS {
            return Err(VirtualShiftError::TooManyAffectedPeers {
                maximum: MAX_AFFECTED_PEERS,
            });
        }

        let mut peers = BTreeSet::new();
        for peer in &self.affected_peers {
            let normalized = peer.trim();
            if normalized.is_empty() {
                return Err(VirtualShiftError::EmptyAffectedPeer);
            }
            if !peers.insert(normalized.to_owned()) {
                return Err(VirtualShiftError::DuplicateAffectedPeer(
                    normalized.to_owned(),
                ));
            }
        }

        if self.evidence.len() > MAX_EVIDENCE_ITEMS {
            return Err(VirtualShiftError::TooManyEvidenceItems {
                maximum: MAX_EVIDENCE_ITEMS,
            });
        }
        for item in &self.evidence {
            let feature = item.feature.trim();
            if feature.is_empty() {
                return Err(VirtualShiftError::EmptyEvidenceFeature);
            }
            if !FEATURE_NAMES.contains(&feature) {
                return Err(VirtualShiftError::UnknownEvidenceFeature(
                    feature.to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Result of registering an anomaly ID.  VS1 recognizes duplicate input;
/// later VS2 adds threshold/debounce policy around this primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyEventRegistration {
    New,
    Duplicate,
}

/// In-memory anomaly-ID registry. Production persistence is a later Virtual
/// Shift deliverable; this small boundary object makes duplicate recognition
/// explicit and deterministic for the current standalone engine/tests.
#[derive(Debug, Default)]
pub struct AnomalyEventRegistry {
    seen: BTreeSet<String>,
}

impl AnomalyEventRegistry {
    pub fn register(&mut self, event: &AnomalyEvent) -> AnomalyEventRegistration {
        if self.seen.insert(event.anomaly_id.clone()) {
            AnomalyEventRegistration::New
        } else {
            AnomalyEventRegistration::Duplicate
        }
    }
}
