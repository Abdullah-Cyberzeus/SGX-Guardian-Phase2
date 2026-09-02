//! VS3: stable recommendation model and deterministic risk classification.
//!
//! VS3 creates a reviewable recommendation record only. Exact firewall,
//! attestation, logging and quarantine proposals are intentionally deferred to
//! VS4–VS7; this module never applies a policy.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::alert::Severity;
use crate::rules::ActionDefinition;

use super::model::{AnomalyEvent, AnomalyEvidence, AnomalyType};

pub mod aggregate;
pub mod attestation;
pub mod firewall;
pub mod logging;
pub mod quarantine;

pub use aggregate::{aggregate_recommendations, AggregatedAction, AggregatedRecommendation};
pub use attestation::{
    attestation_recommendation_from_policy, AttestationProposalResult, AttestationRecommendation,
};
pub use firewall::{
    firewall_recommendations_from_event, firewall_recommendations_with_context,
    FirewallProposalResult, FirewallRecommendation, TrustedFirewallContext,
};
pub use logging::{
    logging_recommendation_from_policy, LoggingProposalResult, LoggingRecommendation, LoggingScope,
};
pub use quarantine::{
    quarantine_recommendation_from_policy, QuarantineProposalResult, QuarantineRecommendation,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// VS3 creates only `PendingReview`; later deliverables control all other
/// transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationStatus {
    PendingReview,
    Approved,
    Rejected,
    Signed,
    Broadcast,
    Verified,
    Staged,
    Applied,
    Reverted,
}

/// The four Virtual Shift action families. VS3 records the eligible action
/// families deterministically; VS4-VS7 later turn them into bounded, concrete
/// proposals only when their extra safety conditions are satisfied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendedAction {
    TightenFirewall,
    IncreaseAttestation,
    EnableLogging,
    QuarantinePeer,
}

/// A reviewable, traceable recommendation tied to one validated anomaly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyRecommendation {
    pub recommendation_id: String,
    pub anomaly_id: String,
    pub source_node: String,
    pub anomaly_type: AnomalyType,
    pub risk_level: RiskLevel,
    /// Candidate action families derived from the validated anomaly. These
    /// are not policy changes and do not contain guessed targets or limits.
    pub candidate_actions: Vec<RecommendedAction>,
    pub anomaly_score: f64,
    pub confidence: f64,
    #[serde(default)]
    pub affected_peers: Vec<String>,
    pub evidence: Vec<AnomalyEvidence>,
    pub source_reason: String,
    pub source_recommendation: String,
    /// Existing Task 1 action retained as evidence, not yet an approved
    /// Virtual Shift policy action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_action: Option<ActionDefinition>,
    pub status: RecommendationStatus,
    pub created_at_ms: u64,
}

/// The caller supplies the ID so later approval/signing/audit records can
/// reference the exact same recommendation deterministically.
pub fn recommendation_from_event(
    recommendation_id: impl Into<String>,
    event: &AnomalyEvent,
) -> PolicyRecommendation {
    PolicyRecommendation {
        recommendation_id: recommendation_id.into(),
        anomaly_id: event.anomaly_id.clone(),
        source_node: event.source_node.clone(),
        anomaly_type: event.anomaly_type.clone(),
        risk_level: classify_risk(event),
        candidate_actions: candidate_actions_for(event),
        anomaly_score: event.score,
        confidence: event.confidence,
        affected_peers: event.affected_peers.clone(),
        evidence: event.evidence.clone(),
        source_reason: event.reason.clone(),
        source_recommendation: event.recommendation.clone(),
        source_action: event.proposed_action.clone(),
        status: RecommendationStatus::PendingReview,
        created_at_ms: event.observed_at_ms,
    }
}

/// Deterministic, high-level action selection for VS3. Exact target, scope,
/// rate, duration and peer requirements remain the responsibility of VS4-VS7.
pub fn candidate_actions_for(event: &AnomalyEvent) -> Vec<RecommendedAction> {
    let mut actions = match event.anomaly_type {
        AnomalyType::ConnectionScan | AnomalyType::TrafficFlood => vec![
            RecommendedAction::TightenFirewall,
            RecommendedAction::IncreaseAttestation,
            RecommendedAction::EnableLogging,
        ],
        AnomalyType::ProtocolViolation => vec![
            RecommendedAction::TightenFirewall,
            RecommendedAction::IncreaseAttestation,
            RecommendedAction::EnableLogging,
        ],
        AnomalyType::ResourceExhaustion | AnomalyType::PeerAnomaly => vec![
            RecommendedAction::IncreaseAttestation,
            RecommendedAction::EnableLogging,
        ],
        AnomalyType::Generic => vec![],
    };
    if classify_risk(event) == RiskLevel::Critical && !event.affected_peers.is_empty() {
        actions.push(RecommendedAction::QuarantinePeer);
    }
    actions
}

/// Persist one VS3 recommendation at the documented, reviewable layout:
/// `<root>/<recommendation_id>/recommendation.json`.
pub fn write_recommendation(
    root: impl AsRef<Path>,
    recommendation: &PolicyRecommendation,
) -> anyhow::Result<PathBuf> {
    if recommendation.recommendation_id.trim().is_empty()
        || matches!(recommendation.recommendation_id.as_str(), "." | "..")
        || recommendation.recommendation_id.contains(['/', '\\'])
    {
        anyhow::bail!("recommendation_id must be a non-empty file-name-safe identifier");
    }
    let directory = root.as_ref().join(&recommendation.recommendation_id);
    std::fs::create_dir_all(&directory)?;
    let output = directory.join("recommendation.json");
    std::fs::write(&output, serde_json::to_string_pretty(recommendation)?)?;
    Ok(output)
}

/// Read a previously persisted VS3 recommendation without losing its anomaly
/// linkage, status, candidate action families, or evidence.
pub fn read_recommendation(path: impl AsRef<Path>) -> anyhow::Result<PolicyRecommendation> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

/// Conservative initial classification from type, Task 1 severity, score and
/// confidence. Later operator configuration can replace these bands without
/// changing Task 1 scoring.
pub fn classify_risk(event: &AnomalyEvent) -> RiskLevel {
    let score_level = if event.score >= 0.95 {
        RiskLevel::Critical
    } else if event.score >= 0.85 {
        RiskLevel::High
    } else if event.score >= 0.70 {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    };
    let type_level = match event.anomaly_type {
        AnomalyType::TrafficFlood | AnomalyType::ProtocolViolation => RiskLevel::High,
        AnomalyType::ConnectionScan
        | AnomalyType::ResourceExhaustion
        | AnomalyType::PeerAnomaly => RiskLevel::Medium,
        AnomalyType::Generic => RiskLevel::Low,
    };
    let severity_level = match event.severity {
        Severity::Low => RiskLevel::Low,
        Severity::Medium => RiskLevel::Medium,
        Severity::High => RiskLevel::High,
        Severity::Critical => RiskLevel::Critical,
    };
    let proposed = score_level.max(type_level).max(severity_level);
    if event.confidence < 0.90 && proposed == RiskLevel::Critical {
        RiskLevel::High
    } else {
        proposed
    }
}

#[cfg(test)]
mod tests {
    use crate::alert::Severity;
    use crate::virtual_shift::{AnomalyEvidence, AnomalyType};

    use super::*;

    fn event(anomaly_type: AnomalyType, score: f64, confidence: f64) -> AnomalyEvent {
        AnomalyEvent {
            anomaly_id: "anom-001".into(),
            source_node: "nodeA".into(),
            anomaly_type,
            score,
            confidence,
            severity: Severity::High,
            affected_peers: vec!["peer-nodeC".into()],
            observed_at_ms: 1000,
            evidence: vec![AnomalyEvidence {
                feature: "conn_rate".into(),
            }],
            reason: "test reason".into(),
            recommendation: "test recommendation".into(),
            proposed_action: None,
        }
    }

    #[test]
    fn type_score_and_confidence_produce_stable_risk() {
        assert_eq!(
            classify_risk(&event(AnomalyType::ConnectionScan, 0.93, 0.91)),
            RiskLevel::High
        );
        assert_eq!(
            classify_risk(&event(AnomalyType::TrafficFlood, 0.96, 0.95)),
            RiskLevel::Critical
        );
        assert_eq!(
            classify_risk(&event(AnomalyType::TrafficFlood, 0.96, 0.85)),
            RiskLevel::High
        );
    }

    #[test]
    fn recommendation_keeps_traceability_and_starts_pending_review() {
        let recommendation =
            recommendation_from_event("vsr-001", &event(AnomalyType::ConnectionScan, 0.93, 0.91));
        assert_eq!(recommendation.anomaly_id, "anom-001");
        assert_eq!(recommendation.status, RecommendationStatus::PendingReview);
        assert_eq!(recommendation.affected_peers, vec!["peer-nodeC"]);
        assert_eq!(
            recommendation.candidate_actions,
            vec![
                RecommendedAction::TightenFirewall,
                RecommendedAction::IncreaseAttestation,
                RecommendedAction::EnableLogging,
            ]
        );
    }

    #[test]
    fn recommendation_json_round_trip_is_stable() {
        let input = recommendation_from_event(
            "vsr-002",
            &event(AnomalyType::ProtocolViolation, 0.93, 0.91),
        );
        let json = serde_json::to_string(&input).unwrap();
        let output: PolicyRecommendation = serde_json::from_str(&json).unwrap();
        assert_eq!(output, input);
    }

    #[test]
    fn critical_event_with_a_peer_adds_reversible_quarantine_candidate() {
        let recommendation = recommendation_from_event(
            "vsr-critical",
            &event(AnomalyType::TrafficFlood, 0.97, 0.95),
        );
        assert!(recommendation
            .candidate_actions
            .contains(&RecommendedAction::QuarantinePeer));
    }

    #[test]
    fn persisted_recommendation_keeps_anomaly_linkage() {
        let root =
            std::env::temp_dir().join(format!("virtual_shift_vs3_{}_{}", std::process::id(), 1));
        let input = recommendation_from_event(
            "vsr-persisted-001",
            &event(AnomalyType::ProtocolViolation, 0.93, 0.91),
        );
        let path = write_recommendation(&root, &input).unwrap();
        let output = read_recommendation(&path).unwrap();
        assert_eq!(output.anomaly_id, "anom-001");
        assert_eq!(output, input);
        let _ = std::fs::remove_dir_all(root);
    }
}
