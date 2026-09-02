//! VS9: bounded, reviewable justification and evidence package.
//!
//! This module records why the already-aggregated VS8 actions were selected.
//! It never changes a recommendation and fails explicitly if essential evidence
//! would be missing or too large to persist safely.

use serde::{Deserialize, Serialize};

use super::{AggregatedAction, AggregatedRecommendation, PolicyRecommendation};

pub const MAX_JUSTIFICATION_BYTES: usize = 8 * 1024;
pub const MAX_STAGE_NOTES: usize = 4;
pub const MAX_STAGE_NOTE_BYTES: usize = 1024;

/// A human-readable result from VS4-VS7. Both proposed and not-proposed
/// stages are retained so the reviewer can see why an action is absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalStageNote {
    pub stage: String,
    pub result: String,
}

/// Explains one final VS8 action in both durable and reviewable form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectedActionReason {
    pub action_type: String,
    pub reason: String,
}

/// Full evidence package required before a future owner-review/signing phase.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JustificationPackage {
    pub schema_version: u32,
    pub recommendation_id: String,
    pub anomaly_id: String,
    pub source_node: String,
    pub anomaly_type: String,
    pub risk_level: String,
    pub anomaly_score: f64,
    pub confidence: f64,
    pub evidence_features: Vec<String>,
    pub source_reason: String,
    pub source_recommendation: String,
    pub stage_notes: Vec<ProposalStageNote>,
    pub selected_action_reasons: Vec<SelectedActionReason>,
    pub human_summary: String,
    pub machine_summary: String,
}

impl JustificationPackage {
    /// Validate the package before persistence. Missing evidence never becomes
    /// an empty explanation later in an approval/signing workflow.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.recommendation_id.trim().is_empty()
            || self.anomaly_id.trim().is_empty()
            || self.source_node.trim().is_empty()
        {
            anyhow::bail!("justification needs recommendation ID, anomaly ID and source node");
        }
        if !(0.0..=1.0).contains(&self.anomaly_score) || !(0.0..=1.0).contains(&self.confidence) {
            anyhow::bail!("justification score and confidence must be from 0 to 1");
        }
        if self.evidence_features.is_empty()
            || self
                .evidence_features
                .iter()
                .any(|item| item.trim().is_empty())
        {
            anyhow::bail!("justification cannot be saved without Task 1 evidence features");
        }
        if self.human_summary.trim().is_empty() || self.machine_summary.trim().is_empty() {
            anyhow::bail!("justification summaries cannot be empty");
        }
        if self.stage_notes.len() > MAX_STAGE_NOTES {
            anyhow::bail!("justification has too many VS4-VS7 stage notes");
        }
        if self.stage_notes.iter().any(|note| {
            note.stage.trim().is_empty()
                || note.result.trim().is_empty()
                || note.result.len() > MAX_STAGE_NOTE_BYTES
        }) {
            anyhow::bail!("justification has an invalid or oversized stage note");
        }
        if self
            .selected_action_reasons
            .iter()
            .any(|item| item.action_type.trim().is_empty() || item.reason.trim().is_empty())
        {
            anyhow::bail!("every selected action needs a non-empty reason");
        }
        if serde_json::to_vec(self)?.len() > MAX_JUSTIFICATION_BYTES {
            anyhow::bail!("justification exceeds the configured 8 KiB persistence limit");
        }
        Ok(())
    }

    pub fn encoded_bytes(&self) -> anyhow::Result<usize> {
        Ok(serde_json::to_vec(self)?.len())
    }
}

/// Create a complete VS9 evidence package from a VS3 recommendation and its
/// final VS8 aggregate. Stage notes must cover VS4–VS7, not a generic string.
pub fn justification_from_aggregate(
    recommendation: &PolicyRecommendation,
    aggregate: &AggregatedRecommendation,
    stage_notes: Vec<ProposalStageNote>,
) -> anyhow::Result<JustificationPackage> {
    if recommendation.recommendation_id != aggregate.recommendation_id
        || recommendation.anomaly_id != aggregate.anomaly_id
        || recommendation.source_node != aggregate.source_node
    {
        anyhow::bail!("VS8 aggregate does not belong to this VS3 recommendation");
    }
    let evidence_features = recommendation
        .evidence
        .iter()
        .map(|item| item.feature.clone())
        .collect::<Vec<_>>();
    let selected_action_reasons = aggregate
        .actions
        .iter()
        .map(action_reason)
        .collect::<Vec<_>>();
    let action_count = selected_action_reasons.len();
    let package = JustificationPackage {
        schema_version: 1,
        recommendation_id: recommendation.recommendation_id.clone(),
        anomaly_id: recommendation.anomaly_id.clone(),
        source_node: recommendation.source_node.clone(),
        anomaly_type: format!("{:?}", recommendation.anomaly_type),
        risk_level: format!("{:?}", recommendation.risk_level),
        anomaly_score: recommendation.anomaly_score,
        confidence: recommendation.confidence,
        evidence_features,
        source_reason: recommendation.source_reason.clone(),
        source_recommendation: recommendation.source_recommendation.clone(),
        stage_notes,
        selected_action_reasons,
        human_summary: format!(
            "{:?} risk anomaly on {} (score {:.3}, confidence {:.1}%) produced {} final advisory action(s).",
            recommendation.risk_level,
            recommendation.source_node,
            recommendation.anomaly_score,
            recommendation.confidence * 100.0,
            action_count,
        ),
        machine_summary: format!(
            "risk={:?}; actions={action_count}; evidence_features={}",
            recommendation.risk_level,
            recommendation.evidence.len(),
        ),
    };
    package.validate()?;
    Ok(package)
}

fn action_reason(action: &AggregatedAction) -> SelectedActionReason {
    match action {
        AggregatedAction::Firewall(value) => SelectedActionReason {
            action_type: "firewall".into(),
            reason: value.reason.clone(),
        },
        AggregatedAction::Attestation(value) => SelectedActionReason {
            action_type: "attestation".into(),
            reason: value.reason.clone(),
        },
        AggregatedAction::Logging(value) => SelectedActionReason {
            action_type: "logging".into(),
            reason: value.reason.clone(),
        },
        AggregatedAction::Quarantine(value) => SelectedActionReason {
            action_type: "quarantine".into(),
            reason: value.reason.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use crate::alert::Severity;
    use crate::policy::{LoggingLevel, PolicyAction};
    use crate::virtual_shift::{
        recommendation_from_event, AggregatedAction, AggregatedRecommendation, AnomalyEvent,
        AnomalyEvidence, AnomalyType, LoggingRecommendation,
    };

    use super::*;

    fn recommendation() -> PolicyRecommendation {
        recommendation_from_event(
            "vsr-justification-001",
            &AnomalyEvent {
                anomaly_id: "anom-justification-001".into(),
                source_node: "nodeA".into(),
                anomaly_type: AnomalyType::ConnectionScan,
                score: 0.93,
                confidence: 0.91,
                severity: Severity::High,
                affected_peers: vec![],
                observed_at_ms: 1_000,
                evidence: vec![AnomalyEvidence {
                    feature: "conn_rate".into(),
                }],
                reason: "Connection rate is elevated.".into(),
                recommendation: "Review peer traffic.".into(),
                proposed_action: None,
            },
        )
    }

    fn aggregate() -> AggregatedRecommendation {
        AggregatedRecommendation {
            recommendation_id: "vsr-justification-001".into(),
            anomaly_id: "anom-justification-001".into(),
            source_node: "nodeA".into(),
            actions: vec![AggregatedAction::Logging(LoggingRecommendation {
                policy_action: PolicyAction::EnableAdditionalLogging,
                target_node: "nodeA".into(),
                logging_level: LoggingLevel::Detailed,
                scopes: vec![],
                duration_seconds: 900,
                starts_at_ms: 1_000,
                expires_at_ms: 901_000,
                advisory_only: true,
                reason: "High risk needs temporary detailed logging.".into(),
            })],
            advisory_only: true,
            conflict_resolution: vec![],
        }
    }

    fn notes() -> Vec<ProposalStageNote> {
        vec![
            ProposalStageNote {
                stage: "VS4".into(),
                result: "No firewall target.".into(),
            },
            ProposalStageNote {
                stage: "VS5".into(),
                result: "Attestation proposed.".into(),
            },
            ProposalStageNote {
                stage: "VS6".into(),
                result: "Logging proposed.".into(),
            },
            ProposalStageNote {
                stage: "VS7".into(),
                result: "Not critical.".into(),
            },
        ]
    }

    #[test]
    fn package_keeps_score_confidence_evidence_and_selected_action_reason() {
        let value = justification_from_aggregate(&recommendation(), &aggregate(), notes()).unwrap();
        assert_eq!(value.anomaly_score, 0.93);
        assert_eq!(value.confidence, 0.91);
        assert_eq!(value.evidence_features, vec!["conn_rate"]);
        assert_eq!(value.selected_action_reasons.len(), 1);
        assert!(value.human_summary.contains("High risk"));
        assert!(value.encoded_bytes().unwrap() <= MAX_JUSTIFICATION_BYTES);
    }

    #[test]
    fn missing_evidence_is_rejected() {
        let mut input = recommendation();
        input.evidence.clear();
        assert!(justification_from_aggregate(&input, &aggregate(), notes()).is_err());
    }

    #[test]
    fn oversized_stage_note_is_rejected_instead_of_silently_dropping_it() {
        let mut input = notes();
        input[0].result = "x".repeat(MAX_STAGE_NOTE_BYTES + 1);
        assert!(justification_from_aggregate(&recommendation(), &aggregate(), input).is_err());
    }

    #[test]
    fn aggregate_identity_mismatch_is_rejected() {
        let mut input = aggregate();
        input.anomaly_id = "wrong".into();
        assert!(justification_from_aggregate(&recommendation(), &input, notes()).is_err());
    }
}
