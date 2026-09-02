//! VS6: bounded, scoped and expiring enhanced logging proposals.

use serde::{Deserialize, Serialize};

use crate::policy::{LoggingLevel, PolicyAction, PolicyParameters, PolicyTemplates};

use super::super::{AnomalyType, PolicyRecommendation, RiskLevel};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoggingScope {
    SecurityEvents,
    NetworkFlowMetadata,
    ProtocolViolationDetails,
    ResourceMetrics,
    PeerInteractionMetadata,
    PolicyEnforcementResults,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoggingRecommendation {
    pub policy_action: PolicyAction,
    pub target_node: String,
    pub logging_level: LoggingLevel,
    pub scopes: Vec<LoggingScope>,
    pub duration_seconds: u64,
    pub starts_at_ms: u64,
    pub expires_at_ms: u64,
    pub advisory_only: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoggingProposalResult {
    Proposed(LoggingRecommendation),
    NoProposal { reason: String },
}

/// Create a temporary logging proposal from VS3 risk and anomaly type.
pub fn logging_recommendation_from_policy(
    recommendation: &PolicyRecommendation,
    templates: &PolicyTemplates,
) -> anyhow::Result<LoggingProposalResult> {
    if recommendation.risk_level == RiskLevel::Low {
        return Ok(LoggingProposalResult::NoProposal {
            reason: "Low risk keeps the current logging level.".into(),
        });
    }
    if recommendation.anomaly_type == AnomalyType::Generic {
        return Ok(LoggingProposalResult::NoProposal {
            reason: "Generic anomaly type has no approved focused logging scope.".into(),
        });
    }
    let template = templates
        .templates
        .iter()
        .find(|template| template.action == PolicyAction::EnableAdditionalLogging)
        .ok_or_else(|| anyhow::anyhow!("admin logging template is missing"))?;
    if !template.enabled {
        return Ok(LoggingProposalResult::NoProposal {
            reason: "Admin policy does not currently allow enhanced logging.".into(),
        });
    }
    let (logging_level, duration_seconds, reason) = match recommendation.risk_level {
        RiskLevel::Medium => (
            template.medium_logging_level,
            template.medium_logging_duration_seconds,
            "Medium risk: temporarily enable basic focused security logging.",
        ),
        RiskLevel::High => (
            template.high_logging_level,
            template.high_logging_duration_seconds,
            "High risk: temporarily enable detailed incident logging.",
        ),
        RiskLevel::Critical => (
            template.critical_logging_level,
            template.critical_logging_duration_seconds,
            "Critical risk: temporarily enable detailed incident logging for the maximum configured response window.",
        ),
        RiskLevel::Low => unreachable!(),
    };
    let logging_level = logging_level.ok_or_else(|| {
        anyhow::anyhow!("admin logging template is missing a level for this risk")
    })?;
    let duration_seconds = duration_seconds.ok_or_else(|| {
        anyhow::anyhow!("admin logging template is missing a duration for this risk")
    })?;
    let parameters = PolicyParameters {
        target: recommendation.source_node.clone(),
        duration_seconds: Some(duration_seconds),
        firewall_mode: None,
        rate_limit_per_second: None,
        attestation_interval_seconds: None,
        logging_level: Some(logging_level),
    };
    templates.validate_parameters(PolicyAction::EnableAdditionalLogging, &parameters)?;
    let starts_at_ms = recommendation.created_at_ms;
    let expires_at_ms = starts_at_ms.saturating_add(duration_seconds.saturating_mul(1_000));
    Ok(LoggingProposalResult::Proposed(LoggingRecommendation {
        policy_action: PolicyAction::EnableAdditionalLogging,
        target_node: recommendation.source_node.clone(),
        logging_level,
        scopes: scopes_for(recommendation.anomaly_type.clone()),
        duration_seconds,
        starts_at_ms,
        expires_at_ms,
        advisory_only: true,
        reason: reason.into(),
    }))
}

fn scopes_for(anomaly_type: AnomalyType) -> Vec<LoggingScope> {
    let mut scopes = vec![
        LoggingScope::SecurityEvents,
        LoggingScope::PolicyEnforcementResults,
    ];
    match anomaly_type {
        AnomalyType::ConnectionScan | AnomalyType::TrafficFlood => {
            scopes.push(LoggingScope::NetworkFlowMetadata)
        }
        AnomalyType::ProtocolViolation => scopes.push(LoggingScope::ProtocolViolationDetails),
        AnomalyType::ResourceExhaustion => scopes.push(LoggingScope::ResourceMetrics),
        AnomalyType::PeerAnomaly => scopes.push(LoggingScope::PeerInteractionMetadata),
        AnomalyType::Generic => {}
    }
    scopes
}

#[cfg(test)]
mod tests {
    use crate::alert::Severity;
    use crate::virtual_shift::{
        recommendation_from_event, AnomalyEvent, AnomalyEvidence, AnomalyType,
    };

    use super::*;

    fn templates() -> PolicyTemplates {
        PolicyTemplates::from_path("config/policy_action_templates.json").unwrap()
    }

    fn recommendation(score: f64, confidence: f64) -> PolicyRecommendation {
        recommendation_from_event(
            "vsr-logging",
            &AnomalyEvent {
                anomaly_id: "anom-logging".into(),
                source_node: "nodeA".into(),
                anomaly_type: AnomalyType::ProtocolViolation,
                score,
                confidence,
                severity: Severity::High,
                affected_peers: vec![],
                observed_at_ms: 1_000,
                evidence: vec![AnomalyEvidence {
                    feature: "proto_violation_rate".into(),
                }],
                reason: "test".into(),
                recommendation: "test".into(),
                proposed_action: None,
            },
        )
    }

    #[test]
    fn high_risk_logging_is_detailed_scoped_and_expiring() {
        let result =
            logging_recommendation_from_policy(&recommendation(0.93, 0.91), &templates()).unwrap();
        let LoggingProposalResult::Proposed(proposal) = result else {
            panic!("expected proposal")
        };
        assert_eq!(proposal.logging_level, LoggingLevel::Detailed);
        assert_eq!(proposal.duration_seconds, 900);
        assert_eq!(proposal.expires_at_ms, 901_000);
        assert!(proposal
            .scopes
            .contains(&LoggingScope::ProtocolViolationDetails));
        assert!(proposal.advisory_only);
    }

    #[test]
    fn critical_risk_logging_uses_longer_bounded_expiry() {
        let result =
            logging_recommendation_from_policy(&recommendation(0.96, 0.95), &templates()).unwrap();
        let LoggingProposalResult::Proposed(proposal) = result else {
            panic!("expected proposal")
        };
        assert_eq!(proposal.duration_seconds, 1_800);
        assert_eq!(proposal.expires_at_ms, 1_801_000);
    }

    #[test]
    fn medium_risk_logging_is_basic_scoped_and_temporary() {
        let mut value = recommendation(0.93, 0.91);
        value.risk_level = RiskLevel::Medium;
        let result = logging_recommendation_from_policy(&value, &templates()).unwrap();
        let LoggingProposalResult::Proposed(proposal) = result else {
            panic!("expected proposal")
        };
        assert_eq!(proposal.logging_level, LoggingLevel::Basic);
        assert_eq!(proposal.duration_seconds, 300);
        assert_eq!(proposal.expires_at_ms, 301_000);
        assert!(proposal
            .scopes
            .contains(&LoggingScope::ProtocolViolationDetails));
    }

    #[test]
    fn low_risk_logging_does_not_escalate() {
        let mut value = recommendation(0.93, 0.91);
        value.risk_level = RiskLevel::Low;
        let result = logging_recommendation_from_policy(&value, &templates()).unwrap();
        assert!(matches!(result, LoggingProposalResult::NoProposal { .. }));
    }

    #[test]
    fn generic_type_fails_closed_without_a_logging_scope() {
        let mut value = recommendation(0.93, 0.91);
        value.anomaly_type = AnomalyType::Generic;
        let result = logging_recommendation_from_policy(&value, &templates()).unwrap();
        assert!(matches!(result, LoggingProposalResult::NoProposal { .. }));
    }

    #[test]
    fn out_of_bounds_logging_duration_is_rejected_by_the_template() {
        let mut invalid_templates = templates();
        let template = invalid_templates
            .templates
            .iter_mut()
            .find(|template| template.action == PolicyAction::EnableAdditionalLogging)
            .unwrap();
        template.critical_logging_duration_seconds = Some(3_601); // max is 3_600
        assert!(invalid_templates.validate().is_err());
    }
}
