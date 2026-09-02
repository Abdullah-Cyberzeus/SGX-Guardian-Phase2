//! VS5: bounded advisory attestation-frequency recommendations.

use serde::{Deserialize, Serialize};

use crate::policy::{PolicyAction, PolicyParameters, PolicyTemplates};

use super::super::{PolicyRecommendation, RiskLevel};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationRecommendation {
    pub policy_action: PolicyAction,
    /// The anomaly source node is known from Task 1 and is used as the
    /// attestation target. A peer is never guessed from telemetry.
    pub target_node: String,
    pub interval_seconds: u64,
    pub immediate_reattest: bool,
    pub advisory_only: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationProposalResult {
    Proposed(AttestationRecommendation),
    NoProposal { reason: String },
}

/// Map VS3 risk to an admin-bounded attestation interval.
///
/// Low risk keeps the current schedule. Medium shortens the schedule. High
/// and Critical also request an immediate fresh attestation, but remain only
/// reviewable proposals until later approval/enforcement phases.
pub fn attestation_recommendation_from_policy(
    recommendation: &PolicyRecommendation,
    templates: &PolicyTemplates,
) -> anyhow::Result<AttestationProposalResult> {
    if recommendation.risk_level == RiskLevel::Low {
        return Ok(AttestationProposalResult::NoProposal {
            reason: "Low risk keeps the existing attestation schedule.".into(),
        });
    }
    let template = templates
        .templates
        .iter()
        .find(|template| template.action == PolicyAction::IncreaseAttestationFrequency)
        .ok_or_else(|| anyhow::anyhow!("admin attestation template is missing"))?;
    if !template.enabled {
        return Ok(AttestationProposalResult::NoProposal {
            reason: "Admin policy does not currently allow attestation-frequency changes.".into(),
        });
    }

    let (interval_seconds, immediate_reattest, reason) = match recommendation.risk_level {
        RiskLevel::Medium => (
            template.medium_attestation_interval_seconds,
            false,
            "Medium risk: temporarily shorten the recurring attestation interval.",
        ),
        RiskLevel::High => (
            template.high_attestation_interval_seconds,
            true,
            "High risk: request immediate re-attestation and a shorter recurring interval.",
        ),
        RiskLevel::Critical => (
            template.critical_attestation_interval_seconds,
            true,
            "Critical risk: request immediate re-attestation and the shortest admin-approved interval.",
        ),
        RiskLevel::Low => unreachable!(),
    };
    let interval_seconds = interval_seconds.ok_or_else(|| {
        anyhow::anyhow!("admin attestation template is missing the interval for this risk level")
    })?;
    let parameters = PolicyParameters {
        target: recommendation.source_node.clone(),
        duration_seconds: None,
        firewall_mode: None,
        rate_limit_per_second: None,
        attestation_interval_seconds: Some(interval_seconds),
        logging_level: None,
    };
    templates.validate_parameters(PolicyAction::IncreaseAttestationFrequency, &parameters)?;
    Ok(AttestationProposalResult::Proposed(
        AttestationRecommendation {
            policy_action: PolicyAction::IncreaseAttestationFrequency,
            target_node: recommendation.source_node.clone(),
            interval_seconds,
            immediate_reattest,
            advisory_only: true,
            reason: reason.into(),
        },
    ))
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
            "vsr-attestation",
            &AnomalyEvent {
                anomaly_id: "anom-attestation".into(),
                source_node: "nodeA".into(),
                anomaly_type: AnomalyType::ConnectionScan,
                score,
                confidence,
                severity: Severity::High,
                affected_peers: vec![],
                observed_at_ms: 1_000,
                evidence: vec![AnomalyEvidence {
                    feature: "conn_rate".into(),
                }],
                reason: "test".into(),
                recommendation: "test".into(),
                proposed_action: None,
            },
        )
    }

    #[test]
    fn high_risk_requests_immediate_bounded_reattest() {
        let result =
            attestation_recommendation_from_policy(&recommendation(0.93, 0.91), &templates())
                .unwrap();
        let AttestationProposalResult::Proposed(proposal) = result else {
            panic!("expected proposal")
        };
        assert_eq!(proposal.target_node, "nodeA");
        assert_eq!(proposal.interval_seconds, 120);
        assert!(proposal.immediate_reattest);
        assert!(proposal.advisory_only);
    }

    #[test]
    fn medium_risk_uses_a_bounded_interval_without_immediate_reattest() {
        let mut value = recommendation(0.93, 0.91);
        value.risk_level = RiskLevel::Medium;
        let result = attestation_recommendation_from_policy(&value, &templates()).unwrap();
        let AttestationProposalResult::Proposed(proposal) = result else {
            panic!("expected proposal")
        };
        assert_eq!(proposal.interval_seconds, 300);
        assert!(!proposal.immediate_reattest);
    }

    #[test]
    fn critical_risk_uses_shortest_admin_interval() {
        let result =
            attestation_recommendation_from_policy(&recommendation(0.96, 0.95), &templates())
                .unwrap();
        let AttestationProposalResult::Proposed(proposal) = result else {
            panic!("expected proposal")
        };
        assert_eq!(proposal.interval_seconds, 30);
        assert!(proposal.immediate_reattest);
    }

    #[test]
    fn low_risk_does_not_change_schedule() {
        let mut value = recommendation(0.93, 0.91);
        value.risk_level = RiskLevel::Low;
        let result = attestation_recommendation_from_policy(&value, &templates()).unwrap();
        assert!(matches!(
            result,
            AttestationProposalResult::NoProposal { .. }
        ));
    }

    #[test]
    fn out_of_bounds_attestation_configuration_is_rejected() {
        let mut invalid_templates = templates();
        let template = invalid_templates
            .templates
            .iter_mut()
            .find(|template| template.action == PolicyAction::IncreaseAttestationFrequency)
            .unwrap();
        template.critical_attestation_interval_seconds = Some(20); // min is 30
        assert!(invalid_templates.validate().is_err());
    }
}
