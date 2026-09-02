//! VS7: peer-specific, reversible quarantine proposals.

use serde::{Deserialize, Serialize};

use crate::policy::{PolicyAction, PolicyParameters, PolicyTemplates};

use super::super::{PolicyRecommendation, RiskLevel};

/// A temporary isolation request for one explicitly identified peer.
/// Later phases serialize this as a policy action; this module makes no local
/// network change and cannot guess a target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineRecommendation {
    pub policy_action: PolicyAction,
    pub target_peer: String,
    pub duration_seconds: u64,
    pub starts_at_ms: u64,
    pub expires_at_ms: u64,
    pub reversible: bool,
    pub advisory_only: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineProposalResult {
    Proposed(QuarantineRecommendation),
    NoProposal { reason: String },
}

/// Propose quarantine only for a Critical recommendation and an explicit peer
/// already attached to the validated event. This prevents the policy layer
/// from inferring an IP/node ID or isolating an unrelated device.
pub fn quarantine_recommendation_from_policy(
    recommendation: &PolicyRecommendation,
    target_peer: &str,
    templates: &PolicyTemplates,
) -> anyhow::Result<QuarantineProposalResult> {
    if recommendation.risk_level != RiskLevel::Critical {
        return Ok(QuarantineProposalResult::NoProposal {
            reason: "Quarantine is reserved for Critical risk after later owner approval.".into(),
        });
    }
    if target_peer.trim().is_empty() {
        return Ok(QuarantineProposalResult::NoProposal {
            reason: "Quarantine requires a non-empty explicit peer target.".into(),
        });
    }
    if !recommendation
        .affected_peers
        .iter()
        .any(|peer| peer == target_peer)
    {
        return Ok(QuarantineProposalResult::NoProposal {
            reason: "Quarantine target is not present in trusted affected-peer evidence.".into(),
        });
    }
    let template = templates
        .templates
        .iter()
        .find(|template| template.action == PolicyAction::QuarantinePeer)
        .ok_or_else(|| anyhow::anyhow!("admin quarantine template is missing"))?;
    if !template.enabled {
        return Ok(QuarantineProposalResult::NoProposal {
            reason: "Admin policy does not currently allow peer quarantine.".into(),
        });
    }
    let duration_seconds = template.default_duration_seconds.ok_or_else(|| {
        anyhow::anyhow!("admin quarantine template is missing a default duration")
    })?;
    let parameters = PolicyParameters {
        target: target_peer.to_string(),
        duration_seconds: Some(duration_seconds),
        firewall_mode: None,
        rate_limit_per_second: None,
        attestation_interval_seconds: None,
        logging_level: None,
    };
    templates.validate_parameters(PolicyAction::QuarantinePeer, &parameters)?;
    let starts_at_ms = recommendation.created_at_ms;
    Ok(QuarantineProposalResult::Proposed(QuarantineRecommendation {
        policy_action: PolicyAction::QuarantinePeer,
        target_peer: target_peer.to_string(),
        duration_seconds,
        starts_at_ms,
        expires_at_ms: starts_at_ms.saturating_add(duration_seconds.saturating_mul(1_000)),
        reversible: true,
        advisory_only: true,
        reason: "Critical risk: temporarily quarantine this explicitly evidenced peer; expiry restores normal connectivity unless a later approved policy changes it.".into(),
    }))
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

    fn critical_recommendation() -> PolicyRecommendation {
        recommendation_from_event(
            "vsr-quarantine",
            &AnomalyEvent {
                anomaly_id: "anom-quarantine".into(),
                source_node: "nodeA".into(),
                anomaly_type: AnomalyType::PeerAnomaly,
                score: 0.97,
                confidence: 0.96,
                severity: Severity::Critical,
                affected_peers: vec!["nodeC".into()],
                observed_at_ms: 1_000,
                evidence: vec![AnomalyEvidence {
                    feature: "relay_ratio".into(),
                }],
                reason: "test".into(),
                recommendation: "test".into(),
                proposed_action: None,
            },
        )
    }

    #[test]
    fn critical_explicit_peer_gets_reversible_bounded_proposal() {
        let result = quarantine_recommendation_from_policy(
            &critical_recommendation(),
            "nodeC",
            &templates(),
        )
        .unwrap();
        let QuarantineProposalResult::Proposed(proposal) = result else {
            panic!("expected proposal")
        };
        assert_eq!(proposal.target_peer, "nodeC");
        assert_eq!(proposal.duration_seconds, 900);
        assert_eq!(proposal.expires_at_ms, 901_000);
        assert!(proposal.reversible);
        assert!(proposal.advisory_only);
    }

    #[test]
    fn unknown_or_empty_peer_cannot_be_quarantined() {
        let recommendation = critical_recommendation();
        for peer in ["", "nodeB"] {
            let result =
                quarantine_recommendation_from_policy(&recommendation, peer, &templates()).unwrap();
            assert!(matches!(
                result,
                QuarantineProposalResult::NoProposal { .. }
            ));
        }
    }

    #[test]
    fn high_risk_cannot_propose_quarantine() {
        let mut recommendation = critical_recommendation();
        recommendation.risk_level = RiskLevel::High;
        let result =
            quarantine_recommendation_from_policy(&recommendation, "nodeC", &templates()).unwrap();
        assert!(matches!(
            result,
            QuarantineProposalResult::NoProposal { .. }
        ));
    }

    #[test]
    fn quarantine_proposal_is_serializable_and_keeps_its_reversible_expiry() {
        let result = quarantine_recommendation_from_policy(
            &critical_recommendation(),
            "nodeC",
            &templates(),
        )
        .unwrap();
        let QuarantineProposalResult::Proposed(input) = result else {
            panic!("expected proposal")
        };
        let json = serde_json::to_string(&input).unwrap();
        let output: QuarantineRecommendation = serde_json::from_str(&json).unwrap();
        assert_eq!(output, input);
        assert!(output.reversible);
        assert!(output.expires_at_ms > output.starts_at_ms);
    }
}
