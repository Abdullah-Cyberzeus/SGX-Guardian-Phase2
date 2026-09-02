//! VS4: bounded, advisory firewall proposals.
//!
//! The generator does not guess IP addresses, ports or protocols from anomaly
//! telemetry. It creates peer-scoped temporary rate-limit proposals only when
//! a trusted affected-peer identifier is present and the admin template allows
//! it. Exact L4 port blocks require a later trusted security-context input.

use serde::{Deserialize, Serialize};

use crate::policy::{FirewallMode, PolicyAction, PolicyParameters, PolicyTemplates};

use crate::virtual_shift::{AnomalyEvent, AnomalyType};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallRecommendation {
    pub policy_action: PolicyAction,
    pub target_peer: String,
    pub firewall_mode: FirewallMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub rate_limit_per_second: u32,
    pub duration_seconds: u64,
    /// Always true in VS4: this is not an active firewall change.
    pub advisory_only: bool,
    pub reason: String,
}

/// Correlated L4 facts from a trusted security source. Telemetry scores never
/// invent these values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedFirewallContext {
    pub target_peer: String,
    pub protocol: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallProposalResult {
    Proposed(Vec<FirewallRecommendation>),
    NoProposal { reason: String },
}

/// Create bounded peer-scoped firewall proposals from a triggered event.
///
/// The result is advisory only. The existing admin policy template validates
/// every duration/rate bound and still requires owner approval later.
pub fn firewall_recommendations_from_event(
    event: &AnomalyEvent,
    templates: &PolicyTemplates,
) -> anyhow::Result<FirewallProposalResult> {
    let relevant_type = matches!(
        event.anomaly_type,
        AnomalyType::ConnectionScan | AnomalyType::TrafficFlood
    );
    if !relevant_type {
        return Ok(FirewallProposalResult::NoProposal {
            reason: "This anomaly type has no bounded firewall proposal in VS4.".into(),
        });
    }
    if event.affected_peers.is_empty() {
        return Ok(FirewallProposalResult::NoProposal {
            reason: "No trusted peer/IP target is attached to this anomaly; VS4 will not guess a firewall target.".into(),
        });
    }

    let template = templates
        .templates
        .iter()
        .find(|template| template.action == PolicyAction::TightenFirewall)
        .ok_or_else(|| anyhow::anyhow!("admin firewall template is missing"))?;
    if !template.enabled
        || !template
            .allowed_firewall_modes
            .contains(&FirewallMode::RateLimit)
    {
        return Ok(FirewallProposalResult::NoProposal {
            reason: "Admin policy does not currently allow temporary firewall rate limiting."
                .into(),
        });
    }
    let rate_limit_per_second = template.default_rate_limit_per_second.ok_or_else(|| {
        anyhow::anyhow!("admin firewall template must define default_rate_limit_per_second")
    })?;
    let duration_seconds = template.default_duration_seconds.ok_or_else(|| {
        anyhow::anyhow!("admin firewall template must define default_duration_seconds")
    })?;

    let reason = match event.anomaly_type {
        AnomalyType::TrafficFlood => {
            "Traffic-flood evidence supports a temporary, peer-scoped rate limit.".to_string()
        }
        _ => "Connection-scan evidence supports a temporary, peer-scoped rate limit.".to_string(),
    };

    let mut proposals = Vec::with_capacity(event.affected_peers.len());
    for peer in &event.affected_peers {
        let parameters = PolicyParameters {
            target: peer.clone(),
            duration_seconds: Some(duration_seconds),
            firewall_mode: Some(FirewallMode::RateLimit),
            rate_limit_per_second: Some(rate_limit_per_second),
            attestation_interval_seconds: None,
            logging_level: None,
        };
        templates.validate_parameters(PolicyAction::TightenFirewall, &parameters)?;
        proposals.push(FirewallRecommendation {
            policy_action: PolicyAction::TightenFirewall,
            target_peer: peer.clone(),
            firewall_mode: FirewallMode::RateLimit,
            protocol: None,
            port: None,
            rate_limit_per_second,
            duration_seconds,
            advisory_only: true,
            reason: reason.clone(),
        });
    }
    Ok(FirewallProposalResult::Proposed(proposals))
}

/// Build a bounded L4 block proposal only for a protocol violation with a
/// trusted, anomaly-bound protocol/port context. Other supported network
/// types continue through the peer-scoped rate-limit path above.
pub fn firewall_recommendations_with_context(
    event: &AnomalyEvent,
    templates: &PolicyTemplates,
    trusted_context: Option<&TrustedFirewallContext>,
) -> anyhow::Result<FirewallProposalResult> {
    if event.anomaly_type != AnomalyType::ProtocolViolation {
        return firewall_recommendations_from_event(event, templates);
    }
    let Some(context) = trusted_context else {
        return Ok(FirewallProposalResult::NoProposal {
            reason: "Protocol violation needs trusted protocol/port context; VS4 will not guess an L4 port to block.".into(),
        });
    };
    let protocol = context.protocol.trim().to_ascii_lowercase();
    if !matches!(protocol.as_str(), "tcp" | "udp") || context.port == 0 {
        return Ok(FirewallProposalResult::NoProposal {
            reason: "Trusted firewall context has an unsupported protocol or invalid port.".into(),
        });
    }
    if !event
        .affected_peers
        .iter()
        .any(|peer| peer == &context.target_peer)
    {
        return Ok(FirewallProposalResult::NoProposal {
            reason: "Trusted firewall target is not bound to this anomaly's affected peer list."
                .into(),
        });
    }
    let template = templates
        .templates
        .iter()
        .find(|template| template.action == PolicyAction::TightenFirewall)
        .ok_or_else(|| anyhow::anyhow!("admin firewall template is missing"))?;
    if !template.enabled
        || !template
            .allowed_firewall_modes
            .contains(&FirewallMode::Block)
    {
        return Ok(FirewallProposalResult::NoProposal {
            reason: "Admin policy does not currently allow a temporary firewall block.".into(),
        });
    }
    let duration_seconds = template.default_duration_seconds.ok_or_else(|| {
        anyhow::anyhow!("admin firewall template must define default_duration_seconds")
    })?;
    let parameters = PolicyParameters {
        target: context.target_peer.clone(),
        duration_seconds: Some(duration_seconds),
        firewall_mode: Some(FirewallMode::Block),
        rate_limit_per_second: None,
        attestation_interval_seconds: None,
        logging_level: None,
    };
    templates.validate_parameters(PolicyAction::TightenFirewall, &parameters)?;
    Ok(FirewallProposalResult::Proposed(vec![
        FirewallRecommendation {
            policy_action: PolicyAction::TightenFirewall,
            target_peer: context.target_peer.clone(),
            firewall_mode: FirewallMode::Block,
            protocol: Some(protocol),
            port: Some(context.port),
            rate_limit_per_second: 0,
            duration_seconds,
            advisory_only: true,
            reason:
                "Trusted protocol-violation context supports a temporary, peer-scoped L4 block."
                    .into(),
        },
    ]))
}

#[cfg(test)]
mod tests {
    use crate::alert::Severity;
    use crate::rules::ActionDefinition;
    use crate::virtual_shift::{AnomalyEvidence, AnomalyType};

    use super::*;

    fn event(peers: Vec<&str>, anomaly_type: AnomalyType) -> AnomalyEvent {
        AnomalyEvent {
            anomaly_id: "anom-fw-001".into(),
            source_node: "nodeA".into(),
            anomaly_type,
            score: 0.93,
            confidence: 0.91,
            severity: Severity::High,
            affected_peers: peers.into_iter().map(str::to_string).collect(),
            observed_at_ms: 1_000,
            evidence: vec![AnomalyEvidence {
                feature: "conn_rate".into(),
            }],
            reason: "test".into(),
            recommendation: "test".into(),
            proposed_action: Some(ActionDefinition {
                kind: "rate_limit_peer".into(),
                params: serde_json::json!({}),
            }),
        }
    }

    fn templates() -> PolicyTemplates {
        PolicyTemplates::from_path("config/policy_action_templates.json").unwrap()
    }

    #[test]
    fn trusted_peer_gets_a_bounded_advisory_rate_limit() {
        let result = firewall_recommendations_from_event(
            &event(vec!["peer-nodeC"], AnomalyType::ConnectionScan),
            &templates(),
        )
        .unwrap();
        let FirewallProposalResult::Proposed(proposals) = result else {
            panic!("expected proposal")
        };
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].target_peer, "peer-nodeC");
        assert_eq!(proposals[0].rate_limit_per_second, 20);
        assert_eq!(proposals[0].duration_seconds, 300);
        assert!(proposals[0].advisory_only);
    }

    #[test]
    fn unknown_target_does_not_create_a_firewall_rule() {
        let result = firewall_recommendations_from_event(
            &event(vec![], AnomalyType::ConnectionScan),
            &templates(),
        )
        .unwrap();
        assert!(matches!(result, FirewallProposalResult::NoProposal { .. }));
    }

    #[test]
    fn unsupported_type_does_not_generate_a_default_drop_rule() {
        let result = firewall_recommendations_from_event(
            &event(vec!["peer-nodeC"], AnomalyType::ResourceExhaustion),
            &templates(),
        )
        .unwrap();
        assert!(matches!(result, FirewallProposalResult::NoProposal { .. }));
    }

    #[test]
    fn trusted_protocol_port_context_can_propose_a_bounded_l4_block() {
        let result = firewall_recommendations_with_context(
            &event(vec!["peer-nodeC"], AnomalyType::ProtocolViolation),
            &templates(),
            Some(&TrustedFirewallContext {
                target_peer: "peer-nodeC".into(),
                protocol: "tcp".into(),
                port: 445,
            }),
        )
        .unwrap();
        let FirewallProposalResult::Proposed(proposals) = result else {
            panic!("expected L4 proposal")
        };
        assert_eq!(proposals[0].firewall_mode, FirewallMode::Block);
        assert_eq!(proposals[0].protocol.as_deref(), Some("tcp"));
        assert_eq!(proposals[0].port, Some(445));
        assert_eq!(proposals[0].duration_seconds, 300);
    }

    #[test]
    fn same_trusted_input_produces_the_same_bounded_firewall_proposal() {
        let event = event(vec!["peer-nodeC"], AnomalyType::TrafficFlood);
        let first = firewall_recommendations_from_event(&event, &templates()).unwrap();
        let second = firewall_recommendations_from_event(&event, &templates()).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn malformed_l4_context_fails_closed_without_a_block() {
        let result = firewall_recommendations_with_context(
            &event(vec!["peer-nodeC"], AnomalyType::ProtocolViolation),
            &templates(),
            Some(&TrustedFirewallContext {
                target_peer: "peer-nodeC".into(),
                protocol: "icmp".into(),
                port: 0,
            }),
        )
        .unwrap();
        assert!(matches!(result, FirewallProposalResult::NoProposal { .. }));
    }
}
