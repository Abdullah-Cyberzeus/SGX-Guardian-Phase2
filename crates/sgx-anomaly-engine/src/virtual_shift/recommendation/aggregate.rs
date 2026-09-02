//! VS8: deterministic aggregation and conflict resolution for VS4-VS7.
//!
//! The aggregator never creates a new enforcement action. It receives only
//! already bounded advisory proposals and produces one canonically ordered
//! package for later owner review/signing phases.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::policy::{FirewallMode, LoggingLevel};

use super::{
    AttestationRecommendation, FirewallRecommendation, LoggingRecommendation, LoggingScope,
    PolicyRecommendation, QuarantineRecommendation,
};

/// One concrete advisory action after VS8 has removed duplicates and resolved
/// conflicts. `serde` tagging keeps JSON machine-readable and unambiguous.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action_type", content = "proposal", rename_all = "snake_case")]
pub enum AggregatedAction {
    Firewall(FirewallRecommendation),
    Attestation(AttestationRecommendation),
    Logging(LoggingRecommendation),
    Quarantine(QuarantineRecommendation),
}

/// The one reviewable action package produced by VS8 for a VS3
/// recommendation. It is still advisory and remains `pending_review`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatedRecommendation {
    pub recommendation_id: String,
    pub anomaly_id: String,
    pub source_node: String,
    pub actions: Vec<AggregatedAction>,
    pub advisory_only: bool,
    pub conflict_resolution: Vec<String>,
}

/// Merge VS4-VS7 output into one stable review package.
///
/// Resolution order is intentional and deterministic:
/// - identical actions collapse;
/// - for the same firewall target, an L4 block overrides a rate limit;
/// - a quarantine of a peer removes a firewall action for the same peer,
///   because quarantine is the stronger temporary isolation action;
/// - duplicate attestation chooses the shortest interval;
/// - duplicate logging combines scopes, uses detailed over basic and keeps
///   the longest bounded duration.
pub fn aggregate_recommendations(
    recommendation: &PolicyRecommendation,
    firewall: Vec<FirewallRecommendation>,
    attestation: Vec<AttestationRecommendation>,
    logging: Vec<LoggingRecommendation>,
    quarantine: Vec<QuarantineRecommendation>,
) -> AggregatedRecommendation {
    let mut resolutions = Vec::new();
    let quarantine = deduplicate_quarantine(quarantine, &mut resolutions);
    let quarantined: BTreeSet<_> = quarantine
        .iter()
        .map(|proposal| proposal.target_peer.clone())
        .collect();
    let firewall = deduplicate_firewall(firewall, &quarantined, &mut resolutions);
    let attestation = deduplicate_attestation(attestation, &mut resolutions);
    let logging = deduplicate_logging(logging, &mut resolutions);

    let mut actions = Vec::new();
    actions.extend(firewall.into_iter().map(AggregatedAction::Firewall));
    actions.extend(attestation.into_iter().map(AggregatedAction::Attestation));
    actions.extend(logging.into_iter().map(AggregatedAction::Logging));
    actions.extend(quarantine.into_iter().map(AggregatedAction::Quarantine));
    actions.sort_by_key(action_sort_key);

    AggregatedRecommendation {
        recommendation_id: recommendation.recommendation_id.clone(),
        anomaly_id: recommendation.anomaly_id.clone(),
        source_node: recommendation.source_node.clone(),
        actions,
        advisory_only: true,
        conflict_resolution: resolutions,
    }
}

fn deduplicate_firewall(
    input: Vec<FirewallRecommendation>,
    quarantined: &BTreeSet<String>,
    resolutions: &mut Vec<String>,
) -> Vec<FirewallRecommendation> {
    let mut output: Vec<FirewallRecommendation> = Vec::new();
    for proposal in input {
        if quarantined.contains(&proposal.target_peer) {
            resolutions.push(format!(
                "Firewall action for '{}' removed because quarantine is the stronger temporary isolation action.",
                proposal.target_peer
            ));
            continue;
        }
        if let Some(existing) = output.iter_mut().find(|value| {
            value.target_peer == proposal.target_peer
                && value.protocol == proposal.protocol
                && value.port == proposal.port
        }) {
            let existing_is_block = existing.firewall_mode == FirewallMode::Block;
            let incoming_is_block = proposal.firewall_mode == FirewallMode::Block;
            if incoming_is_block && !existing_is_block {
                *existing = proposal;
                resolutions.push("Firewall conflict resolved: block overrides rate_limit for the same target/context.".into());
            } else if existing_is_block && !incoming_is_block {
                resolutions.push("Duplicate firewall rate_limit removed because block already exists for the same target/context.".into());
            } else {
                existing.rate_limit_per_second = match (
                    existing.rate_limit_per_second,
                    proposal.rate_limit_per_second,
                ) {
                    (0, value) | (value, 0) => value,
                    (left, right) => left.min(right),
                };
                existing.duration_seconds =
                    existing.duration_seconds.max(proposal.duration_seconds);
                resolutions.push("Duplicate firewall action collapsed using the strictest rate and longest bounded duration.".into());
            }
        } else {
            output.push(proposal);
        }
    }
    output
}

fn deduplicate_attestation(
    input: Vec<AttestationRecommendation>,
    resolutions: &mut Vec<String>,
) -> Vec<AttestationRecommendation> {
    let mut output: Vec<AttestationRecommendation> = Vec::new();
    for proposal in input {
        if let Some(existing) = output
            .iter_mut()
            .find(|value| value.target_node == proposal.target_node)
        {
            existing.interval_seconds = existing.interval_seconds.min(proposal.interval_seconds);
            existing.immediate_reattest |= proposal.immediate_reattest;
            resolutions.push(
                "Duplicate attestation action collapsed using the shortest approved interval."
                    .into(),
            );
        } else {
            output.push(proposal);
        }
    }
    output
}

fn deduplicate_logging(
    input: Vec<LoggingRecommendation>,
    resolutions: &mut Vec<String>,
) -> Vec<LoggingRecommendation> {
    let mut output: Vec<LoggingRecommendation> = Vec::new();
    for proposal in input {
        if let Some(existing) = output
            .iter_mut()
            .find(|value| value.target_node == proposal.target_node)
        {
            if proposal.logging_level == LoggingLevel::Detailed {
                existing.logging_level = LoggingLevel::Detailed;
            }
            existing.duration_seconds = existing.duration_seconds.max(proposal.duration_seconds);
            existing.expires_at_ms = existing.expires_at_ms.max(proposal.expires_at_ms);
            let mut scopes = existing.scopes.clone();
            for scope in proposal.scopes {
                if !scopes.contains(&scope) {
                    scopes.push(scope);
                }
            }
            scopes.sort_by_key(scope_sort_key);
            existing.scopes = scopes;
            resolutions.push("Duplicate logging action collapsed using detailed level, merged scopes and longest bounded duration.".into());
        } else {
            output.push(proposal);
        }
    }
    output
}

fn deduplicate_quarantine(
    input: Vec<QuarantineRecommendation>,
    resolutions: &mut Vec<String>,
) -> Vec<QuarantineRecommendation> {
    let mut output: Vec<QuarantineRecommendation> = Vec::new();
    for proposal in input {
        if let Some(existing) = output
            .iter_mut()
            .find(|value| value.target_peer == proposal.target_peer)
        {
            existing.duration_seconds = existing.duration_seconds.max(proposal.duration_seconds);
            existing.expires_at_ms = existing.expires_at_ms.max(proposal.expires_at_ms);
            resolutions.push(
                "Duplicate quarantine action collapsed using the longest bounded expiry.".into(),
            );
        } else {
            output.push(proposal);
        }
    }
    output
}

fn action_sort_key(action: &AggregatedAction) -> (u8, String, u16) {
    match action {
        AggregatedAction::Firewall(value) => {
            (0, value.target_peer.clone(), value.port.unwrap_or(0))
        }
        AggregatedAction::Attestation(value) => (1, value.target_node.clone(), 0),
        AggregatedAction::Logging(value) => (2, value.target_node.clone(), 0),
        AggregatedAction::Quarantine(value) => (3, value.target_peer.clone(), 0),
    }
}

fn scope_sort_key(scope: &LoggingScope) -> u8 {
    match scope {
        LoggingScope::SecurityEvents => 0,
        LoggingScope::NetworkFlowMetadata => 1,
        LoggingScope::ProtocolViolationDetails => 2,
        LoggingScope::ResourceMetrics => 3,
        LoggingScope::PeerInteractionMetadata => 4,
        LoggingScope::PolicyEnforcementResults => 5,
    }
}

#[cfg(test)]
mod tests {
    use crate::alert::Severity;
    use crate::policy::{FirewallMode, LoggingLevel, PolicyAction};
    use crate::virtual_shift::{
        recommendation_from_event, AnomalyEvent, AnomalyEvidence, AnomalyType, PolicyRecommendation,
    };

    use super::*;

    fn recommendation() -> PolicyRecommendation {
        recommendation_from_event(
            "vsr-aggregate-001",
            &AnomalyEvent {
                anomaly_id: "anom-aggregate-001".into(),
                source_node: "nodeA".into(),
                anomaly_type: AnomalyType::TrafficFlood,
                score: 0.97,
                confidence: 0.96,
                severity: Severity::Critical,
                affected_peers: vec!["nodeC".into()],
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

    fn firewall(mode: FirewallMode, rate: u32) -> FirewallRecommendation {
        FirewallRecommendation {
            policy_action: PolicyAction::TightenFirewall,
            target_peer: "nodeC".into(),
            firewall_mode: mode,
            protocol: Some("tcp".into()),
            port: Some(443),
            rate_limit_per_second: rate,
            duration_seconds: 300,
            advisory_only: true,
            reason: "test".into(),
        }
    }

    #[test]
    fn duplicate_firewall_actions_collapse_and_block_wins() {
        let output = aggregate_recommendations(
            &recommendation(),
            vec![
                firewall(FirewallMode::RateLimit, 20),
                firewall(FirewallMode::Block, 0),
            ],
            vec![],
            vec![],
            vec![],
        );
        assert_eq!(output.actions.len(), 1);
        assert!(matches!(
            &output.actions[0],
            AggregatedAction::Firewall(value) if value.firewall_mode == FirewallMode::Block
        ));
    }

    #[test]
    fn quarantine_removes_firewall_for_the_same_peer() {
        let quarantine = QuarantineRecommendation {
            policy_action: PolicyAction::QuarantinePeer,
            target_peer: "nodeC".into(),
            duration_seconds: 900,
            starts_at_ms: 1_000,
            expires_at_ms: 901_000,
            reversible: true,
            advisory_only: true,
            reason: "test".into(),
        };
        let output = aggregate_recommendations(
            &recommendation(),
            vec![firewall(FirewallMode::RateLimit, 20)],
            vec![],
            vec![],
            vec![quarantine],
        );
        assert_eq!(output.actions.len(), 1);
        assert!(matches!(output.actions[0], AggregatedAction::Quarantine(_)));
    }

    #[test]
    fn order_is_stable_and_duplicate_logging_is_merged() {
        let logging = |level, scopes, duration| LoggingRecommendation {
            policy_action: PolicyAction::EnableAdditionalLogging,
            target_node: "nodeA".into(),
            logging_level: level,
            scopes,
            duration_seconds: duration,
            starts_at_ms: 1_000,
            expires_at_ms: 1_000 + duration * 1_000,
            advisory_only: true,
            reason: "test".into(),
        };
        let first = aggregate_recommendations(
            &recommendation(),
            vec![firewall(FirewallMode::RateLimit, 20)],
            vec![],
            vec![
                logging(LoggingLevel::Basic, vec![LoggingScope::SecurityEvents], 300),
                logging(
                    LoggingLevel::Detailed,
                    vec![LoggingScope::NetworkFlowMetadata],
                    900,
                ),
            ],
            vec![],
        );
        let second = aggregate_recommendations(
            &recommendation(),
            vec![firewall(FirewallMode::RateLimit, 20)],
            vec![],
            vec![
                logging(
                    LoggingLevel::Detailed,
                    vec![LoggingScope::NetworkFlowMetadata],
                    900,
                ),
                logging(LoggingLevel::Basic, vec![LoggingScope::SecurityEvents], 300),
            ],
            vec![],
        );
        assert_eq!(first.actions, second.actions);
        assert!(matches!(first.actions[0], AggregatedAction::Firewall(_)));
        assert!(matches!(first.actions[1], AggregatedAction::Logging(_)));
        assert_eq!(first.actions.len(), 2);
    }
}
