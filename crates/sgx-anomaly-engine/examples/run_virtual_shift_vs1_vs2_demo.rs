//! Combined VS1 through VS6 demo.
//!
//! Run from sgx-anomaly-engine:
//! cargo run --example run_virtual_shift_vs1_vs2_demo

use sgx_anomaly_engine::alert::{AlertTier, AnomalyAlert, Severity};
use sgx_anomaly_engine::policy::PolicyTemplates;
use sgx_anomaly_engine::roles::NodeRole;
use sgx_anomaly_engine::rules::ActionDefinition;
use sgx_anomaly_engine::virtual_shift::{
    anomaly_event_from_alert, attestation_recommendation_from_policy,
    firewall_recommendations_from_event, logging_recommendation_from_policy,
    quarantine_recommendation_from_policy, recommendation_from_event, AttestationProposalResult,
    FirewallProposalResult, LoggingProposalResult, QuarantineProposalResult, TriggerDecision,
    VirtualShiftTriggerConfig, VirtualShiftTriggerManager,
};

fn task1_alert(timestamp: u64, score: f64, confidence: f64) -> AnomalyAlert {
    AnomalyAlert {
        ts: timestamp,
        node: "nodeA".into(),
        role: NodeRole::Member,
        score,
        confidence,
        severity: Severity::High,
        topk: vec!["conn_rate".into(), "net_rx_pkts_rate".into()],
        reason: "connection activity is unusually high".into(),
        recommendation:
            "Review the source peer and temporarily rate-limit new connections if unexpected."
                .into(),
        action: Some(ActionDefinition {
            kind: "rate_limit_peer".into(),
            params: serde_json::json!({}),
        }),
        tier: AlertTier::Tier2,
    }
}

fn show_case(
    trigger: &mut VirtualShiftTriggerManager,
    templates: &PolicyTemplates,
    anomaly_id: &str,
    alert: AnomalyAlert,
    trusted_peers: &[&str],
    title: &str,
) -> anyhow::Result<()> {
    println!("------------------------------------------------------------");
    println!("{title}");
    println!(
        "  Task 1: node={}, score={:.2}, confidence={:.0}%",
        alert.node,
        alert.score,
        alert.confidence * 100.0
    );

    let event = anomaly_event_from_alert(
        anomaly_id,
        &alert,
        trusted_peers
            .iter()
            .map(|peer| (*peer).to_string())
            .collect(),
    )?;
    println!("  VS1   : valid event created (type=connection_scan)");
    println!("          checked node, time, score, confidence and locked-feature evidence");

    match trigger.consider(&event)? {
        TriggerDecision::Triggered => {
            println!("  VS2   : TRIGGERED - event is allowed to continue");
            println!("          reason: score/confidence passed and this is not a duplicate/cooldown event");
            let recommendation = recommendation_from_event(format!("vsr-{anomaly_id}"), &event);
            println!(
                "  VS3   : PENDING REVIEW - risk={:?}, Task 1 action={}",
                recommendation.risk_level,
                recommendation
                    .source_action
                    .as_ref()
                    .map(|action| action.kind.as_str())
                    .unwrap_or("none")
            );
            println!("          meaning: admin review record is ready; nothing is enforced yet");
            match logging_recommendation_from_policy(&recommendation, templates)? {
                LoggingProposalResult::Proposed(proposal) => println!(
                    "  VS6   : ADVISORY logging proposal - node={}, level={:?}, {} sec, expires at {} ms",
                    proposal.target_node,
                    proposal.logging_level,
                    proposal.duration_seconds,
                    proposal.expires_at_ms
                ),
                LoggingProposalResult::NoProposal { reason } => {
                    println!("  VS6   : NO logging proposal - {reason}");
                }
            }
            match trusted_peers.first() {
                Some(peer) => match quarantine_recommendation_from_policy(
                    &recommendation,
                    peer,
                    templates,
                )? {
                    QuarantineProposalResult::Proposed(proposal) => println!(
                        "  VS7   : ADVISORY quarantine proposal - peer={}, {} sec, reversible={}, expires at {} ms",
                        proposal.target_peer,
                        proposal.duration_seconds,
                        proposal.reversible,
                        proposal.expires_at_ms
                    ),
                    QuarantineProposalResult::NoProposal { reason } => {
                        println!("  VS7   : NO quarantine proposal - {reason}");
                    }
                },
                None => println!(
                    "  VS7   : NO quarantine proposal - no trusted affected peer was supplied"
                ),
            }
            match attestation_recommendation_from_policy(&recommendation, templates)? {
                AttestationProposalResult::Proposed(proposal) => println!(
                    "  VS5   : ADVISORY attestation proposal - node={}, every {} sec, immediate re-attest={}",
                    proposal.target_node,
                    proposal.interval_seconds,
                    proposal.immediate_reattest
                ),
                AttestationProposalResult::NoProposal { reason } => {
                    println!("  VS5   : NO attestation proposal - {reason}");
                }
            }
            match firewall_recommendations_from_event(&event, templates)? {
                FirewallProposalResult::Proposed(proposals) => {
                    for proposal in proposals {
                        println!(
                            "  VS4   : ADVISORY firewall proposal - peer={}, rate limit={} conn/sec for {} sec",
                            proposal.target_peer,
                            proposal.rate_limit_per_second,
                            proposal.duration_seconds
                        );
                        println!("          source: trusted peer context; admin approval is still required");
                    }
                }
                FirewallProposalResult::NoProposal { reason } => {
                    println!("  VS4   : NO firewall proposal - {reason}");
                }
            }
        }
        TriggerDecision::BelowThreshold {
            min_score,
            min_confidence,
        } => println!(
            "  VS2   : STOP — needs score >= {:.2} and confidence >= {:.0}%",
            min_score,
            min_confidence * 100.0
        ),
        TriggerDecision::DuplicateAnomalyId => {
            println!("  VS2   : STOP — same anomaly ID was already processed")
        }
        TriggerDecision::Debounced { retry_after_ms } => println!(
            "  VS2   : WAIT — same node/type is in cooldown; retry after {} sec",
            retry_after_ms / 1_000
        ),
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    println!("============================================================");
    println!("VIRTUAL SHIFT DEMO — VS1 TO VS7");
    println!("============================================================");
    println!("VS2 demo limits: score >= 0.85, confidence >= 80%, cooldown = 60 sec\n");
    println!("VS1 = Is Task 1 alert data valid?");
    println!("VS2 = Is it strong, new and outside cooldown?");
    println!("VS3 = If allowed, what risk level and review record should be made?\n");
    println!("VS4 = If a trusted peer is available, make a bounded advisory firewall proposal.\n");
    println!("VS5 = For higher risk, propose faster attestation; it is still not applied.");
    println!(
        "VS6 = For higher risk, propose focused temporary logging; it is still not applied.\n"
    );
    println!("VS7 = Only Critical risk plus an explicit trusted peer can request temporary quarantine.\n");

    let mut trigger = VirtualShiftTriggerManager::new(VirtualShiftTriggerConfig {
        min_score: 0.85,
        min_confidence: 0.80,
        cooldown_ms: 60_000,
    })?;
    let templates = PolicyTemplates::from_path("config/policy_action_templates.json")?;

    show_case(
        &mut trigger,
        &templates,
        "anom-nodeA-001",
        task1_alert(100_000, 0.93, 0.91),
        &["peer-nodeC"],
        "CASE 1 — High-risk valid anomaly",
    )?;
    show_case(
        &mut trigger,
        &templates,
        "anom-nodeA-001",
        task1_alert(100_000, 0.93, 0.91),
        &["peer-nodeC"],
        "CASE 2 — Exact same alert delivered again",
    )?;
    show_case(
        &mut trigger,
        &templates,
        "anom-nodeA-002",
        task1_alert(120_000, 0.70, 0.95),
        &[],
        "CASE 3 — Valid data but low anomaly score",
    )?;
    show_case(
        &mut trigger,
        &templates,
        "anom-nodeA-003",
        task1_alert(130_000, 0.95, 0.92),
        &[],
        "CASE 4 — New high anomaly inside cooldown",
    )?;
    show_case(
        &mut trigger,
        &templates,
        "anom-nodeA-004",
        task1_alert(160_000, 0.95, 0.92),
        &["peer-nodeC"],
        "CASE 5 — New high anomaly after cooldown",
    )?;

    println!("\nRESULT: VS1 validates input; VS2 filters weak/repeated events;");
    println!("VS3 creates a PENDING REVIEW record; VS4/VS5/VS6/VS7 make advisory proposals.");
    println!("No policy is applied here.");
    Ok(())
}
