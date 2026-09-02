//! Read an already-saved Task 1 recommendations.json and show the Task 2
//! decision flow by machine-readable action family.  It never runs Task 1.
//!
//! Example:
//! cargo run --example run_policy_recommendation_groups_demo -- \
//!   data/recommendation_records/nodeA/run_003/recommendations.json \
//!   --min-confidence 0.40 --cooldown-seconds 60 --trusted-peer nodeC

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use anyhow::Result;
use sgx_anomaly_engine::policy::PolicyTemplates;
use sgx_anomaly_engine::policy_candidate::read_task1_recommendations;
use sgx_anomaly_engine::virtual_shift::{
    aggregate_recommendations, anomaly_event_from_task1_record,
    attestation_recommendation_from_policy, firewall_recommendations_from_event,
    justification_from_aggregate, logging_recommendation_from_policy,
    quarantine_recommendation_from_policy, recommendation_from_event,
    task1_virtual_shift_handoff_record, AdminNetworkRuleTemplates, AttestationProposalResult,
    AttestationRecommendation, FirewallProposalResult, FirewallRecommendation,
    LoggingProposalResult, LoggingRecommendation, PolicyRecommendation, ProposalStageNote,
    QuarantineProposalResult, QuarantineRecommendation, RecommendedAction, ReviewQueue,
    ReviewRecord, Task1VirtualShiftHandoff, TriggerDecision, VirtualShiftTriggerConfig,
    VirtualShiftTriggerManager, VS01_TO_VS09_PROPOSALS, VS10_VS11_REVIEWS,
};

#[derive(Clone)]
struct RowOutcome {
    vs1: String,
    vs2: String,
    event: Option<sgx_anomaly_engine::virtual_shift::AnomalyEvent>,
    handoff: Option<Task1VirtualShiftHandoff>,
}

/// VS4-VS7 evaluation plus the exact JSON records written for senior review.
struct ProposalEvaluation {
    summary: Vec<(&'static str, String)>,
    recommendation: PolicyRecommendation,
    firewall_actions: Vec<FirewallRecommendation>,
    attestation_actions: Vec<AttestationRecommendation>,
    logging_actions: Vec<LoggingRecommendation>,
    quarantine_actions: Vec<QuarantineRecommendation>,
    network_policy_draft: serde_json::Value,
}

fn number_flag(args: &[String], flag: &str) -> Result<Option<f64>> {
    let Some(index) = args.iter().position(|value| value == flag) else {
        return Ok(None);
    };
    let raw = args
        .get(index + 1)
        .ok_or_else(|| anyhow::anyhow!("{flag} needs a value"))?;
    let value: f64 = raw
        .parse()
        .map_err(|_| anyhow::anyhow!("{flag} must be a number"))?;
    if !(0.0..=1.0).contains(&value) {
        anyhow::bail!("{flag} must be from 0 to 1");
    }
    Ok(Some(value))
}

fn seconds_flag(args: &[String], flag: &str) -> Result<Option<u64>> {
    let Some(index) = args.iter().position(|value| value == flag) else {
        return Ok(None);
    };
    let raw = args
        .get(index + 1)
        .ok_or_else(|| anyhow::anyhow!("{flag} needs a value"))?;
    let value = raw
        .parse()
        .map_err(|_| anyhow::anyhow!("{flag} must be a positive whole number"))?;
    if value == 0 {
        anyhow::bail!("{flag} must be greater than zero");
    }
    Ok(Some(value))
}

fn text_flag(args: &[String], flag: &str) -> Result<Option<String>> {
    let Some(index) = args.iter().position(|value| value == flag) else {
        return Ok(None);
    };
    let value = args
        .get(index + 1)
        .ok_or_else(|| anyhow::anyhow!("{flag} needs a value"))?
        .trim();
    if value.is_empty() {
        anyhow::bail!("{flag} must not be empty");
    }
    Ok(Some(value.to_owned()))
}

/// A Task 1 run directory (for example `run_006`) makes the downstream
/// Virtual Shift anomaly/recommendation ID unique across fresh runs while
/// preserving idempotency when the same saved JSON is replayed.
fn source_run_key(source: &str) -> String {
    Path::new(source)
        .parent()
        .and_then(Path::file_name)
        .and_then(|value| value.to_str())
        .filter(|value| {
            !value.is_empty()
                && value.chars().all(|character| {
                    character.is_ascii_alphanumeric() || character == '_' || character == '-'
                })
        })
        .unwrap_or("task1")
        .to_owned()
}

fn table_row(label: &str, value: &str) {
    println!("| {label:<22} | {value:<61} |");
}

fn compact(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let short: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{short}...")
    } else {
        short
    }
}

fn top() {
    println!("+------------------------+---------------------------------------------------------------+");
}

fn proposal_evaluation(
    event: &sgx_anomaly_engine::virtual_shift::AnomalyEvent,
    templates: &PolicyTemplates,
    network_templates: &AdminNetworkRuleTemplates,
    trusted_peer: Option<&str>,
) -> Result<ProposalEvaluation> {
    let policy = recommendation_from_event(
        format!("vsr-{}-{}", event.source_node, event.anomaly_id),
        event,
    );
    let actions = policy
        .candidate_actions
        .iter()
        .map(|action| format!("{action:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    let actions = if actions.is_empty() {
        "none (generic anomaly)".to_string()
    } else {
        actions
    };
    let mut results = vec![(
        "VS3",
        format!(
            "{:?} risk; Pending review; candidates: {actions}",
            policy.risk_level
        ),
    )];
    let (_firewall, firewall_actions) = match firewall_recommendations_from_event(event, templates)?
    {
        FirewallProposalResult::Proposed(values) => {
            let value = &values[0];
            results.push((
                "VS4",
                format!(
                    "{:?} {} for {} sec on {} peer(s)",
                    value.firewall_mode,
                    value.rate_limit_per_second,
                    value.duration_seconds,
                    values.len()
                ),
            ));
            (
                serde_json::json!({ "stage": "VS4", "status": "proposed", "proposals": values }),
                values,
            )
        }
        FirewallProposalResult::NoProposal { reason } => {
            results.push(("VS4", reason.clone()));
            (
                serde_json::json!({ "stage": "VS4", "status": "not_proposed", "reason": reason }),
                vec![],
            )
        }
    };
    let (_attestation, attestation_actions) = match attestation_recommendation_from_policy(
        &policy, templates,
    )? {
        AttestationProposalResult::Proposed(value) => {
            results.push((
                "VS5",
                format!(
                    "attest {} every {} sec",
                    value.target_node, value.interval_seconds
                ),
            ));
            (
                serde_json::json!({ "stage": "VS5", "status": "proposed", "proposal": value }),
                vec![value],
            )
        }
        AttestationProposalResult::NoProposal { reason } => {
            results.push(("VS5", reason.clone()));
            (
                serde_json::json!({ "stage": "VS5", "status": "not_proposed", "reason": reason }),
                vec![],
            )
        }
    };
    let (_logging, logging_actions) = match logging_recommendation_from_policy(&policy, templates)?
    {
        LoggingProposalResult::Proposed(value) => {
            results.push((
                "VS6",
                format!(
                    "{:?} logging for {} sec; scopes: {:?}",
                    value.logging_level, value.duration_seconds, value.scopes
                ),
            ));
            (
                serde_json::json!({ "stage": "VS6", "status": "proposed", "proposal": value }),
                vec![value],
            )
        }
        LoggingProposalResult::NoProposal { reason } => {
            results.push(("VS6", reason.clone()));
            (
                serde_json::json!({ "stage": "VS6", "status": "not_proposed", "reason": reason }),
                vec![],
            )
        }
    };
    let (_quarantine, quarantine_actions) = match trusted_peer {
        Some(peer) => match quarantine_recommendation_from_policy(&policy, peer, templates)? {
            QuarantineProposalResult::Proposed(value) => {
                results.push((
                    "VS7",
                    format!(
                        "quarantine {} for {} sec; reversible={}",
                        value.target_peer, value.duration_seconds, value.reversible
                    ),
                ));
                (
                    serde_json::json!({ "stage": "VS7", "status": "proposed", "proposal": value }),
                    vec![value],
                )
            }
            QuarantineProposalResult::NoProposal { reason } => {
                results.push(("VS7", reason.clone()));
                (
                    serde_json::json!({ "stage": "VS7", "status": "not_proposed", "reason": reason }),
                    vec![],
                )
            }
        },
        None => {
            results.push((
                "VS7",
                "No trusted affected peer supplied; quarantine is not evaluated.".into(),
            ));
            (
                serde_json::json!({ "stage": "VS7", "status": "not_proposed", "reason": "No trusted affected peer supplied; quarantine is not evaluated." }),
                vec![],
            )
        }
    };
    let network_policy_draft = if policy
        .candidate_actions
        .contains(&RecommendedAction::TightenFirewall)
    {
        let anomaly_type = match event.anomaly_type {
            sgx_anomaly_engine::virtual_shift::AnomalyType::ConnectionScan => "connection_scan",
            sgx_anomaly_engine::virtual_shift::AnomalyType::TrafficFlood => "traffic_flood",
            sgx_anomaly_engine::virtual_shift::AnomalyType::ProtocolViolation => {
                "protocol_violation"
            }
            sgx_anomaly_engine::virtual_shift::AnomalyType::ResourceExhaustion => {
                "resource_exhaustion"
            }
            sgx_anomaly_engine::virtual_shift::AnomalyType::PeerAnomaly => "peer_anomaly",
            sgx_anomaly_engine::virtual_shift::AnomalyType::Generic => "generic",
        };
        let suggested_rule_ids = network_templates.suggested_rule_ids(anomaly_type);
        // Freeze a small, human-readable preview in the pending review record.
        // The model only selects from owner-maintained templates; it never
        // invents IP ranges, protocols, or ports.  This lets the owner see the
        // exact proposed ALLOW/DENY rules *before* pressing Approve/Trigger.
        let proposed_rules = suggested_rule_ids
            .iter()
            .filter_map(|id| network_templates.rules.iter().find(|rule| &rule.id == id))
            .collect::<Vec<_>>();
        serde_json::json!({
            "status": if suggested_rule_ids.is_empty() { "manual_rule_required" } else { "pending_admin_review" },
            "suggested_action": "DENY_OR_RATE_LIMIT",
            "anomaly_type": anomaly_type,
            "suggested_rule_ids": suggested_rule_ids,
            "proposed_rules": proposed_rules,
            "suggested_target_peer": trusted_peer,
            "reason": "The system matched these owner-approved rules to the anomaly type. The owner reviews the exact rule preview and may approve, reject, or choose different approved templates.",
            "owner_options": ["select_approved_template", "enter_manual_rule", "reject_suggestion"],
            "auto_apply": false
        })
    } else {
        serde_json::json!({
            "status": "not_needed",
            "reason": "This anomaly is handled by non-network actions such as attestation or logging.",
            "auto_apply": false
        })
    };

    Ok(ProposalEvaluation {
        summary: results,
        recommendation: policy,
        firewall_actions,
        attestation_actions,
        logging_actions,
        quarantine_actions,
        network_policy_draft,
    })
}

fn write_json(path: &Path, value: &serde_json::Value) -> Result<()> {
    std::fs::write(path, serde_json::to_string_pretty(value)?)?;
    Ok(())
}

fn stage_notes(evaluation: &ProposalEvaluation) -> Vec<ProposalStageNote> {
    evaluation
        .summary
        .iter()
        .filter(|(stage, _)| matches!(*stage, "VS4" | "VS5" | "VS6" | "VS7"))
        .map(|(stage, result)| ProposalStageNote {
            stage: (*stage).to_owned(),
            result: result.clone(),
        })
        .collect()
}

fn save_proposal_evidence(
    evaluation: &ProposalEvaluation,
    source_task1_json: &str,
    source_rows: &[usize],
    gate_summary: serde_json::Value,
    issue8_handoff: &Task1VirtualShiftHandoff,
) -> Result<PathBuf> {
    let recommendation_id = &evaluation.recommendation.recommendation_id;
    if recommendation_id.trim().is_empty()
        || matches!(recommendation_id.as_str(), "." | "..")
        || recommendation_id.contains('/')
        || recommendation_id.contains('\\')
    {
        anyhow::bail!("recommendation_id must be a non-empty file-name-safe identifier");
    }
    let directory = Path::new("data/virtual_shift")
        .join(VS01_TO_VS09_PROPOSALS)
        .join(recommendation_id);
    std::fs::create_dir_all(&directory)?;
    let vs8 = aggregate_recommendations(
        &evaluation.recommendation,
        evaluation.firewall_actions.clone(),
        evaluation.attestation_actions.clone(),
        evaluation.logging_actions.clone(),
        evaluation.quarantine_actions.clone(),
    );
    let vs9 =
        justification_from_aggregate(&evaluation.recommendation, &vs8, stage_notes(evaluation))?;
    let output = directory.join("virtual_shift_proposal.json");
    write_json(
        &output,
        &serde_json::json!({
            "schema_version": 1,
            "review_summary": {
                "source_task1_recommendations_json": source_task1_json,
                "trigger_row": source_rows.first(),
                "grouped_anomaly_rows": source_rows.len(),
                "gate_result": gate_summary
            },
            "issue8_task1_to_virtual_shift_handoff": issue8_handoff,
            "policy_for_owner_approval": evaluation.network_policy_draft,
            "vs3": evaluation.recommendation,
            "vs8": vs8,
            "vs9": vs9,
            "advisory_only": true,
            "approval_status": "pending_review"
        }),
    )?;
    Ok(output)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let source = args.first().ok_or_else(|| anyhow::anyhow!(
        "usage: cargo run --example run_policy_recommendation_groups_demo -- <recommendations.json> [--min-confidence 0..1] [--cooldown-seconds N] [--trusted-peer <node-or-peer-id>] [--review-owner <node-id>]"
    ))?;
    let mut config = VirtualShiftTriggerConfig::default();
    if let Some(value) = number_flag(&args, "--min-confidence")? {
        config.min_confidence = value;
    }
    if let Some(seconds) = seconds_flag(&args, "--cooldown-seconds")? {
        config.cooldown_ms = seconds * 1_000;
    }
    let trusted_peer = text_flag(&args, "--trusted-peer")?;
    let review_owner = text_flag(&args, "--review-owner")?.unwrap_or_else(|| "nodeA".into());
    let affected_peers = trusted_peer.iter().cloned().collect::<Vec<_>>();

    let templates = PolicyTemplates::from_path("config/policy_action_templates.json")?;
    let network_templates =
        AdminNetworkRuleTemplates::from_path("config/admin_network_rule_templates.json")?;
    let review_queue = ReviewQueue::from_role_config(
        Path::new("data/virtual_shift").join(VS10_VS11_REVIEWS),
        "config/node_roles.json",
    )?;
    let task1 = read_task1_recommendations(source)?;
    let source_run = source_run_key(source);
    let mut trigger = VirtualShiftTriggerManager::new(config.clone())?;
    let mut outcomes = HashMap::new();

    // Process in Task 1's saved order so cooldown decisions are real sequence decisions.
    for record in task1
        .recommendations
        .iter()
        .filter(|record| record.decision == "ANOMALY")
    {
        let mut event =
            match anomaly_event_from_task1_record(&task1.node, record, affected_peers.clone()) {
                Ok(event) => event,
                Err(error) => {
                    outcomes.insert(
                        record.display_row,
                        RowOutcome {
                            vs1: format!("STOP - invalid saved event: {error}"),
                            vs2: "not evaluated".into(),
                            event: None,
                            handoff: None,
                        },
                    );
                    continue;
                }
            };
        event.anomaly_id = format!("{source_run}-{}", event.anomaly_id);
        let decision = trigger.consider(&event)?;
        let vs2 = match &decision {
            TriggerDecision::Triggered => "TRIGGERED".into(),
            TriggerDecision::BelowThreshold { .. } => "STOP - below score/confidence gate".into(),
            TriggerDecision::DuplicateAnomalyId => "STOP - duplicate anomaly ID".into(),
            TriggerDecision::Debounced { retry_after_ms } => {
                format!("WAIT - cooldown ({retry_after_ms} ms remaining)")
            }
        };
        let handoff = task1_virtual_shift_handoff_record(
            source,
            &event,
            record.display_row,
            &config,
            &decision,
        );
        outcomes.insert(
            record.display_row,
            RowOutcome {
                vs1: "VALID".into(),
                vs2,
                event: Some(event),
                handoff: Some(handoff),
            },
        );
    }

    let mut groups: BTreeMap<&str, Vec<_>> = BTreeMap::new();
    for record in &task1.recommendations {
        if record.decision == "ANOMALY" {
            if let Some(action) = &record.proposed_action {
                groups.entry(&action.kind).or_default().push(record);
            }
        }
    }

    println!("==========================================================================");
    println!("TASK 2 - DEMO 1: TASK 1 RESULTS TO OWNER REVIEW (VS1 TO VS11)");
    println!("==========================================================================");
    println!("\n1. ACTION GROUPS — same machine-action anomalies are reviewed together\n");
    // The old overview/gate headings are intentionally suppressed: per-group
    // counts below are the useful review information without duplicated noise.
    if false {
        println!("\n1. INPUT — saved Task 1 anomaly rows being checked");
        println!("\n2. VS2 GATE RESULT — why rows trigger, wait or stop");
        println!("\n3. ACTION GROUPS — same machine action rows are kept together\n");
    }

    for (number, (action, records)) in groups.iter().enumerate() {
        let rows: Vec<usize> = records.iter().map(|record| record.display_row).collect();
        let triggered: Vec<usize> = records
            .iter()
            .filter(|record| outcomes[&record.display_row].vs2 == "TRIGGERED")
            .map(|record| record.display_row)
            .collect();
        let waiting: Vec<usize> = records
            .iter()
            .filter(|record| outcomes[&record.display_row].vs2.starts_with("WAIT"))
            .map(|record| record.display_row)
            .collect();
        let stopped: Vec<usize> = records
            .iter()
            .filter(|record| outcomes[&record.display_row].vs2.starts_with("STOP"))
            .map(|record| record.display_row)
            .collect();

        let _row_decisions = records
            .iter()
            .map(|record| {
                let outcome = &outcomes[&record.display_row];
                serde_json::json!({
                    "task1_row": record.display_row,
                    "vs1": outcome.vs1,
                    "vs2": outcome.vs2,
                    "issue8_handoff_status": outcome.handoff.as_ref().map(|handoff| handoff.trigger_status.clone()),
                })
            })
            .collect::<Vec<_>>();

        println!("GROUP {} — SAME TASK 1 ACTION", number + 1);
        top();
        table_row("Machine action", action);
        table_row("Total anomaly rows", &records.len().to_string());
        // Detailed row gate counters remain in the evidence JSON only.
        if false {
            table_row(
                "VS2 triggered",
                &triggered.first().map_or_else(
                    || "0 row(s) — no proposal starts".to_string(),
                    |row| format!("1 row — Task 1 row {row}; score/confidence passed the gate"),
                ),
            );
            table_row(
                "VS2 wait",
                &format!("{} row(s) — same action inside cooldown", waiting.len()),
            );
            table_row(
                "VS2 stop",
                &format!(
                    "{} row(s) — duplicate or below score/confidence gate",
                    stopped.len()
                ),
            );
            table_row(
                "Row-level record",
                "saved in proposal JSON; not printed in terminal",
            );
        }
        table_row(
            "Review trigger",
            &triggered.first().map_or_else(
                || "No eligible row; no pending policy review was created.".to_string(),
                |row| format!("Task 1 row {row}; score and confidence passed the safety gate."),
            ),
        );
        table_row(
            "Other group rows",
            &format!(
                "{} saved as evidence; no duplicate review is created.",
                records.len().saturating_sub(triggered.len())
            ),
        );

        if let Some(first_row) = triggered.first() {
            let outcome = &outcomes[first_row];
            if outcome.handoff.is_some() {
                table_row(
                    "Issue 8 handoff",
                    "Task1 threshold crossing created a Virtual Shift trigger record.",
                );
            }
            if let Some(event) = &outcome.event {
                let evaluation = proposal_evaluation(
                    event,
                    &templates,
                    &network_templates,
                    trusted_peer.as_deref(),
                )?;
                // Demo 1 is intentionally a short group/gate summary. Full
                // policy fields are saved below and shown before trigger in Demo 2.
                if false {
                    // Full per-stage internals are retained in the proposal JSON.
                    if false {
                        for (stage, result) in &evaluation.summary {
                            table_row(stage, &result);
                        }
                    }
                    table_row(
                        "Risk level",
                        &format!("{:?}", evaluation.recommendation.risk_level),
                    );
                    table_row(
                        "Model evidence",
                        &format!(
                            "score {:.3}; confidence {:.0}%",
                            evaluation.recommendation.anomaly_score,
                            evaluation.recommendation.confidence * 100.0
                        ),
                    );
                    table_row(
                        "Detected pattern",
                        &format!("{:?}", evaluation.recommendation.anomaly_type),
                    );
                    table_row(
                        "Why review is needed",
                        &compact(&evaluation.recommendation.source_reason, 57),
                    );
                    table_row(
                        "Suggested response",
                        &compact(
                            &format!("{:?}", evaluation.recommendation.candidate_actions),
                            57,
                        ),
                    );
                    let draft_status = evaluation
                        .network_policy_draft
                        .get("status")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown");
                    let suggested_action = evaluation
                        .network_policy_draft
                        .get("suggested_action")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("none");
                    table_row(
                        "Network policy status",
                        &format!("{draft_status}; suggested action: {suggested_action}"),
                    );
                    if draft_status == "pending_admin_review" {
                        let suggested_rules = evaluation
                            .network_policy_draft
                            .get("suggested_rule_ids")
                            .and_then(serde_json::Value::as_array)
                            .map(|values| {
                                values
                                    .iter()
                                    .filter_map(serde_json::Value::as_str)
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            })
                            .unwrap_or_else(|| "none".into());
                        table_row("System-matched templates", &compact(&suggested_rules, 55));
                        if let Some(ids) = evaluation
                            .network_policy_draft
                            .get("suggested_rule_ids")
                            .and_then(serde_json::Value::as_array)
                        {
                            for id in ids.iter().filter_map(serde_json::Value::as_str) {
                                if let Some(rule) =
                                    network_templates.rules.iter().find(|rule| rule.id == id)
                                {
                                    table_row(
                                        "Rule preview",
                                        &format!(
                                            "{:?} {}:{} | {} -> {}",
                                            rule.action,
                                            rule.protocol,
                                            rule.port,
                                            rule.src,
                                            rule.dst
                                        ),
                                    );
                                    table_row("Why this rule", &compact(&rule.reason, 57));
                                }
                            }
                        }
                        table_row(
                            "Admin next step",
                            "Review these IP/port rules, then Trigger Policy or Reject.",
                        );
                    }
                    let aggregate = aggregate_recommendations(
                        &evaluation.recommendation,
                        evaluation.firewall_actions.clone(),
                        evaluation.attestation_actions.clone(),
                        evaluation.logging_actions.clone(),
                        evaluation.quarantine_actions.clone(),
                    );
                    table_row(
                        "Final safe actions",
                        &format!(
                            "{} final action(s); {} conflict/deduplication note(s)",
                            aggregate.actions.len(),
                            aggregate.conflict_resolution.len()
                        ),
                    );
                    let vs9 = justification_from_aggregate(
                        &evaluation.recommendation,
                        &aggregate,
                        stage_notes(&evaluation),
                    )?;
                    table_row(
                        "Evidence package",
                        &format!(
                            "{} evidence feature(s), {} action reason(s), {} bytes",
                            vs9.evidence_features.len(),
                            vs9.selected_action_reasons.len(),
                            vs9.encoded_bytes()?
                        ),
                    );
                }
                let gate_summary = serde_json::json!({
                    "triggered_rows": triggered.len(),
                    "waiting_rows": waiting.len(),
                    "stopped_rows": stopped.len(),
                    "trigger_row": triggered.first(),
                    "row_level_decisions": _row_decisions,
                });
                let issue8_handoff = outcome
                    .handoff
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("triggered row is missing Issue 8 handoff"))?;
                let evidence_file = save_proposal_evidence(
                    &evaluation,
                    source,
                    &rows,
                    gate_summary,
                    issue8_handoff,
                )?;
                table_row("Pending policy JSON", &evidence_file.display().to_string());
                let proposed_id = evaluation.recommendation.recommendation_id.clone();
                let review_path = Path::new("data/virtual_shift")
                    .join(VS10_VS11_REVIEWS)
                    .join(&proposed_id)
                    .join("review.json");
                let (review, queue_result) =
                    match review_queue.enqueue_from_proposal(&evidence_file) {
                        Ok(record) => (record, "new pending review saved"),
                        Err(_error) if review_path.is_file() => {
                            // Replaying an old Task 1 run must be safe.  A prior
                            // owner decision is evidence, not a reason to abort
                            // every other group in the demo.
                            let existing: ReviewRecord =
                                serde_json::from_str(&std::fs::read_to_string(&review_path)?)?;
                            (existing, "existing finalized review kept")
                        }
                        Err(error) => return Err(error),
                    };
                table_row("Recommendation ID", &review.recommendation_id);
                table_row(
                    "Review status",
                    &format!(
                        "{:?} for owner {}; {}",
                        review.status, review_owner, queue_result
                    ),
                );
            }
        }
        top();
        println!();
    }

    let pending = review_queue.list_pending(&review_owner)?;
    println!("\n2. OWNER REVIEW QUEUE — waiting for an explicit admin decision");
    top();
    table_row("Authorised owner", &review_owner);
    table_row("Pending policy reviews", &pending.len().to_string());
    table_row(
        "Admin decision",
        "Trigger Policy to approve, or Reject to stop this recommendation.",
    );
    top();
    // Legacy heading retained in source only; the concise queue above is the
    // user-facing demo output.
    if false {
        println!("\n4. OWNER REVIEW QUEUE — no policy is approved yet");
        top();
        table_row("Authorised owner", &review_owner);
        table_row("Pending review items", &pending.len().to_string());
        table_row(
            "Queue storage",
            "data/virtual_shift/02_OWNER_REVIEW_DECISIONS/<recommendation-id>/review.json",
        );
        top();
    }
    println!("\nRESULT: This demo creates Pending Review records only. An owner must explicitly Trigger Policy before any policy can be built or applied.");
    Ok(())
}
