use crate::advisory::AnomalyScoringRuntime;
use crate::metrics::Metrics;
use crate::task1_ai::baseline::{baseline_config_path, Task1RuntimeTracker};
use crate::task1_ai::telemetry::SgxTelemetrySource;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sgx_anomaly_engine::alert::{AlertSink, AlertTier, AnomalyAlert, Severity as MlSeverity};
use sgx_anomaly_engine::engine::AnomalyEngine;
use sgx_anomaly_engine::policy::PolicyTemplates;
use sgx_anomaly_engine::roles::{NodeRole, RoleRegistry};
use sgx_anomaly_engine::rules::{ActionDefinition, PatternRule, RuleFile};
use sgx_anomaly_engine::virtual_shift::{
    aggregate_recommendations, anomaly_event_from_alert, attestation_recommendation_from_policy,
    firewall_recommendations_from_event, justification_from_aggregate,
    logging_recommendation_from_policy, quarantine_recommendation_from_policy,
    recommendation_from_event, task1_virtual_shift_handoff_record, AdminNetworkRuleTemplates,
    AttestationProposalResult, FirewallProposalResult, LoggingProposalResult, ProposalStageNote,
    QuarantineProposalResult, RecommendedAction, ReviewQueue, Task1VirtualShiftHandoff,
    TriggerDecision, VirtualShiftTriggerConfig, VirtualShiftTriggerManager, VS01_TO_VS09_PROPOSALS,
    VS10_VS11_REVIEWS,
};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};

const FULL_ML_ALERTS_FILE: &str = "task1_full_ml_alerts.jsonl";
const FULL_ML_HANDOFFS_FILE: &str = "task1_virtual_shift_handoffs.jsonl";
const MODELS_DIR: &str = "task1_models";
const VIRTUAL_SHIFT_DIR: &str = "virtual_shift";
const VIRTUAL_SHIFT_CONFIG_DIR: &str = "config";

const GLOBAL_MODEL_JSON: &str =
    include_str!("../../crates/sgx-anomaly-engine/data/global_forest.json");
const NODE_A_MODEL_JSON: &str =
    include_str!("../../crates/sgx-anomaly-engine/data/nodeA_forest.json");
const NODE_B_MODEL_JSON: &str =
    include_str!("../../crates/sgx-anomaly-engine/data/nodeB_forest.json");
const POLICY_ACTION_TEMPLATES_JSON: &str =
    include_str!("../../crates/sgx-anomaly-engine/config/policy_action_templates.json");
const ADMIN_NETWORK_RULE_TEMPLATES_JSON: &str =
    include_str!("../../crates/sgx-anomaly-engine/config/admin_network_rule_templates.json");
const NODE_ROLES_JSON: &str =
    include_str!("../../crates/sgx-anomaly-engine/config/node_roles.json");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Task1AdvisoryConfidence {
    pub value: f64,
    pub basis: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Task1FullMlAlertRecord {
    pub ts: u64,
    pub node: String,
    pub role: NodeRole,
    pub score: f64,
    pub model_confidence: f64,
    pub advisory_confidence: Task1AdvisoryConfidence,
    pub severity: MlSeverity,
    pub topk: Vec<String>,
    pub reason: String,
    pub recommendation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<ActionDefinition>,
    pub tier: AlertTier,
    pub runtime: AnomalyScoringRuntime,
}

pub fn spawn_full_ml_runtime(
    node_id: String,
    metrics: Arc<Mutex<Metrics>>,
    state_dir: PathBuf,
) -> Result<()> {
    std::fs::create_dir_all(&state_dir)?;
    let config_path = install_runtime_assets(&state_dir)?;

    let tracker = Task1RuntimeTracker::for_state_dir(&node_id, &state_dir);
    tracker
        .persist_full_ml_runtime()?
        .ok_or_else(|| anyhow!("full ML runtime could not be initialized for '{}'", node_id))?;

    let sink = Arc::new(SgxTask1AlertSink::new(&node_id, state_dir.clone()));
    let source = Box::new(SgxTelemetrySource::new(metrics));
    let config_str = config_path
        .to_str()
        .ok_or_else(|| anyhow!("baseline config path is not valid UTF-8"))?;
    let mut engine = AnomalyEngine::new(node_id.clone(), source, sink)
        .try_with_baseline_lifecycle(config_str)?;

    tokio::spawn(async move {
        engine.run().await;
    });

    tokio::spawn(async move {
        sync_runtime_status(node_id, state_dir).await;
    });

    Ok(())
}

pub fn load_recent_full_ml_alerts(
    state_dir: impl AsRef<Path>,
    limit: usize,
) -> Result<Vec<Task1FullMlAlertRecord>> {
    let path = full_ml_alerts_path(state_dir);
    if !path.exists() {
        return Ok(Vec::new());
    }

    let text = std::fs::read_to_string(path)?;
    let mut alerts = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<Task1FullMlAlertRecord>(line).ok())
        .collect::<Vec<_>>();
    if alerts.len() > limit {
        alerts.drain(0..alerts.len() - limit);
    }
    Ok(alerts)
}

pub fn full_ml_alerts_path(state_dir: impl AsRef<Path>) -> PathBuf {
    state_dir.as_ref().join(FULL_ML_ALERTS_FILE)
}

async fn sync_runtime_status(node_id: String, state_dir: PathBuf) {
    let mut tracker = Task1RuntimeTracker::for_state_dir(&node_id, &state_dir);
    if let Err(error) = tracker.persist_full_ml_runtime() {
        tracing::warn!(
            node_id = %node_id,
            %error,
            "failed to persist initial Task 1 full ML runtime status"
        );
    }

    let mut tick = interval(Duration::from_secs(5));
    loop {
        tick.tick().await;
        match tracker.maybe_reload() {
            Ok(Some(_)) | Ok(None) => {
                if let Err(error) = tracker.persist_full_ml_runtime() {
                    tracing::warn!(
                        node_id = %node_id,
                        %error,
                        "failed to refresh Task 1 full ML runtime status"
                    );
                }
            }
            Err(error) => tracing::warn!(
                node_id = %node_id,
                %error,
                "failed to refresh Task 1 baseline lifecycle state for runtime metadata"
            ),
        }
    }
}

fn install_runtime_assets(state_dir: impl AsRef<Path>) -> Result<PathBuf> {
    let state_dir = state_dir.as_ref();
    let models_dir = state_dir.join(MODELS_DIR);
    std::fs::create_dir_all(&models_dir)?;

    let global_path = models_dir.join("global_forest.json");
    let node_a_path = models_dir.join("nodeA.json");
    let node_b_path = models_dir.join("nodeB.json");

    write_if_missing(&global_path, GLOBAL_MODEL_JSON)?;
    write_if_missing(&node_a_path, NODE_A_MODEL_JSON)?;
    write_if_missing(&node_b_path, NODE_B_MODEL_JSON)?;

    let config_path = baseline_config_path(state_dir);
    let config_json = serde_json::json!({
        "global_model": global_path.display().to_string(),
        "per_node_model_template": models_dir.join("{node}.json").display().to_string(),
        "reload_check_seconds": 5,
        "min_normal_days": 7,
        "refresh_days": 30,
        "evidence_dir": state_dir.join("task1_baseline_evidence").display().to_string(),
    });
    std::fs::write(&config_path, serde_json::to_vec_pretty(&config_json)?)?;
    Ok(config_path)
}

fn write_if_missing(path: &Path, content: &str) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content)?;
    Ok(())
}

fn advisory_confidence_for(topk: &[String], rules: &RuleFile) -> Task1AdvisoryConfidence {
    let best = rules
        .rules
        .iter()
        .map(|rule| {
            let overlap = overlap_count(rule, topk);
            (rule, overlap)
        })
        .filter(|(rule, overlap)| *overlap >= rule.min_overlap)
        .max_by_key(|(_, overlap)| *overlap);

    match best {
        Some((rule, overlap)) => Task1AdvisoryConfidence {
            value: overlap as f64 / rule.signature.len() as f64,
            basis: format!(
                "configured rule '{}' matched {overlap}/{} evidence features",
                rule.name,
                rule.signature.len()
            ),
        },
        None => Task1AdvisoryConfidence {
            value: 0.0,
            basis: "fallback advisory has no configured rule-evidence match".to_string(),
        },
    }
}

fn overlap_count(rule: &PatternRule, topk: &[String]) -> usize {
    rule.signature
        .iter()
        .filter(|feature| topk.iter().any(|top| top == *feature))
        .count()
}

struct SgxTask1AlertSink {
    node_id: String,
    state_dir: PathBuf,
    rules: RuleFile,
    trigger_manager: StdMutex<VirtualShiftTriggerManager>,
    write_lock: StdMutex<()>,
}

impl SgxTask1AlertSink {
    fn new(node_id: &str, state_dir: PathBuf) -> Self {
        // Alerts reaching this sink have already passed Task 1's authoritative
        // admission gate, which uses Tier-1 warm-up confidence plus the
        // calibrated Tier-1/Tier-2 threshold crossing.
        //
        // `AnomalyAlert.confidence` is the winning model's confidence and is
        // intentionally a different semantic value. Requiring the generic
        // Virtual Shift 0.80 confidence threshold here would incorrectly stop
        // valid emitted Tier-2 alerts whose model confidence is lower.
        let mut trigger_config = VirtualShiftTriggerConfig::default();
        trigger_config.min_confidence = 0.0;

        Self {
            node_id: node_id.to_string(),
            state_dir,
            rules: RuleFile::builtin_default(),
            trigger_manager: StdMutex::new(
                VirtualShiftTriggerManager::new(trigger_config)
                    .expect("Task 1 live Virtual Shift trigger config is valid"),
            ),
            write_lock: StdMutex::new(()),
        }
    }

    fn append_record(&self, record: &Task1FullMlAlertRecord) -> Result<usize> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| anyhow!("Task 1 full ML alert sink lock poisoned"))?;
        let path = full_ml_alerts_path(&self.state_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let source_row = count_nonempty_lines(&path)?.saturating_add(1);
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        serde_json::to_writer(&mut file, record)?;
        file.write_all(b"\n")?;
        file.flush()?;
        Ok(source_row)
    }

    fn process_virtual_shift_handoff(&self, alert: &AnomalyAlert, source_row: usize) -> Result<()> {
        let anomaly_id = anomaly_id_for_alert(alert);
        if handoff_record_exists(&full_ml_handoffs_path(&self.state_dir), &anomaly_id)? {
            tracing::info!(
                node_id = %self.node_id,
                anomaly_id = %anomaly_id,
                "Task 1 full ML alert already has a persisted Virtual Shift handoff; skipping duplicate workflow"
            );
            return Ok(());
        }

        let event = anomaly_event_from_alert(anomaly_id.clone(), alert, Vec::new())?;
        let (decision, trigger_config) = {
            let mut manager = self
                .trigger_manager
                .lock()
                .map_err(|_| anyhow!("Task 1 Virtual Shift trigger manager lock poisoned"))?;
            let decision = manager.consider(&event)?;
            (decision, manager.config().clone())
        };
        let handoff = task1_virtual_shift_handoff_record(
            full_ml_alerts_path(&self.state_dir).display().to_string(),
            &event,
            source_row,
            &trigger_config,
            &decision,
        );
        append_handoff_record(&full_ml_handoffs_path(&self.state_dir), &handoff)?;

        match decision {
            TriggerDecision::Triggered => {
                let proposal_path = self.create_pending_virtual_shift_review(&event, &handoff)?;
                tracing::info!(
                    node_id = %self.node_id,
                    anomaly_id = %event.anomaly_id,
                    proposal_path = %proposal_path.display(),
                    "Task 1 full ML alert created a Virtual Shift pending review"
                );
            }
            TriggerDecision::BelowThreshold { .. } => tracing::info!(
                node_id = %self.node_id,
                anomaly_id = %event.anomaly_id,
                score = event.score,
                confidence = event.confidence,
                "Task 1 full ML alert did not pass the Virtual Shift trigger gate"
            ),
            TriggerDecision::DuplicateAnomalyId => tracing::info!(
                node_id = %self.node_id,
                anomaly_id = %event.anomaly_id,
                "Task 1 full ML alert was already considered by the live Virtual Shift trigger"
            ),
            TriggerDecision::Debounced { retry_after_ms } => tracing::info!(
                node_id = %self.node_id,
                anomaly_id = %event.anomaly_id,
                retry_after_ms,
                "Task 1 full ML alert is waiting for the Virtual Shift trigger cooldown"
            ),
        }
        Ok(())
    }

    fn create_pending_virtual_shift_review(
        &self,
        event: &sgx_anomaly_engine::virtual_shift::AnomalyEvent,
        handoff: &Task1VirtualShiftHandoff,
    ) -> Result<PathBuf> {
        let paths = ensure_virtual_shift_assets(&self.state_dir)?;
        let templates = PolicyTemplates::from_path(&paths.policy_templates)?;
        let network_templates = AdminNetworkRuleTemplates::from_path(&paths.network_templates)?;
        let recommendation_id = recommendation_id_for_event(event);
        let recommendation = recommendation_from_event(recommendation_id.clone(), event);
        let proposal = build_pending_review_proposal(
            event,
            handoff,
            &recommendation,
            &templates,
            &network_templates,
        )?;

        let proposal_dir = paths.proposal_root.join(&recommendation_id);
        std::fs::create_dir_all(&proposal_dir)?;
        let proposal_path = proposal_dir.join("virtual_shift_proposal.json");
        if !proposal_path.exists() {
            std::fs::write(&proposal_path, serde_json::to_vec_pretty(&proposal)?)?;
        }

        let roles = RoleRegistry::from_json_str(NODE_ROLES_JSON)?;
        let queue = ReviewQueue::new(paths.review_root, roles);
        match queue.enqueue_from_proposal(&proposal_path) {
            Ok(_) => Ok(proposal_path),
            Err(error) => {
                tracing::warn!(
                    node_id = %self.node_id,
                    recommendation_id = %recommendation_id,
                    %error,
                    "failed to enqueue Task 1 Virtual Shift pending review"
                );
                Err(error)
            }
        }
    }
}

struct VirtualShiftRuntimePaths {
    policy_templates: PathBuf,
    network_templates: PathBuf,
    proposal_root: PathBuf,
    review_root: PathBuf,
}

fn ensure_virtual_shift_assets(state_dir: impl AsRef<Path>) -> Result<VirtualShiftRuntimePaths> {
    let root = virtual_shift_root_path(&state_dir);
    let config_dir = root.join(VIRTUAL_SHIFT_CONFIG_DIR);
    std::fs::create_dir_all(&config_dir)?;

    let policy_templates = config_dir.join("policy_action_templates.json");
    let network_templates = config_dir.join("admin_network_rule_templates.json");
    write_if_missing(&policy_templates, POLICY_ACTION_TEMPLATES_JSON)?;
    write_if_missing(&network_templates, ADMIN_NETWORK_RULE_TEMPLATES_JSON)?;

    let proposal_root = root.join(VS01_TO_VS09_PROPOSALS);
    let review_root = root.join(VS10_VS11_REVIEWS);
    std::fs::create_dir_all(&proposal_root)?;
    std::fs::create_dir_all(&review_root)?;

    Ok(VirtualShiftRuntimePaths {
        policy_templates,
        network_templates,
        proposal_root,
        review_root,
    })
}

fn virtual_shift_root_path(state_dir: impl AsRef<Path>) -> PathBuf {
    state_dir.as_ref().join(VIRTUAL_SHIFT_DIR)
}

pub fn full_ml_handoffs_path(state_dir: impl AsRef<Path>) -> PathBuf {
    virtual_shift_root_path(state_dir).join(FULL_ML_HANDOFFS_FILE)
}

fn build_pending_review_proposal(
    event: &sgx_anomaly_engine::virtual_shift::AnomalyEvent,
    handoff: &Task1VirtualShiftHandoff,
    recommendation: &sgx_anomaly_engine::virtual_shift::PolicyRecommendation,
    templates: &PolicyTemplates,
    network_templates: &AdminNetworkRuleTemplates,
) -> Result<serde_json::Value> {
    let (stage_notes, firewall_actions, attestation_actions, logging_actions, quarantine_actions) =
        virtual_shift_stage_outputs(event, recommendation, templates)?;
    let aggregate = aggregate_recommendations(
        recommendation,
        firewall_actions,
        attestation_actions,
        logging_actions,
        quarantine_actions,
    );
    let justification = justification_from_aggregate(recommendation, &aggregate, stage_notes)?;

    Ok(serde_json::json!({
        "schema_version": 1,
        "approval_status": "pending_review",
        "advisory_only": true,
        "review_summary": {
            "source_task1_full_ml_alerts_jsonl": handoff.source_task1_json,
            "source_row": handoff.source_row,
            "gate_result": {
                "status": handoff.trigger_status,
                "reason": handoff.trigger_reason,
                "threshold_gate": handoff.threshold_gate,
                "next_step": handoff.next_step,
            },
        },
        "issue8_task1_to_virtual_shift_handoff": handoff,
        "policy_for_owner_approval": network_policy_draft(event, recommendation, network_templates),
        "vs3": recommendation,
        "vs8": aggregate,
        "vs9": justification,
    }))
}

type StageOutputs = (
    Vec<ProposalStageNote>,
    Vec<sgx_anomaly_engine::virtual_shift::FirewallRecommendation>,
    Vec<sgx_anomaly_engine::virtual_shift::AttestationRecommendation>,
    Vec<sgx_anomaly_engine::virtual_shift::LoggingRecommendation>,
    Vec<sgx_anomaly_engine::virtual_shift::QuarantineRecommendation>,
);

fn virtual_shift_stage_outputs(
    event: &sgx_anomaly_engine::virtual_shift::AnomalyEvent,
    recommendation: &sgx_anomaly_engine::virtual_shift::PolicyRecommendation,
    templates: &PolicyTemplates,
) -> Result<StageOutputs> {
    let mut notes = Vec::new();

    let firewall_actions = match firewall_recommendations_from_event(event, templates)? {
        FirewallProposalResult::Proposed(values) => {
            let value = &values[0];
            notes.push(ProposalStageNote {
                stage: "VS4".into(),
                result: format!(
                    "{:?} {} for {} sec on {} peer(s)",
                    value.firewall_mode,
                    value.rate_limit_per_second,
                    value.duration_seconds,
                    values.len()
                ),
            });
            values
        }
        FirewallProposalResult::NoProposal { reason } => {
            notes.push(ProposalStageNote {
                stage: "VS4".into(),
                result: reason,
            });
            Vec::new()
        }
    };

    let attestation_actions =
        match attestation_recommendation_from_policy(recommendation, templates)? {
            AttestationProposalResult::Proposed(value) => {
                notes.push(ProposalStageNote {
                    stage: "VS5".into(),
                    result: format!(
                        "attest {} every {} sec",
                        value.target_node, value.interval_seconds
                    ),
                });
                vec![value]
            }
            AttestationProposalResult::NoProposal { reason } => {
                notes.push(ProposalStageNote {
                    stage: "VS5".into(),
                    result: reason,
                });
                Vec::new()
            }
        };

    let logging_actions = match logging_recommendation_from_policy(recommendation, templates)? {
        LoggingProposalResult::Proposed(value) => {
            notes.push(ProposalStageNote {
                stage: "VS6".into(),
                result: format!(
                    "{:?} logging for {} sec; scopes: {:?}",
                    value.logging_level, value.duration_seconds, value.scopes
                ),
            });
            vec![value]
        }
        LoggingProposalResult::NoProposal { reason } => {
            notes.push(ProposalStageNote {
                stage: "VS6".into(),
                result: reason,
            });
            Vec::new()
        }
    };

    let quarantine_actions = match event.affected_peers.first() {
        Some(peer) => match quarantine_recommendation_from_policy(recommendation, peer, templates)?
        {
            QuarantineProposalResult::Proposed(value) => {
                notes.push(ProposalStageNote {
                    stage: "VS7".into(),
                    result: format!(
                        "quarantine {} for {} sec; reversible={}",
                        value.target_peer, value.duration_seconds, value.reversible
                    ),
                });
                vec![value]
            }
            QuarantineProposalResult::NoProposal { reason } => {
                notes.push(ProposalStageNote {
                    stage: "VS7".into(),
                    result: reason,
                });
                Vec::new()
            }
        },
        None => {
            notes.push(ProposalStageNote {
                stage: "VS7".into(),
                result: "No trusted affected peer supplied; quarantine is not evaluated.".into(),
            });
            Vec::new()
        }
    };

    Ok((
        notes,
        firewall_actions,
        attestation_actions,
        logging_actions,
        quarantine_actions,
    ))
}

fn network_policy_draft(
    event: &sgx_anomaly_engine::virtual_shift::AnomalyEvent,
    recommendation: &sgx_anomaly_engine::virtual_shift::PolicyRecommendation,
    network_templates: &AdminNetworkRuleTemplates,
) -> serde_json::Value {
    if recommendation
        .candidate_actions
        .contains(&RecommendedAction::TightenFirewall)
    {
        let anomaly_type = anomaly_type_label(&event.anomaly_type);
        let suggested_rule_ids = network_templates.suggested_rule_ids(anomaly_type);
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
            "suggested_target_peers": event.affected_peers,
            "reason": "The system matched owner-approved rules to the anomaly type. The owner reviews exact rule previews before approving, rejecting, or choosing different approved templates.",
            "owner_options": ["select_approved_template", "enter_manual_rule", "reject_suggestion"],
            "auto_apply": false
        })
    } else {
        serde_json::json!({
            "status": "not_needed",
            "reason": "This anomaly is handled by non-network actions such as attestation or logging.",
            "auto_apply": false
        })
    }
}

fn anomaly_type_label(
    anomaly_type: &sgx_anomaly_engine::virtual_shift::AnomalyType,
) -> &'static str {
    match anomaly_type {
        sgx_anomaly_engine::virtual_shift::AnomalyType::ConnectionScan => "connection_scan",
        sgx_anomaly_engine::virtual_shift::AnomalyType::TrafficFlood => "traffic_flood",
        sgx_anomaly_engine::virtual_shift::AnomalyType::ProtocolViolation => "protocol_violation",
        sgx_anomaly_engine::virtual_shift::AnomalyType::ResourceExhaustion => "resource_exhaustion",
        sgx_anomaly_engine::virtual_shift::AnomalyType::PeerAnomaly => "peer_anomaly",
        sgx_anomaly_engine::virtual_shift::AnomalyType::Generic => "generic",
    }
}

fn recommendation_id_for_event(event: &sgx_anomaly_engine::virtual_shift::AnomalyEvent) -> String {
    format!("vsr-{}", safe_file_component(&event.anomaly_id))
}

fn anomaly_id_for_alert(alert: &AnomalyAlert) -> String {
    let mut hasher = Sha256::new();
    hasher.update(alert.node.as_bytes());
    hasher.update(alert.ts.to_le_bytes());
    hasher.update(alert.score.to_le_bytes());
    hasher.update(alert.confidence.to_le_bytes());
    hasher.update(format!("{:?}", alert.severity).as_bytes());
    hasher.update(format!("{:?}", alert.tier).as_bytes());
    hasher.update(alert.topk.join("|").as_bytes());
    hasher.update(alert.reason.as_bytes());
    hasher.update(alert.recommendation.as_bytes());
    if let Some(action) = &alert.action {
        hasher.update(action.kind.as_bytes());
        hasher.update(serde_json::to_vec(&action.params).unwrap_or_default());
    }
    let digest = hasher.finalize();
    format!(
        "task1-fullml-{}-{}-{}",
        safe_file_component(&alert.node),
        alert.ts,
        hex::encode(&digest[..8])
    )
}

fn safe_file_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

fn count_nonempty_lines(path: &Path) -> Result<usize> {
    if !path.exists() {
        return Ok(0);
    }
    Ok(std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count())
}

fn handoff_record_exists(path: &Path, anomaly_id: &str) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let text = std::fs::read_to_string(path)?;
    Ok(text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .any(|line| {
            serde_json::from_str::<Task1VirtualShiftHandoff>(line)
                .map(|record| record.anomaly_id == anomaly_id)
                .unwrap_or(false)
        }))
}

fn append_handoff_record(path: &Path, handoff: &Task1VirtualShiftHandoff) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, handoff)?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

impl AlertSink for SgxTask1AlertSink {
    fn emit(&self, alert: AnomalyAlert) {
        let advisory_confidence = advisory_confidence_for(&alert.topk, &self.rules);
        let runtime = Task1RuntimeTracker::for_state_dir(&self.node_id, &self.state_dir)
            .build_full_ml_runtime()
            .unwrap_or_else(|| {
                Task1RuntimeTracker::for_state_dir(&self.node_id, &self.state_dir).current_runtime()
            });
        let record = Task1FullMlAlertRecord {
            ts: alert.ts,
            node: alert.node.clone(),
            role: alert.role,
            score: alert.score,
            model_confidence: alert.confidence,
            advisory_confidence,
            severity: alert.severity,
            topk: alert.topk.clone(),
            reason: alert.reason.clone(),
            recommendation: alert.recommendation.clone(),
            action: alert.action.clone(),
            tier: alert.tier,
            runtime,
        };

        let source_row = match self.append_record(&record) {
            Ok(source_row) => source_row,
            Err(error) => {
                tracing::warn!(
                    node_id = %self.node_id,
                    %error,
                    "failed to persist Task 1 full ML alert"
                );
                0
            }
        };

        if let Err(error) = self.process_virtual_shift_handoff(&alert, source_row) {
            tracing::warn!(
                node_id = %self.node_id,
                %error,
                "failed to process Task 1 full ML alert for Virtual Shift handoff"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::{AnomalyBaselineSelectionMode, AnomalyScoringRuntimeModelKind};
    use sgx_anomaly_engine::rules::ActionDefinition;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "sgx-task1-runtime-{label}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn full_ml_alert(score: f64, confidence: f64) -> AnomalyAlert {
        AnomalyAlert {
            ts: 42_000,
            node: "nodeA".into(),
            role: NodeRole::Member,
            score,
            confidence,
            severity: MlSeverity::High,
            topk: vec!["conn_rate".into(), "net_rx_pkts_rate".into()],
            reason: "connection activity crossed the full ML anomaly gate".into(),
            recommendation: "review peer traffic and prepare a bounded policy response".into(),
            action: Some(ActionDefinition {
                kind: "rate_limit_peer".into(),
                params: serde_json::json!({}),
            }),
            tier: AlertTier::Tier2,
        }
    }

    fn read_handoffs(dir: &Path) -> Vec<Task1VirtualShiftHandoff> {
        let text = std::fs::read_to_string(full_ml_handoffs_path(dir)).expect("read handoffs");
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("handoff json"))
            .collect()
    }

    fn review_path(dir: &Path, recommendation_id: &str) -> PathBuf {
        virtual_shift_root_path(dir)
            .join(VS10_VS11_REVIEWS)
            .join(recommendation_id)
            .join("review.json")
    }

    #[test]
    fn runtime_assets_seed_expected_models_and_config() {
        let dir = unique_temp_dir("assets");
        let config_path = install_runtime_assets(&dir).expect("install assets");
        let config: serde_json::Value =
            serde_json::from_slice(&std::fs::read(config_path).expect("read config"))
                .expect("parse config");

        assert!(dir.join(MODELS_DIR).join("global_forest.json").exists());
        assert!(dir.join(MODELS_DIR).join("nodeA.json").exists());
        assert!(dir.join(MODELS_DIR).join("nodeB.json").exists());
        assert_eq!(config["reload_check_seconds"], 5);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn sink_persists_model_and_advisory_confidence_separately() {
        let dir = unique_temp_dir("sink");
        install_runtime_assets(&dir).expect("install assets");
        let tracker = Task1RuntimeTracker::for_state_dir("nodeA", &dir);
        tracker.persist_full_ml_runtime().expect("persist runtime");

        let sink = SgxTask1AlertSink::new("nodeA", dir.clone());
        sink.emit(AnomalyAlert {
            ts: 42,
            node: "nodeA".into(),
            role: NodeRole::Member,
            score: 0.93,
            confidence: 0.81,
            severity: MlSeverity::High,
            topk: vec!["conn_rate".into(), "net_rx_pkts_rate".into()],
            reason: "reason".into(),
            recommendation: "recommendation".into(),
            action: Some(ActionDefinition {
                kind: "inspect_overlay_peers".into(),
                params: serde_json::json!({}),
            }),
            tier: AlertTier::Tier2,
        });

        let records = load_recent_full_ml_alerts(&dir, 10).expect("read alerts");
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.model_confidence, 0.81);
        assert_eq!(record.advisory_confidence.value, 2.0 / 3.0);
        assert_eq!(
            record.runtime.model_kind,
            AnomalyScoringRuntimeModelKind::IsolationForest
        );
        assert_eq!(
            record
                .runtime
                .baseline
                .as_ref()
                .map(|baseline| baseline.selection_mode),
            Some(AnomalyBaselineSelectionMode::PerNode)
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn full_ml_sink_persists_below_threshold_virtual_shift_handoff_without_review() {
        let dir = unique_temp_dir("vs-below");
        let sink = SgxTask1AlertSink::new("nodeA", dir.clone());
        sink.emit(full_ml_alert(0.84, 0.90));

        let handoffs = read_handoffs(&dir);
        assert_eq!(handoffs.len(), 1);
        assert_eq!(handoffs[0].trigger_status, "stopped");
        assert_eq!(handoffs[0].next_step, "no_policy_workflow_started");

        let recommendation_id = format!("vsr-{}", handoffs[0].anomaly_id);
        assert!(!review_path(&dir, &recommendation_id).exists());
        assert_eq!(load_recent_full_ml_alerts(&dir, 10).unwrap().len(), 1);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn authoritative_full_ml_alert_does_not_re_gate_on_model_confidence() {
        let dir = unique_temp_dir("vs-model-confidence");
        let sink = SgxTask1AlertSink::new("nodeA", dir.clone());

        // This mirrors the live Tier-2 case: Task 1 has already admitted the
        // alert using Tier-1 warm-up confidence, while the winning model's
        // reported confidence can legitimately be below 0.50.
        sink.emit(full_ml_alert(0.93, 0.48));

        let handoffs = read_handoffs(&dir);
        assert_eq!(handoffs.len(), 1);
        assert_eq!(handoffs[0].trigger_status, "triggered");
        assert_eq!(handoffs[0].model_confidence, 0.48);
        assert!(handoffs[0].approval_required);

        let recommendation_id = format!("vsr-{}", handoffs[0].anomaly_id);
        assert!(review_path(&dir, &recommendation_id).exists());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn full_ml_sink_creates_triggered_handoff_and_pending_review() {
        let dir = unique_temp_dir("vs-trigger");
        let sink = SgxTask1AlertSink::new("nodeA", dir.clone());
        sink.emit(full_ml_alert(0.93, 0.91));

        let handoffs = read_handoffs(&dir);
        assert_eq!(handoffs.len(), 1);
        assert_eq!(handoffs[0].trigger_status, "triggered");
        assert!(handoffs[0].approval_required);
        assert_eq!(handoffs[0].next_step, "create_pending_owner_review");

        let recommendation_id = format!("vsr-{}", handoffs[0].anomaly_id);
        let proposal_path = virtual_shift_root_path(&dir)
            .join(VS01_TO_VS09_PROPOSALS)
            .join(&recommendation_id)
            .join("virtual_shift_proposal.json");
        assert!(proposal_path.exists());
        assert!(review_path(&dir, &recommendation_id).exists());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn full_ml_sink_dedupes_replayed_alerts_without_losing_alert_history() {
        let dir = unique_temp_dir("vs-duplicate");
        let sink = SgxTask1AlertSink::new("nodeA", dir.clone());
        let alert = full_ml_alert(0.93, 0.91);
        sink.emit(alert.clone());
        sink.emit(alert);

        let handoffs = read_handoffs(&dir);
        assert_eq!(handoffs.len(), 1);
        assert_eq!(load_recent_full_ml_alerts(&dir, 10).unwrap().len(), 2);

        let recommendation_id = format!("vsr-{}", handoffs[0].anomaly_id);
        assert!(review_path(&dir, &recommendation_id).exists());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn pending_review_proposal_keeps_complete_virtual_shift_package() {
        let dir = unique_temp_dir("vs-review");
        let sink = SgxTask1AlertSink::new("nodeA", dir.clone());
        sink.emit(full_ml_alert(0.93, 0.91));

        let handoff = read_handoffs(&dir).pop().expect("handoff");
        let recommendation_id = format!("vsr-{}", handoff.anomaly_id);
        let review: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(review_path(&dir, &recommendation_id)).unwrap(),
        )
        .expect("review json");

        assert_eq!(review["status"], "pending_review");
        assert_eq!(review["proposal"]["approval_status"], "pending_review");
        assert!(review["proposal"]["vs3"].is_object());
        assert!(review["proposal"]["vs8"].is_object());
        assert!(review["proposal"]["vs9"].is_object());
        assert_eq!(
            review["proposal"]["issue8_task1_to_virtual_shift_handoff"]["trigger_status"],
            "triggered"
        );

        let _ = std::fs::remove_dir_all(dir);
    }
}
