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
    AiRemediationAction, AiRemediationHandoffResult, AiRemediationPlan, AttestationProposalResult,
    FirewallProposalResult, LoggingProposalResult, ProposalStageNote, QuarantineProposalResult,
    RecommendedAction, ReviewQueue, Task1VirtualShiftHandoff, TriggerDecision,
    VirtualShiftTriggerConfig, VirtualShiftTriggerManager, VS01_TO_VS09_PROPOSALS,
    VS10_VS11_REVIEWS,
};
use sgx_anomaly_engine::virtual_shift::{
    build_candidate_from_approved_review, canonical_policy_bytes, sha256_hex, sign_approved_policy,
    verify_signed_policy, vshift_alert_from_signed_policy, write_built_candidate,
    write_signed_policy, write_vshift_alert, ActiveVirtualShiftPolicy, ApprovalService,
    GuardianKeyManager, ManualOverrideService, SignedVirtualShiftPolicy, VShiftAlert,
    VS12_CANDIDATES, VS13_SIGNED_POLICIES, VS14_ALERTS, VS17_MEMBER_POLICY_STATE, VS19_OVERRIDES,
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
const ACTIVE_VIRTUAL_SHIFT_POLICY_JSON: &str =
    include_str!("../../crates/sgx-anomaly-engine/config/active_virtual_shift_policy.json");
const GUARDIAN_SIGNER_JSON: &str =
    include_str!("../../crates/sgx-anomaly-engine/config/guardian_signer.json");
const CIRCLE_GOSSIP_TOPOLOGY_JSON: &str =
    include_str!("../../crates/sgx-anomaly-engine/config/circle_gossip_topology.json");

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

    let active_policy = config_dir.join("active_virtual_shift_policy.json");
    let guardian_signer = config_dir.join("guardian_signer.json");
    let node_roles = config_dir.join("node_roles.json");
    let gossip_topology = config_dir.join("circle_gossip_topology.json");
    write_if_missing(&active_policy, ACTIVE_VIRTUAL_SHIFT_POLICY_JSON)?;
    write_if_missing(&guardian_signer, GUARDIAN_SIGNER_JSON)?;
    write_if_missing(&node_roles, NODE_ROLES_JSON)?;
    write_if_missing(&gossip_topology, CIRCLE_GOSSIP_TOPOLOGY_JSON)?;

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

fn task1_remediation_action_for_review(
    action: &crate::task1_ai::ActionType,
    target_ip: &str,
) -> AiRemediationAction {
    match action {
        crate::task1_ai::ActionType::NftablesBlockIp { duration_secs } => AiRemediationAction {
            action_type: "tighten_firewall_rules".into(),
            target: target_ip.into(),
            parameters: serde_json::json!({
                "source_ip": target_ip,
                "duration_secs": duration_secs
            }),
            requires_approval: true,
            reason: "Task 1 recommends a bounded firewall restriction after anomaly detection."
                .into(),
        },
        crate::task1_ai::ActionType::QuarantinePeer { peer_id } => AiRemediationAction {
            action_type: "quarantine_suspicious_peer".into(),
            target: peer_id.clone(),
            parameters: serde_json::json!({
                "peer_id": peer_id
            }),
            requires_approval: true,
            reason: "Task 1 recommends quarantining the suspicious peer after owner review.".into(),
        },
        crate::task1_ai::ActionType::TightenAttestation { interval_secs } => AiRemediationAction {
            action_type: "increase_attestation_frequency".into(),
            target: target_ip.into(),
            parameters: serde_json::json!({
                "interval_secs": interval_secs
            }),
            requires_approval: true,
            reason: "Task 1 recommends tighter attestation after suspicious activity.".into(),
        },
        crate::task1_ai::ActionType::ProposePolicyUpdate { rule_delta } => AiRemediationAction {
            action_type: "propose_policy_update".into(),
            target: target_ip.into(),
            parameters: serde_json::json!({
                "rule_delta": rule_delta
            }),
            requires_approval: true,
            reason: "Task 1 recommends a policy update; owner approval is required.".into(),
        },
        crate::task1_ai::ActionType::EnableDebugLogging { interface } => AiRemediationAction {
            action_type: "enable_additional_logging".into(),
            target: target_ip.into(),
            parameters: serde_json::json!({
                "interface": interface
            }),
            requires_approval: true,
            reason: "Task 1 recommends additional logging for investigation.".into(),
        },
        crate::task1_ai::ActionType::AlertOnly => AiRemediationAction {
            action_type: "alert_only".into(),
            target: target_ip.into(),
            parameters: serde_json::json!({}),
            requires_approval: true,
            reason: "Task 1 recommends owner-visible alert handling.".into(),
        },
    }
}

/// Persist the real ThreatService-generated Task 1 remediation plan into the
/// same Task 2 owner-review queue already used by the Virtual Shift runtime.
pub fn persist_remediation_plan_for_owner_review(
    node_id: &str,
    state_dir: impl AsRef<Path>,
    plan: &crate::task1_ai::RemediationPlan,
    thresholds: &crate::task1_ai::Task1ThresholdSettings,
) -> Result<AiRemediationHandoffResult> {
    let paths = ensure_virtual_shift_assets(state_dir)?;
    let roles = RoleRegistry::from_json_str(NODE_ROLES_JSON)?;
    let queue = ReviewQueue::new(paths.review_root, roles);

    let severity = if plan.score.score >= thresholds.critical_threshold {
        "Critical"
    } else if plan.score.score >= thresholds.high_threshold {
        "High"
    } else {
        "Medium"
    };

    let actions = plan
        .requires_approval
        .iter()
        .map(|action| task1_remediation_action_for_review(action, &plan.target_ip))
        .collect::<Vec<_>>();

    let created_at_ms = u64::try_from(plan.created_at.timestamp_millis())
        .map_err(|_| anyhow!("Task 1 remediation timestamp predates Unix epoch"))?;

    let ai_plan = AiRemediationPlan {
        plan_id: plan.plan_id.clone(),
        anomaly_id: format!("task1-threat-{}", plan.plan_id),
        source_node: node_id.to_string(),
        anomaly_score: f64::from(plan.score.score),
        model_confidence: f64::from(plan.score.model_confidence),
        severity: severity.into(),
        anomaly_metadata: serde_json::json!({
            "contributing_ip": plan.score.contributing_ip,
            "target_ip": plan.target_ip,
            "alert_count": plan.score.alert_count,
            "top_signature_id": plan.score.top_signature_id,
            "top_signature_count": plan.score.top_signature_count,
            "category": plan.score.category,
            "computed_at": plan.score.computed_at,
            "window_secs": plan.score.window_secs,
            "scoring_runtime": plan.score.scoring_runtime
        }),
        justification: plan.justification.clone(),
        created_at_ms,
        requires_approval: true,
        auto_execute: false,
        actions,
    };

    let (_, handoff) =
        queue.enqueue_ai_remediation_plan(ai_plan, "task1-threat-service-runtime")?;

    Ok(handoff)
}

#[derive(Debug, Clone, Serialize)]
pub struct Task2OwnerDecisionRuntimeResult {
    pub schema_version: u32,
    pub plan_id: String,
    pub decision_actor: String,
    pub decision: String,
    pub policy_build_allowed: bool,
    pub candidate_path: Option<String>,
    pub signed_policy_path: Option<String>,
    pub alert_id: Option<String>,
    pub alert_json_path: Option<String>,
    pub alert_protobuf_path: Option<String>,
}

fn task2_now_ms() -> Result<u64> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?)
}

/// Consume one real Task1 remediation review in the production state directory.
///
/// Reject stops at the durable owner decision.
/// Approve continues through VS12 candidate -> VS13 Guardian signing ->
/// VS14 signed VSHIFT_ALERT persistence. VS15 network delivery remains separate.
pub fn process_task2_owner_decision(
    node_id: &str,
    state_dir: impl AsRef<Path>,
    plan_id: &str,
    approve: bool,
    reason: Option<String>,
) -> Result<Task2OwnerDecisionRuntimeResult> {
    let state_dir = state_dir.as_ref();
    let paths = ensure_virtual_shift_assets(state_dir)?;
    let root = virtual_shift_root_path(state_dir);

    let roles = RoleRegistry::from_json_str(NODE_ROLES_JSON)?;
    let queue = ReviewQueue::new(paths.review_root, roles);
    let approval = ApprovalService::new(queue);

    let decided_at_ms = task2_now_ms()?;
    let decided = if approve {
        approval.approve(node_id, plan_id, reason, decided_at_ms)?
    } else {
        approval.reject(node_id, plan_id, reason, decided_at_ms)?
    };

    if !approve {
        return Ok(Task2OwnerDecisionRuntimeResult {
            schema_version: 1,
            plan_id: decided.recommendation_id,
            decision_actor: node_id.to_owned(),
            decision: "rejected".into(),
            policy_build_allowed: false,
            candidate_path: None,
            signed_policy_path: None,
            alert_id: None,
            alert_json_path: None,
            alert_protobuf_path: None,
        });
    }

    // After VS17 has activated a member-local policy, use that policy as the
    // parent for the next owner-approved candidate. The configured policy is
    // only the bootstrap seed before this member has VS17 state.
    let configured_active_policy_path = root
        .join(VIRTUAL_SHIFT_CONFIG_DIR)
        .join("active_virtual_shift_policy.json");

    let member_active_policy_path = root
        .join(VS17_MEMBER_POLICY_STATE)
        .join(node_id)
        .join("active_policy.json");

    let active_policy_path = if member_active_policy_path.is_file() {
        member_active_policy_path
    } else {
        configured_active_policy_path
    };

    let active = ActiveVirtualShiftPolicy::from_path(&active_policy_path)?;

    let built = build_candidate_from_approved_review(&active, &decided)?;
    let candidate_path = write_built_candidate(root.join(VS12_CANDIDATES), &built)?;

    let signer_config = root
        .join(VIRTUAL_SHIFT_CONFIG_DIR)
        .join("guardian_signer.json");
    let guardian = GuardianKeyManager::from_config(&signer_config, root.join("guardian_keys"))?;

    let signed_at_ms = task2_now_ms()?;
    let signed = sign_approved_policy(&guardian, &decided, &built, signed_at_ms)?;
    let signed_policy_path = write_signed_policy(root.join(VS13_SIGNED_POLICIES), &signed)?;

    let issued_at_ms = task2_now_ms()?;
    let alert_id = format!(
        "vsa-{}-v{}-{}",
        built.candidate.circle_id,
        built.candidate.policy_version,
        built.candidate.source_recommendation_id
    );

    let alert = vshift_alert_from_signed_policy(
        &decided,
        &signed,
        alert_id.clone(),
        issued_at_ms,
        issued_at_ms + 300_000,
    )?;

    let (alert_json_path, alert_protobuf_path) =
        write_vshift_alert(root.join(VS14_ALERTS), &alert)?;

    Ok(Task2OwnerDecisionRuntimeResult {
        schema_version: 1,
        plan_id: decided.recommendation_id,
        decision_actor: node_id.to_owned(),
        decision: "approved".into(),
        policy_build_allowed: true,
        candidate_path: Some(candidate_path.display().to_string()),
        signed_policy_path: Some(signed_policy_path.display().to_string()),
        alert_id: Some(alert_id),
        alert_json_path: Some(alert_json_path.display().to_string()),
        alert_protobuf_path: Some(alert_protobuf_path.display().to_string()),
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct Task2FalsePositiveOverrideRuntimeResult {
    pub schema_version: u32,
    pub plan_id: String,
    pub original_alert_id: String,
    pub original_policy_version: u64,
    pub override_id: String,
    pub replacement_policy_version: u64,
    pub override_record_path: String,
    pub signed_policy_path: String,
    pub alert_id: String,
    pub alert_json_path: String,
    pub alert_protobuf_path: String,
}

pub fn process_task2_false_positive_override(
    node_id: &str,
    state_dir: impl AsRef<Path>,
    plan_id: &str,
    reason: &str,
) -> Result<Task2FalsePositiveOverrideRuntimeResult> {
    if reason.trim().is_empty() {
        anyhow::bail!("false-positive override reason is required");
    }

    let state_dir = state_dir.as_ref();
    ensure_virtual_shift_assets(state_dir)?;
    let root = virtual_shift_root_path(state_dir);

    let (original_alert, _) = load_approved_task2_vshift_alert_for_retry(state_dir, plan_id)?;

    let role_config = root.join(VIRTUAL_SHIFT_CONFIG_DIR).join("node_roles.json");

    let role_config_str = role_config
        .to_str()
        .ok_or_else(|| anyhow!("node role config path is not valid UTF-8"))?;

    let override_root = root.join(VS19_OVERRIDES).join(plan_id);

    let service = ManualOverrideService::from_role_config(
        root.join(VS17_MEMBER_POLICY_STATE),
        &override_root,
        role_config_str,
    )?;

    let signer_config = root
        .join(VIRTUAL_SHIFT_CONFIG_DIR)
        .join("guardian_signer.json");

    let guardian = GuardianKeyManager::from_config(&signer_config, root.join("guardian_keys"))?;

    let created_at_ms = task2_now_ms()?;

    let record = service.create_signed_revert(
        node_id,
        node_id,
        &original_alert,
        reason,
        created_at_ms,
        &guardian,
    )?;

    let signed_bytes = std::fs::read(&record.signed_policy_path)?;
    let signed: SignedVirtualShiftPolicy = serde_json::from_slice(&signed_bytes)?;
    verify_signed_policy(&signed)?;

    let policy_blob = canonical_policy_bytes(&signed.policy)?;
    if sha256_hex(&policy_blob) != signed.canonical_sha256 {
        anyhow::bail!("manual override signed policy canonical hash mismatch");
    }

    let issued_at_ms = task2_now_ms()?;
    let alert_id = format!(
        "vsa-{}-v{}-override-{}",
        signed.policy.circle_id, signed.policy.policy_version, plan_id
    );

    let alert = VShiftAlert {
        schema_version: 1,
        alert_id: alert_id.clone(),
        circle_id: signed.policy.circle_id.clone(),
        policy_version: signed.policy.policy_version,
        policy_blob,
        policy_hash_hex: signed.canonical_sha256.clone(),
        guardian_signature_hex: signed.signature_hex.clone(),
        guardian_public_key_hex: signed.public_key_hex.clone(),
        signer_id: signed.signer_id.clone(),
        signature_algorithm: signed.algorithm.clone(),
        anomaly_id: original_alert.anomaly_id.clone(),
        recommendation_id: signed.policy.source_recommendation_id.clone(),
        anomaly_score: original_alert.anomaly_score,
        confidence: original_alert.confidence,
        ai_justification: original_alert.ai_justification.clone(),
        issued_at_ms,
        expires_at_ms: issued_at_ms + 300_000,
    };

    alert.validate()?;

    let (alert_json_path, alert_protobuf_path) =
        write_vshift_alert(root.join(VS14_ALERTS), &alert)?;

    let override_record_path = Path::new(&record.signed_policy_path)
        .parent()
        .ok_or_else(|| anyhow!("manual override directory is missing"))?
        .join("override_record.json");

    Ok(Task2FalsePositiveOverrideRuntimeResult {
        schema_version: 1,
        plan_id: plan_id.to_owned(),
        original_alert_id: record.original_alert_id,
        original_policy_version: record.original_policy_version,
        override_id: record.override_id,
        replacement_policy_version: record.replacement_policy_version,
        override_record_path: override_record_path.display().to_string(),
        signed_policy_path: record.signed_policy_path,
        alert_id,
        alert_json_path: alert_json_path.display().to_string(),
        alert_protobuf_path: alert_protobuf_path.display().to_string(),
    })
}

/// Load the exact persisted VS14 alert for an already-approved Task2 review.
///
/// This is intentionally retry-only:
/// - it never re-runs owner approval,
/// - never builds a new candidate,
/// - never signs a new policy,
/// - never changes policy version,
/// - and resolves the alert by its embedded recommendation/anomaly linkage
///   instead of guessing a policy version or hard-coding an artifact path.
pub fn load_approved_task2_vshift_alert_for_retry(
    state_dir: impl AsRef<Path>,
    plan_id: &str,
) -> Result<(sgx_anomaly_engine::virtual_shift::VShiftAlert, PathBuf)> {
    if plan_id.trim().is_empty()
        || matches!(plan_id, "." | "..")
        || plan_id.contains('/')
        || plan_id.contains('\\')
        || plan_id.contains('\0')
    {
        anyhow::bail!("invalid Task2 plan_id");
    }

    let root = virtual_shift_root_path(state_dir.as_ref());

    let review_path = root
        .join(VS10_VS11_REVIEWS)
        .join(plan_id)
        .join("review.json");

    let review_bytes = std::fs::read(&review_path)?;
    let review: sgx_anomaly_engine::virtual_shift::review::ReviewRecord =
        serde_json::from_slice(&review_bytes)?;

    review.validate()?;

    if review.recommendation_id != plan_id {
        anyhow::bail!("persisted review recommendation_id does not match requested plan_id");
    }

    if review.status != sgx_anomaly_engine::virtual_shift::review::ReviewStatus::Approved {
        anyhow::bail!("Task2 gossip retry requires an already-approved review");
    }

    let owner_decision = review
        .owner_decision
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("approved Task2 review is missing owner decision"))?;

    if owner_decision.decision != sgx_anomaly_engine::virtual_shift::review::ReviewStatus::Approved
    {
        anyhow::bail!("Task2 review owner decision is not approved");
    }

    let alert_root = root.join(VS14_ALERTS);

    let mut matched: Option<(sgx_anomaly_engine::virtual_shift::VShiftAlert, PathBuf)> = None;

    for entry in std::fs::read_dir(&alert_root)? {
        let entry = entry?;

        if !entry.file_type()?.is_dir() {
            continue;
        }

        let alert_pb_path = entry.path().join("vshift_alert.pb");

        if !alert_pb_path.is_file() {
            continue;
        }

        let bytes = match std::fs::read(&alert_pb_path) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };

        let alert = match sgx_anomaly_engine::virtual_shift::VShiftAlert::decode(&bytes) {
            Ok(alert) => alert,
            Err(_) => continue,
        };

        if alert.recommendation_id != plan_id {
            continue;
        }

        if alert.anomaly_id != review.anomaly_id {
            anyhow::bail!("persisted VS14 alert anomaly_id does not match approved review");
        }

        alert.validate()?;

        if matched.is_some() {
            anyhow::bail!(
                "multiple persisted VS14 alerts match approved plan '{}'",
                plan_id
            );
        }

        matched = Some((alert, alert_pb_path));
    }

    matched.ok_or_else(|| {
        anyhow::anyhow!(
            "no persisted VS14 alert found for approved plan '{}'",
            plan_id
        )
    })
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
