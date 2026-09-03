//! VS10: durable Circle Owner review queue and lifecycle protection.
//!
//! VS10 does not approve or reject a recommendation. It persists a complete
//! VS1-VS9 package as `pending_review`, then lets an authorised owner list or
//! view it. VS11 will later add the actual owner decision path.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::roles::{NodeRole, RoleRegistry};

/// The review lifecycle is intentionally small. VS10 creates only pending
/// records; VS11 is the only later phase allowed to finalise them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    PendingReview,
    Approved,
    Rejected,
}

/// Auditable Circle Owner decision. Only VS11 creates this record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerDecision {
    pub reviewer_id: String,
    pub decision: ReviewStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub decided_at_ms: u64,
}

/// One AI-generated remediation action that can later become a Virtual Shift
/// policy action after owner approval. The model may recommend, but the owner
/// still decides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiRemediationAction {
    pub action_type: String,
    pub target: String,
    #[serde(default)]
    pub parameters: serde_json::Value,
    pub requires_approval: bool,
    pub reason: String,
}

/// Durable AI remediation plan generated from a Task 1 anomaly. A plan with
/// `requires_approval=true` must be persisted into the owner review queue
/// before any Virtual Shift policy can be built, signed, or broadcast.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AiRemediationPlan {
    pub plan_id: String,
    pub anomaly_id: String,
    pub source_node: String,
    pub anomaly_score: f64,
    pub model_confidence: f64,
    pub severity: String,
    #[serde(default)]
    pub anomaly_metadata: serde_json::Value,
    pub justification: String,
    pub created_at_ms: u64,
    pub requires_approval: bool,
    pub auto_execute: bool,
    pub actions: Vec<AiRemediationAction>,
}

impl AiRemediationPlan {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.plan_id.trim().is_empty()
            || self.plan_id.contains(['/', '\\'])
            || matches!(self.plan_id.as_str(), "." | "..")
        {
            anyhow::bail!("AI remediation plan_id must be a non-empty file-name-safe identifier");
        }
        if self.anomaly_id.trim().is_empty() || self.source_node.trim().is_empty() {
            anyhow::bail!("AI remediation plan must keep anomaly_id and source_node");
        }
        if !(0.0..=1.0).contains(&self.anomaly_score)
            || !(0.0..=1.0).contains(&self.model_confidence)
        {
            anyhow::bail!("AI remediation plan score/confidence must be between 0.0 and 1.0");
        }
        if self.created_at_ms == 0 {
            anyhow::bail!("AI remediation plan requires a non-zero creation timestamp");
        }
        if !self.requires_approval {
            anyhow::bail!("Task 2 handoff only accepts owner-reviewable remediation plans");
        }
        if self.auto_execute {
            anyhow::bail!("Task 2 handoff refuses auto_execute plans; owner approval is mandatory");
        }
        if self.actions.is_empty() {
            anyhow::bail!("AI remediation plan must include at least one recommended action");
        }
        for action in &self.actions {
            if action.action_type.trim().is_empty()
                || action.target.trim().is_empty()
                || action.reason.trim().is_empty()
            {
                anyhow::bail!("AI remediation action must include type, target and reason");
            }
            if !action.requires_approval {
                anyhow::bail!("AI remediation action must require owner approval");
            }
        }
        Ok(())
    }
}

/// Result of inserting a Task 1 AI remediation plan into the Task 2 owner
/// review lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiRemediationHandoffResult {
    pub plan_id: String,
    pub review_status: ReviewStatus,
    pub pending_review_path: String,
    pub duplicate: bool,
    pub next_step: String,
}

/// One durable review item. `proposal` embeds the complete VS1-VS9 package so
/// the owner sees score, confidence, evidence, actions and justification from
/// one record rather than following several file paths.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviewRecord {
    pub schema_version: u32,
    pub recommendation_id: String,
    pub anomaly_id: String,
    pub source_node: String,
    pub status: ReviewStatus,
    #[serde(default)]
    pub owner_decision: Option<OwnerDecision>,
    pub created_at_ms: u64,
    pub source_proposal_path: String,
    pub proposal: serde_json::Value,
}

impl ReviewRecord {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.schema_version != 1 {
            anyhow::bail!("unsupported review schema {}", self.schema_version);
        }
        if self.recommendation_id.trim().is_empty()
            || self.anomaly_id.trim().is_empty()
            || self.source_node.trim().is_empty()
        {
            anyhow::bail!("review record is missing recommendation, anomaly or node identity");
        }
        if self.created_at_ms == 0 {
            anyhow::bail!("review record needs a non-zero creation timestamp");
        }
        if self.proposal.get("vs8").is_none() || self.proposal.get("vs9").is_none() {
            anyhow::bail!("review record requires complete VS8 aggregate and VS9 justification");
        }
        match (self.status, &self.owner_decision) {
            (ReviewStatus::PendingReview, None) => Ok(()),
            (ReviewStatus::PendingReview, Some(_)) => {
                anyhow::bail!("pending review record cannot already contain an owner decision")
            }
            (ReviewStatus::Approved | ReviewStatus::Rejected, Some(decision)) => {
                if decision.reviewer_id.trim().is_empty() || decision.decided_at_ms == 0 {
                    anyhow::bail!("finalized review record has invalid owner decision metadata");
                }
                if decision.decision != self.status {
                    anyhow::bail!("owner decision does not match review status");
                }
                Ok(())
            }
            (ReviewStatus::Approved | ReviewStatus::Rejected, None) => {
                anyhow::bail!("finalized review record must retain an owner decision")
            }
        }
    }

    /// Lifecycle transitions are deliberately one-way. A finalized record
    /// cannot be returned to pending or decided a second time.
    pub fn finalize(&mut self, decision: OwnerDecision) -> anyhow::Result<()> {
        if self.status != ReviewStatus::PendingReview || self.owner_decision.is_some() {
            anyhow::bail!("recommendation is already finalized and cannot be decided twice");
        }
        if !matches!(
            decision.decision,
            ReviewStatus::Approved | ReviewStatus::Rejected
        ) {
            anyhow::bail!("owner decision must be approved or rejected");
        }
        if decision.reviewer_id.trim().is_empty() || decision.decided_at_ms == 0 {
            anyhow::bail!("owner decision requires reviewer identity and timestamp");
        }
        if decision
            .reason
            .as_deref()
            .is_some_and(|reason| reason.len() > 1024)
        {
            anyhow::bail!("owner decision reason exceeds 1024 bytes");
        }
        self.status = decision.decision;
        self.owner_decision = Some(decision);
        self.validate()
    }
}

/// Durable review queue backed by one JSON file per recommendation.
#[derive(Debug, Clone)]
pub struct ReviewQueue {
    root: PathBuf,
    roles: RoleRegistry,
}

impl ReviewQueue {
    pub fn new(root: impl Into<PathBuf>, roles: RoleRegistry) -> Self {
        Self {
            root: root.into(),
            roles,
        }
    }

    pub fn from_role_config(root: impl Into<PathBuf>, role_config: &str) -> anyhow::Result<Self> {
        Ok(Self::new(root, RoleRegistry::from_path(role_config)?))
    }

    /// Add a VS1-VS9 proposal to the review queue. Re-running the same demo is
    /// idempotent while it remains pending; a finalized recommendation cannot
    /// be silently re-queued.
    pub fn enqueue_from_proposal(
        &self,
        proposal_path: impl AsRef<Path>,
    ) -> anyhow::Result<ReviewRecord> {
        let proposal_path = proposal_path.as_ref();
        let proposal: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(proposal_path)?)?;
        let record = review_record_from_proposal(proposal_path, proposal)?;
        let path = self.record_path(&record.recommendation_id)?;
        if path.exists() {
            let existing = self.read_record_path(&path)?;
            if existing.status == ReviewStatus::PendingReview {
                return Ok(existing);
            }
            anyhow::bail!(
                "recommendation '{}' is finalized and cannot be re-queued",
                existing.recommendation_id
            );
        }
        self.write_record(&record)?;
        Ok(record)
    }

    /// Persist a generated Task 1 AI remediation plan as a Task 2 pending
    /// owner-review record. This prevents AI plans from staying only in
    /// memory/logs; the exact plan ID is what later approval/rejection consumes.
    pub fn enqueue_ai_remediation_plan(
        &self,
        plan: AiRemediationPlan,
        source_description: impl Into<String>,
    ) -> anyhow::Result<(ReviewRecord, AiRemediationHandoffResult)> {
        plan.validate()?;
        let source_description = source_description.into();
        let proposal = ai_plan_to_review_proposal(&plan);
        let record = ReviewRecord {
            schema_version: 1,
            recommendation_id: plan.plan_id.clone(),
            anomaly_id: plan.anomaly_id.clone(),
            source_node: plan.source_node.clone(),
            status: ReviewStatus::PendingReview,
            owner_decision: None,
            created_at_ms: plan.created_at_ms,
            source_proposal_path: source_description,
            proposal,
        };
        let path = self.record_path(&record.recommendation_id)?;
        if path.exists() {
            let existing = self.read_record_path(&path)?;
            if existing.status == ReviewStatus::PendingReview {
                return Ok((
                    existing.clone(),
                    AiRemediationHandoffResult {
                        plan_id: existing.recommendation_id,
                        review_status: existing.status,
                        pending_review_path: path.display().to_string(),
                        duplicate: true,
                        next_step: "owner_review_existing_pending_plan".into(),
                    },
                ));
            }
            anyhow::bail!(
                "AI remediation plan '{}' is already finalized and cannot be re-queued",
                existing.recommendation_id
            );
        }
        self.write_record(&record)?;
        Ok((
            record.clone(),
            AiRemediationHandoffResult {
                plan_id: record.recommendation_id,
                review_status: record.status,
                pending_review_path: path.display().to_string(),
                duplicate: false,
                next_step: "owner_approve_or_reject_exact_plan".into(),
            },
        ))
    }

    /// Only the trusted owner role may browse the queue. Current standalone
    /// deployment maps this role to `admin` in `config/node_roles.json`.
    pub fn list_pending(&self, owner_id: &str) -> anyhow::Result<Vec<ReviewRecord>> {
        self.require_owner(owner_id)?;
        let mut records = Vec::new();
        if !self.root.exists() {
            return Ok(records);
        }
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            let path = entry.path().join("review.json");
            if path.is_file() {
                let record = self.read_record_path(&path)?;
                if record.status == ReviewStatus::PendingReview {
                    records.push(record);
                }
            }
        }
        records.sort_by(|left, right| {
            left.created_at_ms
                .cmp(&right.created_at_ms)
                .then_with(|| left.recommendation_id.cmp(&right.recommendation_id))
        });
        Ok(records)
    }

    /// Show one complete record, including VS8 actions and VS9 justification.
    pub fn show(&self, owner_id: &str, recommendation_id: &str) -> anyhow::Result<ReviewRecord> {
        self.require_owner(owner_id)?;
        self.read_record_path(&self.record_path(recommendation_id)?)
    }

    /// Internal persistence point used by later VS11 approval/rejection code.
    pub(crate) fn write_record(&self, record: &ReviewRecord) -> anyhow::Result<PathBuf> {
        record.validate()?;
        let path = self.record_path(&record.recommendation_id)?;
        let directory = path.parent().expect("review record has a parent directory");
        std::fs::create_dir_all(directory)?;
        std::fs::write(&path, serde_json::to_string_pretty(record)?)?;
        Ok(path)
    }

    pub(crate) fn write_decision_audit(&self, record: &ReviewRecord) -> anyhow::Result<PathBuf> {
        record.validate()?;
        let decision = record
            .owner_decision
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("decision audit requires an owner decision"))?;
        let path = self
            .record_path(&record.recommendation_id)?
            .parent()
            .expect("review record has a parent directory")
            .join("owner_decision_audit.json");
        let audit = serde_json::json!({
            "schema_version": 1,
            "record_type": "task2_owner_decision_audit",
            "plan_id": record.recommendation_id,
            "recommendation_id": record.recommendation_id,
            "anomaly_id": record.anomaly_id,
            "source_node": record.source_node,
            "decision": decision.decision,
            "decision_actor": decision.reviewer_id,
            "decision_timestamp_ms": decision.decided_at_ms,
            "reason": decision.reason,
            "policy_mutation_allowed": record.status == ReviewStatus::Approved,
            "policy_mutation_blocked_reason": if record.status == ReviewStatus::Rejected {
                Some("owner rejected AI recommendation before policy build/sign/broadcast")
            } else {
                None
            },
            "ai_justification": record
                .proposal
                .get("vs3")
                .and_then(|value| value.get("justification"))
                .cloned()
                .unwrap_or(serde_json::Value::Null),
            "original_anomaly_metadata": record
                .proposal
                .get("vs9")
                .and_then(|value| value.get("anomaly_metadata"))
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        });
        std::fs::write(&path, serde_json::to_string_pretty(&audit)?)?;
        Ok(path)
    }

    pub(crate) fn record_path(&self, recommendation_id: &str) -> anyhow::Result<PathBuf> {
        if recommendation_id.trim().is_empty()
            || matches!(recommendation_id, "." | "..")
            || recommendation_id.contains(['/', '\\'])
        {
            anyhow::bail!("recommendation ID must be a file-name-safe identifier");
        }
        Ok(self.root.join(recommendation_id).join("review.json"))
    }

    fn read_record_path(&self, path: &Path) -> anyhow::Result<ReviewRecord> {
        let record: ReviewRecord = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        record.validate()?;
        Ok(record)
    }

    fn require_owner(&self, owner_id: &str) -> anyhow::Result<()> {
        if self.roles.role_for(owner_id) != NodeRole::Admin {
            anyhow::bail!("'{owner_id}' is not an authorised Circle Owner for review access");
        }
        Ok(())
    }

    pub(crate) fn require_authorised_owner(&self, owner_id: &str) -> anyhow::Result<()> {
        self.require_owner(owner_id)
    }
}

fn ai_plan_to_review_proposal(plan: &AiRemediationPlan) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "record_type": "task1_ai_remediation_plan_owner_review",
        "approval_status": "pending_review",
        "task1_ai_remediation_plan": plan,
        "vs3": {
            "recommendation_id": plan.plan_id,
            "anomaly_id": plan.anomaly_id,
            "source_node": plan.source_node,
            "created_at_ms": plan.created_at_ms,
            "risk_level": plan.severity,
            "anomaly_score": plan.anomaly_score,
            "confidence": plan.model_confidence,
            "model_confidence": plan.model_confidence,
            "justification": plan.justification,
            "requires_approval": plan.requires_approval,
            "auto_execute": plan.auto_execute
        },
        "vs8": {
            "actions": plan.actions,
            "advisory_only": true,
            "conflict_resolution": [],
            "handoff_source": "task1_ai_remediation_plan"
        },
        "vs9": {
            "human_summary": plan.justification,
            "anomaly_metadata": plan.anomaly_metadata,
            "traceability": {
                "plan_id": plan.plan_id,
                "anomaly_id": plan.anomaly_id,
                "source_node": plan.source_node
            }
        },
        "lifecycle": {
            "state": "pending",
            "next_allowed_steps": ["owner_approve", "owner_reject"],
            "policy_build_allowed": false
        }
    })
}

fn review_record_from_proposal(
    proposal_path: &Path,
    proposal: serde_json::Value,
) -> anyhow::Result<ReviewRecord> {
    let vs3 = proposal
        .get("vs3")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("proposal is missing VS3 recommendation"))?;
    let text = |name: &str| -> anyhow::Result<String> {
        vs3.get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("proposal VS3 is missing '{name}'"))
    };
    let created_at_ms = vs3
        .get("created_at_ms")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("proposal VS3 is missing creation timestamp"))?;
    if proposal
        .get("approval_status")
        .and_then(serde_json::Value::as_str)
        != Some("pending_review")
    {
        anyhow::bail!("only pending_review VS1-VS9 packages may enter VS10 queue");
    }
    let record = ReviewRecord {
        schema_version: 1,
        recommendation_id: text("recommendation_id")?,
        anomaly_id: text("anomaly_id")?,
        source_node: text("source_node")?,
        status: ReviewStatus::PendingReview,
        owner_decision: None,
        created_at_ms,
        source_proposal_path: proposal_path.display().to_string(),
        proposal,
    };
    record.validate()?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    fn root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "virtual_shift_review_{}_{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn proposal() -> serde_json::Value {
        serde_json::json!({
            "approval_status": "pending_review",
            "vs3": {
                "recommendation_id": "vsr-review-001",
                "anomaly_id": "anom-review-001",
                "source_node": "nodeB",
                "created_at_ms": 1000
            },
            "vs8": { "actions": [] },
            "vs9": { "human_summary": "test evidence" }
        })
    }

    fn queue(root: &Path) -> ReviewQueue {
        ReviewQueue::new(
            root.join("reviews"),
            RoleRegistry::from_json_str(r#"{"nodeA":"admin","nodeB":"member"}"#).unwrap(),
        )
    }

    fn write_proposal(root: &Path) -> PathBuf {
        let path = root.join("proposal.json");
        std::fs::create_dir_all(root).unwrap();
        std::fs::write(&path, serde_json::to_string_pretty(&proposal()).unwrap()).unwrap();
        path
    }

    fn ai_plan() -> AiRemediationPlan {
        AiRemediationPlan {
            plan_id: "plan-nodeA-001".into(),
            anomaly_id: "anom-nodeA-001".into(),
            source_node: "nodeA".into(),
            anomaly_score: 0.91,
            model_confidence: 0.88,
            severity: "High".into(),
            anomaly_metadata: serde_json::json!({
                "detector": "tier2_isolation_forest",
                "source_ip": "10.0.0.99",
                "target_ip": "10.0.0.25",
                "target_port": 3389
            }),
            justification: "Task 1 detected a high-confidence network anomaly; owner review is required before policy change.".into(),
            created_at_ms: 10_000,
            requires_approval: true,
            auto_execute: false,
            actions: vec![AiRemediationAction {
                action_type: "tighten_firewall_rules".into(),
                target: "nodeA".into(),
                parameters: serde_json::json!({
                    "protocol": "TCP",
                    "port": 3389,
                    "mode": "rate_limit"
                }),
                requires_approval: true,
                reason: "Restrict suspicious RDP-like exposure only after owner approval.".into(),
            }],
        }
    }

    #[test]
    fn authorized_owner_can_enqueue_list_and_show_complete_pending_review() {
        let root = root();
        let queue = queue(&root);
        let proposal = write_proposal(&root);
        let first = queue.enqueue_from_proposal(&proposal).unwrap();
        let second = queue.enqueue_from_proposal(&proposal).unwrap();
        assert_eq!(first, second); // idempotent retry
        let pending = queue.list_pending("nodeA").unwrap();
        assert_eq!(pending.len(), 1);
        let shown = queue.show("nodeA", "vsr-review-001").unwrap();
        assert!(shown.proposal.get("vs8").is_some());
        assert!(shown.proposal.get("vs9").is_some());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn member_cannot_list_or_show_owner_review_queue() {
        let root = root();
        let queue = queue(&root);
        assert!(queue.list_pending("nodeB").is_err());
        assert!(queue.show("nodeB", "vsr-review-001").is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn finalized_record_cannot_be_decided_or_requeued_again() {
        let root = root();
        let queue = queue(&root);
        let proposal = write_proposal(&root);
        let mut record = queue.enqueue_from_proposal(&proposal).unwrap();
        record
            .finalize(OwnerDecision {
                reviewer_id: "nodeA".into(),
                decision: ReviewStatus::Approved,
                reason: None,
                decided_at_ms: 2_000,
            })
            .unwrap();
        queue.write_record(&record).unwrap();
        assert!(record
            .finalize(OwnerDecision {
                reviewer_id: "nodeA".into(),
                decision: ReviewStatus::Rejected,
                reason: None,
                decided_at_ms: 3_000,
            })
            .is_err());
        assert!(queue.enqueue_from_proposal(&proposal).is_err());
        assert!(queue.list_pending("nodeA").unwrap().is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn ai_remediation_plan_is_persisted_as_pending_owner_review() {
        let root = root();
        let queue = queue(&root);
        let (record, handoff) = queue
            .enqueue_ai_remediation_plan(ai_plan(), "task1-live-runtime")
            .unwrap();

        assert_eq!(record.recommendation_id, "plan-nodeA-001");
        assert_eq!(record.status, ReviewStatus::PendingReview);
        assert_eq!(record.source_proposal_path, "task1-live-runtime");
        assert_eq!(
            record
                .proposal
                .get("task1_ai_remediation_plan")
                .and_then(|value| value.get("plan_id"))
                .and_then(serde_json::Value::as_str),
            Some("plan-nodeA-001")
        );
        assert_eq!(handoff.plan_id, "plan-nodeA-001");
        assert!(!handoff.duplicate);
        assert!(std::path::Path::new(&handoff.pending_review_path).is_file());

        let pending = queue.list_pending("nodeA").unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].recommendation_id, "plan-nodeA-001");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn ai_remediation_plan_handoff_is_idempotent_until_owner_decision() {
        let root = root();
        let queue = queue(&root);
        let (_, first) = queue
            .enqueue_ai_remediation_plan(ai_plan(), "task1-live-runtime")
            .unwrap();
        let (_, second) = queue
            .enqueue_ai_remediation_plan(ai_plan(), "task1-live-runtime")
            .unwrap();

        assert!(!first.duplicate);
        assert!(second.duplicate);
        assert_eq!(queue.list_pending("nodeA").unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn owner_approval_and_rejection_consume_the_same_persisted_plan_id() {
        let root = root();
        let review_queue = queue(&root);
        review_queue
            .enqueue_ai_remediation_plan(ai_plan(), "task1-live-runtime")
            .unwrap();
        let service = crate::virtual_shift::ApprovalService::new(review_queue.clone());

        let approved = service
            .approve(
                "nodeA",
                "plan-nodeA-001",
                Some("owner reviewed exact AI plan".into()),
                11_000,
            )
            .unwrap();
        assert_eq!(approved.status, ReviewStatus::Approved);
        assert_eq!(approved.recommendation_id, "plan-nodeA-001");
        assert_eq!(
            approved
                .proposal
                .get("task1_ai_remediation_plan")
                .and_then(|value| value.get("plan_id"))
                .and_then(serde_json::Value::as_str),
            Some("plan-nodeA-001")
        );
        assert!(review_queue.list_pending("nodeA").unwrap().is_empty());
        assert!(review_queue
            .enqueue_ai_remediation_plan(ai_plan(), "task1-live-runtime")
            .is_err());

        let reject_root = root.join("reject");
        let reject_queue = queue(&reject_root);
        reject_queue
            .enqueue_ai_remediation_plan(
                AiRemediationPlan {
                    plan_id: "plan-nodeA-002".into(),
                    anomaly_id: "anom-nodeA-002".into(),
                    ..ai_plan()
                },
                "task1-live-runtime",
            )
            .unwrap();
        let reject_service = crate::virtual_shift::ApprovalService::new(reject_queue.clone());
        let rejected = reject_service
            .reject(
                "nodeA",
                "plan-nodeA-002",
                Some("false positive after owner review".into()),
                12_000,
            )
            .unwrap();
        assert_eq!(rejected.status, ReviewStatus::Rejected);
        assert_eq!(
            crate::virtual_shift::ApprovalService::require_approved(&rejected)
                .unwrap_err()
                .to_string(),
            "recommendation 'plan-nodeA-002' is Rejected; only approved records may reach policy building"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn ai_remediation_plan_handoff_refuses_auto_execute_or_unapproved_actions() {
        let root = root();
        let queue = queue(&root);

        let mut auto = ai_plan();
        auto.auto_execute = true;
        assert!(queue
            .enqueue_ai_remediation_plan(auto, "task1-live-runtime")
            .is_err());

        let mut no_approval = ai_plan();
        no_approval.actions[0].requires_approval = false;
        assert!(queue
            .enqueue_ai_remediation_plan(no_approval, "task1-live-runtime")
            .is_err());
        let _ = std::fs::remove_dir_all(root);
    }
}
