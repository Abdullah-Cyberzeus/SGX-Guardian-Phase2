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
}
