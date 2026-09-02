//! VS11: authorised Circle Owner approval/rejection path.
//!
//! This module changes only the durable review lifecycle. It does not build,
//! sign, broadcast or apply a policy; those operations remain unavailable
//! until later Virtual Shift deliverables.

use super::{OwnerDecision, ReviewQueue, ReviewRecord, ReviewStatus};

/// VS11 service over the VS10 durable review queue.
#[derive(Debug, Clone)]
pub struct ApprovalService {
    queue: ReviewQueue,
}

impl ApprovalService {
    pub fn new(queue: ReviewQueue) -> Self {
        Self { queue }
    }

    pub fn approve(
        &self,
        reviewer_id: &str,
        recommendation_id: &str,
        reason: Option<String>,
        decided_at_ms: u64,
    ) -> anyhow::Result<ReviewRecord> {
        self.decide(
            reviewer_id,
            recommendation_id,
            ReviewStatus::Approved,
            reason,
            decided_at_ms,
        )
    }

    pub fn reject(
        &self,
        reviewer_id: &str,
        recommendation_id: &str,
        reason: Option<String>,
        decided_at_ms: u64,
    ) -> anyhow::Result<ReviewRecord> {
        self.decide(
            reviewer_id,
            recommendation_id,
            ReviewStatus::Rejected,
            reason,
            decided_at_ms,
        )
    }

    /// Later VS12 must call this guard before it can build any candidate
    /// policy. A rejected or pending record never reaches signing/broadcast.
    pub fn require_approved(record: &ReviewRecord) -> anyhow::Result<()> {
        if record.status != ReviewStatus::Approved {
            anyhow::bail!(
                "recommendation '{}' is {:?}; only approved records may reach policy building",
                record.recommendation_id,
                record.status
            );
        }
        Ok(())
    }

    fn decide(
        &self,
        reviewer_id: &str,
        recommendation_id: &str,
        status: ReviewStatus,
        reason: Option<String>,
        decided_at_ms: u64,
    ) -> anyhow::Result<ReviewRecord> {
        self.queue.require_authorised_owner(reviewer_id)?;
        let mut record = self.queue.show(reviewer_id, recommendation_id)?;
        record.finalize(OwnerDecision {
            reviewer_id: reviewer_id.to_owned(),
            decision: status,
            reason: reason.and_then(|value| (!value.trim().is_empty()).then_some(value)),
            decided_at_ms,
        })?;
        self.queue.write_record(&record)?;
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::roles::RoleRegistry;
    use crate::virtual_shift::{ReviewQueue, ReviewStatus};

    use super::*;

    static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    fn root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "virtual_shift_approval_{}_{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn queue(root: &Path) -> ReviewQueue {
        ReviewQueue::new(
            root.join("reviews"),
            RoleRegistry::from_json_str(r#"{"nodeA":"admin","nodeB":"member"}"#).unwrap(),
        )
    }

    fn enqueue(queue: &ReviewQueue, root: &Path) {
        let proposal = root.join("proposal.json");
        std::fs::create_dir_all(root).unwrap();
        std::fs::write(
            &proposal,
            serde_json::to_string_pretty(&serde_json::json!({
                "approval_status": "pending_review",
                "vs3": {
                    "recommendation_id": "vsr-approval-001",
                    "anomaly_id": "anom-approval-001",
                    "source_node": "nodeB",
                    "created_at_ms": 1000
                },
                "vs8": { "actions": [] },
                "vs9": { "human_summary": "test evidence" }
            }))
            .unwrap(),
        )
        .unwrap();
        queue.enqueue_from_proposal(proposal).unwrap();
    }

    #[test]
    fn authorised_owner_approval_is_persisted_with_identity_time_and_reason() {
        let root = root();
        let queue = queue(&root);
        enqueue(&queue, &root);
        let service = ApprovalService::new(queue.clone());
        let approved = service
            .approve(
                "nodeA",
                "vsr-approval-001",
                Some("Evidence reviewed; proceed to policy build.".into()),
                2_000,
            )
            .unwrap();
        assert_eq!(approved.status, ReviewStatus::Approved);
        assert_eq!(
            approved.owner_decision.as_ref().unwrap().reviewer_id,
            "nodeA"
        );
        assert!(queue.list_pending("nodeA").unwrap().is_empty());
        ApprovalService::require_approved(&approved).unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rejected_record_cannot_reach_policy_builder_guard() {
        let root = root();
        let queue = queue(&root);
        enqueue(&queue, &root);
        let service = ApprovalService::new(queue);
        let rejected = service
            .reject(
                "nodeA",
                "vsr-approval-001",
                Some("False positive.".into()),
                2_000,
            )
            .unwrap();
        assert_eq!(rejected.status, ReviewStatus::Rejected);
        assert!(ApprovalService::require_approved(&rejected).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn member_is_denied_and_finalized_record_cannot_be_decided_twice() {
        let root = root();
        let queue = queue(&root);
        enqueue(&queue, &root);
        let service = ApprovalService::new(queue);
        assert!(service
            .approve("nodeB", "vsr-approval-001", None, 2_000)
            .is_err());
        service
            .approve("nodeA", "vsr-approval-001", None, 2_000)
            .unwrap();
        assert!(service
            .reject("nodeA", "vsr-approval-001", None, 3_000)
            .is_err());
        let _ = std::fs::remove_dir_all(root);
    }
}
