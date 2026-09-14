//! Task 3 Deliverable 12: sensitive route changes are handed to Task2.
//!
//! Task3 can change only an already trusted, non-policy route through its
//! runtime controller. This module is the explicit boundary for a sensitive
//! change: it blocks direct application and persists the exact AI rationale
//! into the existing Task2 owner-review queue.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::virtual_shift::{AiRemediationAction, AiRemediationPlan, ReviewQueue, ReviewStatus};

pub const NETWORK_AI_SENSITIVE_ROUTE_HANDOFF_VERSION: &str =
    "network-ai-sensitive-route-handoff-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveRouteReason {
    NewUntrustedRelay,
    PolicyRuleChangeNeeded,
    CrossBoundaryRoute,
    QuarantinedMemberRecovery,
    SecurityExceptionRequired,
}

impl SensitiveRouteReason {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "new-untrusted-relay" => Some(Self::NewUntrustedRelay),
            "policy-rule-change-needed" | "policy-rule-change" => {
                Some(Self::PolicyRuleChangeNeeded)
            }
            "cross-boundary-route" => Some(Self::CrossBoundaryRoute),
            "quarantined-member-recovery" => Some(Self::QuarantinedMemberRecovery),
            "security-exception-required" | "security-exception" => {
                Some(Self::SecurityExceptionRequired)
            }
            _ => None,
        }
    }

    pub fn human_reason(&self) -> &'static str {
        match self {
            Self::NewUntrustedRelay => "the requested relay is not already trusted by Task2",
            Self::PolicyRuleChangeNeeded => "the route needs a policy rule change",
            Self::CrossBoundaryRoute => "the route crosses a protected network boundary",
            Self::QuarantinedMemberRecovery => {
                "the route would recover or use a quarantined member"
            }
            Self::SecurityExceptionRequired => "the route needs a security exception",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SensitiveRouteAuditRecord {
    pub schema_version: String,
    pub plan_id: String,
    pub ts_ms: u64,
    pub source_node: String,
    pub destination_node: String,
    pub requested_route_id: String,
    pub sensitive_reason: SensitiveRouteReason,
    pub ai_justification: String,
    pub direct_apply_blocked: bool,
    pub owner_approval_required: bool,
    pub task2_review_status: ReviewStatus,
    pub task2_pending_review_path: String,
    pub task2_audit_link: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SensitiveRouteHandoffResult {
    pub plan_id: String,
    pub direct_apply_blocked: bool,
    pub owner_approval_required: bool,
    pub review_status: ReviewStatus,
    pub pending_review_path: String,
    pub audit_record: SensitiveRouteAuditRecord,
}

/// Link record for the *next* Task3 decision cycle after a Task2 review and
/// authoritative trust-summary update. It makes the handoff, Task2 decision,
/// and later Task3 decision traceable without Task3 mutating Task2 policy or
/// trust state itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Task3PostTask2DecisionAudit {
    pub schema_version: String,
    pub handoff_plan_id: String,
    pub task2_review_id: String,
    pub task2_review_status: ReviewStatus,
    pub task2_trust_state_version: String,
    pub task2_trust_summary_path: String,
    pub later_task3_decision_id: String,
    pub requested_route_id: String,
    pub route_eligible: bool,
    pub route_applied: bool,
    pub outcome: String,
}

pub fn write_post_task2_decision_audit(
    path: impl AsRef<Path>,
    audit: &Task3PostTask2DecisionAudit,
) -> Result<()> {
    write_json(path.as_ref(), audit)
}

#[derive(Debug, Clone)]
pub struct SensitiveRouteHandoffService {
    task2_review_root: std::path::PathBuf,
    task2_role_config: String,
}

impl SensitiveRouteHandoffService {
    pub fn new(
        task2_review_root: impl Into<std::path::PathBuf>,
        task2_role_config: impl Into<String>,
    ) -> Self {
        Self {
            task2_review_root: task2_review_root.into(),
            task2_role_config: task2_role_config.into(),
        }
    }

    pub fn handoff(
        &self,
        ts_ms: u64,
        source_node: &str,
        destination_node: &str,
        requested_route_id: &str,
        sensitive_reason: SensitiveRouteReason,
        anomaly_score: f64,
        model_confidence: f64,
        audit_path: impl AsRef<Path>,
    ) -> Result<SensitiveRouteHandoffResult> {
        if ts_ms == 0 || source_node.trim().is_empty() || destination_node.trim().is_empty() {
            anyhow::bail!("sensitive route handoff requires timestamp, source and destination");
        }
        if !(0.0..=1.0).contains(&anomaly_score) || !(0.0..=1.0).contains(&model_confidence) {
            anyhow::bail!("sensitive route handoff score and confidence must be normalized");
        }
        let plan_id = format!(
            "task3-sensitive-route-{}-{}",
            ts_ms,
            file_safe_id(requested_route_id)
        );
        let justification = format!(
            "Task3 did not apply route '{}': {}; the exact route change requires Task2 owner/admin approval.",
            requested_route_id,
            sensitive_reason.human_reason()
        );
        let plan = AiRemediationPlan {
            plan_id: plan_id.clone(),
            anomaly_id: format!(
                "task3-route-{}-{}",
                file_safe_id(source_node),
                file_safe_id(destination_node)
            ),
            source_node: source_node.to_string(),
            anomaly_score,
            model_confidence,
            severity: "high".to_string(),
            anomaly_metadata: serde_json::json!({
                "producer": "task3-network-ai",
                "requested_route_id": requested_route_id,
                "destination_node": destination_node,
                "sensitive_reason": sensitive_reason,
                "direct_apply_blocked": true,
            }),
            justification: justification.clone(),
            created_at_ms: ts_ms,
            requires_approval: true,
            auto_execute: false,
            actions: vec![AiRemediationAction {
                action_type: "review_sensitive_route_change".to_string(),
                target: requested_route_id.to_string(),
                parameters: serde_json::json!({
                    "source_node": source_node,
                    "destination_node": destination_node,
                    "sensitive_reason": sensitive_reason,
                    "direct_apply_blocked": true,
                }),
                requires_approval: true,
                reason: justification.clone(),
            }],
        };
        let queue = ReviewQueue::from_role_config(&self.task2_review_root, &self.task2_role_config)
            .context("opening Task2 owner review queue for sensitive route handoff")?;
        let (_, handoff) = queue.enqueue_ai_remediation_plan(
            plan,
            format!(
                "Task3 sensitive-route audit: {}",
                audit_path.as_ref().display()
            ),
        )?;
        let audit = SensitiveRouteAuditRecord {
            schema_version: NETWORK_AI_SENSITIVE_ROUTE_HANDOFF_VERSION.to_string(),
            plan_id: plan_id.clone(),
            ts_ms,
            source_node: source_node.to_string(),
            destination_node: destination_node.to_string(),
            requested_route_id: requested_route_id.to_string(),
            sensitive_reason,
            ai_justification: justification,
            direct_apply_blocked: true,
            owner_approval_required: true,
            task2_review_status: handoff.review_status,
            task2_pending_review_path: handoff.pending_review_path.clone(),
            task2_audit_link: format!("Task2 ReviewQueue recommendation_id={plan_id}"),
        };
        write_json(audit_path.as_ref(), &audit)?;
        Ok(SensitiveRouteHandoffResult {
            plan_id,
            direct_apply_blocked: true,
            owner_approval_required: true,
            review_status: handoff.review_status,
            pending_review_path: handoff.pending_review_path,
            audit_record: audit,
        })
    }
}

fn file_safe_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "creating sensitive route audit directory {}",
                parent.display()
            )
        })?;
    }
    fs::write(
        path,
        serde_json::to_string_pretty(value).context("serializing sensitive route audit")?,
    )
    .with_context(|| format!("writing sensitive route audit {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_ai::RouteSwitchState;
    use crate::network_ai::{
        read_task2_trust_summary, EligibilityFilter, RouteCandidateInventory,
        RuntimeRouteApplyRequest, RuntimeRouteState, SafeRuntimeRouteController, TrafficClass,
    };
    use crate::virtual_shift::{ApprovalService, ReviewQueue};

    fn temp_root(test_name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "network-ai-sensitive-{test_name}-{}",
            std::process::id()
        ))
    }

    #[test]
    fn sensitive_route_is_blocked_and_persisted_in_task2_pending_review() {
        let root = temp_root("handoff");
        let review_root = root.join("task2_reviews");
        let roles = root.join("node_roles.json");
        fs::create_dir_all(&root).unwrap();
        fs::write(&roles, r#"{"nodeA":"admin","nodeB":"member"}"#).unwrap();
        let audit_path = root.join("task3_sensitive_route_audit.json");
        let result = SensitiveRouteHandoffService::new(&review_root, roles.display().to_string())
            .handoff(
                1000,
                "nodeA",
                "nodeB",
                "relay-nodeA-via-nodeZ-nodeB",
                SensitiveRouteReason::NewUntrustedRelay,
                0.8,
                0.9,
                &audit_path,
            )
            .unwrap();

        assert!(result.direct_apply_blocked);
        assert!(result.owner_approval_required);
        assert_eq!(result.review_status, ReviewStatus::PendingReview);
        assert!(std::path::Path::new(&result.pending_review_path).exists());
        assert!(audit_path.exists());
        let review = fs::read_to_string(&result.pending_review_path).unwrap();
        assert!(review.contains("review_sensitive_route_change"));
        assert!(review.contains("direct_apply_blocked"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn sensitive_reason_parser_only_accepts_explicit_cases() {
        assert_eq!(
            SensitiveRouteReason::parse("cross-boundary-route"),
            Some(SensitiveRouteReason::CrossBoundaryRoute)
        );
        assert_eq!(SensitiveRouteReason::parse("anything"), None);
    }

    #[test]
    fn task2_decision_updates_fresh_task3_cycle_for_approved_and_rejected_routes() {
        let root = temp_root("post-task2-cycle");
        let review_root = root.join("task2_reviews");
        let roles = root.join("node_roles.json");
        fs::create_dir_all(&root).unwrap();
        fs::write(&roles, r#"{"nodeA":"admin","nodeB":"member"}"#).unwrap();

        for (route_id, relay, approve, timestamp) in [
            ("relay-nodeA-via-nodeZ-nodeB", "nodeZ", true, 200_000_u64),
            ("relay-nodeA-via-nodeY-nodeB", "nodeY", false, 300_000_u64),
        ] {
            let branch = if approve { "approved" } else { "rejected" };
            let handoff =
                SensitiveRouteHandoffService::new(&review_root, roles.display().to_string())
                    .handoff(
                        timestamp,
                        "nodeA",
                        "nodeB",
                        route_id,
                        SensitiveRouteReason::NewUntrustedRelay,
                        0.85,
                        0.90,
                        root.join(branch).join("handoff.json"),
                    )
                    .unwrap();
            let queue =
                ReviewQueue::from_role_config(&review_root, &roles.display().to_string()).unwrap();
            let approval = ApprovalService::new(queue);
            let review = if approve {
                approval
                    .approve(
                        "nodeA",
                        &handoff.plan_id,
                        Some("approved".into()),
                        timestamp + 1,
                    )
                    .unwrap()
            } else {
                approval
                    .reject(
                        "nodeA",
                        &handoff.plan_id,
                        Some("rejected".into()),
                        timestamp + 1,
                    )
                    .unwrap()
            };

            let trust_path = root.join(branch).join("task2_routing_trust_summary.json");
            let summary = serde_json::json!({
                "schema_version": 1,
                "node_id": "nodeB",
                "trust_status": "trusted",
                "routing_allowed": true,
                "policy_status": "task2_owner_decision_recorded",
                "active_policy_id": format!("task2-review-{}", review.recommendation_id),
                "active_policy_version": 1,
                "applicable_members": if approve { vec![relay] } else { Vec::<&str>::new() },
                "policy_restrictions": [],
                "last_alert_id": serde_json::Value::Null,
                "attestation_state": "trusted",
                "updated_at_ms": timestamp + 2
            });
            write_json(&trust_path, &summary).unwrap();
            let latest_task2 = read_task2_trust_summary(&trust_path).unwrap();
            let inventory = RouteCandidateInventory::from_relays(
                "nodeA",
                "nodeB",
                TrafficClass::SecurityControl,
                [relay],
            );
            let eligible = EligibilityFilter.filter_at(
                inventory.candidates,
                &latest_task2.to_trust_snapshot(),
                timestamp + 3,
            );
            let mut runtime_state = RuntimeRouteState::from_switch_state(&RouteSwitchState {
                current_route_id: "direct-nodeA-nodeB".into(),
                current_route_started_ms: timestamp.saturating_sub(60_000),
                last_switch_ms: Some(timestamp.saturating_sub(30_000)),
                switch_timestamps_ms: vec![timestamp.saturating_sub(30_000)],
            });
            let applied = SafeRuntimeRouteController::default().apply(
                &mut runtime_state,
                &eligible,
                &RuntimeRouteApplyRequest {
                    ts_ms: timestamp + 3,
                    requested_route_id: route_id.into(),
                    current_score: 40.0,
                    candidate_score: 60.0,
                    current_route_failed: false,
                    transport_apply_succeeds: true,
                    selected_by: "d12-integration-test".into(),
                    observed_rtt_ms: 12.0,
                    observed_packet_loss_pct: 0.2,
                    observed_throughput_mbps: 60.0,
                    observed_bandwidth_utilization_pct: 35.0,
                    observed_reward: Some(8.0),
                },
            );
            let route_is_eligible = eligible
                .eligible
                .iter()
                .any(|candidate| candidate.route_id == route_id);
            assert_eq!(review.status == ReviewStatus::Approved, approve);
            assert_eq!(
                route_is_eligible, approve,
                "fresh Task2 summary must control later Task3 eligibility"
            );
            assert_eq!(
                applied.audit.apply_result.applied, approve,
                "Task3 must apply only the route trusted by latest Task2 state"
            );
        }
        let _ = fs::remove_dir_all(root);
    }
}
