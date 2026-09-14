//! Task 3 Deliverable 9: Task 2 Virtual Shift trust-state bridge.

use super::eligibility::TrustStateSnapshot;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Task2RoutingTrustSummary {
    pub schema_version: u32,
    pub node_id: String,
    pub trust_status: String,
    pub routing_allowed: bool,
    pub policy_status: String,
    pub active_policy_id: Option<String>,
    pub active_policy_version: Option<u64>,
    pub applicable_members: Vec<String>,
    pub policy_restrictions: Vec<String>,
    pub last_alert_id: Option<String>,
    pub attestation_state: String,
    pub updated_at_ms: u64,
    #[serde(default)]
    pub sources: Task2TrustStateSources,
}

/// Read-only provenance emitted by the existing Virtual Shift writer. Task3
/// stores these links for audit only; it never writes to any Task2 state file.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Task2TrustStateSources {
    pub active_policy_path: Option<String>,
    pub latest_apply_result_path: Option<String>,
    pub identity_state_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OptionalTask2RoutingTrust {
    pub summary: Option<Task2RoutingTrustSummary>,
    pub status: String,
}

impl Task2RoutingTrustSummary {
    pub fn to_trust_snapshot(&self) -> TrustStateSnapshot {
        let version = format!(
            "task2:{}:{}",
            self.active_policy_id.as_deref().unwrap_or("no-policy"),
            self.updated_at_ms
        );
        let mut snapshot = TrustStateSnapshot::new(version)
            .observed_at(self.updated_at_ms)
            .max_age(300_000);
        if self.routing_allowed
            && self.trust_status.eq_ignore_ascii_case("trusted")
            && self.attestation_state.eq_ignore_ascii_case("trusted")
        {
            snapshot = snapshot.trust_peer(&self.node_id);
            for member in &self.applicable_members {
                snapshot = snapshot.trust_peer(member);
            }
        } else {
            snapshot = snapshot.quarantine_peer(&self.node_id);
        }
        snapshot
    }
}

pub fn read_task2_trust_summary(path: impl AsRef<Path>) -> Result<Task2RoutingTrustSummary> {
    let path = path.as_ref();
    let json = std::fs::read_to_string(path)
        .with_context(|| format!("reading Task2 routing trust summary {}", path.display()))?;
    serde_json::from_str(&json).context("parsing Task2 routing trust summary")
}

/// Task2 is the authority for trust and policy. If its summary is unavailable
/// or malformed, Task3 must fail closed through `TrustStateSnapshot::missing`.
pub fn read_optional_task2_trust_summary(path: Option<&Path>) -> OptionalTask2RoutingTrust {
    let Some(path) = path else {
        return OptionalTask2RoutingTrust {
            summary: None,
            status: "Task2 trust state unavailable: safe fallback active".to_string(),
        };
    };
    match read_task2_trust_summary(path) {
        Ok(summary) => OptionalTask2RoutingTrust {
            summary: Some(summary),
            status: "Latest Task2 routing trust summary consumed read-only".to_string(),
        },
        Err(error) => OptionalTask2RoutingTrust {
            summary: None,
            status: format!("Task2 trust state ignored safely: {error}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_summary_becomes_trusted_snapshot() {
        let summary = Task2RoutingTrustSummary {
            schema_version: 1,
            node_id: "nodeB".to_string(),
            trust_status: "trusted".to_string(),
            routing_allowed: true,
            policy_status: "applied".to_string(),
            active_policy_id: Some("policy-1".to_string()),
            active_policy_version: Some(1),
            applicable_members: vec!["nodeB".to_string(), "nodeC".to_string()],
            policy_restrictions: vec![],
            last_alert_id: None,
            attestation_state: "trusted".to_string(),
            updated_at_ms: 10,
            sources: Task2TrustStateSources::default(),
        };

        let snapshot = summary.to_trust_snapshot();

        assert!(snapshot.trusted_peers.contains("nodeB"));
        assert!(snapshot.trusted_peers.contains("nodeC"));
        assert!(snapshot.quarantined_peers.is_empty());
        assert_eq!(snapshot.observed_at_ms, Some(10));
        assert_eq!(snapshot.max_age_ms, Some(300_000));
    }

    #[test]
    fn blocked_summary_quarantines_node() {
        let summary = Task2RoutingTrustSummary {
            schema_version: 1,
            node_id: "nodeB".to_string(),
            trust_status: "quarantined".to_string(),
            routing_allowed: false,
            policy_status: "applied".to_string(),
            active_policy_id: None,
            active_policy_version: None,
            applicable_members: vec![],
            policy_restrictions: vec![],
            last_alert_id: None,
            attestation_state: "untrusted".to_string(),
            updated_at_ms: 10,
            sources: Task2TrustStateSources::default(),
        };

        let snapshot = summary.to_trust_snapshot();

        assert!(snapshot.quarantined_peers.contains("nodeB"));
        assert!(!snapshot.trusted_peers.contains("nodeB"));
    }

    #[test]
    fn missing_or_malformed_summary_fails_closed_without_crashing() {
        let dir =
            std::env::temp_dir().join(format!("task2-bridge-optional-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bad = dir.join("routing_trust_summary.json");
        std::fs::write(&bad, "not-json").unwrap();

        let result = read_optional_task2_trust_summary(Some(&bad));
        assert!(result.summary.is_none());
        assert!(result.status.contains("ignored safely"));
        assert!(read_optional_task2_trust_summary(None).summary.is_none());
        let _ = std::fs::remove_dir_all(dir);
    }
}
