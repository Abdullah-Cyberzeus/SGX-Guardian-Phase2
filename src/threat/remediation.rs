//! Contextual Remediation Plan Generator
//! Maps `AlertAnomalyScore` and `ThreatCategory` to concrete, structured remediation plans.

use crate::threat::{alert_scorer::AlertAnomalyScore, threat_alert::ThreatCategory};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Specific remediation action types supported by SG-X Guardian.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ActionType {
    /// Add an ephemeral nftables drop rule for the specified duration.
    NftablesBlockIp { duration_secs: u64 },
    /// Mark a Circle peer node as untrusted and invalidate its VirtualID.
    QuarantinePeer { peer_id: String },
    /// Reduce the mutual software attestation interval for security posture hardening.
    TightenAttestation { interval_secs: u64 },
    /// Propose a signed Universal Edge Processing (UEP) policy update.
    ProposePolicyUpdate { rule_delta: String },
    /// Enable high-verbosity packet capture / debug logging on an interface.
    EnableDebugLogging { interface: String },
    /// Log an advisory without executing automated network or policy changes.
    AlertOnly,
}

impl fmt::Display for ActionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActionType::NftablesBlockIp { duration_secs } => {
                write!(f, "NftablesBlockIp({}s)", duration_secs)
            }
            ActionType::QuarantinePeer { peer_id } => {
                write!(f, "QuarantinePeer({})", peer_id)
            }
            ActionType::TightenAttestation { interval_secs } => {
                write!(f, "TightenAttestation({}s)", interval_secs)
            }
            ActionType::ProposePolicyUpdate { rule_delta } => {
                write!(f, "ProposePolicyUpdate(\"{}\")", rule_delta)
            }
            ActionType::EnableDebugLogging { interface } => {
                write!(f, "EnableDebugLogging({})", interface)
            }
            ActionType::AlertOnly => write!(f, "AlertOnly"),
        }
    }
}

/// A complete remediation plan generated for a detected anomaly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RemediationPlan {
    /// Unique identifier for this remediation plan.
    pub plan_id: String,
    /// Anomaly score that triggered this remediation plan.
    pub score: AlertAnomalyScore,
    /// Target IP address to apply network/policy actions against.
    pub target_ip: String,
    /// Actions that can be executed automatically without human intervention.
    pub auto_execute: Vec<ActionType>,
    /// Actions requiring explicit administrator approval via CLI or REST API.
    pub requires_approval: Vec<ActionType>,
    /// Human-readable explanation and rationale for the recommended actions.
    pub justification: String,
    /// Timestamp when this plan was created.
    pub created_at: DateTime<Utc>,
}

/// Generates a `RemediationPlan` for a given `AlertAnomalyScore`.
/// Returns `None` if the score is below the minimum threshold (0.50).
pub fn generate_plan(score: AlertAnomalyScore) -> Option<RemediationPlan> {
    if score.score < 0.50 {
        return None;
    }

    let plan_id = Uuid::new_v4().to_string();
    let target_ip = score.contributing_ip.clone();
    let justification = build_justification(&score);

    let auto_execute = vec![ActionType::AlertOnly];
    let mut requires_approval = Vec::new();

    // All actions are recommendations — nothing executes automatically.
    // The administrator reviews and approves/rejects via CLI or REST API.
    if score.score >= 0.50 && score.score < 0.75 {
        // Suspicious: recommend monitoring only, no network changes yet.
        requires_approval.push(ActionType::EnableDebugLogging {
            interface: "eth0".to_string(),
        });
    } else {
        match score.category {
            ThreatCategory::Reconnaissance => {
                let duration = if score.score >= 0.90 { 3600 } else { 1800 };
                requires_approval.push(ActionType::NftablesBlockIp {
                    duration_secs: duration,
                });
                requires_approval.push(ActionType::EnableDebugLogging {
                    interface: "eth0".to_string(),
                });
                requires_approval.push(ActionType::ProposePolicyUpdate {
                    rule_delta: format!("deny ip saddr {} drop;", target_ip),
                });
                if score.score >= 0.90 {
                    requires_approval.push(ActionType::TightenAttestation { interval_secs: 30 });
                }
            }
            ThreatCategory::Exploit => {
                requires_approval.push(ActionType::NftablesBlockIp {
                    duration_secs: 86400,
                });
                requires_approval.push(ActionType::QuarantinePeer {
                    peer_id: format!("peer-{}", target_ip),
                });
                requires_approval.push(ActionType::ProposePolicyUpdate {
                    rule_delta: format!("deny ip saddr {} drop;", target_ip),
                });
                if score.score >= 0.90 {
                    requires_approval.push(ActionType::TightenAttestation { interval_secs: 30 });
                }
            }
            ThreatCategory::Malware => {
                requires_approval.push(ActionType::NftablesBlockIp {
                    duration_secs: 86400,
                });
                requires_approval.push(ActionType::QuarantinePeer {
                    peer_id: format!("peer-{}", target_ip),
                });
                requires_approval.push(ActionType::ProposePolicyUpdate {
                    rule_delta: format!("deny ip saddr {} drop;", target_ip),
                });
            }
            ThreatCategory::PolicyViolation => {
                requires_approval.push(ActionType::EnableDebugLogging {
                    interface: "eth0".to_string(),
                });
                requires_approval.push(ActionType::ProposePolicyUpdate {
                    rule_delta: format!("deny ip saddr {} drop;", target_ip),
                });
            }
            ThreatCategory::AttestationMismatch => {
                requires_approval.push(ActionType::TightenAttestation { interval_secs: 15 });
                requires_approval.push(ActionType::QuarantinePeer {
                    peer_id: format!("peer-{}", target_ip),
                });
                requires_approval.push(ActionType::EnableDebugLogging {
                    interface: "eth0".to_string(),
                });
            }
            ThreatCategory::CertificateIssue => {
                requires_approval.push(ActionType::ProposePolicyUpdate {
                    rule_delta: format!("renew_or_rotate_cert for {};", target_ip),
                });
                requires_approval.push(ActionType::EnableDebugLogging {
                    interface: "eth0".to_string(),
                });
            }
            ThreatCategory::Anomaly => {
                requires_approval.push(ActionType::TightenAttestation { interval_secs: 30 });
                requires_approval.push(ActionType::ProposePolicyUpdate {
                    rule_delta: format!("deny ip saddr {} drop;", target_ip),
                });
            }
            ThreatCategory::Other => {
                requires_approval.push(ActionType::NftablesBlockIp {
                    duration_secs: 1800,
                });
                requires_approval.push(ActionType::EnableDebugLogging {
                    interface: "eth0".to_string(),
                });
            }
        }
    }

    Some(RemediationPlan {
        plan_id,
        score,
        target_ip,
        auto_execute,
        requires_approval,
        justification,
        created_at: Utc::now(),
    })
}

/// Constructs a natural-language justification string for an anomaly score.
pub fn build_justification(score: &AlertAnomalyScore) -> String {
    let severity_label = if score.score >= 0.90 {
        "CRITICAL"
    } else if score.score >= 0.75 {
        "ELEVATED"
    } else {
        "SUSPICIOUS"
    };

    format!(
        "Source IP {} triggered {} alerts in {}s (normal baseline: 3/min). Top signature: SID {}. Anomaly score {:.2} ({}). Category: {}.",
        score.contributing_ip,
        score.alert_count,
        score.window_secs,
        score.top_signature_id,
        score.score,
        severity_label,
        score.category.as_str()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_score(val: f32, cat: ThreatCategory) -> AlertAnomalyScore {
        AlertAnomalyScore {
            score: val,
            contributing_ip: "192.168.1.105".to_string(),
            alert_count: 50,
            top_signature_id: 2009358,
            category: cat,
            computed_at: Utc::now(),
            window_secs: 300,
        }
    }

    #[test]
    fn test_no_plan_below_threshold() {
        let score = make_score(0.40, ThreatCategory::Reconnaissance);
        assert!(generate_plan(score).is_none());
    }

    #[test]
    fn test_alert_only_at_suspicious() {
        let score = make_score(0.60, ThreatCategory::Reconnaissance);
        let plan = generate_plan(score).expect("should generate plan");

        // auto_execute is always exactly [AlertOnly] — system never acts automatically
        assert_eq!(plan.auto_execute.len(), 1);
        assert_eq!(plan.auto_execute[0], ActionType::AlertOnly);
        // At suspicious level, we recommend debug logging
        assert!(plan
            .requires_approval
            .contains(&ActionType::EnableDebugLogging {
                interface: "eth0".to_string()
            }));
    }

    #[test]
    fn test_block_at_elevated_reconnaissance() {
        let score = make_score(0.80, ThreatCategory::Reconnaissance);
        let plan = generate_plan(score).expect("should generate plan");

        // Block must be in requires_approval, NOT auto_execute
        assert!(!plan.auto_execute.contains(&ActionType::NftablesBlockIp {
            duration_secs: 1800
        }));
        assert!(plan.requires_approval.contains(&ActionType::NftablesBlockIp {
            duration_secs: 1800
        }));
        assert!(plan
            .requires_approval
            .iter()
            .any(|a| matches!(a, ActionType::ProposePolicyUpdate { .. })));
    }

    #[test]
    fn test_quarantine_requires_approval() {
        let score = make_score(0.85, ThreatCategory::Exploit);
        let plan = generate_plan(score).expect("should generate plan");

        // Quarantine must NEVER be auto-executed for exploits
        assert!(!plan
            .auto_execute
            .iter()
            .any(|a| matches!(a, ActionType::QuarantinePeer { .. })));
        assert!(plan
            .requires_approval
            .iter()
            .any(|a| matches!(a, ActionType::QuarantinePeer { .. })));
    }

    #[test]
    fn test_justification_nonempty() {
        let score = make_score(0.92, ThreatCategory::Malware);
        let plan = generate_plan(score).expect("should generate plan");

        assert!(!plan.justification.is_empty());
        assert!(plan.justification.contains("192.168.1.105"));
        assert!(plan.justification.contains("CRITICAL"));
    }

    #[test]
    fn test_plan_id_unique() {
        let score1 = make_score(0.85, ThreatCategory::Anomaly);
        let score2 = make_score(0.85, ThreatCategory::Anomaly);

        let plan1 = generate_plan(score1).unwrap();
        let plan2 = generate_plan(score2).unwrap();

        assert_ne!(plan1.plan_id, plan2.plan_id);
    }

    #[test]
    fn test_attestation_mismatch_recommendations() {
        let score = make_score(0.85, ThreatCategory::AttestationMismatch);
        let plan = generate_plan(score).expect("should generate plan");

        assert_eq!(plan.auto_execute.len(), 1);
        assert_eq!(plan.auto_execute[0], ActionType::AlertOnly);
        assert!(plan
            .requires_approval
            .contains(&ActionType::TightenAttestation { interval_secs: 15 }));
        assert!(plan
            .requires_approval
            .iter()
            .any(|a| matches!(a, ActionType::QuarantinePeer { .. })));
    }

    #[test]
    fn test_certificate_issue_recommendations() {
        let score = make_score(0.80, ThreatCategory::CertificateIssue);
        let plan = generate_plan(score).expect("should generate plan");

        assert_eq!(plan.auto_execute.len(), 1);
        assert_eq!(plan.auto_execute[0], ActionType::AlertOnly);
        assert!(plan
            .requires_approval
            .iter()
            .any(|a| matches!(a, ActionType::ProposePolicyUpdate { .. })));
    }
}
