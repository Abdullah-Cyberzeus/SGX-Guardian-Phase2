//! Remediation plan generator for Task 1 anomaly scores.
//!
//! The current SGX runtime uses the shared advisory store for persistence, but
//! this module keeps the Task 1 response policy available in a dedicated folder
//! so the scoring pipeline can be exercised end-to-end.

use crate::task1_ai::scorer::AlertAnomalyScore;
use crate::task1_ai::thresholds::Task1ThresholdSettings;
use crate::threat::threat_alert::ThreatCategory;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Specific remediation action types supported by SG-X Guardian.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ActionType {
    NftablesBlockIp { duration_secs: u64 },
    QuarantinePeer { peer_id: String },
    TightenAttestation { interval_secs: u64 },
    ProposePolicyUpdate { rule_delta: String },
    EnableDebugLogging { interface: String },
    AlertOnly,
}

impl fmt::Display for ActionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActionType::NftablesBlockIp { duration_secs } => {
                write!(f, "NftablesBlockIp({}s)", duration_secs)
            }
            ActionType::QuarantinePeer { peer_id } => write!(f, "QuarantinePeer({})", peer_id),
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
    pub plan_id: String,
    pub score: AlertAnomalyScore,
    pub target_ip: String,
    pub auto_execute: Vec<ActionType>,
    pub requires_approval: Vec<ActionType>,
    pub justification: String,
    pub created_at: DateTime<Utc>,
}

/// Generates a `RemediationPlan` for a given `AlertAnomalyScore`.
/// Returns `None` if the score is below the active detection threshold.
pub fn generate_plan(score: AlertAnomalyScore) -> Option<RemediationPlan> {
    generate_plan_with_thresholds(score, &Task1ThresholdSettings::default_settings())
}

pub fn generate_plan_with_thresholds(
    score: AlertAnomalyScore,
    thresholds: &Task1ThresholdSettings,
) -> Option<RemediationPlan> {
    if score.score < thresholds.detection_threshold {
        return None;
    }

    let plan_id = Uuid::new_v4().to_string();
    let target_ip = score.contributing_ip.clone();
    let justification = build_justification_with_thresholds(&score, thresholds);

    let auto_execute = vec![ActionType::AlertOnly];
    let mut requires_approval = Vec::new();

    // The plan remains advisory-only. The administrator approves the actual
    // policy and quarantine actions through the existing API/CLI workflow.
    if score.score >= thresholds.detection_threshold && score.score < thresholds.high_threshold {
        requires_approval.push(ActionType::EnableDebugLogging {
            interface: "eth0".to_string(),
        });
    } else {
        match score.category {
            ThreatCategory::Reconnaissance => {
                let duration = if score.score >= thresholds.critical_threshold {
                    3600
                } else {
                    1800
                };
                requires_approval.push(ActionType::NftablesBlockIp {
                    duration_secs: duration,
                });
                requires_approval.push(ActionType::EnableDebugLogging {
                    interface: "eth0".to_string(),
                });
                requires_approval.push(ActionType::ProposePolicyUpdate {
                    rule_delta: format!("deny ip saddr {} drop;", target_ip),
                });
                if score.score >= thresholds.critical_threshold {
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
                if score.score >= thresholds.critical_threshold {
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
            ThreatCategory::Anomaly => {
                requires_approval.push(ActionType::TightenAttestation { interval_secs: 30 });
                requires_approval.push(ActionType::ProposePolicyUpdate {
                    rule_delta: format!("virtual_shift: tighten policy for {};", target_ip),
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

pub fn build_justification(score: &AlertAnomalyScore) -> String {
    build_justification_with_thresholds(score, &Task1ThresholdSettings::default_settings())
}

pub fn build_justification_with_thresholds(
    score: &AlertAnomalyScore,
    thresholds: &Task1ThresholdSettings,
) -> String {
    let severity_label = if score.score >= thresholds.critical_threshold {
        "CRITICAL"
    } else if score.score >= thresholds.high_threshold {
        "ELEVATED"
    } else {
        "SUSPICIOUS"
    };

    format!(
        "Source IP {} triggered {} alerts in {}s. Top signature: SID {}. Anomaly score {:.2} ({}). Category: {}.",
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
            model_confidence: 0.82,
            scoring_runtime: crate::advisory::AnomalyScoringRuntime {
                engine_source: "sgx-threat-service".to_string(),
                scorer_source: "task1-alert-scorer".to_string(),
                model_kind: crate::advisory::AnomalyScoringRuntimeModelKind::Heuristic,
                model_artifact: None,
                model_version: Some("task1-alert-scorer".to_string()),
                fallback: true,
                fallback_reason: Some(
                    "Historical Task 1 ML runtime is not wired into this SGX path; the heuristic alert scorer remains active."
                        .to_string(),
                ),
                baseline: None,
            },
            contributing_ip: "192.168.1.105".to_string(),
            alert_count: 50,
            top_signature_id: 2009358,
            top_signature_count: 40,
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
        assert_eq!(plan.auto_execute, vec![ActionType::AlertOnly]);
        assert!(plan
            .requires_approval
            .contains(&ActionType::EnableDebugLogging {
                interface: "eth0".to_string()
            }));
        assert!(plan.justification.contains("SUSPICIOUS"));
    }

    #[test]
    fn test_block_at_elevated_reconnaissance() {
        let score = make_score(0.80, ThreatCategory::Reconnaissance);
        let plan = generate_plan(score).expect("should generate plan");

        assert!(plan
            .requires_approval
            .contains(&ActionType::NftablesBlockIp {
                duration_secs: 1800
            }));
        assert!(plan
            .requires_approval
            .iter()
            .any(|action| matches!(action, ActionType::ProposePolicyUpdate { .. })));
        assert!(plan.requires_approval.iter().any(|action| {
            matches!(action, ActionType::EnableDebugLogging { interface } if interface == "eth0")
        }));
    }

    #[test]
    fn test_high_score_adds_tighten_attestation() {
        let score = make_score(0.95, ThreatCategory::Exploit);
        let plan = generate_plan(score).expect("should generate plan");
        assert!(plan
            .requires_approval
            .iter()
            .any(|action| matches!(action, ActionType::TightenAttestation { .. })));
    }

    #[test]
    fn test_anomaly_category_requests_virtual_shift_update() {
        let score = make_score(0.93, ThreatCategory::Anomaly);
        let plan = generate_plan(score).expect("should generate plan");

        assert_eq!(plan.auto_execute, vec![ActionType::AlertOnly]);
        assert!(plan
            .requires_approval
            .contains(&ActionType::TightenAttestation { interval_secs: 30 }));
        assert!(plan.requires_approval.iter().any(|action| {
            matches!(
                action,
                ActionType::ProposePolicyUpdate { rule_delta }
                if rule_delta == "virtual_shift: tighten policy for 192.168.1.105;"
            )
        }));
        assert!(plan.justification.contains("CRITICAL"));
    }

    #[test]
    fn configurable_thresholds_shift_response_bands() {
        let thresholds = Task1ThresholdSettings {
            detection_threshold: 0.60,
            high_threshold: 0.85,
            critical_threshold: 0.97,
            ..Task1ThresholdSettings::default_settings()
        };
        let score = make_score(0.80, ThreatCategory::Reconnaissance);
        let plan = generate_plan_with_thresholds(score, &thresholds).expect("should generate plan");

        assert!(plan
            .requires_approval
            .contains(&ActionType::EnableDebugLogging {
                interface: "eth0".to_string()
            }));
        assert!(!plan
            .requires_approval
            .iter()
            .any(|action| { matches!(action, ActionType::NftablesBlockIp { .. }) }));
        assert!(plan.justification.contains("SUSPICIOUS"));
    }

    #[test]
    fn test_other_category_stays_local_only() {
        let score = make_score(0.78, ThreatCategory::Other);
        let plan = generate_plan(score).expect("should generate plan");

        assert_eq!(plan.auto_execute, vec![ActionType::AlertOnly]);
        assert!(plan
            .requires_approval
            .contains(&ActionType::NftablesBlockIp {
                duration_secs: 1800
            }));
        assert!(plan.requires_approval.iter().any(|action| {
            matches!(action, ActionType::EnableDebugLogging { interface } if interface == "eth0")
        }));
        assert!(plan.justification.contains("ELEVATED"));
    }

    #[test]
    fn test_malware_category_requests_long_block_and_quarantine() {
        let score = make_score(0.91, ThreatCategory::Malware);
        let plan = generate_plan(score).expect("should generate plan");

        assert_eq!(plan.auto_execute, vec![ActionType::AlertOnly]);
        assert!(plan
            .requires_approval
            .contains(&ActionType::NftablesBlockIp {
                duration_secs: 86400
            }));
        assert!(plan
            .requires_approval
            .contains(&ActionType::QuarantinePeer {
                peer_id: "peer-192.168.1.105".to_string()
            }));
        assert!(plan.requires_approval.iter().any(|action| {
            matches!(
                action,
                ActionType::ProposePolicyUpdate { rule_delta }
                if rule_delta == "deny ip saddr 192.168.1.105 drop;"
            )
        }));
        assert!(plan.justification.contains("CRITICAL"));
    }

    #[test]
    fn test_policy_violation_category_requests_logging_and_policy_update() {
        let score = make_score(0.80, ThreatCategory::PolicyViolation);
        let plan = generate_plan(score).expect("should generate plan");

        assert_eq!(plan.auto_execute, vec![ActionType::AlertOnly]);
        assert!(plan
            .requires_approval
            .contains(&ActionType::EnableDebugLogging {
                interface: "eth0".to_string()
            }));
        assert!(plan.requires_approval.iter().any(|action| {
            matches!(
                action,
                ActionType::ProposePolicyUpdate { rule_delta }
                if rule_delta == "deny ip saddr 192.168.1.105 drop;"
            )
        }));
        assert!(plan.justification.contains("ELEVATED"));
    }
}
