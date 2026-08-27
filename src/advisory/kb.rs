use crate::advisory::errors::{AdvisoryError, AdvisoryResult};
use crate::advisory::model::RemediationStep;
use crate::threat::threat_alert::Severity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecommendationRules {
    #[serde(default)]
    pub rules: Vec<RecommendationRule>,
    pub fallback: RecommendationTemplate,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecommendationRule {
    #[serde(rename = "match")]
    pub rule_match: RuleMatch,
    pub title: String,
    pub summary: String,
    #[serde(default)]
    pub steps: Vec<RuleStep>,
    #[serde(default)]
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleMatch {
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub signature_contains: Option<String>,
    #[serde(default)]
    pub severity_at_least: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecommendationTemplate {
    pub title: String,
    pub summary: String,
    #[serde(default)]
    pub steps: Vec<RuleStep>,
    #[serde(default)]
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleStep {
    pub action: String,
    pub rationale: String,
    pub automatable: bool,
}

impl RecommendationRules {
    pub fn load_or_default(path: &Path) -> Self {
        match Self::load_verified(path) {
            Ok(rules) => rules,
            Err(err) => {
                tracing::warn!(path = %path.display(), %err, "using built-in advisory rules");
                Self::default_rules()
            }
        }
    }

    pub fn load_verified(path: &Path) -> AdvisoryResult<Self> {
        let bytes = std::fs::read(path)?;
        let rules: Self = serde_json::from_slice(&bytes)?;
        rules.validate_signature()?;
        Ok(rules)
    }

    pub fn validate_signature(&self) -> AdvisoryResult<()> {
        if let Some(expected) = self.signature_sha256.as_deref() {
            let mut unsigned = self.clone();
            unsigned.signature_sha256 = None;
            let bytes = serde_json::to_vec(&unsigned)?;
            let actual = hex::encode(Sha256::digest(bytes));
            if !actual.eq_ignore_ascii_case(expected) {
                return Err(AdvisoryError::InvalidRules(
                    "signature_sha256 does not match rules body".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn save_atomic(&self, path: &Path) -> AdvisoryResult<()> {
        self.validate_signature()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("json.tmp");
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&tmp)?;
            serde_json::to_writer_pretty(&mut file, self)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
        }
        std::fs::rename(tmp, path)?;
        Ok(())
    }

    pub fn default_rules() -> Self {
        Self {
            rules: vec![
                RecommendationRule {
                    rule_match: RuleMatch {
                        category: Some("malware".into()),
                        signature_contains: None,
                        severity_at_least: Some("high".into()),
                    },
                    title: "Suspected malware or command-and-control activity".into(),
                    summary:
                        "A device is communicating in a pattern associated with malware control channels."
                            .into(),
                    steps: vec![
                        RuleStep {
                            action: "Isolate the affected device from the Circle network".into(),
                            rationale: "Contain potential command-and-control traffic".into(),
                            automatable: true,
                        },
                        RuleStep {
                            action: "Run a full endpoint and service scan".into(),
                            rationale: "Identify persistence, payloads, and exposed services".into(),
                            automatable: true,
                        },
                        RuleStep {
                            action: "Rotate credentials used on or from this device".into(),
                            rationale: "Limit blast radius if credentials were exposed".into(),
                            automatable: false,
                        },
                    ],
                    references: vec!["signature".into(), "cve".into()],
                },
                RecommendationRule {
                    rule_match: RuleMatch {
                        category: Some("exploit".into()),
                        signature_contains: None,
                        severity_at_least: Some("medium".into()),
                    },
                    title: "Possible exploit attempt against a network service".into(),
                    summary:
                        "Traffic matched exploit behavior and should be checked against exposed services."
                            .into(),
                    steps: vec![
                        RuleStep {
                            action: "Confirm whether the destination service is expected".into(),
                            rationale: "Unexpected services expand the attack surface".into(),
                            automatable: false,
                        },
                        RuleStep {
                            action: "Patch or disable the affected service".into(),
                            rationale: "Known vulnerable service versions are common exploit targets".into(),
                            automatable: false,
                        },
                    ],
                    references: vec!["signature".into(), "cve".into()],
                },
                RecommendationRule {
                    rule_match: RuleMatch {
                        category: Some("reconnaissance".into()),
                        signature_contains: None,
                        severity_at_least: Some("low".into()),
                    },
                    title: "Reconnaissance or scanning activity observed".into(),
                    summary: "Network traffic suggests probing or enumeration of reachable services.".into(),
                    steps: vec![
                        RuleStep {
                            action: "Review source and destination ownership".into(),
                            rationale: "Authorized scans should map to a known maintenance window".into(),
                            automatable: false,
                        },
                        RuleStep {
                            action: "Tighten firewall exposure for unused ports".into(),
                            rationale: "Reducing reachable services lowers follow-on exploit risk".into(),
                            automatable: true,
                        },
                    ],
                    references: vec!["signature".into()],
                },
                RecommendationRule {
                    rule_match: RuleMatch {
                        category: Some("policy_violation".into()),
                        signature_contains: None,
                        severity_at_least: Some("low".into()),
                    },
                    title: "Policy violation requires review".into(),
                    summary: "Traffic or behavior violated a configured security policy.".into(),
                    steps: vec![
                        RuleStep {
                            action: "Compare the alert with the active policy".into(),
                            rationale: "Confirm whether the event is malicious or a policy drift".into(),
                            automatable: false,
                        },
                        RuleStep {
                            action: "Update the policy only after owner approval".into(),
                            rationale: "Advisory recommendations never change enforcement state".into(),
                            automatable: false,
                        },
                    ],
                    references: vec!["policy".into()],
                },
            ],
            fallback: RecommendationTemplate {
                title: "Security alert requires review".into(),
                summary: "Guardian detected a security alert that does not match a more specific advisory rule."
                    .into(),
                steps: vec![
                    RuleStep {
                        action: "Review the alert signature, endpoints, and recent device changes".into(),
                        rationale: "Manual triage can separate expected activity from a new threat".into(),
                        automatable: false,
                    },
                    RuleStep {
                        action: "Preserve logs before taking remediation action".into(),
                        rationale: "Evidence helps confirm scope and supports later audit review".into(),
                        automatable: true,
                    },
                ],
                references: vec!["signature".into()],
            },
            signature_sha256: None,
        }
    }
}

impl RecommendationRule {
    pub fn matches(&self, category: &str, signature: &str, severity: Severity) -> bool {
        if let Some(expected) = self.rule_match.category.as_deref() {
            if !expected.eq_ignore_ascii_case(category) {
                return false;
            }
        }
        if let Some(needle) = self.rule_match.signature_contains.as_deref() {
            if !signature.to_lowercase().contains(&needle.to_lowercase()) {
                return false;
            }
        }
        if let Some(minimum) = self.rule_match.severity_at_least.as_deref() {
            if severity_rank(severity) < severity_name_rank(minimum) {
                return false;
            }
        }
        true
    }

    pub fn steps(&self) -> Vec<RemediationStep> {
        steps_with_order(&self.steps)
    }
}

impl RecommendationTemplate {
    pub fn steps(&self) -> Vec<RemediationStep> {
        steps_with_order(&self.steps)
    }
}

fn steps_with_order(steps: &[RuleStep]) -> Vec<RemediationStep> {
    steps
        .iter()
        .enumerate()
        .map(|(idx, step)| RemediationStep {
            order: (idx + 1).min(u8::MAX as usize) as u8,
            action: step.action.clone(),
            rationale: step.rationale.clone(),
            automatable: step.automatable,
        })
        .collect()
}

fn severity_name_rank(severity: &str) -> u8 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ranking_calculations() {
        assert_eq!(severity_rank(Severity::Info), 0);
        assert_eq!(severity_rank(Severity::Low), 1);
        assert_eq!(severity_rank(Severity::Medium), 2);
        assert_eq!(severity_rank(Severity::High), 3);
        assert_eq!(severity_rank(Severity::Critical), 4);

        assert_eq!(severity_name_rank("info"), 0);
        assert_eq!(severity_name_rank("low"), 1);
        assert_eq!(severity_name_rank("Medium"), 2);
        assert_eq!(severity_name_rank("HIGH"), 3);
        assert_eq!(severity_name_rank("Critical"), 4);
        assert_eq!(severity_name_rank("unknown"), 0);
    }

    #[test]
    fn test_recommendation_rule_matching_logic() {
        let rule = RecommendationRule {
            rule_match: RuleMatch {
                category: Some("malware".into()),
                signature_contains: Some("c2".into()),
                severity_at_least: Some("high".into()),
            },
            title: "Malware Alert".into(),
            summary: "C2 traffic detected".into(),
            steps: vec![RuleStep {
                action: "Isolate device".into(),
                rationale: "Prevent lateral movement".into(),
                automatable: true,
            }],
            references: vec!["cve".into()],
        };

        // Exact match
        assert!(rule.matches("malware", "Known C2 Beacon", Severity::High));
        assert!(rule.matches("MALWARE", "c2 communication", Severity::Critical));

        // Category mismatch
        assert!(!rule.matches("exploit", "Known C2 Beacon", Severity::High));

        // Signature substring mismatch
        assert!(!rule.matches("malware", "Unknown Trojan", Severity::High));

        // Severity below threshold
        assert!(!rule.matches("malware", "Known C2 Beacon", Severity::Medium));
        assert!(!rule.matches("malware", "Known C2 Beacon", Severity::Low));
    }

    #[test]
    fn test_default_rules_structure_and_fallback() {
        let kb = RecommendationRules::default_rules();
        assert!(!kb.rules.is_empty());
        assert!(!kb.fallback.title.is_empty());

        let fallback_steps = kb.fallback.steps();
        assert_eq!(fallback_steps.len(), 2);
        assert_eq!(fallback_steps[0].order, 1);
        assert_eq!(fallback_steps[1].order, 2);
    }

    #[test]
    fn test_validate_signature_integrity() {
        let mut kb = RecommendationRules::default_rules();
        // Unsigned rules pass validation
        assert!(kb.validate_signature().is_ok());

        // Calculate correct SHA-256
        let unsigned = kb.clone();
        let bytes = serde_json::to_vec(&unsigned).unwrap();
        let valid_hash = hex::encode(Sha256::digest(bytes));

        kb.signature_sha256 = Some(valid_hash);
        assert!(kb.validate_signature().is_ok());

        // Tampered signature must fail
        kb.signature_sha256 = Some("0000000000000000000000000000000000000000000000000000000000000000".into());
        assert!(matches!(
            kb.validate_signature(),
            Err(AdvisoryError::InvalidRules(_))
        ));
    }
}

