//! Task 2 phase 1: admin-owned policy templates and safe policy data types.
//!
//! The anomaly model cannot activate a policy.  It may later propose a
//! `PolicyCandidate`, but this module accepts only actions and parameter
//! ranges explicitly configured by the policy owner.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// The four initial policy actions authorised by the Task 2 design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    TightenFirewall,
    IncreaseAttestationFrequency,
    EnableAdditionalLogging,
    QuarantinePeer,
}

/// Firewall changes stay constrained to these two modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallMode {
    Block,
    RateLimit,
}

/// Logging capture choices intentionally remain small and readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoggingLevel {
    Basic,
    Detailed,
}

/// Parameters are optional at the data-type level because Phase 2 will build
/// a pending draft from Task 1 evidence. `PolicyTemplates::validate_parameters`
/// requires the correct fields before a candidate is accepted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyParameters {
    /// Trusted node ID, peer ID, or IP selected by the admin/workflow.
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firewall_mode: Option<FirewallMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_per_second: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_interval_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logging_level: Option<LoggingLevel>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Pending,
    Approved,
    Rejected,
    Applied,
    Reverted,
}

/// Phase 2 will fill this from a Task 1 recommendation JSON.  Defining it in
/// Phase 1 gives every later phase one stable JSON shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyEvidence {
    pub display_row: usize,
    pub source_time_ms: u64,
    pub task1_action: String,
    pub score: f64,
    pub severity: String,
    pub evidence_features: Vec<String>,
    pub recommendation: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyCandidate {
    pub policy_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_recommendation_id: Option<String>,
    pub action: PolicyAction,
    pub parameters: PolicyParameters,
    pub reason: String,
    #[serde(default)]
    pub evidence: Vec<PolicyEvidence>,
    pub status: PolicyStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub approver_id: String,
    pub approved: bool,
    pub note: String,
    pub decided_at_epoch_ms: u128,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedPolicy {
    pub candidate: PolicyCandidate,
    pub policy_digest: String,
    pub signature: String,
    pub signer_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeApplyResult {
    pub node: String,
    pub verified: bool,
    pub applied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyAuditRecord {
    pub policy_id: String,
    pub status: PolicyStatus,
    pub candidate: PolicyCandidate,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval: Option<Approval>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_results: Option<Vec<NodeApplyResult>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyActionTemplate {
    pub action: PolicyAction,
    pub enabled: bool,
    pub approval_required: bool,
    /// Task 1 action names that the admin has explicitly allowed to map to
    /// this policy template. An empty list means Task 1 cannot auto-select it.
    #[serde(default)]
    pub task1_action_kinds: Vec<String>,
    #[serde(default)]
    pub min_duration_seconds: Option<u64>,
    #[serde(default)]
    pub max_duration_seconds: Option<u64>,
    #[serde(default)]
    pub allowed_firewall_modes: Vec<FirewallMode>,
    #[serde(default)]
    pub min_rate_limit_per_second: Option<u32>,
    #[serde(default)]
    pub max_rate_limit_per_second: Option<u32>,
    /// Admin-selected values for bounded advisory firewall proposals. Final
    /// policy enforcement still requires owner approval.
    #[serde(default)]
    pub default_rate_limit_per_second: Option<u32>,
    #[serde(default)]
    pub default_duration_seconds: Option<u64>,
    #[serde(default)]
    pub min_attestation_interval_seconds: Option<u64>,
    #[serde(default)]
    pub max_attestation_interval_seconds: Option<u64>,
    /// Admin-owned intervals used by VS5 advisory attestation proposals.
    #[serde(default)]
    pub medium_attestation_interval_seconds: Option<u64>,
    #[serde(default)]
    pub high_attestation_interval_seconds: Option<u64>,
    #[serde(default)]
    pub critical_attestation_interval_seconds: Option<u64>,
    #[serde(default)]
    pub allowed_logging_levels: Vec<LoggingLevel>,
    /// Admin-owned defaults for VS6 temporary enhanced logging proposals.
    #[serde(default)]
    pub medium_logging_level: Option<LoggingLevel>,
    #[serde(default)]
    pub high_logging_level: Option<LoggingLevel>,
    #[serde(default)]
    pub critical_logging_level: Option<LoggingLevel>,
    #[serde(default)]
    pub medium_logging_duration_seconds: Option<u64>,
    #[serde(default)]
    pub high_logging_duration_seconds: Option<u64>,
    #[serde(default)]
    pub critical_logging_duration_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyTemplates {
    pub version: u32,
    pub templates: Vec<PolicyActionTemplate>,
}

impl PolicyTemplates {
    pub fn from_path(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let templates: Self = serde_json::from_str(&contents)?;
        templates.validate()?;
        Ok(templates)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.version != 1 {
            anyhow::bail!("unsupported policy template version {}", self.version);
        }
        if self.templates.is_empty() {
            anyhow::bail!("policy templates must not be empty");
        }
        for action in [
            PolicyAction::TightenFirewall,
            PolicyAction::IncreaseAttestationFrequency,
            PolicyAction::EnableAdditionalLogging,
            PolicyAction::QuarantinePeer,
        ] {
            if self
                .templates
                .iter()
                .filter(|template| template.action == action)
                .count()
                != 1
            {
                anyhow::bail!("each supported policy action must have exactly one template");
            }
        }
        for template in &self.templates {
            if !template.approval_required {
                anyhow::bail!("all Task 2 policy actions must require admin approval");
            }
            validate_optional_range(
                template.min_duration_seconds,
                template.max_duration_seconds,
                "duration_seconds",
            )?;
            validate_optional_range(
                template.min_rate_limit_per_second,
                template.max_rate_limit_per_second,
                "rate_limit_per_second",
            )?;
            validate_default_in_range(
                template.default_duration_seconds,
                template.min_duration_seconds,
                template.max_duration_seconds,
                "default_duration_seconds",
            )?;
            validate_default_in_range(
                template.medium_logging_duration_seconds,
                template.min_duration_seconds,
                template.max_duration_seconds,
                "medium_logging_duration_seconds",
            )?;
            validate_default_in_range(
                template.high_logging_duration_seconds,
                template.min_duration_seconds,
                template.max_duration_seconds,
                "high_logging_duration_seconds",
            )?;
            validate_default_in_range(
                template.critical_logging_duration_seconds,
                template.min_duration_seconds,
                template.max_duration_seconds,
                "critical_logging_duration_seconds",
            )?;
            validate_default_logging_level(
                template.medium_logging_level,
                &template.allowed_logging_levels,
                "medium_logging_level",
            )?;
            validate_default_logging_level(
                template.high_logging_level,
                &template.allowed_logging_levels,
                "high_logging_level",
            )?;
            validate_default_logging_level(
                template.critical_logging_level,
                &template.allowed_logging_levels,
                "critical_logging_level",
            )?;
            validate_default_in_range(
                template.default_rate_limit_per_second.map(u64::from),
                template.min_rate_limit_per_second.map(u64::from),
                template.max_rate_limit_per_second.map(u64::from),
                "default_rate_limit_per_second",
            )?;
            validate_optional_range(
                template.min_attestation_interval_seconds,
                template.max_attestation_interval_seconds,
                "attestation_interval_seconds",
            )?;
            validate_default_in_range(
                template.medium_attestation_interval_seconds,
                template.min_attestation_interval_seconds,
                template.max_attestation_interval_seconds,
                "medium_attestation_interval_seconds",
            )?;
            validate_default_in_range(
                template.high_attestation_interval_seconds,
                template.min_attestation_interval_seconds,
                template.max_attestation_interval_seconds,
                "high_attestation_interval_seconds",
            )?;
            validate_default_in_range(
                template.critical_attestation_interval_seconds,
                template.min_attestation_interval_seconds,
                template.max_attestation_interval_seconds,
                "critical_attestation_interval_seconds",
            )?;
        }
        Ok(())
    }

    pub fn validate_parameters(
        &self,
        action: PolicyAction,
        parameters: &PolicyParameters,
    ) -> anyhow::Result<()> {
        let template = self
            .templates
            .iter()
            .find(|template| template.action == action)
            .ok_or_else(|| anyhow::anyhow!("policy action is not configured"))?;
        if !template.enabled {
            anyhow::bail!("policy action {:?} is disabled by admin policy", action);
        }
        if parameters.target.trim().is_empty() {
            anyhow::bail!("policy target must not be empty");
        }

        match action {
            PolicyAction::TightenFirewall => {
                let mode = required(parameters.firewall_mode, "firewall_mode")?;
                if !template.allowed_firewall_modes.contains(&mode) {
                    anyhow::bail!("firewall mode is not allowed by admin policy");
                }
                required_range(
                    parameters.duration_seconds,
                    template.min_duration_seconds,
                    template.max_duration_seconds,
                    "duration_seconds",
                )?;
                match mode {
                    FirewallMode::Block if parameters.rate_limit_per_second.is_some() => {
                        anyhow::bail!("block policy must not carry a rate limit")
                    }
                    FirewallMode::RateLimit => required_range(
                        parameters.rate_limit_per_second.map(u64::from),
                        template.min_rate_limit_per_second.map(u64::from),
                        template.max_rate_limit_per_second.map(u64::from),
                        "rate_limit_per_second",
                    )?,
                    FirewallMode::Block => {}
                }
            }
            PolicyAction::IncreaseAttestationFrequency => required_range(
                parameters.attestation_interval_seconds,
                template.min_attestation_interval_seconds,
                template.max_attestation_interval_seconds,
                "attestation_interval_seconds",
            )?,
            PolicyAction::EnableAdditionalLogging => {
                let level = required(parameters.logging_level, "logging_level")?;
                if !template.allowed_logging_levels.contains(&level) {
                    anyhow::bail!("logging level is not allowed by admin policy");
                }
                required_range(
                    parameters.duration_seconds,
                    template.min_duration_seconds,
                    template.max_duration_seconds,
                    "duration_seconds",
                )?;
            }
            PolicyAction::QuarantinePeer => required_range(
                parameters.duration_seconds,
                template.min_duration_seconds,
                template.max_duration_seconds,
                "duration_seconds",
            )?,
        }
        Ok(())
    }

    /// This mapping is owned by the admin template file, not inferred from a
    /// free-text model recommendation.
    pub fn action_for_task1_kind(&self, task1_action_kind: &str) -> Option<PolicyAction> {
        self.templates
            .iter()
            .find(|template| {
                template.enabled
                    && template
                        .task1_action_kinds
                        .iter()
                        .any(|kind| kind == task1_action_kind)
            })
            .map(|template| template.action)
    }
}

fn validate_optional_range<T: Ord + std::fmt::Display>(
    min: Option<T>,
    max: Option<T>,
    field: &str,
) -> anyhow::Result<()> {
    match (min, max) {
        (Some(min), Some(max)) if min <= max => Ok(()),
        (Some(_), Some(_)) => anyhow::bail!("{field} minimum must not exceed maximum"),
        (None, None) => Ok(()),
        _ => anyhow::bail!("{field} must define both minimum and maximum"),
    }
}

fn required<T: Copy>(value: Option<T>, field: &str) -> anyhow::Result<T> {
    value.ok_or_else(|| anyhow::anyhow!("{field} is required"))
}

fn validate_default_in_range(
    value: Option<u64>,
    min: Option<u64>,
    max: Option<u64>,
    field: &str,
) -> anyhow::Result<()> {
    match value {
        None => Ok(()),
        Some(value) => required_range(Some(value), min, max, field),
    }
}

fn validate_default_logging_level(
    value: Option<LoggingLevel>,
    allowed: &[LoggingLevel],
    field: &str,
) -> anyhow::Result<()> {
    if let Some(value) = value {
        if !allowed.contains(&value) {
            anyhow::bail!("{field} must be allowed by admin policy");
        }
    }
    Ok(())
}

fn required_range(
    value: Option<u64>,
    min: Option<u64>,
    max: Option<u64>,
    field: &str,
) -> anyhow::Result<()> {
    let value = value.ok_or_else(|| anyhow::anyhow!("{field} is required"))?;
    let min = min.ok_or_else(|| anyhow::anyhow!("{field} minimum is not configured"))?;
    let max = max.ok_or_else(|| anyhow::anyhow!("{field} maximum is not configured"))?;
    if value < min || value > max {
        anyhow::bail!("{field} must be between {min} and {max}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn templates() -> PolicyTemplates {
        PolicyTemplates::from_path("config/policy_action_templates.json").unwrap()
    }

    #[test]
    fn admin_template_file_is_valid() {
        assert!(templates().validate().is_ok());
    }

    #[test]
    fn valid_rate_limit_is_accepted() {
        let parameters = PolicyParameters {
            target: "10.0.0.25".into(),
            duration_seconds: Some(900),
            firewall_mode: Some(FirewallMode::RateLimit),
            rate_limit_per_second: Some(20),
            ..Default::default()
        };
        assert!(templates()
            .validate_parameters(PolicyAction::TightenFirewall, &parameters)
            .is_ok());
    }

    #[test]
    fn unknown_or_unsafe_parameters_are_rejected() {
        let unsafe_duration = PolicyParameters {
            target: "10.0.0.25".into(),
            duration_seconds: Some(901),
            firewall_mode: Some(FirewallMode::RateLimit),
            rate_limit_per_second: Some(20),
            ..Default::default()
        };
        assert!(templates()
            .validate_parameters(PolicyAction::TightenFirewall, &unsafe_duration)
            .is_err());

        let missing_mode = PolicyParameters {
            target: "10.0.0.25".into(),
            duration_seconds: Some(60),
            ..Default::default()
        };
        assert!(templates()
            .validate_parameters(PolicyAction::TightenFirewall, &missing_mode)
            .is_err());
    }

    #[test]
    fn every_action_requires_approval() {
        let mut templates = templates();
        templates.templates[0].approval_required = false;
        assert!(templates.validate().is_err());
    }
}
