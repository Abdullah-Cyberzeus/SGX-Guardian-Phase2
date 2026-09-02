//! Task 2 -> Task 3 trust handoff.
//!
//! Task 2 owns policy approval, signing, delivery, member verification, safe
//! policy activation, identity rotation and re-attestation. Task 3 must not
//! recreate those decisions. It reads this small per-node summary to know
//! whether a node is currently eligible for normal traffic routing.

use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use super::{
    ActiveVirtualShiftPolicy, AttestationState, MemberPolicyApplyResult, PolicyApplyStatus,
    VirtualIdentityState,
};

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingTrustStatus {
    Trusted,
    Restricted,
    NotTrusted,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingTrustSources {
    pub active_policy_path: String,
    pub latest_apply_result_path: String,
    pub identity_state_path: String,
}

/// A conservative, easy-to-query Task 3 input. `routing_allowed` is false
/// unless Task 2 both applied the policy and completed re-attestation as
/// trusted. `policy_restrictions` tells a future route selector which network
/// policy DENY rules it must honor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingTrustSummary {
    pub schema_version: u32,
    pub purpose: String,
    pub node_id: String,
    pub trust_status: RoutingTrustStatus,
    pub routing_allowed: bool,
    pub routing_guidance: String,
    pub policy_status: String,
    pub active_policy_id: Option<String>,
    pub active_policy_version: Option<u64>,
    pub applicable_members: Vec<String>,
    pub policy_restrictions: Vec<String>,
    pub last_alert_id: Option<String>,
    pub attestation_state: Option<AttestationState>,
    pub updated_at_ms: u64,
    pub sources: RoutingTrustSources,
}

#[derive(Debug, Clone)]
pub struct RoutingTrustSummaryWriter {
    policy_root: PathBuf,
    identity_root: PathBuf,
    output_root: PathBuf,
}

impl RoutingTrustSummaryWriter {
    pub fn new(
        policy_root: impl Into<PathBuf>,
        identity_root: impl Into<PathBuf>,
        output_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            policy_root: policy_root.into(),
            identity_root: identity_root.into(),
            output_root: output_root.into(),
        }
    }

    pub fn write_for_member(
        &self,
        member_id: &str,
        now_ms: u64,
    ) -> anyhow::Result<RoutingTrustSummary> {
        if member_id.trim().is_empty()
            || member_id.contains('/')
            || member_id.contains('\\')
            || now_ms == 0
        {
            anyhow::bail!("member ID and update time must be valid");
        }
        let policy_dir = self.policy_root.join(member_id);
        let active_path = policy_dir.join("active_policy.json");
        let apply_path = policy_dir.join("latest_apply_result.json");
        let identity_path = self
            .identity_root
            .join(member_id)
            .join("identity_state.json");
        let active: Option<ActiveVirtualShiftPolicy> = read_json(&active_path)?;
        let apply: Option<MemberPolicyApplyResult> = read_json(&apply_path)?;
        let identity: Option<VirtualIdentityState> = read_json(&identity_path)?;

        let attestation_state = identity
            .as_ref()
            .map(|state| state.attestation_state.clone());
        let policy_applied = apply
            .as_ref()
            .is_some_and(|value| value.status == PolicyApplyStatus::Applied);
        let (trust_status, routing_allowed, routing_guidance) = match attestation_state {
            Some(AttestationState::Trusted) if policy_applied => (
                RoutingTrustStatus::Trusted,
                true,
                "Task 3 may use this node for normal traffic routes, while respecting the active policy restrictions and live route-health metrics.".into(),
            ),
            Some(AttestationState::Failed) => (
                RoutingTrustStatus::NotTrusted,
                false,
                "Do not select this node for Task 3 routes until a valid policy lifecycle and re-attestation succeed.".into(),
            ),
            Some(AttestationState::ReAttestationRequired) => (
                RoutingTrustStatus::Restricted,
                false,
                "Do not use this node for normal Task 3 routing while re-attestation is pending."
                    .into(),
            ),
            _ if apply
                .as_ref()
                .is_some_and(|value| value.status != PolicyApplyStatus::Applied) =>
            {
                (
                    RoutingTrustStatus::Restricted,
                    false,
                    "The latest Task 2 policy change was not applied; Task 3 must not select this node.".into(),
                )
            }
            _ => (
                RoutingTrustStatus::Unknown,
                false,
                "No trusted Task 2 state is available yet; keep this node out of normal Task 3 routing.".into(),
            ),
        };
        let policy_restrictions = active
            .as_ref()
            .map(|policy| {
                policy
                    .rules
                    .iter()
                    .filter(|rule| rule.action == super::NetworkRuleAction::Deny)
                    .map(|rule| {
                        format!(
                            "DENY {} {}:{} -> {} ({})",
                            rule.protocol, rule.src, rule.port, rule.dst, rule.reason
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let summary = RoutingTrustSummary {
            schema_version: SCHEMA_VERSION,
            purpose: "Task 2 trust and policy handoff for Task 3 route eligibility. Task 3 uses this as a constraint; it does not replace Task 2 policy verification.".into(),
            node_id: member_id.into(),
            trust_status,
            routing_allowed,
            routing_guidance,
            policy_status: apply
                .as_ref()
                .map(|value| format!("{:?}", value.status).to_lowercase())
                .unwrap_or_else(|| "unknown".into()),
            active_policy_id: active.as_ref().map(|policy| policy.policy_id.clone()),
            active_policy_version: active.as_ref().map(|policy| policy.policy_version),
            applicable_members: active
                .as_ref()
                .map(|policy| policy.applicable_members.clone())
                .unwrap_or_default(),
            policy_restrictions,
            last_alert_id: apply.as_ref().map(|value| value.alert_id.clone()),
            attestation_state,
            updated_at_ms: now_ms,
            sources: RoutingTrustSources {
                active_policy_path: active_path.display().to_string(),
                latest_apply_result_path: apply_path.display().to_string(),
                identity_state_path: identity_path.display().to_string(),
            },
        };
        let output_path = self
            .output_root
            .join(member_id)
            .join("routing_trust_summary.json");
        let parent = output_path.parent().expect("output has parent");
        fs::create_dir_all(parent)?;
        fs::write(
            &output_path,
            format!("{}\n", serde_json::to_string_pretty(&summary)?),
        )?;
        Ok(summary)
    }
}

fn read_json<T: for<'a> Deserialize<'a>>(path: &Path) -> anyhow::Result<Option<T>> {
    match fs::read_to_string(path) {
        Ok(contents) => Ok(Some(serde_json::from_str(&contents)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
