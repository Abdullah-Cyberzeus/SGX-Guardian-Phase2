use crate::circle::errors::CircleError;
use crate::circle::store;
use crate::vc::credential::{CredentialRole, MembershipStatus, VerifiableCredential};
use crate::vc::issue::{
    self, classify_vc_state, default_permissions_for_role, IssueMembershipOutcome, IssueRequest,
    VcAdminAction, VcLifecycleState,
};
use crate::vc::status_list::StatusListManager;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemberLifecycleState {
    Active,
    Expired,
    Revoked,
}

impl From<VcLifecycleState> for MemberLifecycleState {
    fn from(value: VcLifecycleState) -> Self {
        match value {
            VcLifecycleState::Active => Self::Active,
            VcLifecycleState::Expired => Self::Expired,
            VcLifecycleState::Revoked => Self::Revoked,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CircleMember {
    pub did: String,
    pub vc_id: String,
    pub issuer_did: String,
    pub role: CredentialRole,
    pub permissions: Vec<String>,
    pub join_date: String,
    pub expiration_date: String,
    pub membership_status: MembershipStatus,
    pub lifecycle_state: MemberLifecycleState,
    pub node_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberMutationResult {
    pub vc: VerifiableCredential,
    pub reused_existing: bool,
    pub replaced_expired: bool,
}

pub fn list_members(node_id: &str, circle_id: &str) -> Result<Vec<CircleMember>, CircleError> {
    let _ = store::get_circle(node_id, circle_id)?;
    let (issuer, km) = store::load_runtime_signing_context(node_id)?;
    let status_list = StatusListManager::load_or_create(&issuer, &km)?;
    let mut latest_by_subject: BTreeMap<String, VerifiableCredential> = BTreeMap::new();
    for vc in crate::vc::persistence::list_issued()? {
        if vc.credential_subject.circle_id != circle_id {
            continue;
        }
        match latest_by_subject.get(vc.subject_did()) {
            Some(existing) if existing.issuance_date >= vc.issuance_date => {}
            _ => {
                latest_by_subject.insert(vc.subject_did().to_string(), vc);
            }
        }
    }

    let mut members = latest_by_subject
        .into_values()
        .map(|vc| {
            let state = classify_vc_state(&vc, &status_list, Utc::now())?;
            Ok(CircleMember {
                did: vc.subject_did().to_string(),
                vc_id: vc.id.clone(),
                issuer_did: vc.issuer.clone(),
                role: vc.credential_subject.role.clone(),
                permissions: vc.credential_subject.permissions.clone(),
                join_date: vc.credential_subject.join_date.clone(),
                expiration_date: vc.expiration_date.clone(),
                membership_status: vc.credential_subject.membership_status.clone(),
                lifecycle_state: state.into(),
                node_hint: vc.credential_subject.node_hint.clone(),
            })
        })
        .collect::<Result<Vec<_>, CircleError>>()?;
    members.sort_by(|left, right| left.did.cmp(&right.did));
    Ok(members)
}

pub fn add_member(
    node_id: &str,
    circle_id: &str,
    subject_did: &str,
    role: CredentialRole,
    duration_days: i64,
) -> Result<MemberMutationResult, CircleError> {
    let circle = store::get_circle(node_id, circle_id)?;
    if circle.is_archived() {
        return Err(CircleError::Conflict(format!(
            "circle {} is archived",
            circle_id
        )));
    }

    let (issuer, km) = store::load_runtime_signing_context(node_id)?;
    let outcome = issue::issue_membership_vc_with_outcome(
        &issuer,
        &km,
        IssueRequest {
            subject_did,
            role: role.clone(),
            permissions: default_permissions_for_role(role),
            circle_id,
            node_hint: None,
            duration_days: Some(duration_days),
        },
    )?;
    let result = match outcome {
        IssueMembershipOutcome::IssuedNew {
            vc,
            replaced_expired,
        } => MemberMutationResult {
            vc,
            reused_existing: false,
            replaced_expired,
        },
        IssueMembershipOutcome::ReusedExisting { vc } => MemberMutationResult {
            vc,
            reused_existing: true,
            replaced_expired: false,
        },
    };
    Ok(result)
}

pub fn remove_member(
    node_id: &str,
    circle_id: &str,
    subject_did: &str,
    reason: &str,
) -> Result<Vec<String>, CircleError> {
    let circle = store::get_circle(node_id, circle_id)?;
    if circle.is_archived() {
        return Err(CircleError::Conflict(format!(
            "circle {} is archived",
            circle_id
        )));
    }

    let matches = crate::vc::persistence::list_issued_for_subject(subject_did)?
        .into_iter()
        .filter(|vc| vc.credential_subject.circle_id == circle_id)
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return Err(CircleError::NotFound(format!(
            "no membership VC found for {} in {}",
            subject_did, circle_id
        )));
    }

    let (issuer, km) = store::load_runtime_signing_context(node_id)?;
    issue::ensure_circle_owner(&issuer, circle_id, VcAdminAction::Revoke, false)?;
    let mut status_list = StatusListManager::load_or_create(&issuer, &km)?;
    let mut revoked_ids = Vec::new();
    for vc in matches {
        let state = classify_vc_state(&vc, &status_list, Utc::now())?;
        if matches!(state, VcLifecycleState::Revoked) {
            continue;
        }
        let index = vc
            .credential_status
            .status_list_index
            .parse::<u64>()
            .map_err(|err| CircleError::Invalid(format!("vc status index: {}", err)))?;
        status_list.set_revoked(index, true)?;
        revoked_ids.push(vc.id.clone());
    }

    if revoked_ids.is_empty() {
        return Ok(revoked_ids);
    }

    let vm_ref = format!("{}#dkp-v{}", issuer.did, issuer.current_dkp_version.max(1));
    status_list.commit(&km, &vm_ref)?;
    crate::audit::logger::log_audit(
        node_id,
        crate::audit::event::AuditCategory::Circle,
        crate::audit::event::AuditSeverity::Warning,
        crate::audit::event::AuditAction::Revoked,
        &format!(
            "Circle member removed from {}: subject={} count={} reason={}",
            circle_id,
            subject_did,
            revoked_ids.len(),
            reason
        ),
    );
    Ok(revoked_ids)
}

pub fn change_role(
    node_id: &str,
    circle_id: &str,
    subject_did: &str,
    role: CredentialRole,
    duration_days: i64,
) -> Result<MemberMutationResult, CircleError> {
    let existing = crate::vc::persistence::list_issued_for_subject(subject_did)?
        .into_iter()
        .filter(|vc| vc.credential_subject.circle_id == circle_id)
        .collect::<Vec<_>>();
    if existing.is_empty() {
        return Err(CircleError::NotFound(format!(
            "no membership VC found for {} in {}",
            subject_did, circle_id
        )));
    }

    let _ = remove_member(
        node_id,
        circle_id,
        subject_did,
        &format!("role changed to {:?}", role),
    )?;
    add_member(node_id, circle_id, subject_did, role, duration_days)
}
