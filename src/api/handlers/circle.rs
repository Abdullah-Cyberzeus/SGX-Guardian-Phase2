use crate::api::auth::middleware::AuthenticatedSession;
use crate::api::auth::store::UserRole;
use crate::api::idempotency;
use crate::api::{error::ApiError, state::AppState};
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::circle::invite::{self, InviteToken, JoinRequest, ReceivedInvite, ReceivedInviteState};
use crate::circle::members::{self, CircleMember};
use crate::circle::snapshot::{self, CircleMemberSnapshot};
use crate::circle::store::{self, CIRCLE_WRITE_LOCK};
use crate::circle::{Circle, CircleError};
use crate::did::Did;
use crate::vc::credential::{CredentialRole, VerifiableCredential};
use crate::vc::issue::{
    self, default_permissions_for_role, IssueMembershipOutcome, IssueRequest, VcAdminAction,
};
use axum::Extension;
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

const GUARDIAN_SERVICE_AUTH_SCHEME: &str = "GuardianService ";
const GUARDIAN_SERVICE_AUTH_CONTEXT: &str = "SGX-GUARDIAN-SERVICE-AUTH-V1";
const GUARDIAN_SERVICE_AUTH_PATH: &str = "/api/v1/circles/invites/inbox";
const GUARDIAN_SERVICE_SNAPSHOT_PATH: &str = "/api/v1/circles/snapshots/inbox";
const GUARDIAN_SERVICE_AUTH_SKEW_SECS: i64 = 300;
const HEADER_GUARDIAN_DID: &str = "x-sgx-guardian-did";
const HEADER_GUARDIAN_TIMESTAMP: &str = "x-sgx-guardian-timestamp";
const HEADER_GUARDIAN_NONCE: &str = "x-sgx-guardian-nonce";

#[derive(Serialize)]
pub struct CircleListResponse {
    pub status: String,
    pub count: usize,
    pub circles: Vec<Circle>,
}

#[derive(Serialize)]
pub struct CircleDetailResponse {
    pub status: String,
    pub circle: Circle,
}

#[derive(Deserialize, Default)]
pub struct CreateCircleRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub circle_id: Option<String>,
    pub days: Option<i64>,
}

#[derive(Deserialize, Default)]
pub struct EditCircleRequest {
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct CircleMutationResponse {
    pub status: String,
    pub message: String,
    pub circle: Circle,
}

#[derive(Serialize)]
pub struct CircleDeleteResponse {
    pub status: String,
    pub message: String,
    pub circle_id: String,
    pub revoked_vc_ids: Vec<String>,
}

#[derive(Serialize)]
pub struct MemberListResponse {
    pub status: String,
    pub count: usize,
    pub members: Vec<CircleMember>,
}

#[derive(Serialize)]
pub struct CircleSnapshotSyncResponse {
    pub status: String,
    pub snapshots_applied: usize,
}

#[derive(Deserialize, Default)]
pub struct AddMemberRequest {
    pub did: Option<String>,
    pub role: Option<String>,
    pub days: Option<i64>,
}

#[derive(Serialize)]
pub struct MemberMutationResponse {
    pub status: String,
    pub message: String,
    pub vc: VerifiableCredential,
    pub reused_existing: bool,
    pub replaced_expired: bool,
}

#[derive(Serialize)]
pub struct MemberRemoveResponse {
    pub status: String,
    pub message: String,
    pub revoked_vc_ids: Vec<String>,
}

#[derive(Deserialize, Default)]
pub struct ChangeRoleRequest {
    pub role: Option<String>,
    pub days: Option<i64>,
}

#[derive(Serialize)]
pub struct InviteListResponse {
    pub status: String,
    pub count: usize,
    pub invites: Vec<InviteToken>,
}

#[derive(Deserialize, Default)]
pub struct MintInviteRequest {
    pub target_did: Option<String>,
    pub role: Option<String>,
    pub expires_in_minutes: Option<i64>,
    pub max_uses: Option<u32>,
    pub owner_host: Option<String>,
    pub deliver: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct InviteMintResponse {
    pub status: String,
    pub invite_id: String,
    pub token_b64: String,
    pub qr_payload: String,
    pub link: String,
    pub expires_at: String,
    pub delivered: bool,
    pub delivery_error: Option<String>,
    pub invite: InviteToken,
}

#[derive(Serialize)]
pub struct InviteDeleteResponse {
    pub status: String,
    pub message: String,
    pub invite_id: String,
}

#[derive(Deserialize)]
pub struct JoinPreviewRequest {
    pub token_b64: String,
}

#[derive(Serialize)]
pub struct JoinPreviewResponse {
    pub status: String,
    pub circle_id: String,
    pub circle_name: String,
    pub issuer_did: String,
    pub role: String,
    pub expires_at: String,
    pub max_uses: u32,
}

#[derive(Deserialize)]
pub struct JoinCircleRequest {
    pub token_b64: String,
    pub owner_host: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct RedeemCircleResponse {
    pub status: String,
    pub message: String,
    pub vc: VerifiableCredential,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_snapshot: Option<CircleMemberSnapshot>,
}

#[derive(Serialize, Deserialize)]
pub struct JoinCircleResponse {
    pub status: String,
    pub message: String,
    pub vc: VerifiableCredential,
    pub circle: Circle,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_snapshot: Option<CircleMemberSnapshot>,
}

#[derive(Serialize)]
pub struct ReceivedInviteListResponse {
    pub status: String,
    pub count: usize,
    pub invites: Vec<ReceivedInvite>,
}

#[derive(Serialize)]
pub struct ReceiveInviteResponse {
    pub status: String,
    pub message: String,
    pub invite: ReceivedInvite,
}

#[derive(Serialize)]
pub struct RejectInviteResponse {
    pub status: String,
    pub message: String,
    pub invite: ReceivedInvite,
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
) -> Result<Json<CircleListResponse>, ApiError> {
    let mut registry = store::load_or_seed(&state.node_id).map_err(map_circle_error)?;
    if is_member_browser_session(&session) {
        registry.circles.retain(|circle| {
            session.as_ref().is_some_and(|Extension(session)| {
                session.claims.circle_ids.contains(&circle.circle_id)
            }) && browser_guardian_has_active_membership(&state, &circle.circle_id).unwrap_or(false)
        });
    }
    Ok(Json(CircleListResponse {
        status: "success".to_string(),
        count: registry.circles.len(),
        circles: registry.circles,
    }))
}

pub async fn detail(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Path(id): Path<String>,
) -> Result<Json<CircleDetailResponse>, ApiError> {
    ensure_member_browser_circle_access(&state, &session, &id)?;
    let circle = store::get_circle(&state.node_id, &id).map_err(map_circle_error)?;
    Ok(Json(CircleDetailResponse {
        status: "success".to_string(),
        circle,
    }))
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateCircleRequest>,
) -> Result<(StatusCode, Json<CircleMutationResponse>), ApiError> {
    let idempotency_key = idempotency::header_key(&headers);
    if let Some(key) = idempotency_key.as_deref() {
        if let Some(cached) = idempotency::lookup::<CircleMutationResponse>("circle:create", key) {
            return Ok((StatusCode::CREATED, Json(cached)));
        }
    }
    let name = required_name(body.name.as_deref())?;
    let description = normalized_description(body.description.as_deref());
    let duration_days = validate_optional_days(body.days)?;
    let circle_id = body
        .circle_id
        .map(|value| normalize_circle_id(&value))
        .transpose()?
        .unwrap_or_else(|| format!("circle-{}", Uuid::new_v4()));
    let (issuer, km) =
        store::load_runtime_signing_context(&state.node_id).map_err(map_circle_error)?;
    let mesh_circle_id = store::mesh_circle_id().map_err(map_circle_error)?;
    issue::ensure_circle_owner(&issuer, &mesh_circle_id, VcAdminAction::Issue, false)
        .map_err(map_vc_error)?;
    let registry = store::load_or_seed(&state.node_id).map_err(map_circle_error)?;
    if registry
        .circles
        .iter()
        .any(|circle| circle.circle_id == circle_id)
    {
        return Err(ApiError::Conflict(format!(
            "circle {} already exists",
            circle_id
        )));
    }

    let owner_vc = issue::issue_membership_vc_with_outcome(
        &issuer,
        &km,
        IssueRequest {
            subject_did: &issuer.did,
            role: CredentialRole::Owner,
            permissions: default_permissions_for_role(CredentialRole::Owner),
            circle_id: &circle_id,
            node_hint: Some(state.node_id.clone()),
            duration_days: Some(duration_days),
        },
    )
    .map_err(map_vc_error)?;
    let circle = store::create_circle(
        &state.node_id,
        circle_id.clone(),
        name.to_string(),
        description,
        issuer.did.clone(),
    )
    .map_err(map_circle_error)?;

    log_audit(
        &state.node_id,
        AuditCategory::Circle,
        AuditSeverity::Info,
        AuditAction::Created,
        &format!("Circle created: {} ({})", circle.circle_id, circle.name),
    );
    if let Err(err) = refresh_and_broadcast_member_snapshot(&state, &circle.circle_id).await {
        tracing::warn!(
            "Circle member snapshot refresh failed after create circle={} error={}",
            circle.circle_id,
            err
        );
    }
    if matches!(owner_vc, IssueMembershipOutcome::IssuedNew { .. }) {
        log_audit(
            &state.node_id,
            AuditCategory::Circle,
            AuditSeverity::Info,
            AuditAction::Succeeded,
            &format!("Circle owner VC ensured for {}", circle.circle_id),
        );
    }

    let response = CircleMutationResponse {
        status: "success".to_string(),
        message: "Circle created".to_string(),
        circle,
    };
    if let Some(key) = idempotency_key.as_deref() {
        idempotency::store("circle:create", key, &response);
    }
    Ok((StatusCode::CREATED, Json(response)))
}

pub async fn edit(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<EditCircleRequest>,
) -> Result<Json<CircleMutationResponse>, ApiError> {
    ensure_circle_owner_access(&state, &id, VcAdminAction::Issue)?;
    let name = body
        .name
        .as_deref()
        .map(|value| required_name(Some(value)).map(str::to_string))
        .transpose()?;
    let description = body
        .description
        .as_deref()
        .map(|value| value.trim().to_string());
    let circle =
        store::edit_circle(&state.node_id, &id, name, description).map_err(map_circle_error)?;
    log_audit(
        &state.node_id,
        AuditCategory::Circle,
        AuditSeverity::Info,
        AuditAction::Updated,
        &format!("Circle updated: {} ({})", circle.circle_id, circle.name),
    );
    Ok(Json(CircleMutationResponse {
        status: "success".to_string(),
        message: "Circle updated".to_string(),
        circle,
    }))
}

pub async fn archive(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<CircleMutationResponse>, ApiError> {
    ensure_circle_owner_access(&state, &id, VcAdminAction::Issue)?;
    let circle = store::archive_circle(&state.node_id, &id).map_err(map_circle_error)?;
    log_audit(
        &state.node_id,
        AuditCategory::Circle,
        AuditSeverity::Warning,
        AuditAction::Updated,
        &format!("Circle archived: {} ({})", circle.circle_id, circle.name),
    );
    Ok(Json(CircleMutationResponse {
        status: "success".to_string(),
        message: "Circle archived".to_string(),
        circle,
    }))
}

pub async fn unarchive(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<CircleMutationResponse>, ApiError> {
    ensure_circle_owner_access(&state, &id, VcAdminAction::Issue)?;
    let circle = store::unarchive_circle(&state.node_id, &id).map_err(map_circle_error)?;
    log_audit(
        &state.node_id,
        AuditCategory::Circle,
        AuditSeverity::Info,
        AuditAction::Updated,
        &format!("Circle unarchived: {} ({})", circle.circle_id, circle.name),
    );
    Ok(Json(CircleMutationResponse {
        status: "success".to_string(),
        message: "Circle unarchived".to_string(),
        circle,
    }))
}

pub async fn delete(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<CircleDeleteResponse>, ApiError> {
    let revoked_vc_ids =
        members::delete_circle(&state.node_id, &id, "circle deleted").map_err(map_circle_error)?;
    log_audit(
        &state.node_id,
        AuditCategory::Circle,
        AuditSeverity::Warning,
        AuditAction::Revoked,
        &format!(
            "Circle deleted: {} members_revoked={}",
            id,
            revoked_vc_ids.len()
        ),
    );
    Ok(Json(CircleDeleteResponse {
        status: "success".to_string(),
        message: "Circle deleted".to_string(),
        circle_id: id,
        revoked_vc_ids,
    }))
}

pub async fn list_members(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Path(id): Path<String>,
) -> Result<Json<MemberListResponse>, ApiError> {
    ensure_member_browser_circle_access(&state, &session, &id)?;
    let members = full_member_list(&state, &id).await?;
    Ok(Json(MemberListResponse {
        status: "success".to_string(),
        count: members.len(),
        members,
    }))
}

/// The complete Circle roster — VC-issued (device/Guardian) members plus
/// locally registered browser members — each with a `join_date`. Shared with
/// `chat::get_history`, which needs the same roster to work out when a
/// requesting member joined so it can withhold messages sent before that.
pub(crate) async fn full_member_list(
    state: &AppState,
    circle_id: &str,
) -> Result<Vec<CircleMember>, ApiError> {
    let mut members = members::list_members(&state.node_id, circle_id).map_err(map_circle_error)?;
    append_browser_members(state, circle_id, &mut members).await?;
    Ok(members)
}

pub async fn member_snapshot(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<CircleMemberSnapshot>, ApiError> {
    let circle = store::get_circle(&state.node_id, &id).map_err(map_circle_error)?;
    let (local, km) =
        store::load_runtime_signing_context(&state.node_id).map_err(map_circle_error)?;
    if local.did != circle.owner_did {
        return Err(ApiError::Forbidden(format!(
            "only owner {} can serve snapshot for {}",
            circle.owner_did, id
        )));
    }
    let snapshot = match snapshot::load(&id).map_err(map_circle_error)? {
        Some(snapshot) => snapshot,
        None => {
            let members = members::list_members_from_local_vcs(&state.node_id, &id, false)
                .map_err(map_circle_error)?;
            snapshot::build_authoritative(&id, &local, &km, members).map_err(map_circle_error)?
        }
    };
    Ok(Json(snapshot))
}

pub async fn sync_member_snapshots(
    State(state): State<Arc<AppState>>,
) -> Result<Json<CircleSnapshotSyncResponse>, ApiError> {
    let applied = snapshot::pull_latest_for_joined_circles(&state.node_id, &state.did_resolver)
        .await
        .map_err(map_circle_error)?;
    Ok(Json(CircleSnapshotSyncResponse {
        status: "success".to_string(),
        snapshots_applied: applied,
    }))
}

async fn append_browser_members(
    state: &AppState,
    circle_id: &str,
    members: &mut Vec<CircleMember>,
) -> Result<(), ApiError> {
    let users = state.admin.users.list().await?;
    let now = chrono::Utc::now().timestamp();
    for user in users {
        if user.role != UserRole::Member
            || user.status != "active"
            || !user.circle_ids.iter().any(|allowed| allowed == circle_id)
            || user
                .registration_expires_at
                .is_none_or(|expiry| expiry <= now)
        {
            continue;
        }

        let registration_id = match user.browser_registration_id.clone() {
            Some(value) if !value.trim().is_empty() => value,
            _ => continue,
        };
        let did = crate::api::handlers::browser_member::did_for_registration(&registration_id);
        let presence = crate::api::handlers::pwa::presence_fields_for_privacy(user.hide_presence, true, "");
        if members.iter().any(|member| {
            member.browser_registration_id.as_deref() == Some(registration_id.as_str())
                || member.did == did
        }) {
            continue;
        }
        members.push(CircleMember {
            did,
            vc_id: user
                .invite_id
                .clone()
                .unwrap_or_else(|| user.user_id.clone()),
            issuer_did: state.device_did.clone(),
            role: CredentialRole::Member,
            permissions: user.scopes.clone(),
            join_date: user.created_at.clone(),
            expiration_date: chrono::DateTime::from_timestamp(
                user.registration_expires_at.unwrap_or(now),
                0,
            )
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| user.created_at.clone()),
            membership_status: crate::vc::credential::MembershipStatus::Active,
            lifecycle_state: crate::circle::MemberLifecycleState::Active,
            node_hint: Some(state.node_id.clone()),
            name: Some(user.name),
            email: Some(user.email),
            member_type: Some("browser".to_string()),
            browser_registration_id: Some(registration_id),
            online: Some(presence.online),
            presence_status: Some(presence.presence_status),
        });
    }
    members.sort_by(|left, right| {
        let left_name = left.name.as_deref().unwrap_or(&left.did);
        let right_name = right.name.as_deref().unwrap_or(&right.did);
        left_name.cmp(right_name)
    });
    Ok(())
}

pub async fn add_member(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<AddMemberRequest>,
) -> Result<(StatusCode, Json<MemberMutationResponse>), ApiError> {
    let did = required_did(body.did.as_deref())?;
    let role = parse_role(body.role.as_deref().unwrap_or("member"))?;
    let days = validate_optional_days(body.days)?;
    let result = members::add_member(&state.node_id, &id, &did, role.clone(), days)
        .map_err(map_circle_error)?;
    if let Err(err) = refresh_and_broadcast_member_snapshot(&state, &id).await {
        tracing::warn!(
            "Circle member snapshot broadcast failed after add circle={} subject={} error={}",
            id,
            did,
            err
        );
    }
    log_audit(
        &state.node_id,
        AuditCategory::Circle,
        AuditSeverity::Info,
        AuditAction::Succeeded,
        &format!(
            "Circle member added: circle={} subject={} role={:?}",
            id, did, role
        ),
    );
    Ok((
        if result.reused_existing {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(MemberMutationResponse {
            status: "success".to_string(),
            message: if result.reused_existing {
                "Existing active membership reused".to_string()
            } else {
                "Circle member added".to_string()
            },
            vc: result.vc,
            reused_existing: result.reused_existing,
            replaced_expired: result.replaced_expired,
        }),
    ))
}

pub async fn remove_member(
    State(state): State<Arc<AppState>>,
    Path((id, did)): Path<(String, String)>,
) -> Result<Json<MemberRemoveResponse>, ApiError> {
    let did = required_did(Some(&did))?;
    let revoked_vc_ids = members::remove_member(&state.node_id, &id, &did, "circle member removed")
        .map_err(map_circle_error)?;
    if let Err(err) = refresh_and_broadcast_member_snapshot(&state, &id).await {
        tracing::warn!(
            "Circle member snapshot broadcast failed after remove circle={} subject={} error={}",
            id,
            did,
            err
        );
    }
    log_audit(
        &state.node_id,
        AuditCategory::Circle,
        AuditSeverity::Warning,
        AuditAction::Revoked,
        &format!("Circle member removed: circle={} subject={}", id, did),
    );
    Ok(Json(MemberRemoveResponse {
        status: "success".to_string(),
        message: "Circle member removed".to_string(),
        revoked_vc_ids,
    }))
}

pub async fn change_role(
    State(state): State<Arc<AppState>>,
    Path((id, did)): Path<(String, String)>,
    Json(body): Json<ChangeRoleRequest>,
) -> Result<Json<MemberMutationResponse>, ApiError> {
    let did = required_did(Some(&did))?;
    let role = parse_role(body.role.as_deref().unwrap_or("member"))?;
    let days = validate_optional_days(body.days)?;
    let result = members::change_role(&state.node_id, &id, &did, role.clone(), days)
        .map_err(map_circle_error)?;
    if let Err(err) = refresh_and_broadcast_member_snapshot(&state, &id).await {
        tracing::warn!(
            "Circle member snapshot broadcast failed after role change circle={} subject={} error={}",
            id,
            did,
            err
        );
    }
    log_audit(
        &state.node_id,
        AuditCategory::Circle,
        AuditSeverity::Info,
        AuditAction::Updated,
        &format!(
            "Circle role changed: circle={} subject={} role={:?}",
            id, did, role
        ),
    );
    Ok(Json(MemberMutationResponse {
        status: "success".to_string(),
        message: "Circle member role updated".to_string(),
        vc: result.vc,
        reused_existing: result.reused_existing,
        replaced_expired: result.replaced_expired,
    }))
}

pub async fn list_invites(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<InviteListResponse>, ApiError> {
    ensure_circle_owner_access(&state, &id, VcAdminAction::Issue)?;
    let invites = invite::list_invites(&id).map_err(map_circle_error)?;
    Ok(Json(InviteListResponse {
        status: "success".to_string(),
        count: invites.len(),
        invites,
    }))
}

pub async fn mint_invite(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<MintInviteRequest>,
) -> Result<(StatusCode, Json<InviteMintResponse>), ApiError> {
    ensure_circle_owner_access(&state, &id, VcAdminAction::Issue)?;
    let idempotency_scope = format!("circle:mint_invite:{}", id);
    let idempotency_key = idempotency::header_key(&headers);
    if let Some(key) = idempotency_key.as_deref() {
        if let Some(cached) = idempotency::lookup::<InviteMintResponse>(&idempotency_scope, key) {
            return Ok((StatusCode::CREATED, Json(cached)));
        }
    }
    let circle = store::get_circle(&state.node_id, &id).map_err(map_circle_error)?;
    if circle.is_archived() {
        return Err(ApiError::Conflict(format!("circle {} is archived", id)));
    }
    let role = parse_role(body.role.as_deref().unwrap_or("member"))?;
    let target_did = required_did(body.target_did.as_deref())?;
    let (issuer, km) =
        store::load_runtime_signing_context(&state.node_id).map_err(map_circle_error)?;
    let invite_token = invite::mint_invite(
        &circle,
        &issuer,
        &km,
        &target_did,
        role.clone(),
        body.expires_in_minutes,
        body.max_uses,
    )
    .map_err(map_circle_error)?;
    let token_b64 = invite::encode_compact(&invite_token).map_err(map_circle_error)?;
    let owner_host = match body.owner_host.as_deref() {
        Some(raw) => normalize_owner_url(raw)?,
        None => resolve_owner_share_url(&state, &issuer.did).await?,
    };
    let link = invite::build_share_link(&token_b64, &owner_host).map_err(map_circle_error)?;
    let (delivered, delivery_error) = if body.deliver.unwrap_or(true) {
        match deliver_invite(&state, &invite_token).await {
            Ok(()) => (true, None),
            Err(err) => (false, Some(err.to_string())),
        }
    } else {
        (
            false,
            Some("delivery disabled; QR/link fallback generated".to_string()),
        )
    };
    log_audit(
        &state.node_id,
        AuditCategory::Circle,
        AuditSeverity::Info,
        AuditAction::Created,
        &format!(
            "Circle invite minted: circle={} invite={} role={:?}",
            id, invite_token.id, role
        ),
    );
    let response = InviteMintResponse {
        status: "success".to_string(),
        invite_id: invite_token.id.clone(),
        token_b64,
        qr_payload: link.clone(),
        link,
        expires_at: invite_token.expires_at.clone(),
        delivered,
        delivery_error,
        invite: invite_token,
    };
    if let Some(key) = idempotency_key.as_deref() {
        idempotency::store(&idempotency_scope, key, &response);
    }
    Ok((StatusCode::CREATED, Json(response)))
}

pub async fn received_invites(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<ReceivedInviteListResponse>, ApiError> {
    let invites = invite::list_received_invites().map_err(map_circle_error)?;
    Ok(Json(ReceivedInviteListResponse {
        status: "success".to_string(),
        count: invites.len(),
        invites,
    }))
}

pub async fn receive_invite(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<InviteToken>,
) -> Result<(StatusCode, Json<ReceiveInviteResponse>), ApiError> {
    verify_guardian_service_auth(&state, &headers, &body).await?;
    invite::verify_invite(&body, &state.did_resolver)
        .await
        .map_err(|err| {
            tracing::warn!(
                "invite signature failed invite={} issuer={} target={} error={}",
                body.id,
                body.issuer_did,
                body.target_did,
                err
            );
            map_circle_error(err)
        })?;
    let (local, _) =
        store::load_runtime_signing_context(&state.node_id).map_err(map_circle_error)?;
    if body.target_did != local.did {
        return Err(ApiError::BadRequest(format!(
            "invite targets {}, this node is {}",
            body.target_did, local.did
        )));
    }
    let received = invite::save_received_invite(body).map_err(map_circle_error)?;
    Ok((
        StatusCode::CREATED,
        Json(ReceiveInviteResponse {
            status: "success".to_string(),
            message: "Circle invite received".to_string(),
            invite: received,
        }),
    ))
}

pub async fn revoke_invite(
    State(state): State<Arc<AppState>>,
    Path((id, invite_id)): Path<(String, String)>,
) -> Result<Json<InviteDeleteResponse>, ApiError> {
    ensure_circle_owner_access(&state, &id, VcAdminAction::Issue)?;
    let invite_token = invite::load_invite(&invite_id).map_err(map_circle_error)?;
    if invite_token.circle_id != id {
        return Err(ApiError::BadRequest(format!(
            "invite {} does not belong to {}",
            invite_id, id
        )));
    }
    invite::delete_invite(&invite_id).map_err(map_circle_error)?;
    log_audit(
        &state.node_id,
        AuditCategory::Circle,
        AuditSeverity::Warning,
        AuditAction::Revoked,
        &format!("Circle invite revoked: circle={} invite={}", id, invite_id),
    );
    Ok(Json(InviteDeleteResponse {
        status: "success".to_string(),
        message: "Circle invite revoked".to_string(),
        invite_id,
    }))
}

pub async fn deliver_existing_invite(
    State(state): State<Arc<AppState>>,
    Path((id, invite_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<InviteMintResponse>, ApiError> {
    ensure_circle_owner_access(&state, &id, VcAdminAction::Issue)?;
    let idempotency_scope = format!("circle:deliver_invite:{}", invite_id);
    let idempotency_key = idempotency::header_key(&headers);
    if let Some(key) = idempotency_key.as_deref() {
        if let Some(cached) = idempotency::lookup::<InviteMintResponse>(&idempotency_scope, key) {
            return Ok(Json(cached));
        }
    }
    let invite_token = invite::load_invite(&invite_id).map_err(map_circle_error)?;
    if invite_token.circle_id != id {
        return Err(ApiError::BadRequest(format!(
            "invite {} does not belong to {}",
            invite_id, id
        )));
    }
    let token_b64 = invite::encode_compact(&invite_token).map_err(map_circle_error)?;
    let owner_host = resolve_owner_share_url(&state, &invite_token.issuer_did).await?;
    let link = invite::build_share_link(&token_b64, &owner_host).map_err(map_circle_error)?;
    let (delivered, delivery_error) = match deliver_invite(&state, &invite_token).await {
        Ok(()) => (true, None),
        Err(err) => (false, Some(err.to_string())),
    };
    let response = InviteMintResponse {
        status: "success".to_string(),
        invite_id: invite_token.id.clone(),
        token_b64,
        qr_payload: link.clone(),
        link,
        expires_at: invite_token.expires_at.clone(),
        delivered,
        delivery_error,
        invite: invite_token,
    };
    if let Some(key) = idempotency_key.as_deref() {
        idempotency::store(&idempotency_scope, key, &response);
    }
    Ok(Json(response))
}

pub async fn join_preview(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Json(body): Json<JoinPreviewRequest>,
) -> Result<Json<JoinPreviewResponse>, ApiError> {
    enforce_join_rate_limit(&state, &session, "preview")?;
    let invite_token = invite::decode_compact(body.token_b64.trim()).map_err(map_circle_error)?;
    invite::verify_invite(&invite_token, &state.did_resolver)
        .await
        .map_err(map_circle_error)?;
    Ok(Json(JoinPreviewResponse {
        status: "success".to_string(),
        circle_id: invite_token.circle_id,
        circle_name: invite_token.circle_name,
        issuer_did: invite_token.issuer_did,
        role: role_name(&invite_token.role),
        expires_at: invite_token.expires_at,
        max_uses: invite_token.max_uses,
    }))
}

pub async fn join(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    headers: HeaderMap,
    Json(body): Json<JoinCircleRequest>,
) -> Result<(StatusCode, Json<JoinCircleResponse>), ApiError> {
    enforce_join_rate_limit(&state, &session, "join")?;
    // Scoped by the invite token itself (not just the client's key) so a
    // retry is recognized as the same join attempt even if the client
    // regenerates its Idempotency-Key, and so two different invites never
    // share a cache slot.
    let idempotency_scope = format!("circle:join:{}", body.token_b64.trim());
    let idempotency_key = idempotency::header_key(&headers);
    if let Some(key) = idempotency_key.as_deref() {
        if let Some(cached) = idempotency::lookup::<JoinCircleResponse>(&idempotency_scope, key) {
            return Ok((StatusCode::CREATED, Json(cached)));
        }
    }
    let invite_token = invite::decode_compact(body.token_b64.trim()).map_err(map_circle_error)?;
    invite::verify_invite(&invite_token, &state.did_resolver)
        .await
        .map_err(map_circle_error)?;
    let owner_host = match body.owner_host.as_deref() {
        Some(raw) => normalize_owner_url(raw)?,
        None => invite::resolve_circle_endpoint(&invite_token.issuer_did, &state.did_resolver)
            .await
            .map_err(map_circle_error)?,
    };
    let (redeemed, circle) = join_remote_circle(&state, invite_token, &owner_host).await?;
    let response = JoinCircleResponse {
        status: redeemed.status,
        message: redeemed.message,
        vc: redeemed.vc,
        circle,
        member_snapshot: redeemed.member_snapshot,
    };
    if let Some(key) = idempotency_key.as_deref() {
        idempotency::store(&idempotency_scope, key, &response);
    }
    Ok((StatusCode::CREATED, Json(response)))
}

/// Redeem a signed Circle invitation at its owner while keeping the browser
/// and resulting membership on the current Guardian. This is shared by the
/// authenticated device-join screen and PWA member onboarding.
pub(crate) async fn join_remote_circle(
    state: &Arc<AppState>,
    invite_token: InviteToken,
    owner_host: &str,
) -> Result<(RedeemCircleResponse, Circle), ApiError> {
    let (joiner, km) =
        store::load_runtime_signing_context(&state.node_id).map_err(map_circle_error)?;
    let join_request =
        invite::sign_join_request(&joiner, &km, invite_token.clone()).map_err(map_circle_error)?;
    if invite_token.target_did != joiner.did {
        return Err(ApiError::BadRequest(format!(
            "invite targets {}, this node is {}",
            invite_token.target_did, joiner.did
        )));
    }
    let owner_url = normalize_owner_url(owner_host)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|err| ApiError::Internal(format!("join client: {}", err)))?;
    let response = client
        .post(format!(
            "{}/api/v1/circles/redeem",
            owner_url.trim_end_matches('/')
        ))
        .json(&join_request)
        .send()
        .await
        .map_err(|err| ApiError::Internal(format!("circle join request failed: {}", err)))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "owner redeem failed".to_string());
        return Err(ApiError::BadRequest(format!(
            "owner redeem failed ({}): {}",
            status, body
        )));
    }

    let redeemed: RedeemCircleResponse = response
        .json()
        .await
        .map_err(|err| ApiError::Internal(format!("redeem response parse: {}", err)))?;
    crate::vc::verify::verify_vc(
        &redeemed.vc,
        &state.did_resolver,
        crate::vc::verify::VerifyOptions {
            expected_subject_did: Some(&state.device_did),
            expected_circle_id: Some(&invite_token.circle_id),
            expected_issuer_did: Some(&invite_token.issuer_did),
            check_status_list: false,
            status_list: None,
        },
    )
    .await
    .map_err(map_vc_error)?;
    crate::vc::persistence::save_own(&redeemed.vc).map_err(map_vc_error)?;
    let circle =
        invite::save_joined_circle(&state.node_id, &invite_token).map_err(map_circle_error)?;
    if let Some(snapshot) = redeemed.member_snapshot.clone() {
        snapshot::accept_from_owner(snapshot, &state.did_resolver)
            .await
            .map_err(map_circle_error)?;
    }
    log_audit(
        &state.node_id,
        AuditCategory::Circle,
        AuditSeverity::Info,
        AuditAction::Succeeded,
        &format!(
            "Circle joined: circle={} owner={}",
            circle.circle_id, circle.owner_did
        ),
    );
    Ok((redeemed, circle))
}

fn enforce_join_rate_limit(
    state: &AppState,
    session: &Option<Extension<AuthenticatedSession>>,
    action: &str,
) -> Result<(), ApiError> {
    let actor = session
        .as_ref()
        .map(|Extension(session)| session.claims.sub.as_str())
        .unwrap_or("login-disabled-local");
    let key = format!("circle-{}:{}", action, actor);
    if state.login_rate_limiter.check_and_record(
        &key,
        chrono::Utc::now().timestamp(),
        state.auth_rate_limit,
    ) {
        Ok(())
    } else {
        Err(ApiError::TooManyRequests(
            "too many Circle join attempts; try again later".into(),
        ))
    }
}

fn is_member_browser_session(session: &Option<Extension<AuthenticatedSession>>) -> bool {
    session
        .as_ref()
        .is_some_and(|Extension(session)| session.claims.role == "member")
}

fn browser_guardian_has_active_membership(
    state: &AppState,
    circle_id: &str,
) -> Result<bool, ApiError> {
    Ok(
        crate::api::auth::authorization::local_active_circle_ids(&state.node_id, &state.device_did)
            .map_err(ApiError::Internal)?
            .contains(circle_id),
    )
}

fn ensure_member_browser_circle_access(
    state: &AppState,
    session: &Option<Extension<AuthenticatedSession>>,
    circle_id: &str,
) -> Result<(), ApiError> {
    if !is_member_browser_session(session)
        || (session.as_ref().is_some_and(|Extension(session)| {
            session
                .claims
                .circle_ids
                .iter()
                .any(|allowed| allowed == circle_id)
        }) && browser_guardian_has_active_membership(state, circle_id)?)
    {
        Ok(())
    } else {
        if let Some(Extension(session)) = session.as_ref() {
            crate::api::auth::authorization::audit_member_resource_denied(
                &state.node_id,
                &session.claims.sub,
                "Circle",
            );
        }
        Err(ApiError::Forbidden(
            "Guardian is not an active member of this Circle".into(),
        ))
    }
}

pub async fn accept_invite(
    State(state): State<Arc<AppState>>,
    Path(invite_id): Path<String>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<JoinCircleResponse>), ApiError> {
    let received = invite::load_received_invite(&invite_id).map_err(map_circle_error)?;
    if matches!(received.state, ReceivedInviteState::Rejected) {
        return Err(ApiError::Conflict(format!(
            "invite {} was rejected",
            invite_id
        )));
    }
    let token_b64 = invite::encode_compact(&received.invite).map_err(map_circle_error)?;
    let result = join(
        State(state),
        None,
        headers,
        Json(JoinCircleRequest {
            token_b64,
            owner_host: None,
        }),
    )
    .await?;
    invite::set_received_invite_state(&invite_id, ReceivedInviteState::Accepted)
        .map_err(map_circle_error)?;
    Ok(result)
}

pub async fn reject_invite(
    State(_state): State<Arc<AppState>>,
    Path(invite_id): Path<String>,
) -> Result<Json<RejectInviteResponse>, ApiError> {
    let invite = invite::set_received_invite_state(&invite_id, ReceivedInviteState::Rejected)
        .map_err(map_circle_error)?;
    Ok(Json(RejectInviteResponse {
        status: "success".to_string(),
        message: "Circle invite rejected".to_string(),
        invite,
    }))
}

pub async fn redeem(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<JoinRequest>,
) -> Result<(StatusCode, Json<RedeemCircleResponse>), ApiError> {
    // Scoped by invite + joiner: `assert_redeemable` below already rejects a
    // same-joiner replay outright (`CircleError::InviteReplay`), so this
    // mainly turns that hard error into a clean replay of the original
    // success response for a client that merely timed out waiting for it.
    let idempotency_scope = format!("circle:redeem:{}:{}", body.invite_token.id, body.joiner_did);
    let idempotency_key = idempotency::header_key(&headers);
    if let Some(key) = idempotency_key.as_deref() {
        if let Some(cached) = idempotency::lookup::<RedeemCircleResponse>(&idempotency_scope, key) {
            return Ok((StatusCode::CREATED, Json(cached)));
        }
    }
    invite::verify_invite(&body.invite_token, &state.did_resolver)
        .await
        .map_err(map_circle_error)?;
    invite::verify_join_request(&body, &state.did_resolver)
        .await
        .map_err(map_circle_error)?;

    if crate::crl::is_revoked(&body.joiner_did) {
        log_audit(
            &state.node_id,
            AuditCategory::Circle,
            AuditSeverity::Warning,
            AuditAction::Rejected,
            &format!(
                "Circle invite redemption rejected for revoked DID {}",
                body.joiner_did
            ),
        );
        return Err(ApiError::Conflict(format!(
            "joiner DID {} is revoked",
            body.joiner_did
        )));
    }

    let (issuer, km) =
        store::load_runtime_signing_context(&state.node_id).map_err(map_circle_error)?;
    let circle = store::get_circle(&state.node_id, &body.invite_token.circle_id)
        .map_err(map_circle_error)?;
    if circle.is_archived() {
        return Err(ApiError::Conflict(format!(
            "circle {} is archived",
            circle.circle_id
        )));
    }

    let vc = {
        let _guard = CIRCLE_WRITE_LOCK
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        issue::ensure_circle_owner(&issuer, &circle.circle_id, VcAdminAction::Issue, false)
            .map_err(map_vc_error)?;
        invite::assert_redeemable(&circle, &body.invite_token, &body.joiner_did)
            .map_err(map_circle_error)?;

        let outcome = issue::issue_membership_vc_with_outcome(
            &issuer,
            &km,
            IssueRequest {
                subject_did: &body.joiner_did,
                role: body.invite_token.role.clone(),
                permissions: default_permissions_for_role(body.invite_token.role.clone()),
                circle_id: &circle.circle_id,
                node_hint: None,
                duration_days: Some(issue::DEFAULT_VC_DURATION_DAYS),
            },
        )
        .map_err(map_vc_error)?;
        invite::record_redemption(&body.invite_token.id, &body.joiner_did)
            .map_err(map_circle_error)?;
        outcome.into_vc()
    };
    let member_snapshot = match refresh_and_broadcast_member_snapshot_skipping(
        &state,
        &circle.circle_id,
        Some(body.joiner_did.as_str()),
    )
    .await
    {
        Ok(snapshot) => Some(snapshot),
        Err(err) => {
            tracing::warn!(
                "Circle member snapshot broadcast failed after redeem circle={} joiner={} error={}",
                circle.circle_id,
                body.joiner_did,
                err
            );
            None
        }
    };
    log_audit(
        &state.node_id,
        AuditCategory::Circle,
        AuditSeverity::Info,
        AuditAction::Succeeded,
        &format!(
            "Circle invite redeemed: circle={} invite={} joiner={}",
            circle.circle_id, body.invite_token.id, body.joiner_did
        ),
    );
    let response = RedeemCircleResponse {
        status: "success".to_string(),
        message: "Circle membership issued".to_string(),
        vc,
        member_snapshot,
    };
    if let Some(key) = idempotency_key.as_deref() {
        idempotency::store(&idempotency_scope, key, &response);
    }
    Ok((StatusCode::CREATED, Json(response)))
}

pub async fn receive_member_snapshot(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CircleMemberSnapshot>,
) -> Result<Json<MemberListResponse>, ApiError> {
    verify_guardian_snapshot_auth(&state, &headers, &body).await?;
    let circle_id = body.circle_id.clone();
    let previously_known: std::collections::HashSet<String> =
        members::list_members(&state.node_id, &circle_id)
            .map(|members| members.into_iter().map(|member| member.did).collect())
            .unwrap_or_default();
    let circle_label = store::get_circle(&state.node_id, &circle_id)
        .map(|circle| circle.name)
        .unwrap_or_else(|_| circle_id.clone());
    let snapshot = snapshot::accept_from_owner(body, &state.did_resolver)
        .await
        .map_err(map_circle_error)?;
    for member in &snapshot.members {
        if member.membership_status == crate::vc::credential::MembershipStatus::Active
            && member.lifecycle_state == crate::circle::MemberLifecycleState::Active
            && !previously_known.contains(&member.did)
        {
            let member_label = member.name.clone().unwrap_or_else(|| member.did.clone());
            crate::notify::publish_circle_member_joined(
                &member.did,
                &member_label,
                &circle_label,
                &circle_id,
            );
        }
    }
    log_audit(
        &state.node_id,
        AuditCategory::Circle,
        AuditSeverity::Info,
        AuditAction::Updated,
        &format!(
            "Circle member snapshot synchronized: circle={} version={} members={}",
            snapshot.circle_id,
            snapshot.version,
            snapshot.members.len()
        ),
    );
    Ok(Json(MemberListResponse {
        status: "success".to_string(),
        count: snapshot.members.len(),
        members: snapshot.members,
    }))
}

async fn refresh_and_broadcast_member_snapshot(
    state: &Arc<AppState>,
    circle_id: &str,
) -> Result<CircleMemberSnapshot, CircleError> {
    refresh_and_broadcast_member_snapshot_skipping(state, circle_id, None).await
}

async fn refresh_and_broadcast_member_snapshot_skipping(
    state: &Arc<AppState>,
    circle_id: &str,
    skip_did: Option<&str>,
) -> Result<CircleMemberSnapshot, CircleError> {
    let (owner, km) = store::load_runtime_signing_context(&state.node_id)?;
    let circle = store::get_circle(&state.node_id, circle_id)?;
    if owner.did != circle.owner_did {
        return Err(CircleError::Invalid(format!(
            "local DID {} is not owner {} for {}",
            owner.did, circle.owner_did, circle_id
        )));
    }
    let members = members::list_members_from_local_vcs(&state.node_id, circle_id, false)?;
    let snapshot = snapshot::build_authoritative(circle_id, &owner, &km, members)?;
    broadcast_member_snapshot(state, &snapshot, skip_did).await;
    Ok(snapshot)
}

async fn broadcast_member_snapshot(
    state: &Arc<AppState>,
    snapshot: &CircleMemberSnapshot,
    skip_did: Option<&str>,
) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            tracing::warn!("Circle member snapshot client creation failed: {}", err);
            return;
        }
    };
    for member in snapshot.members.iter() {
        if member.did == snapshot.owner_did {
            continue;
        }
        if skip_did == Some(member.did.as_str()) {
            continue;
        }
        let (owner, km) = match store::load_runtime_signing_context(&state.node_id) {
            Ok(context) => context,
            Err(err) => {
                tracing::warn!(
                    "Circle member snapshot auth context failed circle={} target={} error={}",
                    snapshot.circle_id,
                    member.did,
                    err
                );
                continue;
            }
        };
        let timestamp = Utc::now().to_rfc3339();
        let nonce = Uuid::new_v4().to_string();
        let canonical = match guardian_snapshot_auth_bytes(&owner.did, &timestamp, &nonce, snapshot)
        {
            Ok(bytes) => bytes,
            Err(err) => {
                tracing::warn!(
                    "Circle member snapshot auth canonical failed circle={} target={} error={}",
                    snapshot.circle_id,
                    member.did,
                    err
                );
                continue;
            }
        };
        let digest = Sha256::digest(&canonical);
        let signature = match km.sign(&digest) {
            Ok(signature) => signature,
            Err(err) => {
                tracing::warn!(
                    "Circle member snapshot auth signing failed circle={} target={} error={}",
                    snapshot.circle_id,
                    member.did,
                    err
                );
                continue;
            }
        };
        let signature_b64 = general_purpose::STANDARD.encode(signature);
        let endpoints =
            circle_member_delivery_endpoints(&member.did, &owner.did, &state.did_resolver).await;
        if endpoints.is_empty() {
            tracing::warn!(
                "Circle member snapshot endpoint resolve failed circle={} target={}",
                snapshot.circle_id,
                member.did
            );
            continue;
        }
        for endpoint in endpoints {
            let response = client
                .post(format!(
                    "{}/api/v1/circles/snapshots/inbox",
                    endpoint.trim_end_matches('/')
                ))
                .header(
                    reqwest::header::AUTHORIZATION,
                    format!("{}{}", GUARDIAN_SERVICE_AUTH_SCHEME, signature_b64),
                )
                .header(HEADER_GUARDIAN_DID, owner.did.clone())
                .header(HEADER_GUARDIAN_TIMESTAMP, timestamp.clone())
                .header(HEADER_GUARDIAN_NONCE, nonce.clone())
                .json(snapshot)
                .send()
                .await;
            match response {
                Ok(response) if response.status().is_success() => {
                    tracing::info!(
                        "Circle member snapshot delivered circle={} version={} target={}",
                        snapshot.circle_id,
                        snapshot.version,
                        member.did
                    );
                    break;
                }
                Ok(response) => {
                    let status = response.status();
                    let body = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "snapshot delivery failed".to_string());
                    tracing::warn!(
                        "Circle member snapshot delivery rejected circle={} target={} endpoint={} status={} body={}",
                        snapshot.circle_id,
                        member.did,
                        endpoint,
                        status,
                        body
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        "Circle member snapshot delivery failed circle={} target={} endpoint={} error={}",
                        snapshot.circle_id,
                        member.did,
                        endpoint,
                        err
                    );
                }
            }
        }
    }
}

async fn circle_member_delivery_endpoints(
    target_did: &str,
    self_did: &str,
    resolver: &crate::did::Resolver,
) -> Vec<String> {
    let mut endpoints = Vec::new();
    if let Ok(endpoint) = invite::resolve_circle_endpoint(target_did, resolver).await {
        endpoints.push(endpoint);
    }
    for peer in crate::crl::gossip::engine::active_gossip_peers(self_did) {
        if peer.did == target_did {
            let endpoint = format!("http://{}:8443", peer.overlay_ip);
            if !endpoints.iter().any(|existing| existing == &endpoint) {
                endpoints.push(endpoint);
            }
        }
    }
    endpoints
}

async fn deliver_invite(state: &Arc<AppState>, token: &InviteToken) -> Result<(), CircleError> {
    let endpoint = invite::resolve_circle_endpoint(&token.target_did, &state.did_resolver).await?;
    let (issuer, km) = store::load_runtime_signing_context(&state.node_id)
        .map_err(|err| CircleError::Invalid(format!("service auth signing context: {}", err)))?;
    if issuer.did != token.issuer_did {
        return Err(CircleError::Invalid(format!(
            "service auth DID {} does not match invite issuer {}",
            issuer.did, token.issuer_did
        )));
    }
    let timestamp = Utc::now().to_rfc3339();
    let nonce = Uuid::new_v4().to_string();
    let canonical = guardian_service_auth_bytes(&issuer.did, token, &timestamp, &nonce)
        .map_err(|err| CircleError::Invalid(format!("service auth canonical bytes: {}", err)))?;
    let digest = Sha256::digest(&canonical);
    let signature = km
        .sign(&digest)
        .map_err(|err| CircleError::Invalid(format!("service auth sign: {}", err)))?;
    let signature_b64 = general_purpose::STANDARD.encode(signature);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|err| CircleError::Invalid(format!("invite delivery client: {}", err)))?;
    let response = client
        .post(format!(
            "{}/api/v1/circles/invites/inbox",
            endpoint.trim_end_matches('/')
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("{}{}", GUARDIAN_SERVICE_AUTH_SCHEME, signature_b64),
        )
        .header(HEADER_GUARDIAN_DID, issuer.did)
        .header(HEADER_GUARDIAN_TIMESTAMP, timestamp)
        .header(HEADER_GUARDIAN_NONCE, nonce)
        .json(token)
        .send()
        .await
        .map_err(|err| {
            CircleError::Invalid(format!(
                "unreachable endpoint for {} at {}: {}",
                token.target_did, endpoint, err
            ))
        })?;
    if response.status().is_success() {
        tracing::info!(
            "Circle invite delivered target_did={} endpoint={}",
            token.target_did,
            endpoint
        );
        Ok(())
    } else {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "delivery failed".to_string());
        tracing::warn!(
            "remote delivery failed target_did={} status={} body={}",
            token.target_did,
            status,
            body
        );
        Err(CircleError::Invalid(format!(
            "invite delivery failed for {} ({}): {}",
            token.target_did, status, body
        )))
    }
}

async fn verify_guardian_service_auth(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    token: &InviteToken,
) -> Result<(), ApiError> {
    let canonical =
        guardian_service_auth_bytes(&token.issuer_did, token, "", "").map_err(|err| {
            tracing::warn!(
                "peer/service auth failed invite={} issuer={} reason=canonical template {}",
                token.id,
                token.issuer_did,
                err
            );
            ApiError::Unauthorized("peer/service auth failed".to_string())
        })?;
    verify_guardian_service_auth_for_payload(
        state,
        headers,
        &token.issuer_did,
        &format!("invite={}", token.id),
        move |service_did, timestamp, nonce| {
            let _ = &canonical;
            guardian_service_auth_bytes(service_did, token, timestamp, nonce)
        },
    )
    .await
}

async fn verify_guardian_snapshot_auth(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    snapshot: &CircleMemberSnapshot,
) -> Result<(), ApiError> {
    verify_guardian_service_auth_for_payload(
        state,
        headers,
        &snapshot.owner_did,
        &format!(
            "snapshot circle={} version={}",
            snapshot.circle_id, snapshot.version
        ),
        move |service_did, timestamp, nonce| {
            guardian_snapshot_auth_bytes(service_did, timestamp, nonce, snapshot)
        },
    )
    .await
}

async fn verify_guardian_service_auth_for_payload<F>(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    expected_service_did: &str,
    label: &str,
    canonical: F,
) -> Result<(), ApiError>
where
    F: Fn(&str, &str, &str) -> Result<Vec<u8>, serde_json::Error>,
{
    let auth = header_value(headers, header::AUTHORIZATION.as_str()).ok_or_else(|| {
        tracing::warn!(
            "peer/service auth failed {} reason=missing authorization header",
            label
        );
        ApiError::Unauthorized("peer/service auth failed".to_string())
    })?;
    let signature_b64 = auth
        .strip_prefix(GUARDIAN_SERVICE_AUTH_SCHEME)
        .ok_or_else(|| {
            tracing::warn!(
                "peer/service auth failed {} reason=unsupported authorization scheme",
                label
            );
            ApiError::Unauthorized("peer/service auth failed".to_string())
        })?;
    let service_did = header_value(headers, HEADER_GUARDIAN_DID).ok_or_else(|| {
        tracing::warn!(
            "peer/service auth failed {} reason=missing guardian did header",
            label
        );
        ApiError::Unauthorized("peer/service auth failed".to_string())
    })?;
    let timestamp = header_value(headers, HEADER_GUARDIAN_TIMESTAMP).ok_or_else(|| {
        tracing::warn!(
            "peer/service auth failed {} reason=missing timestamp header",
            label
        );
        ApiError::Unauthorized("peer/service auth failed".to_string())
    })?;
    let nonce = header_value(headers, HEADER_GUARDIAN_NONCE).ok_or_else(|| {
        tracing::warn!(
            "peer/service auth failed {} reason=missing nonce header",
            label
        );
        ApiError::Unauthorized("peer/service auth failed".to_string())
    })?;

    if service_did != expected_service_did {
        tracing::warn!(
            "peer/service auth failed {} reason=service DID {} does not match expected {}",
            label,
            service_did,
            expected_service_did
        );
        return Err(ApiError::Unauthorized(
            "peer/service auth failed".to_string(),
        ));
    }
    if nonce.trim().len() < 8 {
        tracing::warn!(
            "peer/service auth failed {} issuer={} reason=nonce too short",
            label,
            service_did
        );
        return Err(ApiError::Unauthorized(
            "peer/service auth failed".to_string(),
        ));
    }
    let created_at = DateTime::parse_from_rfc3339(timestamp).map_err(|err| {
        tracing::warn!(
            "peer/service auth failed {} issuer={} reason=bad timestamp {}",
            label,
            service_did,
            err
        );
        ApiError::Unauthorized("peer/service auth failed".to_string())
    })?;
    let age = (Utc::now() - created_at.with_timezone(&Utc))
        .num_seconds()
        .abs();
    if age > GUARDIAN_SERVICE_AUTH_SKEW_SECS {
        tracing::warn!(
            "peer/service auth failed {} issuer={} reason=timestamp skew {}s",
            label,
            service_did,
            age
        );
        return Err(ApiError::Unauthorized(
            "peer/service auth failed".to_string(),
        ));
    }

    let signature = general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|err| {
            tracing::warn!(
                "peer/service auth failed {} issuer={} reason=signature base64 {}",
                label,
                service_did,
                err
            );
            ApiError::Unauthorized("peer/service auth failed".to_string())
        })?;
    let canonical = canonical(service_did, timestamp, nonce).map_err(|err| {
        tracing::warn!(
            "peer/service auth failed {} issuer={} reason=canonical bytes {}",
            label,
            service_did,
            err
        );
        ApiError::Unauthorized("peer/service auth failed".to_string())
    })?;
    let digest = Sha256::digest(&canonical);
    let resolved = state
        .did_resolver
        .resolve(service_did)
        .await
        .map_err(|err| {
            tracing::warn!(
                "peer/service auth failed {} issuer={} reason=DID resolve {}",
                label,
                service_did,
                err
            );
            ApiError::Unauthorized("peer/service auth failed".to_string())
        })?;
    let public_key = general_purpose::STANDARD
        .decode(resolved.public_key_der_b64)
        .map_err(|err| {
            tracing::warn!(
                "peer/service auth failed {} issuer={} reason=public key decode {}",
                label,
                service_did,
                err
            );
            ApiError::Unauthorized("peer/service auth failed".to_string())
        })?;
    crate::did::doc_sign::ecdsa_p256_verify_der_or_raw(&public_key, &digest, &signature).map_err(
        |err| {
            tracing::warn!(
                "peer/service auth failed {} issuer={} reason=signature verify {}",
                label,
                service_did,
                err
            );
            ApiError::Unauthorized("peer/service auth failed".to_string())
        },
    )?;
    Ok(())
}

fn guardian_service_auth_bytes(
    service_did: &str,
    token: &InviteToken,
    timestamp: &str,
    nonce: &str,
) -> Result<Vec<u8>, serde_json::Error> {
    let token_hash = Sha256::digest(token.canonical_bytes_for_sign()?);
    guardian_service_auth_bytes_for_hash(
        GUARDIAN_SERVICE_AUTH_PATH,
        service_did,
        timestamp,
        nonce,
        &token_hash,
    )
}

fn guardian_snapshot_auth_bytes(
    service_did: &str,
    timestamp: &str,
    nonce: &str,
    snapshot: &CircleMemberSnapshot,
) -> Result<Vec<u8>, serde_json::Error> {
    let snapshot_hash = Sha256::digest(snapshot.canonical_bytes_for_sign()?);
    guardian_service_auth_bytes_for_hash(
        GUARDIAN_SERVICE_SNAPSHOT_PATH,
        service_did,
        timestamp,
        nonce,
        &snapshot_hash,
    )
}

fn guardian_service_auth_bytes_for_hash(
    path: &str,
    service_did: &str,
    timestamp: &str,
    nonce: &str,
    payload_hash: &[u8],
) -> Result<Vec<u8>, serde_json::Error> {
    Ok(format!(
        "{}\nPOST\n{}\n{}\n{}\n{}\n{}",
        GUARDIAN_SERVICE_AUTH_CONTEXT,
        path,
        service_did,
        timestamp,
        nonce,
        general_purpose::STANDARD.encode(payload_hash)
    )
    .into_bytes())
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn ensure_circle_owner_access(
    state: &Arc<AppState>,
    circle_id: &str,
    action: VcAdminAction,
) -> Result<(), ApiError> {
    let (issuer, _) =
        store::load_runtime_signing_context(&state.node_id).map_err(map_circle_error)?;
    issue::ensure_circle_owner(&issuer, circle_id, action, false).map_err(map_vc_error)
}

fn required_name(raw: Option<&str>) -> Result<&str, ApiError> {
    let value = raw.ok_or_else(|| ApiError::BadRequest("name is required".to_string()))?;
    let value = value.trim();
    if value.is_empty() {
        return Err(ApiError::BadRequest("name must not be empty".to_string()));
    }
    if value.len() > 120 {
        return Err(ApiError::BadRequest(
            "name must be 120 characters or fewer".to_string(),
        ));
    }
    Ok(value)
}

fn normalized_description(raw: Option<&str>) -> String {
    raw.map(|value| value.trim().to_string())
        .unwrap_or_default()
}

fn normalize_circle_id(raw: &str) -> Result<String, ApiError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(ApiError::BadRequest(
            "circle_id must not be empty".to_string(),
        ));
    }
    if value.contains('/') || value.contains('\\') || value.contains(' ') {
        return Err(ApiError::BadRequest(
            "circle_id may not contain spaces or path separators".to_string(),
        ));
    }
    Ok(value.to_string())
}

fn required_did(raw: Option<&str>) -> Result<String, ApiError> {
    let value = raw.ok_or_else(|| ApiError::BadRequest("did is required".to_string()))?;
    Did::parse(value.trim())
        .map(|did| did.to_string())
        .map_err(|err| ApiError::BadRequest(format!("invalid DID: {}", err)))
}

fn parse_role(raw: &str) -> Result<CredentialRole, ApiError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "owner" => Ok(CredentialRole::Owner),
        "member" => Ok(CredentialRole::Member),
        other => Err(ApiError::BadRequest(format!(
            "unsupported role '{}'",
            other
        ))),
    }
}

fn role_name(role: &CredentialRole) -> String {
    match role {
        CredentialRole::Owner => "owner",
        CredentialRole::Member => "member",
    }
    .to_string()
}

fn validate_optional_days(days: Option<i64>) -> Result<i64, ApiError> {
    let value = days.unwrap_or(issue::DEFAULT_VC_DURATION_DAYS);
    if !(1..=3650).contains(&value) {
        return Err(ApiError::BadRequest(
            "days must be between 1 and 3650".to_string(),
        ));
    }
    Ok(value)
}

pub(crate) fn normalize_owner_url(raw: &str) -> Result<String, ApiError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest(
            "owner_host must not be empty".to_string(),
        ));
    }
    let with_scheme = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{}", trimmed)
    };
    let (scheme, rest) = with_scheme
        .split_once("://")
        .ok_or_else(|| ApiError::BadRequest("owner_host has invalid scheme".to_string()))?;
    let rest = rest.trim_end_matches('/');
    let (authority, suffix) = match rest.split_once('/') {
        Some((authority, suffix)) => (authority.to_string(), format!("/{}", suffix)),
        None => (rest.to_string(), String::new()),
    };
    let authority = if authority.contains(':') {
        authority
    } else {
        format!("{}:8443", authority)
    };
    Ok(format!("{}://{}{}", scheme, authority, suffix))
}

async fn resolve_owner_share_url(
    state: &Arc<AppState>,
    owner_did: &str,
) -> Result<String, ApiError> {
    if let Ok(raw) = std::env::var("SGX_PUBLIC_API_URL") {
        return normalize_owner_url(&raw);
    }
    invite::resolve_circle_endpoint(owner_did, &state.did_resolver)
        .await
        .map(|endpoint| endpoint.replacen("http://", "https://", 1))
        .map_err(map_circle_error)
}

fn map_circle_error(err: CircleError) -> ApiError {
    match err {
        CircleError::NotFound(item) => ApiError::NotFound(item),
        CircleError::Conflict(message) => ApiError::Conflict(message),
        CircleError::Invalid(_)
        | CircleError::InvalidProof(_)
        | CircleError::InviteExpired(_)
        | CircleError::InviteReplay(_)
        | CircleError::QrPayloadTooLarge { .. } => ApiError::BadRequest(err.to_string()),
        CircleError::Vc(vc_err) => map_vc_error(vc_err),
        CircleError::Io(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ApiError::NotFound(error.to_string())
        }
        _ => ApiError::Internal(err.to_string()),
    }
}

fn map_vc_error(err: crate::vc::errors::VcError) -> ApiError {
    match err {
        crate::vc::errors::VcError::NotCircleOwnerForIssue
        | crate::vc::errors::VcError::NotCircleOwnerForRevoke
        | crate::vc::errors::VcError::NotCircleOwnerForRenew => {
            ApiError::Forbidden(err.to_string())
        }
        crate::vc::errors::VcError::NotFound(item) => ApiError::NotFound(item),
        crate::vc::errors::VcError::CannotRenewRevokedVc
        | crate::vc::errors::VcError::CannotRenewExpiredVc(_) => {
            ApiError::Conflict(err.to_string())
        }
        crate::vc::errors::VcError::InvalidStructure(_)
        | crate::vc::errors::VcError::InvalidMembershipStatus(_)
        | crate::vc::errors::VcError::UnknownPermission(_)
        | crate::vc::errors::VcError::IndexOutOfRange { .. }
        | crate::vc::errors::VcError::CircleMismatch { .. }
        | crate::vc::errors::VcError::IssuerMismatch { .. }
        | crate::vc::errors::VcError::SubjectMismatch { .. } => {
            ApiError::BadRequest(err.to_string())
        }
        crate::vc::errors::VcError::Io(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ApiError::NotFound(error.to_string())
        }
        other => ApiError::Internal(other.to_string()),
    }
}
