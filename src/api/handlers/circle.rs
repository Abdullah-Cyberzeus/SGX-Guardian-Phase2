use crate::api::{error::ApiError, state::AppState};
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::circle::invite::{self, InviteToken, JoinRequest};
use crate::circle::members::{self, CircleMember};
use crate::circle::store::{self, CIRCLE_WRITE_LOCK};
use crate::circle::{Circle, CircleError};
use crate::did::Did;
use crate::vc::credential::{CredentialRole, VerifiableCredential};
use crate::vc::issue::{
    self, default_permissions_for_role, IssueMembershipOutcome, IssueRequest, VcAdminAction,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

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

#[derive(Serialize)]
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
    pub role: Option<String>,
    pub expires_in_minutes: Option<i64>,
    pub max_uses: Option<u32>,
    pub owner_host: Option<String>,
}

#[derive(Serialize)]
pub struct InviteMintResponse {
    pub status: String,
    pub invite_id: String,
    pub token_b64: String,
    pub qr_payload: String,
    pub link: String,
    pub expires_at: String,
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
    pub owner_host: String,
}

#[derive(Serialize, Deserialize)]
pub struct RedeemCircleResponse {
    pub status: String,
    pub message: String,
    pub vc: VerifiableCredential,
}

#[derive(Serialize)]
pub struct JoinCircleResponse {
    pub status: String,
    pub message: String,
    pub vc: VerifiableCredential,
    pub circle: Circle,
}

pub async fn list(
    State(state): State<Arc<AppState>>,
) -> Result<Json<CircleListResponse>, ApiError> {
    let registry = store::load_or_seed(&state.node_id).map_err(map_circle_error)?;
    Ok(Json(CircleListResponse {
        status: "success".to_string(),
        count: registry.circles.len(),
        circles: registry.circles,
    }))
}

pub async fn detail(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<CircleDetailResponse>, ApiError> {
    let circle = store::get_circle(&state.node_id, &id).map_err(map_circle_error)?;
    Ok(Json(CircleDetailResponse {
        status: "success".to_string(),
        circle,
    }))
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateCircleRequest>,
) -> Result<(StatusCode, Json<CircleMutationResponse>), ApiError> {
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
    if matches!(owner_vc, IssueMembershipOutcome::IssuedNew { .. }) {
        log_audit(
            &state.node_id,
            AuditCategory::Circle,
            AuditSeverity::Info,
            AuditAction::Succeeded,
            &format!("Circle owner VC ensured for {}", circle.circle_id),
        );
    }

    Ok((
        StatusCode::CREATED,
        Json(CircleMutationResponse {
            status: "success".to_string(),
            message: "Circle created".to_string(),
            circle,
        }),
    ))
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
    Path(id): Path<String>,
) -> Result<Json<MemberListResponse>, ApiError> {
    let members = members::list_members(&state.node_id, &id).map_err(map_circle_error)?;
    Ok(Json(MemberListResponse {
        status: "success".to_string(),
        count: members.len(),
        members,
    }))
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
    Json(body): Json<MintInviteRequest>,
) -> Result<(StatusCode, Json<InviteMintResponse>), ApiError> {
    ensure_circle_owner_access(&state, &id, VcAdminAction::Issue)?;
    let circle = store::get_circle(&state.node_id, &id).map_err(map_circle_error)?;
    if circle.is_archived() {
        return Err(ApiError::Conflict(format!("circle {} is archived", id)));
    }
    let role = parse_role(body.role.as_deref().unwrap_or("member"))?;
    let (issuer, km) =
        store::load_runtime_signing_context(&state.node_id).map_err(map_circle_error)?;
    let invite_token = invite::mint_invite(
        &circle,
        &issuer,
        &km,
        role.clone(),
        body.expires_in_minutes,
        body.max_uses,
    )
    .map_err(map_circle_error)?;
    let token_b64 = invite::encode_compact(&invite_token).map_err(map_circle_error)?;
    let owner_host = body
        .owner_host
        .as_deref()
        .map(normalize_owner_url)
        .transpose()?
        .unwrap_or_else(|| "http://127.0.0.1:8443".to_string());
    let link = invite::build_share_link(&token_b64, &owner_host).map_err(map_circle_error)?;
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
    Ok((
        StatusCode::CREATED,
        Json(InviteMintResponse {
            status: "success".to_string(),
            invite_id: invite_token.id.clone(),
            token_b64,
            qr_payload: link.clone(),
            link,
            expires_at: invite_token.expires_at.clone(),
            invite: invite_token,
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

pub async fn join_preview(
    State(state): State<Arc<AppState>>,
    Json(body): Json<JoinPreviewRequest>,
) -> Result<Json<JoinPreviewResponse>, ApiError> {
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
    Json(body): Json<JoinCircleRequest>,
) -> Result<(StatusCode, Json<JoinCircleResponse>), ApiError> {
    let invite_token = invite::decode_compact(body.token_b64.trim()).map_err(map_circle_error)?;
    invite::verify_invite(&invite_token, &state.did_resolver)
        .await
        .map_err(map_circle_error)?;
    let (joiner, km) =
        store::load_runtime_signing_context(&state.node_id).map_err(map_circle_error)?;
    let join_request =
        invite::sign_join_request(&joiner, &km, invite_token.clone()).map_err(map_circle_error)?;
    let owner_url = normalize_owner_url(&body.owner_host)?;
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
    crate::vc::persistence::save_own(&redeemed.vc).map_err(map_vc_error)?;
    let circle =
        invite::save_joined_circle(&state.node_id, &invite_token).map_err(map_circle_error)?;
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
    Ok((
        StatusCode::CREATED,
        Json(JoinCircleResponse {
            status: redeemed.status,
            message: redeemed.message,
            vc: redeemed.vc,
            circle,
        }),
    ))
}

pub async fn redeem(
    State(state): State<Arc<AppState>>,
    Json(body): Json<JoinRequest>,
) -> Result<(StatusCode, Json<RedeemCircleResponse>), ApiError> {
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
    invite::record_redemption(&body.invite_token.id, &body.joiner_did).map_err(map_circle_error)?;
    let vc = outcome.into_vc();
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
    Ok((
        StatusCode::CREATED,
        Json(RedeemCircleResponse {
            status: "success".to_string(),
            message: "Circle membership issued".to_string(),
            vc,
        }),
    ))
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

fn normalize_owner_url(raw: &str) -> Result<String, ApiError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest(
            "owner_host must not be empty".to_string(),
        ));
    }
    let with_scheme = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{}", trimmed)
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
