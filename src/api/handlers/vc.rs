use crate::api::{error::ApiError, state::AppState};
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::did::{Did, DidRecord};
use crate::vc::credential::{CredentialRole, VerifiableCredential};
use crate::vc::issue::{self, IssueMembershipOutcome, IssueRequest, RenewRequest};
use crate::vc::{VcError, distribution, persistence, status_list, verify};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path as StdPath, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

const DID_PATH_ENV: &str = "SGX_GUARDIAN_DID_PATH";

#[derive(Deserialize, Default)]
pub struct IssueVcRequest {
    pub to: Option<String>,
    pub subject_did: Option<String>,
    pub role: Option<String>,
    pub permissions: Option<Vec<String>>,
    pub days: Option<i64>,
}

#[derive(Serialize)]
pub struct IssueVcResponse {
    pub status: String,
    pub message: String,
    pub vc_id: String,
    pub subject: String,
    pub role: String,
    pub expires: String,
    pub reused: bool,
    pub vc: VerifiableCredential,
}

#[derive(Serialize)]
pub struct VcListResponse {
    pub count: usize,
    pub vcs: Vec<VerifiableCredential>,
}

#[derive(Deserialize, Default)]
pub struct RenewVcRequest {
    pub id: Option<String>,
    pub vc_id: Option<String>,
    pub days: Option<i64>,
}

#[derive(Serialize)]
pub struct RenewVcResponse {
    pub status: String,
    pub message: String,
    pub vc_id: String,
    pub old_expiration: String,
    pub new_expiration: String,
    pub vc: VerifiableCredential,
}

#[derive(Deserialize, Default)]
pub struct RevokeVcRequest {
    pub id: Option<String>,
    pub vc_id: Option<String>,
    pub reason: Option<String>,
}

#[derive(Serialize)]
pub struct RevokeVcResponse {
    pub success: bool,
    pub status: String,
    pub message: String,
    pub vc_id: String,
    pub revoked: bool,
    pub reason: String,
}

#[derive(Deserialize)]
pub struct VerifyVcRequest {
    pub id: String,
}

#[derive(Serialize)]
pub struct VerifyVcResponse {
    pub status: String,
    pub valid: bool,
    pub vc_id: String,
    pub reason: Option<String>,
}

#[derive(Deserialize)]
pub struct StatusQuery {
    pub id: String,
}

#[derive(Serialize)]
pub struct VcStatusResponse {
    pub status: String,
    pub id: String,
    pub vc_id: String,
    pub subject_did: String,
    pub issuer_did: String,
    pub active: bool,
    pub revoked: bool,
    pub expired: bool,
    pub membership_status: String,
    pub status_list_index: String,
    pub reason: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct PullStatusRequest {
    pub owner_addr: Option<String>,
    pub ca_host: Option<String>,
}

#[derive(Serialize)]
pub struct PullStatusResponse {
    pub success: bool,
    pub status: String,
    pub message: String,
    pub ca_host: String,
    pub issuer: String,
    pub sgx_next_index: u64,
}

#[derive(Deserialize, Default)]
pub struct ShowQuery {
    pub scope: Option<String>,
    pub role: Option<String>,
    pub status: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct VcListItem {
    pub vc_id: String,
    pub subject: String,
    pub issuer: String,
    pub role: String,
    pub circle_id: String,
    pub membership_status: String,
    pub issuance_date: String,
    pub expiration_date: String,
    pub status_list_index: String,
    pub revoked: bool,
    pub source_scope: String,
}

#[derive(Serialize)]
pub struct VcShowResponse {
    pub status: String,
    pub count: usize,
    pub items: Vec<VcListItem>,
}

#[derive(Serialize)]
pub struct VcFileListResponse {
    pub status: String,
    pub count: usize,
    pub items: Vec<VcListItem>,
}

#[derive(Serialize)]
pub struct VcSummary {
    pub status: String,
    pub issued_total: usize,
    pub own_total: usize,
    pub peer_total: usize,
    pub active_total: usize,
    pub revoked_total: usize,
    pub expired_total: usize,
    pub next_index: u64,
    pub owner_did: String,
    pub circle_id: String,
}

#[derive(Deserialize, Default)]
pub struct AuditQuery {
    pub limit: Option<usize>,
    pub action: Option<String>,
}

#[derive(Serialize)]
pub struct VcAuditItem {
    pub timestamp: u64,
    pub node_id: String,
    pub severity: String,
    pub action: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct VcAuditResponse {
    pub status: String,
    pub count: usize,
    pub items: Vec<VcAuditItem>,
}

pub async fn issue(
    State(state): State<Arc<AppState>>,
    Json(body): Json<IssueVcRequest>,
) -> Result<(StatusCode, Json<IssueVcResponse>), ApiError> {
    // TODO(auth): no authentication on this endpoint yet. Admin API stays on
    // 0.0.0.0:8443 for the Lightning Leap Analytics console (see ADR 0002);
    // JWT bearer-token auth lands via the Login/Onboarding branch and is
    // tracked as a hardening-milestone issue, not blocking this PR.
    let subject = validate_subject_did(&body)?;
    let role = parse_role(body.role.as_deref().unwrap_or("member"))?;
    let days = validate_optional_days(body.days)?;
    let permissions = body
        .permissions
        .unwrap_or_else(|| issue::default_permissions_for_role(role.clone()));
    let (issuer, km) = load_runtime_signing_context()?;

    let outcome = issue::issue_membership_vc_with_outcome(
        &issuer,
        &km,
        IssueRequest {
            subject_did: &subject,
            role,
            permissions,
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: None,
            duration_days: Some(days),
        },
    )
    .map_err(map_vc_error)?;

    let (status_code, message, reused, vc) = match outcome {
        IssueMembershipOutcome::IssuedNew { vc, .. } => {
            (StatusCode::CREATED, "Issued new VC".to_string(), false, vc)
        }
        IssueMembershipOutcome::ReusedExisting { vc } => {
            log_vc_api_event(
                &state.node_id,
                AuditSeverity::Info,
                AuditAction::Loaded,
                &format!("VC_REUSED_NO_CHANGE: {} for {}", vc.id, vc.subject_did()),
            );
            (
                StatusCode::OK,
                "Existing active VC found — no changes made".to_string(),
                true,
                vc,
            )
        }
    };

    Ok((
        status_code,
        Json(IssueVcResponse {
            status: "success".to_string(),
            message,
            vc_id: vc.id.clone(),
            subject: vc.subject_did().to_string(),
            role: role_name(&vc.credential_subject.role),
            expires: vc.expiration_date.clone(),
            reused,
            vc,
        }),
    ))
}

pub async fn renew(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RenewVcRequest>,
) -> Result<Json<RenewVcResponse>, ApiError> {
    // TODO(auth): see issue() above.
    let vc_id = validate_vc_id(request_vc_id(body.id, body.vc_id)?.trim())?;
    let days = validate_required_days(body.days)?;
    let (issuer, km) = load_runtime_signing_context()?;
    let current = persistence::find_vc_by_id(&vc_id)
        .map_err(map_vc_error)?
        .ok_or_else(|| ApiError::NotFound(format!("VC not found: {}", vc_id)))?;

    let renewed = issue::renew_membership_vc(
        &issuer,
        &km,
        RenewRequest {
            vc_id: Some(&vc_id),
            subject_did: None,
            circle_id: issue::DEFAULT_CIRCLE_ID,
            duration_days: days,
            allow_expired: false,
        },
        &state.node_id,
    )
    .map_err(map_vc_error)?;

    Ok(Json(RenewVcResponse {
        status: "success".to_string(),
        message: "VC renewed".to_string(),
        vc_id: renewed.id.clone(),
        old_expiration: current.expiration_date,
        new_expiration: renewed.expiration_date.clone(),
        vc: renewed,
    }))
}

pub async fn revoke(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RevokeVcRequest>,
) -> Result<Json<RevokeVcResponse>, ApiError> {
    // TODO(auth): see issue() above.
    let vc_id = validate_vc_id(request_vc_id(body.id, body.vc_id)?.trim())?;
    let reason = validate_reason(body.reason)?;
    let (issuer, km) = load_runtime_signing_context()?;

    issue::revoke_vc(&issuer, &km, &vc_id, &reason, &state.node_id).map_err(map_vc_error)?;

    Ok(Json(RevokeVcResponse {
        success: true,
        status: "success".to_string(),
        message: "VC revoked".to_string(),
        vc_id,
        revoked: true,
        reason,
    }))
}

pub async fn verify(
    State(state): State<Arc<AppState>>,
    Json(body): Json<VerifyVcRequest>,
) -> Result<Json<VerifyVcResponse>, ApiError> {
    let vc_id = validate_vc_id(body.id.trim())?;
    let vc = persistence::find_vc_by_id(&vc_id)
        .map_err(map_vc_error)?
        .ok_or_else(|| ApiError::NotFound(format!("VC not found: {}", vc_id)))?;

    let expected_circle = local_circle_id().unwrap_or_else(|| issue::DEFAULT_CIRCLE_ID.to_string());
    let expected_issuer = issue::known_ca_did().ok();
    let verify_result = match strict_status_view(&state, expected_issuer.as_deref()).await {
        Ok(status_view) => {
            verify::verify_vc(
                &vc,
                &state.did_resolver,
                verify::VerifyOptions {
                    expected_subject_did: None,
                    expected_circle_id: Some(expected_circle.as_str()),
                    expected_issuer_did: expected_issuer.as_deref(),
                    check_status_list: true,
                    status_list: Some(&status_view),
                },
            )
            .await
        }
        Err(err) => Err(api_error_to_vc_error(err)),
    };

    match verify_result {
        Ok(()) => {
            log_vc_api_event(
                &state.node_id,
                AuditSeverity::Info,
                AuditAction::Succeeded,
                &format!("VC_VERIFY_SUCCESS: {}", vc.id),
            );
            Ok(Json(VerifyVcResponse {
                status: "success".to_string(),
                valid: true,
                vc_id,
                reason: None,
            }))
        }
        Err(err) => {
            log_vc_api_event(
                &state.node_id,
                AuditSeverity::Warning,
                AuditAction::Failed,
                &format!("VC_VERIFY_FAILED: {} ({})", vc.id, err),
            );
            Ok(Json(VerifyVcResponse {
                status: "success".to_string(),
                valid: false,
                vc_id,
                reason: Some(err.to_string()),
            }))
        }
    }
}

pub async fn show(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ShowQuery>,
) -> Result<Json<VcShowResponse>, ApiError> {
    // TODO: integrate read-only/admin auth middleware when available.
    let scope = parse_scope(q.scope.as_deref().unwrap_or("all"))?;
    let role = parse_optional_role(q.role.as_deref())?;
    let status_filter = parse_status_filter(q.status.as_deref().unwrap_or("all"))?;
    let mut items = collect_scope_items(&state, scope).await?;

    if let Some(role) = role {
        items.retain(|item| item.role == role_name(&role));
    }

    items.retain(|item| match status_filter {
        StatusFilter::All => true,
        StatusFilter::Revoked => item.revoked,
        StatusFilter::Expired => is_expired(&item.expiration_date),
        StatusFilter::Active => {
            !item.revoked
                && !is_expired(&item.expiration_date)
                && item.membership_status.eq_ignore_ascii_case("active")
        }
    });

    Ok(Json(VcShowResponse {
        status: "success".to_string(),
        count: items.len(),
        items,
    }))
}

pub async fn status(
    State(state): State<Arc<AppState>>,
    Query(q): Query<StatusQuery>,
) -> Result<Json<VcStatusResponse>, ApiError> {
    status_inner(&state, q.id).await
}

pub async fn status_by_id(
    State(state): State<Arc<AppState>>,
    Path(vc_id): Path<String>,
) -> Result<Json<VcStatusResponse>, ApiError> {
    status_inner(&state, vc_id).await
}

pub async fn pull_status(
    State(state): State<Arc<AppState>>,
    maybe_body: Option<Json<PullStatusRequest>>,
) -> Result<Json<PullStatusResponse>, ApiError> {
    // TODO: integrate admin auth middleware when available; for now this follows the
    // existing local-admin REST pattern used by the rest of the service.
    let body = maybe_body.map(|payload| payload.0).unwrap_or_default();
    let ca_host = body
        .owner_addr
        .or(body.ca_host)
        .or_else(resolve_ca_host)
        .ok_or_else(|| ApiError::BadRequest("CA host is not configured".to_string()))?;
    let expected_issuer = issue::known_ca_did().ok();
    let credential = distribution::pull_status_list_verified(
        &state.did_resolver,
        &ca_host,
        expected_issuer.as_deref(),
    )
    .await
    .map_err(map_vc_error)?;

    log_vc_api_event(
        &state.node_id,
        AuditSeverity::Info,
        AuditAction::Loaded,
        &format!(
            "VC_STATUS_LIST_PULLED: issuer={} next_index={}",
            credential.issuer, credential.sgx_next_index
        ),
    );

    Ok(Json(PullStatusResponse {
        success: true,
        status: "success".to_string(),
        message: "Pulled VC status list".to_string(),
        ca_host,
        issuer: credential.issuer,
        sgx_next_index: credential.sgx_next_index,
    }))
}

pub async fn list(_state: State<Arc<AppState>>) -> Result<Json<VcListResponse>, ApiError> {
    let vcs = persistence::list_own().map_err(map_vc_error)?;
    Ok(Json(VcListResponse {
        count: vcs.len(),
        vcs,
    }))
}

pub async fn peers(_state: State<Arc<AppState>>) -> Result<Json<VcListResponse>, ApiError> {
    let vcs = persistence::list_peers().map_err(map_vc_error)?;
    Ok(Json(VcListResponse {
        count: vcs.len(),
        vcs,
    }))
}

pub async fn files_issued(
    State(state): State<Arc<AppState>>,
) -> Result<Json<VcFileListResponse>, ApiError> {
    list_scope_files(&state, Scope::Issued).await
}

pub async fn files_own(
    State(state): State<Arc<AppState>>,
) -> Result<Json<VcFileListResponse>, ApiError> {
    list_scope_files(&state, Scope::Own).await
}

pub async fn files_peers(
    State(state): State<Arc<AppState>>,
) -> Result<Json<VcFileListResponse>, ApiError> {
    list_scope_files(&state, Scope::Peers).await
}

pub async fn file_issued(
    State(state): State<Arc<AppState>>,
    Path(vc_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let vc_id = validate_vc_id(vc_id.trim())?;
    let value = load_json_file(&persistence::issued_path_for_id(&vc_id))?;
    log_file_read(&state.node_id, &format!("issued/{}", vc_id));
    Ok(Json(value))
}

pub async fn file_own(
    State(state): State<Arc<AppState>>,
    Path(vc_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let vc_id = validate_vc_id(vc_id.trim())?;
    let value = load_json_file(&persistence::own_path_for_id(&vc_id))?;
    log_file_read(&state.node_id, &format!("own/{}", vc_id));
    Ok(Json(value))
}

pub async fn file_peer(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let did = validate_did(did.trim())?;
    let value = load_json_file(&persistence::peer_path_for_subject(&did))?;
    log_file_read(&state.node_id, &format!("peer/{}", did));
    Ok(Json(value))
}

pub async fn status_list_get(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let value: Value =
        serde_json::from_str(&persistence::load_status_list_raw().map_err(map_vc_error)?)
            .map_err(ApiError::from)?;
    log_file_read(&state.node_id, "status_list.json");
    Ok(Json(value))
}

pub async fn status_list_index_get(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, ApiError> {
    let value: Value =
        serde_json::from_str(&persistence::load_status_list_index_raw().map_err(map_vc_error)?)
            .map_err(ApiError::from)?;
    log_file_read(&state.node_id, "status_list_index.json");
    Ok(Json(value))
}

pub async fn summary(State(state): State<Arc<AppState>>) -> Result<Json<VcSummary>, ApiError> {
    // TODO: integrate read-only/admin auth middleware when available.
    let issued = persistence::list_issued().map_err(map_vc_error)?;
    let own = persistence::list_own().map_err(map_vc_error)?;
    let peers = persistence::list_peers().map_err(map_vc_error)?;

    let mut unique = BTreeSet::new();
    let mut active_total = 0usize;
    let mut revoked_total = 0usize;
    let mut expired_total = 0usize;

    for vc in issued
        .iter()
        .chain(own.iter())
        .chain(peers.iter())
        .filter(|vc| unique.insert(vc.id.clone()))
    {
        let revoked = best_effort_revoked_status(&state, vc).await;
        let expired = vc.is_expired(Utc::now());
        if revoked {
            revoked_total += 1;
        } else if expired {
            expired_total += 1;
        } else if vc.has_active_membership_status() {
            active_total += 1;
        }
    }

    let next_index = read_next_index().unwrap_or(0);
    let owner_did = issue::known_ca_did()
        .or_else(|_| load_issuer_record().map(|record| record.did))
        .unwrap_or_else(|_| "unknown".to_string());
    let circle_id = local_circle_id().unwrap_or_else(|| issue::DEFAULT_CIRCLE_ID.to_string());

    log_vc_api_event(
        &state.node_id,
        AuditSeverity::Info,
        AuditAction::Loaded,
        "VC_SUMMARY_READ: summary requested",
    );

    Ok(Json(VcSummary {
        status: "success".to_string(),
        issued_total: issued.len(),
        own_total: own.len(),
        peer_total: peers.len(),
        active_total,
        revoked_total,
        expired_total,
        next_index,
        owner_did,
        circle_id,
    }))
}

pub async fn audit(
    State(_state): State<Arc<AppState>>,
    Query(q): Query<AuditQuery>,
) -> Result<Json<VcAuditResponse>, ApiError> {
    let mut items = read_vc_audit_items()?;
    if let Some(action) = q.action.as_deref() {
        items.retain(|item| item.action == action);
    }
    let limit = q.limit.unwrap_or(100).min(1000);
    items.truncate(limit);

    Ok(Json(VcAuditResponse {
        status: "success".to_string(),
        count: items.len(),
        items,
    }))
}

async fn status_inner(
    state: &Arc<AppState>,
    raw_vc_id: String,
) -> Result<Json<VcStatusResponse>, ApiError> {
    let vc_id = validate_vc_id(raw_vc_id.trim())?;
    let vc = persistence::find_vc_by_id(&vc_id)
        .map_err(map_vc_error)?
        .ok_or_else(|| ApiError::NotFound(format!("VC not found: {}", vc_id)))?;
    let revoked = strict_revoked_status(state, &vc).await?;
    let expired = vc.is_expired(Utc::now());
    let active = vc.has_active_membership_status() && !revoked && !expired;
    let reason = if revoked {
        Some("VC revoked".to_string())
    } else if expired {
        Some("VC expired".to_string())
    } else if !vc.has_active_membership_status() {
        Some(format!(
            "membershipStatus must be active, got {}",
            vc.credential_subject.membership_status
        ))
    } else {
        None
    };

    Ok(Json(VcStatusResponse {
        status: "success".to_string(),
        id: vc.id.clone(),
        vc_id: vc.id.clone(),
        subject_did: vc.subject_did().to_string(),
        issuer_did: vc.issuer_did().to_string(),
        active,
        revoked,
        expired,
        membership_status: vc.credential_subject.membership_status.to_string(),
        status_list_index: vc.credential_status.status_list_index.clone(),
        reason,
    }))
}

async fn list_scope_files(
    state: &Arc<AppState>,
    scope: Scope,
) -> Result<Json<VcFileListResponse>, ApiError> {
    let items = collect_scope_items(state, scope).await?;
    log_file_read(state.node_id.as_str(), scope.label());
    Ok(Json(VcFileListResponse {
        status: "success".to_string(),
        count: items.len(),
        items,
    }))
}

async fn collect_scope_items(
    state: &Arc<AppState>,
    scope: Scope,
) -> Result<Vec<VcListItem>, ApiError> {
    if matches!(scope, Scope::All) {
        let mut items = list_scope_items_inner(state, Scope::Issued).await?;
        items.extend(list_scope_items_inner(state, Scope::Own).await?);
        items.extend(list_scope_items_inner(state, Scope::Peers).await?);
        return Ok(items);
    }

    list_scope_items_inner(state, scope).await
}

async fn list_scope_items_inner(
    state: &Arc<AppState>,
    scope: Scope,
) -> Result<Vec<VcListItem>, ApiError> {
    let vcs = match scope {
        Scope::Issued => persistence::list_issued().map_err(map_vc_error)?,
        Scope::Own => persistence::list_own().map_err(map_vc_error)?,
        Scope::Peers => persistence::list_peers().map_err(map_vc_error)?,
        Scope::All => unreachable!("handled above"),
    };

    let mut items = Vec::with_capacity(vcs.len());
    for vc in vcs {
        let revoked = best_effort_revoked_status(state, &vc).await;
        items.push(vc_list_item(vc, scope.item_scope().to_string(), revoked));
    }
    Ok(items)
}

fn vc_list_item(vc: VerifiableCredential, source_scope: String, revoked: bool) -> VcListItem {
    VcListItem {
        vc_id: vc.id,
        subject: vc.credential_subject.id,
        issuer: vc.issuer,
        role: role_name(&vc.credential_subject.role),
        circle_id: vc.credential_subject.circle_id,
        membership_status: vc.credential_subject.membership_status.to_string(),
        issuance_date: vc.issuance_date,
        expiration_date: vc.expiration_date,
        status_list_index: vc.credential_status.status_list_index,
        revoked,
        source_scope,
    }
}

async fn strict_revoked_status(
    state: &Arc<AppState>,
    vc: &VerifiableCredential,
) -> Result<bool, ApiError> {
    let expected_issuer = Some(vc.issuer_did());
    let status_view = strict_status_view(state, expected_issuer).await?;
    let index = vc
        .credential_status
        .status_list_index
        .parse::<u64>()
        .map_err(|e| ApiError::BadRequest(format!("invalid VC status index: {}", e)))?;
    status_view.is_revoked(index).map_err(map_vc_error)
}

async fn strict_status_view(
    state: &Arc<AppState>,
    expected_issuer: Option<&str>,
) -> Result<status_list::StatusListView, ApiError> {
    let credential = persistence::load_status_list_credential().map_err(map_vc_error)?;
    status_list::verify_status_list_credential(&credential, &state.did_resolver, expected_issuer)
        .await
        .map_err(map_vc_error)
}

async fn best_effort_revoked_status(state: &Arc<AppState>, vc: &VerifiableCredential) -> bool {
    strict_revoked_status(state, vc).await.unwrap_or(false)
}

fn load_runtime_signing_context()
-> Result<(DidRecord, std::sync::Arc<crate::key_manager::KeyManager>), ApiError> {
    let issuer = load_issuer_record()?;
    let node_id = issue::resolve_runtime_node_id().ok_or_else(|| {
        ApiError::Internal("cannot resolve runtime node_id for VC signing".into())
    })?;
    let km = issue::load_runtime_key_manager(&node_id)
        .map_err(|e| ApiError::Internal(format!("vc key manager: {}", e)))?;
    Ok((issuer, km))
}

fn load_issuer_record() -> Result<DidRecord, ApiError> {
    let did_path =
        std::env::var(DID_PATH_ENV).unwrap_or_else(|_| crate::did::DEFAULT_DID_PATH.to_string());
    DidRecord::load(&did_path).map_err(|e| ApiError::Internal(format!("vc issuer did: {}", e)))
}

fn validate_subject_did(body: &IssueVcRequest) -> Result<String, ApiError> {
    let raw = body
        .to
        .as_deref()
        .or(body.subject_did.as_deref())
        .ok_or_else(|| ApiError::BadRequest("to is required".to_string()))?;
    validate_did(raw.trim())
}

fn validate_did(raw: &str) -> Result<String, ApiError> {
    Did::parse(raw)
        .map(|did| did.to_string())
        .map_err(|e| ApiError::BadRequest(format!("invalid DID: {}", e)))
}

fn validate_vc_id(raw: &str) -> Result<String, ApiError> {
    let suffix = raw
        .strip_prefix("urn:uuid:")
        .ok_or_else(|| ApiError::BadRequest("id must start with urn:uuid:".to_string()))?;
    if raw.contains('/') || raw.contains('\\') || raw.contains("..") || raw.contains('\0') {
        return Err(ApiError::BadRequest("invalid VC id".to_string()));
    }
    Uuid::parse_str(suffix).map_err(|e| ApiError::BadRequest(format!("invalid VC id: {}", e)))?;
    Ok(raw.to_string())
}

fn validate_optional_days(days: Option<i64>) -> Result<i64, ApiError> {
    let days = days.unwrap_or(issue::DEFAULT_VC_DURATION_DAYS);
    validate_days(days)
}

fn validate_required_days(days: Option<i64>) -> Result<i64, ApiError> {
    let days = days.ok_or_else(|| ApiError::BadRequest("days is required".to_string()))?;
    validate_days(days)
}

fn validate_days(days: i64) -> Result<i64, ApiError> {
    if !(1..=3650).contains(&days) {
        return Err(ApiError::BadRequest(
            "days must be between 1 and 3650".to_string(),
        ));
    }
    Ok(days)
}

fn validate_reason(reason: Option<String>) -> Result<String, ApiError> {
    let reason = reason
        .unwrap_or_else(|| "manual revoke".to_string())
        .trim()
        .to_string();
    if reason.is_empty() {
        return Err(ApiError::BadRequest("reason must not be empty".to_string()));
    }
    if reason.len() > 256 {
        return Err(ApiError::BadRequest(
            "reason must be 256 characters or fewer".to_string(),
        ));
    }
    Ok(reason)
}

fn request_vc_id(id: Option<String>, legacy_vc_id: Option<String>) -> Result<String, ApiError> {
    id.or(legacy_vc_id)
        .ok_or_else(|| ApiError::BadRequest("id is required".to_string()))
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

fn parse_optional_role(raw: Option<&str>) -> Result<Option<CredentialRole>, ApiError> {
    raw.map(parse_role).transpose()
}

fn role_name(role: &CredentialRole) -> String {
    match role {
        CredentialRole::Owner => "owner",
        CredentialRole::Member => "member",
    }
    .to_string()
}

fn map_vc_error(err: VcError) -> ApiError {
    match err {
        VcError::NotFound(item) => ApiError::NotFound(format!("VC not found: {}", item)),
        VcError::NotCircleOwnerForIssue
        | VcError::NotCircleOwnerForRevoke
        | VcError::NotCircleOwnerForRenew => ApiError::Forbidden(err.to_string()),
        VcError::CannotRenewRevokedVc | VcError::CannotRenewExpiredVc(_) => {
            ApiError::Conflict(err.to_string())
        }
        VcError::InvalidStructure(_)
        | VcError::InvalidMembershipStatus(_)
        | VcError::UnknownPermission(_)
        | VcError::IndexOutOfRange { .. }
        | VcError::CircleMismatch { .. }
        | VcError::IssuerMismatch { .. }
        | VcError::SubjectMismatch { .. } => ApiError::BadRequest(err.to_string()),
        VcError::Io(e) if e.kind() == std::io::ErrorKind::NotFound => {
            ApiError::NotFound(e.to_string())
        }
        _ => ApiError::Internal(err.to_string()),
    }
}

fn api_error_to_vc_error(err: ApiError) -> VcError {
    match err {
        ApiError::BadRequest(message)
        | ApiError::Forbidden(message)
        | ApiError::Conflict(message)
        | ApiError::DeviceAlreadyPaired(message)
        | ApiError::Locked(message)
        | ApiError::NotFound(message)
        | ApiError::TooManyRequests(message)
        | ApiError::PayloadTooLarge(message)
        | ApiError::Unauthorized(message)
        | ApiError::Gone(message)
        | ApiError::Internal(message) => VcError::InvalidStructure(message),
        ApiError::ServiceUnavailable { message, .. } => VcError::InvalidStructure(message),
    }
}

#[derive(Clone, Copy)]
enum Scope {
    Issued,
    Own,
    Peers,
    All,
}

impl Scope {
    fn item_scope(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Own => "own",
            Self::Peers => "peers",
            Self::All => "all",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Issued => "issued files",
            Self::Own => "own files",
            Self::Peers => "peer files",
            Self::All => "all files",
        }
    }
}

fn parse_scope(raw: &str) -> Result<Scope, ApiError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "issued" => Ok(Scope::Issued),
        "own" => Ok(Scope::Own),
        "peers" => Ok(Scope::Peers),
        "all" => Ok(Scope::All),
        other => Err(ApiError::BadRequest(format!(
            "unsupported scope '{}'",
            other
        ))),
    }
}

#[derive(Clone, Copy)]
enum StatusFilter {
    Active,
    Revoked,
    Expired,
    All,
}

fn parse_status_filter(raw: &str) -> Result<StatusFilter, ApiError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "active" => Ok(StatusFilter::Active),
        "revoked" => Ok(StatusFilter::Revoked),
        "expired" => Ok(StatusFilter::Expired),
        "all" => Ok(StatusFilter::All),
        other => Err(ApiError::BadRequest(format!(
            "unsupported status '{}'",
            other
        ))),
    }
}

fn is_expired(expiration_date: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(expiration_date)
        .map(|ts| Utc::now() > ts.with_timezone(&Utc))
        .unwrap_or(true)
}

fn load_json_file(path: &StdPath) -> Result<Value, ApiError> {
    let bytes = fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ApiError::NotFound(format!("file not found: {}", path.display()))
        } else {
            ApiError::Internal(format!("read {}: {}", path.display(), e))
        }
    })?;
    serde_json::from_slice(&bytes).map_err(ApiError::from)
}

fn read_next_index() -> Result<u64, ApiError> {
    let raw = persistence::load_status_list_index_raw().map_err(map_vc_error)?;
    let value: Value = serde_json::from_str(&raw).map_err(ApiError::from)?;
    value
        .get("next_index")
        .and_then(Value::as_u64)
        .ok_or_else(|| ApiError::Internal("status_list_index.json missing next_index".to_string()))
}

fn local_circle_id() -> Option<String> {
    if let Ok(vcs) = persistence::list_own() {
        if let Some(vc) = vcs.last() {
            return Some(vc.credential_subject.circle_id.clone());
        }
    }
    let issuer = load_issuer_record().ok()?;
    persistence::list_issued()
        .ok()?
        .into_iter()
        .rev()
        .find(|vc| vc.subject_did() == issuer.did)
        .map(|vc| vc.credential_subject.circle_id)
}

fn resolve_ca_host() -> Option<String> {
    std::env::var("SGX_CA_HOST")
        .ok()
        .filter(|host| !host.trim().is_empty() && host != "0.0.0.0")
        .or_else(|| {
            for path in [
                PathBuf::from("/etc/sgx-guardian/config/nodeA.yaml"),
                PathBuf::from("/etc/sgx-guardian/nodeA.yaml"),
                PathBuf::from("config/nodeA.yaml"),
            ] {
                if let Ok(cfg) = crate::config_loader::load_config(path.to_str()?) {
                    if !cfg.ip.trim().is_empty() && cfg.ip != "0.0.0.0" {
                        return Some(cfg.ip);
                    }
                }
            }
            None
        })
}

fn log_vc_api_event(node_id: &str, severity: AuditSeverity, action: AuditAction, message: &str) {
    log_audit(node_id, AuditCategory::Vc, severity, action, message);
}

fn log_file_read(node_id: &str, target: &str) {
    log_vc_api_event(
        node_id,
        AuditSeverity::Info,
        AuditAction::Loaded,
        &format!("VC_FILE_READ: {}", target),
    );
}

fn read_vc_audit_items() -> Result<Vec<VcAuditItem>, ApiError> {
    let log_path = resolve_audit_log_path()?;
    let body = fs::read_to_string(&log_path)
        .map_err(|e| ApiError::Internal(format!("read audit log {}: {}", log_path.display(), e)))?;
    let mut items = Vec::new();

    for line in body.lines().rev() {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(event) = value.get("event") else {
            continue;
        };
        if event.get("category").and_then(Value::as_str) != Some("Vc") {
            continue;
        }
        let message = event
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let Some(action) = derive_vc_audit_action(&message) else {
            continue;
        };
        items.push(VcAuditItem {
            timestamp: event.get("timestamp").and_then(Value::as_u64).unwrap_or(0),
            node_id: event
                .get("node_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            severity: event
                .get("severity")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            action,
            message,
        });
    }

    Ok(items)
}

fn resolve_audit_log_path() -> Result<PathBuf, ApiError> {
    if let Ok(path) = std::env::var("SGX_GUARDIAN_AUDIT_LOG_PATH") {
        let explicit = PathBuf::from(path);
        if explicit.exists() {
            return Ok(explicit);
        }
    }

    for dir in ["/var/log/sgx-guardian", "logs"] {
        let directory = PathBuf::from(dir);
        if !directory.exists() {
            continue;
        }
        if let Ok(mut entries) = fs::read_dir(&directory).map(|it| it.flatten().collect::<Vec<_>>())
        {
            entries.sort_by_key(|entry| entry.path());
            if let Some(entry) = entries
                .into_iter()
                .rev()
                .find(|entry| entry.file_name().to_string_lossy().starts_with("audit-"))
            {
                return Ok(entry.path());
            }
        }
        let legacy = directory.join("audit.log");
        if legacy.exists() {
            return Ok(legacy);
        }
    }

    Err(ApiError::NotFound("audit log not found".to_string()))
}

fn derive_vc_audit_action(message: &str) -> Option<String> {
    let action = if message.starts_with("VC_REUSED_NO_CHANGE:") {
        "VC_REUSED_NO_CHANGE"
    } else if message.starts_with("VC_VERIFY_SUCCESS:") {
        "VC_VERIFY_SUCCESS"
    } else if message.starts_with("VC_VERIFY_FAILED:") {
        "VC_VERIFY_FAILED"
    } else if message.starts_with("VC_FILE_READ:") {
        "VC_FILE_READ"
    } else if message.starts_with("VC_SUMMARY_READ:") {
        "VC_SUMMARY_READ"
    } else if message.starts_with("VC_STATUS_LIST_PULLED:") {
        "VC_STATUS_LIST_PULLED"
    } else if message.contains("Issued VC ") {
        "VC_ISSUED"
    } else if message.contains("VC renewed by Circle owner") {
        "VC_RENEWED"
    } else if message.contains("Revoked VC ") {
        "VC_REVOKED"
    } else {
        return None;
    };
    Some(action.to_string())
}
