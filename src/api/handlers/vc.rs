use crate::api::{error::ApiError, state::AppState};
use crate::vc::credential::{CredentialRole, VerifiableCredential};
use crate::vc::issue::{self, IssueRequest};
use crate::vc::{persistence, status_list};
use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct IssueVcRequest {
    pub subject_did: String,
    pub role: Option<String>,
    pub permissions: Option<Vec<String>>,
    pub days: Option<i64>,
}

#[derive(Serialize)]
pub struct IssueVcResponse {
    pub vc: VerifiableCredential,
}

#[derive(Serialize)]
pub struct VcListResponse {
    pub count: usize,
    pub vcs: Vec<VerifiableCredential>,
}

#[derive(Deserialize)]
pub struct RevokeVcRequest {
    pub vc_id: String,
    pub reason: Option<String>,
}

#[derive(Serialize)]
pub struct RevokeVcResponse {
    pub success: bool,
    pub vc_id: String,
}

#[derive(Deserialize)]
pub struct StatusQuery {
    pub id: String,
}

#[derive(Serialize)]
pub struct VcStatusResponse {
    pub id: String,
    pub subject_did: String,
    pub issuer_did: String,
    pub revoked: bool,
}

#[derive(Deserialize)]
pub struct PullStatusRequest {
    pub ca_host: Option<String>,
}

#[derive(Serialize)]
pub struct PullStatusResponse {
    pub success: bool,
    pub ca_host: String,
}

pub async fn issue(
    State(_state): State<Arc<AppState>>,
    Json(body): Json<IssueVcRequest>,
) -> Result<Json<IssueVcResponse>, ApiError> {
    let role = parse_role(body.role.as_deref().unwrap_or("member"))?;
    let node_id = issue::resolve_runtime_node_id().unwrap_or_else(|| "nodeA".to_string());
    let issuer = crate::did::DidRecord::load(crate::did::DEFAULT_DID_PATH).map_err(api_vc_error)?;
    let km = issue::load_runtime_key_manager(&node_id)
        .map_err(|e| ApiError::Internal(format!("vc key manager: {}", e)))?;
    let permissions = body
        .permissions
        .unwrap_or_else(|| issue::default_permissions_for_role(role.clone()));
    let vc = issue::issue_membership_vc(
        &issuer,
        &km,
        IssueRequest {
            subject_did: body.subject_did.trim(),
            role,
            permissions,
            circle_id: issue::DEFAULT_CIRCLE_ID,
            node_hint: None,
            duration_days: body.days,
        },
    )
    .map_err(api_vc_error)?;
    Ok(Json(IssueVcResponse { vc }))
}

pub async fn list(_state: State<Arc<AppState>>) -> Result<Json<VcListResponse>, ApiError> {
    let vcs = persistence::list_own().map_err(api_vc_error)?;
    Ok(Json(VcListResponse {
        count: vcs.len(),
        vcs,
    }))
}

pub async fn peers(_state: State<Arc<AppState>>) -> Result<Json<VcListResponse>, ApiError> {
    let vcs = persistence::list_peers().map_err(api_vc_error)?;
    Ok(Json(VcListResponse {
        count: vcs.len(),
        vcs,
    }))
}

pub async fn revoke(
    State(_state): State<Arc<AppState>>,
    Json(body): Json<RevokeVcRequest>,
) -> Result<Json<RevokeVcResponse>, ApiError> {
    let node_id = issue::resolve_runtime_node_id().unwrap_or_else(|| "nodeA".to_string());
    let issuer = crate::did::DidRecord::load(crate::did::DEFAULT_DID_PATH).map_err(api_vc_error)?;
    let km = issue::load_runtime_key_manager(&node_id)
        .map_err(|e| ApiError::Internal(format!("vc key manager: {}", e)))?;
    issue::revoke_vc(
        &issuer,
        &km,
        body.vc_id.trim(),
        body.reason.as_deref().unwrap_or("manual revoke"),
    )
    .map_err(api_vc_error)?;
    Ok(Json(RevokeVcResponse {
        success: true,
        vc_id: body.vc_id,
    }))
}

pub async fn status(
    State(state): State<Arc<AppState>>,
    Query(q): Query<StatusQuery>,
) -> Result<Json<VcStatusResponse>, ApiError> {
    let vc = persistence::find_vc_by_id(q.id.trim())
        .map_err(api_vc_error)?
        .ok_or_else(|| ApiError::NotFound(format!("VC not found: {}", q.id.trim())))?;
    let revoked = revoked_status_for_vc(&state, &vc).await?;
    Ok(Json(VcStatusResponse {
        id: vc.id.clone(),
        subject_did: vc.subject_did().to_string(),
        issuer_did: vc.issuer_did().to_string(),
        revoked,
    }))
}

pub async fn pull_status(
    State(_state): State<Arc<AppState>>,
    maybe_body: Option<Json<PullStatusRequest>>,
) -> Result<Json<PullStatusResponse>, ApiError> {
    let ca_host = maybe_body
        .and_then(|body| body.ca_host.clone())
        .or_else(resolve_ca_host)
        .ok_or_else(|| ApiError::BadRequest("CA host is not configured".to_string()))?;
    crate::vc::distribution::pull_status_list(&ca_host)
        .await
        .map_err(api_vc_error)?;
    Ok(Json(PullStatusResponse {
        success: true,
        ca_host,
    }))
}

async fn revoked_status_for_vc(
    state: &Arc<AppState>,
    vc: &VerifiableCredential,
) -> Result<bool, ApiError> {
    let expected_issuer = issue::known_ca_did().ok();
    let status_credential = persistence::load_status_list_credential().map_err(api_vc_error)?;
    let status_view = status_list::verify_status_list_credential(
        &status_credential,
        &state.did_resolver,
        expected_issuer.as_deref(),
    )
    .await
    .map_err(api_vc_error)?;
    let index = vc
        .credential_status
        .status_list_index
        .parse::<u64>()
        .map_err(|e| ApiError::BadRequest(format!("invalid VC status index: {}", e)))?;
    status_view.is_revoked(index).map_err(api_vc_error)
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

fn api_vc_error<E: std::fmt::Display>(err: E) -> ApiError {
    ApiError::Internal(err.to_string())
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
