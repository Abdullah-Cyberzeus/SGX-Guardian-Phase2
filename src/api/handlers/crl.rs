use super::dkp::{run_cli, ActionResponse};
use crate::api::error::ApiError;
use crate::crl::entry::CrlEntry;
use crate::crl::persistence;
use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Deserialize, Default)]
pub struct RevokeCrlRequest {
    pub did: String,
    pub reason: String,
    pub severity: String,
    pub device_id: Option<String>,
    pub user_id: Option<String>,
    pub note: Option<String>,
    pub audit_ref: Option<String>,
    pub attestation_ref: Option<String>,
    pub evidence_digest: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RevokeCrlResponse {
    pub status: String,
    pub message: String,
    pub entry: CrlEntry,
    pub sequence: u64,
    pub merkle_root: String,
}

#[derive(Debug, Deserialize)]
pub struct EntryQuery {
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub struct CheckQuery {
    pub did: String,
}

#[derive(Debug, Serialize)]
pub struct CrlListResponse {
    pub status: String,
    pub count: usize,
    pub entries: Vec<CrlEntry>,
}

#[derive(Debug, Serialize)]
pub struct CrlCheckResponse {
    pub status: String,
    pub did: String,
    pub revoked: bool,
    pub entry: Option<CrlEntry>,
}

#[derive(Debug, Serialize)]
pub struct CrlVerifyResponse {
    pub ok: bool,
    pub errors: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CrlRootResponse {
    pub sequence: u64,
    pub merkle_root: String,
}

pub async fn revoke(
    State(_state): State<Arc<crate::api::state::AppState>>,
    Json(body): Json<RevokeCrlRequest>,
) -> Result<Json<RevokeCrlResponse>, ApiError> {
    if body.did.trim().is_empty() {
        return Err(ApiError::BadRequest("did must not be empty".to_string()));
    }

    let mut args = vec![
        "crl".to_string(),
        "revoke".to_string(),
        "--did".to_string(),
        body.did.clone(),
        "--reason".to_string(),
        body.reason.clone(),
        "--severity".to_string(),
        body.severity.clone(),
    ];
    push_optional_arg(&mut args, "--device-id", body.device_id.as_deref());
    push_optional_arg(&mut args, "--user-id", body.user_id.as_deref());
    push_optional_arg(&mut args, "--note", body.note.as_deref());

    let response = run_owned_cli(args).await?;
    ensure_cli_success(response)?;

    let crl = persistence::load_crl()
        .map_err(|error| ApiError::Internal(error.to_string()))?
        .ok_or_else(|| ApiError::NotFound("CRL not found after revoke".to_string()))?;
    let entry = crl
        .entries
        .iter()
        .find(|entry| entry.revoked_did == body.did)
        .cloned()
        .ok_or_else(|| ApiError::NotFound(format!("CRL entry not found for DID {}", body.did)))?;

    Ok(Json(RevokeCrlResponse {
        status: "success".to_string(),
        message: "CRL entry issued".to_string(),
        entry,
        sequence: crl.sequence,
        merkle_root: crl.merkle_root,
    }))
}

pub async fn list(
    State(_state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<CrlListResponse>, ApiError> {
    let response = run_owned_cli(vec!["crl".to_string(), "list".to_string()]).await?;
    ensure_cli_success(response)?;

    let crl = persistence::load_crl().map_err(|error| ApiError::Internal(error.to_string()))?;
    let entries = crl.map(|crl| crl.entries).unwrap_or_default();
    Ok(Json(CrlListResponse {
        status: "success".to_string(),
        count: entries.len(),
        entries,
    }))
}

pub async fn entry(
    State(_state): State<Arc<crate::api::state::AppState>>,
    Query(query): Query<EntryQuery>,
) -> Result<Json<CrlEntry>, ApiError> {
    let id = query.id.trim();
    if id.is_empty() {
        return Err(ApiError::BadRequest("id must not be empty".to_string()));
    }

    let response = run_owned_cli(vec![
        "crl".to_string(),
        "show".to_string(),
        "--id".to_string(),
        id.to_string(),
    ])
    .await?;
    let response = ensure_cli_success(response)?;
    let entry: CrlEntry = serde_json::from_str(&response.stdout)?;
    Ok(Json(entry))
}

pub async fn check(
    State(_state): State<Arc<crate::api::state::AppState>>,
    Query(query): Query<CheckQuery>,
) -> Result<Json<CrlCheckResponse>, ApiError> {
    let did = query.did.trim();
    if did.is_empty() {
        return Err(ApiError::BadRequest("did must not be empty".to_string()));
    }

    let response = run_owned_cli(vec![
        "crl".to_string(),
        "check".to_string(),
        "--did".to_string(),
        did.to_string(),
    ])
    .await?;
    let response = ensure_cli_success(response)?;
    let value: serde_json::Value = serde_json::from_str(&response.stdout)?;
    let entry = value
        .get("entry")
        .filter(|entry| !entry.is_null())
        .map(|entry| serde_json::from_value(entry.clone()))
        .transpose()?;

    Ok(Json(CrlCheckResponse {
        status: "success".to_string(),
        did: did.to_string(),
        revoked: value
            .get("revoked")
            .and_then(|revoked| revoked.as_bool())
            .unwrap_or(false),
        entry,
    }))
}

pub async fn verify(
    State(_state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<CrlVerifyResponse>, ApiError> {
    let response = run_owned_cli(vec!["crl".to_string(), "verify".to_string()]).await?;
    if response.success {
        Ok(Json(CrlVerifyResponse {
            ok: true,
            errors: Vec::new(),
        }))
    } else {
        Ok(Json(CrlVerifyResponse {
            ok: false,
            errors: vec![cli_message(&response)],
        }))
    }
}

pub async fn root(
    State(_state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<CrlRootResponse>, ApiError> {
    let response = run_owned_cli(vec!["crl".to_string(), "root".to_string()]).await?;
    let response = ensure_cli_success(response)?;
    let root: CrlRootResponse = serde_json::from_str(&response.stdout)?;
    Ok(Json(root))
}

async fn run_owned_cli(args: Vec<String>) -> Result<ActionResponse, ApiError> {
    let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    run_cli(&refs).await
}

fn push_optional_arg(args: &mut Vec<String>, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        args.push(name.to_string());
        args.push(value.to_string());
    }
}

fn ensure_cli_success(response: ActionResponse) -> Result<ActionResponse, ApiError> {
    if response.success {
        Ok(response)
    } else {
        Err(map_cli_failure(&response))
    }
}

fn map_cli_failure(response: &ActionResponse) -> ApiError {
    let message = cli_message(response);
    let lower = message.to_ascii_lowercase();
    if lower.contains("already revoked") {
        ApiError::Conflict(message)
    } else if lower.contains("self")
        || lower.contains("member-issued")
        || lower.contains("invalid signature")
    {
        ApiError::Forbidden(message)
    } else if lower.contains("not found") {
        ApiError::NotFound(message)
    } else {
        ApiError::BadRequest(message)
    }
}

fn cli_message(response: &ActionResponse) -> String {
    let stderr = response.stderr.trim();
    if !stderr.is_empty() {
        return stderr.to_string();
    }
    let stdout = response.stdout.trim();
    if !stdout.is_empty() {
        return stdout.to_string();
    }
    "sgx-pa-cli crl command failed".to_string()
}
