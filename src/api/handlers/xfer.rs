use crate::api::auth::middleware::AuthenticatedSession;
use crate::api::error::ApiError;
use crate::api::idempotency;
use crate::api::state::AppState;
use crate::vault::namespace::validate_vault_id;
use crate::vault::{persistence as vault_persistence, VaultConfig};
use crate::xfer::errors::XferError;
use crate::xfer::store::{self, ReceiverState, SenderProgress};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct SendRequest {
    pub peer_did: String,
    pub path: Option<String>,
    pub vault_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendResponse {
    pub status: String,
    pub transfer_id: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct TransferSummary {
    pub transfer_id: String,
    pub direction: String,
    pub status: String,
    pub circle_id: String,
    pub filename: String,
    pub size: u64,
    pub chunk_bytes: u32,
    pub chunk_count: u32,
    pub peer_did: Option<String>,
    pub sender_did: Option<String>,
    pub file_path: Option<String>,
    pub sent_chunks: Option<u32>,
    pub requested_chunks: Option<u32>,
    pub received_chunks: Option<usize>,
    pub bytes_sent: Option<u64>,
    pub last_error: Option<String>,
    pub updated_at: String,
    pub completed_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TransferListResponse {
    pub count: usize,
    pub transfers: Vec<TransferSummary>,
    pub transfers_sent: u64,
    pub transfers_received: u64,
    pub bytes_transferred: u64,
    pub last_transfer: Option<crate::xfer::engine::LastTransfer>,
}

#[derive(Debug, Serialize)]
pub struct CancelResponse {
    pub status: String,
    pub transfer_id: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct InboxResponse {
    pub count: usize,
    pub files: Vec<store::InboxItem>,
}

pub async fn send(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    headers: HeaderMap,
    Json(body): Json<SendRequest>,
) -> Result<Json<SendResponse>, ApiError> {
    let idempotency_key = idempotency::header_key(&headers);
    if let Some(key) = idempotency_key.as_deref() {
        if let Some(cached) = idempotency::lookup::<SendResponse>("xfer:send", key) {
            return Ok(Json(cached));
        }
    }
    let config = crate::xfer::XferConfig::from_env();
    let peer_did = body.peer_did.trim();
    if peer_did.is_empty() {
        return Err(ApiError::BadRequest(
            "peer_did must not be empty".to_string(),
        ));
    }
    if session
        .as_ref()
        .is_some_and(|Extension(session)| session.claims.role == "member")
    {
        let allowed = crate::api::auth::authorization::scoped_circle_contact_dids(
            &state.node_id,
            &state.device_did,
            session
                .as_ref()
                .map(|Extension(session)| session.claims.circle_ids.as_slice())
                .unwrap_or(&[]),
        )
        .map_err(ApiError::Internal)?;
        if !allowed.contains(peer_did) {
            if let Some(Extension(session)) = session.as_ref() {
                crate::api::auth::authorization::audit_member_resource_denied(
                    &state.node_id,
                    &session.claims.sub,
                    "Circle transfer target",
                );
            }
            return Err(ApiError::Forbidden(
                "transfer target does not share a Circle with this Guardian".into(),
            ));
        }
    }
    let transfer_id = match (body.path, body.vault_id) {
        (Some(path), None) => {
            let path = path.trim();
            if path.is_empty() {
                return Err(ApiError::BadRequest("path must not be empty".to_string()));
            }
            let metadata = tokio::fs::metadata(path).await.map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    ApiError::BadRequest(error.to_string())
                } else {
                    ApiError::Internal(error.to_string())
                }
            })?;
            if !metadata.is_file() {
                return Err(ApiError::BadRequest(
                    "path must reference a regular file".to_string(),
                ));
            }
            if metadata.len() > config.max_file_bytes {
                return Err(ApiError::PayloadTooLarge(format!(
                    "file too large: {} > {}",
                    metadata.len(),
                    config.max_file_bytes
                )));
            }
            crate::xfer::engine::send_file(
                state.node_id.clone(),
                config,
                peer_did.to_string(),
                PathBuf::from(path),
            )
            .await
            .map_err(map_xfer_error)?
        }
        (None, Some(vault_id)) => {
            let vault_id = validate_vault_id(vault_id.trim())
                .map_err(|error| ApiError::BadRequest(error.to_string()))?;
            let record = vault_persistence::find_record(&VaultConfig::from_env(), &vault_id)
                .await
                .map_err(|error| ApiError::Internal(error.to_string()))?
                .ok_or_else(|| ApiError::NotFound(format!("vault file not found: {}", vault_id)))?;
            if record.size_plain > config.max_file_bytes {
                return Err(ApiError::PayloadTooLarge(format!(
                    "file too large: {} > {}",
                    record.size_plain, config.max_file_bytes
                )));
            }
            crate::xfer::engine::send_vault_record(
                state.node_id.clone(),
                config,
                peer_did.to_string(),
                vault_id,
            )
            .await
            .map_err(map_xfer_error)?
        }
        (Some(_), Some(_)) | (None, None) => {
            return Err(ApiError::BadRequest(
                "exactly one of path or vault_id must be provided".to_string(),
            ))
        }
    };
    let response = SendResponse {
        status: "accepted".to_string(),
        transfer_id,
        message: "transfer queued".to_string(),
    };
    if let Some(key) = idempotency_key.as_deref() {
        idempotency::store("xfer:send", key, &response);
    }
    Ok(Json(response))
}

pub async fn list(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<TransferListResponse>, ApiError> {
    let transfers = store::list_outbox().await.map_err(map_xfer_error)?;
    let transfers = transfers
        .into_iter()
        .map(sender_summary)
        .collect::<Vec<_>>();
    Ok(Json(TransferListResponse {
        count: transfers.len(),
        transfers,
        transfers_sent: crate::xfer::engine::transfers_sent(),
        transfers_received: crate::xfer::engine::transfers_received(),
        bytes_transferred: crate::xfer::engine::bytes_transferred(),
        last_transfer: crate::xfer::engine::last_transfer(),
    }))
}

pub async fn detail(
    State(_state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<TransferSummary>, ApiError> {
    let id = id.trim();
    if id.is_empty() {
        return Err(ApiError::BadRequest(
            "transfer id must not be empty".to_string(),
        ));
    }
    if let Some(progress) = store::load_outbox(id).await.map_err(map_xfer_error)? {
        return Ok(Json(sender_summary(progress)));
    }
    if let Some(state) = store::find_receiver_state(id)
        .await
        .map_err(map_xfer_error)?
    {
        return Ok(Json(receiver_summary(state)));
    }
    Err(ApiError::NotFound(format!("transfer not found: {}", id)))
}

pub async fn cancel(
    State(_state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<CancelResponse>, ApiError> {
    let id = id.trim();
    if id.is_empty() {
        return Err(ApiError::BadRequest(
            "transfer id must not be empty".to_string(),
        ));
    }
    let found = crate::xfer::engine::cancel_transfer(id)
        .await
        .map_err(map_xfer_error)?;
    if !found {
        return Err(ApiError::NotFound(format!("transfer not found: {}", id)));
    }
    Ok(Json(CancelResponse {
        status: "cancelled".to_string(),
        transfer_id: id.to_string(),
        message: "transfer cancelled".to_string(),
    }))
}

pub async fn inbox(State(_state): State<Arc<AppState>>) -> Result<Json<InboxResponse>, ApiError> {
    let files = store::list_inbox().await.map_err(map_xfer_error)?;
    Ok(Json(InboxResponse {
        count: files.len(),
        files,
    }))
}

fn sender_summary(progress: SenderProgress) -> TransferSummary {
    TransferSummary {
        transfer_id: progress.transfer_id,
        direction: "outbound".to_string(),
        status: format!("{:?}", progress.status).to_ascii_lowercase(),
        circle_id: progress.circle_id,
        filename: progress.filename,
        size: progress.size,
        chunk_bytes: progress.chunk_bytes,
        chunk_count: progress.chunk_count,
        peer_did: Some(progress.peer_did),
        sender_did: None,
        file_path: Some(progress.file_path),
        sent_chunks: Some(progress.sent_chunks),
        requested_chunks: Some(progress.requested_chunks),
        received_chunks: None,
        bytes_sent: Some(progress.bytes_sent),
        last_error: progress.last_error,
        updated_at: progress.updated_at,
        completed_at: progress.completed_at,
    }
}

fn receiver_summary(state: ReceiverState) -> TransferSummary {
    TransferSummary {
        transfer_id: state.transfer_id,
        direction: "inbound".to_string(),
        status: format!("{:?}", state.status).to_ascii_lowercase(),
        circle_id: state.circle_id,
        filename: state.filename,
        size: state.size,
        chunk_bytes: state.chunk_bytes,
        chunk_count: state.chunk_count,
        peer_did: None,
        sender_did: Some(state.sender_did),
        file_path: None,
        sent_chunks: None,
        requested_chunks: None,
        received_chunks: Some(state.received_chunks.len()),
        bytes_sent: None,
        last_error: state.last_error,
        updated_at: state.updated_at,
        completed_at: state.completed_at,
    }
}

fn map_xfer_error(error: XferError) -> ApiError {
    match error {
        XferError::SourceNotFound(message) | XferError::TransferNotFound(message) => {
            ApiError::NotFound(message)
        }
        XferError::PeerNotFound(message) => ApiError::BadRequest(message),
        XferError::InvalidStructure(message) => ApiError::BadRequest(message),
        XferError::FileTooLarge { size, max } => {
            ApiError::PayloadTooLarge(format!("file too large: {} > {}", size, max))
        }
        XferError::RevokedPeer(message) => ApiError::Forbidden(message),
        XferError::Conflict(message) | XferError::Cancelled(message) => ApiError::Conflict(message),
        XferError::HashMismatch { .. } | XferError::CircleMismatch { .. } => {
            ApiError::Conflict(error.to_string())
        }
        XferError::Io(io) if io.kind() == std::io::ErrorKind::NotFound => {
            ApiError::BadRequest(io.to_string())
        }
        other => ApiError::Internal(other.to_string()),
    }
}
