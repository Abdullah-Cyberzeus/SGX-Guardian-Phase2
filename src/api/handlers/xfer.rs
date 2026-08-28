use crate::api::auth::middleware::AuthenticatedSession;
use crate::api::error::ApiError;
use crate::api::idempotency;
use crate::api::state::AppState;
use crate::vault::namespace::validate_vault_id;
use crate::vault::VaultConfig;
use crate::xfer::errors::XferError;
use crate::xfer::store::{self, LocalTransferRecord, ReceiverState, SenderProgress};
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
    let caller_did = crate::api::handlers::vault::resolve_caller_did(&state, &session);
    let peer_did = body.peer_did.trim();
    if peer_did.is_empty() {
        return Err(ApiError::BadRequest(
            "peer_did must not be empty".to_string(),
        ));
    }
    let is_member = session
        .as_ref()
        .is_some_and(|Extension(session)| session.claims.role == "member");
    let allowed_circle_ids = if is_member {
        session
            .as_ref()
            .map(|Extension(session)| session.claims.circle_ids.clone())
            .unwrap_or_default()
    } else {
        crate::api::auth::authorization::local_active_circle_ids(&state.node_id, &state.device_did)
            .map_err(ApiError::Internal)?
            .into_iter()
            .collect()
    };
    let allowed_circle_set = allowed_circle_ids.iter().cloned().collect();
    let mut allowed = crate::api::auth::authorization::scoped_circle_contact_dids(
        &state.node_id,
        &state.device_did,
        &allowed_circle_ids,
    )
    .map_err(ApiError::Internal)?;
    allowed.extend(
        crate::api::handlers::browser_member::dids_for_circles(&state, &allowed_circle_set).await?,
    );
    if !allowed_circle_ids.is_empty() {
        allowed.insert(state.device_did.clone());
    }
    if is_member {
        if !allowed.contains(peer_did) {
            if let Some(Extension(session)) = session.as_ref() {
                crate::api::auth::authorization::audit_member_resource_denied(
                    &state.node_id,
                    &session.claims.sub,
                    "Circle transfer target",
                );
            }
            return Err(ApiError::Forbidden(
                "transfer target does not share an authorized Circle with this member".into(),
            ));
        }
    }

    let local_browser_recipient =
        crate::api::handlers::browser_member::state_for_did(&state, peer_did, &allowed_circle_set)
            .await?;
    let is_local_recipient = peer_did == state.device_did
        || local_browser_recipient
            == Some(crate::api::handlers::browser_member::BrowserMemberState::Active);
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
                caller_did.clone(),
                peer_did.to_string(),
                PathBuf::from(path),
            )
            .await
            .map_err(map_xfer_error)?
        }
        (None, Some(vault_id)) => {
            let vault_id = validate_vault_id(vault_id.trim())
                .map_err(|error| ApiError::BadRequest(error.to_string()))?;
            let vault_config = VaultConfig::from_env();
            let record = crate::api::handlers::vault::load_authorized_record(
                &vault_config,
                &session,
                &caller_did,
                &vault_id,
            )
            .await?;
            if record.size_plain > config.max_file_bytes {
                return Err(ApiError::PayloadTooLarge(format!(
                    "file too large: {} > {}",
                    record.size_plain, config.max_file_bytes
                )));
            }
            if is_local_recipient {
                let cloned = crate::vault::ingest::clone_for_local_recipient(&record, peer_did)
                    .await
                    .map_err(crate::api::handlers::vault::map_vault_error)?;
                let transfer_id = format!("local-{}", uuid::Uuid::new_v4());
                let now = chrono::Utc::now().to_rfc3339();
                store::save_local_transfer(&LocalTransferRecord {
                    transfer_id: transfer_id.clone(),
                    circle_id: allowed_circle_ids.first().cloned().unwrap_or_default(),
                    sender_did: caller_did,
                    recipient_did: peer_did.to_string(),
                    filename: cloned.filename,
                    size: cloned.size_plain,
                    file_sha256: cloned.sha256_plain,
                    vault_id: cloned.vault_id,
                    updated_at: now.clone(),
                    completed_at: now,
                })
                .await
                .map_err(map_xfer_error)?;
                transfer_id
            } else {
                crate::xfer::engine::send_vault_record(
                    state.node_id.clone(),
                    config,
                    caller_did,
                    peer_did.to_string(),
                    vault_id,
                )
                .await
                .map_err(map_xfer_error)?
            }
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
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
) -> Result<Json<TransferListResponse>, ApiError> {
    let caller_did = crate::api::handlers::vault::resolve_caller_did(&state, &session);
    // Legacy records predate actor scoping and therefore belong to the
    // Guardian. New network and same-board records carry the real actor DID.
    let mut transfers = store::list_outbox()
        .await
        .map_err(map_xfer_error)?
        .into_iter()
        .filter(|progress| {
            if progress.actor_did.is_empty() {
                caller_did == state.device_did
            } else {
                progress.actor_did == caller_did
            }
        })
        .map(sender_summary)
        .collect::<Vec<_>>();
    transfers.extend(
        store::list_local_transfers()
            .await
            .map_err(map_xfer_error)?
            .into_iter()
            .filter(|record| record.sender_did == caller_did)
            .map(local_sender_summary),
    );
    transfers.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    let visible_bytes = transfers.iter().map(|item| item.size).sum();
    let visible_sent = transfers.len() as u64;
    Ok(Json(TransferListResponse {
        count: transfers.len(),
        transfers,
        transfers_sent: visible_sent,
        transfers_received: 0,
        bytes_transferred: visible_bytes,
        last_transfer: None,
    }))
}

pub async fn detail(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Path(id): Path<String>,
) -> Result<Json<TransferSummary>, ApiError> {
    let id = id.trim();
    if id.is_empty() {
        return Err(ApiError::BadRequest(
            "transfer id must not be empty".to_string(),
        ));
    }
    let caller_did = crate::api::handlers::vault::resolve_caller_did(&state, &session);
    if let Some(progress) = store::load_outbox(id).await.map_err(map_xfer_error)? {
        let owns_progress = if progress.actor_did.is_empty() {
            caller_did == state.device_did
        } else {
            progress.actor_did == caller_did
        };
        if owns_progress {
            return Ok(Json(sender_summary(progress)));
        }
        return Err(ApiError::Forbidden(
            "transfer belongs to another identity".into(),
        ));
    }
    if let Some(record) = store::load_local_transfer(id)
        .await
        .map_err(map_xfer_error)?
    {
        if record.sender_did == caller_did {
            return Ok(Json(local_sender_summary(record)));
        }
        if record.recipient_did == caller_did {
            return Ok(Json(local_receiver_summary(record)));
        }
        return Err(ApiError::Forbidden(
            "transfer belongs to another identity".into(),
        ));
    }
    if caller_did == state.device_did {
        if let Some(state) = store::find_receiver_state(id)
            .await
            .map_err(map_xfer_error)?
        {
            return Ok(Json(receiver_summary(state)));
        }
    }
    Err(ApiError::NotFound(format!("transfer not found: {}", id)))
}

pub async fn cancel(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Path(id): Path<String>,
) -> Result<Json<CancelResponse>, ApiError> {
    let id = id.trim();
    if id.is_empty() {
        return Err(ApiError::BadRequest(
            "transfer id must not be empty".to_string(),
        ));
    }
    let caller_did = crate::api::handlers::vault::resolve_caller_did(&state, &session);
    let owns_transfer = store::load_outbox(id)
        .await
        .map_err(map_xfer_error)?
        .is_some_and(|progress| {
            if progress.actor_did.is_empty() {
                caller_did == state.device_did
            } else {
                progress.actor_did == caller_did
            }
        });
    if !owns_transfer {
        return Err(ApiError::Forbidden(
            "only the sending identity can cancel this network transfer".into(),
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

pub async fn inbox(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
) -> Result<Json<InboxResponse>, ApiError> {
    let caller_did = crate::api::handlers::vault::resolve_caller_did(&state, &session);
    let mut files = if caller_did == state.device_did {
        store::list_inbox().await.map_err(map_xfer_error)?
    } else {
        Vec::new()
    };
    files.extend(
        store::list_local_transfers()
            .await
            .map_err(map_xfer_error)?
            .into_iter()
            .filter(|record| record.recipient_did == caller_did)
            .map(local_inbox_item),
    );
    files.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    Ok(Json(InboxResponse {
        count: files.len(),
        files,
    }))
}

fn local_sender_summary(record: LocalTransferRecord) -> TransferSummary {
    TransferSummary {
        transfer_id: record.transfer_id,
        direction: "outbound".into(),
        status: "completed".into(),
        circle_id: record.circle_id,
        filename: record.filename,
        size: record.size,
        chunk_bytes: 0,
        chunk_count: 0,
        peer_did: Some(record.recipient_did),
        sender_did: Some(record.sender_did),
        file_path: None,
        sent_chunks: None,
        requested_chunks: None,
        received_chunks: None,
        bytes_sent: Some(record.size),
        last_error: None,
        updated_at: record.updated_at,
        completed_at: Some(record.completed_at),
    }
}

fn local_receiver_summary(record: LocalTransferRecord) -> TransferSummary {
    let mut summary = local_sender_summary(record);
    summary.direction = "inbound".into();
    summary.peer_did = None;
    summary.bytes_sent = None;
    summary
}

fn local_inbox_item(record: LocalTransferRecord) -> store::InboxItem {
    store::InboxItem {
        transfer_id: record.transfer_id,
        circle_id: record.circle_id,
        sender_did: record.sender_did,
        filename: record.filename,
        size: record.size,
        completed: true,
        path: Some(crate::vault::download_path(&record.vault_id)),
        updated_at: record.updated_at,
        completed_at: Some(record.completed_at),
        file_sha256: record.file_sha256,
        vault_id: Some(record.vault_id.clone()),
        download_path: Some(crate::vault::download_path(&record.vault_id)),
        vault_available: true,
    }
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
        sender_did: (!progress.actor_did.is_empty()).then_some(progress.actor_did),
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
