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
    if is_member && !allowed.contains(peer_did) {
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
            ));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xfer::persistence;
    use crate::xfer::store::TransferStatus;
    use tempfile::TempDir;

    /// Full Guardian state tree (identity, VCs, Circles, transfers) in a
    /// temp dir, plus the signed local owner every authorization hop reads.
    struct Harness {
        _env: crate::test_support::guardian::GuardianEnv,
        base: TempDir,
        state: Arc<AppState>,
        caller_did: String,
    }

    async fn harness() -> (crate::test_support::EnvLockGuard, Harness) {
        let lock = crate::test_support::async_env_lock().await;
        let env = crate::test_support::guardian::GuardianEnv::new();
        let (base, state) = test_state("nodeA");
        crate::test_support::guardian::seed_owner("nodeA", &state.device_did, "192.168.100.1/24");
        let caller_did = state.device_did.clone();
        (
            lock,
            Harness {
                _env: env,
                base,
                state,
                caller_did,
            },
        )
    }

    fn test_state(node_id: &str) -> (TempDir, Arc<AppState>) {
        let temp = TempDir::new().expect("tempdir");
        let config_dir = temp.path().join("config");
        std::fs::create_dir_all(&config_dir).expect("config dir");
        let state = AppState::for_tests(temp.path(), node_id, config_dir.display().to_string());
        (temp, state)
    }

    fn progress(transfer_id: &str, actor_did: &str) -> SenderProgress {
        SenderProgress {
            transfer_id: transfer_id.to_string(),
            circle_id: "circle-alpha".to_string(),
            actor_did: actor_did.to_string(),
            peer_did: "did:sgx:peer".to_string(),
            filename: "report.pdf".to_string(),
            file_path: "/tmp/report.pdf".to_string(),
            size: 2048,
            chunk_bytes: 1024,
            chunk_count: 2,
            requested_chunks: 2,
            sent_chunks: 1,
            bytes_sent: 1024,
            status: TransferStatus::Sending,
            updated_at: "2026-01-02T00:00:00Z".to_string(),
            completed_at: None,
            last_error: Some("stalled".to_string()),
        }
    }

    fn local_record(transfer_id: &str, sender: &str, recipient: &str) -> LocalTransferRecord {
        LocalTransferRecord {
            transfer_id: transfer_id.to_string(),
            circle_id: "circle-alpha".to_string(),
            sender_did: sender.to_string(),
            recipient_did: recipient.to_string(),
            filename: "photo.jpg".to_string(),
            size: 512,
            file_sha256: "sha-256-digest".to_string(),
            vault_id: "vault-1".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            completed_at: "2026-01-01T00:00:01Z".to_string(),
        }
    }

    async fn save_progress(record: &SenderProgress) {
        persistence::save_json_pretty(&persistence::outbox_path(&record.transfer_id), record)
            .await
            .expect("save outbox record");
    }

    #[tokio::test]
    async fn send_rejects_an_empty_peer_did() {
        let (_lock, h) = harness().await;
        let state = h.state.clone();
        let error = send(
            State(state),
            None,
            HeaderMap::new(),
            Json(SendRequest {
                peer_did: "   ".to_string(),
                path: Some("/tmp/whatever".to_string()),
                vault_id: None,
            }),
        )
        .await
        .expect_err("empty peer_did must be rejected");
        assert!(matches!(error, ApiError::BadRequest(msg) if msg.contains("peer_did")));
    }

    #[tokio::test]
    async fn send_requires_exactly_one_of_path_or_vault_id() {
        let (_lock, h) = harness().await;
        let state = h.state.clone();
        for (path, vault_id) in [
            (None, None),
            (Some("/tmp/a".to_string()), Some("vault-1".to_string())),
        ] {
            let error = send(
                State(state.clone()),
                None,
                HeaderMap::new(),
                Json(SendRequest {
                    peer_did: "did:sgx:peer".to_string(),
                    path,
                    vault_id,
                }),
            )
            .await
            .expect_err("ambiguous source must be rejected");
            assert!(
                matches!(&error, ApiError::BadRequest(msg) if msg.contains("exactly one")),
                "unexpected error variant: {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn send_rejects_a_blank_path_and_a_missing_file() {
        let (_lock, h) = harness().await;
        let state = h.state.clone();

        let error = send(
            State(state.clone()),
            None,
            HeaderMap::new(),
            Json(SendRequest {
                peer_did: "did:sgx:peer".to_string(),
                path: Some("   ".to_string()),
                vault_id: None,
            }),
        )
        .await
        .expect_err("blank path must be rejected");
        assert!(matches!(error, ApiError::BadRequest(msg) if msg.contains("path")));

        let missing = h.base.path().join("absent.bin");
        let error = send(
            State(state),
            None,
            HeaderMap::new(),
            Json(SendRequest {
                peer_did: "did:sgx:peer".to_string(),
                path: Some(missing.display().to_string()),
                vault_id: None,
            }),
        )
        .await
        .expect_err("missing file must be rejected");
        assert!(matches!(error, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn send_rejects_a_directory_and_an_oversized_file() {
        let (_lock, h) = harness().await;
        let state = h.state.clone();

        let dir = h.base.path().join("a-directory");
        std::fs::create_dir_all(&dir).expect("create dir");
        let error = send(
            State(state.clone()),
            None,
            HeaderMap::new(),
            Json(SendRequest {
                peer_did: "did:sgx:peer".to_string(),
                path: Some(dir.display().to_string()),
                vault_id: None,
            }),
        )
        .await
        .expect_err("a directory is not a transferable file");
        assert!(matches!(error, ApiError::BadRequest(msg) if msg.contains("regular file")));

        let big = h.base.path().join("big.bin");
        std::fs::write(&big, vec![0u8; 4096]).expect("write big file");
        std::env::set_var("SGX_XFER_MAX_FILE_BYTES", "16");
        let error = send(
            State(state),
            None,
            HeaderMap::new(),
            Json(SendRequest {
                peer_did: "did:sgx:peer".to_string(),
                path: Some(big.display().to_string()),
                vault_id: None,
            }),
        )
        .await
        .expect_err("oversized file must be rejected");
        std::env::remove_var("SGX_XFER_MAX_FILE_BYTES");
        assert!(matches!(error, ApiError::PayloadTooLarge(msg) if msg.contains("too large")));
    }

    #[tokio::test]
    async fn send_rejects_an_invalid_vault_id() {
        let (_lock, h) = harness().await;
        let state = h.state.clone();
        let error = send(
            State(state),
            None,
            HeaderMap::new(),
            Json(SendRequest {
                peer_did: "did:sgx:peer".to_string(),
                path: None,
                vault_id: Some("../escape".to_string()),
            }),
        )
        .await
        .expect_err("path traversal in a vault id must be rejected");
        assert!(matches!(error, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn list_returns_owned_network_and_local_transfers_newest_first() {
        let (_lock, h) = harness().await;
        let state = h.state.clone();
        let caller = h.caller_did.clone();

        // Legacy record (empty actor) belongs to the Guardian identity.
        let mut legacy = progress("xfer-legacy", "");
        legacy.updated_at = "2026-01-03T00:00:00Z".to_string();
        save_progress(&legacy).await;
        // Another identity's record must not leak into the listing.
        save_progress(&progress("xfer-other", "did:sgx:someone-else")).await;
        store::save_local_transfer(&local_record("local-1", &caller, "did:sgx:peer"))
            .await
            .expect("save local transfer");

        let response = list(State(state), None).await.expect("list transfers");
        let ids: Vec<&str> = response
            .0
            .transfers
            .iter()
            .map(|item| item.transfer_id.as_str())
            .collect();
        assert_eq!(ids, vec!["xfer-legacy", "local-1"]);
        assert_eq!(response.0.count, 2);
        assert_eq!(response.0.transfers_sent, 2);
        assert_eq!(response.0.transfers_received, 0);
        assert_eq!(response.0.bytes_transferred, 2048 + 512);
    }

    #[tokio::test]
    async fn detail_rejects_a_blank_id_and_reports_unknown_transfers() {
        let (_lock, h) = harness().await;
        let state = h.state.clone();

        let error = detail(State(state.clone()), None, Path("  ".to_string()))
            .await
            .expect_err("blank id must be rejected");
        assert!(matches!(error, ApiError::BadRequest(msg) if msg.contains("transfer id")));

        let error = detail(State(state), None, Path("nope".to_string()))
            .await
            .expect_err("unknown id must be reported as missing");
        assert!(matches!(error, ApiError::NotFound(msg) if msg.contains("nope")));
    }

    #[tokio::test]
    async fn detail_returns_a_sender_summary_for_the_owning_identity() {
        let (_lock, h) = harness().await;
        let state = h.state.clone();
        let caller = h.caller_did.clone();
        save_progress(&progress("xfer-1", &caller)).await;

        let summary = detail(State(state), None, Path("xfer-1".to_string()))
            .await
            .expect("detail for owned transfer");
        assert_eq!(summary.0.direction, "outbound");
        assert_eq!(summary.0.status, "sending");
        assert_eq!(summary.0.sent_chunks, Some(1));
        assert_eq!(summary.0.sender_did.as_deref(), Some(caller.as_str()));
        assert_eq!(summary.0.last_error.as_deref(), Some("stalled"));
    }

    #[tokio::test]
    async fn detail_refuses_a_transfer_owned_by_another_identity() {
        let (_lock, h) = harness().await;
        let state = h.state.clone();
        save_progress(&progress("xfer-foreign", "did:sgx:someone-else")).await;

        let error = detail(State(state), None, Path("xfer-foreign".to_string()))
            .await
            .expect_err("foreign transfers must not be readable");
        assert!(matches!(error, ApiError::Forbidden(_)));
    }

    #[tokio::test]
    async fn detail_serves_both_sides_of_a_same_board_local_transfer() {
        let (_lock, h) = harness().await;
        let state = h.state.clone();
        let caller = h.caller_did.clone();

        store::save_local_transfer(&local_record("local-out", &caller, "did:sgx:peer"))
            .await
            .expect("save outbound local transfer");
        let outbound = detail(State(state.clone()), None, Path("local-out".to_string()))
            .await
            .expect("outbound local detail");
        assert_eq!(outbound.0.direction, "outbound");
        assert_eq!(outbound.0.bytes_sent, Some(512));

        store::save_local_transfer(&local_record("local-in", "did:sgx:peer", &caller))
            .await
            .expect("save inbound local transfer");
        let inbound = detail(State(state.clone()), None, Path("local-in".to_string()))
            .await
            .expect("inbound local detail");
        assert_eq!(inbound.0.direction, "inbound");
        assert!(inbound.0.peer_did.is_none());
        assert!(inbound.0.bytes_sent.is_none());

        store::save_local_transfer(&local_record("local-foreign", "did:sgx:one", "did:sgx:two"))
            .await
            .expect("save third-party local transfer");
        let error = detail(State(state), None, Path("local-foreign".to_string()))
            .await
            .expect_err("third-party local transfers must not be readable");
        assert!(matches!(error, ApiError::Forbidden(_)));
    }

    #[tokio::test]
    async fn cancel_validates_the_id_and_requires_ownership() {
        let (_lock, h) = harness().await;
        let state = h.state.clone();

        let error = cancel(State(state.clone()), None, Path("".to_string()))
            .await
            .expect_err("blank id must be rejected");
        assert!(matches!(error, ApiError::BadRequest(_)));

        // No record at all: the caller does not own it either.
        let error = cancel(State(state.clone()), None, Path("ghost".to_string()))
            .await
            .expect_err("unknown transfers cannot be cancelled");
        assert!(matches!(error, ApiError::Forbidden(_)));

        save_progress(&progress("xfer-foreign", "did:sgx:someone-else")).await;
        let error = cancel(State(state), None, Path("xfer-foreign".to_string()))
            .await
            .expect_err("only the sender may cancel");
        assert!(matches!(error, ApiError::Forbidden(_)));
    }

    #[tokio::test]
    async fn cancel_marks_an_owned_transfer_cancelled() {
        let (_lock, h) = harness().await;
        let state = h.state.clone();
        let caller = h.caller_did.clone();
        save_progress(&progress("xfer-mine", &caller)).await;

        let response = cancel(State(state), None, Path("xfer-mine".to_string()))
            .await
            .expect("owned transfer cancels");
        assert_eq!(response.0.status, "cancelled");
        assert_eq!(response.0.transfer_id, "xfer-mine");

        let stored = store::load_outbox("xfer-mine")
            .await
            .expect("reload outbox")
            .expect("record still present");
        assert_eq!(stored.status, TransferStatus::Cancelled);
    }

    #[tokio::test]
    async fn inbox_lists_guardian_receipts_and_local_deliveries() {
        let (_lock, h) = harness().await;
        let state = h.state.clone();
        let caller = h.caller_did.clone();

        store::save_local_transfer(&local_record("local-in", "did:sgx:peer", &caller))
            .await
            .expect("save inbound local transfer");
        store::save_local_transfer(&local_record("local-other", "did:sgx:peer", "did:sgx:x"))
            .await
            .expect("save unrelated local transfer");

        let response = inbox(State(state), None).await.expect("inbox listing");
        assert_eq!(response.0.count, 1);
        let item = &response.0.files[0];
        assert_eq!(item.transfer_id, "local-in");
        assert!(item.completed);
        assert!(item.vault_available);
        assert_eq!(item.vault_id.as_deref(), Some("vault-1"));
        assert!(item.download_path.is_some());
    }

    #[test]
    fn receiver_summary_reports_inbound_progress() {
        let summary = receiver_summary(ReceiverState {
            transfer_id: "in-1".into(),
            circle_id: "circle-alpha".into(),
            sender_did: "did:sgx:peer".into(),
            filename: "notes.txt".into(),
            size: 96,
            chunk_bytes: 32,
            chunk_count: 3,
            file_sha256: "digest".into(),
            received_chunks: vec![0, 1],
            status: TransferStatus::Receiving,
            updated_at: "2026-01-01T00:00:00Z".into(),
            completed_at: None,
            last_error: None,
            vault_id: None,
        });
        assert_eq!(summary.direction, "inbound");
        assert_eq!(summary.status, "receiving");
        assert_eq!(summary.received_chunks, Some(2));
        assert!(summary.peer_did.is_none());
        assert!(summary.bytes_sent.is_none());
    }

    #[test]
    fn map_xfer_error_maps_every_transport_failure_to_its_api_status() {
        assert!(matches!(
            map_xfer_error(XferError::SourceNotFound("gone".into())),
            ApiError::NotFound(_)
        ));
        assert!(matches!(
            map_xfer_error(XferError::TransferNotFound("gone".into())),
            ApiError::NotFound(_)
        ));
        assert!(matches!(
            map_xfer_error(XferError::PeerNotFound("peer".into())),
            ApiError::BadRequest(_)
        ));
        assert!(matches!(
            map_xfer_error(XferError::InvalidStructure("bad".into())),
            ApiError::BadRequest(_)
        ));
        assert!(matches!(
            map_xfer_error(XferError::FileTooLarge { size: 9, max: 4 }),
            ApiError::PayloadTooLarge(_)
        ));
        assert!(matches!(
            map_xfer_error(XferError::RevokedPeer("revoked".into())),
            ApiError::Forbidden(_)
        ));
        assert!(matches!(
            map_xfer_error(XferError::Conflict("busy".into())),
            ApiError::Conflict(_)
        ));
        assert!(matches!(
            map_xfer_error(XferError::Cancelled("stopped".into())),
            ApiError::Conflict(_)
        ));
        assert!(matches!(
            map_xfer_error(XferError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "absent"
            ))),
            ApiError::BadRequest(_)
        ));
        assert!(matches!(
            map_xfer_error(XferError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "denied"
            ))),
            ApiError::Internal(_)
        ));
    }
}
