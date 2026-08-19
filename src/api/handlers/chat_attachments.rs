use crate::api::auth::middleware::AuthenticatedSession;
use crate::api::error::ApiError;
use crate::api::handlers::vault::{
    ensure_downloadable, idempotency_lookup, idempotency_store, load_authorized_record,
    map_vault_error, record_download_audit, resolve_caller_did, stream_record,
};
use crate::api::state::AppState;
use crate::vault::namespace::VaultNamespace;
use crate::vault::{ingest, mime_policy, persistence, VaultConfig};
use axum::{
    extract::{Extension, Multipart, Path, State},
    http::HeaderMap,
    response::Response,
    Json,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

#[derive(Serialize)]
pub struct UploadAttachmentResponse {
    pub attachment_id: String,
    pub status: String,
}

/// Chat attachments are stored as ordinary `VaultRecord`s (`source:
/// ChatAttachment`) under the sender's Personal namespace, since the
/// eventual destination (a group's Circle, or a 1:1 recipient) isn't known
/// until `send_message` links the upload to a real message. Encryption,
/// hashing, quota, and MIME enforcement are the same ones the Files-tab
/// upload path uses — see `vault::ingest::ingest_chat_attachment`.
pub async fn upload_attachment(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Json<UploadAttachmentResponse>, ApiError> {
    let config = VaultConfig::from_env();
    let caller_did = resolve_caller_did(&state, &session);
    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    if let Some(key) = idempotency_key.as_deref() {
        if let Some(vault_id) = idempotency_lookup(VaultNamespace::PERSONAL_STORAGE_KEY, key) {
            if persistence::find_record(&config, &vault_id)
                .await
                .map_err(map_vault_error)?
                .is_some()
            {
                return Ok(Json(UploadAttachmentResponse {
                    attachment_id: vault_id,
                    status: "uploaded".to_string(),
                }));
            }
        }
    }
    let mut file_received = false;
    let mut attachment_id = String::new();

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::BadRequest(format!("Failed to read multipart stream: {}", e)))?
    {
        let name = field.name().unwrap_or("").to_string();

        if name == "file" {
            file_received = true;
            let file_name = field.file_name().unwrap_or("unknown").to_string();
            let mime_type = field
                .content_type()
                .map(ToString::to_string)
                .unwrap_or_else(|| ingest::infer_mime(&file_name));
            mime_policy::ensure_mime_allowed(&mime_type).map_err(map_vault_error)?;

            let staging_path = persistence::staging_dir(&config)
                .join(format!("chat-upload-{}.part", Uuid::new_v4()));
            if let Some(parent) = staging_path.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|e| ApiError::Internal(format!("Failed to create staging dir: {}", e)))?;
            }

            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&staging_path)
                .await
                .map_err(|e| ApiError::Internal(format!("Failed to open file: {}", e)))?;

            let mut hasher = Sha256::new();
            let mut total_size = 0_u64;

            const MAX_ATTACHMENT_BYTES: u64 = crate::chat::storage::MAX_ATTACHMENT_BYTES;
            while let Some(chunk) = field
                .chunk()
                .await
                .map_err(|e| ApiError::BadRequest(e.to_string()))?
            {
                total_size = total_size.saturating_add(chunk.len() as u64);
                if total_size > MAX_ATTACHMENT_BYTES {
                    drop(file);
                    let _ = tokio::fs::remove_file(&staging_path).await;
                    return Err(ApiError::PayloadTooLarge(
                        "File exceeds maximum allowed size (50MB)".to_string(),
                    ));
                }
                hasher.update(&chunk);
                file.write_all(&chunk)
                    .await
                    .map_err(|e| ApiError::Internal(format!("File write error: {}", e)))?;
            }
            file.sync_all()
                .await
                .map_err(|e| ApiError::Internal(format!("File sync error: {}", e)))?;

            let record = ingest::ingest_chat_attachment(
                VaultNamespace::Personal,
                &caller_did,
                &staging_path,
                ingest::IngestMeta {
                    filename: file_name,
                    mime: mime_type,
                    sha256_plain: hex::encode(hasher.finalize()),
                    size_plain: total_size,
                    chunk_bytes: VaultConfig::DEFAULT_CHUNK_BYTES,
                },
                None,
            )
            .await
            .map_err(map_vault_error)?;

            attachment_id = record.vault_id;
            if let Some(key) = idempotency_key.as_deref() {
                idempotency_store(VaultNamespace::PERSONAL_STORAGE_KEY, key, &attachment_id);
            }
            break;
        }
    }

    if !file_received {
        return Err(ApiError::BadRequest(
            "No 'file' field found in multipart form data".to_string(),
        ));
    }

    Ok(Json(UploadAttachmentResponse {
        attachment_id,
        status: "uploaded".to_string(),
    }))
}

/// Downloads a chat attachment (used by the browser client). Peer-to-peer
/// Guardian sync uses the gRPC `get_attachment` path instead (see
/// `chat::grpc_server`), which streams the same decrypted bytes.
pub async fn download_attachment(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Path(attachment_id): Path<String>,
) -> Result<Response, ApiError> {
    let config = VaultConfig::from_env();
    let caller_did = resolve_caller_did(&state, &session);
    let record = load_authorized_record(&config, &session, &caller_did, &attachment_id).await?;
    ensure_downloadable(&record)?;
    let response = stream_record(record.clone(), "attachment")
        .await
        .map_err(map_vault_error)?;
    record_download_audit(&config, &record.vault_id, &caller_did, "chat").await;
    Ok(response)
}
