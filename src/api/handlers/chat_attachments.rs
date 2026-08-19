use crate::api::error::ApiError;
use crate::api::state::AppState;
use axum::{
    body::Body,
    extract::{Multipart, Path, State},
    response::Response,
    Json,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

#[derive(Serialize)]
pub struct UploadAttachmentResponse {
    pub attachment_id: String,
    pub status: String,
}

/// Task 4.1: Endpoint to accept multipart/form-data file uploads for chat attachments.
pub async fn upload_attachment(
    State(_state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<Json<UploadAttachmentResponse>, ApiError> {
    let mut file_received = false;
    let mut attachment_id = String::new();

    // Iterate over the multipart stream to extract the uploaded file
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
                .unwrap_or("application/octet-stream")
                .to_string();
            attachment_id = Uuid::new_v4().to_string();

            let file_path = crate::chat::storage::attachment_path(&attachment_id);
            let attachments_dir = file_path
                .parent()
                .ok_or_else(|| ApiError::Internal("Invalid attachment storage path".to_string()))?;
            if let Err(e) = tokio::fs::create_dir_all(&attachments_dir).await {
                return Err(ApiError::Internal(format!(
                    "Failed to create attachments dir: {}",
                    e
                )));
            }

            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&file_path)
                .await
                .map_err(|e| ApiError::Internal(format!("Failed to open file: {}", e)))?;

            let mut hasher = Sha256::new();
            let mut total_size = 0;

            const MAX_ATTACHMENT_BYTES: usize = crate::chat::storage::MAX_ATTACHMENT_BYTES as usize;
            // Stream chunks directly to disk and hash simultaneously.
            while let Some(chunk) = field
                .chunk()
                .await
                .map_err(|e| ApiError::BadRequest(e.to_string()))?
            {
                total_size += chunk.len();
                if total_size > MAX_ATTACHMENT_BYTES {
                    drop(file);
                    let _ = tokio::fs::remove_file(&file_path).await;
                    return Err(ApiError::BadRequest(
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

            let checksum = hex::encode(hasher.finalize());

            // Append metadata via storage module
            let record = crate::chat::models::AttachmentRecord {
                file_id: attachment_id.clone(),
                message_id: "pending_upload".to_string(),
                file_name,
                mime_type,
                encrypted_size: total_size as u64,
                sha256_hash: checksum,
                local_path: file_path.to_string_lossy().to_string(),
                encrypted_file_key: "not_yet_keyed".to_string(),
            };

            crate::chat::storage::append_attachment_metadata(&record)
                .await
                .map_err(|e| ApiError::Internal(e.to_string()))?;

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

/// Task 4.3: Endpoint to download an attachment (used by peers over the Nebula tunnel)
pub async fn download_attachment(
    State(_state): State<Arc<AppState>>,
    Path(attachment_id): Path<String>,
) -> Result<Response, ApiError> {
    // 1. Basic Path Traversal Prevention
    if uuid::Uuid::parse_str(&attachment_id).is_err() {
        return Err(ApiError::BadRequest(
            "Invalid attachment ID format".to_string(),
        ));
    }

    let file_path = crate::chat::storage::attachment_path(&attachment_id);

    // 2. Open the file
    let file = match File::open(&file_path).await {
        Ok(f) => f,
        Err(_) => {
            return Err(ApiError::NotFound(format!(
                "Attachment {} not found on this node",
                attachment_id
            )))
        }
    };

    // 3. Stream it securely directly from disk to the network
    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);

    // Fetch original filename from metadata, fallback to attachment_id if missing
    let mut filename = attachment_id.clone();
    let mut mime_type = "application/octet-stream".to_string();
    if let Ok(Some(metadata)) = crate::chat::storage::get_attachment_metadata(&attachment_id).await
    {
        filename = metadata.file_name;
        mime_type = metadata.mime_type;
    }
    let filename = filename
        .chars()
        .map(|character| match character {
            '\r' | '\n' | '"' | '\\' => '_',
            _ => character,
        })
        .collect::<String>();

    // Stream the stored bytes with the original media type and safe filename.
    let response = Response::builder()
        .header("Content-Type", mime_type)
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .body(body)
        .map_err(|e| ApiError::Internal(format!("Failed to build response: {}", e)))?;

    Ok(response)
}
