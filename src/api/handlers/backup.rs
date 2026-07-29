use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::backup::errors::BackupError;
use crate::backup::model::{BackupHistory, BackupRecord, RestoreReport, ValidateReport};
use crate::backup::BackupConfig;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct BackupSecretRequest {
    pub passphrase: String,
    #[serde(default = "default_portable")]
    pub portable: bool,
}

#[derive(Debug, Deserialize)]
pub struct BackupIdSecretRequest {
    pub id: String,
    pub passphrase: String,
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    Json(body): Json<BackupSecretRequest>,
) -> Result<Json<BackupRecord>, ApiError> {
    if body.passphrase.is_empty() {
        return Err(ApiError::BadRequest(
            "passphrase must not be empty".to_string(),
        ));
    }
    let record = crate::backup::create::create_backup(
        state,
        BackupConfig::from_env(),
        body.passphrase,
        body.portable,
    )
    .await
    .map_err(map_backup_error)?;
    Ok(Json(record))
}

pub async fn history(State(_state): State<Arc<AppState>>) -> Result<Json<BackupHistory>, ApiError> {
    Ok(Json(
        crate::backup::create::load_history(&BackupConfig::from_env())
            .await
            .map_err(map_backup_error)?,
    ))
}

pub async fn download(
    State(_state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let config = BackupConfig::from_env();
    let id = crate::backup::safe_id(&id);
    if id.is_empty() {
        return Err(ApiError::BadRequest(
            "backup id must not be empty".to_string(),
        ));
    }
    let path = config.bundle_path(&id);
    if !tokio::fs::try_exists(&path).await? {
        return Err(ApiError::NotFound(format!("backup not found: {}", id)));
    }
    let meta = tokio::fs::metadata(&path).await?;
    if meta.len() > config.max_bundle_bytes {
        return Err(ApiError::PayloadTooLarge(format!(
            "backup bundle is too large to download through this endpoint: {} > {}",
            meta.len(),
            config.max_bundle_bytes
        )));
    }
    let bytes = tokio::fs::read(&path).await?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}.sgxbak\"", id),
        )
        .body(Body::from(bytes))
        .map_err(|error| ApiError::Internal(error.to_string()))
}

pub async fn delete(
    State(_state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = crate::backup::safe_id(&id);
    if id.is_empty() {
        return Err(ApiError::BadRequest(
            "backup id must not be empty".to_string(),
        ));
    }
    crate::backup::create::delete_backup(&BackupConfig::from_env(), &id)
        .await
        .map_err(map_backup_error)?;
    Ok(Json(serde_json::json!({ "status": "deleted", "id": id })))
}

pub async fn validate(
    State(state): State<Arc<AppState>>,
    Json(body): Json<BackupIdSecretRequest>,
) -> Result<Json<ValidateReport>, ApiError> {
    if body.passphrase.is_empty() {
        return Err(ApiError::BadRequest(
            "passphrase must not be empty".to_string(),
        ));
    }
    Ok(Json(
        crate::backup::validate::validate_backup(
            state,
            BackupConfig::from_env(),
            &body.id,
            body.passphrase,
        )
        .await
        .map_err(map_backup_error)?,
    ))
}

pub async fn restore(
    State(_state): State<Arc<AppState>>,
    Json(_body): Json<BackupIdSecretRequest>,
) -> Result<Json<RestoreReport>, ApiError> {
    crate::backup::restore::restore_backup()
        .await
        .map(Json)
        .map_err(map_backup_error)
}

fn default_portable() -> bool {
    true
}

fn map_backup_error(error: BackupError) -> ApiError {
    match error {
        BackupError::NotFound(message) => ApiError::NotFound(message),
        BackupError::InvalidRequest(message) => ApiError::BadRequest(message),
        BackupError::Integrity(message)
        | BackupError::UnsupportedSchema(message)
        | BackupError::RestoreUnavailable(message) => ApiError::Conflict(message),
        BackupError::BundleTooLarge { size, max } => {
            ApiError::PayloadTooLarge(format!("bundle too large: {} > {}", size, max))
        }
        BackupError::Io(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ApiError::NotFound(error.to_string())
        }
        other => ApiError::Internal(other.to_string()),
    }
}
