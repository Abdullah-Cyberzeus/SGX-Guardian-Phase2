use crate::api::auth::middleware::AuthenticatedSession;
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::backup::errors::BackupError;
use crate::backup::restore::{RestorePreflightOptions, RestorePreflightReport};
use crate::backup::BackupConfig;
use axum::extract::State;
use axum::{Extension, Json};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct RestoreValidateRequest {
    pub id: String,
    pub passphrase: String,
    #[serde(default)]
    pub confirm: bool,
    #[serde(default, flatten)]
    pub options: RestorePreflightOptions,
}

#[derive(Debug, Deserialize)]
pub struct RestoreUndoRequest {
    #[serde(default)]
    pub confirm: bool,
}

pub async fn validate(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RestoreValidateRequest>,
) -> Result<Json<RestorePreflightReport>, ApiError> {
    if body.id.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "backup id must not be empty".to_string(),
        ));
    }
    if body.passphrase.is_empty() {
        return Err(ApiError::BadRequest(
            "passphrase must not be empty".to_string(),
        ));
    }
    let report = crate::backup::restore::validate_restore(
        state,
        BackupConfig::from_env(),
        body.id.trim(),
        body.passphrase,
        body.options,
    )
    .await
    .map_err(map_backup_error)?;
    Ok(Json(report))
}

pub async fn apply(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Json(body): Json<RestoreValidateRequest>,
) -> Result<Json<crate::backup::model::RestoreReport>, ApiError> {
    require_owner_or_admin(session.as_ref().map(|session| &session.0))?;
    if body.id.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "backup id must not be empty".to_string(),
        ));
    }
    if body.passphrase.is_empty() {
        return Err(ApiError::BadRequest(
            "passphrase must not be empty".to_string(),
        ));
    }
    let node_id = state.node_id.clone();
    let backup_id = body.id.trim().to_string();
    let report = crate::backup::restore::apply_restore(
        state,
        BackupConfig::from_env(),
        body.id.trim(),
        body.passphrase,
        body.options,
        body.confirm,
    )
    .await
    .map_err(map_backup_error)?;
    log_audit(
        &node_id,
        AuditCategory::Vault,
        AuditSeverity::Critical,
        AuditAction::Applied,
        &format!("Restore applied from backup: {}", backup_id),
    );
    Ok(Json(report))
}

pub async fn undo(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Json(body): Json<RestoreUndoRequest>,
) -> Result<Json<crate::backup::model::RestoreReport>, ApiError> {
    require_owner_or_admin(session.as_ref().map(|session| &session.0))?;
    let report = crate::backup::restore::undo_restore(BackupConfig::from_env(), body.confirm)
        .await
        .map_err(map_backup_error)?;
    log_audit(
        &state.node_id,
        AuditCategory::Vault,
        AuditSeverity::Critical,
        AuditAction::Rollback,
        "Restore undone",
    );
    Ok(Json(report))
}

pub async fn status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<crate::backup::restore::journal::RestoreStatus>, ApiError> {
    crate::backup::restore::journal::status_with_recovery(&BackupConfig::from_env(), &state.node_id)
        .map(Json)
        .map_err(map_backup_error)
}

fn require_owner_or_admin(session: Option<&AuthenticatedSession>) -> Result<(), ApiError> {
    if crate::runtime_gates::login_disabled() {
        return Ok(());
    }
    let Some(session) = session else {
        return Err(ApiError::Unauthorized(
            "restore requires authentication".to_string(),
        ));
    };
    if !matches!(session.claims.role.as_str(), "owner" | "admin") {
        return Err(ApiError::Forbidden(
            "restore requires owner or admin role".to_string(),
        ));
    }
    Ok(())
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
