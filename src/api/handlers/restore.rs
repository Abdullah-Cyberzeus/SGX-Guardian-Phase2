use crate::api::auth::middleware::AuthenticatedSession;
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::backup::BackupConfig;
use crate::backup::errors::BackupError;
use crate::backup::restore::{RestorePreflightOptions, RestorePreflightReport};
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::auth::session::Claims;
    use tempfile::TempDir;

    fn test_state(base: &std::path::Path) -> Arc<AppState> {
        let config_dir = base.join("config");
        std::fs::create_dir_all(&config_dir).expect("config dir");
        AppState::for_tests(base, "nodeA", config_dir.display().to_string())
    }

    fn session_with_role(role: &str) -> Extension<AuthenticatedSession> {
        Extension(AuthenticatedSession {
            claims: Claims {
                sub: "user-1".into(),
                role: role.into(),
                scopes: Vec::new(),
                circle_ids: Vec::new(),
                browser_registration_id: None,
                guardian_fingerprint: None,
                iss: "did:guardian:test".into(),
                iat: 0,
                exp: i64::MAX,
                jti: "jti-1".into(),
            },
            token: "token".into(),
        })
    }

    /// `require_owner_or_admin` short-circuits when login is disabled, so the
    /// role tests have to pin the gate closed first.
    struct LoginGate;

    impl LoginGate {
        fn enforced() -> Self {
            crate::runtime_gates::set_test_login_disabled(Some(false));
            Self
        }
    }

    impl Drop for LoginGate {
        fn drop(&mut self) {
            crate::runtime_gates::set_test_login_disabled(None);
        }
    }

    #[test]
    fn require_owner_or_admin_accepts_privileged_roles_only() {
        let _gate = LoginGate::enforced();
        for role in ["owner", "admin"] {
            let session = session_with_role(role);
            require_owner_or_admin(Some(&session.0)).expect("privileged role is accepted");
        }
        let member = session_with_role("member");
        assert!(matches!(
            require_owner_or_admin(Some(&member.0)),
            Err(ApiError::Forbidden(_))
        ));
        assert!(matches!(
            require_owner_or_admin(None),
            Err(ApiError::Unauthorized(_))
        ));
    }

    #[test]
    fn require_owner_or_admin_is_bypassed_while_login_is_disabled() {
        crate::runtime_gates::set_test_login_disabled(Some(true));
        let result = require_owner_or_admin(None);
        crate::runtime_gates::set_test_login_disabled(None);
        result.expect("an unauthenticated caller passes while login is disabled");
    }

    #[tokio::test]
    async fn validate_rejects_a_blank_id_or_passphrase() {
        let temp = TempDir::new().expect("tempdir");
        let state = test_state(temp.path());

        let error = validate(
            State(state.clone()),
            Json(RestoreValidateRequest {
                id: "  ".into(),
                passphrase: "hunter2".into(),
                confirm: false,
                options: RestorePreflightOptions::default(),
            }),
        )
        .await
        .expect_err("a blank backup id is rejected");
        assert!(matches!(error, ApiError::BadRequest(msg) if msg.contains("backup id")));

        let error = validate(
            State(state),
            Json(RestoreValidateRequest {
                id: "backup-1".into(),
                passphrase: String::new(),
                confirm: false,
                options: RestorePreflightOptions::default(),
            }),
        )
        .await
        .expect_err("an empty passphrase is rejected");
        assert!(matches!(error, ApiError::BadRequest(msg) if msg.contains("passphrase")));
    }

    #[tokio::test]
    async fn apply_checks_authorization_before_validating_the_request() {
        let _gate = LoginGate::enforced();
        let temp = TempDir::new().expect("tempdir");
        let state = test_state(temp.path());
        let error = apply(
            State(state.clone()),
            Some(session_with_role("member")),
            Json(RestoreValidateRequest {
                id: String::new(),
                passphrase: String::new(),
                confirm: false,
                options: RestorePreflightOptions::default(),
            }),
        )
        .await
        .expect_err("a member may not restore");
        assert!(matches!(error, ApiError::Forbidden(_)));

        let error = apply(
            State(state),
            Some(session_with_role("owner")),
            Json(RestoreValidateRequest {
                id: "  ".into(),
                passphrase: "hunter2".into(),
                confirm: false,
                options: RestorePreflightOptions::default(),
            }),
        )
        .await
        .expect_err("an owner still has to send a backup id");
        assert!(matches!(error, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn undo_requires_a_privileged_session() {
        let _gate = LoginGate::enforced();
        let temp = TempDir::new().expect("tempdir");
        let state = test_state(temp.path());
        let error = undo(
            State(state),
            Some(session_with_role("member")),
            Json(RestoreUndoRequest { confirm: true }),
        )
        .await
        .expect_err("a member may not undo a restore");
        assert!(matches!(error, ApiError::Forbidden(_)));
    }

    #[tokio::test]
    async fn status_reports_an_idle_journal_for_a_fresh_backup_root() {
        // `BACKUP_BASE_ENV` is process-global and `api::tests` redirects it too,
        // so this redirect has to be exclusive for as long as it is in effect.
        let _lock = crate::test_support::async_env_lock().await;
        let temp = TempDir::new().expect("tempdir");
        let state = test_state(temp.path());
        let previous = std::env::var_os(crate::backup::BACKUP_BASE_ENV);
        std::env::set_var(crate::backup::BACKUP_BASE_ENV, temp.path().join("backup"));
        let result = status(State(state)).await;
        match previous {
            Some(value) => std::env::set_var(crate::backup::BACKUP_BASE_ENV, value),
            None => std::env::remove_var(crate::backup::BACKUP_BASE_ENV),
        }
        result.expect("a fresh journal reports a status rather than failing");
    }

    #[test]
    fn map_backup_error_maps_each_failure_to_its_api_status() {
        assert!(matches!(
            map_backup_error(BackupError::NotFound("gone".into())),
            ApiError::NotFound(_)
        ));
        assert!(matches!(
            map_backup_error(BackupError::InvalidRequest("bad".into())),
            ApiError::BadRequest(_)
        ));
        for error in [
            BackupError::Integrity("tampered".into()),
            BackupError::UnsupportedSchema("v99".into()),
            BackupError::RestoreUnavailable("busy".into()),
        ] {
            assert!(matches!(map_backup_error(error), ApiError::Conflict(_)));
        }
        assert!(matches!(
            map_backup_error(BackupError::BundleTooLarge { size: 9, max: 4 }),
            ApiError::PayloadTooLarge(_)
        ));
        assert!(matches!(
            map_backup_error(BackupError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "absent"
            ))),
            ApiError::NotFound(_)
        ));
        assert!(matches!(
            map_backup_error(BackupError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "denied"
            ))),
            ApiError::Internal(_)
        ));
    }
}
