use crate::api::{error::ApiError, state::AppState};
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::did::{self, DidError};
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const DEFAULT_DKP_PUBKEY_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_pub.der";
const DID_PATH_ENV: &str = "SGX_GUARDIAN_DID_PATH";
const DKP_PUBKEY_PATH_ENV: &str = "SGX_GUARDIAN_DKP_PUBKEY_PATH";

#[derive(Serialize)]
pub struct DidStatusResponse {
    pub did: String,
    pub method: String,
    #[serde(rename = "methodVersion")]
    pub method_version: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "deactivatedAt")]
    pub deactivated_at: Option<String>,
    #[serde(rename = "currentDkpVersion")]
    pub current_dkp_version: u32,
    #[serde(rename = "se050UidSource")]
    pub se050_uid_source: String,
    #[serde(rename = "dikPubkeySha256B16")]
    pub dik_pubkey_sha256_b16: String,
    pub status: String,
}

#[derive(Serialize)]
pub struct DidResolveResponse {
    pub did: String,
    pub status: String,
    #[serde(rename = "publicKeyPreview")]
    pub public_key_preview: String,
    #[serde(rename = "publicKeyBytes")]
    pub public_key_bytes: usize,
}

#[derive(Deserialize)]
pub struct DeactivateRequest {
    pub reason: Option<String>,
    pub confirm: bool,
}

#[derive(Debug, Serialize)]
pub struct DeactivateResponse {
    pub ok: bool,
    pub message: String,
    #[serde(rename = "restartRequired")]
    pub restart_required: bool,
}

pub async fn status(_state: State<Arc<AppState>>) -> Result<Json<DidStatusResponse>, ApiError> {
    let did_path = did_path();
    let rec = did::DidRecord::load(&did_path).map_err(|e| did_error(e, &did_path))?;

    Ok(Json(DidStatusResponse {
        did: rec.did,
        method: rec.method,
        method_version: rec.method_version,
        created_at: rec.created_at,
        deactivated_at: rec.deactivated_at.clone(),
        current_dkp_version: rec.current_dkp_version,
        se050_uid_source: rec.derivation.se050_uid_source,
        dik_pubkey_sha256_b16: rec.derivation.dik_pubkey_sha256_b16,
        status: if rec.deactivated_at.is_none() {
            "active".to_string()
        } else {
            "deactivated".to_string()
        },
    }))
}

pub async fn resolve(_state: State<Arc<AppState>>) -> Result<Json<DidResolveResponse>, ApiError> {
    let did_path = did_path();
    let dkp_pubkey_path = dkp_pubkey_path();
    let (resolved_did, public_key, active) =
        did::method::resolve_local(&did_path, &dkp_pubkey_path)
            .map_err(|e| did_error(e, &did_path))?;

    let public_key_hex = hex::encode(&public_key);
    let preview_len = public_key_hex.len().min(32);
    let mut public_key_preview = public_key_hex[..preview_len].to_string();
    if public_key_hex.len() > preview_len {
        public_key_preview.push_str("...");
    }

    Ok(Json(DidResolveResponse {
        did: resolved_did.as_str().to_string(),
        status: if active {
            "ACTIVE".to_string()
        } else {
            "DEACTIVATED".to_string()
        },
        public_key_preview,
        public_key_bytes: public_key.len(),
    }))
}

pub async fn deactivate(
    State(s): State<Arc<AppState>>,
    Json(body): Json<DeactivateRequest>,
) -> Result<Json<DeactivateResponse>, ApiError> {
    if !body.confirm {
        log_audit(
            &s.node_id,
            AuditCategory::Did,
            AuditSeverity::Warning,
            AuditAction::Rejected,
            "DID deactivation rejected: confirm was not true",
        );
        return Err(ApiError::BadRequest(
            "confirm must be true to deactivate DID".to_string(),
        ));
    }

    let reason = body
        .reason
        .unwrap_or_else(|| "manual-admin".to_string())
        .trim()
        .to_string();
    let reason = if reason.is_empty() {
        "manual-admin".to_string()
    } else {
        reason
    };

    let did_path = did_path();
    let message = match did::method::deactivate(&did_path, &reason) {
        Ok(()) => {
            log_audit(
                &s.node_id,
                AuditCategory::Did,
                AuditSeverity::Warning,
                AuditAction::Revoked,
                &format!("DID deactivated by admin (reason={})", reason),
            );
            "DID deactivated. Restart daemon to enforce runtime refusal.".to_string()
        }
        Err(DidError::Deactivated(at)) => {
            log_audit(
                &s.node_id,
                AuditCategory::Did,
                AuditSeverity::Info,
                AuditAction::Revoked,
                &format!("DID already deactivated at {}", at),
            );
            format!("DID already deactivated at {}", at)
        }
        Err(e) => return Err(did_error(e, &did_path)),
    };

    Ok(Json(DeactivateResponse {
        ok: true,
        message,
        restart_required: true,
    }))
}

fn did_path() -> String {
    std::env::var(DID_PATH_ENV).unwrap_or_else(|_| did::DEFAULT_DID_PATH.to_string())
}

fn dkp_pubkey_path() -> String {
    std::env::var(DKP_PUBKEY_PATH_ENV).unwrap_or_else(|_| DEFAULT_DKP_PUBKEY_PATH.to_string())
}

fn did_error(err: DidError, did_path: &str) -> ApiError {
    match err {
        DidError::Io(e) if e.kind() == std::io::ErrorKind::NotFound => {
            ApiError::NotFound(format!("did record not found at {}", did_path))
        }
        DidError::InvalidFormat(e)
        | DidError::WrongMethod(e)
        | DidError::Base58(e)
        | DidError::UidUnavailable(e)
        | DidError::Signing(e)
        | DidError::DkpPubkeyMissing(e) => ApiError::BadRequest(e),
        other => ApiError::Internal(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::persistence::{DerivationProof, DidRecord};
    use axum::extract::State;
    use base64::engine::general_purpose;
    use base64::Engine as _;
    use once_cell::sync::Lazy;
    use std::ffi::OsString;
    use tokio::sync::Mutex;

    static TEST_ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    struct EnvGuard {
        did_prev: Option<OsString>,
        dkp_prev: Option<OsString>,
    }

    impl EnvGuard {
        fn new(did_path: &str, dkp_path: &str) -> Self {
            let did_prev = std::env::var_os(DID_PATH_ENV);
            let dkp_prev = std::env::var_os(DKP_PUBKEY_PATH_ENV);
            std::env::set_var(DID_PATH_ENV, did_path);
            std::env::set_var(DKP_PUBKEY_PATH_ENV, dkp_path);
            Self { did_prev, dkp_prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            restore_env(DID_PATH_ENV, self.did_prev.take());
            restore_env(DKP_PUBKEY_PATH_ENV, self.dkp_prev.take());
        }
    }

    fn restore_env(key: &str, value: Option<OsString>) {
        if let Some(v) = value {
            std::env::set_var(key, v);
        } else {
            std::env::remove_var(key);
        }
    }

    fn test_state() -> Arc<AppState> {
        Arc::new(AppState {
            node_id: "nodeA".into(),
            config_dir: "/tmp/config".into(),
            boot_dir: "/tmp/boot".into(),
            keys_dir: "/tmp/keys".into(),
            pcr_dir: "/tmp/pcr".into(),
            pcr_baseline_dir: "/tmp".into(),
            log_dir_primary: "/tmp/logs".into(),
            log_dir_fallback: "/tmp/logs2".into(),
        })
    }

    fn seed_did(path: &str, deactivated: Option<String>) {
        let did = crate::did::Did::from_id_bytes(&[1u8; 32]);
        let rec = DidRecord {
            did: did.as_str().to_string(),
            method: "guardian".into(),
            method_version: "1.0".into(),
            did_id_b58: did.msi().to_string(),
            did_id_hex: "01".repeat(32),
            created_at: "2026-04-26T10:00:00Z".into(),
            deactivated_at: deactivated,
            derivation: DerivationProof {
                se050_uid: "fixture-uid".into(),
                se050_uid_source: "fallback".into(),
                dkp_v1_pubkey_sha256_b16: "ab".repeat(32),
                dkp_v1_pubkey_path: "/tmp/dkp_pub.der".into(),
                dkp_v1_pubkey_der_b64: None,
                dik_pubkey_sha256_b16: "cd".repeat(32),
                dik_pubkey_der_b64: Some(general_purpose::STANDARD.encode([1u8; 64])),
            },
            current_dkp_version: 3,
            deriv_signature_b64: "Zm9v".into(),
        };
        rec.save(path).expect("save did");
    }

    #[tokio::test]
    async fn did_status_route_returns_expected_fields() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let did_path = tmp.path().join("identity").join("did.json");
        let dkp_path = tmp.path().join("keys").join("dkp_pub.der");
        let _env = EnvGuard::new(&did_path.to_string_lossy(), &dkp_path.to_string_lossy());
        seed_did(&did_path.to_string_lossy(), None);

        let Json(resp) = super::status(State(test_state())).await.expect("status");
        assert_eq!(resp.status, "active");
        assert_eq!(resp.method, "guardian");
        assert_eq!(resp.current_dkp_version, 3);
    }

    #[tokio::test]
    async fn did_resolve_marks_deactivated_record() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let did_path = tmp.path().join("identity").join("did.json");
        let dkp_path = tmp.path().join("keys").join("dkp_pub.der");
        let _env = EnvGuard::new(&did_path.to_string_lossy(), &dkp_path.to_string_lossy());
        seed_did(
            &did_path.to_string_lossy(),
            Some("2026-05-21T09:00:00Z".into()),
        );

        let Json(resp) = super::resolve(State(test_state())).await.expect("resolve");
        assert_eq!(resp.status, "DEACTIVATED");
        assert_eq!(resp.public_key_bytes, 64);
    }

    #[tokio::test]
    async fn did_deactivate_requires_confirm_true() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let did_path = tmp.path().join("identity").join("did.json");
        let dkp_path = tmp.path().join("keys").join("dkp_pub.der");
        let _env = EnvGuard::new(&did_path.to_string_lossy(), &dkp_path.to_string_lossy());
        seed_did(&did_path.to_string_lossy(), None);

        let err = super::deactivate(
            State(test_state()),
            Json(DeactivateRequest {
                reason: Some("manual-admin".into()),
                confirm: false,
            }),
        )
        .await
        .expect_err("confirm rejection expected");

        let response = axum::response::IntoResponse::into_response(err);
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn did_deactivate_returns_restart_required() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let did_path = tmp.path().join("identity").join("did.json");
        let dkp_path = tmp.path().join("keys").join("dkp_pub.der");
        let _env = EnvGuard::new(&did_path.to_string_lossy(), &dkp_path.to_string_lossy());
        seed_did(&did_path.to_string_lossy(), None);

        let Json(resp) = super::deactivate(
            State(test_state()),
            Json(DeactivateRequest {
                reason: Some("manual-admin".into()),
                confirm: true,
            }),
        )
        .await
        .expect("deactivate");

        assert!(resp.ok);
        assert!(resp.restart_required);
    }
}
