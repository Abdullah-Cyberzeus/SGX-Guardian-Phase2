use crate::api::{error::ApiError, state::AppState};
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::policy_authority::{PaKey, PA_PRIV_PATH, PA_PUB_PATH};
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

const GUARDIAN_PROVIDER: &str = "PaKey";
const GUARDIAN_ALGORITHM: &str = "ECDSA-P256";

#[derive(Clone)]
struct GuardianKeyPaths {
    private_key_path: String,
    public_key_path: String,
}

#[derive(Serialize)]
pub struct GuardianKeyStatusResponse {
    pub exists: bool,
    #[serde(rename = "privateKeyExists")]
    pub private_key_exists: bool,
    #[serde(rename = "publicKeyExists")]
    pub public_key_exists: bool,
    #[serde(rename = "privateKeyPath")]
    pub private_key_path: String,
    #[serde(rename = "publicKeyPath")]
    pub public_key_path: String,
    pub provider: String,
    pub algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct GenerateGuardianKeyRequest {
    #[serde(default)]
    pub force: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KeyBackup {
    #[serde(rename = "originalPath")]
    pub original_path: String,
    #[serde(rename = "backupPath")]
    pub backup_path: String,
}

#[derive(Serialize, Deserialize)]
pub struct GuardianKeyGenerateResponse {
    pub success: bool,
    #[serde(rename = "alreadyExists")]
    pub already_exists: bool,
    pub provider: String,
    pub algorithm: String,
    pub stdout: String,
    pub stderr: String,
    #[serde(rename = "privateKeyPath")]
    pub private_key_path: String,
    #[serde(rename = "publicKeyPath")]
    pub public_key_path: String,
    #[serde(rename = "restartRequired")]
    pub restart_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub backups: Vec<KeyBackup>,
}

/// GET /api/v1/guardian/key/status
pub async fn status(
    State(_): State<Arc<AppState>>,
) -> Result<Json<GuardianKeyStatusResponse>, ApiError> {
    let paths = guardian_key_paths();
    let private_key_exists = Path::new(&paths.private_key_path).exists();
    let public_key_exists = Path::new(&paths.public_key_path).exists();

    Ok(Json(GuardianKeyStatusResponse {
        exists: private_key_exists && public_key_exists,
        private_key_exists,
        public_key_exists,
        private_key_path: paths.private_key_path.clone(),
        public_key_path: paths.public_key_path.clone(),
        provider: GUARDIAN_PROVIDER.to_string(),
        algorithm: GUARDIAN_ALGORITHM.to_string(),
        fingerprint: fingerprint_from_public_key(&paths.public_key_path)?,
    }))
}

/// POST /api/v1/guardian/key/generate
pub async fn generate(
    State(s): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<GenerateGuardianKeyRequest>,
) -> Result<Json<GuardianKeyGenerateResponse>, ApiError> {
    // A retried `force:true` request must not rotate the key twice — the
    // second rotation would invalidate the key the first call just issued,
    // stranding anything (like this response) that already captured it.
    let idempotency_key = crate::api::idempotency::header_key(&headers);
    if let Some(key) = idempotency_key.as_deref() {
        if let Some(cached) = crate::api::idempotency::lookup::<GuardianKeyGenerateResponse>(
            "guardian_keys:generate",
            key,
        ) {
            return Ok(Json(cached));
        }
    }
    let paths = guardian_key_paths();
    let private_exists = Path::new(&paths.private_key_path).exists();
    let public_exists = Path::new(&paths.public_key_path).exists();

    if private_exists && public_exists && !body.force {
        let msg = "Guardian key pair already exists. Set {\"force\":true} to regenerate.";
        let fingerprint = fingerprint_from_public_key(&paths.public_key_path)?;
        log_audit(
            &s.node_id,
            AuditCategory::Policy,
            AuditSeverity::Warning,
            AuditAction::Rejected,
            msg,
        );
        let response = GuardianKeyGenerateResponse {
            success: false,
            already_exists: true,
            provider: GUARDIAN_PROVIDER.to_string(),
            algorithm: GUARDIAN_ALGORITHM.to_string(),
            stdout: String::new(),
            stderr: msg.to_string(),
            private_key_path: paths.private_key_path.clone(),
            public_key_path: paths.public_key_path.clone(),
            restart_required: false,
            fingerprint,
            backups: Vec::new(),
        };
        if let Some(key) = idempotency_key.as_deref() {
            crate::api::idempotency::store("guardian_keys:generate", key, &response);
        }
        return Ok(Json(response));
    }

    let mut backups = Vec::new();
    let forced = body.force && (private_exists || public_exists);
    if forced {
        backups = backup_existing_key_files(&paths)?;
        log_audit(
            &s.node_id,
            AuditCategory::Policy,
            AuditSeverity::Warning,
            AuditAction::Started,
            "Forced Guardian key regeneration started",
        );
    } else {
        log_audit(
            &s.node_id,
            AuditCategory::Policy,
            AuditSeverity::Info,
            AuditAction::Started,
            "Guardian software key generation started",
        );
    }

    let mut success = true;
    let mut stdout = String::new();
    let mut stderr = String::new();

    if let Err(e) = PaKey::load_or_generate_at(&paths.private_key_path, &paths.public_key_path) {
        success = false;
        append_line(&mut stderr, &format!("PaKey generation failed: {}", e));
    } else if let Err(e) = apply_required_permissions(&paths) {
        success = false;
        append_line(&mut stderr, &format!("permission update failed: {}", e));
    } else {
        stdout = "Policy Authority keypair ready".to_string();
    }

    if !success && !backups.is_empty() {
        if let Err(e) = restore_backups(&backups) {
            append_line(&mut stderr, &format!("failed to restore backups: {}", e));
        } else {
            append_line(&mut stderr, "restored previous key files from backup");
        }
    }

    let response = GuardianKeyGenerateResponse {
        success,
        already_exists: false,
        provider: GUARDIAN_PROVIDER.to_string(),
        algorithm: GUARDIAN_ALGORITHM.to_string(),
        stdout,
        stderr,
        private_key_path: paths.private_key_path.clone(),
        public_key_path: paths.public_key_path.clone(),
        restart_required: true,
        fingerprint: fingerprint_from_public_key(&paths.public_key_path)?,
        backups,
    };

    if response.success {
        log_audit(
            &s.node_id,
            AuditCategory::Policy,
            AuditSeverity::Info,
            AuditAction::Succeeded,
            &format!(
                "Policy Authority key generation succeeded (forced={})",
                forced
            ),
        );
    } else {
        log_audit(
            &s.node_id,
            AuditCategory::Policy,
            AuditSeverity::Critical,
            AuditAction::Failed,
            &format!("Policy Authority key generation failed (forced={})", forced),
        );
    }

    if let Some(key) = idempotency_key.as_deref() {
        crate::api::idempotency::store("guardian_keys:generate", key, &response);
    }
    Ok(Json(response))
}

fn guardian_key_paths() -> GuardianKeyPaths {
    let private_key_path =
        std::env::var("SGX_GUARDIAN_PRIV_KEY_PATH").unwrap_or_else(|_| PA_PRIV_PATH.to_string());
    let public_key_path =
        std::env::var("SGX_GUARDIAN_PUB_KEY_PATH").unwrap_or_else(|_| PA_PUB_PATH.to_string());
    GuardianKeyPaths {
        private_key_path,
        public_key_path,
    }
}

fn append_line(buf: &mut String, line: &str) {
    if !buf.is_empty() {
        buf.push('\n');
    }
    buf.push_str(line);
}

fn apply_required_permissions(paths: &GuardianKeyPaths) -> std::io::Result<()> {
    set_file_mode(&paths.private_key_path, 0o600)?;
    set_file_mode(&paths.public_key_path, 0o644)?;
    Ok(())
}

fn set_file_mode(path: &str, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if Path::new(path).exists() {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        let _ = mode;
    }
    Ok(())
}

fn timestamp_suffix() -> String {
    chrono::Utc::now().format("%Y%m%dT%H%M%S%3fZ").to_string()
}

fn backup_path_for(original: &str) -> String {
    format!("{}.bak.{}", original, timestamp_suffix())
}

fn backup_existing_key_files(paths: &GuardianKeyPaths) -> Result<Vec<KeyBackup>, ApiError> {
    let mut out = Vec::new();
    for src in [&paths.private_key_path, &paths.public_key_path] {
        if Path::new(src).exists() {
            let backup_path = backup_path_for(src);
            std::fs::rename(src, &backup_path)?;
            out.push(KeyBackup {
                original_path: src.to_string(),
                backup_path,
            });
        }
    }
    Ok(out)
}

fn restore_backups(backups: &[KeyBackup]) -> std::io::Result<()> {
    for backup in backups {
        let original = Path::new(&backup.original_path);
        if original.exists() {
            std::fs::remove_file(original)?;
        }
        let backup_path = Path::new(&backup.backup_path);
        if backup_path.exists() {
            std::fs::rename(backup_path, original)?;
        }
    }
    Ok(())
}

fn fingerprint_from_public_key(path: &str) -> Result<Option<String>, ApiError> {
    if !Path::new(path).exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(path)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    Ok(Some(hex::encode(&Sha256::digest(&bytes)[..8])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::state::AppState;
    use std::ffi::OsString;
    use std::path::Path;

    /// Redirects only the two paths `guardian_key_paths` actually reads.
    ///
    /// An earlier revision also set `SGX_PA_CLI_PATH` and
    /// `SGX_GUARDIAN_KEYGEN_DIR` here, back when key generation shelled out to
    /// `sgx-pa-cli`. Generation is in-process via `PaKey` now, so this module
    /// never reads either one — and `SGX_PA_CLI_PATH` is still live for `dkp`
    /// and `rules::exec::actions`, so clobbering it from here corrupted their
    /// tests whenever the two overlapped.
    struct EnvGuard {
        priv_prev: Option<OsString>,
        pub_prev: Option<OsString>,
    }

    impl EnvGuard {
        fn new(priv_path: &Path, pub_path: &Path) -> Self {
            let priv_prev = std::env::var_os("SGX_GUARDIAN_PRIV_KEY_PATH");
            let pub_prev = std::env::var_os("SGX_GUARDIAN_PUB_KEY_PATH");

            std::env::set_var("SGX_GUARDIAN_PRIV_KEY_PATH", priv_path);
            std::env::set_var("SGX_GUARDIAN_PUB_KEY_PATH", pub_path);

            Self {
                priv_prev,
                pub_prev,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            restore_env("SGX_GUARDIAN_PRIV_KEY_PATH", self.priv_prev.take());
            restore_env("SGX_GUARDIAN_PUB_KEY_PATH", self.pub_prev.take());
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
        let base = std::env::temp_dir().join(format!("sgx-guardian-keys-{}", uuid::Uuid::new_v4()));
        AppState::for_tests(
            &base,
            "test-nodeA",
            base.join("config").to_string_lossy().to_string(),
        )
    }

    #[tokio::test]
    async fn status_false_when_keys_missing() {
        let _lock = crate::test_support::env_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let priv_path = dir.path().join("guardian_private.key");
        let pub_path = dir.path().join("guardian_public.key");
        let _env = EnvGuard::new(&priv_path, &pub_path);

        let Json(resp) = status(State(test_state())).await.expect("status response");
        assert!(!resp.exists);
        assert!(!resp.private_key_exists);
        assert!(!resp.public_key_exists);
        assert!(resp.fingerprint.is_none());
    }

    #[tokio::test]
    async fn generate_creates_target_keys() {
        let _lock = crate::test_support::env_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let priv_path = dir.path().join("guardian_private.key.installed");
        let pub_path = dir.path().join("guardian_public.key.installed");
        let _env = EnvGuard::new(&priv_path, &pub_path);

        let Json(resp) = generate(
            State(test_state()),
            axum::http::HeaderMap::new(),
            Json(GenerateGuardianKeyRequest::default()),
        )
        .await
        .expect("generate response");

        assert!(resp.success);
        assert!(priv_path.exists());
        assert!(pub_path.exists());

        // The key material is DER, not text, so assert it is a real, reloadable
        // P-256 keypair rather than comparing against a literal.
        let pub_bytes = std::fs::read(&pub_path).expect("read public key");
        assert!(!pub_bytes.is_empty());
        let reloaded = PaKey::load_or_generate_at(
            priv_path.to_str().expect("priv path"),
            pub_path.to_str().expect("pub path"),
        )
        .expect("generated private key must reload as valid PKCS#8");
        assert_eq!(
            reloaded.pubkey_der(),
            pub_bytes.as_slice(),
            "published public key must match the stored private key"
        );

        assert_eq!(
            resp.fingerprint.as_deref(),
            Some(hex::encode(&Sha256::digest(&pub_bytes)[..8]).as_str()),
            "reported fingerprint must describe the key actually written"
        );
    }

    #[tokio::test]
    async fn generate_rejects_existing_keys_without_force() {
        let _lock = crate::test_support::env_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let priv_path = dir.path().join("guardian_private.key.installed");
        let pub_path = dir.path().join("guardian_public.key.installed");
        std::fs::write(&priv_path, "OLD_PRIVATE").expect("seed private");
        std::fs::write(&pub_path, "OLD_PUBLIC").expect("seed public");
        let _env = EnvGuard::new(&priv_path, &pub_path);

        let Json(resp) = generate(
            State(test_state()),
            axum::http::HeaderMap::new(),
            Json(GenerateGuardianKeyRequest { force: false }),
        )
        .await
        .expect("generate response");

        assert!(!resp.success);
        assert!(resp.already_exists);
    }

    #[tokio::test]
    async fn force_backs_up_old_keys() {
        let _lock = crate::test_support::env_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let priv_path = dir.path().join("guardian_private.key.installed");
        let pub_path = dir.path().join("guardian_public.key.installed");
        // Seed a real previous keypair so the rotation replaces valid material.
        PaKey::load_or_generate_at(
            priv_path.to_str().expect("priv path"),
            pub_path.to_str().expect("pub path"),
        )
        .expect("seed previous keypair");
        let old_priv = std::fs::read(&priv_path).expect("read seeded private");
        let old_pub = std::fs::read(&pub_path).expect("read seeded public");
        let _env = EnvGuard::new(&priv_path, &pub_path);

        let Json(resp) = generate(
            State(test_state()),
            axum::http::HeaderMap::new(),
            Json(GenerateGuardianKeyRequest { force: true }),
        )
        .await
        .expect("generate response");

        assert!(resp.success);
        assert_eq!(resp.backups.len(), 2);

        // Both previous files must survive at their backup paths...
        for backup in &resp.backups {
            assert!(
                Path::new(&backup.backup_path).exists(),
                "backup {} must exist",
                backup.backup_path
            );
        }

        // ...and the live paths must now hold different, still-valid material.
        let new_priv = std::fs::read(&priv_path).expect("read new private");
        let new_pub = std::fs::read(&pub_path).expect("read new public");
        assert_ne!(new_priv, old_priv, "force must rotate the private key");
        assert_ne!(new_pub, old_pub, "force must rotate the public key");
        let reloaded = PaKey::load_or_generate_at(
            priv_path.to_str().expect("priv path"),
            pub_path.to_str().expect("pub path"),
        )
        .expect("rotated private key must reload as valid PKCS#8");
        assert_eq!(reloaded.pubkey_der(), new_pub.as_slice());
    }

    #[tokio::test]
    async fn response_never_contains_private_key_data() {
        let _lock = crate::test_support::env_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let priv_path = dir.path().join("guardian_private.key.installed");
        let pub_path = dir.path().join("guardian_public.key.installed");
        let secret = "DO_NOT_LEAK_PRIVATE_KEY_VALUE";
        let _env = EnvGuard::new(&priv_path, &pub_path);

        let Json(resp) = generate(
            State(test_state()),
            axum::http::HeaderMap::new(),
            Json(GenerateGuardianKeyRequest::default()),
        )
        .await
        .expect("generate response");
        let payload = serde_json::to_string(&resp).expect("serialize response");
        assert!(resp.success);
        assert!(!payload.contains(secret));
    }

    #[tokio::test]
    async fn permissions_are_set_correctly() {
        let _lock = crate::test_support::env_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let priv_path = dir.path().join("guardian_private.key.installed");
        let pub_path = dir.path().join("guardian_public.key.installed");
        let _env = EnvGuard::new(&priv_path, &pub_path);

        let Json(resp) = generate(
            State(test_state()),
            axum::http::HeaderMap::new(),
            Json(GenerateGuardianKeyRequest::default()),
        )
        .await
        .expect("generate response");
        assert!(resp.success);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let priv_mode = std::fs::metadata(&priv_path)
                .expect("priv metadata")
                .permissions()
                .mode()
                & 0o777;
            let pub_mode = std::fs::metadata(&pub_path)
                .expect("pub metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(priv_mode, 0o600);
            assert_eq!(pub_mode, 0o644);
        }
    }

    #[tokio::test]
    async fn corrupt_private_key_reports_failure_without_silently_regenerating() {
        let _lock = crate::test_support::env_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let priv_path = dir.path().join("guardian_private.key.installed");
        let pub_path = dir.path().join("guardian_public.key.installed");
        // Only the private key exists, so `generate` does not take the
        // already-exists short circuit — and its contents are not valid PKCS#8.
        let corrupt = b"not-a-pkcs8-document";
        std::fs::write(&priv_path, corrupt).expect("seed corrupt private key");
        let _env = EnvGuard::new(&priv_path, &pub_path);

        let Json(resp) = generate(
            State(test_state()),
            axum::http::HeaderMap::new(),
            Json(GenerateGuardianKeyRequest::default()),
        )
        .await
        .expect("generate response");

        assert!(
            !resp.success,
            "corrupt key material must not report success"
        );
        assert!(
            resp.stderr.contains("PaKey generation failed"),
            "stderr should explain the failure, got {:?}",
            resp.stderr
        );
        // The unreadable key must be left untouched rather than overwritten,
        // so an operator can still recover it.
        assert_eq!(
            std::fs::read(&priv_path).expect("read private"),
            corrupt,
            "a failed generation must not destroy existing key material"
        );
    }
}
