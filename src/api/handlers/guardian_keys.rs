use crate::api::{error::ApiError, state::AppState};
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const DEFAULT_GUARDIAN_PRIV_KEY_PATH: &str = "/etc/sgx-guardian/guardian_private.key";
const DEFAULT_GUARDIAN_PUB_KEY_PATH: &str = "/etc/sgx-guardian/guardian_public.key";
const DEFAULT_KEYGEN_WORKDIR: &str = "/etc/sgx-guardian/";
const GENERATED_PRIV_KEY_NAME: &str = "guardian_private.key";
const GENERATED_PUB_KEY_NAME: &str = "guardian_public.key";
const GUARDIAN_PROVIDER: &str = "software";
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

#[derive(Serialize, Clone)]
pub struct KeyBackup {
    #[serde(rename = "originalPath")]
    pub original_path: String,
    #[serde(rename = "backupPath")]
    pub backup_path: String,
}

#[derive(Serialize)]
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

struct CliResult {
    success: bool,
    stdout: String,
    stderr: String,
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
    Json(body): Json<GenerateGuardianKeyRequest>,
) -> Result<Json<GuardianKeyGenerateResponse>, ApiError> {
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
        return Ok(Json(GuardianKeyGenerateResponse {
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
        }));
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

    let workdir = guardian_keygen_workdir();
    let cli = run_guardian_keygen(&workdir).await?;

    let mut success = cli.success;
    let stdout = cli.stdout;
    let mut stderr = cli.stderr;

    if success {
        if let Err(e) = install_generated_keys(&workdir, &paths) {
            success = false;
            append_line(&mut stderr, &format!("install failed: {}", e));
        }
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
                "Guardian software key generation succeeded (forced={})",
                forced
            ),
        );
    } else {
        log_audit(
            &s.node_id,
            AuditCategory::Policy,
            AuditSeverity::Critical,
            AuditAction::Failed,
            &format!(
                "Guardian software key generation failed (forced={})",
                forced
            ),
        );
    }

    Ok(Json(response))
}

fn guardian_key_paths() -> GuardianKeyPaths {
    let private_key_path = std::env::var("SGX_GUARDIAN_PRIV_KEY_PATH")
        .unwrap_or_else(|_| DEFAULT_GUARDIAN_PRIV_KEY_PATH.to_string());
    let public_key_path = std::env::var("SGX_GUARDIAN_PUB_KEY_PATH")
        .unwrap_or_else(|_| DEFAULT_GUARDIAN_PUB_KEY_PATH.to_string());
    GuardianKeyPaths {
        private_key_path,
        public_key_path,
    }
}

fn guardian_keygen_workdir() -> PathBuf {
    std::env::var("SGX_GUARDIAN_KEYGEN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_KEYGEN_WORKDIR))
}

fn append_line(buf: &mut String, line: &str) {
    if !buf.is_empty() {
        buf.push('\n');
    }
    buf.push_str(line);
}

fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

fn find_in_path(bin: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(bin);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn resolve_pa_cli_path() -> Option<PathBuf> {
    if let Ok(override_path) = std::env::var("SGX_PA_CLI_PATH") {
        let p = PathBuf::from(override_path);
        if is_executable_file(&p) {
            return Some(p);
        }
    }

    if let Some(p) = find_in_path("sgx-pa-cli") {
        return Some(p);
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join("sgx-pa-cli");
            if is_executable_file(&sibling) {
                return Some(sibling);
            }
        }
    }

    [
        "/usr/local/bin/sgx-pa-cli",
        "/usr/bin/sgx-pa-cli",
        "/bin/sgx-pa-cli",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| is_executable_file(p))
}

async fn run_guardian_keygen(workdir: &Path) -> Result<CliResult, ApiError> {
    let output = if let Some(cli_path) = resolve_pa_cli_path() {
        tokio::process::Command::new(&cli_path)
            .current_dir(workdir)
            .arg("keygen")
            .output()
            .await
            .map_err(|e| {
                ApiError::Internal(format!(
                    "failed to spawn sgx-pa-cli ({}) in {}: {}",
                    cli_path.display(),
                    workdir.display(),
                    e
                ))
            })?
    } else {
        tokio::process::Command::new("cargo")
            .current_dir(workdir)
            .args(["run", "--", "keygen"])
            .output()
            .await
            .map_err(|e| {
                ApiError::Internal(format!(
                    "failed to run fallback cargo keygen in {}: {}",
                    workdir.display(),
                    e
                ))
            })?
    };

    Ok(CliResult {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

fn install_generated_keys(workdir: &Path, paths: &GuardianKeyPaths) -> std::io::Result<()> {
    let generated_private = workdir.join(GENERATED_PRIV_KEY_NAME);
    let generated_public = workdir.join(GENERATED_PUB_KEY_NAME);

    if !generated_private.exists() || !generated_public.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "keygen output missing in {} (need {} and {})",
                workdir.display(),
                GENERATED_PRIV_KEY_NAME,
                GENERATED_PUB_KEY_NAME
            ),
        ));
    }

    let private_bytes = std::fs::read(generated_private)?;
    let public_bytes = std::fs::read(generated_public)?;

    atomic_write_bytes(&paths.private_key_path, &private_bytes)?;
    atomic_write_bytes(&paths.public_key_path, &public_bytes)?;
    apply_required_permissions(paths)?;
    Ok(())
}

fn atomic_write_bytes(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    ensure_parent_dir(path)?;
    let tmp = format!("{}.tmp", path);
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(tmp, path)?;
    Ok(())
}

fn ensure_parent_dir(path: &str) -> std::io::Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    Ok(())
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
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    use crate::test_utils::TEST_ENV_LOCK;

    struct EnvGuard {
        priv_prev: Option<OsString>,
        pub_prev: Option<OsString>,
        keygen_dir_prev: Option<OsString>,
        cli_prev: Option<OsString>,
    }

    impl EnvGuard {
        fn new(
            priv_path: &Path,
            pub_path: &Path,
            keygen_dir: &Path,
            cli_path: Option<&Path>,
        ) -> Self {
            let priv_prev = std::env::var_os("SGX_GUARDIAN_PRIV_KEY_PATH");
            let pub_prev = std::env::var_os("SGX_GUARDIAN_PUB_KEY_PATH");
            let keygen_dir_prev = std::env::var_os("SGX_GUARDIAN_KEYGEN_DIR");
            let cli_prev = std::env::var_os("SGX_PA_CLI_PATH");

            std::env::set_var("SGX_GUARDIAN_PRIV_KEY_PATH", priv_path);
            std::env::set_var("SGX_GUARDIAN_PUB_KEY_PATH", pub_path);
            std::env::set_var("SGX_GUARDIAN_KEYGEN_DIR", keygen_dir);
            if let Some(p) = cli_path {
                std::env::set_var("SGX_PA_CLI_PATH", p);
            } else {
                std::env::remove_var("SGX_PA_CLI_PATH");
            }

            Self {
                priv_prev,
                pub_prev,
                keygen_dir_prev,
                cli_prev,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            restore_env("SGX_GUARDIAN_PRIV_KEY_PATH", self.priv_prev.take());
            restore_env("SGX_GUARDIAN_PUB_KEY_PATH", self.pub_prev.take());
            restore_env("SGX_GUARDIAN_KEYGEN_DIR", self.keygen_dir_prev.take());
            restore_env("SGX_PA_CLI_PATH", self.cli_prev.take());
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
            node_id: "test-nodeA".into(),
            config_dir: "/tmp/config".into(),
            boot_dir: "/tmp/boot".into(),
            keys_dir: "/tmp/keys".into(),
            pcr_dir: "/tmp/pcr".into(),
            pcr_baseline_dir: "/tmp".into(),
            log_dir_primary: "/tmp/logs".into(),
            log_dir_fallback: "/tmp/logs-fallback".into(),
            did_resolver: crate::did::Resolver::new(Default::default()),
            vid_cache: crate::virtual_id_cache::VirtualIdCache::new(),
            discovery_config_dir: "/tmp/discovery-config".into(),
            discovery_state_dir: "/tmp/discovery-state".into(),
        })
    }

    fn write_fake_cli(dir: &TempDir, script_body: &str) -> PathBuf {
        let script_path = dir.path().join("fake-sgx-pa-cli.sh");
        let script = format!("#!/usr/bin/env bash\nset -eu\n{}\n", script_body);
        std::fs::write(&script_path, script).expect("write fake cli script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
                .expect("chmod fake cli");
        }
        script_path
    }

    #[tokio::test]
    async fn status_false_when_keys_missing() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let priv_path = dir.path().join("guardian_private.key");
        let pub_path = dir.path().join("guardian_public.key");
        let _env = EnvGuard::new(&priv_path, &pub_path, dir.path(), None);

        let Json(resp) = status(State(test_state())).await.expect("status response");
        assert!(!resp.exists);
        assert!(!resp.private_key_exists);
        assert!(!resp.public_key_exists);
        assert!(resp.fingerprint.is_none());
    }

    #[tokio::test]
    async fn generate_creates_target_keys() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let priv_path = dir.path().join("guardian_private.key.installed");
        let pub_path = dir.path().join("guardian_public.key.installed");
        let cli_path = write_fake_cli(
            &dir,
            "if [ \"${1:-}\" != \"keygen\" ]; then\n  exit 22\nfi\nprintf 'PRIVATE-KEY-DATA' > guardian_private.key\nprintf 'PUBLIC-KEY-DATA' > guardian_public.key\necho generated\nexit 0",
        );
        let _env = EnvGuard::new(&priv_path, &pub_path, dir.path(), Some(&cli_path));

        let Json(resp) = generate(
            State(test_state()),
            Json(GenerateGuardianKeyRequest::default()),
        )
        .await
        .expect("generate response");

        assert!(resp.success);
        assert!(priv_path.exists());
        assert!(pub_path.exists());
        assert_eq!(
            std::fs::read_to_string(&priv_path).expect("priv read"),
            "PRIVATE-KEY-DATA"
        );
        assert_eq!(
            std::fs::read_to_string(&pub_path).expect("pub read"),
            "PUBLIC-KEY-DATA"
        );
    }

    #[tokio::test]
    async fn generate_rejects_existing_keys_without_force() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let priv_path = dir.path().join("guardian_private.key.installed");
        let pub_path = dir.path().join("guardian_public.key.installed");
        std::fs::write(&priv_path, "OLD_PRIVATE").expect("seed private");
        std::fs::write(&pub_path, "OLD_PUBLIC").expect("seed public");
        let cli_path = write_fake_cli(&dir, "echo should-not-run >&2\nexit 99");
        let _env = EnvGuard::new(&priv_path, &pub_path, dir.path(), Some(&cli_path));

        let Json(resp) = generate(
            State(test_state()),
            Json(GenerateGuardianKeyRequest { force: false }),
        )
        .await
        .expect("generate response");

        assert!(!resp.success);
        assert!(resp.already_exists);
    }

    #[tokio::test]
    async fn force_backs_up_old_keys() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let priv_path = dir.path().join("guardian_private.key.installed");
        let pub_path = dir.path().join("guardian_public.key.installed");
        std::fs::write(&priv_path, "OLD_PRIVATE").expect("seed private");
        std::fs::write(&pub_path, "OLD_PUBLIC").expect("seed public");
        let cli_path = write_fake_cli(
            &dir,
            "if [ \"${1:-}\" != \"keygen\" ]; then\n  exit 22\nfi\nprintf 'NEW_PRIVATE' > guardian_private.key\nprintf 'NEW_PUBLIC' > guardian_public.key\nexit 0",
        );
        let _env = EnvGuard::new(&priv_path, &pub_path, dir.path(), Some(&cli_path));

        let Json(resp) = generate(
            State(test_state()),
            Json(GenerateGuardianKeyRequest { force: true }),
        )
        .await
        .expect("generate response");

        assert!(resp.success);
        assert_eq!(resp.backups.len(), 2);
        assert_eq!(
            std::fs::read_to_string(&priv_path).expect("new private"),
            "NEW_PRIVATE"
        );
        assert_eq!(
            std::fs::read_to_string(&pub_path).expect("new public"),
            "NEW_PUBLIC"
        );
    }

    #[tokio::test]
    async fn response_never_contains_private_key_data() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let priv_path = dir.path().join("guardian_private.key.installed");
        let pub_path = dir.path().join("guardian_public.key.installed");
        let secret = "DO_NOT_LEAK_PRIVATE_KEY_VALUE";
        let cli_path = write_fake_cli(
            &dir,
            "printf 'DO_NOT_LEAK_PRIVATE_KEY_VALUE' > guardian_private.key\nprintf 'PUBLIC_DATA' > guardian_public.key\nexit 0",
        );
        let _env = EnvGuard::new(&priv_path, &pub_path, dir.path(), Some(&cli_path));

        let Json(resp) = generate(
            State(test_state()),
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
        let _lock = TEST_ENV_LOCK.lock().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let priv_path = dir.path().join("guardian_private.key.installed");
        let pub_path = dir.path().join("guardian_public.key.installed");
        let cli_path = write_fake_cli(
            &dir,
            "printf 'PRIVATE' > guardian_private.key\nprintf 'PUBLIC' > guardian_public.key\nexit 0",
        );
        let _env = EnvGuard::new(&priv_path, &pub_path, dir.path(), Some(&cli_path));

        let Json(resp) = generate(
            State(test_state()),
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
    async fn cli_failure_returns_success_false() {
        let _lock = TEST_ENV_LOCK.lock().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let priv_path = dir.path().join("guardian_private.key.installed");
        let pub_path = dir.path().join("guardian_public.key.installed");
        let cli_path = write_fake_cli(&dir, "echo 'simulated keygen failure' >&2\nexit 7");
        let _env = EnvGuard::new(&priv_path, &pub_path, dir.path(), Some(&cli_path));

        let Json(resp) = generate(
            State(test_state()),
            Json(GenerateGuardianKeyRequest::default()),
        )
        .await
        .expect("generate response");
        assert!(!resp.success);
        assert!(resp.stderr.contains("simulated keygen failure"));
    }
}
