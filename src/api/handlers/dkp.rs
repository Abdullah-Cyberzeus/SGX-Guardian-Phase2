use crate::api::{error::ApiError, state::AppState};
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Serialize)]
pub struct DkpKey {
    pub version: u32,
    #[serde(rename = "keyId")]
    pub key_id: String,
    pub algorithm: String,
    pub status: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "rotatedFrom", skip_serializing_if = "Option::is_none")]
    pub rotated_from: Option<String>,
}

#[derive(Serialize)]
pub struct DkpStatus {
    #[serde(rename = "totalVersions")]
    pub total_versions: usize,
    #[serde(rename = "activeVersion")]
    pub active_version: Option<u32>,
    #[serde(rename = "se050Available")]
    pub se050_available: bool,
    #[serde(rename = "activePublicKeyPath")]
    pub active_pub_path: Option<String>,
    #[serde(rename = "activePublicKeySize")]
    pub active_pub_size: Option<u64>,
    pub keys: Vec<DkpKey>,
}

pub async fn status(State(s): State<Arc<AppState>>) -> Result<Json<DkpStatus>, ApiError> {
    let base = std::path::Path::new(&s.keys_dir)
        .canonicalize()
        .map_err(|_| ApiError::NotFound("no DKP found - daemon not started?".into()))?;
    let meta_path = base.join("dkp_metadata.json");
    let pub_path = base.join("dkp_pub.der");
    if meta_path
        .canonicalize()
        .map(|p| !p.starts_with(&base))
        .unwrap_or(true)
    {
        return Err(ApiError::NotFound(
            "no DKP found - daemon not started?".into(),
        ));
    }
    let text = tokio::fs::read_to_string(&meta_path)
        .await
        .map_err(|_| ApiError::NotFound("no DKP found - daemon not started?".into()))?;
    let raw: serde_json::Value = serde_json::from_str(&text)?;
    let arr: Vec<serde_json::Value> = if raw.is_array() {
        raw.as_array().cloned().unwrap_or_default()
    } else {
        vec![raw]
    };

    let keys: Vec<DkpKey> = arr
        .iter()
        .map(|k| DkpKey {
            version: k.get("version").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
            key_id: k
                .get("key_id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            algorithm: k
                .get("algorithm")
                .and_then(|x| x.as_str())
                .unwrap_or("ECDSA-P256")
                .to_string(),
            status: k
                .get("status")
                .and_then(|x| x.as_str())
                .unwrap_or("unknown")
                .to_string(),
            created_at: k
                .get("created_at")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            rotated_from: k
                .get("rotated_from")
                .and_then(|x| x.as_str())
                .map(String::from),
        })
        .collect();

    let active_version = keys
        .iter()
        .find(|k| k.status == "Active")
        .map(|k| k.version);
    let se050_available = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::process::Command::new("ssscli")
            .arg("--version")
            .output(),
    )
    .await
    .ok()
    .and_then(Result::ok)
    .map(|o| o.status.success())
    .unwrap_or(false);
    let active_pub_size = tokio::fs::metadata(&pub_path).await.ok().map(|m| m.len());
    let active_pub_path = if active_pub_size.is_some() {
        Some(pub_path.to_string_lossy().to_string())
    } else {
        None
    };
    let total_versions = keys.len();

    Ok(Json(DkpStatus {
        total_versions,
        active_version,
        se050_available,
        active_pub_path,
        active_pub_size,
        keys,
    }))
}

#[derive(Deserialize)]
pub struct RevokeBody {
    pub version: u32,
    pub reason: Option<String>,
}

#[derive(Deserialize)]
pub struct EmergencyBody {
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ActionResponse {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    #[serde(rename = "restartRequired")]
    pub restart_required: bool,
    pub timestamp: String,
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
    // 1) Respect explicit override if provided.
    if let Ok(override_path) = std::env::var("SGX_PA_CLI_PATH") {
        let p = PathBuf::from(override_path);
        if is_executable_file(&p) {
            return Some(p);
        }
    }

    // 2) Search process PATH (works when service PATH is configured correctly).
    if let Some(p) = find_in_path("sgx-pa-cli") {
        return Some(p);
    }

    // 3) In local dev runs, sgx-pa-cli is commonly a sibling binary in target/{debug,release}.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join("sgx-pa-cli");
            if is_executable_file(&sibling) {
                return Some(sibling);
            }
        }
    }

    // 4) Fall back to common install locations used by packaging/deploy scripts.
    [
        "/usr/local/bin/sgx-pa-cli",
        "/usr/bin/sgx-pa-cli",
        "/bin/sgx-pa-cli",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| is_executable_file(p))
}

pub async fn run_cli(args: &[&str]) -> Result<ActionResponse, ApiError> {
    run_cli_with_env(args, &[]).await
}

pub async fn run_cli_with_env(
    args: &[&str],
    envs: &[(&str, &str)],
) -> Result<ActionResponse, ApiError> {
    let cli_path = resolve_pa_cli_path().ok_or_else(|| {
        let path_env = std::env::var("PATH").unwrap_or_else(|_| "<unset>".to_string());
        eprintln!("sgx-pa-cli not found. PATH={}", path_env);
        ApiError::Internal("sgx-pa-cli not found — check server logs".into())
    })?;

    let mut command = tokio::process::Command::new(&cli_path);
    command.args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    let out = command.output().await.map_err(|e| {
        ApiError::Internal(format!("sgx-pa-cli spawn ({}): {}", cli_path.display(), e))
    })?;
    Ok(ActionResponse {
        success: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        restart_required: true,
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}

pub async fn rotate(State(_): State<Arc<AppState>>) -> Result<Json<ActionResponse>, ApiError> {
    Ok(Json(run_cli(&["dkp-rotate"]).await?))
}

pub async fn revoke(
    State(_): State<Arc<AppState>>,
    Json(b): Json<RevokeBody>,
) -> Result<Json<ActionResponse>, ApiError> {
    let v = b.version.to_string();
    let reason = b.reason.unwrap_or_else(|| "admin revocation".into());
    Ok(Json(
        run_cli(&["dkp-revoke", "--version", &v, "--reason", &reason]).await?,
    ))
}

pub async fn emergency_rotate(
    State(_): State<Arc<AppState>>,
    Json(b): Json<EmergencyBody>,
) -> Result<Json<ActionResponse>, ApiError> {
    let _ = b.reason;
    Ok(Json(run_cli(&["emergency-rotate"]).await?))
}
