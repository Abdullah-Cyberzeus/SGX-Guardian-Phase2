use super::dkp::{run_cli, ActionResponse};
use crate::api::{error::ApiError, state::AppState};
use crate::policy;
use axum::{
    extract::{Multipart, State},
    Json,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

const FALLBACK_POLICY_PATH: &str = "/etc/sgx-guardian/schemas/uep_policy_v1.yaml";
const ACTIVE_POLICY_PREVIEW_CANDIDATES: &[&str] = &[
    // Runtime path used by policy_state/policy_manager.
    crate::policy_state::ACTIVE_POLICY,
    // Preferred: active policy materialized by runtime.
    "/etc/sgx-guardian/policies/active_policy.yaml",
];
const ACTIVE_POLICY_PATH: &str = crate::policy_state::ACTIVE_POLICY;
const BACKUP_POLICY_PATH: &str = crate::policy_state::BACKUP_POLICY;
const PENDING_POLICY_PATH: &str = crate::policy_state::PENDING_POLICY;

/// POST /api/v1/policy/sign
/// multipart fields: `policy` (the YAML file), `key` (the private key PKCS8)
pub async fn sign(
    State(_): State<Arc<AppState>>,
    mut mp: Multipart,
) -> Result<Json<ActionResponse>, ApiError> {
    let tmpdir = tempdir()?;
    let (mut policy_path, mut key_path) = (None, None);
    while let Some(field) = mp
        .next_field()
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?
    {
        let name = field.name().unwrap_or("").to_string();
        let bytes = field
            .bytes()
            .await
            .map_err(|e| ApiError::BadRequest(e.to_string()))?;
        match name.as_str() {
            "policy" => {
                let p = tmpdir.path().join("policy.yaml");
                tokio::fs::write(&p, &bytes).await?;
                policy_path = Some(p);
            }
            "key" => {
                let p = tmpdir.path().join("key.pkcs8");
                tokio::fs::write(&p, &bytes).await?;
                key_path = Some(p);
            }
            _ => {}
        }
    }
    let policy = policy_path.ok_or_else(|| ApiError::BadRequest("missing policy field".into()))?;
    let _ = key_path.take();
    Ok(Json(
        run_cli(&["sign", policy.to_str().unwrap_or("")]).await?,
    ))
}

/// POST /api/v1/policy/verify
/// multipart: `policy` (the .sig file)
pub async fn verify(
    State(_): State<Arc<AppState>>,
    mut mp: Multipart,
) -> Result<Json<ActionResponse>, ApiError> {
    let tmpdir = tempdir()?;
    let mut sig_path = None;
    while let Some(field) = mp
        .next_field()
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?
    {
        if field.name() == Some("policy") {
            let bytes = field
                .bytes()
                .await
                .map_err(|e| ApiError::BadRequest(e.to_string()))?;
            let p = tmpdir.path().join("policy.sig");
            tokio::fs::write(&p, &bytes).await?;
            sig_path = Some(p);
        }
    }
    let sig = sig_path.ok_or_else(|| ApiError::BadRequest("missing policy field".into()))?;
    Ok(Json(
        run_cli(&["verify", "--signed", sig.to_str().unwrap_or("")]).await?,
    ))
}

#[derive(Serialize)]
pub struct CurrentPolicyResponse {
    pub source_path: String,
    pub content: String,
    pub version: String,
    pub updated_at: Option<String>,
}

/// GET /api/v1/policy/current
/// Returns the editable YAML policy used by nodeA admins.
pub async fn current(
    State(_): State<Arc<AppState>>,
) -> Result<Json<CurrentPolicyResponse>, ApiError> {
    let source_path = resolve_active_policy_preview_path();
    let content = tokio::fs::read_to_string(&source_path)
        .await
        .map_err(|e| ApiError::NotFound(format!("failed to read policy file: {}", e)))?;

    let parsed = policy::validate_policy(&content)
        .map_err(|e| ApiError::BadRequest(format!("invalid policy YAML on disk: {}", e)))?;

    let updated_at = tokio::fs::metadata(&source_path)
        .await
        .ok()
        .and_then(|m| m.modified().ok())
        .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339());

    Ok(Json(CurrentPolicyResponse {
        source_path,
        content,
        version: parsed.version,
        updated_at,
    }))
}

#[derive(Deserialize)]
pub struct SavePolicyRequest {
    pub content: String,
}

#[derive(Serialize)]
pub struct SavePolicyResponse {
    pub success: bool,
    pub source_path: String,
    pub version: String,
    pub bytes_written: usize,
    pub updated_at: String,
}

/// PUT /api/v1/policy/current
/// Validates YAML and atomically stages it to pending policy path.
pub async fn save_current(
    State(_): State<Arc<AppState>>,
    Json(body): Json<SavePolicyRequest>,
) -> Result<Json<SavePolicyResponse>, ApiError> {
    let source_path = PENDING_POLICY_PATH.to_string();
    let parsed = policy::validate_policy(&body.content)
        .map_err(|e| ApiError::BadRequest(format!("policy validation failed: {}", e)))?;

    ensure_parent_dir(&source_path)
        .map_err(|e| ApiError::Internal(format!("failed to prepare policy directory: {}", e)))?;

    atomic_write_text(&source_path, &body.content)
        .map_err(|e| ApiError::Internal(format!("failed to stage pending policy: {}", e)))?;

    let updated_at = chrono::Utc::now().to_rfc3339();
    Ok(Json(SavePolicyResponse {
        success: true,
        source_path,
        version: parsed.version,
        bytes_written: body.content.len(),
        updated_at,
    }))
}

/// POST /api/v1/policy/sign-deploy-current
/// Signs and deploys the pending policy to required policy.sig path, then promotes it active.
pub async fn sign_deploy_current(
    State(_): State<Arc<AppState>>,
) -> Result<Json<ActionResponse>, ApiError> {
    let pending_yaml = tokio::fs::read_to_string(PENDING_POLICY_PATH)
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ApiError::BadRequest(format!(
                    "pending policy not found at {}. Save policy edits first.",
                    PENDING_POLICY_PATH
                ))
            } else {
                ApiError::Internal(format!(
                    "failed to read pending policy {}: {}",
                    PENDING_POLICY_PATH, e
                ))
            }
        })?;

    policy::validate_policy(&pending_yaml)
        .map_err(|e| ApiError::BadRequest(format!("pending policy validation failed: {}", e)))?;

    let pending_digest = sha256_hex(pending_yaml.as_bytes());
    let active_digest = read_policy_digest(ACTIVE_POLICY_PATH)
        .map_err(|e| ApiError::Internal(format!("failed to read active policy digest: {}", e)))?;

    let mut backup_rotated = false;
    if active_digest
        .as_ref()
        .is_some_and(|digest| !digest.eq_ignore_ascii_case(&pending_digest))
        && Path::new(ACTIVE_POLICY_PATH).exists()
    {
        atomic_copy_file(ACTIVE_POLICY_PATH, BACKUP_POLICY_PATH).map_err(|e| {
            ApiError::Internal(format!(
                "failed to rotate backup policy ({} -> {}): {}",
                ACTIVE_POLICY_PATH, BACKUP_POLICY_PATH, e
            ))
        })?;
        backup_rotated = true;
    }

    let mut response = run_cli(&["policy-sign-and-deploy", PENDING_POLICY_PATH]).await?;
    if !response.success {
        return Ok(Json(response));
    }

    promote_pending_to_active(PENDING_POLICY_PATH, ACTIVE_POLICY_PATH).map_err(|e| {
        ApiError::Internal(format!(
            "failed to promote pending policy ({} -> {}): {}",
            PENDING_POLICY_PATH, ACTIVE_POLICY_PATH, e
        ))
    })?;

    if backup_rotated {
        response.stdout.push_str(&format!(
            "\nBackup rotated: {} -> {}",
            ACTIVE_POLICY_PATH, BACKUP_POLICY_PATH
        ));
    } else {
        response
            .stdout
            .push_str("\nBackup rotation skipped (no active policy change)");
    }
    response.stdout.push_str(&format!(
        "\nPromoted pending policy: {} -> {}",
        PENDING_POLICY_PATH, ACTIVE_POLICY_PATH
    ));

    Ok(Json(response))
}

fn tempdir() -> std::io::Result<tempfile::TempDir> {
    tempfile::tempdir()
}

fn atomic_write_text(path: &str, content: &str) -> std::io::Result<()> {
    atomic_write_bytes(path, content.as_bytes())
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

fn atomic_copy_file(src_path: &str, dst_path: &str) -> std::io::Result<()> {
    let bytes = std::fs::read(src_path)?;
    atomic_write_bytes(dst_path, &bytes)
}

fn promote_pending_to_active(pending_path: &str, active_path: &str) -> std::io::Result<()> {
    ensure_parent_dir(active_path)?;
    std::fs::rename(pending_path, active_path)?;
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

fn read_policy_digest(path: &str) -> std::io::Result<Option<String>> {
    if !Path::new(path).exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(path)?;
    Ok(Some(sha256_hex(&bytes)))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn resolve_active_policy_preview_path() -> String {
    for path in ACTIVE_POLICY_PREVIEW_CANDIDATES {
        if let Ok(content) = std::fs::read_to_string(path) {
            if policy::validate_policy(&content).is_ok() {
                return (*path).to_string();
            }
        }
    }
    FALLBACK_POLICY_PATH.to_string()
}
