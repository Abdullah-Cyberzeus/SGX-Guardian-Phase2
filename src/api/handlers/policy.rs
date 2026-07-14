use super::dkp::{run_cli, ActionResponse};
use crate::api::{error::ApiError, state::AppState};
use crate::policy;
use axum::{
    extract::{Multipart, State},
    Json,
};
use serde::{Deserialize, Serialize};
use std::future::Future;
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
const DEPLOYED_POLICY_SIG_PATH: &str = "/etc/sgx-guardian/policies/policy.sig";

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

/// POST /api/v1/policy/verify-deployed
/// Verifies the currently deployed policy signature from disk.
pub async fn verify_deployed(
    State(_): State<Arc<AppState>>,
) -> Result<Json<ActionResponse>, ApiError> {
    if !Path::new(DEPLOYED_POLICY_SIG_PATH).is_file() {
        return Err(ApiError::NotFound(format!(
            "deployed policy signature not found at {}",
            DEPLOYED_POLICY_SIG_PATH
        )));
    }
    Ok(Json(
        run_cli(&["verify", "--signed", DEPLOYED_POLICY_SIG_PATH]).await?,
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
/// GET /api/v1/policy/backup
/// Returns the currently stored backup policy YAML.
pub async fn backup(
    State(_): State<Arc<AppState>>,
) -> Result<Json<CurrentPolicyResponse>, ApiError> {
    let source_path = crate::policy_state::BACKUP_POLICY.to_string();

    let content = tokio::fs::read_to_string(&source_path)
        .await
        .map_err(|e| ApiError::NotFound(format!("failed to read backup policy file: {}", e)))?;

    let parsed = policy::validate_policy(&content)
        .map_err(|e| ApiError::BadRequest(format!("invalid backup policy YAML: {}", e)))?;

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
    let response = sign_deploy_current_with_paths(
        PENDING_POLICY_PATH,
        ACTIVE_POLICY_PATH,
        BACKUP_POLICY_PATH,
        || async { run_cli(&["policy-sign-and-deploy", PENDING_POLICY_PATH]).await },
    )
    .await?;
    Ok(Json(response))
}

async fn sign_deploy_current_with_paths<F, Fut>(
    pending_path: &str,
    active_path: &str,
    backup_path: &str,
    run_sign_and_deploy: F,
) -> Result<ActionResponse, ApiError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<ActionResponse, ApiError>>,
{
    let pending_yaml = tokio::fs::read_to_string(pending_path).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ApiError::BadRequest(format!(
                "pending policy not found at {}. Save policy edits first.",
                pending_path
            ))
        } else {
            ApiError::Internal(format!(
                "failed to read pending policy {}: {}",
                pending_path, e
            ))
        }
    })?;

    let parsed_pending = policy::validate_policy(&pending_yaml)
        .map_err(|e| ApiError::BadRequest(format!("pending policy validation failed: {}", e)))?;
    let pending_digest = policy::canonical_policy_digest(&parsed_pending);

    let active_exists = Path::new(active_path).exists();
    if active_exists {
        let active_yaml = tokio::fs::read_to_string(active_path)
            .await
            .map_err(|e| ApiError::Internal(format!("failed to read active policy: {}", e)))?;
        let parsed_active = policy::validate_policy(&active_yaml)
            .map_err(|e| ApiError::Internal(format!("active policy validation failed: {}", e)))?;
        let active_digest = policy::canonical_policy_digest(&parsed_active);

        if active_digest == pending_digest {
            if let Err(e) = tokio::fs::remove_file(pending_path).await {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(ApiError::Internal(format!(
                        "failed to clean pending policy {}: {}",
                        pending_path, e
                    )));
                }
            }

            return Ok(ActionResponse {
                success: true,
                stdout: "Policy already active; no semantic change. Backup rotation skipped."
                    .to_string(),
                stderr: String::new(),
                restart_required: false,
                timestamp: chrono::Utc::now().to_rfc3339(),
            });
        }
    }

    let mut response = run_sign_and_deploy().await?;
    if !response.success {
        return Ok(response);
    }

    let mut backup_rotated = false;
    if active_exists {
        atomic_copy_file(active_path, backup_path).map_err(|e| {
            ApiError::Internal(format!(
                "failed to rotate backup policy ({} -> {}): {}",
                active_path, backup_path, e
            ))
        })?;
        backup_rotated = true;
    }

    promote_pending_to_active(pending_path, active_path).map_err(|e| {
        ApiError::Internal(format!(
            "failed to promote pending policy ({} -> {}): {}",
            pending_path, active_path, e
        ))
    })?;

    if backup_rotated {
        response.stdout.push_str(&format!(
            "\nBackup rotated: {} -> {}",
            active_path, backup_path
        ));
    } else {
        response
            .stdout
            .push_str("\nBackup rotation skipped (no active policy change)");
    }
    response.stdout.push_str(&format!(
        "\nPromoted pending policy: {} -> {}",
        pending_path, active_path
    ));

    Ok(response)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    const ACTIVE_POLICY_YAML: &str = r#"policy_id: "alpha"
version: "1.0.0"
rules:
  - id: "allow-all"
    action: "ALLOW"
    src: "0.0.0.0/0"
    dst: "0.0.0.0/0"
    protocol: "ALL"
"#;

    const BACKUP_POLICY_YAML: &str = r#"policy_id: "previous"
version: "0.9.0"
rules:
  - id: "deny-tcp"
    action: "DENY"
    src: "10.0.0.0/8"
    dst: "10.0.0.0/8"
    protocol: "TCP"
"#;

    fn cli_response(success: bool) -> ActionResponse {
        ActionResponse {
            success,
            stdout: "policy-sign-and-deploy".to_string(),
            stderr: if success {
                String::new()
            } else {
                "deploy failed".to_string()
            },
            restart_required: true,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    #[tokio::test]
    async fn same_policy_with_extra_newline_is_noop() {
        let td = tempfile::tempdir().expect("tempdir");
        let active_path = td.path().join("active_policy.yaml");
        let backup_path = td.path().join("backup_policy.yaml");
        let pending_path = td.path().join("pending_policy.yaml");

        std::fs::write(&active_path, ACTIVE_POLICY_YAML).expect("write active");
        std::fs::write(&backup_path, BACKUP_POLICY_YAML).expect("write backup");
        std::fs::write(&pending_path, format!("{}\n", ACTIVE_POLICY_YAML)).expect("write pending");

        let cli_calls = Arc::new(AtomicUsize::new(0));
        let cli_calls_cloned = Arc::clone(&cli_calls);
        let response = sign_deploy_current_with_paths(
            pending_path.to_str().unwrap_or(""),
            active_path.to_str().unwrap_or(""),
            backup_path.to_str().unwrap_or(""),
            move || {
                let cli_calls = Arc::clone(&cli_calls_cloned);
                async move {
                    cli_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(cli_response(true))
                }
            },
        )
        .await
        .expect("no-op should succeed");

        assert!(response.success);
        assert!(!response.restart_required);
        assert_eq!(
            response.stdout,
            "Policy already active; no semantic change. Backup rotation skipped."
        );
        assert_eq!(cli_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            std::fs::read_to_string(&active_path).expect("read active"),
            ACTIVE_POLICY_YAML
        );
        assert_eq!(
            std::fs::read_to_string(&backup_path).expect("read backup"),
            BACKUP_POLICY_YAML
        );
        assert!(
            !pending_path.exists(),
            "pending should be cleaned after no-op"
        );
    }

    #[tokio::test]
    async fn same_policy_with_whitespace_only_changes_does_not_rotate_backup() {
        let td = tempfile::tempdir().expect("tempdir");
        let active_path = td.path().join("active_policy.yaml");
        let backup_path = td.path().join("backup_policy.yaml");
        let pending_path = td.path().join("pending_policy.yaml");

        let pending_yaml = r#"policy_id: "alpha"   
version: "1.0.0"
rules:

  - id: "allow-all"
    action: "ALLOW"
    src: "0.0.0.0/0"
    dst: "0.0.0.0/0"
    protocol: "ALL"

"#;

        std::fs::write(&active_path, ACTIVE_POLICY_YAML).expect("write active");
        std::fs::write(&backup_path, BACKUP_POLICY_YAML).expect("write backup");
        std::fs::write(&pending_path, pending_yaml).expect("write pending");

        let response = sign_deploy_current_with_paths(
            pending_path.to_str().unwrap_or(""),
            active_path.to_str().unwrap_or(""),
            backup_path.to_str().unwrap_or(""),
            || async { Ok(cli_response(true)) },
        )
        .await
        .expect("no-op should succeed");

        assert!(response.success);
        assert_eq!(
            std::fs::read_to_string(&backup_path).expect("read backup"),
            BACKUP_POLICY_YAML
        );
        assert_eq!(
            std::fs::read_to_string(&active_path).expect("read active"),
            ACTIVE_POLICY_YAML
        );
        assert!(
            !pending_path.exists(),
            "pending should be cleaned after no-op"
        );
    }

    #[tokio::test]
    async fn changed_policy_rotates_backup_and_promotes_pending() {
        let td = tempfile::tempdir().expect("tempdir");
        let active_path = td.path().join("active_policy.yaml");
        let backup_path = td.path().join("backup_policy.yaml");
        let pending_path = td.path().join("pending_policy.yaml");

        let pending_yaml = r#"policy_id: "alpha"
version: "2.0.0"
rules:
  - id: "allow-all"
    action: "ALLOW"
    src: "0.0.0.0/0"
    dst: "0.0.0.0/0"
    protocol: "ALL"
  - id: "deny-http"
    action: "DENY"
    src: "0.0.0.0/0"
    dst: "10.10.0.0/16"
    protocol: "TCP"
    port: 80
"#;

        std::fs::write(&active_path, ACTIVE_POLICY_YAML).expect("write active");
        std::fs::write(&backup_path, BACKUP_POLICY_YAML).expect("write backup");
        std::fs::write(&pending_path, pending_yaml).expect("write pending");

        let response = sign_deploy_current_with_paths(
            pending_path.to_str().unwrap_or(""),
            active_path.to_str().unwrap_or(""),
            backup_path.to_str().unwrap_or(""),
            || async { Ok(cli_response(true)) },
        )
        .await
        .expect("deploy should succeed");

        assert!(response.success);
        assert_eq!(
            std::fs::read_to_string(&backup_path).expect("read backup"),
            ACTIVE_POLICY_YAML
        );
        assert_eq!(
            std::fs::read_to_string(&active_path).expect("read active"),
            pending_yaml
        );
        assert!(!pending_path.exists(), "pending should be promoted");
    }

    #[tokio::test]
    async fn cli_failure_keeps_active_and_backup_unchanged() {
        let td = tempfile::tempdir().expect("tempdir");
        let active_path = td.path().join("active_policy.yaml");
        let backup_path = td.path().join("backup_policy.yaml");
        let pending_path = td.path().join("pending_policy.yaml");

        let pending_yaml = r#"policy_id: "alpha"
version: "2.1.0"
rules:
  - id: "deny-ssh"
    action: "DENY"
    src: "0.0.0.0/0"
    dst: "10.20.0.0/16"
    protocol: "TCP"
    port: 22
"#;

        std::fs::write(&active_path, ACTIVE_POLICY_YAML).expect("write active");
        std::fs::write(&backup_path, BACKUP_POLICY_YAML).expect("write backup");
        std::fs::write(&pending_path, pending_yaml).expect("write pending");

        let response = sign_deploy_current_with_paths(
            pending_path.to_str().unwrap_or(""),
            active_path.to_str().unwrap_or(""),
            backup_path.to_str().unwrap_or(""),
            || async { Ok(cli_response(false)) },
        )
        .await
        .expect("handler should return CLI response");

        assert!(!response.success);
        assert_eq!(
            std::fs::read_to_string(&active_path).expect("read active"),
            ACTIVE_POLICY_YAML
        );
        assert_eq!(
            std::fs::read_to_string(&backup_path).expect("read backup"),
            BACKUP_POLICY_YAML
        );
        assert_eq!(
            std::fs::read_to_string(&pending_path).expect("read pending"),
            pending_yaml
        );
    }
}
