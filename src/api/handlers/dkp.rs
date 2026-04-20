use crate::api::{error::ApiError, state::AppState};
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
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
    let meta_path = format!("{}/dkp_metadata.json", s.keys_dir);
    let pub_path = format!("{}/dkp_pub.der", s.keys_dir);
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
    let se050_available = std::process::Command::new("ssscli")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let active_pub_size = tokio::fs::metadata(&pub_path).await.ok().map(|m| m.len());
    let active_pub_path = if active_pub_size.is_some() {
        Some(pub_path)
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

#[derive(Serialize)]
pub struct ActionResponse {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    #[serde(rename = "restartRequired")]
    pub restart_required: bool,
    pub timestamp: String,
}

pub async fn run_cli(args: &[&str]) -> Result<ActionResponse, ApiError> {
    let out = tokio::process::Command::new("sgx-pa-cli")
        .args(args)
        .output()
        .await
        .map_err(|e| ApiError::Internal(format!("sgx-pa-cli spawn: {}", e)))?;
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
    let reason = b.reason.unwrap_or_else(|| "emergency rotation".into());
    Ok(Json(
        run_cli(&["emergency-rotate", "--reason", &reason]).await?,
    ))
}
