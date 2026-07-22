use crate::api::{error::ApiError, state::AppState};
use axum::{extract::State, Json};
use serde::Serialize;
use std::path::Path;
use std::sync::Arc;

#[derive(Serialize)]
pub struct LastAttestation {
    #[serde(rename = "peerId")]
    pub peer_id: String,
    #[serde(rename = "policyDigest")]
    pub policy_digest: String,
    pub result: String,
    pub timestamp: String,
}

/// Read a JSON file from a base directory with path-traversal protection.
async fn read_json_from_dir(base_dir: &str, filename: &str) -> Result<String, ApiError> {
    let base = tokio::fs::canonicalize(Path::new(base_dir))
        .await
        .map_err(|_| ApiError::NotFound("directory not found".into()))?;
    let candidate = base.join(filename);
    let resolved = tokio::fs::canonicalize(&candidate)
        .await
        .map_err(|_| ApiError::NotFound("file not found".into()))?;
    if !resolved.starts_with(&base) {
        return Err(ApiError::NotFound("path traversal blocked".into()));
    }
    tokio::fs::read_to_string(&resolved)
        .await
        .map_err(|_| ApiError::NotFound("file unreadable".into()))
}

pub async fn last(State(s): State<Arc<AppState>>) -> Result<Json<LastAttestation>, ApiError> {
    let text = match read_json_from_dir(&s.log_dir_primary, "last_attestation.json").await {
        Ok(t) => t,
        Err(_) => read_json_from_dir(&s.log_dir_fallback, "last_attestation.json")
            .await
            .map_err(|_| ApiError::NotFound("no attestation result recorded yet".into()))?,
    };
    let v: serde_json::Value = serde_json::from_str(&text)?;
    Ok(Json(LastAttestation {
        peer_id: v
            .get("peer_id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        policy_digest: v
            .get("policy_digest")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        result: v
            .get("result")
            .and_then(|x| x.as_str())
            .unwrap_or("unknown")
            .to_string(),
        timestamp: v
            .get("timestamp")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
    }))
}
