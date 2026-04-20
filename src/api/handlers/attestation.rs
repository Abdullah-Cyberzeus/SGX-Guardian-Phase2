use crate::api::{error::ApiError, state::AppState};
use axum::{extract::State, Json};
use serde::Serialize;
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

pub async fn last(State(s): State<Arc<AppState>>) -> Result<Json<LastAttestation>, ApiError> {
    let primary = format!("{}/last_attestation.json", s.log_dir_primary);
    let fallback = format!("{}/last_attestation.json", s.log_dir_fallback);
    let text = match tokio::fs::read_to_string(&primary).await {
        Ok(t) => t,
        Err(_) => tokio::fs::read_to_string(&fallback)
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
