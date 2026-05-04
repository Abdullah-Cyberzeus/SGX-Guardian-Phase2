use crate::api::{error::ApiError, state::AppState};
use axum::{extract::State, Json};
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
pub struct Peer {
    #[serde(rename = "peerId")]
    pub peer_id: String,
    pub ip: String,
    pub status: String,
    #[serde(rename = "lastSeen")]
    pub last_seen: String,
}

#[derive(Serialize)]
pub struct PeersResponse {
    pub peers: Vec<Peer>,
    pub total: usize,
    pub timestamp: String,
}

async fn safe_read(filename: &str, base_dir: &str) -> Option<String> {
    let base = std::path::Path::new(base_dir).canonicalize().ok()?;
    let path = base.join(filename);
    let resolved = path.canonicalize().ok()?;
    if !resolved.starts_with(&base) {
        return None;
    }
    tokio::fs::read_to_string(resolved).await.ok()
}

pub async fn list(State(s): State<Arc<AppState>>) -> Result<Json<PeersResponse>, ApiError> {
    let text = match safe_read("trusted_peers.json", &s.log_dir_primary).await {
        Some(t) => t,
        None => safe_read("trusted_peers.json", &s.log_dir_fallback)
            .await
            .unwrap_or_else(|| "[]".into()),
    };
    let raw: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap_or_default();
    let peers: Vec<Peer> = raw
        .into_iter()
        .map(|v| Peer {
            peer_id: v
                .get("peer_id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            ip: v
                .get("ip")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            status: v
                .get("status")
                .and_then(|x| x.as_str())
                .unwrap_or("unknown")
                .to_string(),
            last_seen: v
                .get("timestamp")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
        })
        .collect();
    let total = peers.len();
    Ok(Json(PeersResponse {
        peers,
        total,
        timestamp: chrono::Utc::now().to_rfc3339(),
    }))
}
