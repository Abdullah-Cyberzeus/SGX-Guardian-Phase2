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
    #[serde(rename = "callAvailable")]
    pub call_available: bool,
    #[serde(
        rename = "callUnavailableReason",
        skip_serializing_if = "Option::is_none"
    )]
    pub call_unavailable_reason: Option<String>,
    pub online: bool,
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

async fn call_peer_online(ip: &str) -> bool {
    let signaling_port = std::env::var("SGX_CALL_SIGNALING_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(50065);
    let address = format!("{}:{}", ip, signaling_port);
    for attempt in 0..3 {
        let connected = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::net::TcpStream::connect(&address),
        )
        .await
        .is_ok_and(|result| result.is_ok());
        if connected {
            return true;
        }
        if attempt < 2 {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
    }
    false
}

pub async fn list(State(s): State<Arc<AppState>>) -> Result<Json<PeersResponse>, ApiError> {
    let text = match safe_read("trusted_peers.json", &s.log_dir_primary).await {
        Some(t) => t,
        None => safe_read("trusted_peers.json", &s.log_dir_fallback)
            .await
            .unwrap_or_else(|| "[]".into()),
    };
    let raw: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap_or_default();
    let candidates: Vec<(serde_json::Value, String)> = raw
        .into_iter()
        .filter_map(|v| {
            let peer_id = v
                .get("peer_id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let has_attested_identity = v
                .get("virtual_id")
                .and_then(|x| x.as_str())
                .is_some_and(|value| !value.trim().is_empty());
            (peer_id != s.node_id && has_attested_identity).then_some((v, peer_id))
        })
        .collect();
    let peers: Vec<Peer> =
        futures_util::future::join_all(candidates.into_iter().map(|(v, peer_id)| async move {
            let ip = v
                .get("ip")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let status = v
                .get("status")
                .and_then(|x| x.as_str())
                .unwrap_or("unknown")
                .to_string();
            let has_virtual_id = v
                .get("virtual_id")
                .and_then(|x| x.as_str())
                .is_some_and(|value| !value.trim().is_empty());
            let trusted = matches!(status.as_str(), "verified" | "trusted" | "success");
            let valid_ip = ip.parse::<std::net::IpAddr>().is_ok();
            let online = if valid_ip && trusted && has_virtual_id {
                call_peer_online(&ip).await
            } else {
                false
            };
            let call_unavailable_reason = if !trusted {
                Some("Peer is not currently trusted".to_string())
            } else if !valid_ip {
                Some("Peer registry has no plain Nebula IP address".to_string())
            } else if !has_virtual_id {
                Some("Peer registry has no attested VirtualID".to_string())
            } else if !online {
                Some("Peer is offline on the Nebula call network".to_string())
            } else {
                None
            };
            Peer {
                peer_id,
                ip,
                status,
                last_seen: v
                    .get("timestamp")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                call_available: call_unavailable_reason.is_none(),
                call_unavailable_reason,
                online,
            }
        }))
        .await;
    let total = peers.len();
    Ok(Json(PeersResponse {
        peers,
        total,
        timestamp: chrono::Utc::now().to_rfc3339(),
    }))
}
