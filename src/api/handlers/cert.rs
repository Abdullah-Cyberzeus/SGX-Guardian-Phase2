use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::cert_service::{ApprovalDecision, CertRequestYaml};
use axum::{
    Json,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertRequestInfo {
    pub node_id: String,
    pub requested_at: String,
    pub overlay_ip: String,
    pub public_key_fingerprint: String,
    pub requested_role: String,
    pub approve: String,
}

#[derive(Debug, Deserialize)]
pub struct ApproveRequestPayload {
    pub node_id: String,
    pub decision: String, // "false", "member", "lighthouse", "relay", "lh_relay"
}

fn get_nebula_base_dir() -> String {
    std::env::var("SGX_NEBULA_DIR").unwrap_or("/var/lib/sgx-guardian/nebula".to_string())
}

fn read_requests() -> Vec<CertRequestInfo> {
    let requests_dir = format!("{}/requests", get_nebula_base_dir());
    let mut list = Vec::new();
    if let Ok(entries) = fs::read_dir(requests_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.extension().map(|s| s == "yaml").unwrap_or(false) {
                continue;
            }
            let Ok(content) = fs::read_to_string(&path) else {
                continue;
            };
            let Ok(yaml) = serde_yaml::from_str::<CertRequestYaml>(&content) else {
                continue;
            };
            let approve = match yaml.approve {
                ApprovalDecision::False => "false",
                ApprovalDecision::Member => "member",
                ApprovalDecision::Lighthouse => "lighthouse",
                ApprovalDecision::Relay => "relay",
                ApprovalDecision::LhRelay => "lh_relay",
            };
            list.push(CertRequestInfo {
                node_id: yaml.node_id,
                requested_at: yaml.requested_at,
                overlay_ip: yaml.overlay_ip,
                public_key_fingerprint: yaml.public_key_fingerprint,
                requested_role: yaml.requested_role,
                approve: approve.to_string(),
            });
        }
    }
    list.sort_by(|a, b| a.requested_at.cmp(&b.requested_at));
    list
}

/// GET /api/v1/cert/requests
pub async fn list_requests(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<Vec<CertRequestInfo>>, ApiError> {
    Ok(Json(read_requests()))
}

/// GET /api/v1/cert/requests/ws
/// Sends an initial snapshot and another snapshot whenever the request files change.
pub async fn requests_socket(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(run_requests_socket)
}

async fn run_requests_socket(socket: WebSocket) {
    let (mut sender, mut receiver) = socket.split();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
    let mut previous = String::new();
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let requests = read_requests();
                let Ok(serialized) = serde_json::to_string(&requests) else { continue };
                if serialized == previous { continue; }
                previous = serialized;
                let payload = serde_json::json!({
                    "type": "cert.requests.snapshot",
                    "requests": requests,
                }).to_string();
                if sender.send(Message::Text(payload.into())).await.is_err() { break; }
            }
            incoming = receiver.next() => match incoming {
                Some(Ok(Message::Ping(bytes))) => {
                    if sender.send(Message::Pong(bytes)).await.is_err() { break; }
                }
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                _ => {}
            }
        }
    }
}

/// POST /api/v1/cert/approve
pub async fn approve_request(
    State(_state): State<Arc<AppState>>,
    Json(payload): Json<ApproveRequestPayload>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Validate node_id to prevent path traversal
    if payload.node_id.is_empty()
        || payload.node_id.contains('/')
        || payload.node_id.contains('\\')
        || payload.node_id.contains("..")
    {
        return Err(ApiError::BadRequest("Invalid node_id".to_string()));
    }

    let decision = match payload.decision.trim().to_ascii_lowercase().as_str() {
        "false" | "reject" | "deny" | "no" => ApprovalDecision::False,
        "member" => ApprovalDecision::Member,
        "lighthouse" | "lh" => ApprovalDecision::Lighthouse,
        "relay" => ApprovalDecision::Relay,
        "lh_relay" | "lhrelay" | "relay_lh" => ApprovalDecision::LhRelay,
        _ => return Err(ApiError::BadRequest(
            "Invalid decision. Must be one of: reject/false, member, lighthouse, relay, lh_relay"
                .to_string(),
        )),
    };

    let base_dir = get_nebula_base_dir();
    let yaml_path = format!("{}/requests/{}.yaml", base_dir, payload.node_id);

    if !std::path::Path::new(&yaml_path).exists() {
        return Err(ApiError::NotFound(format!(
            "Request for node {} not found",
            payload.node_id
        )));
    }

    let content = fs::read_to_string(&yaml_path)
        .map_err(|e| ApiError::Internal(format!("Failed to read request file: {}", e)))?;

    let mut yaml: CertRequestYaml = serde_yaml::from_str(&content)
        .map_err(|e| ApiError::Internal(format!("Failed to parse request file: {}", e)))?;

    yaml.approve = decision;

    let updated_content = serde_yaml::to_string(&yaml)
        .map_err(|e| ApiError::Internal(format!("Failed to serialize request file: {}", e)))?;

    fs::write(&yaml_path, updated_content)
        .map_err(|e| ApiError::Internal(format!("Failed to write request file: {}", e)))?;

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": format!("Request for node {} set to {:?}", payload.node_id, decision)
    })))
}
