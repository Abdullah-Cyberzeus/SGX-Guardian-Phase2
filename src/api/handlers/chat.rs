use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::chat::models::{ChatMessageRecord, MessageStatus};
use axum::extract::{
    ws::{Message, WebSocket, WebSocketUpgrade},
    Json, Query, State,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

fn get_grpc_addr(ip: &str, peer_id_str: &str) -> String {
    let parsed_port = peer_id_str
        .split(':')
        .nth(1)
        .and_then(|p| p.parse::<u16>().ok());

    let chat_port = match parsed_port {
        Some(port) if (50051..=50099).contains(&port) => port + 200,
        Some(port) if (50151..=50199).contains(&port) => port + 100,
        Some(port) if (50251..=50299).contains(&port) => port,
        Some(port) => port + 100,
        None => match peer_id_str {
            "nodeA" => 50251,
            "nodeB" => 50252,
            "nodeC" => 50253,
            _ => {
                if let Some(last_octet) = ip.split('.').last().and_then(|s| s.parse::<u16>().ok()) {
                    if (1..=9).contains(&last_octet) {
                        50250 + last_octet
                    } else {
                        50251
                    }
                } else {
                    50251
                }
            }
        },
    };
    format!("{}:{}", ip, chat_port)
}

/// Returns the local Nebula overlay IP (from the `nebula0` interface), or None if not found.
/// Used to detect corrupted registry entries where a peer's DID is stored with our own IP.
fn get_local_nebula_ip() -> Option<String> {
    use std::net::IpAddr;
    // Try reading from the Nebula overlay registry first
    let reg_path = "/var/lib/sgx-guardian/nebula/overlay_registry.json";
    let node_id = std::env::args().nth(1).unwrap_or_default();
    if !node_id.is_empty() {
        if let Ok(json) = std::fs::read_to_string(reg_path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json) {
                if let Some(ip) = val.get(&node_id).and_then(|v| v.as_str()) {
                    // Strip CIDR suffix if present (e.g., "192.168.100.1/24" -> "192.168.100.1")
                    let ip_only = ip.split('/').next().unwrap_or(ip);
                    if ip_only.parse::<IpAddr>().is_ok() {
                        return Some(ip_only.to_string());
                    }
                }
            }
        }
    }
    // Fallback: run `ip -4 addr show nebula0` and parse the inet line
    if let Ok(output) = std::process::Command::new("ip")
        .args(["-4", "addr", "show", "nebula0"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with("inet ") {
                // e.g. "inet 192.168.100.1/24 scope global nebula0"
                if let Some(addr) = line.split_whitespace().nth(1) {
                    let ip_only = addr.split('/').next().unwrap_or(addr);
                    if ip_only.parse::<IpAddr>().is_ok() {
                        return Some(ip_only.to_string());
                    }
                }
            }
        }
    }
    None
}

#[derive(Deserialize)]
pub struct SendMessageRequest {
    pub recipient_did: String,
    pub content: Option<String>,
    pub attachment_id: Option<String>,
    pub is_group: bool,
}

#[derive(Serialize)]
pub struct SendMessageResponse {
    pub message_id: String,
    pub signature_base64: String,
    pub status: String,
}

pub async fn send_message(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SendMessageRequest>,
) -> Result<Json<SendMessageResponse>, ApiError> {
    // 1. Validate payload
    if req.content.is_none() && req.attachment_id.is_none() {
        return Err(ApiError::BadRequest(
            "Message must contain either content or an attachment".to_string(),
        ));
    }

    // 1b. Validate Attestation Status & Determine Target IPs
    let mut target_peers_info: Vec<(String, String)> = Vec::new();

    // Read from BOTH the global trusted_peers.json AND the per-node
    // trusted_peers_<node>.json. The per-node file keeps ALL attested DIDs
    // (including multiple DIDs for the same overlay IP), while the global
    // merged file may drop duplicates when deduplicating by peer_id.
    let node_id_for_file = state.node_id.clone();
    let per_node_name = format!("trusted_peers_{}.json", node_id_for_file);

    let global_path = std::path::Path::new(&state.log_dir_primary).join("trusted_peers.json");
    let pernode_path = std::path::Path::new(&state.log_dir_primary).join(&per_node_name);

    let global_json = tokio::fs::read_to_string(&global_path)
        .await
        .unwrap_or_else(|_| "[]".to_string());
    let pernode_json = tokio::fs::read_to_string(&pernode_path)
        .await
        .unwrap_or_else(|_| "[]".to_string());

    let mut global_peers: Vec<serde_json::Value> =
        serde_json::from_str(&global_json).unwrap_or_default();
    let pernode_peers: Vec<serde_json::Value> =
        serde_json::from_str(&pernode_json).unwrap_or_default();

    // Merge per-node entries: add any peer whose DID is not already in global list.
    for p in pernode_peers {
        let p_did = p
            .get("did")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if p_did.is_empty() {
            continue;
        }
        let already = global_peers
            .iter()
            .any(|g| g.get("did").and_then(|v| v.as_str()).unwrap_or("") == p_did.as_str());
        if !already {
            global_peers.push(p);
        }
    }
    let raw_peers = global_peers;

    if raw_peers.is_empty() {
        eprintln!(
            "❌ Chat: no trusted peers found (checked {} and {})",
            global_path.display(),
            pernode_path.display()
        );
    } else {
        eprintln!("💬 Chat: {} peers in trusted registry", raw_peers.len());
        for p in &raw_peers {
            eprintln!(
                "  → peer_id={} ip={} status={} did={}",
                p.get("peer_id").and_then(|v| v.as_str()).unwrap_or("?"),
                p.get("ip").and_then(|v| v.as_str()).unwrap_or("?"),
                p.get("status").and_then(|v| v.as_str()).unwrap_or("?"),
                p.get("did").and_then(|v| v.as_str()).unwrap_or("null"),
            );
        }
    }

    if req.is_group {
        // Group Chat: Full-Mesh Fan-Out to ALL trusted peers
        for p in raw_peers.iter() {
            let status = p.get("status").and_then(|v| v.as_str());
            if status == Some("trusted") || status == Some("verified") {
                let did_val = p
                    .get("did")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| {
                        p.get("peer_id")
                            .and_then(|v| v.as_str())
                            .map(|s| format!("did:guardian:{}", s))
                    });
                let ip_str = p.get("ip").and_then(|v| v.as_str());
                let peer_id_str = p.get("peer_id").and_then(|v| v.as_str()).unwrap_or("");

                if let (Some(did), Some(ip_str)) = (did_val, ip_str) {
                    if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                        let target_addr = get_grpc_addr(&ip.to_string(), peer_id_str);
                        target_peers_info.push((did, target_addr));
                    }
                }
            }
        }
        if target_peers_info.is_empty() {
            return Err(ApiError::Forbidden(
                "No trusted peers found in the circle for group fan-out".to_string(),
            ));
        }
    } else {
        // P2P Chat: Find the specific trusted peer.
        // Match by full DID string OR by the base58 key suffix OR by peer_id.
        let target_peer_id = req
            .recipient_did
            .strip_prefix("did:guardian:")
            .unwrap_or(&req.recipient_did);
        let target_peer = raw_peers.iter().find(|p| {
            let status = p.get("status").and_then(|v| v.as_str());
            let is_trusted = status == Some("trusted") || status == Some("verified");
            let peer_did = p.get("did").and_then(|v| v.as_str()).unwrap_or("");
            let peer_id = p.get("peer_id").and_then(|v| v.as_str()).unwrap_or("");
            // Match full DID, or the key suffix, or the plain peer_id label
            let matches = peer_did == req.recipient_did.as_str()
                || peer_did == target_peer_id
                || peer_id == target_peer_id
                || peer_id == req.recipient_did.as_str();
            is_trusted && matches
        });

        if let Some(peer) = target_peer {
            let ip_str = peer
                .get("ip")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ApiError::Internal("Peer has no IP address".into()))?;

            // Guard: never route to our own overlay IP — that means the registry
            // has a stale entry where the peer's DID was saved with our own IP.
            let local_overlay_ip = get_local_nebula_ip();
            if let Some(ref local_ip) = local_overlay_ip {
                if ip_str == local_ip.as_str() {
                    eprintln!(
                        "❌ Chat: registry entry for {} points to our own IP {} — stale entry, skipping",
                        req.recipient_did, ip_str
                    );
                    return Err(ApiError::Forbidden(format!(
                        "Peer registry entry for {} is stale (points to local node IP {}). \
                         Please wait for a fresh attestation round to update the peer's IP.",
                        req.recipient_did, ip_str
                    )));
                }
            }

            let ip = ip_str
                .parse::<std::net::IpAddr>()
                .map_err(|_| ApiError::Internal(format!("Peer has invalid IP: {}", ip_str)))?;
            let peer_id_str = peer.get("peer_id").and_then(|v| v.as_str()).unwrap_or("");
            let target_addr = get_grpc_addr(&ip.to_string(), peer_id_str);
            eprintln!("💬 Chat: target peer found — sending to {}", target_addr);
            target_peers_info.push((req.recipient_did.clone(), target_addr));
        } else {
            eprintln!(
                "❌ Chat: peer not found or not trusted for recipient={}",
                req.recipient_did
            );
            return Err(ApiError::Forbidden(format!(
                "Recipient {} has not passed mutual attestation or is not in the trusted circle",
                req.recipient_did
            )));
        }
    }

    // 2. Generate UUID and current timestamp
    let message_id = Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().timestamp();
    let sender_did = state.device_did.clone();

    // 3. Determine seq_no
    let mut seq_no = 1u64;
    if req.is_group {
        if let Ok(history) = crate::chat::storage::read_group_history(&req.recipient_did).await {
            seq_no = history.iter().map(|m| m.seq_no).max().unwrap_or(0) + 1;
        }
    } else if let Ok(history) = crate::chat::storage::read_p2p_history(&req.recipient_did).await {
        seq_no = history.iter().map(|m| m.seq_no).max().unwrap_or(0) + 1;
    }

    // 4. Save outbound message locally (plaintext JSON, no encryption)
    let payload_obj = serde_json::json!({
        "content": req.content,
        "attachment_id": req.attachment_id,
    });
    let content_str = serde_json::to_string(&payload_obj).unwrap_or_default();
    let group_id_opt = if req.is_group {
        Some(req.recipient_did.clone())
    } else {
        None
    };

    let record = ChatMessageRecord {
        message_id: message_id.clone(),
        sender_did: sender_did.clone(),
        recipient_did: req.recipient_did.clone(),
        group_id: group_id_opt.clone(),
        timestamp,
        seq_no,
        encrypted_payload: content_str.clone(), // field name kept for schema compat
        signature: String::new(),
        status: MessageStatus::Pending,
        read_by: Vec::new(),
    };

    if req.is_group {
        crate::chat::storage::append_group_message(&req.recipient_did, &record)
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to save group message: {}", e)))?;
    } else {
        crate::chat::storage::append_p2p_message(&req.recipient_did, &record)
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to save p2p message: {}", e)))?;
    }

    // 5. Dispatch gRPC push in background (Nebula overlay already provides E2E security)
    let message_id_clone = message_id.clone();
    let sender_did_clone = sender_did.clone();
    let is_group = req.is_group;
    let group_id_str = if is_group {
        req.recipient_did.clone()
    } else {
        String::new()
    };
    tokio::spawn(async move {
        for (recipient_did, target_addr) in target_peers_info {
            let msg_id = message_id_clone.clone();
            let snd_did = sender_did_clone.clone();
            let rec_did = recipient_did.clone();
            let content = content_str.clone();
            let addr = target_addr.clone();
            let g_id = group_id_str.clone();

            tokio::spawn(async move {
                let grpc_req = crate::proto::sgx::PushMessageRequest {
                    message_id: msg_id,
                    sender_did: snd_did,
                    recipient_did: rec_did,
                    timestamp,
                    seq_no,
                    encrypted_payload: content, // plain text over Nebula-secured channel
                    signature: String::new(),
                    group_id: g_id,
                };

                match crate::chat::grpc_client::push_message_to_peer(addr.clone(), grpc_req).await {
                    Ok(()) => println!("💬 ✅ Message delivered to {}", addr),
                    Err(e) => eprintln!("❌ Chat delivery failed to {}: {}", addr, e),
                }
            });
        }
    });

    // 6. Respond immediately — message queued for delivery
    Ok(Json(SendMessageResponse {
        message_id,
        signature_base64: String::new(),
        status: "queued".to_string(),
    }))
}

#[derive(Deserialize)]
pub struct MarkReadRequest {
    pub message_id: String,
    pub original_sender_did: String,
    pub group_id: Option<String>,
}

#[derive(Serialize)]
pub struct MarkReadResponse {
    pub message_id: String,
    pub status: String,
}

/// Task 5.3: API endpoint called by the UI when a user views a message
pub async fn mark_as_read(
    State(state): State<Arc<AppState>>,
    Json(req): Json<MarkReadRequest>,
) -> Result<Json<MarkReadResponse>, ApiError> {
    // Peers are authorised by DID. Transport confidentiality and endpoint
    // authentication are supplied by the Nebula overlay.
    let reader_did = state.device_did.clone();
    let timestamp = chrono::Utc::now().timestamp();

    // 1. Verify the message exists
    if let Some(ref gid) = req.group_id {
        if let Ok(history) = crate::chat::storage::read_group_history(gid).await {
            if !history.iter().any(|m| m.message_id == req.message_id) {
                return Err(ApiError::BadRequest(
                    "Message not found in group history".to_string(),
                ));
            }
        } else {
            return Err(ApiError::BadRequest(
                "Group conversation history not found".to_string(),
            ));
        }
    } else if let Ok(history) =
        crate::chat::storage::read_p2p_history(&req.original_sender_did).await
    {
        if !history.iter().any(|m| m.message_id == req.message_id) {
            return Err(ApiError::BadRequest(
                "Message not found in conversation history".to_string(),
            ));
        }
    } else {
        return Err(ApiError::BadRequest(
            "Conversation history not found".to_string(),
        ));
    }

    // 2. Log the receipt locally
    let receipt = crate::chat::models::ReadReceiptRecord {
        message_id: req.message_id.clone(),
        reader_did: reader_did.clone(),
        group_id: req.group_id.clone(),
        read_at: timestamp,
    };

    crate::chat::storage::append_read_receipt(&receipt)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to save read receipt: {}", e)))?;

    // Also update read_by in local storage file for this node
    let is_group = req.group_id.is_some();
    let target_file_id = req.group_id.as_deref().unwrap_or(&req.original_sender_did);
    let _ = crate::chat::storage::update_message_read_by(
        is_group,
        target_file_id,
        &req.message_id,
        &reader_did,
    )
    .await;

    // 3. Fetch peer IP to notify original sender
    let peers_path = std::path::Path::new(&state.log_dir_primary).join("trusted_peers.json");
    let peers_json = tokio::fs::read_to_string(&peers_path)
        .await
        .unwrap_or_else(|_| "[]".to_string());
    let raw_peers: Vec<serde_json::Value> = serde_json::from_str(&peers_json).unwrap_or_default();

    let target_peer = raw_peers.iter().find(|p| {
        let status = p.get("status").and_then(|v| v.as_str());
        let is_trusted = status == Some("trusted") || status == Some("verified");
        let matches_did = p.get("did").and_then(|v| v.as_str())
            == Some(req.original_sender_did.as_str())
            || p.get("peer_id").and_then(|v| v.as_str())
                == Some(
                    req.original_sender_did
                        .strip_prefix("did:guardian:")
                        .unwrap_or(&req.original_sender_did),
                );
        is_trusted && matches_did
    });

    if let Some(peer) = target_peer {
        let peer_ip = peer
            .get("ip")
            .and_then(|v| v.as_str())
            .unwrap_or("127.0.0.1")
            .to_string();
        let peer_id_str = peer.get("peer_id").and_then(|v| v.as_str()).unwrap_or("");
        let target_addr = get_grpc_addr(&peer_ip, peer_id_str);

        let grpc_req = crate::proto::sgx::PushReceiptRequest {
            message_id: req.message_id.clone(),
            reader_did: reader_did.clone(),
            timestamp,
            group_id: req.group_id.clone().unwrap_or_default(),
        };

        let peer_did = req.original_sender_did.clone();

        // 4. Dispatch via gRPC in the background
        tokio::spawn(async move {
            if let Err(e) = crate::chat::grpc_client::push_receipt_to_peer(
                peer_did,
                target_addr.clone(),
                grpc_req,
            )
            .await
            {
                tracing::error!("Failed to push receipt to peer {}: {}", target_addr, e);
            }
        });
    }

    Ok(Json(MarkReadResponse {
        message_id: req.message_id,
        status: "read_logged".to_string(),
    }))
}

#[derive(Serialize)]
pub struct SyncResponse {
    pub status: String,
    pub peers_synced: usize,
}

/// Task 6.5: Auto-trigger endpoint called by UI on reconnect or boot
pub async fn trigger_sync(
    State(state): State<Arc<AppState>>,
) -> Result<Json<SyncResponse>, ApiError> {
    let peers_path = std::path::Path::new(&state.log_dir_primary).join("trusted_peers.json");
    let peers_json = tokio::fs::read_to_string(&peers_path)
        .await
        .unwrap_or_else(|_| "[]".to_string());
    let raw_peers: Vec<serde_json::Value> = serde_json::from_str(&peers_json).unwrap_or_default();

    let mut sync_count = 0;
    let local_did = state.device_did.clone();

    for peer in raw_peers {
        let status = peer.get("status").and_then(|v| v.as_str());
        if status != Some("trusted") && status != Some("verified") {
            continue;
        }

        let peer_did = match peer
            .get("did")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                peer.get("peer_id")
                    .and_then(|v| v.as_str())
                    .map(|s| format!("did:guardian:{}", s))
            }) {
            Some(did) => did,
            None => continue,
        };

        let peer_ip_str = match peer.get("ip").and_then(|v| v.as_str()) {
            Some(ip) => ip,
            None => continue,
        };

        let peer_ip: std::net::IpAddr = match peer_ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        let peer_id_str = peer.get("peer_id").and_then(|v| v.as_str()).unwrap_or("");
        let target_addr = get_grpc_addr(&peer_ip.to_string(), peer_id_str);

        let mut last_seq_no = 0;
        if let Ok(history) = crate::chat::storage::read_p2p_history(&peer_did).await {
            last_seq_no = history.iter().map(|m| m.seq_no).max().unwrap_or(0);
        }

        let my_did = local_did.clone();

        tokio::spawn(async move {
            if let Err(e) = crate::chat::grpc_client::request_sync_from_peer(
                my_did,
                peer_did.clone(),
                target_addr,
                last_seq_no,
            )
            .await
            {
                tracing::error!("Sync task failed for peer {}: {}", peer_did, e);
            }
        });

        sync_count += 1;
    }

    Ok(Json(SyncResponse {
        status: "sync_initiated".to_string(),
        peers_synced: sync_count,
    }))
}

#[derive(Deserialize)]
pub struct ChatHistoryQuery {
    pub peer_did: Option<String>,
    pub group_id: Option<String>,
}

#[derive(Serialize)]
pub struct ChatHistoryResponse {
    pub messages: Vec<crate::chat::models::ChatMessageRecord>,
}

/// Task 7.1: Local Axum REST API to query paginated chat logs
pub async fn get_history(
    Query(query): Query<ChatHistoryQuery>,
) -> Result<Json<ChatHistoryResponse>, ApiError> {
    let messages = if let Some(peer_did) = query.peer_did {
        crate::chat::storage::read_p2p_history(&peer_did)
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to read P2P history: {}", e)))?
    } else if let Some(group_id) = query.group_id {
        crate::chat::storage::read_group_history(&group_id)
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to read Group history: {}", e)))?
    } else {
        return Err(ApiError::BadRequest(
            "Must provide either peer_did or group_id".to_string(),
        ));
    };

    Ok(Json(ChatHistoryResponse { messages }))
}

/// Task 7.2: Local WebSocket Server for real-time event push
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<std::sync::Arc<AppState>>,
) -> axum::response::Response {
    let rx = state.chat_events.subscribe();
    ws.on_upgrade(move |socket| handle_socket(socket, rx))
}

async fn handle_socket(
    socket: WebSocket,
    mut rx: tokio::sync::broadcast::Receiver<crate::chat::models::ChatEvent>,
) {
    let (mut sender, mut receiver) = socket.split();
    loop {
        tokio::select! {
            event = rx.recv() => match event {
                Ok(event) => {
                    if let Ok(msg) = serde_json::to_string(&event) {
                        if sender.send(Message::Text(msg.into())).await.is_err() {
                            break;
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "chat WebSocket client lagged; keeping connection alive");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            },
            incoming = receiver.next() => match incoming {
                Some(Ok(Message::Text(text))) if text.contains("heartbeat") => {
                    if sender.send(Message::Text("{\"type\":\"heartbeat_ack\"}".into())).await.is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Ping(payload))) => {
                    if sender.send(Message::Pong(payload)).await.is_err() { break; }
                }
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                _ => {}
            }
        }
    }
}
