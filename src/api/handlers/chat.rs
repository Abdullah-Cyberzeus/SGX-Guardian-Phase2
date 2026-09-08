use crate::api::auth::middleware::AuthenticatedSession;
use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::chat::models::{ChatMessageRecord, MessageStatus};
use axum::extract::{
    ws::{Message, WebSocket, WebSocketUpgrade},
    Json, Query, State,
};
use axum::Extension;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

pub(crate) fn get_grpc_addr(ip: &str, peer_id_str: &str) -> String {
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
                if let Some(last_octet) = ip
                    .split('.')
                    .next_back()
                    .and_then(|s| s.parse::<u16>().ok())
                {
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

/// A peer registry entry counts as trusted enough to chat with. Mirrors
/// `peers.rs::list`'s own definition of "trusted" (which also accepts
/// `"success"`) — every chat trust check here and in grpc_server.rs
/// previously only accepted `"trusted"`/`"verified"`, so a `"success"`
/// status peer was exposed to the frontend as a normal, chattable contact
/// (and thus polled for history/unread) while every actual send/read check
/// silently rejected it as untrusted.
pub(crate) fn is_trusted_status(status: Option<&str>) -> bool {
    matches!(status, Some("trusted") | Some("verified") | Some("success"))
}

pub(crate) fn peer_route_id(peer: &serde_json::Value) -> &str {
    peer.get("node_id")
        .or_else(|| peer.get("nodeId"))
        .or_else(|| peer.get("peer_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
}

pub(crate) fn member_node_hint_for_did(state: &AppState, did: &str) -> Option<String> {
    let registry = crate::circle::store::load_or_seed(&state.node_id).ok()?;
    for circle in registry
        .circles
        .into_iter()
        .filter(|circle| !circle.is_archived())
    {
        let Ok(members) = crate::circle::members::list_members(&state.node_id, &circle.circle_id)
        else {
            continue;
        };
        for member in members {
            if member.did.eq_ignore_ascii_case(did)
                && matches!(
                    member.lifecycle_state,
                    crate::circle::members::MemberLifecycleState::Active
                )
            {
                let hint = member.node_hint.unwrap_or_default();
                if !hint.trim().is_empty() {
                    return Some(hint);
                }
            }
        }
    }
    None
}

async fn load_registry_peers(state: &AppState) -> Vec<serde_json::Value> {
    let global_path = std::path::Path::new(&state.log_dir_primary).join("trusted_peers.json");
    let per_node_path = std::path::Path::new(&state.log_dir_primary)
        .join(format!("trusted_peers_{}.json", state.node_id));
    let global_json = tokio::fs::read_to_string(&global_path)
        .await
        .unwrap_or_else(|_| "[]".to_string());
    let per_node_json = tokio::fs::read_to_string(&per_node_path)
        .await
        .unwrap_or_else(|_| "[]".to_string());
    let mut peers: Vec<serde_json::Value> = serde_json::from_str(&global_json).unwrap_or_default();
    peers
        .extend(serde_json::from_str::<Vec<serde_json::Value>>(&per_node_json).unwrap_or_default());
    peers
}

/// Finds the trusted/verified registry entry `did` resolves to — by direct
/// DID/peer_id match, or (when Circle membership is available) by
/// node-hint. Returns the full registry object (not just its `did` field)
/// so callers can also match other identity fields it carries, since the
/// registry entry for a peer can have no `did` field at all and still be
/// resolvable this way. `None` only when nothing in the trusted registry
/// matches `did` by any means.
pub(crate) async fn find_trusted_peer_for_did(
    state: &AppState,
    did: &str,
) -> Option<serde_json::Value> {
    let peers = load_registry_peers(state).await;
    let node_hint = member_node_hint_for_did(state, did);
    peers.into_iter().find(|peer| {
        let status = peer.get("status").and_then(|v| v.as_str());
        is_trusted_status(status) && peer_matches_identity(peer, did, node_hint.as_deref())
    })
}

/// Resolves `did` to the registry's own canonical `did` string for that
/// peer, or `None` if no trusted/verified entry matches at all, or matches
/// but carries no `did` field of its own (identified only by peer_id/
/// node_hint — see `find_trusted_peer_for_did`). Used as a fallback when a
/// direct history lookup by the caller-supplied DID comes up empty, since
/// the frontend's idea of a peer's DID (from Circle membership or a stale
/// local cache) can diverge in casing or format from what that peer
/// actually used when storing its side of the conversation.
pub(crate) async fn resolve_canonical_peer_did(state: &AppState, did: &str) -> Option<String> {
    find_trusted_peer_for_did(state, did)
        .await
        .and_then(|peer| peer.get("did").and_then(|v| v.as_str()).map(str::to_string))
}

pub(crate) fn peer_matches_identity(
    peer: &serde_json::Value,
    did: &str,
    node_hint: Option<&str>,
) -> bool {
    let target_peer_id = did.strip_prefix("did:guardian:").unwrap_or(did);
    let peer_did = peer.get("did").and_then(|v| v.as_str()).unwrap_or("");
    let peer_id = peer.get("peer_id").and_then(|v| v.as_str()).unwrap_or("");
    let route_id = peer_route_id(peer);
    peer_did.eq_ignore_ascii_case(did)
        || peer_did.eq_ignore_ascii_case(target_peer_id)
        || peer_id.eq_ignore_ascii_case(target_peer_id)
        || peer_id.eq_ignore_ascii_case(did)
        || node_hint.is_some_and(|hint| {
            route_id.eq_ignore_ascii_case(hint) || peer_id.eq_ignore_ascii_case(hint)
        })
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
    /// Optional client-generated canonical message ID. Replaying the same
    /// send (e.g. an interrupted offline-queue retry) with the same ID
    /// returns the already-accepted message instead of creating a duplicate.
    #[serde(default)]
    pub message_id: Option<String>,
}

#[derive(Serialize)]
pub struct SendMessageResponse {
    pub message_id: String,
    pub signature_base64: String,
    pub status: String,
}

fn request_payload_json(
    req: &SendMessageRequest,
    attachment: Option<&crate::vault::VaultRecord>,
) -> String {
    serde_json::to_string(&serde_json::json!({
        "content": req.content,
        "attachment_id": req.attachment_id,
        "attachment_name": attachment.map(|record| record.filename.as_str()),
        "attachment_mime": attachment.map(|record| record.mime.as_str()),
        "attachment_size": attachment.map(|record| record.size_plain),
    }))
    .unwrap_or_default()
}

fn payload_matches_request(payload: &str, req: &SendMessageRequest) -> bool {
    serde_json::from_str::<serde_json::Value>(payload).is_ok_and(|value| {
        value.get("content") == Some(&serde_json::json!(req.content))
            && value.get("attachment_id") == Some(&serde_json::json!(req.attachment_id))
    })
}

/// The file-store key for a local (same-backend) 1:1 conversation between
/// two DIDs. When one side is the Guardian device itself, the thread is
/// keyed by the other (member) DID, matching the existing on-disk layout.
/// When neither side is the Guardian — two browser members talking to each
/// other — there is no privileged identity to key by, so the pair is
/// canonicalized by sorting the DIDs. Without this, a conversation would
/// split into two divergent single-direction logs depending on who sent
/// the most recent message.
fn local_pair_conversation_id(state: &AppState, a: &str, b: &str) -> String {
    if a == state.device_did {
        b.to_string()
    } else if b == state.device_did {
        a.to_string()
    } else if a <= b {
        format!("pair-{}-{}", a, b)
    } else {
        format!("pair-{}-{}", b, a)
    }
}

/// How many distinct readers a group message needs before it counts as
/// fully `Read` — every circle member except whoever sent it. Circle
/// membership is the union of VC-attested device members and this node's
/// own registered browser members, since browser members are only known
/// to the Guardian that hosts them.
pub(crate) async fn group_min_reader_count(
    state: &AppState,
    circle_id: &str,
    sender_did: &str,
) -> usize {
    let mut roster: std::collections::HashSet<String> =
        crate::circle::members::list_members(&state.node_id, circle_id)
            .map(|members| members.into_iter().map(|m| m.did).collect())
            .unwrap_or_default();
    roster.extend(
        crate::api::handlers::browser_member::dids_for_circles(
            state,
            &std::collections::HashSet::from([circle_id.to_string()]),
        )
        .await
        .unwrap_or_default(),
    );
    roster.remove(sender_did);
    roster.len().max(1)
}

/// A friendly label for a notification body — the display name for a local
/// browser member, a generic label for the Guardian device itself, or the
/// raw DID as a last resort (a remote peer's own Guardian, whose `User`
/// record lives on their box, not ours).
async fn resolve_actor_label(state: &AppState, did: &str) -> String {
    if did == state.device_did {
        return "the Guardian administrator".to_string();
    }
    if let Ok(users) = state.admin.users.list().await {
        for user in users {
            let Some(registration_id) = user.browser_registration_id.as_deref() else {
                continue;
            };
            if crate::api::handlers::browser_member::did_for_registration(registration_id) == did {
                return user.name;
            }
        }
    }
    did.to_string()
}

pub async fn send_message(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Json(req): Json<SendMessageRequest>,
) -> Result<Json<SendMessageResponse>, ApiError> {
    // 1. Validate payload
    if req.content.is_none() && req.attachment_id.is_none() {
        return Err(ApiError::BadRequest(
            "Message must contain either content or an attachment".to_string(),
        ));
    }
    let sender_did = crate::api::handlers::browser_member::did_from_session(&session)
        .unwrap_or_else(|| state.device_did.clone());
    let sender_label = resolve_actor_label(&state, &sender_did).await;

    // Chat attachments are Vault records uploaded before the destination is
    // known (Personal namespace, owned by the sender). Now that the
    // recipient/group is known, link the attachment to it: group messages
    // move the record into that Circle's namespace (so Circle-membership
    // authorization covers it); direct messages record the recipient DID so
    // only the two participants can access it.
    let attachment = if let Some(attachment_id) = req.attachment_id.as_deref() {
        let vault_config = crate::vault::VaultConfig::from_env();
        let record = crate::api::handlers::vault::load_authorized_record(
            &vault_config,
            &session,
            &sender_did,
            attachment_id,
        )
        .await
        .map_err(|_| ApiError::NotFound("Attachment metadata not found".to_string()))?;
        if record.owner_did != sender_did {
            return Err(ApiError::Forbidden(
                "cannot attach a file you do not own".to_string(),
            ));
        }
        crate::api::handlers::vault::ensure_downloadable(&record)
            .map_err(|_| ApiError::NotFound("Attachment file not found".to_string()))?;

        let target_namespace = if req.is_group {
            crate::vault::VaultNamespace::Circle(req.recipient_did.clone())
        } else {
            crate::vault::VaultNamespace::Personal
        };
        let record = {
            let _guard = crate::vault::write_lock().lock().await;
            let mut record = if record.namespace_ref() != target_namespace {
                crate::vault::persistence::move_to_namespace(
                    &vault_config,
                    record,
                    &target_namespace,
                )
                .await
                .map_err(|error| ApiError::Internal(error.to_string()))?
            } else {
                record
            };
            if !req.is_group {
                record.conversation_recipient_did = Some(req.recipient_did.clone());
            }
            crate::vault::persistence::save_record(&vault_config, &record)
                .await
                .map_err(|error| ApiError::Internal(error.to_string()))?;
            record
        };
        Some(record)
    } else {
        None
    };
    if !req.is_group {
        ensure_member_contact_access(&state, &session, &req.recipient_did).await?;
    }
    let local_circle_ids =
        crate::api::auth::authorization::local_active_circle_ids(&state.node_id, &state.device_did)
            .map_err(ApiError::Internal)?;
    let browser_recipient_state = if !req.is_group {
        crate::api::handlers::browser_member::state_for_did(
            &state,
            &req.recipient_did,
            &local_circle_ids,
        )
        .await?
    } else {
        None
    };
    let is_local_guardian_recipient =
        !req.is_group && req.recipient_did == state.device_did && sender_did != state.device_did;
    let is_local_direct = is_local_guardian_recipient || browser_recipient_state.is_some();
    let direct_conversation_id = if is_local_direct {
        local_pair_conversation_id(&state, &sender_did, &req.recipient_did)
    } else {
        req.recipient_did.clone()
    };

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
        // Group Chat: Fetch circle members and intersect with trusted peers
        let circle_id = req.recipient_did.clone();
        let circle_members = crate::circle::members::list_members(&state.node_id, &circle_id)
            .map_err(|e| ApiError::BadRequest(format!("Failed to load circle members: {:?}", e)))?;
        ensure_local_guardian_circle_access(&state, &session, &circle_id)?;

        // Older approved PWA members may predate browser identities in the
        // signed Circle snapshot. Repair and broadcast once before relaying
        // their first group message so remote Guardians can authenticate the
        // actor DID separately from this Guardian's transport DID.
        if sender_did != state.device_did {
            let snapshot_has_sender = crate::circle::snapshot::load(&circle_id)
                .map_err(|error| ApiError::Internal(format!("load Circle snapshot: {error:?}")))?
                .is_some_and(|snapshot| {
                    snapshot
                        .members
                        .iter()
                        .any(|member| member.did == sender_did)
                });
            if !snapshot_has_sender {
                crate::api::handlers::circle::refresh_and_broadcast_member_snapshot(
                    &state, &circle_id,
                )
                .await
                .map_err(|error| {
                    ApiError::Internal(format!(
                        "refresh Circle member identity snapshot: {error:?}"
                    ))
                })?;
            }
        }

        // Extract DIDs of circle members
        let member_dids: std::collections::HashSet<String> =
            circle_members.into_iter().map(|m| m.did).collect();

        for p in raw_peers.iter() {
            let status = p.get("status").and_then(|v| v.as_str());
            if is_trusted_status(status) {
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
                let peer_id_str = peer_route_id(p);

                if let (Some(did), Some(ip_str)) = (did_val, ip_str) {
                    // Only send if the peer's DID is in the circle member list
                    if member_dids.contains(&did) {
                        if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                            let target_addr = get_grpc_addr(&ip.to_string(), peer_id_str);
                            target_peers_info.push((did, target_addr));
                        }
                    }
                }
            }
        }
        // Group history is a single shared local file, so a member's browser
        // client sees new messages as soon as they're stored — no gRPC
        // fan-out is needed to reach it. Fan-out is only required to
        // replicate the message to *other* device Guardians in the circle,
        // so only fail here when there's truly nobody to deliver to. Browser
        // members are never in `member_dids` (that list is VC/device-only),
        // so they're checked separately via the pwa registration store.
        let has_local_browser_recipient = !crate::api::handlers::browser_member::dids_for_circles(
            &state,
            &std::collections::HashSet::from([circle_id.clone()]),
        )
        .await?
        .is_empty();
        if target_peers_info.is_empty() && !has_local_browser_recipient {
            return Err(ApiError::Forbidden(
                "No trusted peers found in the circle for group fan-out".to_string(),
            ));
        }
    } else if !is_local_direct {
        // P2P Chat: Find the specific trusted peer.
        // Match by full DID string OR by the base58 key suffix OR by peer_id.
        let recipient_node_hint = member_node_hint_for_did(&state, &req.recipient_did);
        let target_peer = raw_peers.iter().find(|p| {
            let status = p.get("status").and_then(|v| v.as_str());
            is_trusted_status(status)
                && peer_matches_identity(p, &req.recipient_did, recipient_node_hint.as_deref())
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
            let peer_id_str = peer_route_id(peer);
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

    // 2/3. Load current history once: it drives both the idempotent-replay
    // check and the seq_no assignment below.
    let history = if req.is_group {
        crate::chat::storage::read_group_history(&req.recipient_did)
            .await
            .unwrap_or_default()
    } else {
        crate::chat::storage::read_p2p_history(&direct_conversation_id)
            .await
            .unwrap_or_default()
    };

    let requested_id = req
        .message_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty());
    if requested_id.is_some_and(|id| id.len() > 100) {
        return Err(ApiError::BadRequest(
            "message_id must be 100 characters or fewer".to_string(),
        ));
    }
    let content_str = request_payload_json(&req, attachment.as_ref());

    if let Some(existing) = requested_id.and_then(|id| history.iter().find(|m| m.message_id == id))
    {
        if !payload_matches_request(&existing.encrypted_payload, &req) {
            return Err(ApiError::BadRequest(
                "idempotency replay payload does not match the original message".to_string(),
            ));
        }
        // Idempotent replay: this exact message was already accepted, so do
        // not append another log entry or re-dispatch gRPC delivery. Return
        // its real current status rather than a fixed placeholder so a
        // retried send reflects delivery progress made since the first
        // attempt.
        return Ok(Json(SendMessageResponse {
            message_id: existing.message_id.clone(),
            signature_base64: String::new(),
            status: existing.status.as_str().to_string(),
        }));
    }

    let message_id = requested_id
        .map(str::to_string)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let timestamp = chrono::Utc::now().timestamp();
    let seq_no = history.iter().map(|m| m.seq_no).max().unwrap_or(0) + 1;

    // 4. Save outbound message locally. The field name is kept for schema
    // compatibility while Phase 0's encryption-at-rest decision is finalized.
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
        status: MessageStatus::AcceptedByGuardian,
        read_by: Vec::new(),
    };

    if let Some(attachment_record) = attachment.as_ref() {
        let mut linked = attachment_record.clone();
        linked.message_id = Some(message_id.clone());
        let vault_config = crate::vault::VaultConfig::from_env();
        let _guard = crate::vault::write_lock().lock().await;
        let _ = crate::vault::persistence::save_record(&vault_config, &linked).await;
        // Group history is one shared local file — every local browser
        // member sees it immediately, with no per-recipient "delivery" step
        // to hook a notification on, so group sends always notify here. A
        // direct message's remote delivery is announced when it lands on
        // the *other* Guardian instead, via `push_message` in
        // grpc_server.rs — so only local-direct fires here for those.
        if is_local_direct || req.is_group {
            crate::notify::publish_circle_file_shared(
                &sender_did,
                &sender_label,
                &attachment_record.filename,
                &attachment_record.vault_id,
            );
        }
    }

    if req.is_group {
        crate::chat::storage::append_group_message(&req.recipient_did, &record)
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to save group message: {}", e)))?;
        // Group history is one shared local file with no per-recipient
        // delivery step (see the file-shared notification above for the
        // same reasoning), so notify unconditionally here.
        crate::notify::publish_circle_new_message(&sender_did, &sender_label, &message_id);
    } else {
        crate::chat::storage::append_p2p_message(&direct_conversation_id, &record)
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to save p2p message: {}", e)))?;
    }
    let _ = state
        .chat_events
        .send(crate::chat::models::ChatEvent::NewMessage(record.clone()));

    if is_local_direct {
        crate::notify::publish_circle_new_message(&sender_did, &sender_label, &message_id);
        let delivered = is_local_guardian_recipient
            || browser_recipient_state
                == Some(crate::api::handlers::browser_member::BrowserMemberState::Active);
        if delivered {
            match crate::chat::storage::update_message_status(
                false,
                &direct_conversation_id,
                &message_id,
                crate::chat::models::MessageStatus::DeliveredToRemoteGuardian,
            )
            .await
            {
                Ok(Some(record)) => {
                    let _ = state
                        .chat_events
                        .send(crate::chat::models::ChatEvent::MessageStatus(record));
                }
                Ok(None) => {}
                Err(e) => eprintln!("❌ Chat: failed to update local delivered status: {}", e),
            }
        }
        return Ok(Json(SendMessageResponse {
            message_id,
            signature_base64: String::new(),
            status: if delivered {
                MessageStatus::DeliveredToRemoteGuardian
                    .as_str()
                    .to_string()
            } else {
                MessageStatus::AcceptedByGuardian.as_str().to_string()
            },
        }));
    }

    // 5. Dispatch gRPC push in background (Nebula overlay already provides E2E security).
    // The message stays `Pending` (the status already persisted above) until a
    // push actually succeeds — that is the "offline peer keeps it pending"
    // behavior. Once at least one target acknowledges delivery, the stored
    // record is advanced to `Delivered` and connected clients are notified so
    // the UI stops showing "Pending" for a message that in fact went through.
    let message_id_clone = message_id.clone();
    let sender_did_clone = sender_did.clone();
    let is_group = req.is_group;
    let group_id_str = if is_group {
        req.recipient_did.clone()
    } else {
        String::new()
    };
    let status_state = state.clone();
    let status_target_id = req.recipient_did.clone();
    tokio::spawn(async move {
        let mut delivery_tasks = Vec::new();
        let relay_did = status_state.device_did.clone();
        for (recipient_did, target_addr) in target_peers_info {
            let msg_id = message_id_clone.clone();
            let snd_did = sender_did_clone.clone();
            let rec_did = recipient_did.clone();
            let content = content_str.clone();
            let addr = target_addr.clone();
            let g_id = group_id_str.clone();
            let relay = relay_did.clone();

            delivery_tasks.push(tokio::spawn(async move {
                let grpc_req = crate::proto::sgx::PushMessageRequest {
                    message_id: msg_id,
                    sender_did: snd_did,
                    recipient_did: rec_did,
                    timestamp,
                    seq_no,
                    encrypted_payload: content, // plain text over Nebula-secured channel
                    signature: String::new(),
                    group_id: g_id,
                    relay_did: relay,
                };

                match crate::chat::grpc_client::push_message_to_peer(addr.clone(), grpc_req).await {
                    Ok(()) => {
                        println!("💬 ✅ Message delivered to {}", addr);
                        true
                    }
                    Err(e) => {
                        eprintln!("❌ Chat delivery failed to {}: {}", addr, e);
                        false
                    }
                }
            }));
        }

        let mut any_delivered = false;
        for task in delivery_tasks {
            if matches!(task.await, Ok(true)) {
                any_delivered = true;
            }
        }

        if any_delivered {
            match crate::chat::storage::update_message_status(
                is_group,
                &status_target_id,
                &message_id_clone,
                crate::chat::models::MessageStatus::DeliveredToRemoteGuardian,
            )
            .await
            {
                Ok(Some(record)) => {
                    let _ = status_state
                        .chat_events
                        .send(crate::chat::models::ChatEvent::MessageStatus(record));
                }
                Ok(None) => {}
                Err(e) => eprintln!("❌ Chat: failed to update delivered status: {}", e),
            }
        }
    });

    // 6. Respond immediately — message persisted locally and queued for delivery
    Ok(Json(SendMessageResponse {
        message_id,
        signature_base64: String::new(),
        status: MessageStatus::AcceptedByGuardian.as_str().to_string(),
    }))
}

#[derive(Deserialize)]
pub struct TypingRequest {
    pub recipient_did: String,
    #[serde(default)]
    pub is_group: bool,
    pub is_typing: bool,
}

#[derive(Serialize)]
pub struct TypingResponse {
    pub status: String,
}

/// Broadcast an ephemeral typing indicator on the existing authenticated chat
/// WebSocket. The event is never persisted and respects the sender's privacy setting.
pub async fn typing(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Json(req): Json<TypingRequest>,
) -> Result<Json<TypingResponse>, ApiError> {
    let sender_did = crate::api::handlers::browser_member::did_from_session(&session)
        .unwrap_or_else(|| state.device_did.clone());

    let hide_typing = match session.as_ref() {
        Some(Extension(authed)) => state
            .admin
            .users
            .find_by_id(&authed.claims.sub)
            .await?
            .is_some_and(|user| user.hide_typing),
        None => false,
    };

    if req.is_group {
        ensure_local_guardian_circle_access(&state, &session, &req.recipient_did)?;
    } else {
        ensure_member_contact_access(&state, &session, &req.recipient_did).await?;
    }

    if !hide_typing {
        let conversation_id = if req.is_group {
            req.recipient_did.clone()
        } else {
            local_pair_conversation_id(&state, &sender_did, &req.recipient_did)
        };
        let _ = state
            .chat_events
            .send(crate::chat::models::ChatEvent::Typing(
                crate::chat::models::TypingEvent {
                    conversation_id,
                    sender_did,
                    is_typing: req.is_typing,
                },
            ));
    }

    Ok(Json(TypingResponse {
        status: "ok".to_string(),
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
    session: Option<Extension<AuthenticatedSession>>,
    Json(req): Json<MarkReadRequest>,
) -> Result<Json<MarkReadResponse>, ApiError> {
    // Peers are authorised by DID. Transport confidentiality and endpoint
    // authentication are supplied by the Nebula overlay.
    let reader_did = crate::api::handlers::browser_member::did_from_session(&session)
        .unwrap_or_else(|| state.device_did.clone());
    let hide_read_receipts = match session.as_ref() {
        Some(Extension(authed)) => state
            .admin
            .users
            .find_by_id(&authed.claims.sub)
            .await?
            .is_some_and(|user| user.hide_read_receipts),
        None => false,
    };
    let timestamp = chrono::Utc::now().timestamp();
    let p2p_conversation_id =
        local_pair_conversation_id(&state, &reader_did, &req.original_sender_did);
    let mut min_reader_count: usize = 1;

    // 1. Verify the message exists
    if let Some(ref gid) = req.group_id {
        ensure_local_guardian_circle_access(&state, &session, gid)?;
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
        min_reader_count = group_min_reader_count(&state, gid, &req.original_sender_did).await;
    } else if let Ok(history) = crate::chat::storage::read_p2p_history(&p2p_conversation_id).await {
        ensure_member_contact_access(&state, &session, &req.original_sender_did).await?;
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

    // 2. Log the receipt locally — gated by *this reader's current*
    // preference, at the moment they read it. Once recorded (or skipped),
    // it's permanent: toggling the preference later never rewrites past
    // messages in either direction — only reads that happen after a change
    // are affected, matching what the reader's setting was at read time.
    if !hide_read_receipts {
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
        let target_file_id = req.group_id.as_deref().unwrap_or(&p2p_conversation_id);
        let updated_record = crate::chat::storage::update_message_read_by(
            is_group,
            target_file_id,
            &req.message_id,
            &reader_did,
            min_reader_count,
        )
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to update read status: {}", e)))?;
        let _ = state
            .chat_events
            .send(crate::chat::models::ChatEvent::ReadReceipt(receipt.clone()));
        if let Some(record) = updated_record {
            let _ = state
                .chat_events
                .send(crate::chat::models::ChatEvent::MessageStatus(record));
        }
    }

    // 3. Fetch peer IP to notify original sender — skipped entirely when
    // this reader hides read receipts, so a remote sender never learns
    // their message was read either.
    if !hide_read_receipts {
        let target_peer = find_trusted_peer_for_did(&state, &req.original_sender_did).await;

        if let Some(peer) = target_peer.as_ref() {
            let peer_ip = peer
                .get("ip")
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1")
                .to_string();
            let peer_id_str = peer_route_id(peer);
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
        if !is_trusted_status(status) {
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
        let peer_id_str = peer_route_id(&peer);
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
    pub after_seq: Option<u64>,
    pub limit: Option<usize>,
}

#[derive(Serialize)]
pub struct ChatHistoryResponse {
    pub messages: Vec<crate::chat::models::ChatMessageRecord>,
    pub next_cursor: Option<u64>,
}

/// Task 7.1: Local Axum REST API to query paginated chat logs
pub async fn get_history(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Query(query): Query<ChatHistoryQuery>,
) -> Result<Json<ChatHistoryResponse>, ApiError> {
    let mut messages = if let Some(peer_did) = query.peer_did {
        ensure_member_contact_access(&state, &session, &peer_did).await?;
        let own_did = crate::api::handlers::browser_member::did_from_session(&session)
            .unwrap_or_else(|| state.device_did.clone());
        let conversation_id = local_pair_conversation_id(&state, &own_did, &peer_did);
        // Tagged distinctly (🔎, not 💬) and always printed — carries both
        // DIDs on one line so it can be grepped for a specific pair without
        // having to infer which of several concurrent background-poll
        // lookups (unread badge refresh, etc.) belongs to which peer.
        eprintln!(
            "🔎 History request: own_did={} peer_did={} conversation_id={}",
            own_did, peer_did, conversation_id
        );
        let mut history = crate::chat::storage::read_p2p_history(&conversation_id)
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to read P2P history: {}", e)))?;
        // The requested peer_did came straight from the frontend (Circle
        // roster or a locally cached peer entry) and can diverge in casing
        // or format from the DID that peer actually used to store its side
        // of the exchange. Retry once against the registry's own canonical
        // DID for that identity before concluding the conversation is
        // empty — this is the one lookup path that didn't share the
        // node-hint fallback `send_message`/`mark_as_read` already use.
        if history.is_empty() {
            if let Some(canonical_did) = resolve_canonical_peer_did(&state, &peer_did).await {
                if canonical_did != peer_did {
                    let alt_conversation_id =
                        local_pair_conversation_id(&state, &own_did, &canonical_did);
                    history = crate::chat::storage::read_p2p_history(&alt_conversation_id)
                        .await
                        .unwrap_or_default();
                    eprintln!(
                        "💬 History: direct lookup for peer_did={} empty, canonical retry via {} found {} message(s)",
                        peer_did,
                        canonical_did,
                        history.len()
                    );
                }
            }
        }
        // Last resort — and the one that does NOT require Circle membership
        // or a `did` field in the registry at all: find whichever trusted
        // registry entry `peer_did` resolves to (by any of its identity
        // fields — see `peer_matches_identity`), then check every *existing*
        // conversation file to see whether ITS key also resolves to that
        // same registry entry. A received message is filed verbatim under
        // the sender's own self-declared DID (`push_message` in
        // grpc_server.rs) — ground truth, independent of this node's
        // registry quality — so this finds it even when neither side's
        // guess at the other's DID matches the other's literally.
        if history.is_empty() {
            if let Some(target_peer) = find_trusted_peer_for_did(&state, &peer_did).await {
                let node_hint = member_node_hint_for_did(&state, &peer_did);
                let candidates = crate::chat::storage::list_p2p_conversation_ids().await;
                eprintln!(
                    "💬 History: canonical retry also empty for peer_did={}, scanning {} existing conversation file(s) against matched registry entry {:?}",
                    peer_did,
                    candidates.len(),
                    target_peer.get("peer_id").and_then(|v| v.as_str())
                );
                for candidate_did in candidates {
                    if candidate_did == peer_did {
                        continue;
                    }
                    if peer_matches_identity(&target_peer, &candidate_did, node_hint.as_deref()) {
                        let alt_conversation_id =
                            local_pair_conversation_id(&state, &own_did, &candidate_did);
                        let found = crate::chat::storage::read_p2p_history(&alt_conversation_id)
                            .await
                            .unwrap_or_default();
                        eprintln!(
                            "💬 History: candidate conversation file {} matched — {} message(s)",
                            candidate_did,
                            found.len()
                        );
                        if !found.is_empty() {
                            history = found;
                            break;
                        }
                    }
                }
            } else {
                eprintln!(
                    "💬 History: no trusted registry entry resolves peer_did={} at all — nothing to scan for",
                    peer_did
                );
            }
        }
        eprintln!(
            "🔎 History result: own_did={} peer_did={} -> {} message(s)",
            own_did,
            peer_did,
            history.len()
        );
        history
    } else if let Some(group_id) = query.group_id {
        ensure_local_guardian_circle_access(&state, &session, &group_id)?;
        let mut group_messages = crate::chat::storage::read_group_history(&group_id)
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to read Group history: {}", e)))?;
        // A member should only see messages sent from the point they joined
        // the Circle onward, not history predating their membership. This
        // doesn't apply to the Guardian device/admin session itself, which
        // has full visibility into every Circle it hosts.
        let is_member_session = session
            .as_ref()
            .is_some_and(|Extension(session)| session.claims.role == "member");
        if is_member_session {
            let own_did = crate::api::handlers::browser_member::did_from_session(&session)
                .unwrap_or_else(|| state.device_did.clone());
            if let Some(join_timestamp) = member_join_timestamp(&state, &group_id, &own_did).await?
            {
                group_messages.retain(|message| message.timestamp >= join_timestamp);
            }
        }
        group_messages
    } else {
        return Err(ApiError::BadRequest(
            "Must provide either peer_did or group_id".to_string(),
        ));
    };
    messages.sort_by_key(|message| (message.seq_no, message.timestamp));
    if let Some(after_seq) = query.after_seq {
        messages.retain(|message| message.seq_no > after_seq);
    }
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    if messages.len() > limit {
        messages.truncate(limit);
    }
    let next_cursor = messages.last().map(|message| message.seq_no);

    // Read-receipt privacy is enforced at write time in `mark_as_read`
    // (a reader hiding receipts simply never gets recorded into `read_by`),
    // not here — so history returned here needs no further filtering. That
    // keeps a toggle's effect strictly forward-only: whatever was already
    // recorded before a preference change stays exactly as it was.

    Ok(Json(ChatHistoryResponse {
        messages,
        next_cursor,
    }))
}

async fn ensure_member_contact_access(
    state: &AppState,
    session: &Option<Extension<AuthenticatedSession>>,
    contact_did: &str,
) -> Result<(), ApiError> {
    let is_member = session
        .as_ref()
        .is_some_and(|Extension(session)| session.claims.role == "member");
    if !is_member {
        return Ok(());
    }
    if contact_did == state.device_did {
        return Ok(());
    }
    let circle_ids: std::collections::HashSet<String> = session
        .as_ref()
        .map(|Extension(session)| session.claims.circle_ids.iter().cloned().collect())
        .unwrap_or_default();
    let browser_allowed = crate::api::handlers::browser_member::did_from_session(session)
        .as_deref()
        == Some(contact_did);
    // Browser identities only exist on their hosting Guardian. A member may
    // therefore direct-message its own Guardian or another browser member
    // hosted here, but never a remote Guardian/device from the Circle roster.
    // Remote Guardians remain reachable through the replicated group chat.
    let browser_contact =
        crate::api::handlers::browser_member::dids_for_circles(state, &circle_ids)
            .await?
            .contains(contact_did);
    if browser_allowed || browser_contact {
        Ok(())
    } else {
        if let Some(Extension(session)) = session.as_ref() {
            crate::api::auth::authorization::audit_member_resource_denied(
                &state.node_id,
                &session.claims.sub,
                "Circle contact",
            );
        }
        Err(ApiError::Forbidden(
            "members cannot directly message another Guardian; use the Circle group chat".into(),
        ))
    }
}

/// The Unix-seconds timestamp at which `member_did` joined `circle_id`,
/// derived from the roster's `join_date` (RFC3339). `None` if the member
/// isn't found on the roster or their `join_date` fails to parse — callers
/// treat that as "no cutoff" rather than hiding all history over a lookup
/// hiccup.
async fn member_join_timestamp(
    state: &AppState,
    circle_id: &str,
    member_did: &str,
) -> Result<Option<i64>, ApiError> {
    let members = crate::api::handlers::circle::full_member_list(state, circle_id).await?;
    Ok(members
        .into_iter()
        .find(|member| member.did == member_did)
        .and_then(|member| chrono::DateTime::parse_from_rfc3339(&member.join_date).ok())
        .map(|joined_at| joined_at.timestamp()))
}

fn ensure_local_guardian_circle_access(
    state: &AppState,
    session: &Option<Extension<AuthenticatedSession>>,
    circle_id: &str,
) -> Result<(), ApiError> {
    let is_member = session
        .as_ref()
        .is_some_and(|Extension(session)| session.claims.role == "member");
    if !is_member
        || (session.as_ref().is_some_and(|Extension(session)| {
            session
                .claims
                .circle_ids
                .iter()
                .any(|allowed| allowed == circle_id)
        }) && crate::api::auth::authorization::local_active_circle_ids(
            &state.node_id,
            &state.device_did,
        )
        .map_err(ApiError::Internal)?
        .contains(circle_id))
    {
        return Ok(());
    }
    if let Some(Extension(session)) = session.as_ref() {
        crate::api::auth::authorization::audit_member_resource_denied(
            &state.node_id,
            &session.claims.sub,
            "Circle conversation",
        );
    }
    Err(ApiError::Forbidden(format!(
        "Guardian is not a member of circle {}",
        circle_id
    )))
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn peer_route_id_prefers_stable_node_id_for_port_selection() {
        let peer = serde_json::json!({
            "peer_id": "Renamed Guardian",
            "node_id": "nodeB",
            "ip": "127.0.0.1",
            "status": "verified",
        });
        assert_eq!(peer_route_id(&peer), "nodeB");
        assert_eq!(
            get_grpc_addr("127.0.0.1", peer_route_id(&peer)),
            "127.0.0.1:50252"
        );
    }

    #[test]
    fn peer_identity_can_match_circle_node_hint_when_registry_lacks_did() {
        let peer = serde_json::json!({
            "peer_id": "nodeA",
            "ip": "127.0.0.1",
            "status": "verified",
        });
        assert!(peer_matches_identity(
            &peer,
            "did:guardian:z6MkRealDeviceDid",
            Some("nodeA"),
        ));
    }

    /// `session: None` (the admin/device-level caller) short-circuits every
    /// circle/contact-membership check in this file before it touches any
    /// VC or key-manager state — see `ensure_member_contact_access`'s
    /// `if !is_member { return Ok(()); }`. That keeps this test hardware-
    /// free, unlike a `role: "member"` session would be.
    #[tokio::test]
    async fn mark_as_read_updates_read_by_for_admin_caller() {
        let _lock = crate::test_support::async_env_lock().await;
        let td = TempDir::new().expect("tempdir");
        // `chat::storage`'s BASE_DIR is a process-wide `Lazy`, bound on first
        // use — safe to set here since this is the only test in the binary
        // that touches chat message storage.
        std::env::set_var("CHAT_STORAGE_DIR", td.path().join("chat"));
        let state = AppState::for_tests(
            td.path(),
            "nodeA",
            td.path().join("config").to_string_lossy().to_string(),
        );
        let sender_did = "did:guardian:remote-sender".to_string();
        let conversation_id = local_pair_conversation_id(&state, &state.device_did, &sender_did);
        let record = ChatMessageRecord {
            message_id: "msg-1".to_string(),
            sender_did: sender_did.clone(),
            recipient_did: state.device_did.clone(),
            group_id: None,
            timestamp: chrono::Utc::now().timestamp(),
            seq_no: 1,
            encrypted_payload: "{}".to_string(),
            signature: String::new(),
            status: MessageStatus::Delivered,
            read_by: Vec::new(),
        };
        crate::chat::storage::append_p2p_message(&conversation_id, &record)
            .await
            .expect("seed p2p history");

        let response = mark_as_read(
            State(state.clone()),
            None,
            Json(MarkReadRequest {
                message_id: "msg-1".to_string(),
                original_sender_did: sender_did.clone(),
                group_id: None,
            }),
        )
        .await
        .expect("mark_as_read succeeds");
        assert_eq!(response.0.status, "read_logged");

        let history = crate::chat::storage::read_p2p_history(&conversation_id)
            .await
            .expect("read p2p history");
        let updated = history
            .iter()
            .find(|entry| entry.message_id == "msg-1")
            .expect("message present");
        assert!(updated.read_by.contains(&state.device_did));

        // --- Read-receipt privacy is enforced at write time: a reader's
        // *current* preference when they call mark_as_read decides whether
        // that read ever gets recorded, permanently. Toggling the
        // preference later never rewrites past reads in either direction.
        // Reuses this test's already-bound CHAT_STORAGE_DIR (the Lazy only
        // binds once per process).
        let member = state
            .admin
            .users
            .create_or_reactivate_member(crate::api::auth::store::NewMemberRegistration {
                name: "Reader".into(),
                email: "reader@example.com".into(),
                pw_hash: "hash".into(),
                circle_id: "circle-1".into(),
                browser_registration_id: "reg-reader".into(),
                guardian_fingerprint: "fp".into(),
                registration_expires_at: chrono::Utc::now().timestamp() + 3600,
                invite_id: "invite-1".into(),
                pending_approval: false,
            })
            .await
            .expect("create member");
        let member_did = crate::api::handlers::browser_member::did_for_registration("reg-reader");
        let member_session = Some(Extension(AuthenticatedSession {
            claims: crate::api::auth::session::Claims {
                sub: member.user_id.clone(),
                role: "member".to_string(),
                scopes: crate::api::auth::authorization::default_scopes("member"),
                circle_ids: vec!["circle-1".to_string()],
                browser_registration_id: Some("reg-reader".to_string()),
                guardian_fingerprint: None,
                iss: state.device_did.clone(),
                iat: chrono::Utc::now().timestamp(),
                exp: chrono::Utc::now().timestamp() + 300,
                jti: uuid::Uuid::new_v4().to_string(),
            },
            token: String::new(),
        }));

        let sender_conversation_id =
            local_pair_conversation_id(&state, &state.device_did, &member_did);
        let seed_message = |message_id: &str| ChatMessageRecord {
            message_id: message_id.to_string(),
            sender_did: state.device_did.clone(),
            recipient_did: member_did.clone(),
            group_id: None,
            timestamp: chrono::Utc::now().timestamp(),
            seq_no: 1,
            encrypted_payload: "{}".to_string(),
            signature: String::new(),
            status: MessageStatus::Delivered,
            read_by: Vec::new(),
        };
        crate::chat::storage::append_p2p_message(&sender_conversation_id, &seed_message("msg-2"))
            .await
            .expect("seed sender-side p2p history (msg-2)");

        // Read while visible: recorded normally.
        let _ = mark_as_read(
            State(state.clone()),
            member_session.clone(),
            Json(MarkReadRequest {
                message_id: "msg-2".to_string(),
                original_sender_did: state.device_did.clone(),
                group_id: None,
            }),
        )
        .await
        .expect("member marks msg-2 read while visible");

        let after_visible_read = get_history(
            State(state.clone()),
            None,
            Query(ChatHistoryQuery {
                peer_did: Some(member_did.clone()),
                group_id: None,
                after_seq: None,
                limit: None,
            }),
        )
        .await
        .expect("sender reads history")
        .0;
        let msg2 = after_visible_read
            .messages
            .iter()
            .find(|m| m.message_id == "msg-2")
            .expect("msg-2 present");
        assert!(
            msg2.read_by.contains(&member_did),
            "read while visible should be recorded"
        );
        assert_eq!(msg2.status, MessageStatus::Read);

        // Now hide read receipts, then read a second message while hidden.
        state
            .admin
            .users
            .update_profile(
                &member.user_id,
                crate::api::auth::store::ProfilePatch {
                    hide_read_receipts: Some(true),
                    ..Default::default()
                },
            )
            .await
            .expect("enable hide_read_receipts");

        crate::chat::storage::append_p2p_message(&sender_conversation_id, &seed_message("msg-3"))
            .await
            .expect("seed sender-side p2p history (msg-3)");
        let _ = mark_as_read(
            State(state.clone()),
            member_session.clone(),
            Json(MarkReadRequest {
                message_id: "msg-3".to_string(),
                original_sender_did: state.device_did.clone(),
                group_id: None,
            }),
        )
        .await
        .expect("member marks msg-3 read while hidden");

        let while_hidden = get_history(
            State(state.clone()),
            None,
            Query(ChatHistoryQuery {
                peer_did: Some(member_did.clone()),
                group_id: None,
                after_seq: None,
                limit: None,
            }),
        )
        .await
        .expect("sender reads history while reader is hidden")
        .0;
        let msg2 = while_hidden
            .messages
            .iter()
            .find(|m| m.message_id == "msg-2")
            .expect("msg-2 present");
        let msg3 = while_hidden
            .messages
            .iter()
            .find(|m| m.message_id == "msg-3")
            .expect("msg-3 present");
        assert!(
            msg2.read_by.contains(&member_did),
            "a read recorded before the toggle must be unaffected by it"
        );
        assert_eq!(msg2.status, MessageStatus::Read);
        assert!(
            !msg3.read_by.contains(&member_did),
            "a read while hidden must never be recorded"
        );
        assert_eq!(msg3.status, MessageStatus::Delivered);

        // Un-hide again: the read that happened while hidden must stay
        // unrecorded — toggling back does not retroactively add it.
        state
            .admin
            .users
            .update_profile(
                &member.user_id,
                crate::api::auth::store::ProfilePatch {
                    hide_read_receipts: Some(false),
                    ..Default::default()
                },
            )
            .await
            .expect("disable hide_read_receipts");

        let after_unhide = get_history(
            State(state.clone()),
            None,
            Query(ChatHistoryQuery {
                peer_did: Some(member_did.clone()),
                group_id: None,
                after_seq: None,
                limit: None,
            }),
        )
        .await
        .expect("sender reads history after un-hiding")
        .0;
        let msg2 = after_unhide
            .messages
            .iter()
            .find(|m| m.message_id == "msg-2")
            .expect("msg-2 present");
        let msg3 = after_unhide
            .messages
            .iter()
            .find(|m| m.message_id == "msg-3")
            .expect("msg-3 present");
        assert!(
            msg2.read_by.contains(&member_did),
            "the earlier visible read must still be recorded"
        );
        assert!(
            !msg3.read_by.contains(&member_did),
            "un-hiding must not retroactively reveal a read that happened while hidden"
        );
        assert_eq!(msg3.status, MessageStatus::Delivered);
    }

    #[test]
    fn get_grpc_addr_maps_known_port_ranges_and_named_nodes() {
        assert_eq!(get_grpc_addr("10.0.0.1", "peer:50060"), "10.0.0.1:50260");
        assert_eq!(get_grpc_addr("10.0.0.1", "peer:50160"), "10.0.0.1:50260");
        assert_eq!(get_grpc_addr("10.0.0.1", "peer:50260"), "10.0.0.1:50260");
        assert_eq!(get_grpc_addr("10.0.0.1", "peer:60000"), "10.0.0.1:60100");
        assert_eq!(get_grpc_addr("10.0.0.1", "nodeA"), "10.0.0.1:50251");
        assert_eq!(get_grpc_addr("10.0.0.1", "nodeB"), "10.0.0.1:50252");
        assert_eq!(get_grpc_addr("10.0.0.1", "nodeC"), "10.0.0.1:50253");
        assert_eq!(get_grpc_addr("192.168.1.5", "unknown"), "192.168.1.5:50255");
        assert_eq!(
            get_grpc_addr("192.168.1.20", "unknown"),
            "192.168.1.20:50251"
        );
        assert_eq!(get_grpc_addr("not-an-ip", "unknown"), "not-an-ip:50251");
    }

    #[test]
    fn get_local_nebula_ip_returns_none_without_registry_or_interface() {
        // No overlay registry file and no real `nebula0` interface exist in
        // this sandbox, so both the file-based and `ip`-based lookups
        // deterministically fail.
        assert!(get_local_nebula_ip().is_none());
    }

    #[test]
    fn local_pair_conversation_id_keys_by_the_non_device_side_or_canonical_pair() {
        let td = TempDir::new().expect("tempdir");
        let state = AppState::for_tests(
            td.path(),
            "nodeA",
            td.path().join("config").to_string_lossy().to_string(),
        );
        let other = "did:guardian:other".to_string();
        assert_eq!(
            local_pair_conversation_id(&state, &state.device_did, &other),
            other
        );
        assert_eq!(
            local_pair_conversation_id(&state, &other, &state.device_did),
            other
        );
        assert_eq!(
            local_pair_conversation_id(&state, "did:guardian:aaa", "did:guardian:bbb"),
            "pair-did:guardian:aaa-did:guardian:bbb"
        );
        assert_eq!(
            local_pair_conversation_id(&state, "did:guardian:bbb", "did:guardian:aaa"),
            "pair-did:guardian:aaa-did:guardian:bbb"
        );
    }

    #[test]
    fn payload_matches_request_compares_content_and_attachment_id() {
        let req = SendMessageRequest {
            recipient_did: "did:guardian:x".to_string(),
            content: Some("hi".to_string()),
            attachment_id: None,
            is_group: false,
            message_id: None,
        };
        let payload = request_payload_json(&req, None);
        assert!(payload_matches_request(&payload, &req));

        let other = SendMessageRequest {
            recipient_did: "did:guardian:x".to_string(),
            content: Some("different".to_string()),
            attachment_id: None,
            is_group: false,
            message_id: None,
        };
        assert!(!payload_matches_request(&payload, &other));
        assert!(!payload_matches_request("not json", &req));
    }

    #[tokio::test]
    async fn group_min_reader_count_is_at_least_one_with_no_roster() {
        let td = TempDir::new().expect("tempdir");
        let state = AppState::for_tests(
            td.path(),
            "nodeA",
            td.path().join("config").to_string_lossy().to_string(),
        );
        let count = group_min_reader_count(&state, "no-such-circle", &state.device_did).await;
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn resolve_actor_label_uses_the_device_admin_label_for_the_guardian_itself() {
        let td = TempDir::new().expect("tempdir");
        let state = AppState::for_tests(
            td.path(),
            "nodeA",
            td.path().join("config").to_string_lossy().to_string(),
        );
        let label = resolve_actor_label(&state, &state.device_did).await;
        assert_eq!(label, "the Guardian administrator");

        let fallback = resolve_actor_label(&state, "did:guardian:unregistered").await;
        assert_eq!(fallback, "did:guardian:unregistered");
    }

    #[tokio::test]
    async fn send_message_rejects_a_request_with_neither_content_nor_attachment() {
        let td = TempDir::new().expect("tempdir");
        let state = AppState::for_tests(
            td.path(),
            "nodeA",
            td.path().join("config").to_string_lossy().to_string(),
        );
        let req = SendMessageRequest {
            recipient_did: "did:guardian:someone".to_string(),
            content: None,
            attachment_id: None,
            is_group: false,
            message_id: None,
        };
        let error = send_message(State(state), None, Json(req))
            .await
            .err()
            .expect("must reject empty payload");
        assert!(matches!(error, ApiError::BadRequest(_)));
    }
}
