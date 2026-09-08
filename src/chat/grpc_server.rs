use crate::api::state::AppState;
use crate::chat::models::{ChatMessageRecord, MessageStatus};
use crate::proto::sgx::chat_service_server::ChatService;
use crate::proto::sgx::{PushMessageRequest, PushMessageResponse};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tonic::{Request, Response, Status};

pub struct MyChatService {
    pub state: Arc<AppState>,
}

/// A friendly label for a notification body when the sender is a remote
/// peer's own Guardian (their `User` record lives on their box, not ours,
/// so `resolve_actor_label` can't see it) — falls back to the raw DID only
/// if this peer isn't in the trusted registry.
async fn resolve_remote_peer_label(state: &AppState, did: &str, group_id: Option<&str>) -> String {
    if let Some(group_id) = group_id {
        if let Ok(members) = crate::circle::members::list_members(&state.node_id, group_id) {
            if let Some(member) = members.into_iter().find(|member| member.did == did) {
                if let Some(label) = member.name.or(member.email).or(member.node_hint) {
                    if !label.trim().is_empty() {
                        return label;
                    }
                }
            }
        }
    }
    let peers_path = std::path::Path::new(&state.log_dir_primary).join("trusted_peers.json");
    let peers_json = tokio::fs::read_to_string(&peers_path)
        .await
        .unwrap_or_else(|_| "[]".to_string());
    let raw_peers: Vec<serde_json::Value> = serde_json::from_str(&peers_json).unwrap_or_default();
    raw_peers
        .iter()
        .find(|peer| peer.get("did").and_then(|v| v.as_str()) == Some(did))
        .and_then(|peer| peer.get("peer_id").and_then(|v| v.as_str()))
        .filter(|label| !label.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| did.to_string())
}

#[tonic::async_trait]
impl ChatService for MyChatService {
    async fn push_message(
        &self,
        request: Request<PushMessageRequest>,
    ) -> Result<Response<PushMessageResponse>, Status> {
        let req = request.into_inner();
        let message_id = req.message_id.clone();

        let group_id = if req.group_id.is_empty() {
            None
        } else {
            Some(req.group_id.clone())
        };
        let relay_did = if req.relay_did.trim().is_empty() {
            req.sender_did.clone()
        } else {
            req.relay_did.clone()
        };

        // The overlay authenticates Guardian devices. A browser member has a
        // distinct application DID but no overlay endpoint, so authenticate
        // the relaying Guardian and separately authorize the actor in the
        // message's Circle.
        verify_peer_is_trusted(&self.state, &relay_did).await?;
        verify_relayed_actor(
            &self.state,
            &relay_did,
            &req.sender_did,
            group_id.as_deref(),
        )?;

        // A chat envelope contains only attachment metadata. Pull the bytes
        // from the attested sender before acknowledging the message so the UI
        // never receives a download link for a file absent on this Guardian.
        if let Some(attachment_id) = attachment_id_from_payload(&req.encrypted_payload) {
            let sender_addr = trusted_peer_grpc_addr(&self.state, &relay_did).await?;
            crate::chat::grpc_client::download_attachment_from_peer(
                self.state.device_did.clone(),
                relay_did.clone(),
                sender_addr,
                attachment_id,
                req.sender_did.clone(),
                req.recipient_did.clone(),
                group_id.clone(),
            )
            .await
            .map_err(|error| Status::unavailable(format!("attachment transfer failed: {error}")))?;
        }

        // 2. Save the message locally
        let record = ChatMessageRecord {
            message_id: req.message_id.clone(),
            sender_did: req.sender_did.clone(),
            recipient_did: req.recipient_did.clone(),
            group_id: group_id.clone(),
            timestamp: req.timestamp,
            seq_no: req.seq_no,
            encrypted_payload: req.encrypted_payload.clone(), // plain text over Nebula
            signature: String::new(),
            status: MessageStatus::Delivered,
            read_by: Vec::new(),
        };

        if let Some(ref gid) = group_id {
            crate::chat::storage::append_group_message(gid, &record)
                .await
                .map_err(|e| Status::internal(format!("Failed to save group message: {}", e)))?;
        } else {
            eprintln!(
                "💬 History: storing inbound message under sender_did={} (this is the exact key /chat/history?peer_did=... must match to find it)",
                req.sender_did
            );
            crate::chat::storage::append_p2p_message(&req.sender_did, &record)
                .await
                .map_err(|e| Status::internal(format!("Failed to save message: {}", e)))?;
        }

        let _ = self
            .state
            .chat_events
            .send(crate::chat::models::ChatEvent::NewMessage(record.clone()));
        let sender_label =
            resolve_remote_peer_label(&self.state, &req.sender_did, group_id.as_deref()).await;
        crate::notify::publish_circle_new_message(
            &req.sender_did,
            &sender_label,
            &record.message_id,
        );

        println!(
            "💬 📥 Received message from {} → \"{}\"",
            req.sender_did, req.encrypted_payload
        );

        Ok(Response::new(PushMessageResponse {
            message_id,
            status: "delivered".to_string(),
        }))
    }

    async fn push_receipt(
        &self,
        request: tonic::Request<crate::proto::sgx::PushReceiptRequest>,
    ) -> Result<tonic::Response<crate::proto::sgx::PushReceiptResponse>, tonic::Status> {
        let req = request.into_inner();

        // 0. Verify the sender is in our trusted circle (VC Membership Check)
        verify_peer_is_trusted(&self.state, &req.reader_did).await?;

        let group_id = if req.group_id.is_empty() {
            None
        } else {
            Some(req.group_id.clone())
        };

        let receipt = crate::chat::models::ReadReceiptRecord {
            message_id: req.message_id.clone(),
            reader_did: req.reader_did.clone(),
            group_id: group_id.clone(),
            read_at: req.timestamp,
        };

        crate::chat::storage::append_read_receipt(&receipt)
            .await
            .map_err(|e| Status::internal(format!("Failed to save incoming receipt: {}", e)))?;

        // Update read_by field in stored JSONL log file
        let is_group = group_id.is_some();
        let target_id = group_id.as_deref().unwrap_or(&req.reader_did);
        let min_reader_count = if let Some(gid) = group_id.as_deref() {
            let sender_did = crate::chat::storage::read_group_history(gid)
                .await
                .ok()
                .and_then(|history| {
                    history
                        .into_iter()
                        .find(|message| message.message_id == req.message_id)
                        .map(|message| message.sender_did)
                });
            match sender_did {
                Some(sender_did) => {
                    crate::api::handlers::chat::group_min_reader_count(
                        &self.state,
                        gid,
                        &sender_did,
                    )
                    .await
                }
                None => 1,
            }
        } else {
            1
        };
        let _ = crate::chat::storage::update_message_read_by(
            is_group,
            target_id,
            &req.message_id,
            &req.reader_did,
            min_reader_count,
        )
        .await;

        let _ = self
            .state
            .chat_events
            .send(crate::chat::models::ChatEvent::ReadReceipt(receipt.clone()));

        tracing::info!(
            "✅ Received and logged read receipt for message {} from peer {}",
            req.message_id,
            req.reader_did
        );

        Ok(tonic::Response::new(
            crate::proto::sgx::PushReceiptResponse {
                message_id: req.message_id,
                status: "receipt_logged".to_string(),
            },
        ))
    }

    type SyncMessagesStream = tokio_stream::wrappers::ReceiverStream<
        Result<crate::proto::sgx::PushMessageRequest, tonic::Status>,
    >;

    async fn sync_messages(
        &self,
        request: tonic::Request<crate::proto::sgx::SyncRequest>,
    ) -> Result<tonic::Response<Self::SyncMessagesStream>, tonic::Status> {
        let req = request.into_inner();
        let requester_did = req.requester_did.clone();
        let last_seq = req.last_known_seq_no;

        // 0. Verify the sender is in our trusted circle (VC Membership Check)
        verify_peer_is_trusted(&self.state, &requester_did).await?;

        tracing::info!(
            "🔄 Sync request from {} starting at seq > {}",
            requester_did,
            last_seq
        );

        let history = crate::chat::storage::read_p2p_history(&requester_did)
            .await
            .map_err(|e| tonic::Status::internal(format!("Failed to read history: {}", e)))?;

        let (tx, rx) = tokio::sync::mpsc::channel(100);
        let sync_state = self.state.clone();

        tokio::spawn(async move {
            for record in history {
                if record.seq_no > last_seq {
                    // This peer was offline (or unreachable) when we tried the
                    // original push, leaving our own copy `Pending`. It just
                    // proved it is reachable by requesting this catch-up sync,
                    // so advance our copy to `Delivered` too — otherwise a
                    // message we sent while the recipient was offline would
                    // stay "Pending" forever on our side even after they
                    // caught up.
                    if matches!(
                        record.status,
                        MessageStatus::Pending | MessageStatus::AcceptedByGuardian
                    ) {
                        match crate::chat::storage::update_message_status(
                            false,
                            &requester_did,
                            &record.message_id,
                            MessageStatus::DeliveredToRemoteGuardian,
                        )
                        .await
                        {
                            Ok(Some(updated)) => {
                                let _ = sync_state
                                    .chat_events
                                    .send(crate::chat::models::ChatEvent::MessageStatus(updated));
                            }
                            Ok(None) => {}
                            Err(e) => tracing::warn!(
                                "Failed to mark message {} delivered after sync: {}",
                                record.message_id,
                                e
                            ),
                        }
                    }

                    let msg = crate::proto::sgx::PushMessageRequest {
                        message_id: record.message_id,
                        sender_did: record.sender_did,
                        recipient_did: record.recipient_did,
                        timestamp: record.timestamp,
                        seq_no: record.seq_no,
                        encrypted_payload: record.encrypted_payload,
                        signature: record.signature,
                        group_id: record.group_id.unwrap_or_default(),
                        relay_did: sync_state.device_did.clone(),
                    };

                    if tx.send(Ok(msg)).await.is_err() {
                        tracing::warn!("Sync stream aborted by client {}", requester_did);
                        break;
                    }
                }
            }
            tracing::info!("✅ Sync stream to {} completed", requester_did);
        });

        Ok(tonic::Response::new(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        ))
    }

    type GetAttachmentStream = tokio_stream::wrappers::ReceiverStream<
        Result<crate::proto::sgx::AttachmentChunk, tonic::Status>,
    >;

    async fn get_attachment(
        &self,
        request: tonic::Request<crate::proto::sgx::GetAttachmentRequest>,
    ) -> Result<tonic::Response<Self::GetAttachmentStream>, tonic::Status> {
        let req = request.into_inner();
        verify_peer_is_trusted(&self.state, &req.requester_did).await?;
        let attachment_id = crate::vault::namespace::validate_vault_id(&req.attachment_id)
            .map_err(|_| Status::invalid_argument("invalid attachment ID"))?;

        let vault_config = crate::vault::VaultConfig::from_env();
        let record = crate::vault::persistence::find_record(&vault_config, &attachment_id)
            .await
            .map_err(|error| Status::internal(format!("attachment metadata read failed: {error}")))?
            .ok_or_else(|| Status::not_found("attachment metadata not found"))?;
        if record.revoked {
            return Err(Status::permission_denied("attachment access revoked"));
        }
        if record.is_expired() {
            return Err(Status::not_found("attachment expired"));
        }
        if record.size_plain > crate::chat::storage::MAX_ATTACHMENT_BYTES {
            return Err(Status::resource_exhausted(
                "attachment exceeds 50 MiB limit",
            ));
        }

        // Decrypting to a temp plaintext file both hands us bytes to stream
        // and verifies the on-disk ciphertext against `sha256_plain` (see
        // `vault::crypto::decrypt_file`) before anything is sent to the peer.
        let temp_path = crate::vault::ingest::decrypt_record_to_temp(&record)
            .await
            .map_err(|error| Status::internal(format!("attachment decrypt failed: {error}")))?;
        let mut file = match tokio::fs::File::open(&temp_path).await {
            Ok(file) => file,
            Err(_) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                return Err(Status::not_found("attachment file not found"));
            }
        };

        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let file_name = record.filename.clone();
        let mime_type = record.mime.clone();
        let total_size = record.size_plain;
        let sha256_hash = record.sha256_plain.clone();
        let attachment_id = record.vault_id.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 64 * 1024];
            loop {
                let read = match file.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(read) => read,
                    Err(error) => {
                        let _ = tx
                            .send(Err(Status::internal(format!(
                                "attachment read failed: {error}"
                            ))))
                            .await;
                        let _ = tokio::fs::remove_file(&temp_path).await;
                        return;
                    }
                };
                let chunk = crate::proto::sgx::AttachmentChunk {
                    attachment_id: attachment_id.clone(),
                    file_name: file_name.clone(),
                    mime_type: mime_type.clone(),
                    total_size,
                    sha256_hash: sha256_hash.clone(),
                    data: buffer[..read].to_vec(),
                };
                if tx.send(Ok(chunk)).await.is_err() {
                    let _ = tokio::fs::remove_file(&temp_path).await;
                    return;
                }
            }

            // Empty files still need one metadata-bearing chunk.
            if total_size == 0 {
                let chunk = crate::proto::sgx::AttachmentChunk {
                    attachment_id: attachment_id.clone(),
                    file_name: file_name.clone(),
                    mime_type: mime_type.clone(),
                    total_size: 0,
                    sha256_hash: sha256_hash.clone(),
                    data: Vec::new(),
                };
                let _ = tx.send(Ok(chunk)).await;
            }
            let _ = tokio::fs::remove_file(&temp_path).await;
        });

        Ok(tonic::Response::new(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        ))
    }
}

fn attachment_id_from_payload(payload: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(payload)
        .ok()?
        .get("attachment_id")?
        .as_str()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn verify_relayed_actor(
    state: &AppState,
    relay_did: &str,
    actor_did: &str,
    group_id: Option<&str>,
) -> Result<(), Status> {
    if actor_did == relay_did {
        return Ok(());
    }

    let registry = crate::circle::store::load_or_seed(&state.node_id)
        .map_err(|error| Status::internal(format!("load Circle registry: {error:?}")))?;
    let actor_is_authorized = registry
        .circles
        .into_iter()
        .filter(|circle| {
            !circle.is_archived() && group_id.is_none_or(|expected| circle.circle_id == expected)
        })
        .any(|circle| {
            crate::circle::members::list_members(&state.node_id, &circle.circle_id)
                .map(|members| {
                    let active = members
                        .into_iter()
                        .filter(|member| {
                            matches!(
                                member.lifecycle_state,
                                crate::circle::members::MemberLifecycleState::Active
                            )
                        })
                        .map(|member| member.did)
                        .collect::<std::collections::HashSet<_>>();
                    active.contains(actor_did)
                        && active.contains(relay_did)
                        && active.contains(&state.device_did)
                })
                .unwrap_or(false)
        });

    if actor_is_authorized {
        Ok(())
    } else {
        tracing::warn!(
            actor = actor_did,
            relay = relay_did,
            circle = group_id.unwrap_or("direct"),
            "blocked relayed browser actor outside shared Circle"
        );
        Err(Status::permission_denied(
            "Relayed message actor is not an active member of the shared Circle",
        ))
    }
}

async fn trusted_peer_grpc_addr(state: &Arc<AppState>, did: &str) -> Result<String, Status> {
    let peers = load_trusted_peers(state).await;
    let node_hint = crate::api::handlers::chat::member_node_hint_for_did(state, did);
    let peer = peers.iter().find(|peer| {
        let status = peer.get("status").and_then(|value| value.as_str());
        crate::api::handlers::chat::is_trusted_status(status)
            && crate::api::handlers::chat::peer_matches_identity(peer, did, node_hint.as_deref())
    });
    let peer = peer.ok_or_else(|| Status::permission_denied("sender is not trusted"))?;
    let ip = peer
        .get("ip")
        .and_then(|value| value.as_str())
        .ok_or_else(|| Status::failed_precondition("trusted sender has no overlay IP"))?;
    let peer_id = crate::api::handlers::chat::peer_route_id(peer);
    Ok(crate::api::handlers::chat::get_grpc_addr(ip, peer_id))
}

async fn load_trusted_peers(state: &Arc<AppState>) -> Vec<serde_json::Value> {
    let per_node_name = format!("trusted_peers_{}.json", state.node_id);
    let global_path = std::path::Path::new(&state.log_dir_primary).join("trusted_peers.json");
    let pernode_path = std::path::Path::new(&state.log_dir_primary).join(per_node_name);
    let mut peers: Vec<serde_json::Value> = tokio::fs::read_to_string(global_path)
        .await
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default();
    let per_node: Vec<serde_json::Value> = tokio::fs::read_to_string(pernode_path)
        .await
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default();
    for candidate in per_node {
        let did = candidate.get("did").and_then(|value| value.as_str());
        if did.is_some_and(|did| {
            !peers
                .iter()
                .any(|peer| peer.get("did").and_then(|value| value.as_str()) == Some(did))
        }) {
            peers.push(candidate);
        }
    }
    peers
}

async fn verify_peer_is_trusted(state: &Arc<AppState>, did: &str) -> Result<(), Status> {
    let node_hint = crate::api::handlers::chat::member_node_hint_for_did(state, did);
    let is_trusted = load_trusted_peers(state).await.iter().any(|p| {
        let status = p.get("status").and_then(|v| v.as_str());
        crate::api::handlers::chat::is_trusted_status(status)
            && crate::api::handlers::chat::peer_matches_identity(p, did, node_hint.as_deref())
    });

    if !is_trusted {
        tracing::warn!(
            "Blocked incoming gRPC from untrusted or revoked peer: {}",
            did
        );
        return Err(Status::permission_denied(
            "Sender is not a trusted member of the Circle",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_state(td: &TempDir) -> Arc<AppState> {
        AppState::for_tests(
            td.path(),
            "nodeA",
            td.path().join("config").to_string_lossy().to_string(),
        )
    }

    /// Writes the global trusted-peer registry this Guardian reads.
    fn write_global_registry(state: &AppState, peers: serde_json::Value) {
        let path = std::path::Path::new(&state.log_dir_primary).join("trusted_peers.json");
        std::fs::create_dir_all(path.parent().expect("parent")).expect("log dir");
        std::fs::write(&path, serde_json::to_vec(&peers).expect("serialize")).expect("write");
    }

    /// ...and the per-node one, which is merged in for DIDs the global file
    /// does not already carry.
    fn write_per_node_registry(state: &AppState, peers: serde_json::Value) {
        let path = std::path::Path::new(&state.log_dir_primary)
            .join(format!("trusted_peers_{}.json", state.node_id));
        std::fs::create_dir_all(path.parent().expect("parent")).expect("log dir");
        std::fs::write(&path, serde_json::to_vec(&peers).expect("serialize")).expect("write");
    }

    #[test]
    fn attachment_id_from_payload_extracts_only_a_non_empty_string_id() {
        assert_eq!(
            attachment_id_from_payload(r#"{"attachment_id":"abc-123"}"#).as_deref(),
            Some("abc-123")
        );
        // Absent, empty, wrong type, and not JSON at all.
        assert_eq!(attachment_id_from_payload(r#"{"other":"x"}"#), None);
        assert_eq!(attachment_id_from_payload(r#"{"attachment_id":""}"#), None);
        assert_eq!(attachment_id_from_payload(r#"{"attachment_id":42}"#), None);
        assert_eq!(attachment_id_from_payload("plain text"), None);
        assert_eq!(attachment_id_from_payload(""), None);
    }

    #[tokio::test]
    async fn load_trusted_peers_merges_the_per_node_registry_without_duplicating() {
        let td = TempDir::new().expect("tempdir");
        let state = test_state(&td);

        // Neither file exists yet.
        assert!(load_trusted_peers(&state).await.is_empty());

        write_global_registry(
            &state,
            serde_json::json!([{"peer_id": "nodeB", "status": "verified", "ip": "127.0.0.1", "did": "did:guardian:b"}]),
        );
        write_per_node_registry(
            &state,
            serde_json::json!([
                {"peer_id": "nodeB", "status": "verified", "ip": "127.0.0.9", "did": "did:guardian:b"},
                {"peer_id": "nodeC", "status": "verified", "ip": "127.0.0.3", "did": "did:guardian:c"},
                {"peer_id": "nameless", "status": "verified", "ip": "127.0.0.4"}
            ]),
        );

        let peers = load_trusted_peers(&state).await;
        let dids: Vec<&str> = peers
            .iter()
            .filter_map(|peer| peer.get("did").and_then(|value| value.as_str()))
            .collect();
        assert_eq!(
            dids,
            vec!["did:guardian:b", "did:guardian:c"],
            "the duplicate is skipped and the DID-less entry is not merged"
        );
        // The global entry wins for a DID present in both.
        assert_eq!(
            peers[0].get("ip").and_then(|value| value.as_str()),
            Some("127.0.0.1")
        );
    }

    #[tokio::test]
    async fn load_trusted_peers_tolerates_malformed_registry_files() {
        let td = TempDir::new().expect("tempdir");
        let state = test_state(&td);
        let path = std::path::Path::new(&state.log_dir_primary).join("trusted_peers.json");
        std::fs::create_dir_all(path.parent().expect("parent")).expect("log dir");
        std::fs::write(&path, b"{ not json").expect("write");

        assert!(
            load_trusted_peers(&state).await.is_empty(),
            "a corrupt registry reads as empty rather than panicking"
        );
    }

    #[tokio::test]
    async fn verify_peer_is_trusted_accepts_trusted_dids_and_peer_ids_only() {
        let td = TempDir::new().expect("tempdir");
        let state = test_state(&td);

        // Nothing in the registry at all.
        assert!(verify_peer_is_trusted(&state, "did:guardian:b")
            .await
            .is_err());

        write_global_registry(
            &state,
            serde_json::json!([
                {"peer_id": "nodeB", "status": "verified", "ip": "127.0.0.1", "did": "did:guardian:b"},
                {"peer_id": "nodeC", "status": "trusted", "ip": "127.0.0.3", "did": "did:guardian:c"},
                {"peer_id": "nodeD", "status": "unknown", "ip": "127.0.0.4", "did": "did:guardian:d"}
            ]),
        );

        // Matched by full DID, and by the bare peer id.
        verify_peer_is_trusted(&state, "did:guardian:b")
            .await
            .expect("a verified peer is trusted");
        verify_peer_is_trusted(&state, "did:guardian:c")
            .await
            .expect("a trusted peer is trusted");
        verify_peer_is_trusted(&state, "nodeB")
            .await
            .expect("the bare peer id also matches");

        // Present but not attested, and absent entirely.
        assert!(verify_peer_is_trusted(&state, "did:guardian:d")
            .await
            .is_err());
        assert!(verify_peer_is_trusted(&state, "did:guardian:z")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn trusted_peer_grpc_addr_resolves_an_address_or_explains_why_not() {
        let td = TempDir::new().expect("tempdir");
        let state = test_state(&td);

        // Untrusted sender.
        let error = trusted_peer_grpc_addr(&state, "did:guardian:b")
            .await
            .err()
            .expect("no registry yet");
        assert_eq!(error.code(), tonic::Code::PermissionDenied);

        write_global_registry(
            &state,
            serde_json::json!([
                {"peer_id": "nodeB", "status": "verified", "ip": "127.0.0.1", "did": "did:guardian:b"},
                {"peer_id": "nodeC", "status": "verified", "did": "did:guardian:c"}
            ]),
        );

        let addr = trusted_peer_grpc_addr(&state, "did:guardian:b")
            .await
            .expect("resolves");
        assert!(addr.contains("127.0.0.1"), "{addr}");

        // Trusted, but the registry entry carries no overlay address — a
        // different failure from "not trusted", and reported as such.
        let error = trusted_peer_grpc_addr(&state, "did:guardian:c")
            .await
            .err()
            .expect("no ip");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn verify_relayed_actor_allows_a_self_relay_and_blocks_outsiders() {
        let _lock = crate::test_support::async_env_lock().await;
        let td = TempDir::new().expect("tempdir");
        // The Circle registry is process-global; point it at this tempdir so
        // `load_or_seed` succeeds and yields an empty, Circle-less Guardian
        // rather than failing with an I/O error.
        let previous = std::env::var_os("SGX_GUARDIAN_CIRCLE_BASE");
        std::env::set_var("SGX_GUARDIAN_CIRCLE_BASE", td.path().join("circle-base"));
        let state = test_state(&td);

        // A peer relaying its own message needs no Circle lookup at all.
        verify_relayed_actor(&state, "did:guardian:b", "did:guardian:b", None)
            .expect("a self-relay is always allowed");

        // Relaying on behalf of somebody else requires a shared active Circle.
        // This Guardian has none, so the relay is refused — fail-closed is the
        // property that matters here, and the code distinguishes "no shared
        // Circle" (PermissionDenied) from "the registry could not be read at
        // all" (Internal). Both are denials; which one appears depends on
        // whether a Circle store exists for this node.
        let error = verify_relayed_actor(&state, "did:guardian:b", "did:guardian:x", None)
            .err()
            .expect("an unrelated actor must be blocked");
        assert!(
            matches!(
                error.code(),
                tonic::Code::PermissionDenied | tonic::Code::Internal
            ),
            "relay must fail closed, got {:?}: {}",
            error.code(),
            error.message()
        );

        // Naming a specific group that does not exist is refused the same way.
        let error = verify_relayed_actor(
            &state,
            "did:guardian:b",
            "did:guardian:x",
            Some("no-such-circle"),
        )
        .err()
        .expect("unknown circle");
        assert!(
            matches!(
                error.code(),
                tonic::Code::PermissionDenied | tonic::Code::Internal
            ),
            "naming an unknown Circle must also fail closed, got {:?}",
            error.code()
        );

        match previous {
            Some(value) => std::env::set_var("SGX_GUARDIAN_CIRCLE_BASE", value),
            None => std::env::remove_var("SGX_GUARDIAN_CIRCLE_BASE"),
        }
    }

    #[tokio::test]
    async fn resolve_remote_peer_label_prefers_the_registry_and_falls_back_to_the_did() {
        let td = TempDir::new().expect("tempdir");
        let state = test_state(&td);

        // No registry and no Circle: the DID is its own label.
        assert_eq!(
            resolve_remote_peer_label(&state, "did:guardian:b", None).await,
            "did:guardian:b"
        );

        write_global_registry(
            &state,
            serde_json::json!([
                {"peer_id": "nodeB", "status": "verified", "ip": "127.0.0.1", "did": "did:guardian:b"},
                {"peer_id": "   ", "status": "verified", "ip": "127.0.0.5", "did": "did:guardian:blank"}
            ]),
        );

        assert_eq!(
            resolve_remote_peer_label(&state, "did:guardian:b", None).await,
            "nodeB"
        );
        // A blank label is not a label.
        assert_eq!(
            resolve_remote_peer_label(&state, "did:guardian:blank", None).await,
            "did:guardian:blank"
        );
        // An unknown DID, and a group id that resolves to no Circle members,
        // both fall through to the DID.
        assert_eq!(
            resolve_remote_peer_label(&state, "did:guardian:z", Some("no-such-circle")).await,
            "did:guardian:z"
        );
    }
}
