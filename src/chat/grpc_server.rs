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

#[tonic::async_trait]
impl ChatService for MyChatService {
    async fn push_message(
        &self,
        request: Request<PushMessageRequest>,
    ) -> Result<Response<PushMessageResponse>, Status> {
        let req = request.into_inner();
        let message_id = req.message_id.clone();

        // 1. Verify sender is a trusted attested peer
        verify_peer_is_trusted(&self.state, &req.sender_did).await?;

        let group_id = if req.group_id.is_empty() {
            None
        } else {
            Some(req.group_id.clone())
        };

        // A chat envelope contains only attachment metadata. Pull the bytes
        // from the attested sender before acknowledging the message so the UI
        // never receives a download link for a file absent on this Guardian.
        if let Some(attachment_id) = attachment_id_from_payload(&req.encrypted_payload) {
            let sender_addr = trusted_peer_grpc_addr(&self.state, &req.sender_did).await?;
            crate::chat::grpc_client::download_attachment_from_peer(
                self.state.device_did.clone(),
                req.sender_did.clone(),
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
            crate::chat::storage::append_p2p_message(&req.sender_did, &record)
                .await
                .map_err(|e| Status::internal(format!("Failed to save message: {}", e)))?;
        }

        let _ = self
            .state
            .chat_events
            .send(crate::chat::models::ChatEvent::NewMessage(record.clone()));
        crate::notify::publish_circle_new_message(&req.sender_did, &record.message_id);

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
                    crate::api::handlers::chat::group_min_reader_count(&self.state, gid, &sender_did)
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
            return Err(Status::resource_exhausted("attachment exceeds 50 MiB limit"));
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

async fn trusted_peer_grpc_addr(state: &Arc<AppState>, did: &str) -> Result<String, Status> {
    let peers = load_trusted_peers(state).await;
    let target_peer_id = did.strip_prefix("did:guardian:").unwrap_or(did);
    let peer = peers.iter().find(|peer| {
        let status = peer.get("status").and_then(|value| value.as_str());
        matches!(status, Some("trusted" | "verified"))
            && (peer.get("did").and_then(|value| value.as_str()) == Some(did)
                || peer.get("peer_id").and_then(|value| value.as_str()) == Some(target_peer_id))
    });
    let peer = peer.ok_or_else(|| Status::permission_denied("sender is not trusted"))?;
    let ip = peer
        .get("ip")
        .and_then(|value| value.as_str())
        .ok_or_else(|| Status::failed_precondition("trusted sender has no overlay IP"))?;
    let peer_id = peer
        .get("peer_id")
        .and_then(|value| value.as_str())
        .unwrap_or(target_peer_id);
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
    let target_peer_id = did.strip_prefix("did:guardian:").unwrap_or(did);
    let is_trusted = load_trusted_peers(state).await.iter().any(|p| {
        let status = p.get("status").and_then(|v| v.as_str());
        let is_valid_status = status == Some("trusted") || status == Some("verified");
        let matches_did = p.get("did").and_then(|v| v.as_str()) == Some(did)
            || p.get("peer_id").and_then(|v| v.as_str()) == Some(target_peer_id);
        is_valid_status && matches_did
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
