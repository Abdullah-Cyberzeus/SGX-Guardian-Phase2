use crate::api::state::AppState;
use crate::chat::models::{ChatMessageRecord, MessageStatus};
use crate::proto::sgx::chat_service_server::ChatService;
use crate::proto::sgx::{PushMessageRequest, PushMessageResponse};
use std::sync::Arc;
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
        let _ = crate::chat::storage::update_message_read_by(
            is_group,
            target_id,
            &req.message_id,
            &req.reader_did,
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
                    if record.status == MessageStatus::Pending {
                        match crate::chat::storage::update_message_status(
                            false,
                            &requester_did,
                            &record.message_id,
                            MessageStatus::Delivered,
                        )
                        .await
                        {
                            Ok(Some(updated)) => {
                                let _ = sync_state.chat_events.send(
                                    crate::chat::models::ChatEvent::MessageStatus(updated),
                                );
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
}

async fn verify_peer_is_trusted(state: &Arc<AppState>, did: &str) -> Result<(), Status> {
    let target_peer_id = did.strip_prefix("did:guardian:").unwrap_or(did);

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

    let is_trusted = global_peers.iter().any(|p| {
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
