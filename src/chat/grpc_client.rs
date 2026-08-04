use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::proto::sgx::chat_service_client::ChatServiceClient;
use crate::proto::sgx::{PushMessageRequest, PushReceiptRequest};
use anyhow::Error;

pub async fn push_message_to_peer(
    addr: String,
    request: PushMessageRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let from_id = request.sender_did.clone();

    log_audit(
        &from_id,
        AuditCategory::Network,
        AuditSeverity::Info,
        AuditAction::Started,
        &format!("Outbound Chat push attempt to {}", addr),
    );

    let channel = tonic::transport::Endpoint::from_shared(format!("http://{}", addr))
        .map_err(|e| Error::msg(format!("Invalid endpoint URI: {}", e)))?
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .connect()
        .await
        .map_err(|e| Error::msg(format!("gRPC connect to {} failed: {}", addr, e)))?;

    let mut client = ChatServiceClient::new(channel);
    let response = match client.push_message(tonic::Request::new(request)).await {
        Ok(resp) => resp,
        Err(e) => {
            log_audit(
                &from_id,
                AuditCategory::Network,
                AuditSeverity::Warning,
                AuditAction::Failed,
                &format!("Push message failed to {}: {}", addr, e),
            );
            return Err(Error::msg(e.to_string()).into());
        }
    };

    let status = response.into_inner().status;
    tracing::info!("🎉 gRPC Chat Message delivered! Status: {}", status);

    log_audit(
        &from_id,
        AuditCategory::Network,
        AuditSeverity::Info,
        AuditAction::Succeeded,
        &format!("Secure chat push succeeded to {}", addr),
    );

    Ok(())
}

pub async fn push_receipt_to_peer(
    _peer_did: String,
    addr: String,
    request: PushReceiptRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let reader_id = request.reader_did.clone();

    log_audit(
        &reader_id,
        AuditCategory::Network,
        AuditSeverity::Info,
        AuditAction::Started,
        &format!("Outbound Chat receipt push attempt to {}", addr),
    );

    let channel = tonic::transport::Endpoint::from_shared(format!("http://{}", addr))
        .map_err(|e| Error::msg(format!("Invalid endpoint URI: {}", e)))?
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .connect()
        .await
        .map_err(|e| Error::msg(format!("gRPC connect to {} failed: {}", addr, e)))?;

    let mut client = ChatServiceClient::new(channel);
    let response = match client.push_receipt(tonic::Request::new(request)).await {
        Ok(resp) => resp,
        Err(e) => {
            log_audit(
                &reader_id,
                AuditCategory::Network,
                AuditSeverity::Warning,
                AuditAction::Failed,
                &format!("Push receipt failed to {}: {}", addr, e),
            );
            return Err(Error::msg(e.to_string()).into());
        }
    };

    let status = response.into_inner().status;
    tracing::info!("🎉 gRPC Chat Receipt delivered! Status: {}", status);

    log_audit(
        &reader_id,
        AuditCategory::Network,
        AuditSeverity::Info,
        AuditAction::Succeeded,
        &format!("Secure chat receipt push succeeded to {}", addr),
    );

    Ok(())
}

pub async fn request_sync_from_peer(
    local_did: String,
    peer_did: String,
    addr: String,
    last_known_seq_no: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    log_audit(
        &local_did,
        AuditCategory::Network,
        AuditSeverity::Info,
        AuditAction::Started,
        &format!(
            "Outbound Chat sync request to {} (seq > {})",
            addr, last_known_seq_no
        ),
    );

    let channel = tonic::transport::Endpoint::from_shared(format!("http://{}", addr))
        .map_err(|e| Error::msg(format!("Invalid endpoint URI: {}", e)))?
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .connect()
        .await
        .map_err(|e| Error::msg(format!("gRPC connect to {} failed: {}", addr, e)))?;

    let mut client = ChatServiceClient::new(channel);
    let request = crate::proto::sgx::SyncRequest {
        requester_did: local_did.clone(),
        last_known_seq_no,
    };

    let response = match client.sync_messages(tonic::Request::new(request)).await {
        Ok(resp) => resp,
        Err(e) => {
            log_audit(
                &local_did,
                AuditCategory::Network,
                AuditSeverity::Warning,
                AuditAction::Failed,
                &format!("Sync request failed to {}: {}", addr, e),
            );
            return Err(Error::msg(e.to_string()).into());
        }
    };

    let mut stream = response.into_inner();
    let mut synced_count = 0;

    // Iteratively process the incoming server stream of missed messages
    loop {
        let msg = match stream.message().await {
            Ok(Some(msg)) => msg,
            Ok(None) => break,
            Err(e) => {
                log_audit(
                    &local_did,
                    AuditCategory::Network,
                    AuditSeverity::Warning,
                    AuditAction::Failed,
                    &format!("Sync stream failed from {}: {}", addr, e),
                );
                return Err(Error::msg(e.to_string()).into());
            }
        };

        // CRITICAL SECURITY FIX: Prevent cross-conversation message injection
        // A compromised or misbehaving peer could relay validly signed messages from other conversations.
        // We must enforce that the message truly belongs to the conversation between us and peer_did.
        if msg.sender_did != peer_did && msg.sender_did != local_did {
            return Err(Error::msg(format!(
                "Security Violation: Peer {} attempted to inject a message from sender {}",
                peer_did, msg.sender_did
            ))
            .into());
        }
        if msg.recipient_did != local_did && msg.recipient_did != peer_did {
            return Err(Error::msg(format!(
                "Security Violation: Peer {} attempted to inject a message intended for {}",
                peer_did, msg.recipient_did
            ))
            .into());
        }
        if msg.sender_did == msg.recipient_did {
            return Err(
                Error::msg("Security Violation: Sender and recipient cannot be identical").into(),
            );
        }

        let group_id = if msg.group_id.is_empty() {
            None
        } else {
            Some(msg.group_id.clone())
        };

        let record = crate::chat::models::ChatMessageRecord {
            message_id: msg.message_id,
            sender_did: msg.sender_did,
            recipient_did: msg.recipient_did,
            group_id: group_id.clone(),
            timestamp: msg.timestamp,
            seq_no: msg.seq_no,
            encrypted_payload: msg.encrypted_payload,
            signature: msg.signature,
            status: crate::chat::models::MessageStatus::Delivered,
            read_by: Vec::new(),
        };

        if let Some(ref gid) = group_id {
            crate::chat::storage::append_group_message(gid, &record)
                .await
                .map_err(|e| {
                    Error::msg(format!(
                        "Failed to save synced group message from {}: {}",
                        peer_did, e
                    ))
                })?;
        } else {
            crate::chat::storage::append_p2p_message(&peer_did, &record)
                .await
                .map_err(|e| {
                    Error::msg(format!(
                        "Failed to save synced message from {}: {}",
                        peer_did, e
                    ))
                })?;
        }
        synced_count += 1;
    }

    tracing::info!(
        "🎉 Successfully synced {} missing messages from {}",
        synced_count,
        addr
    );

    log_audit(
        &local_did,
        AuditCategory::Network,
        AuditSeverity::Info,
        AuditAction::Succeeded,
        &format!(
            "Successfully synced {} messages from {}",
            synced_count, addr
        ),
    );

    Ok(())
}
