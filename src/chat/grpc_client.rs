use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::proto::sgx::chat_service_client::ChatServiceClient;
use crate::proto::sgx::{PushMessageRequest, PushReceiptRequest};
use anyhow::Error;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

pub async fn push_message_to_peer(
    addr: String,
    request: PushMessageRequest,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
        // The receiver acknowledges only after any referenced attachment has
        // been pulled and checksum-verified. Allow enough time for 50 MiB on a
        // constrained Guardian link.
        .timeout(std::time::Duration::from_secs(120))
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

pub async fn download_attachment_from_peer(
    local_did: String,
    peer_did: String,
    addr: String,
    attachment_id: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    uuid::Uuid::parse_str(&attachment_id)
        .map_err(|_| Error::msg("invalid attachment ID"))?;
    let destination = crate::chat::storage::attachment_path(&attachment_id);
    if let (Ok(file), Ok(Some(metadata))) = (
        tokio::fs::metadata(&destination).await,
        crate::chat::storage::get_attachment_metadata(&attachment_id).await,
    ) {
        if file.len() == metadata.encrypted_size {
            return Ok(());
        }
    }

    let channel = tonic::transport::Endpoint::from_shared(format!("http://{}", addr))
        .map_err(|error| Error::msg(format!("Invalid endpoint URI: {error}")))?
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(120))
        .connect()
        .await
        .map_err(|error| Error::msg(format!("gRPC connect to {addr} failed: {error}")))?;
    let mut client = ChatServiceClient::new(channel);
    let response = client
        .get_attachment(tonic::Request::new(crate::proto::sgx::GetAttachmentRequest {
            requester_did: local_did,
            attachment_id: attachment_id.clone(),
        }))
        .await
        .map_err(|error| {
            Error::msg(format!(
                "attachment {attachment_id} request from {peer_did} failed: {error}"
            ))
        })?;

    if let Some(parent) = destination.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let temporary = destination.with_extension(format!("part-{}", uuid::Uuid::new_v4()));
    let result: Result<
        crate::chat::models::AttachmentRecord,
        Box<dyn std::error::Error + Send + Sync>,
    > = async {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .await?;
        let mut stream = response.into_inner();
        let mut expected_name: Option<String> = None;
        let mut expected_mime: Option<String> = None;
        let mut expected_size: Option<u64> = None;
        let mut expected_hash: Option<String> = None;
        let mut received = 0u64;
        let mut hasher = Sha256::new();

        while let Some(chunk) = stream.message().await? {
            if chunk.attachment_id != attachment_id {
                return Err(Error::msg("attachment stream ID changed").into());
            }
            if chunk.total_size > crate::chat::storage::MAX_ATTACHMENT_BYTES {
                return Err(Error::msg("attachment exceeds 50 MiB limit").into());
            }
            if let Some(size) = expected_size {
                if size != chunk.total_size
                    || expected_hash.as_deref() != Some(chunk.sha256_hash.as_str())
                    || expected_name.as_deref() != Some(chunk.file_name.as_str())
                    || expected_mime.as_deref() != Some(chunk.mime_type.as_str())
                {
                    return Err(Error::msg("attachment metadata changed during transfer").into());
                }
            } else {
                expected_size = Some(chunk.total_size);
                expected_hash = Some(chunk.sha256_hash.clone());
                expected_name = Some(chunk.file_name.clone());
                expected_mime = Some(chunk.mime_type.clone());
            }
            received = received
                .checked_add(chunk.data.len() as u64)
                .ok_or_else(|| Error::msg("attachment size overflow"))?;
            if received > crate::chat::storage::MAX_ATTACHMENT_BYTES
                || received > chunk.total_size
            {
                return Err(Error::msg("attachment stream exceeded declared size").into());
            }
            hasher.update(&chunk.data);
            file.write_all(&chunk.data).await?;
        }

        let expected_size = expected_size.ok_or_else(|| Error::msg("empty attachment stream"))?;
        let expected_hash = expected_hash.ok_or_else(|| Error::msg("missing attachment checksum"))?;
        if received != expected_size {
            return Err(Error::msg(format!(
                "attachment size mismatch: received {received}, expected {expected_size}"
            ))
            .into());
        }
        let actual_hash = hex::encode(hasher.finalize());
        if actual_hash != expected_hash {
            return Err(Error::msg("attachment checksum mismatch").into());
        }
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&temporary, &destination).await?;

        Ok(crate::chat::models::AttachmentRecord {
            file_id: attachment_id.clone(),
            message_id: "received_attachment".to_string(),
            file_name: expected_name.unwrap_or_else(|| attachment_id.clone()),
            mime_type: expected_mime
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "application/octet-stream".to_string()),
            encrypted_size: received,
            sha256_hash: expected_hash,
            local_path: destination.to_string_lossy().to_string(),
            encrypted_file_key: "nebula_transport".to_string(),
        })
    }
    .await;

    match result {
        Ok(metadata) => {
            crate::chat::storage::append_attachment_metadata_if_absent(&metadata).await?;
            Ok(())
        }
        Err(error) => {
            let _ = tokio::fs::remove_file(&temporary).await;
            Err(error)
        }
    }
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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

        if let Some(attachment_id) = attachment_id_from_payload(&msg.encrypted_payload) {
            download_attachment_from_peer(
                local_did.clone(),
                peer_did.clone(),
                addr.clone(),
                attachment_id,
            )
            .await?;
        }

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

fn attachment_id_from_payload(payload: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(payload)
        .ok()?
        .get("attachment_id")?
        .as_str()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}
