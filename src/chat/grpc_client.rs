use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::proto::sgx::chat_service_client::ChatServiceClient;
use crate::proto::sgx::{PushMessageRequest, PushReceiptRequest};
use crate::vault::namespace::VaultNamespace;
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

/// Pulls a chat attachment from its owning peer and stores it locally as an
/// encrypted `VaultRecord` (`source: ChatAttachment`), so the local copy
/// gets the same AES-256-GCM-at-rest and Circle/DM access control as any
/// other Vault file. `group_id` selects the Circle namespace for a group
/// message; otherwise the attachment lives in the sender's Personal
/// namespace with `recipient_did` recorded so both DM participants on this
/// Guardian can reach it.
#[allow(clippy::too_many_arguments)]
pub async fn download_attachment_from_peer(
    local_did: String,
    peer_did: String,
    addr: String,
    attachment_id: String,
    sender_did: String,
    recipient_did: String,
    group_id: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let attachment_id = crate::vault::namespace::validate_vault_id(&attachment_id)
        .map_err(|_| Error::msg("invalid attachment ID"))?;
    let vault_config = crate::vault::VaultConfig::from_env();
    if let Some(existing) = crate::vault::persistence::find_record(&vault_config, &attachment_id)
        .await
        .unwrap_or(None)
    {
        return Ok(existing).map(|_| ());
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
        .get_attachment(tonic::Request::new(
            crate::proto::sgx::GetAttachmentRequest {
                requester_did: local_did,
                attachment_id: attachment_id.clone(),
            },
        ))
        .await
        .map_err(|error| {
            Error::msg(format!(
                "attachment {attachment_id} request from {peer_did} failed: {error}"
            ))
        })?;

    let staging_path = crate::vault::persistence::staging_dir(&vault_config)
        .join(format!("chat-recv-{}.part", uuid::Uuid::new_v4()));
    if let Some(parent) = staging_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let result: Result<(String, String, u64, String), Box<dyn std::error::Error + Send + Sync>> =
        async {
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&staging_path)
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
                        return Err(
                            Error::msg("attachment metadata changed during transfer").into()
                        );
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

            let expected_size =
                expected_size.ok_or_else(|| Error::msg("empty attachment stream"))?;
            let expected_hash =
                expected_hash.ok_or_else(|| Error::msg("missing attachment checksum"))?;
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

            let file_name = expected_name.unwrap_or_else(|| attachment_id.clone());
            let mime_type = expected_mime
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "application/octet-stream".to_string());
            Ok((file_name, mime_type, received, expected_hash))
        }
        .await;

    let (file_name, mime_type, size_plain, sha256_plain) = match result {
        Ok(value) => value,
        Err(error) => {
            let _ = tokio::fs::remove_file(&staging_path).await;
            return Err(error);
        }
    };

    let namespace = match group_id.filter(|id| !id.is_empty()) {
        Some(circle_id) => VaultNamespace::Circle(circle_id),
        None => VaultNamespace::Personal,
    };
    let conversation_recipient_did = matches!(namespace, VaultNamespace::Personal)
        .then_some(recipient_did)
        .filter(|did| !did.is_empty());

    crate::vault::ingest::ingest_replicated_chat_attachment(
        attachment_id,
        namespace,
        &sender_did,
        &staging_path,
        crate::vault::ingest::IngestMeta {
            filename: file_name,
            mime: mime_type,
            sha256_plain,
            size_plain,
            chunk_bytes: crate::vault::VaultConfig::DEFAULT_CHUNK_BYTES,
        },
        conversation_recipient_did,
    )
    .await?;

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
        let relay_did = if msg.relay_did.trim().is_empty() {
            msg.sender_did.as_str()
        } else {
            msg.relay_did.as_str()
        };
        if relay_did != peer_did && relay_did != local_did {
            return Err(Error::msg(format!(
                "Security Violation: Peer {} claimed relay {}",
                peer_did, relay_did
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
                msg.sender_did.clone(),
                msg.recipient_did.clone(),
                group_id.clone(),
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
        crate::notify::publish_circle_new_message(
            &record.sender_did,
            &record.sender_did,
            &record.message_id,
        );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attachment_id_from_payload_extracts_a_present_non_empty_id() {
        assert_eq!(
            attachment_id_from_payload(r#"{"attachment_id":"urn-1","text":"hi"}"#),
            Some("urn-1".to_string())
        );
    }

    #[test]
    fn attachment_id_from_payload_returns_none_when_absent_empty_or_malformed() {
        assert_eq!(attachment_id_from_payload(r#"{"text":"hi"}"#), None);
        assert_eq!(attachment_id_from_payload(r#"{"attachment_id":""}"#), None);
        assert_eq!(attachment_id_from_payload("not json"), None);
        assert_eq!(attachment_id_from_payload(r#"{"attachment_id":42}"#), None);
    }
}
