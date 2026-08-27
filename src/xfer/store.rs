use crate::xfer::errors::XferError;
use crate::xfer::manifest::FileManifest;
use crate::xfer::persistence;
use chrono::Utc;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use tokio::sync::Mutex;

/// Serializes every xfer state read-modify-write in this process.
pub static XFER_WRITE_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransferStatus {
    Queued,
    Connecting,
    Sending,
    Receiving,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiverState {
    pub transfer_id: String,
    pub circle_id: String,
    pub sender_did: String,
    pub filename: String,
    pub size: u64,
    pub chunk_bytes: u32,
    pub chunk_count: u32,
    pub file_sha256: String,
    pub received_chunks: Vec<u32>,
    pub status: TransferStatus,
    pub updated_at: String,
    pub completed_at: Option<String>,
    pub last_error: Option<String>,
    pub vault_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderProgress {
    pub transfer_id: String,
    pub circle_id: String,
    /// UI/application actor that initiated the transfer. For legacy records
    /// this is empty and the owning Guardian DID is used by the API.
    #[serde(default)]
    pub actor_did: String,
    pub peer_did: String,
    pub filename: String,
    pub file_path: String,
    pub size: u64,
    pub chunk_bytes: u32,
    pub chunk_count: u32,
    pub requested_chunks: u32,
    pub sent_chunks: u32,
    pub bytes_sent: u64,
    pub status: TransferStatus,
    pub updated_at: String,
    pub completed_at: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxItem {
    pub transfer_id: String,
    pub circle_id: String,
    pub sender_did: String,
    pub filename: String,
    pub size: u64,
    pub completed: bool,
    pub path: Option<String>,
    pub updated_at: String,
    pub completed_at: Option<String>,
    pub file_sha256: String,
    pub vault_id: Option<String>,
    pub download_path: Option<String>,
    pub vault_available: bool,
}

/// Audit/UI receipt for a transfer between two identities hosted by the same
/// Guardian. The network XFER engine is intentionally bypassed for this case,
/// but the sender and recipient must still see separate Outbox/Inbox entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalTransferRecord {
    pub transfer_id: String,
    pub circle_id: String,
    pub sender_did: String,
    pub recipient_did: String,
    pub filename: String,
    pub size: u64,
    pub file_sha256: String,
    pub vault_id: String,
    pub updated_at: String,
    pub completed_at: String,
}

impl ReceiverState {
    pub fn have_chunks(&self) -> Vec<u32> {
        self.received_chunks.clone()
    }
}

pub async fn load_manifest(
    circle_id: &str,
    transfer_id: &str,
) -> Result<Option<FileManifest>, XferError> {
    persistence::read_json_if_exists(&persistence::manifest_path(circle_id, transfer_id)).await
}

pub async fn load_receiver_state(
    circle_id: &str,
    transfer_id: &str,
) -> Result<Option<ReceiverState>, XferError> {
    persistence::read_json_if_exists(&persistence::state_path(circle_id, transfer_id)).await
}

pub async fn find_receiver_state(transfer_id: &str) -> Result<Option<ReceiverState>, XferError> {
    let mut circles = match tokio::fs::read_dir(persistence::inbox_dir()).await {
        Ok(dir) => dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    while let Some(circle) = circles.next_entry().await? {
        if !circle.file_type().await?.is_dir() {
            continue;
        }
        let path = circle.path().join(transfer_id).join("state.json");
        if let Some(state) = persistence::read_json_if_exists(&path).await? {
            return Ok(Some(state));
        }
    }
    Ok(None)
}

pub async fn prepare_receiver(manifest: &FileManifest) -> Result<ReceiverState, XferError> {
    manifest.validate_shape()?;
    let _guard = XFER_WRITE_LOCK.lock().await;
    let dir = persistence::inbox_transfer_dir(&manifest.circle_id, &manifest.transfer_id);
    tokio::fs::create_dir_all(&dir).await?;

    match load_manifest(&manifest.circle_id, &manifest.transfer_id).await? {
        Some(existing) if !same_manifest_core(&existing, manifest) => {
            return Err(XferError::Conflict(format!(
                "transfer_id {} already exists with different manifest",
                manifest.transfer_id
            )));
        }
        Some(_) => {}
        None => {
            persistence::save_json_pretty(
                &persistence::manifest_path(&manifest.circle_id, &manifest.transfer_id),
                manifest,
            )
            .await?;
        }
    }

    let now = Utc::now().to_rfc3339();
    let state = match load_receiver_state(&manifest.circle_id, &manifest.transfer_id).await? {
        Some(mut state) => {
            validate_receiver_state(&state, manifest)?;
            if state.status != TransferStatus::Completed {
                state.status = TransferStatus::Receiving;
            }
            state.updated_at = now;
            state
        }
        None => ReceiverState {
            transfer_id: manifest.transfer_id.clone(),
            circle_id: manifest.circle_id.clone(),
            sender_did: manifest.sender_did.clone(),
            filename: manifest.filename.clone(),
            size: manifest.size,
            chunk_bytes: manifest.chunk_bytes,
            chunk_count: manifest.chunk_count,
            file_sha256: manifest.file_sha256.clone(),
            received_chunks: Vec::new(),
            status: TransferStatus::Receiving,
            updated_at: now,
            completed_at: None,
            last_error: None,
            vault_id: None,
        },
    };
    persistence::save_json_pretty(
        &persistence::state_path(&manifest.circle_id, &manifest.transfer_id),
        &state,
    )
    .await?;
    Ok(state)
}

pub async fn record_chunk(manifest: &FileManifest, index: u32) -> Result<ReceiverState, XferError> {
    let _guard = XFER_WRITE_LOCK.lock().await;
    let mut state = load_receiver_state(&manifest.circle_id, &manifest.transfer_id)
        .await?
        .ok_or_else(|| XferError::TransferNotFound(manifest.transfer_id.clone()))?;
    validate_receiver_state(&state, manifest)?;
    let mut chunks = state
        .received_chunks
        .iter()
        .copied()
        .collect::<BTreeSet<u32>>();
    chunks.insert(index);
    state.received_chunks = chunks.into_iter().collect();
    state.status = TransferStatus::Receiving;
    state.last_error = None;
    state.updated_at = Utc::now().to_rfc3339();
    persistence::save_json_pretty(
        &persistence::state_path(&manifest.circle_id, &manifest.transfer_id),
        &state,
    )
    .await?;
    Ok(state)
}

pub async fn mark_receiver_complete(manifest: &FileManifest) -> Result<ReceiverState, XferError> {
    let _guard = XFER_WRITE_LOCK.lock().await;
    let mut state = load_receiver_state(&manifest.circle_id, &manifest.transfer_id)
        .await?
        .ok_or_else(|| XferError::TransferNotFound(manifest.transfer_id.clone()))?;
    validate_receiver_state(&state, manifest)?;
    state.status = TransferStatus::Completed;
    state.received_chunks = (0..manifest.chunk_count).collect();
    state.updated_at = Utc::now().to_rfc3339();
    state.completed_at = Some(state.updated_at.clone());
    state.last_error = None;
    state.vault_id = None;
    persistence::save_json_pretty(
        &persistence::state_path(&manifest.circle_id, &manifest.transfer_id),
        &state,
    )
    .await?;
    Ok(state)
}

pub async fn mark_receiver_complete_with_vault(
    manifest: &FileManifest,
    vault_id: &str,
) -> Result<ReceiverState, XferError> {
    let _guard = XFER_WRITE_LOCK.lock().await;
    let mut state = load_receiver_state(&manifest.circle_id, &manifest.transfer_id)
        .await?
        .ok_or_else(|| XferError::TransferNotFound(manifest.transfer_id.clone()))?;
    validate_receiver_state(&state, manifest)?;
    state.status = TransferStatus::Completed;
    state.received_chunks = (0..manifest.chunk_count).collect();
    state.updated_at = Utc::now().to_rfc3339();
    state.completed_at = Some(state.updated_at.clone());
    state.last_error = None;
    state.vault_id = Some(vault_id.to_string());
    persistence::save_json_pretty(
        &persistence::state_path(&manifest.circle_id, &manifest.transfer_id),
        &state,
    )
    .await?;
    Ok(state)
}

pub async fn mark_receiver_failed(
    manifest: &FileManifest,
    error: &str,
) -> Result<ReceiverState, XferError> {
    let _guard = XFER_WRITE_LOCK.lock().await;
    let mut state = load_receiver_state(&manifest.circle_id, &manifest.transfer_id)
        .await?
        .ok_or_else(|| XferError::TransferNotFound(manifest.transfer_id.clone()))?;
    validate_receiver_state(&state, manifest)?;
    state.status = TransferStatus::Failed;
    state.updated_at = Utc::now().to_rfc3339();
    state.last_error = Some(error.to_string());
    persistence::save_json_pretty(
        &persistence::state_path(&manifest.circle_id, &manifest.transfer_id),
        &state,
    )
    .await?;
    Ok(state)
}

pub async fn create_outbox(
    actor_did: &str,
    peer_did: &str,
    file_path: &str,
    manifest: &FileManifest,
) -> Result<SenderProgress, XferError> {
    let _guard = XFER_WRITE_LOCK.lock().await;
    let progress = SenderProgress {
        transfer_id: manifest.transfer_id.clone(),
        circle_id: manifest.circle_id.clone(),
        actor_did: actor_did.to_string(),
        peer_did: peer_did.to_string(),
        filename: manifest.filename.clone(),
        file_path: file_path.to_string(),
        size: manifest.size,
        chunk_bytes: manifest.chunk_bytes,
        chunk_count: manifest.chunk_count,
        requested_chunks: manifest.chunk_count,
        sent_chunks: 0,
        bytes_sent: 0,
        status: TransferStatus::Queued,
        updated_at: Utc::now().to_rfc3339(),
        completed_at: None,
        last_error: None,
    };
    persistence::save_json_pretty(&persistence::outbox_path(&manifest.transfer_id), &progress)
        .await?;
    Ok(progress)
}

pub async fn load_outbox(transfer_id: &str) -> Result<Option<SenderProgress>, XferError> {
    persistence::read_json_if_exists(&persistence::outbox_path(transfer_id)).await
}

pub async fn update_outbox<F>(transfer_id: &str, update: F) -> Result<SenderProgress, XferError>
where
    F: FnOnce(&mut SenderProgress),
{
    let _guard = XFER_WRITE_LOCK.lock().await;
    let mut progress = load_outbox(transfer_id)
        .await?
        .ok_or_else(|| XferError::TransferNotFound(transfer_id.to_string()))?;
    update(&mut progress);
    progress.updated_at = Utc::now().to_rfc3339();
    persistence::save_json_pretty(&persistence::outbox_path(transfer_id), &progress).await?;
    Ok(progress)
}

pub async fn list_outbox() -> Result<Vec<SenderProgress>, XferError> {
    let mut dir = match tokio::fs::read_dir(persistence::outbox_dir()).await {
        Ok(dir) => dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut out = Vec::new();
    while let Some(entry) = dir.next_entry().await? {
        if !entry.file_type().await?.is_file() {
            continue;
        }
        let Ok(progress) = persistence::read_json::<SenderProgress>(&entry.path()).await else {
            continue;
        };
        out.push(progress);
    }
    out.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    Ok(out)
}

pub async fn save_local_transfer(record: &LocalTransferRecord) -> Result<(), XferError> {
    let _guard = XFER_WRITE_LOCK.lock().await;
    persistence::save_json_pretty(
        &persistence::local_transfer_path(&record.transfer_id),
        record,
    )
    .await
}

pub async fn load_local_transfer(
    transfer_id: &str,
) -> Result<Option<LocalTransferRecord>, XferError> {
    persistence::read_json_if_exists(&persistence::local_transfer_path(transfer_id)).await
}

pub async fn list_local_transfers() -> Result<Vec<LocalTransferRecord>, XferError> {
    let mut dir = match tokio::fs::read_dir(persistence::local_dir()).await {
        Ok(dir) => dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut out = Vec::new();
    while let Some(entry) = dir.next_entry().await? {
        if !entry.file_type().await?.is_file() {
            continue;
        }
        let Ok(record) = persistence::read_json::<LocalTransferRecord>(&entry.path()).await else {
            continue;
        };
        out.push(record);
    }
    out.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    Ok(out)
}

pub async fn list_inbox() -> Result<Vec<InboxItem>, XferError> {
    let mut out = Vec::new();
    let vault_config = crate::vault::VaultConfig::from_env();
    let mut circles = match tokio::fs::read_dir(persistence::inbox_dir()).await {
        Ok(dir) => dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(error) => return Err(error.into()),
    };
    while let Some(circle) = circles.next_entry().await? {
        if !circle.file_type().await?.is_dir() {
            continue;
        }
        let circle_id = circle.file_name().to_string_lossy().to_string();
        let mut transfers = tokio::fs::read_dir(circle.path()).await?;
        while let Some(transfer) = transfers.next_entry().await? {
            if !transfer.file_type().await?.is_dir() {
                continue;
            }
            let transfer_id = transfer.file_name().to_string_lossy().to_string();
            let Some(manifest) = load_manifest(&circle_id, &transfer_id).await? else {
                continue;
            };
            let state = load_receiver_state(&circle_id, &transfer_id).await?;
            let completed = state
                .as_ref()
                .map(|value| value.status == TransferStatus::Completed)
                .unwrap_or(false);
            let vault_id = state.as_ref().and_then(|value| value.vault_id.clone());
            let (path, download_path, vault_available) = if completed {
                if let Some(vault_id) = vault_id.as_deref() {
                    match crate::vault::persistence::find_record(&vault_config, vault_id).await {
                        Ok(Some(_)) => {
                            let download_path = Some(crate::vault::download_path(vault_id));
                            (download_path.clone(), download_path, true)
                        }
                        Ok(None) => (None, None, false),
                        Err(error) => {
                            return Err(match error {
                                crate::vault::VaultError::Io(io) => io.into(),
                                crate::vault::VaultError::Json(json) => json.into(),
                                other => XferError::InvalidStructure(format!(
                                    "vault lookup failed for {}: {}",
                                    vault_id, other
                                )),
                            });
                        }
                    }
                } else {
                    (
                        Some(
                            persistence::final_path(&circle_id, &transfer_id, &manifest.filename)
                                .display()
                                .to_string(),
                        ),
                        None,
                        false,
                    )
                }
            } else {
                (
                    Some(
                        persistence::part_path(&circle_id, &transfer_id, &manifest.filename)
                            .display()
                            .to_string(),
                    ),
                    None,
                    false,
                )
            };
            let updated_at = state
                .as_ref()
                .map(|value| value.updated_at.clone())
                .unwrap_or_else(|| manifest.created_at.clone());
            let completed_at = state.as_ref().and_then(|value| value.completed_at.clone());
            out.push(InboxItem {
                transfer_id: manifest.transfer_id.clone(),
                circle_id: manifest.circle_id.clone(),
                sender_did: manifest.sender_did.clone(),
                filename: manifest.filename.clone(),
                size: manifest.size,
                completed,
                path,
                updated_at,
                completed_at,
                file_sha256: manifest.file_sha256.clone(),
                vault_id,
                download_path,
                vault_available,
            });
        }
    }
    out.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    Ok(out)
}

pub async fn cancel_transfer_files(transfer_id: &str) -> Result<bool, XferError> {
    let mut found = false;
    let mut circles = match tokio::fs::read_dir(persistence::inbox_dir()).await {
        Ok(dir) => dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    while let Some(circle) = circles.next_entry().await? {
        if !circle.file_type().await?.is_dir() {
            continue;
        }
        let circle_id = circle.file_name().to_string_lossy().to_string();
        let transfer_dir = circle.path().join(transfer_id);
        if !tokio::fs::try_exists(&transfer_dir).await? {
            continue;
        }
        found |= remove_receiver_transfer_dir(&circle_id, transfer_id).await?;
    }
    Ok(found)
}

pub async fn remove_receiver_transfer_dir(
    circle_id: &str,
    transfer_id: &str,
) -> Result<bool, XferError> {
    let _guard = XFER_WRITE_LOCK.lock().await;
    let transfer_dir = persistence::inbox_transfer_dir(circle_id, transfer_id);
    match tokio::fs::remove_dir_all(&transfer_dir).await {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn same_manifest_core(left: &FileManifest, right: &FileManifest) -> bool {
    left.transfer_id == right.transfer_id
        && left.circle_id == right.circle_id
        && left.sender_did == right.sender_did
        && left.filename == right.filename
        && left.size == right.size
        && left.chunk_bytes == right.chunk_bytes
        && left.chunk_count == right.chunk_count
        && left.chunk_digests == right.chunk_digests
        && left.file_sha256 == right.file_sha256
}

fn validate_receiver_state(
    state: &ReceiverState,
    manifest: &FileManifest,
) -> Result<(), XferError> {
    if state.transfer_id != manifest.transfer_id
        || state.circle_id != manifest.circle_id
        || state.sender_did != manifest.sender_did
        || state.filename != manifest.filename
        || state.size != manifest.size
        || state.chunk_bytes != manifest.chunk_bytes
        || state.chunk_count != manifest.chunk_count
        || state.file_sha256 != manifest.file_sha256
    {
        return Err(XferError::Conflict(format!(
            "persisted state for {} does not match manifest",
            manifest.transfer_id
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::document::Proof;

    fn sample_manifest() -> FileManifest {
        FileManifest {
            transfer_id: "xfer-123".into(),
            circle_id: "circle-abc".into(),
            sender_did: "did:guardian:sender1".into(),
            filename: "report.pdf".into(),
            size: 1024,
            chunk_bytes: 512,
            chunk_count: 2,
            chunk_digests: vec!["hash1".into(), "hash2".into()],
            file_sha256: "filehash123".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            proof: Proof::default(),
        }
    }

    #[test]
    fn test_transfer_status_serde_roundtrip() {
        let statuses = vec![
            (TransferStatus::Queued, "\"queued\""),
            (TransferStatus::Connecting, "\"connecting\""),
            (TransferStatus::Sending, "\"sending\""),
            (TransferStatus::Receiving, "\"receiving\""),
            (TransferStatus::Completed, "\"completed\""),
            (TransferStatus::Failed, "\"failed\""),
            (TransferStatus::Cancelled, "\"cancelled\""),
        ];

        for (status, expected_json) in statuses {
            let serialized = serde_json::to_string(&status).unwrap();
            assert_eq!(serialized, expected_json);
            let deserialized: TransferStatus = serde_json::from_str(&serialized).unwrap();
            assert_eq!(deserialized, status);
        }
    }

    #[test]
    fn test_receiver_state_have_chunks() {
        let state = ReceiverState {
            transfer_id: "xfer-1".into(),
            circle_id: "c1".into(),
            sender_did: "did:guardian:s1".into(),
            filename: "test.txt".into(),
            size: 100,
            chunk_bytes: 50,
            chunk_count: 2,
            file_sha256: "sha".into(),
            received_chunks: vec![0, 1],
            status: TransferStatus::Completed,
            updated_at: "2026-01-01T00:00:00Z".into(),
            completed_at: Some("2026-01-01T00:01:00Z".into()),
            last_error: None,
            vault_id: Some("v1".into()),
        };

        assert_eq!(state.have_chunks(), vec![0, 1]);
    }

    #[test]
    fn test_same_manifest_core_comparison() {
        let manifest_a = sample_manifest();
        let mut manifest_b = manifest_a.clone();
        // Changing non-core proof or created_at does not change core equality
        manifest_b.created_at = "2026-02-02T00:00:00Z".into();
        assert!(same_manifest_core(&manifest_a, &manifest_b));

        // Changing a core field like filename causes difference
        let mut manifest_c = manifest_a.clone();
        manifest_c.filename = "different.pdf".into();
        assert!(!same_manifest_core(&manifest_a, &manifest_c));

        // Changing size causes difference
        let mut manifest_d = manifest_a.clone();
        manifest_d.size = 2048;
        assert!(!same_manifest_core(&manifest_a, &manifest_d));
    }

    #[test]
    fn test_validate_receiver_state_success_and_conflict() {
        let manifest = sample_manifest();
        let state = ReceiverState {
            transfer_id: manifest.transfer_id.clone(),
            circle_id: manifest.circle_id.clone(),
            sender_did: manifest.sender_did.clone(),
            filename: manifest.filename.clone(),
            size: manifest.size,
            chunk_bytes: manifest.chunk_bytes,
            chunk_count: manifest.chunk_count,
            file_sha256: manifest.file_sha256.clone(),
            received_chunks: vec![],
            status: TransferStatus::Receiving,
            updated_at: "2026-01-01T00:00:00Z".into(),
            completed_at: None,
            last_error: None,
            vault_id: None,
        };

        assert!(validate_receiver_state(&state, &manifest).is_ok());

        // Tampered sha256 in state must be rejected
        let mut tampered_state = state.clone();
        tampered_state.file_sha256 = "corrupted_hash".into();
        assert!(matches!(
            validate_receiver_state(&tampered_state, &manifest),
            Err(XferError::Conflict(_))
        ));

        // Tampered sender_did must be rejected
        let mut tampered_sender = state.clone();
        tampered_sender.sender_did = "did:guardian:attacker".into();
        assert!(matches!(
            validate_receiver_state(&tampered_sender, &manifest),
            Err(XferError::Conflict(_))
        ));
    }

    #[test]
    fn test_sender_progress_and_inbox_item_serde() {
        let sender = SenderProgress {
            transfer_id: "x1".into(),
            circle_id: "c1".into(),
            actor_did: "did:guardian:actor".into(),
            peer_did: "did:guardian:peer".into(),
            filename: "doc.docx".into(),
            file_path: "/tmp/doc.docx".into(),
            size: 500,
            chunk_bytes: 250,
            chunk_count: 2,
            requested_chunks: 1,
            sent_chunks: 1,
            bytes_sent: 250,
            status: TransferStatus::Sending,
            updated_at: "2026-01-01T00:00:00Z".into(),
            completed_at: None,
            last_error: None,
        };
        let serialized = serde_json::to_string(&sender).unwrap();
        let deserialized: SenderProgress = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.transfer_id, sender.transfer_id);
        assert_eq!(deserialized.actor_did, sender.actor_did);

        let inbox = InboxItem {
            transfer_id: "x1".into(),
            circle_id: "c1".into(),
            sender_did: "did:guardian:peer".into(),
            filename: "doc.docx".into(),
            size: 500,
            completed: true,
            path: Some("/tmp/inbox/doc.docx".into()),
            updated_at: "2026-01-01T00:00:00Z".into(),
            completed_at: Some("2026-01-01T00:01:00Z".into()),
            file_sha256: "sha".into(),
            vault_id: Some("v1".into()),
            download_path: Some("/api/download".into()),
            vault_available: true,
        };
        let inbox_str = serde_json::to_string(&inbox).unwrap();
        let inbox_deserialized: InboxItem = serde_json::from_str(&inbox_str).unwrap();
        assert_eq!(inbox_deserialized.transfer_id, inbox.transfer_id);
        assert!(inbox_deserialized.vault_available);
    }
}

