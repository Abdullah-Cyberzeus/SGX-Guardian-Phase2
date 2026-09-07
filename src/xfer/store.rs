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
    use tempfile::TempDir;

    struct XferBaseGuard(Option<std::ffi::OsString>);

    impl XferBaseGuard {
        fn set(path: &std::path::Path) -> Self {
            let previous = std::env::var_os(persistence::XFER_BASE_ENV);
            std::env::set_var(persistence::XFER_BASE_ENV, path);
            Self(previous)
        }
    }

    impl Drop for XferBaseGuard {
        fn drop(&mut self) {
            if let Some(previous) = self.0.take() {
                std::env::set_var(persistence::XFER_BASE_ENV, previous);
            } else {
                std::env::remove_var(persistence::XFER_BASE_ENV);
            }
        }
    }

    fn manifest(id: &str) -> FileManifest {
        FileManifest {
            transfer_id: id.into(),
            circle_id: "circle-alpha".into(),
            sender_did: "did:guardian:sender".into(),
            filename: "report.txt".into(),
            size: 7,
            chunk_bytes: 4,
            chunk_count: 2,
            chunk_digests: vec!["chunk-a".into(), "chunk-b".into()],
            file_sha256: "file-digest".into(),
            created_at: "2026-08-31T00:00:00Z".into(),
            proof: Proof::default(),
        }
    }

    fn receiver_state(manifest: &FileManifest) -> ReceiverState {
        ReceiverState {
            transfer_id: manifest.transfer_id.clone(),
            circle_id: manifest.circle_id.clone(),
            sender_did: manifest.sender_did.clone(),
            filename: manifest.filename.clone(),
            size: manifest.size,
            chunk_bytes: manifest.chunk_bytes,
            chunk_count: manifest.chunk_count,
            file_sha256: manifest.file_sha256.clone(),
            received_chunks: vec![1, 0],
            status: TransferStatus::Receiving,
            updated_at: "2026-08-31T00:00:00Z".into(),
            completed_at: None,
            last_error: None,
            vault_id: None,
        }
    }

    #[test]
    fn manifest_and_receiver_core_comparisons_cover_every_mismatch() {
        let left = manifest("transfer-1");
        assert!(same_manifest_core(&left, &left));
        assert!(validate_receiver_state(&receiver_state(&left), &left).is_ok());

        macro_rules! mismatch {
            ($field:ident, $value:expr) => {{
                let mut right = left.clone();
                right.$field = $value;
                assert!(!same_manifest_core(&left, &right), stringify!($field));
            }};
        }
        mismatch!(transfer_id, "different-transfer".into());
        mismatch!(circle_id, "different-circle".into());
        mismatch!(sender_did, "did:guardian:other".into());
        mismatch!(filename, "other.txt".into());
        mismatch!(size, 99);
        mismatch!(chunk_bytes, 8);
        mismatch!(chunk_count, 1);
        mismatch!(chunk_digests, vec!["other".into()]);
        mismatch!(file_sha256, "other-digest".into());

        let mut state = receiver_state(&left);
        state.filename = "other.txt".into();
        assert!(matches!(
            validate_receiver_state(&state, &left),
            Err(XferError::Conflict(_))
        ));
        assert_eq!(receiver_state(&left).have_chunks(), vec![1, 0]);
    }

    #[tokio::test]
    async fn receiver_lifecycle_persists_chunks_failure_completion_and_vault_state() {
        let _env_lock = crate::xfer::lock_test_env().await;
        let temp = TempDir::new().expect("tempdir");
        let _base = XferBaseGuard::set(temp.path());
        let manifest = manifest("receiver-lifecycle");

        assert!(load_manifest(&manifest.circle_id, &manifest.transfer_id)
            .await
            .expect("load missing manifest")
            .is_none());
        let prepared = prepare_receiver(&manifest).await.expect("prepare receiver");
        assert_eq!(prepared.status, TransferStatus::Receiving);
        assert!(prepared.received_chunks.is_empty());
        assert!(find_receiver_state(&manifest.transfer_id)
            .await
            .expect("find receiver")
            .is_some());

        let state = record_chunk(&manifest, 1).await.expect("record chunk 1");
        assert_eq!(state.received_chunks, vec![1]);
        let state = record_chunk(&manifest, 0).await.expect("record chunk 0");
        assert_eq!(state.received_chunks, vec![0, 1]);
        let state = record_chunk(&manifest, 1).await.expect("deduplicate chunk");
        assert_eq!(state.received_chunks, vec![0, 1]);

        let failed = mark_receiver_failed(&manifest, "checksum mismatch")
            .await
            .expect("mark failed");
        assert_eq!(failed.status, TransferStatus::Failed);
        assert_eq!(failed.last_error.as_deref(), Some("checksum mismatch"));

        let completed = mark_receiver_complete(&manifest)
            .await
            .expect("mark complete");
        assert_eq!(completed.status, TransferStatus::Completed);
        assert_eq!(completed.received_chunks, vec![0, 1]);
        assert!(completed.completed_at.is_some());
        assert!(completed.last_error.is_none());

        let prepared_again = prepare_receiver(&manifest)
            .await
            .expect("prepare completed receiver");
        assert_eq!(prepared_again.status, TransferStatus::Completed);

        let vaulted = mark_receiver_complete_with_vault(&manifest, "vault-record-1")
            .await
            .expect("mark complete with vault");
        assert_eq!(vaulted.vault_id.as_deref(), Some("vault-record-1"));

        let mut conflict = manifest.clone();
        conflict.filename = "conflict.txt".into();
        assert!(matches!(
            prepare_receiver(&conflict).await,
            Err(XferError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn outbox_local_transfer_and_listing_cover_missing_corrupt_and_sorted_records() {
        let _env_lock = crate::xfer::lock_test_env().await;
        let temp = TempDir::new().expect("tempdir");
        let _base = XferBaseGuard::set(temp.path());
        let first = manifest("outbox-first");
        let second = manifest("outbox-second");

        assert!(load_outbox("missing")
            .await
            .expect("missing outbox")
            .is_none());
        assert!(matches!(
            update_outbox("missing", |_| {}).await,
            Err(XferError::TransferNotFound(_))
        ));

        let queued = create_outbox(
            "did:guardian:actor",
            "did:guardian:peer",
            "/tmp/report.txt",
            &first,
        )
        .await
        .expect("create outbox");
        assert_eq!(queued.status, TransferStatus::Queued);
        assert_eq!(queued.actor_did, "did:guardian:actor");

        let sending = update_outbox(&first.transfer_id, |progress| {
            progress.status = TransferStatus::Sending;
            progress.sent_chunks = 1;
            progress.bytes_sent = 4;
        })
        .await
        .expect("update outbox");
        assert_eq!(sending.status, TransferStatus::Sending);
        assert_eq!(sending.bytes_sent, 4);

        create_outbox("", "did:guardian:peer", "/tmp/second", &second)
            .await
            .expect("create second outbox");
        tokio::fs::write(persistence::outbox_dir().join("corrupt.json"), b"not-json")
            .await
            .expect("write corrupt outbox");
        tokio::fs::create_dir_all(persistence::outbox_dir().join("ignored-directory"))
            .await
            .expect("create ignored directory");
        let outbox = list_outbox().await.expect("list outbox");
        assert_eq!(outbox.len(), 2);

        let local = LocalTransferRecord {
            transfer_id: "local-1".into(),
            circle_id: "circle-alpha".into(),
            sender_did: "did:guardian:sender".into(),
            recipient_did: "did:guardian:recipient".into(),
            filename: "local.txt".into(),
            size: 3,
            file_sha256: "local-digest".into(),
            vault_id: "vault-local".into(),
            updated_at: "2026-08-31T00:00:00Z".into(),
            completed_at: "2026-08-31T00:00:00Z".into(),
        };
        save_local_transfer(&local)
            .await
            .expect("save local transfer");
        assert_eq!(
            load_local_transfer(&local.transfer_id)
                .await
                .expect("load local transfer")
                .expect("local record")
                .vault_id,
            "vault-local"
        );
        tokio::fs::write(persistence::local_dir().join("corrupt.json"), b"not-json")
            .await
            .expect("write corrupt local record");
        assert_eq!(list_local_transfers().await.expect("list local").len(), 1);
    }

    #[tokio::test]
    async fn inbox_listing_and_cancellation_cover_partial_complete_and_missing_transfers() {
        let _env_lock = crate::xfer::lock_test_env().await;
        let temp = TempDir::new().expect("tempdir");
        let _base = XferBaseGuard::set(temp.path());
        let partial = manifest("partial-transfer");
        let complete = manifest("complete-transfer");

        prepare_receiver(&partial).await.expect("prepare partial");
        prepare_receiver(&complete).await.expect("prepare complete");
        mark_receiver_complete(&complete)
            .await
            .expect("complete receiver");

        let inbox = list_inbox().await.expect("list inbox");
        assert_eq!(inbox.len(), 2);
        let partial_item = inbox
            .iter()
            .find(|item| item.transfer_id == partial.transfer_id)
            .expect("partial inbox item");
        assert!(!partial_item.completed);
        assert!(partial_item
            .path
            .as_deref()
            .is_some_and(|path| path.ends_with(".part")));
        let complete_item = inbox
            .iter()
            .find(|item| item.transfer_id == complete.transfer_id)
            .expect("complete inbox item");
        assert!(complete_item.completed);
        assert!(complete_item
            .path
            .as_deref()
            .is_some_and(|path| path.ends_with("report.txt")));

        assert!(cancel_transfer_files(&partial.transfer_id)
            .await
            .expect("cancel partial"));
        assert!(!cancel_transfer_files("missing-transfer")
            .await
            .expect("cancel missing"));
        assert!(
            remove_receiver_transfer_dir(&complete.circle_id, &complete.transfer_id)
                .await
                .expect("remove complete")
        );
        assert!(
            !remove_receiver_transfer_dir(&complete.circle_id, &complete.transfer_id)
                .await
                .expect("remove missing complete")
        );
    }
}
