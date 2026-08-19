use crate::vault::crypto;
use crate::vault::errors::VaultError;
use crate::vault::mime_policy;
use crate::vault::model::{VaultRecord, VaultSource};
use crate::vault::namespace::VaultNamespace;
use crate::vault::persistence;
use crate::vault::quota;
use crate::vault::wrapper;
use crate::vault::VaultConfig;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tokio::fs::OpenOptions;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct IngestMeta {
    pub filename: String,
    pub mime: String,
    pub sha256_plain: String,
    pub size_plain: u64,
    pub chunk_bytes: u32,
}

pub fn infer_mime(filename: &str) -> String {
    let lower = filename.to_ascii_lowercase();
    if lower.ends_with(".txt") {
        "text/plain".to_string()
    } else if lower.ends_with(".json") {
        "application/json".to_string()
    } else if lower.ends_with(".pdf") {
        "application/pdf".to_string()
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        "image/jpeg".to_string()
    } else if lower.ends_with(".png") {
        "image/png".to_string()
    } else if lower.ends_with(".gif") {
        "image/gif".to_string()
    } else if lower.ends_with(".csv") {
        "text/csv".to_string()
    } else if lower.ends_with(".xml") {
        "application/xml".to_string()
    } else if lower.ends_with(".zip") {
        "application/zip".to_string()
    } else {
        "application/octet-stream".to_string()
    }
}

/// Extra fields set by callers that need more than the base file-transfer
/// shape (Files-tab uploads and chat attachments).
#[derive(Debug, Clone, Default)]
pub struct IngestExtras {
    pub description: String,
    pub conversation_recipient_did: Option<String>,
    /// Preserves a specific `vault_id` instead of minting a new one, and
    /// skips filename de-duplication. Used only when replicating a peer's
    /// chat attachment: the local copy must be addressable by the same id
    /// the chat message already references.
    pub vault_id_override: Option<String>,
}

pub async fn ingest_file(
    circle_id: &str,
    sender_did: &str,
    path: &Path,
    meta: IngestMeta,
) -> Result<VaultRecord, VaultError> {
    ingest_file_with_namespace(
        VaultNamespace::Circle(circle_id.to_string()),
        sender_did,
        path,
        meta,
        VaultSource::FileTransfer,
        String::new(),
        IngestExtras::default(),
    )
    .await
}

pub async fn ingest_upload_file(
    namespace: VaultNamespace,
    sender_did: &str,
    path: &Path,
    meta: IngestMeta,
    folder_id: String,
    description: String,
) -> Result<VaultRecord, VaultError> {
    mime_policy::ensure_mime_allowed(&meta.mime)?;
    ingest_file_with_namespace(
        namespace,
        sender_did,
        path,
        meta,
        VaultSource::Upload,
        folder_id,
        IngestExtras {
            description,
            conversation_recipient_did: None,
            vault_id_override: None,
        },
    )
    .await
}

/// Chat attachments (Files-tab-independent) land in the sender's namespace —
/// the group's Circle for group chat, or the sender's Personal store (with
/// `conversation_recipient_did` set) for a 1:1 direct message.
pub async fn ingest_chat_attachment(
    namespace: VaultNamespace,
    sender_did: &str,
    path: &Path,
    meta: IngestMeta,
    conversation_recipient_did: Option<String>,
) -> Result<VaultRecord, VaultError> {
    mime_policy::ensure_mime_allowed(&meta.mime)?;
    ingest_file_with_namespace(
        namespace,
        sender_did,
        path,
        meta,
        VaultSource::ChatAttachment,
        String::new(),
        IngestExtras {
            description: String::new(),
            conversation_recipient_did,
            vault_id_override: None,
        },
    )
    .await
}

/// Stores a chat attachment pulled from its owning peer over gRPC as a local
/// `VaultRecord`, preserving `vault_id` so it stays addressable by the id
/// the chat message already references.
#[allow(clippy::too_many_arguments)]
pub async fn ingest_replicated_chat_attachment(
    vault_id: String,
    namespace: VaultNamespace,
    sender_did: &str,
    path: &Path,
    meta: IngestMeta,
    conversation_recipient_did: Option<String>,
) -> Result<VaultRecord, VaultError> {
    ingest_file_with_namespace(
        namespace,
        sender_did,
        path,
        meta,
        VaultSource::ChatAttachment,
        String::new(),
        IngestExtras {
            description: String::new(),
            conversation_recipient_did,
            vault_id_override: Some(vault_id),
        },
    )
    .await
}

async fn ingest_file_with_namespace(
    namespace: VaultNamespace,
    sender_did: &str,
    path: &Path,
    meta: IngestMeta,
    source: VaultSource,
    folder_id: String,
    extras: IngestExtras,
) -> Result<VaultRecord, VaultError> {
    let config = VaultConfig::from_env();
    let reservation = quota::reserve_namespace_capacity_for_plaintext(
        &config,
        &namespace,
        meta.size_plain,
        meta.chunk_bytes,
    )
    .await?;
    let is_replicated_copy = extras.vault_id_override.is_some();
    let vault_id = extras
        .vault_id_override
        .clone()
        .unwrap_or_else(|| format!("urn:uuid:{}", Uuid::new_v4()));
    let blob_path = persistence::blob_path_for_namespace(&config, &namespace, &vault_id);
    let tmp_blob_path = blob_path.with_extension("enc.tmp");

    let path_buf = path.to_path_buf();
    let config_for_task = config.clone();
    let meta_for_task = meta.clone();
    let tmp_blob_for_task = tmp_blob_path.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let wrapper = wrapper::default_wrapper(&config_for_task)?;
        crypto::encrypt_file(&path_buf, &tmp_blob_for_task, &meta_for_task, &wrapper)
    })
    .await
    .map_err(|error| VaultError::InvalidStructure(format!("encrypt task: {}", error)));
    let outcome = match outcome {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(error)) => {
            quota::release_reservation(&reservation);
            return Err(error);
        }
        Err(error) => {
            quota::release_reservation(&reservation);
            return Err(error);
        }
    };

    if let Some(parent) = blob_path.parent() {
        if let Err(error) = tokio::fs::create_dir_all(parent).await {
            quota::release_reservation(&reservation);
            return Err(error.into());
        }
    }
    if let Err(error) = tokio::fs::rename(&tmp_blob_path, &blob_path).await {
        quota::release_reservation(&reservation);
        return Err(error.into());
    }

    let mut record = VaultRecord {
        vault_id,
        namespace: if namespace.is_personal() {
            VaultNamespace::PERSONAL_STORAGE_KEY.to_string()
        } else {
            String::new()
        },
        circle_id: match &namespace {
            VaultNamespace::Personal => String::new(),
            VaultNamespace::Circle(circle_id) => circle_id.clone(),
        },
        filename: meta.filename,
        mime: meta.mime,
        size_plain: meta.size_plain,
        size_cipher: outcome.size_cipher,
        sha256_plain: meta.sha256_plain,
        sender_did: sender_did.to_string(),
        received_at: chrono::Utc::now().to_rfc3339(),
        source,
        folder_id,
        starred: false,
        description: extras.description,
        owner_did: sender_did.to_string(),
        revoked: false,
        revoked_at: None,
        expires_at: None,
        conversation_recipient_did: extras.conversation_recipient_did,
        message_id: None,
        enc: outcome.enc,
    };

    let save_result = {
        let _guard = crate::vault::write_lock().lock().await;
        let result = if is_replicated_copy {
            persistence::save_record(&config, &record).await
        } else {
            match resolve_unique_filename(&config, &namespace, &record.folder_id, &record.filename)
                .await
            {
                Ok(unique_filename) => {
                    record.filename = unique_filename;
                    persistence::save_record(&config, &record).await
                }
                Err(error) => Err(error),
            }
        };
        quota::release_reservation(&reservation);
        result
    };

    if let Err(error) = save_result {
        let _ = tokio::fs::remove_file(&blob_path).await;
        return Err(error);
    }

    if let Err(error) = cleanup_plaintext(path).await {
        let _ = tokio::fs::remove_file(&blob_path).await;
        let _ = tokio::fs::remove_file(persistence::record_meta_path(&config, &record)).await;
        return Err(error);
    }

    Ok(record)
}

/// Deterministically resolves a filename collision within the same
/// namespace/folder by appending " (n)" before the extension, incrementing
/// until free. Must be called while holding `crate::vault::write_lock()` so
/// concurrent uploads of the same name can't race past each other.
async fn resolve_unique_filename(
    config: &VaultConfig,
    namespace: &VaultNamespace,
    folder_id: &str,
    filename: &str,
) -> Result<String, VaultError> {
    let taken: HashSet<String> = persistence::list_records(config, Some(&namespace.storage_key()))
        .await?
        .into_iter()
        .filter(|record| record.folder_id == folder_id)
        .map(|record| record.filename)
        .collect();
    if !taken.contains(filename) {
        return Ok(filename.to_string());
    }

    let (stem, ext) = match filename.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem, format!(".{}", ext)),
        _ => (filename, String::new()),
    };
    let mut counter = 1u32;
    loop {
        let candidate = format!("{stem} ({counter}){ext}");
        if !taken.contains(&candidate) {
            return Ok(candidate);
        }
        counter += 1;
    }
}

pub async fn decrypt_record_to_temp(record: &VaultRecord) -> Result<PathBuf, VaultError> {
    let config = VaultConfig::from_env();
    let temp_path = persistence::decrypt_temp_path(&config, &record.vault_id);
    decrypt_record_to_path_with_config(&config, record, &temp_path).await?;
    Ok(temp_path)
}

pub async fn decrypt_record_to_path(
    record: &VaultRecord,
    output_path: &Path,
) -> Result<(), VaultError> {
    let config = VaultConfig::from_env();
    decrypt_record_to_path_with_config(&config, record, output_path).await
}

async fn decrypt_record_to_path_with_config(
    config: &VaultConfig,
    record: &VaultRecord,
    output_path: &Path,
) -> Result<(), VaultError> {
    let blob_path = persistence::record_blob_path(config, record);
    if !tokio::fs::try_exists(&blob_path).await? {
        return Err(VaultError::NotFound(record.vault_id.clone()));
    }

    let config_for_task = config.clone();
    let record_for_task = record.clone();
    let blob_for_task = blob_path.clone();
    let output_for_task = output_path.to_path_buf();
    let outcome = tokio::task::spawn_blocking(move || {
        let wrapper = wrapper::wrapper_for_record(&config_for_task, &record_for_task)?;
        crypto::decrypt_file(&blob_for_task, &output_for_task, &record_for_task, &wrapper)
    })
    .await
    .map_err(|error| VaultError::InvalidStructure(format!("decrypt task: {}", error)))?;

    if let Err(error) = outcome {
        let _ = tokio::fs::remove_file(output_path).await;
        return Err(error);
    }

    Ok(())
}

pub async fn cleanup_plaintext(path: &Path) -> Result<(), VaultError> {
    if !tokio::fs::try_exists(path).await? {
        return Ok(());
    }
    let metadata = tokio::fs::metadata(path).await?;
    let len = metadata.len();

    let mut file = OpenOptions::new().write(true).open(path).await?;
    let mut written = 0_u64;
    let zeroes = vec![0_u8; 256 * 1024];
    while written < len {
        let remaining = (len - written) as usize;
        let slice = if remaining >= zeroes.len() {
            &zeroes[..]
        } else {
            &zeroes[..remaining]
        };
        file.write_all(slice).await?;
        written += slice.len() as u64;
    }
    file.flush().await?;
    file.sync_data().await?;
    file.seek(std::io::SeekFrom::Start(0)).await?;
    drop(file);
    tokio::fs::remove_file(path).await?;
    Ok(())
}
