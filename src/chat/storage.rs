use crate::chat::models::{AttachmentRecord, ChatMessageRecord, MessageStatus, ReadReceiptRecord};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

/// Fine-grained locks per file path to ensure thread-safe append-only writes.
static FILE_LOCKS: Lazy<DashMap<PathBuf, Arc<Mutex<()>>>> = Lazy::new(DashMap::new);

/// Base directory for all persisted chat history and attachments.
static BASE_DIR: Lazy<String> = Lazy::new(|| {
    std::env::var("CHAT_STORAGE_DIR").unwrap_or_else(|_| "/var/lib/sgx-guardian/chat".to_string())
});

pub const MAX_ATTACHMENT_BYTES: u64 = 50 * 1024 * 1024;

pub fn attachment_path(file_id: &str) -> PathBuf {
    PathBuf::from(&*BASE_DIR).join("attachments").join(file_id)
}

/// Appends a new chat message to a specific peer's P2P conversation log.
/// This function is thread-safe and writes to the bottom of the `.jsonl` file.
pub async fn append_p2p_message(
    peer_did: &str,
    record: &ChatMessageRecord,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = PathBuf::from(&*BASE_DIR)
        .join("p2p")
        .join(safe_filename(peer_did));
    let json_line = serde_json::to_string(record)?;

    append_message_if_absent(&path, &record.message_id, &json_line).await
}

/// Appends a new chat message to a specific Group/Circle conversation log.
pub async fn append_group_message(
    group_id: &str,
    record: &ChatMessageRecord,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = PathBuf::from(&*BASE_DIR)
        .join("group")
        .join(safe_filename(group_id));
    let json_line = serde_json::to_string(record)?;

    append_message_if_absent(&path, &record.message_id, &json_line).await
}

/// Persist a message exactly once. Network retries and an overlapping history
/// sync may deliver the same message more than once, so `message_id` is the
/// idempotency key for every conversation log.
async fn append_message_if_absent(
    path: &PathBuf,
    message_id: &str,
    line: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let lock = FILE_LOCKS
        .entry(path.clone())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    if let Ok(file) = File::open(path).await {
        let mut reader = BufReader::new(file);
        let mut existing = String::new();
        while reader.read_line(&mut existing).await? > 0 {
            if serde_json::from_str::<ChatMessageRecord>(existing.trim())
                .is_ok_and(|record| record.message_id == message_id)
            {
                return Ok(());
            }
            existing.clear();
        }
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    file.write_all(line.as_bytes()).await?;
    file.write_all(b"\n").await?;
    file.flush().await?;
    file.sync_all().await?;
    Ok(())
}

pub async fn append_attachment_metadata(
    record: &AttachmentRecord,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = PathBuf::from(&*BASE_DIR).join("attachments.jsonl");
    let json_line = serde_json::to_string(record)?;

    append_line(&path, &json_line).await
}

/// Stores attachment metadata once. Retries and offline sync may retrieve the
/// same attachment repeatedly, but the metadata journal must stay idempotent.
pub async fn append_attachment_metadata_if_absent(
    record: &AttachmentRecord,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if get_attachment_metadata(&record.file_id).await?.is_some() {
        return Ok(());
    }
    append_attachment_metadata(record).await
}

pub async fn get_attachment_metadata(
    file_id: &str,
) -> Result<Option<AttachmentRecord>, Box<dyn std::error::Error + Send + Sync>> {
    let path = PathBuf::from(&*BASE_DIR).join("attachments.jsonl");
    let lock = FILE_LOCKS
        .entry(path.clone())
        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    let file = match File::open(&path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };

    let mut reader = BufReader::new(file);
    let mut line = String::new();

    while reader.read_line(&mut line).await? > 0 {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            if let Ok(record) = serde_json::from_str::<AttachmentRecord>(trimmed) {
                if record.file_id == file_id {
                    return Ok(Some(record));
                }
            }
        }
        line.clear();
    }

    Ok(None)
}

pub async fn append_read_receipt(
    record: &ReadReceiptRecord,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = PathBuf::from(&*BASE_DIR).join("read_receipts.jsonl");
    let json_line = serde_json::to_string(record)?;

    append_line(&path, &json_line).await
}

/// Core helper: Safely appends a raw JSON string to the specified file path.
/// Includes an fsync (sync_all) to protect against sudden power loss.
async fn append_line(
    path: &PathBuf,
    line: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let lock = FILE_LOCKS
        .entry(path.clone())
        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;

    file.write_all(line.as_bytes()).await?;
    file.write_all(b"\n").await?;
    file.flush().await?;
    // Defence-in-depth: fsync after append so sudden power-loss
    // doesn't leave a partial or corrupted JSON line at the end of the file.
    file.sync_all().await?;
    Ok(())
}

pub async fn read_p2p_history(
    peer_did: &str,
) -> Result<Vec<ChatMessageRecord>, Box<dyn std::error::Error + Send + Sync>> {
    let path = PathBuf::from(&*BASE_DIR)
        .join("p2p")
        .join(safe_filename(peer_did));

    let mut messages = read_history_file(&path).await?;
    let receipts_map = read_all_receipts().await.unwrap_or_default();

    for msg in &mut messages {
        if let Some(readers) = receipts_map.get(&msg.message_id) {
            for reader in readers {
                if !msg.read_by.contains(reader) {
                    msg.read_by.push(reader.clone());
                }
            }
        }
        if !msg.read_by.is_empty() {
            msg.status = crate::chat::models::MessageStatus::Read;
        }
    }
    Ok(messages)
}

pub async fn read_group_history(
    group_id: &str,
) -> Result<Vec<ChatMessageRecord>, Box<dyn std::error::Error + Send + Sync>> {
    let path = PathBuf::from(&*BASE_DIR)
        .join("group")
        .join(safe_filename(group_id));

    let mut messages = read_history_file(&path).await?;
    let receipts_map = read_all_receipts().await.unwrap_or_default();

    for msg in &mut messages {
        if let Some(readers) = receipts_map.get(&msg.message_id) {
            for reader in readers {
                if !msg.read_by.contains(reader) {
                    msg.read_by.push(reader.clone());
                }
            }
        }
    }
    Ok(messages)
}

/// Appends a reader DID to a message's `read_by` list in the history file.
pub async fn update_message_read_by(
    is_group: bool,
    target_id: &str,
    message_id: &str,
    reader_did: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let dir_name = if is_group { "group" } else { "p2p" };
    let path = PathBuf::from(&*BASE_DIR)
        .join(dir_name)
        .join(safe_filename(target_id));

    let lock = FILE_LOCKS
        .entry(path.clone())
        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    let file = match File::open(&path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };

    let mut reader = BufReader::new(file);
    let mut updated_lines = Vec::new();
    let mut line = String::new();
    let mut modified = false;

    while reader.read_line(&mut line).await? > 0 {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            if let Ok(mut record) = serde_json::from_str::<ChatMessageRecord>(trimmed) {
                if record.message_id == message_id
                    && !record.read_by.contains(&reader_did.to_string())
                {
                    record.read_by.push(reader_did.to_string());
                    modified = true;
                }
                updated_lines.push(serde_json::to_string(&record)?);
            } else {
                updated_lines.push(trimmed.to_string());
            }
        }
        line.clear();
    }

    if modified {
        let content = updated_lines.join("\n") + "\n";
        tokio::fs::write(&path, content.as_bytes()).await?;
    }

    Ok(())
}

/// Advances a message's delivery status (e.g. `Pending` -> `Delivered`) in its
/// conversation log. Only a transition away from `Pending` is applied, so a
/// message already marked `Read` is never regressed by a late delivery ack.
/// Returns the updated record so the caller can notify live websocket clients.
pub async fn update_message_status(
    is_group: bool,
    target_id: &str,
    message_id: &str,
    status: MessageStatus,
) -> Result<Option<ChatMessageRecord>, Box<dyn std::error::Error + Send + Sync>> {
    let dir_name = if is_group { "group" } else { "p2p" };
    let path = PathBuf::from(&*BASE_DIR)
        .join(dir_name)
        .join(safe_filename(target_id));

    let lock = FILE_LOCKS
        .entry(path.clone())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    let file = match File::open(&path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };

    let mut reader = BufReader::new(file);
    let mut updated_lines = Vec::new();
    let mut line = String::new();
    let mut updated_record = None;

    while reader.read_line(&mut line).await? > 0 {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            if let Ok(mut record) = serde_json::from_str::<ChatMessageRecord>(trimmed) {
                if record.message_id == message_id
                    && matches!(
                        record.status,
                        MessageStatus::Pending | MessageStatus::AcceptedByGuardian
                    )
                {
                    record.status = status.clone();
                    updated_record = Some(record.clone());
                }
                updated_lines.push(serde_json::to_string(&record)?);
            } else {
                updated_lines.push(trimmed.to_string());
            }
        }
        line.clear();
    }

    if updated_record.is_some() {
        let content = updated_lines.join("\n") + "\n";
        tokio::fs::write(&path, content.as_bytes()).await?;
    }

    Ok(updated_record)
}

async fn read_all_receipts(
) -> Result<std::collections::HashMap<String, Vec<String>>, Box<dyn std::error::Error + Send + Sync>>
{
    let path = PathBuf::from(&*BASE_DIR).join("read_receipts.jsonl");
    let lock = FILE_LOCKS
        .entry(path.clone())
        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    let file = match File::open(&path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(std::collections::HashMap::new())
        }
        Err(e) => return Err(e.into()),
    };

    let mut reader = BufReader::new(file);
    let mut receipts: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    let mut line = String::new();

    while reader.read_line(&mut line).await? > 0 {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            if let Ok(record) = serde_json::from_str::<ReadReceiptRecord>(trimmed) {
                let entry = receipts.entry(record.message_id).or_default();
                if !entry.contains(&record.reader_did) {
                    entry.push(record.reader_did);
                }
            }
        }
        line.clear();
    }

    Ok(receipts)
}

/// Internal helper: Reads a generic JSONL file into a chronological vector of messages.
/// Gracefully handles missing files (returns empty list instead of crashing).
async fn read_history_file(
    path: &PathBuf,
) -> Result<Vec<ChatMessageRecord>, Box<dyn std::error::Error + Send + Sync>> {
    let lock = FILE_LOCKS
        .entry(path.clone())
        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    let file = match File::open(path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };

    let mut reader = BufReader::new(file);
    let mut messages = Vec::new();
    let mut seen_message_ids = HashSet::new();
    let mut line = String::new();

    while reader.read_line(&mut line).await? > 0 {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            let record = serde_json::from_str::<ChatMessageRecord>(trimmed)
                .map_err(|e| format!("Corrupted JSON in chat history: {}", e))?;
            if seen_message_ids.insert(record.message_id.clone()) {
                messages.push(record);
            }
        }
        line.clear();
    }

    Ok(messages)
}

fn safe_filename(id: &str) -> String {
    format!("{}.jsonl", id)
}
