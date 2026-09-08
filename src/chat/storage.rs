use crate::chat::models::{ChatMessageRecord, MessageStatus, ReadReceiptRecord};
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

/// Hard ceiling on chat attachment size, enforced during upload/receive
/// streaming, on top of the Vault's per-namespace quota.
pub const MAX_ATTACHMENT_BYTES: u64 = 50 * 1024 * 1024;

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
/// `min_reader_count` is how many distinct readers are required before the
/// message is considered fully `Read` — 1 for a 1:1 conversation (the only
/// possible reader), or the circle's recipient count for a group message,
/// so a group message isn't shown as "Read" the moment a single member
/// (out of many) has seen it.
pub async fn update_message_read_by(
    is_group: bool,
    target_id: &str,
    message_id: &str,
    reader_did: &str,
    min_reader_count: usize,
) -> Result<Option<ChatMessageRecord>, Box<dyn std::error::Error + Send + Sync>> {
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
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };

    let mut reader = BufReader::new(file);
    let mut updated_lines = Vec::new();
    let mut line = String::new();
    let mut modified = false;
    let mut updated_record = None;

    while reader.read_line(&mut line).await? > 0 {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            if let Ok(mut record) = serde_json::from_str::<ChatMessageRecord>(trimmed) {
                if record.message_id == message_id
                    && !record.read_by.contains(&reader_did.to_string())
                {
                    record.read_by.push(reader_did.to_string());
                    if record.read_by.len() >= min_reader_count.max(1) {
                        record.status = MessageStatus::Read;
                    }
                    updated_record = Some(record.clone());
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

    Ok(updated_record)
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
/// Gracefully handles missing files and isolated malformed records. Chat logs are
/// append-only, so a power loss can leave one partial trailing line; that record
/// must not make every valid message in the conversation unavailable.
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
    let mut line_number = 0usize;

    while reader.read_line(&mut line).await? > 0 {
        line_number += 1;
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            match serde_json::from_str::<ChatMessageRecord>(trimmed) {
                Ok(record) => {
                    if seen_message_ids.insert(record.message_id.clone()) {
                        messages.push(record);
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        path = %path.display(),
                        line = line_number,
                        %error,
                        "Skipping malformed chat-history record"
                    );
                }
            }
        }
        line.clear();
    }

    Ok(messages)
}

fn safe_filename(id: &str) -> String {
    format!("{}.jsonl", id)
}

/// Every DID currently keying a stored P2P conversation log, recovered
/// verbatim from the `.jsonl` filenames under `p2p/` (the DID is used
/// as-is as the filename, see `safe_filename`). Used as a last-resort
/// lookup when a caller's DID for a peer doesn't match any conversation
/// file directly — rather than requiring the caller to already know the
/// exact key, every existing key can be checked against the peer's known
/// identity instead.
pub async fn list_p2p_conversation_ids() -> Vec<String> {
    let dir = PathBuf::from(&*BASE_DIR).join("p2p");
    let mut entries = match tokio::fs::read_dir(&dir).await {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };
    let mut ids = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name();
        if let Some(id) = name.to_str().and_then(|n| n.strip_suffix(".jsonl")) {
            ids.push(id.to_string());
        }
    }
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(id: &str, sequence: u64) -> ChatMessageRecord {
        ChatMessageRecord {
            message_id: id.to_string(),
            sender_did: "did:guardian:nodeA".to_string(),
            recipient_did: "did:guardian:nodeB".to_string(),
            group_id: None,
            timestamp: sequence as i64,
            seq_no: sequence,
            encrypted_payload: "{}".to_string(),
            signature: "test-signature".to_string(),
            status: MessageStatus::Delivered,
            read_by: Vec::new(),
        }
    }

    #[tokio::test]
    async fn malformed_record_does_not_block_valid_conversation_history() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nodeB.jsonl");
        let first = serde_json::to_string(&message("msg-1", 1)).expect("serialize first");
        let second = serde_json::to_string(&message("msg-2", 2)).expect("serialize second");
        tokio::fs::write(&path, format!("{}\n{{partial-json\n{}\n", first, second))
            .await
            .expect("write history");

        let history = read_history_file(&path).await.expect("read history");

        assert_eq!(history.len(), 2);
        assert_eq!(history[0].message_id, "msg-1");
        assert_eq!(history[1].message_id, "msg-2");
    }
}
