use crate::vault::errors::VaultError;
use crate::vault::VaultConfig;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DownloadRecord {
    pub vault_id: String,
    pub downloader_did: String,
    pub downloaded_at: String,
    pub source: String,
}

fn downloads_log_path(config: &VaultConfig) -> std::path::PathBuf {
    config.base_dir.join("meta").join("downloads.jsonl")
}

static DOWNLOAD_LOG_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

fn log_lock() -> &'static tokio::sync::Mutex<()> {
    DOWNLOAD_LOG_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

pub async fn record_download(
    config: &VaultConfig,
    vault_id: &str,
    downloader_did: &str,
    source: &str,
) -> Result<(), VaultError> {
    let record = DownloadRecord {
        vault_id: vault_id.to_string(),
        downloader_did: downloader_did.to_string(),
        downloaded_at: chrono::Utc::now().to_rfc3339(),
        source: source.to_string(),
    };
    let path = downloads_log_path(config);
    let _guard = log_lock().lock().await;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let line = serde_json::to_string(&record)?;
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await?;
    file.write_all(line.as_bytes()).await?;
    file.write_all(b"\n").await?;
    file.flush().await?;
    Ok(())
}

pub async fn list_downloads_for(
    config: &VaultConfig,
    vault_id: &str,
) -> Result<Vec<DownloadRecord>, VaultError> {
    let path = downloads_log_path(config);
    let file = match tokio::fs::File::open(&path).await {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut reader = BufReader::new(file).lines();
    let mut out = Vec::new();
    while let Some(line) = reader.next_line().await? {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(record) = serde_json::from_str::<DownloadRecord>(trimmed) {
            if record.vault_id == vault_id {
                out.push(record);
            }
        }
    }
    out.sort_by(|left, right| right.downloaded_at.cmp(&left.downloaded_at));
    Ok(out)
}
