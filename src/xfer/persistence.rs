use crate::xfer::errors::XferError;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::env;
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

pub const XFER_BASE: &str = "/var/lib/sgx-guardian/xfer";
pub const XFER_BASE_ENV: &str = "SGX_GUARDIAN_XFER_BASE";

pub fn base_dir() -> PathBuf {
    env::var(XFER_BASE_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(XFER_BASE))
}

pub fn inbox_dir() -> PathBuf {
    base_dir().join("inbox")
}

pub fn outbox_dir() -> PathBuf {
    base_dir().join("outbox")
}

pub fn staging_dir() -> PathBuf {
    base_dir().join("staging")
}

pub fn staging_transfer_dir(staging_id: &str) -> PathBuf {
    staging_dir().join(staging_id)
}

pub fn inbox_transfer_dir(circle_id: &str, transfer_id: &str) -> PathBuf {
    inbox_dir().join(circle_id).join(transfer_id)
}

pub fn manifest_path(circle_id: &str, transfer_id: &str) -> PathBuf {
    inbox_transfer_dir(circle_id, transfer_id).join("manifest.json")
}

pub fn state_path(circle_id: &str, transfer_id: &str) -> PathBuf {
    inbox_transfer_dir(circle_id, transfer_id).join("state.json")
}

pub fn part_path(circle_id: &str, transfer_id: &str, filename: &str) -> PathBuf {
    inbox_transfer_dir(circle_id, transfer_id).join(format!("{}.part", safe_file_name(filename)))
}

pub fn final_path(circle_id: &str, transfer_id: &str, filename: &str) -> PathBuf {
    inbox_transfer_dir(circle_id, transfer_id).join(safe_file_name(filename))
}

pub fn outbox_path(transfer_id: &str) -> PathBuf {
    outbox_dir().join(format!("{}.json", transfer_id))
}

pub fn safe_file_name(name: &str) -> String {
    crate::xfer::manifest::safe_manifest_name(name)
}

pub async fn create_secure_staging_dir(staging_id: &str) -> Result<PathBuf, XferError> {
    let dir = staging_transfer_dir(staging_id);
    tokio::fs::create_dir_all(&dir).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).await?;
    }
    Ok(dir)
}

pub async fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), XferError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let tmp = path.with_extension("tmp");
    let mut file = tokio::fs::File::create(&tmp).await?;
    file.write_all(bytes).await?;
    file.sync_all().await?;
    drop(file);
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

pub async fn save_json_pretty<T>(path: &Path, value: &T) -> Result<(), XferError>
where
    T: Serialize,
{
    write_atomic(path, &serde_json::to_vec_pretty(value)?).await
}

pub async fn read_json<T>(path: &Path) -> Result<T, XferError>
where
    T: DeserializeOwned,
{
    let bytes = tokio::fs::read(path).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub async fn read_json_if_exists<T>(path: &Path) -> Result<Option<T>, XferError>
where
    T: DeserializeOwned,
{
    if !tokio::fs::try_exists(path).await? {
        return Ok(None);
    }
    read_json(path).await.map(Some)
}
