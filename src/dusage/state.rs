use crate::dusage::errors::DusageResult;
use crate::dusage::model::{local_integrity_proof, DusageQuota, DusageState, UsageSnapshot};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncWriteExt;

pub const DUSAGE_BASE: &str = "/var/lib/sgx-guardian/dusage";
pub const DUSAGE_BASE_ENV: &str = "SGX_GUARDIAN_DUSAGE_BASE";
pub const MAX_HISTORY_ROWS: usize = 400;

pub fn base_dir() -> PathBuf {
    std::env::var(DUSAGE_BASE_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DUSAGE_BASE))
}

pub fn state_path() -> PathBuf {
    base_dir().join("state.json")
}

pub fn history_path() -> PathBuf {
    base_dir().join("history.jsonl")
}

pub fn quota_path() -> PathBuf {
    base_dir().join("quota.json")
}

pub async fn load_state() -> DusageResult<Option<DusageState>> {
    read_json_optional(&state_path()).await
}

pub async fn save_state(state: &mut DusageState) -> DusageResult<()> {
    seal_state(state)?;
    write_atomic(&state_path(), &serde_json::to_vec_pretty(state)?).await
}

pub async fn load_quota() -> DusageResult<Option<DusageQuota>> {
    read_json_optional(&quota_path()).await
}

pub async fn save_quota(quota: &mut DusageQuota) -> DusageResult<()> {
    seal_quota(quota)?;
    write_atomic(&quota_path(), &serde_json::to_vec_pretty(quota)?).await
}

pub async fn load_history() -> DusageResult<Vec<UsageSnapshot>> {
    let path = history_path();
    let text = match fs::read_to_string(&path).await {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };

    let mut out = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        out.push(serde_json::from_str::<UsageSnapshot>(line)?);
    }
    Ok(out)
}

pub async fn append_history(snapshot: &UsageSnapshot) -> DusageResult<()> {
    let mut rows = load_history().await?;
    rows.push(snapshot.clone());
    if rows.len() > MAX_HISTORY_ROWS {
        let drain_count = rows.len() - MAX_HISTORY_ROWS;
        rows.drain(0..drain_count);
    }

    let mut bytes = Vec::new();
    for row in rows {
        serde_json::to_writer(&mut bytes, &row)?;
        bytes.push(b'\n');
    }
    write_atomic(&history_path(), &bytes).await
}

pub fn seal_state(state: &mut DusageState) -> DusageResult<()> {
    state.proof = crate::did::document::Proof::default();
    let bytes = serde_json::to_vec(&state.without_proof())?;
    state.proof = local_integrity_proof(&bytes);
    Ok(())
}

pub fn seal_quota(quota: &mut DusageQuota) -> DusageResult<()> {
    quota.proof = crate::did::document::Proof::default();
    let bytes = serde_json::to_vec(&quota.without_proof())?;
    quota.proof = local_integrity_proof(&bytes);
    Ok(())
}

async fn read_json_optional<T>(path: &Path) -> DusageResult<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    let bytes = match fs::read(path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    Ok(Some(serde_json::from_slice(&bytes)?))
}

async fn write_atomic(path: &Path, bytes: &[u8]) -> DusageResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }

    let tmp = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&tmp).await?;
        file.write_all(bytes).await?;
        file.sync_all().await?;
    }
    fs::rename(&tmp, path).await?;
    Ok(())
}
