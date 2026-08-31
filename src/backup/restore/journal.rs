use crate::backup::errors::BackupError;
use crate::backup::BackupConfig;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestorePhase {
    Prepared,
    Snapshotted,
    Staged,
    Swapping,
    Swapped,
    Verifying,
    Committed,
    RollingBack,
    RolledBack,
}

impl RestorePhase {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Committed | Self::RolledBack)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreJournal {
    pub restore_id: String,
    pub bundle_id: String,
    pub node_id: String,
    pub phase: RestorePhase,
    pub component_index: Option<usize>,
    pub snapshot_path: Option<String>,
    pub updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreStatus {
    pub status: String,
    pub journal_path: String,
    pub journal: Option<RestoreJournal>,
}

pub fn restore_dir(config: &BackupConfig) -> PathBuf {
    config.restore_dir()
}

pub fn restore_staging_dir(config: &BackupConfig) -> PathBuf {
    restore_dir(config).join("staging")
}

pub fn journal_path(config: &BackupConfig) -> PathBuf {
    restore_dir(config).join("journal.json")
}

pub fn status(config: &BackupConfig) -> Result<RestoreStatus, BackupError> {
    let path = journal_path(config);
    let journal = load_current(config)?;
    Ok(RestoreStatus {
        status: if journal.is_some() {
            "journal_present".to_string()
        } else {
            "idle".to_string()
        },
        journal_path: path.to_string_lossy().to_string(),
        journal,
    })
}

pub fn status_with_recovery(
    config: &BackupConfig,
    node_id: &str,
) -> Result<RestoreStatus, BackupError> {
    recover_stale_journal(config, node_id)?;
    status(config)
}

pub fn load_current(config: &BackupConfig) -> Result<Option<RestoreJournal>, BackupError> {
    let path = journal_path(config);
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
}

pub fn write_journal(config: &BackupConfig, journal: &RestoreJournal) -> Result<(), BackupError> {
    let path = journal_path(config);
    secure_write_atomic(&path, &serde_json::to_vec_pretty(journal)?)
}

pub fn recover_if_interrupted(node_id: &str) {
    let config = BackupConfig::from_env();
    match recover_if_interrupted_inner(&config, node_id) {
        Ok(Some(journal)) => {
            eprintln!(
                "restore recovery marked interrupted restore {} as {:?}",
                journal.restore_id, journal.phase
            );
        }
        Ok(None) => {}
        Err(error) => {
            eprintln!("restore recovery check failed: {}", error);
        }
    }
}

pub fn recover_if_interrupted_inner(
    config: &BackupConfig,
    node_id: &str,
) -> Result<Option<RestoreJournal>, BackupError> {
    let Some(mut journal) = load_current(config)? else {
        return Ok(None);
    };
    if journal.phase.is_terminal() {
        return Ok(None);
    }
    journal.phase = RestorePhase::RolledBack;
    journal.node_id = node_id.to_string();
    journal.updated_at = Utc::now().to_rfc3339();
    journal.message = Some(
        "interrupted restore detected at startup; recovery marked the transaction rolled_back"
            .to_string(),
    );
    write_journal(config, &journal)?;
    Ok(Some(journal))
}

pub fn recover_stale_journal(
    config: &BackupConfig,
    node_id: &str,
) -> Result<Option<RestoreJournal>, BackupError> {
    let Some(journal) = load_current(config)? else {
        return Ok(None);
    };
    if journal.phase.is_terminal() || !journal_is_stale(&journal) {
        return Ok(None);
    }

    let mut recovered = journal;
    recovered.phase = RestorePhase::RolledBack;
    recovered.node_id = node_id.to_string();
    recovered.updated_at = Utc::now().to_rfc3339();
    recovered.message = Some(
        "stale restore journal detected; recovery marked the transaction rolled_back"
            .to_string(),
    );
    write_journal(config, &recovered)?;
    Ok(Some(recovered))
}

fn journal_is_stale(journal: &RestoreJournal) -> bool {
    const STALE_RESTORE_WINDOW_MINUTES: i64 = 15;
    let Ok(updated_at) = DateTime::parse_from_rfc3339(&journal.updated_at) else {
        return true;
    };
    Utc::now().signed_duration_since(updated_at.with_timezone(&Utc))
        >= Duration::minutes(STALE_RESTORE_WINDOW_MINUTES)
}

fn secure_write_atomic(path: &Path, bytes: &[u8]) -> Result<(), BackupError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        set_dir_mode(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut file = create_secure_file(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    set_file_mode(path)?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

#[cfg(unix)]
fn create_secure_file(path: &Path) -> Result<fs::File, BackupError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

#[cfg(not(unix))]
fn create_secure_file(path: &Path) -> Result<fs::File, BackupError> {
    Ok(OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?)
}

#[cfg(unix)]
fn set_dir_mode(path: &Path) -> Result<(), BackupError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_mode(_path: &Path) -> Result<(), BackupError> {
    Ok(())
}

#[cfg(unix)]
fn set_file_mode(path: &Path) -> Result<(), BackupError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_mode(_path: &Path) -> Result<(), BackupError> {
    Ok(())
}
