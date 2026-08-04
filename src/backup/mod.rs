pub mod components;
pub mod create;
pub mod crypto;
pub mod errors;
pub mod import;
pub mod init;
pub mod model;
pub mod restore;
pub mod validate;

use std::path::PathBuf;

pub const BACKUP_BASE_ENV: &str = "SGX_GUARDIAN_BACKUP_BASE";
pub const BACKUP_MAX_BUNDLE_BYTES_ENV: &str = "SGX_BACKUP_MAX_BUNDLE_BYTES";

#[derive(Debug, Clone)]
pub struct BackupConfig {
    pub base_dir: PathBuf,
    pub max_bundle_bytes: u64,
}

impl BackupConfig {
    pub fn from_env() -> Self {
        let base_dir = std::env::var(BACKUP_BASE_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/var/lib/sgx-guardian/backup"));
        let max_bundle_bytes = std::env::var(BACKUP_MAX_BUNDLE_BYTES_ENV)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(1024 * 1024 * 1024);
        Self {
            base_dir,
            max_bundle_bytes,
        }
    }

    pub fn bundles_dir(&self) -> PathBuf {
        self.base_dir.join("bundles")
    }

    pub fn history_path(&self) -> PathBuf {
        self.base_dir.join("history.json")
    }

    pub fn staging_dir(&self) -> PathBuf {
        self.base_dir.join("staging")
    }

    pub fn pre_restore_dir(&self) -> PathBuf {
        self.base_dir.join("pre-restore")
    }

    pub fn restore_dir(&self) -> PathBuf {
        self.base_dir.join("restore")
    }

    pub fn bundle_path(&self, id: &str) -> PathBuf {
        self.bundles_dir().join(format!("{}.sgxbak", safe_id(id)))
    }
}

pub fn safe_id(id: &str) -> String {
    id.chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
        .collect()
}

#[cfg(test)]
mod tests;
