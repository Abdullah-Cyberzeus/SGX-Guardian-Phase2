//! Encrypted attachment vault used by in-circle file transfer.

pub mod crypto;
pub mod errors;
pub mod folders;
pub mod ingest;
pub mod model;
pub mod namespace;
pub mod persistence;
pub mod quota;
pub mod upload;
pub mod wrapper;

pub use errors::VaultError;
pub use model::{EncMeta, VaultRecord, VaultSource};
pub use namespace::VaultNamespace;

use std::env;
use std::path::PathBuf;

pub const VAULT_BASE: &str = "/var/lib/sgx-guardian/vault";
pub const VAULT_BASE_ENV: &str = "SGX_GUARDIAN_VAULT_BASE";

static VAULT_WRITE_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

#[derive(Debug, Clone)]
pub struct VaultConfig {
    pub base_dir: PathBuf,
}

impl VaultConfig {
    pub const DEFAULT_CHUNK_BYTES: u32 = crate::xfer::XferConfig::DEFAULT_CHUNK_BYTES;

    pub fn from_env() -> Self {
        Self {
            base_dir: env::var(VAULT_BASE_ENV)
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from(VAULT_BASE)),
        }
    }
}

pub fn download_path(vault_id: &str) -> String {
    format!("/api/v1/vault/files/{}/download", vault_id)
}

pub(crate) fn write_lock() -> &'static tokio::sync::Mutex<()> {
    VAULT_WRITE_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

#[cfg(test)]
static TEST_ENV_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

#[cfg(test)]
pub(crate) async fn lock_test_env() -> tokio::sync::MutexGuard<'static, ()> {
    TEST_ENV_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
