use crate::api::state::AppState;
use crate::backup::errors::BackupError;
use crate::backup::model::{BackupRecord, Component};
use crate::backup::BackupConfig;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(unix)]
const SECURE_DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const SECURE_FILE_MODE: u32 = 0o600;

#[derive(Debug, Clone, Serialize)]
pub struct BackupImportReport {
    pub id: String,
    pub created_at: String,
    pub source_node_id: String,
    pub source_did: String,
    pub target_did: String,
    pub portable: bool,
    pub components: Vec<Component>,
    pub bundle_path: String,
    pub size_bytes: u64,
}

pub fn import_dir(config: &BackupConfig) -> PathBuf {
    config.base_dir.join("import")
}

pub async fn prepare_import_dir(config: &BackupConfig) -> Result<PathBuf, BackupError> {
    let dir = import_dir(config);
    create_secure_dir_all(&dir).await?;
    Ok(dir)
}

pub async fn import_staged_bundle(
    state: Arc<AppState>,
    config: BackupConfig,
    staged_path: &Path,
    passphrase: &str,
) -> Result<BackupImportReport, BackupError> {
    create_secure_dir_all(&config.bundles_dir()).await?;
    let size_bytes = tokio::fs::metadata(staged_path).await?.len();
    if size_bytes > config.max_bundle_bytes {
        return Err(BackupError::BundleTooLarge {
            size: size_bytes,
            max: config.max_bundle_bytes,
        });
    }

    let decoded = crate::backup::validate::decode_backup_file(
        staged_path,
        passphrase,
        config.max_bundle_bytes,
    )
    .await?;
    crate::backup::validate::validate_manifest(&decoded)?;

    let backup_id = decoded.manifest.backup_id.clone();
    if crate::backup::safe_id(&backup_id) != backup_id {
        return Err(BackupError::InvalidRequest(format!(
            "unsafe backup id: {}",
            backup_id
        )));
    }
    let same_device_identity = decoded.manifest.source_did == state.device_did;
    if !same_device_identity && !decoded.manifest.portable {
        return Err(BackupError::RestoreUnavailable(
            "source DID differs from target DID and backup is not portable".to_string(),
        ));
    }

    let history = crate::backup::create::load_history(&config).await?;
    if history.records.iter().any(|record| record.id == backup_id) {
        return Err(BackupError::Duplicate(backup_id));
    }
    let bundle_path = config.bundle_path(&backup_id);
    if tokio::fs::try_exists(&bundle_path).await? {
        return Err(BackupError::Duplicate(backup_id));
    }

    publish_without_overwrite(staged_path, &bundle_path).await?;
    let record = BackupRecord {
        id: backup_id,
        created_at: decoded.manifest.created_at,
        source_node_id: decoded.manifest.source_node_id,
        source_did: decoded.manifest.source_did,
        portable: decoded.manifest.portable,
        components: decoded
            .manifest
            .components
            .iter()
            .map(|component| component.component)
            .collect(),
        bundle_path: bundle_path.to_string_lossy().to_string(),
        size_bytes,
    };
    crate::backup::create::register_imported_backup(&config, record.clone()).await?;

    Ok(BackupImportReport {
        id: record.id,
        created_at: record.created_at,
        source_node_id: record.source_node_id,
        source_did: record.source_did,
        target_did: state.device_did.clone(),
        portable: record.portable,
        components: record.components,
        bundle_path: record.bundle_path,
        size_bytes: record.size_bytes,
    })
}

async fn publish_without_overwrite(source: &Path, target: &Path) -> Result<(), BackupError> {
    let source = source.to_path_buf();
    let target = target.to_path_buf();
    let published = target.clone();
    tokio::task::spawn_blocking(move || -> Result<(), BackupError> {
        std::fs::hard_link(&source, &target).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                BackupError::Duplicate("bundle already exists".to_string())
            } else {
                BackupError::Io(error)
            }
        })?;
        std::fs::remove_file(&source)?;
        Ok(())
    })
    .await
    .map_err(|error| BackupError::Io(std::io::Error::other(error)))??;
    set_secure_file_permissions(&published).await
}

async fn create_secure_dir_all(path: &Path) -> Result<(), BackupError> {
    tokio::fs::create_dir_all(path).await?;
    set_secure_dir_permissions(path).await
}

#[cfg(unix)]
async fn set_secure_dir_permissions(path: &Path) -> Result<(), BackupError> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(SECURE_DIR_MODE)).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn set_secure_dir_permissions(_path: &Path) -> Result<(), BackupError> {
    Ok(())
}

#[cfg(unix)]
async fn set_secure_file_permissions(path: &Path) -> Result<(), BackupError> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(SECURE_FILE_MODE)).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn set_secure_file_permissions(_path: &Path) -> Result<(), BackupError> {
    Ok(())
}
