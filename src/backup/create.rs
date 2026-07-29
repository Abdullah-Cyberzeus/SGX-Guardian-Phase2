use crate::api::state::AppState;
use crate::backup::components;
use crate::backup::crypto;
use crate::backup::errors::BackupError;
use crate::backup::model::{BackupHistory, BackupRecord, Manifest, BACKUP_SCHEMA_VERSION};
use crate::backup::BackupConfig;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use uuid::Uuid;

#[cfg(unix)]
const SECURE_DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const SECURE_FILE_MODE: u32 = 0o600;

pub async fn create_backup(
    state: Arc<AppState>,
    config: BackupConfig,
    passphrase: String,
    portable: bool,
) -> Result<BackupRecord, BackupError> {
    components::assert_no_private_identity_paths(&components::component_paths(&state))?;
    ensure_secure_layout(&config).await?;

    let files = components::gather_files(&state).await?;
    let created_at = Utc::now().to_rfc3339();
    let backup_id = format!("bak-{}", Uuid::new_v4());
    let component_manifest = components::component_manifest(&files);
    let identity_meta = components::identity_meta(&state);
    let plaintext = encode_plaintext(&files)?;
    let plaintext_sha256 = hex::encode(Sha256::digest(&plaintext));

    let mut manifest = Manifest {
        schema_version: BACKUP_SCHEMA_VERSION,
        backup_id: backup_id.clone(),
        created_at: created_at.clone(),
        source_node_id: state.node_id.clone(),
        source_did: state.device_did.clone(),
        portable,
        components: component_manifest,
        identity_meta,
        plaintext_sha256,
        bundle_hmac_sha256: String::new(),
    };
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let mut full_plaintext = Vec::with_capacity(4 + manifest_bytes.len() + plaintext.len());
    let manifest_len = u32::try_from(manifest_bytes.len())
        .map_err(|_| BackupError::InvalidRequest("manifest too large".to_string()))?;
    full_plaintext.write_all(&manifest_len.to_be_bytes())?;
    full_plaintext.write_all(&manifest_bytes)?;
    full_plaintext.write_all(&plaintext)?;

    let bundle_path = config.bundle_path(&backup_id);
    let passphrase_for_blocking = passphrase.clone();
    let bundle_path_for_blocking = bundle_path.clone();
    let encrypt_result = tokio::task::spawn_blocking(move || {
        let mut file = create_secure_file(&bundle_path_for_blocking)?;
        crypto::encrypt_to_writer(&full_plaintext, &passphrase_for_blocking, &mut file)
    })
    .await
    .map_err(|error| BackupError::Crypto(format!("backup encryption task failed: {}", error)))??;

    manifest.bundle_hmac_sha256 = encrypt_result.bundle_hmac_sha256;
    let size_bytes = tokio::fs::metadata(&bundle_path).await?.len();
    let record = BackupRecord {
        id: backup_id,
        created_at,
        source_node_id: state.node_id.clone(),
        source_did: state.device_did.clone(),
        portable,
        components: manifest
            .components
            .iter()
            .map(|component| component.component)
            .collect(),
        bundle_path: bundle_path.to_string_lossy().to_string(),
        size_bytes,
    };
    append_history(&config, record.clone()).await?;
    Ok(record)
}

pub async fn load_history(config: &BackupConfig) -> Result<BackupHistory, BackupError> {
    if !tokio::fs::try_exists(config.history_path()).await? {
        return Ok(BackupHistory::default());
    }
    Ok(serde_json::from_slice(
        &tokio::fs::read(config.history_path()).await?,
    )?)
}

pub async fn save_history(
    config: &BackupConfig,
    history: &BackupHistory,
) -> Result<(), BackupError> {
    secure_write_atomic(&config.history_path(), &serde_json::to_vec_pretty(history)?).await
}

pub async fn delete_backup(config: &BackupConfig, id: &str) -> Result<(), BackupError> {
    let mut history = load_history(config).await?;
    let before = history.records.len();
    history.records.retain(|record| record.id != id);
    if before == history.records.len() {
        return Err(BackupError::NotFound(id.to_string()));
    }
    let path = config.bundle_path(id);
    match tokio::fs::remove_file(path).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    save_history(config, &history).await
}

async fn append_history(config: &BackupConfig, record: BackupRecord) -> Result<(), BackupError> {
    let mut history = load_history(config).await?;
    history.records.retain(|existing| existing.id != record.id);
    history.records.insert(0, record);
    save_history(config, &history).await
}

fn encode_plaintext(files: &[components::GatheredFile]) -> Result<Vec<u8>, BackupError> {
    let mut out = Vec::new();
    for file in files {
        let path = file.archive_path.as_bytes();
        let path_len = u32::try_from(path.len())
            .map_err(|_| BackupError::InvalidRequest("archive path too long".to_string()))?;
        let data_len = u64::try_from(file.bytes.len())
            .map_err(|_| BackupError::InvalidRequest("file too large".to_string()))?;
        out.write_all(&path_len.to_be_bytes())?;
        out.write_all(path)?;
        out.write_all(&data_len.to_be_bytes())?;
        out.write_all(&file.bytes)?;
    }
    Ok(out)
}

async fn ensure_secure_layout(config: &BackupConfig) -> Result<(), BackupError> {
    for dir in [
        config.base_dir.clone(),
        config.bundles_dir(),
        config.staging_dir(),
        config.restore_dir(),
        config.pre_restore_dir(),
    ] {
        create_secure_dir_all(&dir).await?;
    }
    Ok(())
}

async fn create_secure_dir_all(path: &Path) -> Result<(), BackupError> {
    tokio::fs::create_dir_all(path).await?;
    set_secure_dir_permissions(path).await
}

async fn secure_write_atomic(path: &Path, bytes: &[u8]) -> Result<(), BackupError> {
    if let Some(parent) = path.parent() {
        create_secure_dir_all(parent).await?;
    }
    let tmp = path.with_extension("tmp");
    let bytes = bytes.to_vec();
    let tmp_for_blocking = tmp.clone();
    tokio::task::spawn_blocking(move || -> Result<(), BackupError> {
        let mut file = create_secure_file(&tmp_for_blocking)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    })
    .await
    .map_err(|error| BackupError::Io(std::io::Error::other(error)))??;
    tokio::fs::rename(&tmp, path).await?;
    set_secure_file_permissions(path).await
}

#[cfg(unix)]
fn create_secure_file(path: &Path) -> Result<std::fs::File, BackupError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(SECURE_DIR_MODE))?;
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(SECURE_FILE_MODE)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(SECURE_FILE_MODE))?;
    Ok(file)
}

#[cfg(not(unix))]
fn create_secure_file(path: &Path) -> Result<std::fs::File, BackupError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?)
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
