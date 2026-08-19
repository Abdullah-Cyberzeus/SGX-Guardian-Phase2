use crate::vault::errors::VaultError;
use crate::vault::model::VaultRecord;
use crate::vault::namespace::VaultNamespace;
use crate::vault::VaultConfig;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

pub fn safe_id(id: &str) -> String {
    id.chars()
        .map(|ch| match ch {
            ':' | '/' | '\\' | '\0' => '_',
            _ => ch,
        })
        .collect()
}

pub fn blobs_dir(config: &VaultConfig) -> PathBuf {
    config.base_dir.join("blobs")
}

pub fn meta_dir(config: &VaultConfig) -> PathBuf {
    config.base_dir.join("meta")
}

pub fn staging_dir(config: &VaultConfig) -> PathBuf {
    config.base_dir.join("staging")
}

pub fn quota_dir(config: &VaultConfig) -> PathBuf {
    config.base_dir.join("quota")
}

pub fn wrap_dir(config: &VaultConfig) -> PathBuf {
    config.base_dir.join("wrap")
}

pub fn blob_path(config: &VaultConfig, circle_id: &str, vault_id: &str) -> PathBuf {
    blob_path_for_namespace(
        config,
        &VaultNamespace::Circle(circle_id.to_string()),
        vault_id,
    )
}

pub fn meta_path(config: &VaultConfig, circle_id: &str, vault_id: &str) -> PathBuf {
    meta_path_for_namespace(
        config,
        &VaultNamespace::Circle(circle_id.to_string()),
        vault_id,
    )
}

pub fn blob_namespace_dir(config: &VaultConfig, namespace: &VaultNamespace) -> PathBuf {
    blobs_dir(config).join(namespace.dir_name())
}

pub fn meta_namespace_dir(config: &VaultConfig, namespace: &VaultNamespace) -> PathBuf {
    meta_dir(config).join(namespace.dir_name())
}

pub fn blob_path_for_namespace(
    config: &VaultConfig,
    namespace: &VaultNamespace,
    vault_id: &str,
) -> PathBuf {
    blob_namespace_dir(config, namespace).join(format!("{}.enc", safe_id(vault_id)))
}

pub fn meta_path_for_namespace(
    config: &VaultConfig,
    namespace: &VaultNamespace,
    vault_id: &str,
) -> PathBuf {
    meta_namespace_dir(config, namespace).join(format!("{}.json", safe_id(vault_id)))
}

pub fn record_blob_path(config: &VaultConfig, record: &VaultRecord) -> PathBuf {
    blob_path_for_namespace(config, &record.namespace_ref(), &record.vault_id)
}

pub fn record_meta_path(config: &VaultConfig, record: &VaultRecord) -> PathBuf {
    meta_path_for_namespace(config, &record.namespace_ref(), &record.vault_id)
}

pub fn folder_index_path(config: &VaultConfig, namespace: &VaultNamespace) -> PathBuf {
    meta_namespace_dir(config, namespace).join("folders.json")
}

pub fn master_key_path(config: &VaultConfig) -> PathBuf {
    wrap_dir(config).join("software-master.key")
}

pub fn quota_settings_path(config: &VaultConfig) -> PathBuf {
    quota_dir(config).join("settings.json")
}

pub fn decrypt_temp_path(config: &VaultConfig, vault_id: &str) -> PathBuf {
    staging_dir(config).join(format!("{}-{}.download", safe_id(vault_id), Uuid::new_v4()))
}

pub async fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
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

pub async fn save_json_pretty<T>(path: &Path, value: &T) -> Result<(), VaultError>
where
    T: Serialize,
{
    write_atomic(path, &serde_json::to_vec_pretty(value)?).await
}

pub async fn read_json<T>(path: &Path) -> Result<T, VaultError>
where
    T: DeserializeOwned,
{
    let bytes = tokio::fs::read(path).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub async fn read_json_if_exists<T>(path: &Path) -> Result<Option<T>, VaultError>
where
    T: DeserializeOwned,
{
    if !tokio::fs::try_exists(path).await? {
        return Ok(None);
    }
    read_json(path).await.map(Some)
}

pub async fn save_record(config: &VaultConfig, record: &VaultRecord) -> Result<(), VaultError> {
    save_json_pretty(&record_meta_path(config, record), record).await
}

pub async fn load_record(
    config: &VaultConfig,
    circle_id: &str,
    vault_id: &str,
) -> Result<Option<VaultRecord>, VaultError> {
    let namespace = VaultNamespace::parse(circle_id)?;
    read_json_if_exists(&meta_path_for_namespace(config, &namespace, vault_id)).await
}

pub async fn find_record(
    config: &VaultConfig,
    vault_id: &str,
) -> Result<Option<VaultRecord>, VaultError> {
    let mut circles = match tokio::fs::read_dir(meta_dir(config)).await {
        Ok(dir) => dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let target = format!("{}.json", safe_id(vault_id));
    while let Some(circle) = circles.next_entry().await? {
        if !circle.file_type().await?.is_dir() {
            continue;
        }
        let path = circle.path().join(&target);
        if let Some(record) = read_json_if_exists(&path).await? {
            return Ok(Some(record));
        }
    }
    Ok(None)
}

pub async fn list_records(
    config: &VaultConfig,
    circle_id: Option<&str>,
) -> Result<Vec<VaultRecord>, VaultError> {
    let mut out = Vec::new();
    let circles = if let Some(circle_id) = circle_id {
        let namespace = VaultNamespace::parse(circle_id)?;
        vec![meta_namespace_dir(config, &namespace)]
    } else {
        let mut dirs = Vec::new();
        let mut entries = match tokio::fs::read_dir(meta_dir(config)).await {
            Ok(dir) => dir,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(error) => return Err(error.into()),
        };
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir() {
                dirs.push(entry.path());
            }
        }
        dirs
    };

    for dir in circles {
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(dir) => dir,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        while let Some(entry) = entries.next_entry().await? {
            if !entry.file_type().await?.is_file() {
                continue;
            }
            let Ok(record) = read_json::<VaultRecord>(&entry.path()).await else {
                continue;
            };
            out.push(record);
        }
    }

    out.sort_by(|left, right| right.received_at.cmp(&left.received_at));
    Ok(out)
}

/// Moves a record's blob + metadata to a different namespace, updating
/// `namespace`/`circle_id` in place. Used when a chat attachment uploaded
/// before its destination was known (Personal, owned by the sender) is
/// attached to a group message and needs to live under that Circle's
/// namespace so Circle-membership authorization applies to it. Caller must
/// hold `crate::vault::write_lock()`.
pub async fn move_to_namespace(
    config: &VaultConfig,
    mut record: VaultRecord,
    new_namespace: &VaultNamespace,
) -> Result<VaultRecord, VaultError> {
    let old_blob = record_blob_path(config, &record);
    let old_meta = record_meta_path(config, &record);

    record.namespace = if new_namespace.is_personal() {
        VaultNamespace::PERSONAL_STORAGE_KEY.to_string()
    } else {
        String::new()
    };
    record.circle_id = match new_namespace {
        VaultNamespace::Personal => String::new(),
        VaultNamespace::Circle(circle_id) => circle_id.clone(),
    };

    let new_blob = record_blob_path(config, &record);
    let new_meta = record_meta_path(config, &record);

    if new_blob != old_blob {
        if let Some(parent) = new_blob.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::rename(&old_blob, &new_blob).await?;
    }
    save_json_pretty(&new_meta, &record).await?;
    if new_meta != old_meta {
        let _ = tokio::fs::remove_file(&old_meta).await;
    }
    Ok(record)
}

pub async fn delete_record(config: &VaultConfig, record: &VaultRecord) -> Result<(), VaultError> {
    match tokio::fs::remove_file(record_blob_path(config, record)).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    match tokio::fs::remove_file(record_meta_path(config, record)).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
