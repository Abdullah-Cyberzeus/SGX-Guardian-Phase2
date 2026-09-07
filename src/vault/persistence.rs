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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::model::{EncMeta, VaultSource};
    use tempfile::TempDir;

    fn temp_config() -> (TempDir, VaultConfig) {
        let temp = TempDir::new().expect("tempdir");
        let config = VaultConfig {
            base_dir: temp.path().join("vault"),
        };
        (temp, config)
    }

    fn record(
        vault_id: &str,
        namespace: VaultNamespace,
        received_at: &str,
        size_cipher: u64,
    ) -> VaultRecord {
        VaultRecord {
            vault_id: vault_id.to_string(),
            namespace: if namespace.is_personal() {
                VaultNamespace::PERSONAL_STORAGE_KEY.to_string()
            } else {
                String::new()
            },
            circle_id: match namespace {
                VaultNamespace::Personal => String::new(),
                VaultNamespace::Circle(circle_id) => circle_id,
            },
            filename: "fixture.bin".into(),
            mime: "application/octet-stream".into(),
            size_plain: 16,
            size_cipher,
            sha256_plain: "ab".repeat(32),
            sender_did: "did:guardian:sender".into(),
            received_at: received_at.to_string(),
            source: VaultSource::FileTransfer,
            folder_id: String::new(),
            starred: false,
            description: String::new(),
            owner_did: String::new(),
            revoked: false,
            revoked_at: None,
            expires_at: None,
            conversation_recipient_did: None,
            message_id: None,
            enc: EncMeta {
                algo: "AES-256-GCM/STREAM-BE32".into(),
                chunk_bytes: VaultConfig::DEFAULT_CHUNK_BYTES,
                base_nonce_b64: "AAAAAAAAAA==".into(),
                wrapped_dek_b64: "d3JhcHBlZA==".into(),
                wrap_scheme: "software-hkdf".into(),
                wrap_key_id: "software-master-v1".into(),
            },
        }
    }

    #[test]
    fn safe_id_replaces_path_sensitive_characters_only() {
        assert_eq!(
            safe_id("urn:uuid/file\\name\0tail"),
            "urn_uuid_file_name_tail"
        );
        assert_eq!(safe_id("plain id with spaces"), "plain id with spaces");
        assert_eq!(safe_id("dots..and-dashes"), "dots..and-dashes");
    }

    #[test]
    fn path_helpers_use_expected_directories_and_safe_file_names() {
        let (_temp, config) = temp_config();
        let personal = VaultNamespace::Personal;
        let circle = VaultNamespace::Circle("circle/a:b\\c".to_string());

        assert_eq!(blobs_dir(&config), config.base_dir.join("blobs"));
        assert_eq!(meta_dir(&config), config.base_dir.join("meta"));
        assert_eq!(staging_dir(&config), config.base_dir.join("staging"));
        assert_eq!(quota_dir(&config), config.base_dir.join("quota"));
        assert_eq!(wrap_dir(&config), config.base_dir.join("wrap"));
        assert_eq!(
            master_key_path(&config),
            wrap_dir(&config).join("software-master.key")
        );
        assert_eq!(
            quota_settings_path(&config),
            quota_dir(&config).join("settings.json")
        );
        assert!(decrypt_temp_path(&config, "urn:uuid/a").starts_with(staging_dir(&config)));

        assert_eq!(
            blob_path_for_namespace(&config, &personal, "urn:uuid/file"),
            blobs_dir(&config)
                .join("personal")
                .join("urn_uuid_file.enc")
        );
        assert_eq!(
            meta_path_for_namespace(&config, &circle, "urn:uuid/file"),
            meta_dir(&config)
                .join("circle_a_b_c")
                .join("urn_uuid_file.json")
        );
    }

    #[tokio::test]
    async fn write_atomic_creates_parents_overwrites_and_cleans_temp_path() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("nested").join("value.json");

        write_atomic(&path, b"{\"value\":1}")
            .await
            .expect("initial write");
        write_atomic(&path, b"{\"value\":2}")
            .await
            .expect("overwrite");

        assert_eq!(
            tokio::fs::read(&path).await.expect("read final bytes"),
            br#"{"value":2}"#
        );
        assert!(!path.with_extension("tmp").exists());
    }

    #[tokio::test]
    async fn json_helpers_handle_missing_valid_and_malformed_files() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("data.json");

        assert!(read_json_if_exists::<serde_json::Value>(&path)
            .await
            .expect("missing is ok")
            .is_none());

        save_json_pretty(&path, &serde_json::json!({ "ok": true }))
            .await
            .expect("save json");
        assert_eq!(
            read_json::<serde_json::Value>(&path)
                .await
                .expect("read json"),
            serde_json::json!({ "ok": true })
        );

        write_atomic(&path, b"{broken-json")
            .await
            .expect("write malformed");
        assert!(read_json::<serde_json::Value>(&path).await.is_err());
        assert!(read_json_if_exists::<serde_json::Value>(&path)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn record_save_load_find_and_list_cover_missing_and_invalid_namespaces() {
        let (_temp, config) = temp_config();
        let circle = VaultNamespace::Circle("circle-alpha".to_string());
        let personal = VaultNamespace::Personal;
        let circle_record = record(
            "urn:uuid:circle",
            circle.clone(),
            "2026-01-02T00:00:00Z",
            200,
        );
        let personal_record = record("urn:uuid:personal", personal, "2026-01-01T00:00:00Z", 100);

        assert!(list_records(&config, None)
            .await
            .expect("missing meta dir lists empty")
            .is_empty());
        assert!(find_record(&config, "missing")
            .await
            .expect("missing find")
            .is_none());

        save_record(&config, &circle_record)
            .await
            .expect("save circle record");
        save_record(&config, &personal_record)
            .await
            .expect("save personal record");

        assert_eq!(
            load_record(&config, "circle-alpha", &circle_record.vault_id)
                .await
                .expect("load circle")
                .expect("circle record"),
            circle_record
        );
        assert_eq!(
            find_record(&config, &personal_record.vault_id)
                .await
                .expect("find personal")
                .expect("personal record"),
            personal_record
        );

        let all = list_records(&config, None).await.expect("list all");
        assert_eq!(
            all.iter()
                .map(|record| record.vault_id.as_str())
                .collect::<Vec<_>>(),
            vec!["urn:uuid:circle", "urn:uuid:personal"]
        );
        assert!(list_records(&config, Some("bad/name")).await.is_err());
        assert!(load_record(&config, "../bad", "id").await.is_err());
    }

    #[tokio::test]
    async fn list_records_ignores_non_files_and_malformed_json_and_sorts_descending() {
        let (_temp, config) = temp_config();
        let namespace = VaultNamespace::Circle("circle-sort".to_string());
        let older = record(
            "urn:uuid:older",
            namespace.clone(),
            "2026-01-01T00:00:00Z",
            100,
        );
        let newer = record(
            "urn:uuid:newer",
            namespace.clone(),
            "2026-01-03T00:00:00Z",
            300,
        );

        save_record(&config, &older).await.expect("save older");
        save_record(&config, &newer).await.expect("save newer");
        tokio::fs::write(
            meta_namespace_dir(&config, &namespace).join("broken.json"),
            b"{bad",
        )
        .await
        .expect("write malformed json");
        tokio::fs::create_dir_all(meta_namespace_dir(&config, &namespace).join("subdir.json"))
            .await
            .expect("create ignored dir");
        tokio::fs::write(meta_dir(&config).join("not-a-dir"), b"ignored")
            .await
            .expect("write ignored file");

        let listed = list_records(&config, Some("circle-sort"))
            .await
            .expect("list namespace");
        assert_eq!(
            listed
                .iter()
                .map(|record| record.vault_id.as_str())
                .collect::<Vec<_>>(),
            vec!["urn:uuid:newer", "urn:uuid:older"]
        );
    }

    #[tokio::test]
    async fn delete_record_removes_existing_files_and_ignores_missing_files() {
        let (_temp, config) = temp_config();
        let record = record(
            "urn:uuid:delete",
            VaultNamespace::Circle("circle-delete".to_string()),
            "2026-01-01T00:00:00Z",
            100,
        );
        let blob = record_blob_path(&config, &record);
        let meta = record_meta_path(&config, &record);

        save_record(&config, &record).await.expect("save metadata");
        write_atomic(&blob, b"ciphertext").await.expect("save blob");
        assert!(blob.exists());
        assert!(meta.exists());

        delete_record(&config, &record)
            .await
            .expect("delete existing");
        assert!(!blob.exists());
        assert!(!meta.exists());

        delete_record(&config, &record)
            .await
            .expect("delete missing is ok");
    }

    #[tokio::test]
    async fn move_to_namespace_moves_blob_and_metadata_between_personal_and_circle() {
        let (_temp, config) = temp_config();
        let original = record(
            "urn:uuid:move",
            VaultNamespace::Personal,
            "2026-01-01T00:00:00Z",
            100,
        );
        let old_blob = record_blob_path(&config, &original);
        let old_meta = record_meta_path(&config, &original);
        save_record(&config, &original)
            .await
            .expect("save original metadata");
        write_atomic(&old_blob, b"ciphertext")
            .await
            .expect("save original blob");

        let moved = move_to_namespace(
            &config,
            original,
            &VaultNamespace::Circle("circle-move".to_string()),
        )
        .await
        .expect("move to circle");

        assert_eq!(moved.namespace, "");
        assert_eq!(moved.circle_id, "circle-move");
        assert!(!old_blob.exists());
        assert!(!old_meta.exists());
        assert_eq!(
            tokio::fs::read(record_blob_path(&config, &moved))
                .await
                .expect("read moved blob"),
            b"ciphertext"
        );
        assert!(load_record(&config, "circle-move", &moved.vault_id)
            .await
            .expect("load moved")
            .is_some());
    }

    #[tokio::test]
    async fn move_to_namespace_fails_when_source_blob_is_missing() {
        let (_temp, config) = temp_config();
        let original = record(
            "urn:uuid:missing-blob",
            VaultNamespace::Personal,
            "2026-01-01T00:00:00Z",
            100,
        );
        save_record(&config, &original)
            .await
            .expect("save metadata only");

        let error = move_to_namespace(
            &config,
            original,
            &VaultNamespace::Circle("circle-move".to_string()),
        )
        .await
        .expect_err("missing blob should fail");
        assert!(matches!(
            error,
            VaultError::Io(ref io_error) if io_error.kind() == std::io::ErrorKind::NotFound
        ));
    }
}
