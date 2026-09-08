use chrono::{Duration, Utc};
use sgx_guardian_client::vault::model::{EncMeta, VaultRecord, VaultSource};
use sgx_guardian_client::vault::namespace::VaultNamespace;
use sgx_guardian_client::vault::persistence::{
    blob_path_for_namespace, meta_namespace_dir, save_record,
};
use sgx_guardian_client::vault::{VaultConfig, VaultExpiryReaper};
use tempfile::tempdir;

fn config() -> (tempfile::TempDir, VaultConfig) {
    let dir = tempdir().unwrap();
    let config = VaultConfig {
        base_dir: dir.path().join("vault"),
    };
    (dir, config)
}

fn record(id: &str, namespace: VaultNamespace, expires_at: Option<String>) -> VaultRecord {
    VaultRecord {
        vault_id: id.into(),
        namespace: if namespace.is_personal() {
            VaultNamespace::PERSONAL_STORAGE_KEY.into()
        } else {
            String::new()
        },
        circle_id: match namespace {
            VaultNamespace::Personal => String::new(),
            VaultNamespace::Circle(circle) => circle,
        },
        filename: "file.bin".into(),
        mime: "application/octet-stream".into(),
        size_plain: 3,
        size_cipher: 4,
        sha256_plain: "ab".repeat(32),
        sender_did: "did:sender".into(),
        received_at: "2026-01-01T00:00:00Z".into(),
        source: VaultSource::Upload,
        folder_id: String::new(),
        starred: false,
        description: String::new(),
        owner_did: "did:owner".into(),
        revoked: false,
        revoked_at: None,
        expires_at,
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

async fn save_record_and_blob(config: &VaultConfig, record: &VaultRecord) {
    save_record(config, record).await.unwrap();
    let namespace = record.namespace_ref();
    let blob = blob_path_for_namespace(config, &namespace, &record.vault_id);
    tokio::fs::create_dir_all(blob.parent().unwrap())
        .await
        .unwrap();
    tokio::fs::write(blob, b"blob").await.unwrap();
}

#[tokio::test]
async fn sweep_returns_zero_when_meta_dir_is_missing() {
    let (_dir, config) = config();
    assert_eq!(VaultExpiryReaper::new(config).sweep().await, 0);
}

#[tokio::test]
async fn sweep_removes_expired_record_and_blob() {
    let (_dir, config) = config();
    let expired = record(
        "expired",
        VaultNamespace::Circle("circle".into()),
        Some((Utc::now() - Duration::seconds(1)).to_rfc3339()),
    );
    let blob = blob_path_for_namespace(&config, &expired.namespace_ref(), &expired.vault_id);
    save_record_and_blob(&config, &expired).await;
    assert_eq!(VaultExpiryReaper::new(config.clone()).sweep().await, 1);
    assert!(!blob.exists());
}

#[tokio::test]
async fn sweep_keeps_future_expiration() {
    let (_dir, config) = config();
    let future = record(
        "future",
        VaultNamespace::Circle("circle".into()),
        Some((Utc::now() + Duration::days(1)).to_rfc3339()),
    );
    let blob = blob_path_for_namespace(&config, &future.namespace_ref(), &future.vault_id);
    save_record_and_blob(&config, &future).await;
    assert_eq!(VaultExpiryReaper::new(config.clone()).sweep().await, 0);
    assert!(blob.exists());
}

#[tokio::test]
async fn sweep_keeps_records_without_expiration() {
    let (_dir, config) = config();
    let live = record("live", VaultNamespace::Personal, None);
    let blob = blob_path_for_namespace(&config, &live.namespace_ref(), &live.vault_id);
    save_record_and_blob(&config, &live).await;
    assert_eq!(VaultExpiryReaper::new(config.clone()).sweep().await, 0);
    assert!(blob.exists());
}

#[tokio::test]
async fn sweep_treats_malformed_expiration_as_not_expired() {
    let (_dir, config) = config();
    let live = record(
        "bad-expiry",
        VaultNamespace::Personal,
        Some("not-a-date".into()),
    );
    let blob = blob_path_for_namespace(&config, &live.namespace_ref(), &live.vault_id);
    save_record_and_blob(&config, &live).await;
    assert_eq!(VaultExpiryReaper::new(config.clone()).sweep().await, 0);
    assert!(blob.exists());
}

#[tokio::test]
async fn sweep_counts_expired_record_even_when_blob_is_missing() {
    let (_dir, config) = config();
    let expired = record(
        "missing-blob",
        VaultNamespace::Personal,
        Some((Utc::now() - Duration::minutes(5)).to_rfc3339()),
    );
    save_record(&config, &expired).await.unwrap();
    assert_eq!(VaultExpiryReaper::new(config.clone()).sweep().await, 1);
    assert!(
        sgx_guardian_client::vault::persistence::find_record(&config, "missing-blob")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn sweep_handles_multiple_namespaces() {
    let (_dir, config) = config();
    let personal = record(
        "personal-expired",
        VaultNamespace::Personal,
        Some((Utc::now() - Duration::seconds(1)).to_rfc3339()),
    );
    let circle = record(
        "circle-expired",
        VaultNamespace::Circle("circle-b".into()),
        Some((Utc::now() - Duration::seconds(1)).to_rfc3339()),
    );
    save_record_and_blob(&config, &personal).await;
    save_record_and_blob(&config, &circle).await;
    assert_eq!(VaultExpiryReaper::new(config).sweep().await, 2);
}

#[tokio::test]
async fn sweep_ignores_malformed_metadata_files() {
    let (_dir, config) = config();
    let namespace = VaultNamespace::Circle("circle".into());
    let dir = meta_namespace_dir(&config, &namespace);
    tokio::fs::create_dir_all(&dir).await.unwrap();
    tokio::fs::write(dir.join("broken.json"), b"{bad")
        .await
        .unwrap();
    assert_eq!(VaultExpiryReaper::new(config).sweep().await, 0);
}

#[tokio::test]
async fn sweep_is_idempotent_after_expired_record_removed() {
    let (_dir, config) = config();
    let expired = record(
        "once",
        VaultNamespace::Circle("circle".into()),
        Some((Utc::now() - Duration::seconds(1)).to_rfc3339()),
    );
    save_record_and_blob(&config, &expired).await;
    let reaper = VaultExpiryReaper::new(config);
    assert_eq!(reaper.sweep().await, 1);
    assert_eq!(reaper.sweep().await, 0);
}
