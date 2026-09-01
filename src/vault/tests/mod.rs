use crate::vault::crypto;
use crate::vault::folders;
use crate::vault::ingest::{self, IngestMeta};
use crate::vault::model::{EncMeta, VaultRecord, VaultSource};
use crate::vault::namespace::VaultNamespace;
use crate::vault::quota;
use crate::vault::upload;
use crate::vault::wrapper::KeyWrapper;
use crate::vault::{persistence, VaultConfig};
use rand::RngCore;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use sha2::Digest;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tokio::sync::Barrier;

struct EnvRestore {
    key: &'static str,
    previous: Option<String>,
}

impl EnvRestore {
    fn set(key: &'static str, value: &std::path::Path) -> Self {
        let previous = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self { key, previous }
    }

    fn set_value(key: &'static str, value: &str) -> Self {
        let previous = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self { key, previous }
    }
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        if let Some(value) = &self.previous {
            std::env::set_var(self.key, value);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

#[derive(Default)]
struct MockSe050State {
    available: bool,
    provision_count: usize,
    wrap_count: usize,
    unwrap_count: usize,
    wrap_delay_ms: u64,
    unwrap_delay_ms: u64,
    last_wrap_input_len: Option<usize>,
    keys: HashMap<String, [u8; 32]>,
}

struct MockSe050Backend {
    state: Arc<Mutex<MockSe050State>>,
}

impl MockSe050Backend {
    fn available() -> (Arc<Self>, Arc<Mutex<MockSe050State>>) {
        let state = Arc::new(Mutex::new(MockSe050State {
            available: true,
            ..Default::default()
        }));
        (
            Arc::new(Self {
                state: Arc::clone(&state),
            }),
            state,
        )
    }

    fn unavailable() -> Arc<Self> {
        Arc::new(Self {
            state: Arc::new(Mutex::new(MockSe050State::default())),
        })
    }

    fn available_with_delays(
        wrap_delay_ms: u64,
        unwrap_delay_ms: u64,
    ) -> (Arc<Self>, Arc<Mutex<MockSe050State>>) {
        let state = Arc::new(Mutex::new(MockSe050State {
            available: true,
            wrap_delay_ms,
            unwrap_delay_ms,
            ..Default::default()
        }));
        (
            Arc::new(Self {
                state: Arc::clone(&state),
            }),
            state,
        )
    }

    fn wrap_key(bytes: &[u8; 32]) -> LessSafeKey {
        let key = UnboundKey::new(&AES_256_GCM, bytes).expect("valid mock AES key");
        LessSafeKey::new(key)
    }

    fn seal(bytes: &[u8; 32], plain: &[u8]) -> Vec<u8> {
        let mut nonce_bytes = [0_u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut sealed = plain.to_vec();
        Self::wrap_key(bytes)
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut sealed)
            .expect("mock seal");
        let mut out = nonce_bytes.to_vec();
        out.extend_from_slice(&sealed);
        out
    }

    fn open(bytes: &[u8; 32], wrapped: &[u8]) -> Result<Vec<u8>, crate::vault::VaultError> {
        if wrapped.len() < 12 + 16 {
            return Err(crate::vault::VaultError::InvalidStructure(format!(
                "mock wrapped DEK too short: {}",
                wrapped.len()
            )));
        }
        let mut nonce_bytes = [0_u8; 12];
        nonce_bytes.copy_from_slice(&wrapped[..12]);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut sealed = wrapped[12..].to_vec();
        let plain = Self::wrap_key(bytes)
            .open_in_place(nonce, Aad::empty(), &mut sealed)
            .map_err(|_| crate::vault::VaultError::Crypto("mock unwrap failed".to_string()))?;
        Ok(plain.to_vec())
    }
}

impl crate::vault::wrapper::Se050WrapBackend for MockSe050Backend {
    fn slot_exists(&self, key_id: &str) -> Result<bool, crate::vault::VaultError> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if !state.available {
            return Err(crate::vault::VaultError::Crypto(
                "mock SE050 unavailable".to_string(),
            ));
        }
        Ok(state.keys.contains_key(key_id))
    }

    fn provision_key(&self, key_id: &str) -> Result<(), crate::vault::VaultError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if !state.available {
            return Err(crate::vault::VaultError::Crypto(
                "mock SE050 unavailable".to_string(),
            ));
        }
        state.provision_count += 1;
        let digest = sha2::Sha256::digest(format!("mock-se050-wrap-key:{key_id}"));
        let mut key = [0_u8; 32];
        key.copy_from_slice(&digest);
        state.keys.entry(key_id.to_string()).or_insert(key);
        Ok(())
    }

    fn wrap(&self, key_id: &str, plain: &[u8]) -> Result<Vec<u8>, crate::vault::VaultError> {
        let (key, delay_ms) = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if !state.available {
                return Err(crate::vault::VaultError::Crypto(
                    "mock SE050 unavailable".to_string(),
                ));
            }
            state.wrap_count += 1;
            state.last_wrap_input_len = Some(plain.len());
            let key = state.keys.get(key_id).copied().ok_or_else(|| {
                crate::vault::VaultError::Crypto(format!("mock key missing: {}", key_id))
            })?;
            (key, state.wrap_delay_ms)
        };
        if delay_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }
        Ok(Self::seal(&key, plain))
    }

    fn unwrap(&self, key_id: &str, wrapped: &[u8]) -> Result<Vec<u8>, crate::vault::VaultError> {
        let (key, delay_ms) = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if !state.available {
                return Err(crate::vault::VaultError::Crypto(
                    "mock SE050 unavailable".to_string(),
                ));
            }
            state.unwrap_count += 1;
            let key = state.keys.get(key_id).copied().ok_or_else(|| {
                crate::vault::VaultError::Crypto(format!("mock key missing: {}", key_id))
            })?;
            (key, state.unwrap_delay_ms)
        };
        if delay_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }
        Self::open(&key, wrapped)
    }
}

struct MockSe050LegacyPayloadBackend {
    state: Arc<Mutex<MockSe050State>>,
}

impl MockSe050LegacyPayloadBackend {
    fn available() -> Arc<Self> {
        Arc::new(Self {
            state: Arc::new(Mutex::new(MockSe050State {
                available: true,
                ..Default::default()
            })),
        })
    }
}

impl crate::vault::wrapper::Se050WrapBackend for MockSe050LegacyPayloadBackend {
    fn slot_exists(&self, key_id: &str) -> Result<bool, crate::vault::VaultError> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if !state.available {
            return Err(crate::vault::VaultError::Crypto(
                "mock SE050 unavailable".to_string(),
            ));
        }
        Ok(state.keys.contains_key(key_id))
    }

    fn provision_key(&self, key_id: &str) -> Result<(), crate::vault::VaultError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if !state.available {
            return Err(crate::vault::VaultError::Crypto(
                "mock SE050 unavailable".to_string(),
            ));
        }
        state.provision_count += 1;
        let digest = sha2::Sha256::digest(format!("mock-se050-wrap-key:{key_id}"));
        let mut key = [0_u8; 32];
        key.copy_from_slice(&digest);
        state.keys.entry(key_id.to_string()).or_insert(key);
        Ok(())
    }

    fn wrap(&self, key_id: &str, plain: &[u8]) -> Result<Vec<u8>, crate::vault::VaultError> {
        let key = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if !state.available {
                return Err(crate::vault::VaultError::Crypto(
                    "mock SE050 unavailable".to_string(),
                ));
            }
            state.wrap_count += 1;
            state.keys.get(key_id).copied().ok_or_else(|| {
                crate::vault::VaultError::Crypto(format!("mock key missing: {}", key_id))
            })?
        };
        Ok(MockSe050Backend::seal(&key, plain))
    }

    fn unwrap(&self, key_id: &str, wrapped: &[u8]) -> Result<Vec<u8>, crate::vault::VaultError> {
        let key = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if !state.available {
                return Err(crate::vault::VaultError::Crypto(
                    "mock SE050 unavailable".to_string(),
                ));
            }
            state.unwrap_count += 1;
            state.keys.get(key_id).copied().ok_or_else(|| {
                crate::vault::VaultError::Crypto(format!("mock key missing: {}", key_id))
            })?
        };
        let plain = MockSe050Backend::open(&key, wrapped)?;
        let mut dek = [0_u8; 32];
        dek.copy_from_slice(&plain);
        Ok(crate::vault::wrapper::test_encode_legacy_buggy_se050_payload_v1(&dek))
    }
}

struct MockSe050InvalidPayloadBackend {
    state: Arc<Mutex<MockSe050State>>,
    unwrap_plaintext: Vec<u8>,
}

impl MockSe050InvalidPayloadBackend {
    fn available(unwrap_plaintext: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            state: Arc::new(Mutex::new(MockSe050State {
                available: true,
                ..Default::default()
            })),
            unwrap_plaintext,
        })
    }
}

impl crate::vault::wrapper::Se050WrapBackend for MockSe050InvalidPayloadBackend {
    fn slot_exists(&self, key_id: &str) -> Result<bool, crate::vault::VaultError> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if !state.available {
            return Err(crate::vault::VaultError::Crypto(
                "mock SE050 unavailable".to_string(),
            ));
        }
        Ok(state.keys.contains_key(key_id))
    }

    fn provision_key(&self, key_id: &str) -> Result<(), crate::vault::VaultError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if !state.available {
            return Err(crate::vault::VaultError::Crypto(
                "mock SE050 unavailable".to_string(),
            ));
        }
        state.provision_count += 1;
        let digest = sha2::Sha256::digest(format!("mock-se050-wrap-key:{key_id}"));
        let mut key = [0_u8; 32];
        key.copy_from_slice(&digest);
        state.keys.entry(key_id.to_string()).or_insert(key);
        Ok(())
    }

    fn wrap(&self, key_id: &str, plain: &[u8]) -> Result<Vec<u8>, crate::vault::VaultError> {
        let key = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if !state.available {
                return Err(crate::vault::VaultError::Crypto(
                    "mock SE050 unavailable".to_string(),
                ));
            }
            state.wrap_count += 1;
            state.last_wrap_input_len = Some(plain.len());
            state.keys.get(key_id).copied().ok_or_else(|| {
                crate::vault::VaultError::Crypto(format!("mock key missing: {}", key_id))
            })?
        };
        Ok(MockSe050Backend::seal(&key, plain))
    }

    fn unwrap(&self, _key_id: &str, _wrapped: &[u8]) -> Result<Vec<u8>, crate::vault::VaultError> {
        Ok(self.unwrap_plaintext.clone())
    }
}

async fn save_quota_settings(
    config: &VaultConfig,
    personal_quota_bytes: u64,
    circle_quota_bytes: u64,
) {
    quota::save_settings(
        config,
        &quota::VaultQuotaSettings {
            personal_quota_bytes,
            circle_quota_bytes,
        },
    )
    .await
    .expect("save quota settings");
}

async fn ingest_personal_upload(
    config: &VaultConfig,
    staging_path: std::path::PathBuf,
    payload: &[u8],
    filename: &str,
) -> Result<VaultRecord, crate::vault::VaultError> {
    upload::ingest_staged_upload(
        config,
        upload::StagedUpload {
            namespace: VaultNamespace::Personal,
            folder_id: String::new(),
            filename: filename.to_string(),
            mime: ingest::infer_mime(filename),
            sender_did: "did:guardian:nodeA".into(),
            staging_path,
            size_plain: payload.len() as u64,
            sha256_plain: hex::encode(sha2::Sha256::digest(payload)),
            chunk_bytes: crate::vault::VaultConfig::DEFAULT_CHUNK_BYTES,
            description: String::new(),
        },
    )
    .await
}

#[tokio::test]
async fn vault_record_round_trip_and_list() {
    let _env_lock = crate::vault::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
    let config = VaultConfig::from_env();

    let record = VaultRecord {
        vault_id: "urn:uuid:test-record".into(),
        namespace: String::new(),
        circle_id: "guardian-circle-alpha".into(),
        filename: "report.pdf".into(),
        mime: "application/pdf".into(),
        size_plain: 123,
        size_cipher: 456,
        sha256_plain: "ab".repeat(32),
        sender_did: "did:guardian:sender".into(),
        received_at: chrono::Utc::now().to_rfc3339(),
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
            chunk_bytes: crate::vault::VaultConfig::DEFAULT_CHUNK_BYTES,
            base_nonce_b64: "bm9uY2VwcmU=".into(),
            wrapped_dek_b64: "d3JhcHBlZA==".into(),
            wrap_scheme: "software-hkdf".into(),
            wrap_key_id: "software-master-v1".into(),
        },
    };

    persistence::save_record(&config, &record)
        .await
        .expect("save record");
    let loaded = persistence::load_record(&config, &record.circle_id, &record.vault_id)
        .await
        .expect("load record")
        .expect("record exists");
    assert_eq!(loaded, record);

    let listed = persistence::list_records(&config, Some(&record.circle_id))
        .await
        .expect("list records");
    assert_eq!(listed, vec![record.clone()]);

    let found = persistence::find_record(&config, &record.vault_id)
        .await
        .expect("find record")
        .expect("found");
    assert_eq!(found, record);
}

#[tokio::test]
async fn vault_crypto_round_trip_and_tamper_fails() {
    let _env_lock = crate::vault::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
    let config = VaultConfig::from_env();

    let plain_path = temp.path().join("fixture.bin");
    let blob_path = temp.path().join("fixture.enc");
    let decrypt_path = temp.path().join("fixture.out");
    let payload = (0..(crate::vault::VaultConfig::DEFAULT_CHUNK_BYTES as usize * 3 + 17))
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    tokio::fs::write(&plain_path, &payload)
        .await
        .expect("write plaintext");

    let meta = IngestMeta {
        filename: "fixture.bin".into(),
        mime: "application/octet-stream".into(),
        sha256_plain: hex::encode(sha2::Sha256::digest(&payload)),
        size_plain: payload.len() as u64,
        chunk_bytes: crate::vault::VaultConfig::DEFAULT_CHUNK_BYTES,
    };

    let wrapper =
        crate::vault::wrapper::SoftwareWrapper::from_config(&config).expect("software wrapper");
    let outcome = crypto::encrypt_file(&plain_path, &blob_path, &meta, &wrapper).expect("encrypt");
    let record = VaultRecord {
        vault_id: "urn:uuid:roundtrip".into(),
        namespace: String::new(),
        circle_id: "guardian-circle-alpha".into(),
        filename: meta.filename.clone(),
        mime: meta.mime.clone(),
        size_plain: meta.size_plain,
        size_cipher: outcome.size_cipher,
        sha256_plain: meta.sha256_plain.clone(),
        sender_did: "did:guardian:sender".into(),
        received_at: chrono::Utc::now().to_rfc3339(),
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
        enc: outcome.enc.clone(),
    };

    crypto::decrypt_file(&blob_path, &decrypt_path, &record, &wrapper).expect("decrypt");
    assert_eq!(
        tokio::fs::read(&decrypt_path)
            .await
            .expect("read decrypted"),
        payload
    );

    let mut tampered = tokio::fs::read(&blob_path).await.expect("read blob");
    let last = tampered.len() - 1;
    tampered[last] ^= 0x55;
    tokio::fs::write(&blob_path, tampered)
        .await
        .expect("write tampered blob");

    let error = crypto::decrypt_file(&blob_path, &decrypt_path, &record, &wrapper)
        .expect_err("tampered blob must fail");
    assert!(error.to_string().contains("authentication failed"));
}

#[tokio::test]
async fn ingest_encrypts_and_shreds_plaintext() {
    let _env_lock = crate::vault::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
    let _profile = crate::vault::wrapper::test_force_runtime_profile(
        crate::vault::wrapper::RuntimeProfile::Docker,
    );
    let payload = b"top secret attachment".repeat(1024);
    let plain_path = temp.path().join("incoming.part");
    tokio::fs::write(&plain_path, &payload)
        .await
        .expect("write staging file");

    let meta = IngestMeta {
        filename: "incoming.bin".into(),
        mime: ingest::infer_mime("incoming.bin"),
        sha256_plain: hex::encode(sha2::Sha256::digest(&payload)),
        size_plain: payload.len() as u64,
        chunk_bytes: crate::vault::VaultConfig::DEFAULT_CHUNK_BYTES,
    };

    let record = ingest::ingest_file(
        "guardian-circle-alpha",
        "did:guardian:sender",
        &plain_path,
        meta,
    )
    .await
    .expect("ingest");

    let config = VaultConfig::from_env();
    let blob_path = persistence::blob_path(&config, &record.circle_id, &record.vault_id);
    assert!(
        tokio::fs::try_exists(&blob_path)
            .await
            .expect("blob exists"),
        "ciphertext blob should exist"
    );
    assert!(
        !tokio::fs::try_exists(&plain_path)
            .await
            .expect("plain removed"),
        "plaintext staging file should be removed"
    );

    let temp_out = persistence::decrypt_temp_path(&config, &record.vault_id);
    let wrapper =
        crate::vault::wrapper::SoftwareWrapper::from_config(&config).expect("software wrapper");
    crypto::decrypt_file(&blob_path, &temp_out, &record, &wrapper).expect("decrypt stored blob");
    assert_eq!(
        tokio::fs::read(temp_out).await.expect("read output"),
        payload
    );
}

#[test]
fn legacy_vault_record_defaults_to_root_and_unstarred() {
    let record: VaultRecord = serde_json::from_value(serde_json::json!({
        "vault_id": "urn:uuid:test-legacy",
        "circle_id": "guardian-circle-alpha",
        "filename": "legacy.txt",
        "mime": "text/plain",
        "size_plain": 12,
        "size_cipher": 48,
        "sha256_plain": "ab".repeat(32),
        "sender_did": "did:guardian:legacy",
        "received_at": "2026-07-15T00:00:00Z",
        "source": "file_transfer",
        "enc": {
            "algo": "AES-256-GCM/STREAM-BE32",
            "chunk_bytes": 65536,
            "base_nonce_b64": "bm9uY2VwcmU=",
            "wrapped_dek_b64": "d3JhcHBlZA==",
            "wrap_scheme": "software-hkdf",
            "wrap_key_id": "software-master-v1"
        }
    }))
    .expect("legacy record should deserialize");

    assert_eq!(record.folder_id, "");
    assert!(!record.starred);
    assert_eq!(
        record.namespace_ref(),
        VaultNamespace::Circle("guardian-circle-alpha".to_string())
    );
}

#[tokio::test]
async fn namespace_helpers_resolve_personal_and_circle_paths() {
    let _env_lock = crate::vault::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
    let config = VaultConfig::from_env();

    let personal =
        persistence::blob_path_for_namespace(&config, &VaultNamespace::Personal, "urn:uuid:file");
    let circle = persistence::blob_path_for_namespace(
        &config,
        &VaultNamespace::Circle("guardian-circle-alpha".into()),
        "urn:uuid:file",
    );

    assert!(personal.ends_with("blobs/personal/urn_uuid_file.enc"));
    assert!(circle.ends_with("blobs/guardian-circle-alpha/urn_uuid_file.enc"));
}

#[tokio::test]
async fn folder_index_supports_create_move_recursive_delete_and_tamper_detection() {
    let _env_lock = crate::vault::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
    let key_dir = temp.path().join("keys");
    let _keys = EnvRestore::set(crate::vc::issue::DEVICE_KEY_DIR_ENV, &key_dir);
    let config = VaultConfig::from_env();
    let namespace = VaultNamespace::Personal;

    let reports = folders::create_folder(&config, &namespace, "nodeA", "", "Reports")
        .await
        .expect("create root folder");
    let fy = folders::create_folder(&config, &namespace, "nodeA", &reports.folder_id, "2026")
        .await
        .expect("create nested folder");

    let error = folders::delete_folder(&config, &namespace, "nodeA", &reports.folder_id, false)
        .await
        .expect_err("non-empty delete should fail");
    assert!(error.to_string().contains("not empty"));

    let fy = folders::update_folder(
        &config,
        &namespace,
        "nodeA",
        &fy.folder_id,
        Some("FY26"),
        Some(""),
    )
    .await
    .expect("move folder to root");
    assert_eq!(fy.parent_id, "");
    assert_eq!(fy.name, "FY26");

    let quarter = folders::create_folder(&config, &namespace, "nodeA", &fy.folder_id, "Q1")
        .await
        .expect("create grandchild");
    let removed = folders::delete_folder(&config, &namespace, "nodeA", &fy.folder_id, true)
        .await
        .expect("recursive delete should succeed");
    assert_eq!(removed.len(), 2);
    assert!(removed.contains(&fy.folder_id));
    assert!(removed.contains(&quarter.folder_id));

    let index = folders::load_index(&config, &namespace, "nodeA")
        .await
        .expect("load folder index");
    assert!(index.contains_folder(&reports.folder_id));
    assert!(!index.contains_folder(&fy.folder_id));

    let path = persistence::folder_index_path(&config, &namespace);
    let mut index_json: serde_json::Value =
        serde_json::from_slice(&tokio::fs::read(&path).await.expect("read folder index"))
            .expect("folder index json");
    let proof_value = index_json["proof"]["proofValue"]
        .as_str()
        .expect("proof value");
    let replacement = if let Some(stripped) = proof_value.strip_suffix('A') {
        format!("{stripped}B")
    } else {
        format!("{}A", &proof_value[..proof_value.len() - 1])
    };
    index_json["proof"]["proofValue"] = serde_json::Value::String(replacement);
    tokio::fs::write(
        &path,
        serde_json::to_vec_pretty(&index_json).expect("serialize tamper"),
    )
    .await
    .expect("tamper folder index");

    let error = folders::load_index(&config, &namespace, "nodeA")
        .await
        .expect_err("tampered folder index must fail");
    assert!(!error.to_string().is_empty());
}

#[tokio::test]
async fn quota_uses_persisted_record_sizes_and_reports_namespace_usage() {
    let _env_lock = crate::vault::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
    let config = VaultConfig::from_env();
    save_quota_settings(&config, 500, 700).await;

    let circle_record = VaultRecord {
        vault_id: "urn:uuid:quota-circle".into(),
        namespace: String::new(),
        circle_id: "guardian-circle-alpha".into(),
        filename: "circle.bin".into(),
        mime: "application/octet-stream".into(),
        size_plain: 10,
        size_cipher: 450,
        sha256_plain: "cd".repeat(32),
        sender_did: "did:guardian:sender".into(),
        received_at: "2026-07-15T00:00:00Z".into(),
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
            chunk_bytes: crate::vault::VaultConfig::DEFAULT_CHUNK_BYTES,
            base_nonce_b64: "bm9uY2VwcmU=".into(),
            wrapped_dek_b64: "d3JhcHBlZA==".into(),
            wrap_scheme: "software-hkdf".into(),
            wrap_key_id: "software-master-v1".into(),
        },
    };
    let personal_record = VaultRecord {
        vault_id: "urn:uuid:quota-personal".into(),
        namespace: VaultNamespace::PERSONAL_STORAGE_KEY.to_string(),
        circle_id: String::new(),
        filename: "personal.bin".into(),
        mime: "application/octet-stream".into(),
        size_plain: 20,
        size_cipher: 200,
        sha256_plain: "ef".repeat(32),
        sender_did: "did:guardian:sender".into(),
        received_at: "2026-07-15T00:00:01Z".into(),
        source: VaultSource::Upload,
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
            chunk_bytes: crate::vault::VaultConfig::DEFAULT_CHUNK_BYTES,
            base_nonce_b64: "bm9uY2VwcmU=".into(),
            wrapped_dek_b64: "d3JhcHBlZA==".into(),
            wrap_scheme: "software-hkdf".into(),
            wrap_key_id: "software-master-v1".into(),
        },
    };

    persistence::save_record(&config, &circle_record)
        .await
        .expect("save circle record");
    persistence::save_record(&config, &personal_record)
        .await
        .expect("save personal record");

    let personal = quota::compute_namespace(&config, &VaultNamespace::Personal)
        .await
        .expect("compute personal quota");
    assert_eq!(personal.used_bytes, 200);
    assert_eq!(personal.quota_bytes, 500);
    assert_eq!(personal.remaining_bytes(), 300);
    assert_eq!(personal.usage_percent(), 40.0);

    let circle = quota::compute_namespace(
        &config,
        &VaultNamespace::Circle("guardian-circle-alpha".into()),
    )
    .await
    .expect("compute circle quota");
    assert_eq!(circle.used_bytes, 450);
    assert_eq!(circle.quota_bytes, 700);
    assert_eq!(circle.remaining_bytes(), 250);

    let aggregate = quota::compute(&config).await.expect("aggregate quota");
    assert_eq!(aggregate.used_bytes, 650);
    assert_eq!(aggregate.capacity_bytes, 1_200);
}

#[tokio::test]
async fn personal_upload_round_trip_uses_personal_namespace() {
    let _env_lock = crate::vault::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
    let _profile = crate::vault::wrapper::test_force_runtime_profile(
        crate::vault::wrapper::RuntimeProfile::Docker,
    );
    let config = VaultConfig::from_env();

    let payload = b"personal upload payload".repeat(1024);
    let staging_path = temp.path().join("upload.part");
    tokio::fs::write(&staging_path, &payload)
        .await
        .expect("write staging upload");

    let record = upload::ingest_staged_upload(
        &config,
        upload::StagedUpload {
            namespace: VaultNamespace::Personal,
            folder_id: String::new(),
            filename: "photo.png".into(),
            mime: "image/png".into(),
            sender_did: "did:guardian:nodeA".into(),
            staging_path: staging_path.clone(),
            size_plain: payload.len() as u64,
            sha256_plain: hex::encode(sha2::Sha256::digest(&payload)),
            chunk_bytes: crate::vault::VaultConfig::DEFAULT_CHUNK_BYTES,
            description: String::new(),
        },
    )
    .await
    .expect("store personal upload");

    assert_eq!(record.namespace_key(), "personal");
    assert!(record.circle_id.is_empty());
    assert_eq!(record.source, VaultSource::Upload);
    assert!(!tokio::fs::try_exists(&staging_path)
        .await
        .expect("staging should be removed"));

    let decrypted = ingest::decrypt_record_to_temp(&record)
        .await
        .expect("decrypt personal upload");
    assert_eq!(
        tokio::fs::read(decrypted)
            .await
            .expect("read decrypted upload"),
        payload
    );
}

#[tokio::test]
async fn personal_upload_succeeds_at_exact_quota_limit() {
    let _env_lock = crate::vault::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
    let _profile = crate::vault::wrapper::test_force_runtime_profile(
        crate::vault::wrapper::RuntimeProfile::Docker,
    );
    let config = VaultConfig::from_env();
    let payload = b"exact-limit".repeat(128);
    let required_bytes =
        quota::estimate_cipher_size(payload.len() as u64, VaultConfig::DEFAULT_CHUNK_BYTES);
    save_quota_settings(&config, required_bytes, required_bytes * 4).await;

    let staging_path = temp.path().join("exact-limit.part");
    tokio::fs::write(&staging_path, &payload)
        .await
        .expect("write exact-limit staging");

    let record = ingest_personal_upload(&config, staging_path, &payload, "exact-limit.txt")
        .await
        .expect("exact-limit upload");
    let quota = quota::compute_namespace(&config, &VaultNamespace::Personal)
        .await
        .expect("personal quota");
    assert_eq!(record.size_cipher, required_bytes);
    assert_eq!(quota.used_bytes, required_bytes);
    assert_eq!(quota.remaining_bytes(), 0);
    assert_eq!(quota.usage_percent(), 100.0);
}

#[tokio::test]
async fn personal_upload_rejects_when_over_quota() {
    let _env_lock = crate::vault::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
    let _profile = crate::vault::wrapper::test_force_runtime_profile(
        crate::vault::wrapper::RuntimeProfile::Docker,
    );
    let config = VaultConfig::from_env();
    let payload = b"over-quota".repeat(128);
    let required_bytes =
        quota::estimate_cipher_size(payload.len() as u64, VaultConfig::DEFAULT_CHUNK_BYTES);
    save_quota_settings(&config, required_bytes - 1, required_bytes * 4).await;

    let staging_path = temp.path().join("over-quota.part");
    tokio::fs::write(&staging_path, &payload)
        .await
        .expect("write over-quota staging");

    let error = ingest_personal_upload(&config, staging_path.clone(), &payload, "over-quota.txt")
        .await
        .expect_err("upload must reject over quota");
    assert!(matches!(
        error,
        crate::vault::VaultError::QuotaExceeded { .. }
    ));
    assert!(
        !tokio::fs::try_exists(&staging_path)
            .await
            .expect("staging existence"),
        "staging file should be cleaned up on quota failure"
    );
}

#[tokio::test]
async fn quota_usage_recovers_after_file_deletion() {
    let _env_lock = crate::vault::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
    let _profile = crate::vault::wrapper::test_force_runtime_profile(
        crate::vault::wrapper::RuntimeProfile::Docker,
    );
    let config = VaultConfig::from_env();
    let payload = b"deletion-recovery".repeat(128);
    let required_bytes =
        quota::estimate_cipher_size(payload.len() as u64, VaultConfig::DEFAULT_CHUNK_BYTES);
    save_quota_settings(&config, required_bytes, required_bytes * 4).await;

    let first_stage = temp.path().join("delete-first.part");
    tokio::fs::write(&first_stage, &payload)
        .await
        .expect("write first staging");
    let record = ingest_personal_upload(&config, first_stage, &payload, "delete-first.txt")
        .await
        .expect("first upload");
    let used_before_delete = quota::compute_namespace(&config, &VaultNamespace::Personal)
        .await
        .expect("quota before delete");
    assert_eq!(used_before_delete.used_bytes, required_bytes);

    persistence::delete_record(&config, &record)
        .await
        .expect("delete first record");
    let used_after_delete = quota::compute_namespace(&config, &VaultNamespace::Personal)
        .await
        .expect("quota after delete");
    assert_eq!(used_after_delete.used_bytes, 0);

    let second_stage = temp.path().join("delete-second.part");
    tokio::fs::write(&second_stage, &payload)
        .await
        .expect("write second staging");
    ingest_personal_upload(&config, second_stage, &payload, "delete-second.txt")
        .await
        .expect("quota should recover after deletion");
}

#[tokio::test]
async fn circle_quota_usage_isolated_per_namespace() {
    let _env_lock = crate::vault::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
    let _profile = crate::vault::wrapper::test_force_runtime_profile(
        crate::vault::wrapper::RuntimeProfile::Docker,
    );
    let config = VaultConfig::from_env();
    let payload = b"circle-isolation".repeat(128);
    let required_bytes =
        quota::estimate_cipher_size(payload.len() as u64, VaultConfig::DEFAULT_CHUNK_BYTES);
    save_quota_settings(&config, required_bytes * 4, required_bytes).await;

    let alpha_path = temp.path().join("alpha.part");
    tokio::fs::write(&alpha_path, &payload)
        .await
        .expect("write alpha staging");
    ingest::ingest_file(
        "guardian-circle-alpha",
        "did:guardian:sender",
        &alpha_path,
        IngestMeta {
            filename: "alpha.bin".into(),
            mime: "application/octet-stream".into(),
            sha256_plain: hex::encode(sha2::Sha256::digest(&payload)),
            size_plain: payload.len() as u64,
            chunk_bytes: VaultConfig::DEFAULT_CHUNK_BYTES,
        },
    )
    .await
    .expect("alpha ingest");

    let beta_path = temp.path().join("beta.part");
    tokio::fs::write(&beta_path, &payload)
        .await
        .expect("write beta staging");
    ingest::ingest_file(
        "guardian-circle-beta",
        "did:guardian:sender",
        &beta_path,
        IngestMeta {
            filename: "beta.bin".into(),
            mime: "application/octet-stream".into(),
            sha256_plain: hex::encode(sha2::Sha256::digest(&payload)),
            size_plain: payload.len() as u64,
            chunk_bytes: VaultConfig::DEFAULT_CHUNK_BYTES,
        },
    )
    .await
    .expect("beta ingest");

    let alpha = quota::compute_namespace(
        &config,
        &VaultNamespace::Circle("guardian-circle-alpha".into()),
    )
    .await
    .expect("alpha quota");
    let beta = quota::compute_namespace(
        &config,
        &VaultNamespace::Circle("guardian-circle-beta".into()),
    )
    .await
    .expect("beta quota");
    assert_eq!(alpha.used_bytes, required_bytes);
    assert_eq!(beta.used_bytes, required_bytes);

    let alpha_overflow_path = temp.path().join("alpha-overflow.part");
    tokio::fs::write(&alpha_overflow_path, &payload)
        .await
        .expect("write alpha overflow staging");
    let error = ingest::ingest_file(
        "guardian-circle-alpha",
        "did:guardian:sender",
        &alpha_overflow_path,
        IngestMeta {
            filename: "alpha-overflow.bin".into(),
            mime: "application/octet-stream".into(),
            sha256_plain: hex::encode(sha2::Sha256::digest(&payload)),
            size_plain: payload.len() as u64,
            chunk_bytes: VaultConfig::DEFAULT_CHUNK_BYTES,
        },
    )
    .await
    .expect_err("alpha namespace should be full");
    assert!(matches!(
        error,
        crate::vault::VaultError::QuotaExceeded { .. }
    ));
}

#[tokio::test]
async fn quota_settings_persist_across_restart() {
    let _env_lock = crate::vault::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
    let config = VaultConfig::from_env();
    save_quota_settings(&config, 1_234, 5_678).await;
    let _legacy = EnvRestore::set_value(crate::vault::quota::CAPACITY_ENV, "9999");
    let _personal = EnvRestore::set_value(crate::vault::quota::PERSONAL_QUOTA_ENV, "9999");
    let _circle = EnvRestore::set_value(crate::vault::quota::CIRCLE_QUOTA_ENV, "9999");

    let restarted = VaultConfig::from_env();
    let loaded = quota::load_settings(&restarted)
        .await
        .expect("load persisted settings after restart");
    assert_eq!(
        loaded,
        quota::VaultQuotaSettings {
            personal_quota_bytes: 1_234,
            circle_quota_bytes: 5_678,
        }
    );
}

#[tokio::test]
async fn concurrent_quota_enforcement_is_atomic() {
    let _env_lock = crate::vault::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
    let _profile = crate::vault::wrapper::test_force_runtime_profile(
        crate::vault::wrapper::RuntimeProfile::Production,
    );
    let (backend, _state) = MockSe050Backend::available_with_delays(750, 0);
    let _backend = crate::vault::wrapper::test_override_se050_wrap_backend(backend);
    let config = VaultConfig::from_env();
    let payload = b"concurrent-quota".repeat(512);
    let required_bytes =
        quota::estimate_cipher_size(payload.len() as u64, VaultConfig::DEFAULT_CHUNK_BYTES);
    save_quota_settings(&config, required_bytes, required_bytes * 4).await;

    let stage_a = temp.path().join("concurrent-a.part");
    let stage_b = temp.path().join("concurrent-b.part");
    tokio::fs::write(&stage_a, &payload)
        .await
        .expect("write concurrent A");
    tokio::fs::write(&stage_b, &payload)
        .await
        .expect("write concurrent B");

    let barrier = Arc::new(Barrier::new(3));
    let config_a = config.clone();
    let payload_a = payload.clone();
    let barrier_a = Arc::clone(&barrier);
    let task_a = tokio::spawn(async move {
        barrier_a.wait().await;
        ingest_personal_upload(&config_a, stage_a, &payload_a, "concurrent-a.bin").await
    });
    let config_b = config.clone();
    let payload_b = payload.clone();
    let barrier_b = Arc::clone(&barrier);
    let task_b = tokio::spawn(async move {
        barrier_b.wait().await;
        ingest_personal_upload(&config_b, stage_b, &payload_b, "concurrent-b.bin").await
    });

    barrier.wait().await;
    let result_a = task_a.await.expect("join A");
    let result_b = task_b.await.expect("join B");
    let successes = [result_a.is_ok(), result_b.is_ok()]
        .into_iter()
        .filter(|success| *success)
        .count();
    assert_eq!(successes, 1, "exactly one upload should reserve quota");
    let failures = [result_a, result_b]
        .into_iter()
        .filter_map(Result::err)
        .collect::<Vec<_>>();
    assert_eq!(failures.len(), 1);
    assert!(matches!(
        failures[0],
        crate::vault::VaultError::QuotaExceeded { .. }
    ));

    let personal = quota::compute_namespace(&config, &VaultNamespace::Personal)
        .await
        .expect("personal quota after concurrent uploads");
    assert_eq!(personal.used_bytes, required_bytes);
}

#[tokio::test]
async fn default_wrapper_selects_hardware_in_production() {
    let _env_lock = crate::vault::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
    let _profile = crate::vault::wrapper::test_force_runtime_profile(
        crate::vault::wrapper::RuntimeProfile::Production,
    );
    let (backend, state) = MockSe050Backend::available();
    let _backend = crate::vault::wrapper::test_override_se050_wrap_backend(backend);
    let config = VaultConfig::from_env();

    let wrapper = crate::vault::wrapper::default_wrapper(&config).expect("hardware wrapper");

    assert_eq!(wrapper.scheme(), crate::vault::wrapper::SE050_WRAP_SCHEME);
    assert_eq!(
        wrapper.key_id(),
        crate::vault::wrapper::DEFAULT_SE050_WRAP_KEY_ID
    );
    let state = state.lock().unwrap_or_else(|error| error.into_inner());
    assert_eq!(state.provision_count, 1);
    assert!(state
        .keys
        .contains_key(crate::vault::wrapper::DEFAULT_SE050_WRAP_KEY_ID));
}

#[tokio::test]
async fn production_hardware_wrapper_round_trips_raw_32_byte_dek() {
    let _env_lock = crate::vault::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
    let _profile = crate::vault::wrapper::test_force_runtime_profile(
        crate::vault::wrapper::RuntimeProfile::Production,
    );
    let (backend, _state) = MockSe050Backend::available();
    let _backend = crate::vault::wrapper::test_override_se050_wrap_backend(backend);
    let config = VaultConfig::from_env();

    let wrapper = crate::vault::wrapper::default_wrapper(&config).expect("hardware wrapper");
    let mut dek = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut dek);

    let wrapped = wrapper.wrap(&dek).expect("wrap");
    let unwrapped = wrapper.unwrap(&wrapped).expect("unwrap");
    assert_eq!(unwrapped, dek);
}

#[tokio::test]
async fn production_hardware_wrapper_passes_exactly_32_bytes_to_se050_backend() {
    let _env_lock = crate::vault::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
    let _profile = crate::vault::wrapper::test_force_runtime_profile(
        crate::vault::wrapper::RuntimeProfile::Production,
    );
    let (backend, state) = MockSe050Backend::available();
    let _backend = crate::vault::wrapper::test_override_se050_wrap_backend(backend);
    let config = VaultConfig::from_env();

    let wrapper = crate::vault::wrapper::default_wrapper(&config).expect("hardware wrapper");
    let dek = [9_u8; 32];
    let wrapped = wrapper.wrap(&dek).expect("wrap");
    assert!(
        !wrapped.is_empty(),
        "wrapped DEK envelope should not be empty"
    );

    let state = state.lock().unwrap_or_else(|error| error.into_inner());
    assert_eq!(state.last_wrap_input_len, Some(32));
}

#[tokio::test]
async fn production_hardware_wrapper_decodes_known_legacy_52_byte_payload() {
    let _env_lock = crate::vault::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
    let _profile = crate::vault::wrapper::test_force_runtime_profile(
        crate::vault::wrapper::RuntimeProfile::Production,
    );
    let _backend = crate::vault::wrapper::test_override_se050_wrap_backend(
        MockSe050LegacyPayloadBackend::available(),
    );
    let config = VaultConfig::from_env();

    let wrapper = crate::vault::wrapper::default_wrapper(&config).expect("hardware wrapper");
    let dek = [9_u8; 32];
    let wrapped = wrapper.wrap(&dek).expect("wrap");
    let unwrapped = wrapper
        .unwrap(&wrapped)
        .expect("legacy payload should decode");
    assert_eq!(unwrapped, dek);
}

#[tokio::test]
async fn production_hardware_wrapper_decodes_real_board_49_byte_utf8_sample() {
    let _env_lock = crate::vault::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
    let _profile = crate::vault::wrapper::test_force_runtime_profile(
        crate::vault::wrapper::RuntimeProfile::Production,
    );
    let dek = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E,
        0x8F, 0x90, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F,
    ];
    let sample = crate::vault::wrapper::test_encode_ssscli_utf8_marshaled_bytes(&dek);
    assert_eq!(sample.len(), 49);
    let _backend = crate::vault::wrapper::test_override_se050_wrap_backend(
        MockSe050InvalidPayloadBackend::available(sample),
    );
    let config = VaultConfig::from_env();

    let wrapper = crate::vault::wrapper::default_wrapper(&config).expect("hardware wrapper");
    let wrapped = wrapper.wrap(&dek).expect("wrap");
    let unwrapped = wrapper.unwrap(&wrapped).expect("unwrap widened sample");
    assert_eq!(unwrapped, dek);
}

#[tokio::test]
async fn production_hardware_wrapper_rejects_invalid_unwrap_payload_lengths() {
    let _env_lock = crate::vault::lock_test_env().await;

    for invalid_len in [31_usize, 33_usize] {
        let temp = TempDir::new().expect("tempdir");
        let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
        let _profile = crate::vault::wrapper::test_force_runtime_profile(
            crate::vault::wrapper::RuntimeProfile::Production,
        );
        let _backend = crate::vault::wrapper::test_override_se050_wrap_backend(
            MockSe050InvalidPayloadBackend::available(vec![0xA5; invalid_len]),
        );
        let config = VaultConfig::from_env();

        let wrapper = crate::vault::wrapper::default_wrapper(&config).expect("hardware wrapper");
        let wrapped = wrapper.wrap(&[7_u8; 32]).expect("wrap");
        let error = wrapper
            .unwrap(&wrapped)
            .expect_err("invalid SE050 payload length must fail");
        assert!(error
            .to_string()
            .contains(&format!("got {} bytes", invalid_len)));
    }
}

#[tokio::test]
async fn production_hardware_wrapper_rejects_utf8_marshaled_unwrap_output_with_wrong_length() {
    let _env_lock = crate::vault::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
    let _profile = crate::vault::wrapper::test_force_runtime_profile(
        crate::vault::wrapper::RuntimeProfile::Production,
    );
    let malformed = crate::vault::wrapper::test_encode_ssscli_utf8_marshaled_bytes(&[0x80_u8; 31]);
    let _backend = crate::vault::wrapper::test_override_se050_wrap_backend(
        MockSe050InvalidPayloadBackend::available(malformed),
    );
    let config = VaultConfig::from_env();

    let wrapper = crate::vault::wrapper::default_wrapper(&config).expect("hardware wrapper");
    let wrapped = wrapper.wrap(&[7_u8; 32]).expect("wrap");
    let error = wrapper
        .unwrap(&wrapped)
        .expect_err("wrong-length widened output must fail");
    assert!(error.to_string().contains("recovered 31 bytes"));
}

#[tokio::test]
async fn production_hardware_wrapper_rejects_malformed_legacy_52_byte_payload() {
    let _env_lock = crate::vault::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
    let _profile = crate::vault::wrapper::test_force_runtime_profile(
        crate::vault::wrapper::RuntimeProfile::Production,
    );
    let mut malformed =
        crate::vault::wrapper::test_encode_legacy_buggy_se050_payload_v1(&[4_u8; 32]);
    malformed[0] = 9;
    let _backend = crate::vault::wrapper::test_override_se050_wrap_backend(
        MockSe050InvalidPayloadBackend::available(malformed),
    );
    let config = VaultConfig::from_env();

    let wrapper = crate::vault::wrapper::default_wrapper(&config).expect("hardware wrapper");
    let wrapped = wrapper.wrap(&[4_u8; 32]).expect("wrap");
    let error = wrapper
        .unwrap(&wrapped)
        .expect_err("malformed legacy payload must fail");
    assert!(error
        .to_string()
        .contains("malformed legacy v1 52-byte framing"));
}

#[tokio::test]
async fn software_wrapper_is_limited_to_non_production_profiles() {
    let _env_lock = crate::vault::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
    let config = VaultConfig::from_env();

    let _docker = crate::vault::wrapper::test_force_runtime_profile(
        crate::vault::wrapper::RuntimeProfile::Docker,
    );
    let docker_wrapper = crate::vault::wrapper::default_wrapper(&config).expect("docker wrapper");
    assert_eq!(
        docker_wrapper.scheme(),
        crate::vault::wrapper::SOFTWARE_WRAP_SCHEME
    );
    drop(_docker);

    let _ci = crate::vault::wrapper::test_force_runtime_profile(
        crate::vault::wrapper::RuntimeProfile::Ci,
    );
    let ci_wrapper = crate::vault::wrapper::default_wrapper(&config).expect("ci wrapper");
    assert_eq!(
        ci_wrapper.scheme(),
        crate::vault::wrapper::SOFTWARE_WRAP_SCHEME
    );
    drop(_ci);

    let _dev = EnvRestore::set_value(crate::vault::wrapper::VAULT_DEV_MODE_ENV, "1");
    let dev_wrapper = crate::vault::wrapper::default_wrapper(&config).expect("dev wrapper");
    assert_eq!(
        dev_wrapper.scheme(),
        crate::vault::wrapper::SOFTWARE_WRAP_SCHEME
    );
}

#[tokio::test]
async fn production_mode_refuses_software_fallback() {
    let _env_lock = crate::vault::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
    let config = VaultConfig::from_env();
    let _profile = crate::vault::wrapper::test_force_runtime_profile(
        crate::vault::wrapper::RuntimeProfile::Production,
    );
    let _backend =
        crate::vault::wrapper::test_override_se050_wrap_backend(MockSe050Backend::unavailable());

    let error = match crate::vault::wrapper::default_wrapper(&config) {
        Ok(_) => panic!("production should fail closed without SE050"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("SE050"));
    assert!(!persistence::master_key_path(&config).exists());

    let payload = b"software-only fixture".repeat(64);
    let plain_path = temp.path().join("software.bin");
    let blob_path = temp.path().join("software.enc");
    tokio::fs::write(&plain_path, &payload)
        .await
        .expect("write plaintext");
    let meta = IngestMeta {
        filename: "software.bin".into(),
        mime: "application/octet-stream".into(),
        sha256_plain: hex::encode(sha2::Sha256::digest(&payload)),
        size_plain: payload.len() as u64,
        chunk_bytes: crate::vault::VaultConfig::DEFAULT_CHUNK_BYTES,
    };
    let software_wrapper =
        crate::vault::wrapper::SoftwareWrapper::from_config(&config).expect("software wrapper");
    let outcome =
        crypto::encrypt_file(&plain_path, &blob_path, &meta, &software_wrapper).expect("encrypt");
    let record = VaultRecord {
        vault_id: "urn:uuid:software-production".into(),
        namespace: String::new(),
        circle_id: "guardian-circle-alpha".into(),
        filename: meta.filename.clone(),
        mime: meta.mime.clone(),
        size_plain: meta.size_plain,
        size_cipher: outcome.size_cipher,
        sha256_plain: meta.sha256_plain.clone(),
        sender_did: "did:guardian:sender".into(),
        received_at: chrono::Utc::now().to_rfc3339(),
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
        enc: outcome.enc,
    };

    let error = match crate::vault::wrapper::wrapper_for_record(&config, &record) {
        Ok(_) => panic!("production must refuse software-wrapped records"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("explicit development mode"));
}

#[tokio::test]
async fn production_hardware_wrapper_encrypts_decrypts_and_persists_across_restart() {
    let _env_lock = crate::vault::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
    let _profile = crate::vault::wrapper::test_force_runtime_profile(
        crate::vault::wrapper::RuntimeProfile::Production,
    );
    let (backend, state) = MockSe050Backend::available_with_delays(0, 0);
    let _backend = crate::vault::wrapper::test_override_se050_wrap_backend(backend);
    let config = VaultConfig::from_env();

    let payload = b"hardware wrapped payload".repeat(2048);
    let plain_path = temp.path().join("hardware.part");
    tokio::fs::write(&plain_path, &payload)
        .await
        .expect("write plaintext");

    let record = ingest::ingest_file(
        "guardian-circle-alpha",
        "did:guardian:sender",
        &plain_path,
        IngestMeta {
            filename: "hardware.bin".into(),
            mime: "application/octet-stream".into(),
            sha256_plain: hex::encode(sha2::Sha256::digest(&payload)),
            size_plain: payload.len() as u64,
            chunk_bytes: crate::vault::VaultConfig::DEFAULT_CHUNK_BYTES,
        },
    )
    .await
    .expect("hardware ingest");

    assert_eq!(
        record.enc.wrap_scheme,
        crate::vault::wrapper::SE050_WRAP_SCHEME
    );
    assert_eq!(
        record.enc.wrap_key_id,
        crate::vault::wrapper::DEFAULT_SE050_WRAP_KEY_ID
    );

    let metadata_path = persistence::wrap_dir(&config).join("se050-wrap-key.json");
    assert!(metadata_path.exists(), "SE050 metadata should persist");

    {
        let first = state.lock().unwrap_or_else(|error| error.into_inner());
        assert_eq!(first.provision_count, 1);
    }

    let restarted = crate::vault::wrapper::default_wrapper(&config).expect("restart wrapper");
    assert_eq!(restarted.scheme(), crate::vault::wrapper::SE050_WRAP_SCHEME);
    assert_eq!(restarted.key_id(), record.enc.wrap_key_id);

    let decrypted = ingest::decrypt_record_to_temp(&record)
        .await
        .expect("decrypt hardware record after restart");
    assert_eq!(
        tokio::fs::read(decrypted)
            .await
            .expect("read decrypted hardware payload"),
        payload
    );

    let final_state = state.lock().unwrap_or_else(|error| error.into_inner());
    assert_eq!(final_state.provision_count, 1);
    assert!(final_state.wrap_count >= 1);
    assert!(final_state.unwrap_count >= 1);
}

struct EnvUnsetRestore {
    key: &'static str,
    previous: Option<String>,
}

impl EnvUnsetRestore {
    fn unset(key: &'static str) -> Self {
        let previous = std::env::var(key).ok();
        std::env::remove_var(key);
        Self { key, previous }
    }
}

impl Drop for EnvUnsetRestore {
    fn drop(&mut self) {
        if let Some(value) = &self.previous {
            std::env::set_var(self.key, value);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

#[tokio::test]
async fn vault_config_from_env_uses_default_base_when_env_is_missing() {
    let _env_lock = crate::vault::lock_test_env().await;
    let _base = EnvUnsetRestore::unset(crate::vault::VAULT_BASE_ENV);

    let config = VaultConfig::from_env();

    assert_eq!(config.base_dir, std::path::PathBuf::from(crate::vault::VAULT_BASE));
    assert_eq!(
        VaultConfig::DEFAULT_CHUNK_BYTES,
        crate::xfer::XferConfig::DEFAULT_CHUNK_BYTES
    );
    assert_eq!(config.clone().base_dir, config.base_dir);
    assert!(format!("{config:?}").contains("base_dir"));
}

#[tokio::test]
async fn vault_config_from_env_preserves_custom_values_without_normalizing() {
    let _env_lock = crate::vault::lock_test_env().await;

    for raw in [
        "",
        ".",
        "relative/vault",
        "/tmp/guardian vault/custom",
        "/tmp/guardian-vault/../vault",
    ] {
        let _base = EnvRestore::set_value(crate::vault::VAULT_BASE_ENV, raw);
        let config = VaultConfig::from_env();
        assert_eq!(config.base_dir, std::path::PathBuf::from(raw));
    }
}

#[test]
fn download_path_formats_vault_ids_without_validation_or_encoding() {
    assert_eq!(
        crate::vault::download_path("urn:uuid:abc-123"),
        "/api/v1/vault/files/urn:uuid:abc-123/download"
    );
    assert_eq!(
        crate::vault::download_path(""),
        "/api/v1/vault/files//download"
    );
    assert_eq!(
        crate::vault::download_path("folder/name with spaces?x=1#frag"),
        "/api/v1/vault/files/folder/name with spaces?x=1#frag/download"
    );
}

#[tokio::test]
async fn write_lock_is_singleton_and_exclusive() {
    let first = crate::vault::write_lock();
    let second = crate::vault::write_lock();
    assert!(std::ptr::eq(first, second));

    let guard = first.lock().await;
    assert!(second.try_lock().is_err());
    drop(guard);

    let reacquired = second.try_lock().expect("lock should be available after guard drops");
    drop(reacquired);
}

fn test_record(
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
        size_plain: 32,
        size_cipher,
        sha256_plain: "00".repeat(32),
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
            wrap_scheme: crate::vault::wrapper::SOFTWARE_WRAP_SCHEME.into(),
            wrap_key_id: crate::vault::wrapper::SOFTWARE_WRAP_KEY_ID.into(),
        },
    }
}

#[test]
fn persistence_safe_id_replaces_only_path_sensitive_characters() {
    assert_eq!(
        persistence::safe_id("urn:uuid/a\\b\0c"),
        "urn_uuid_a_b_c"
    );
    assert_eq!(
        persistence::safe_id("spaces and unicode \u{2603} stay"),
        "spaces and unicode \u{2603} stay"
    );
}

#[tokio::test]
async fn persistence_read_json_if_exists_and_write_atomic_cover_missing_and_malformed_files() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("nested").join("value.json");

    let missing = persistence::read_json_if_exists::<serde_json::Value>(&path)
        .await
        .expect("missing read should succeed");
    assert!(missing.is_none());

    persistence::write_atomic(&path, br#"{"ready":true}"#)
        .await
        .expect("write atomic");
    assert_eq!(
        persistence::read_json::<serde_json::Value>(&path)
            .await
            .expect("read json"),
        serde_json::json!({ "ready": true })
    );
    assert!(!path.with_extension("tmp").exists());

    persistence::write_atomic(&path, b"{not-json")
        .await
        .expect("write malformed json");
    assert!(persistence::read_json::<serde_json::Value>(&path)
        .await
        .is_err());
}

#[tokio::test]
async fn persistence_lists_sorted_valid_records_and_ignores_unreadable_entries() {
    let temp = TempDir::new().expect("tempdir");
    let config = VaultConfig {
        base_dir: temp.path().join("vault"),
    };
    let namespace = VaultNamespace::Circle("circle-alpha".to_string());
    let older = test_record(
        "urn:uuid:older",
        namespace.clone(),
        "2026-01-01T00:00:00Z",
        101,
    );
    let newer = test_record(
        "urn:uuid:newer",
        namespace.clone(),
        "2026-01-02T00:00:00Z",
        202,
    );

    persistence::save_record(&config, &older)
        .await
        .expect("save older");
    persistence::save_record(&config, &newer)
        .await
        .expect("save newer");
    tokio::fs::write(
        persistence::meta_namespace_dir(&config, &namespace).join("broken.json"),
        b"{bad-json",
    )
    .await
    .expect("write malformed record");
    tokio::fs::write(persistence::meta_dir(&config).join("not-a-namespace"), b"ignored")
        .await
        .expect("write non-dir entry");

    let listed = persistence::list_records(&config, None)
        .await
        .expect("list all records");
    assert_eq!(
        listed
            .iter()
            .map(|record| record.vault_id.as_str())
            .collect::<Vec<_>>(),
        vec!["urn:uuid:newer", "urn:uuid:older"]
    );
    assert!(persistence::find_record(&config, "missing")
        .await
        .expect("find missing")
        .is_none());
}

#[tokio::test]
async fn delete_record_removes_blob_and_metadata_and_is_idempotent() {
    let temp = TempDir::new().expect("tempdir");
    let config = VaultConfig {
        base_dir: temp.path().join("vault"),
    };
    let record = test_record(
        "urn:uuid:delete-me",
        VaultNamespace::Circle("circle-delete".to_string()),
        "2026-01-01T00:00:00Z",
        64,
    );
    let blob_path = persistence::record_blob_path(&config, &record);
    let meta_path = persistence::record_meta_path(&config, &record);

    persistence::save_record(&config, &record)
        .await
        .expect("save metadata");
    persistence::write_atomic(&blob_path, b"encrypted")
        .await
        .expect("save blob");

    persistence::delete_record(&config, &record)
        .await
        .expect("delete existing record");
    assert!(!blob_path.exists());
    assert!(!meta_path.exists());

    persistence::delete_record(&config, &record)
        .await
        .expect("delete missing record is ok");
}

#[tokio::test]
async fn move_to_namespace_moves_blob_metadata_and_updates_namespace_fields() {
    let temp = TempDir::new().expect("tempdir");
    let config = VaultConfig {
        base_dir: temp.path().join("vault"),
    };
    let record = test_record(
        "urn:uuid:move-me",
        VaultNamespace::Personal,
        "2026-01-01T00:00:00Z",
        64,
    );
    let old_blob = persistence::record_blob_path(&config, &record);
    let old_meta = persistence::record_meta_path(&config, &record);
    persistence::save_record(&config, &record)
        .await
        .expect("save metadata");
    persistence::write_atomic(&old_blob, b"encrypted")
        .await
        .expect("save blob");

    let _guard = crate::vault::write_lock().lock().await;
    let moved = persistence::move_to_namespace(
        &config,
        record,
        &VaultNamespace::Circle("circle-moved".to_string()),
    )
    .await
    .expect("move namespace");
    drop(_guard);

    assert_eq!(moved.namespace, "");
    assert_eq!(moved.circle_id, "circle-moved");
    assert!(!old_blob.exists());
    assert!(!old_meta.exists());
    assert_eq!(
        tokio::fs::read(persistence::record_blob_path(&config, &moved))
            .await
            .expect("read moved blob"),
        b"encrypted"
    );
    assert!(persistence::load_record(&config, "circle-moved", &moved.vault_id)
        .await
        .expect("load moved")
        .is_some());
}

#[tokio::test]
async fn upload_invalid_folder_id_returns_before_ingest_and_preserves_staging_file() {
    let temp = TempDir::new().expect("tempdir");
    let config = VaultConfig {
        base_dir: temp.path().join("vault"),
    };
    let staging_path = temp.path().join("invalid-folder.part");
    tokio::fs::write(&staging_path, b"payload")
        .await
        .expect("write staging payload");

    let error = upload::ingest_staged_upload(
        &config,
        upload::StagedUpload {
            namespace: VaultNamespace::Personal,
            folder_id: "../bad".into(),
            filename: "payload.txt".into(),
            mime: "text/plain".into(),
            sender_did: "did:guardian:sender".into(),
            staging_path: staging_path.clone(),
            size_plain: 7,
            sha256_plain: hex::encode(sha2::Sha256::digest(b"payload")),
            chunk_bytes: VaultConfig::DEFAULT_CHUNK_BYTES,
            description: String::new(),
        },
    )
    .await
    .expect_err("invalid folder id should fail");

    assert!(error.to_string().contains("folder id"));
    assert!(staging_path.exists());
}

#[tokio::test]
async fn software_wrapper_rejects_malformed_master_key_lengths() {
    let temp = TempDir::new().expect("tempdir");
    let config = VaultConfig {
        base_dir: temp.path().join("vault"),
    };
    let master_key = persistence::master_key_path(&config);
    tokio::fs::create_dir_all(master_key.parent().expect("parent"))
        .await
        .expect("create wrap dir");

    for len in [0_usize, 31, 33] {
        tokio::fs::write(&master_key, vec![0xA5; len])
            .await
            .expect("write malformed master key");
        let error = crate::vault::wrapper::SoftwareWrapper::from_config(&config)
            .expect_err("bad master key length must fail");
        assert!(error.to_string().contains("master key must be 32 bytes"));
        assert!(error.to_string().contains(&len.to_string()));
    }
}

#[tokio::test]
async fn software_wrapper_rejects_short_and_tampered_wrapped_deks() {
    let temp = TempDir::new().expect("tempdir");
    let config = VaultConfig {
        base_dir: temp.path().join("vault"),
    };
    let wrapper =
        crate::vault::wrapper::SoftwareWrapper::from_config(&config).expect("software wrapper");

    for len in [0_usize, 11, 27] {
        let error = wrapper
            .unwrap(&vec![0xA5; len])
            .expect_err("short wrapped DEK must fail");
        assert!(error.to_string().contains("wrapped DEK too short"));
    }

    let mut wrapped = wrapper.wrap(&[0x11; 32]).expect("wrap DEK");
    let last = wrapped.len() - 1;
    wrapped[last] ^= 0x01;
    let error = wrapper
        .unwrap(&wrapped)
        .expect_err("tampered wrapped DEK must fail");
    assert!(error.to_string().contains("software wrap open failed"));
}

#[tokio::test]
async fn wrapper_for_metadata_rejects_mismatched_empty_and_unknown_metadata() {
    let _env_lock = crate::vault::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
    let config = VaultConfig::from_env();
    let _profile = crate::vault::wrapper::test_force_runtime_profile(
        crate::vault::wrapper::RuntimeProfile::Docker,
    );

    let software = crate::vault::wrapper::wrapper_for_metadata(
        &config,
        crate::vault::wrapper::SOFTWARE_WRAP_SCHEME,
        "",
    )
    .expect("blank software key id is accepted for legacy metadata");
    assert_eq!(software.scheme(), crate::vault::wrapper::SOFTWARE_WRAP_SCHEME);

    let mismatch = match crate::vault::wrapper::wrapper_for_metadata(
        &config,
        crate::vault::wrapper::SOFTWARE_WRAP_SCHEME,
        "other-key",
    ) {
        Ok(_) => panic!("software key mismatch should fail"),
        Err(error) => error,
    };
    assert!(mismatch.to_string().contains("software wrap key id mismatch"));

    let empty_se050 = match crate::vault::wrapper::wrapper_for_metadata(
        &config,
        crate::vault::wrapper::SE050_WRAP_SCHEME,
        "  ",
    ) {
        Ok(_) => panic!("SE050 metadata requires key id"),
        Err(error) => error,
    };
    assert!(empty_se050.to_string().contains("require wrap_key_id"));

    let unknown = match crate::vault::wrapper::wrapper_for_metadata(
        &config,
        "unknown-scheme",
        "key",
    ) {
        Ok(_) => panic!("unknown scheme should fail"),
        Err(error) => error,
    };
    assert!(unknown.to_string().contains("unsupported wrap scheme"));
}

#[tokio::test]
async fn se050_wrapper_rejects_malformed_envelope_metadata_before_unwrap() {
    let _env_lock = crate::vault::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base = EnvRestore::set(crate::vault::VAULT_BASE_ENV, temp.path());
    let _profile = crate::vault::wrapper::test_force_runtime_profile(
        crate::vault::wrapper::RuntimeProfile::Production,
    );
    let (backend, state) = MockSe050Backend::available_with_delays(0, 0);
    let _backend = crate::vault::wrapper::test_override_se050_wrap_backend(backend);
    let config = VaultConfig::from_env();
    let wrapper = crate::vault::wrapper::default_wrapper(&config).expect("SE050 wrapper");

    for (name, envelope) in [
        (
            "version",
            serde_json::json!({
                "version": 2,
                "oaep_hash": "backend-default",
                "oaep_mgf1_hash": "backend-default",
                "oaep_label_b64": "",
                "payload_format": "raw-dek-32",
                "ciphertext_b64": "AA=="
            }),
        ),
        (
            "hash",
            serde_json::json!({
                "version": 1,
                "oaep_hash": "sha256",
                "oaep_mgf1_hash": "backend-default",
                "oaep_label_b64": "",
                "payload_format": "raw-dek-32",
                "ciphertext_b64": "AA=="
            }),
        ),
        (
            "label",
            serde_json::json!({
                "version": 1,
                "oaep_hash": "backend-default",
                "oaep_mgf1_hash": "backend-default",
                "oaep_label_b64": "bGFiZWw=",
                "payload_format": "raw-dek-32",
                "ciphertext_b64": "AA=="
            }),
        ),
        (
            "payload",
            serde_json::json!({
                "version": 1,
                "oaep_hash": "backend-default",
                "oaep_mgf1_hash": "backend-default",
                "oaep_label_b64": "",
                "payload_format": "raw-dek-48",
                "ciphertext_b64": "AA=="
            }),
        ),
    ] {
        let error = match wrapper.unwrap(envelope.to_string().as_bytes()) {
            Ok(_) => panic!("bad {name} envelope should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("SE050"));
    }

    let malformed_json = wrapper
        .unwrap(br#"{"version":"#)
        .expect_err("malformed JSON envelope should fail");
    assert!(malformed_json
        .to_string()
        .contains("invalid SE050 wrapped DEK envelope"));

    let invalid_base64 = wrapper
        .unwrap(
            serde_json::json!({
                "version": 1,
                "oaep_hash": "backend-default",
                "oaep_mgf1_hash": "backend-default",
                "oaep_label_b64": "",
                "payload_format": "raw-dek-32",
                "ciphertext_b64": "@@@"
            })
            .to_string()
            .as_bytes(),
        )
        .expect_err("invalid ciphertext base64 should fail");
    assert!(invalid_base64.to_string().contains("Invalid"));

    let final_state = state.lock().unwrap_or_else(|error| error.into_inner());
    assert_eq!(final_state.unwrap_count, 0);
}
