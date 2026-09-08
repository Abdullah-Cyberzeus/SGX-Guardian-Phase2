use sgx_guardian_client::backup::crypto::{
    decrypt_bundle_bytes, decrypt_from_reader, encrypt_to_writer, CryptoHeader,
};
use sgx_guardian_client::backup::errors::BackupError;
use sgx_guardian_client::backup::model::{
    BackupHistory, BackupRecord, Component, ComponentManifest, IdentityMeta, Manifest,
    RestoreReport, ValidateReport, BACKUP_SCHEMA_VERSION, COMPONENT_SCHEMA_VERSION,
};
use sgx_guardian_client::backup::validate::{validate_manifest, DecodedBackup, DecodedFile};
use sgx_guardian_client::backup::{safe_id, BackupConfig};
use sha2::{Digest, Sha256};
use std::io::Cursor;

fn file(path: &str, bytes: &[u8]) -> DecodedFile {
    DecodedFile {
        archive_path: path.into(),
        bytes: bytes.to_vec(),
    }
}

fn hash_files(files: &[DecodedFile]) -> String {
    let mut encoded = Vec::new();
    for file in files {
        encoded.extend_from_slice(&(file.archive_path.len() as u32).to_be_bytes());
        encoded.extend_from_slice(file.archive_path.as_bytes());
        encoded.extend_from_slice(&(file.bytes.len() as u64).to_be_bytes());
        encoded.extend_from_slice(&file.bytes);
    }
    hex::encode(Sha256::digest(encoded))
}

fn manifest(files: &[DecodedFile]) -> Manifest {
    Manifest {
        schema_version: BACKUP_SCHEMA_VERSION,
        backup_id: "backup".into(),
        created_at: "2026-01-01T00:00:00Z".into(),
        source_node_id: "nodeA".into(),
        source_did: "did:source".into(),
        portable: true,
        components: vec![ComponentManifest {
            component: Component::Config,
            schema_version: COMPONENT_SCHEMA_VERSION,
            paths: files.iter().map(|f| f.archive_path.clone()).collect(),
        }],
        identity_meta: IdentityMeta {
            did: "did:source".into(),
            dkp_slot_id: "0x20000010".into(),
            dik_slot_id: "0x20000100".into(),
            dkp_public_versions: vec!["pub".into()],
        },
        plaintext_sha256: hash_files(files),
        bundle_hmac_sha256: "00".repeat(32),
    }
}

fn decoded(files: Vec<DecodedFile>) -> DecodedBackup {
    DecodedBackup {
        manifest: manifest(&files),
        files,
    }
}

#[test]
fn component_as_str_covers_all_variants() {
    let pairs = [
        (Component::Policy, "policy"),
        (Component::Config, "config"),
        (Component::Nebula, "nebula"),
        (Component::Nftables, "nftables"),
        (Component::IdentityMeta, "identity_meta"),
        (Component::Tls, "tls"),
        (Component::Credentials, "credentials"),
        (Component::Crl, "crl"),
        (Component::State, "state"),
        (Component::FeatureState, "feature_state"),
        (Component::Vault, "vault"),
    ];
    for (component, name) in pairs {
        assert_eq!(component.as_str(), name);
    }
}

#[test]
fn component_serializes_snake_case() {
    assert_eq!(
        serde_json::to_string(&Component::FeatureState).unwrap(),
        "\"feature_state\""
    );
}

#[test]
fn component_rejects_unknown_variant() {
    assert!(serde_json::from_str::<Component>("\"unknown\"").is_err());
}

#[test]
fn backup_history_default_empty() {
    assert!(BackupHistory::default().records.is_empty());
}

#[test]
fn backup_record_serializes_components() {
    let record = BackupRecord {
        id: "id".into(),
        created_at: "t".into(),
        source_node_id: "node".into(),
        source_did: "did".into(),
        portable: true,
        components: vec![Component::Vault],
        bundle_path: "bundle".into(),
        size_bytes: 7,
    };
    assert!(serde_json::to_string(&record).unwrap().contains("vault"));
}

#[test]
fn validate_report_serializes_warnings() {
    let report = ValidateReport {
        status: "ok".into(),
        backup_id: "b".into(),
        source_node_id: "n".into(),
        source_did: "did:s".into(),
        target_did: "did:t".into(),
        same_device_identity: false,
        portable: true,
        components: vec![],
        warnings: vec!["warn".into()],
    };
    assert_eq!(serde_json::to_value(report).unwrap()["warnings"][0], "warn");
}

#[test]
fn restore_report_serializes_restart_flag() {
    let report = RestoreReport {
        status: "ok".into(),
        message: "done".into(),
        restart_required: true,
    };
    assert_eq!(
        serde_json::to_value(report).unwrap()["restart_required"],
        true
    );
}

#[test]
fn safe_id_removes_path_characters() {
    assert_eq!(safe_id("../abc-DEF_123!.bak"), "abc-DEF_123bak");
}

#[test]
fn backup_config_paths_are_under_base_dir() {
    let config = BackupConfig {
        base_dir: "/tmp/backup".into(),
        max_bundle_bytes: 9,
    };
    assert_eq!(
        config.bundles_dir(),
        std::path::PathBuf::from("/tmp/backup/bundles")
    );
    assert_eq!(
        config.bundle_path("a/b"),
        std::path::PathBuf::from("/tmp/backup/bundles/ab.sgxbak")
    );
}

#[test]
fn backup_error_display_variants() {
    assert!(BackupError::NotFound("x".into())
        .to_string()
        .contains("backup not found"));
    assert!(BackupError::InvalidRequest("x".into())
        .to_string()
        .contains("invalid backup request"));
    assert!(BackupError::Duplicate("x".into())
        .to_string()
        .contains("duplicate backup"));
    assert!(BackupError::Integrity("x".into())
        .to_string()
        .contains("integrity"));
    assert!(BackupError::UnsupportedSchema("x".into())
        .to_string()
        .contains("unsupported"));
    assert!(BackupError::RestoreUnavailable("x".into())
        .to_string()
        .contains("restore is not available"));
    assert!(BackupError::BundleTooLarge { size: 2, max: 1 }
        .to_string()
        .contains("2 > 1"));
    assert!(BackupError::Crypto("x".into())
        .to_string()
        .contains("crypto"));
}

#[test]
fn crypto_header_round_trips() {
    let header = CryptoHeader {
        version: 1,
        kdf: "kdf".into(),
        cipher: "cipher".into(),
        chunk_bytes: 64,
        salt_b64: "salt".into(),
        nonce_prefix_b64: "nonce".into(),
    };
    assert_eq!(
        serde_json::from_str::<CryptoHeader>(&serde_json::to_string(&header).unwrap())
            .unwrap()
            .cipher,
        "cipher"
    );
}

#[test]
fn encrypt_decrypt_empty_plaintext_round_trips() {
    let mut out = Vec::new();
    encrypt_to_writer(b"", "pass", &mut out).unwrap();
    assert_eq!(decrypt_bundle_bytes(&out, "pass").unwrap(), b"");
}

#[test]
fn encrypt_decrypt_small_plaintext_round_trips() {
    let mut out = Vec::new();
    let result = encrypt_to_writer(b"hello", "pass", &mut out).unwrap();
    assert_eq!(result.header.version, 1);
    assert_eq!(
        decrypt_from_reader(Cursor::new(out), "pass", 1024 * 1024).unwrap(),
        b"hello"
    );
}

#[test]
fn encrypt_decrypt_multichunk_plaintext_round_trips() {
    let data = vec![7u8; 70 * 1024];
    let mut out = Vec::new();
    encrypt_to_writer(&data, "pass", &mut out).unwrap();
    assert_eq!(decrypt_bundle_bytes(&out, "pass").unwrap(), data);
}

#[test]
fn encrypt_rejects_empty_passphrase() {
    assert!(matches!(
        encrypt_to_writer(b"x", "", Vec::new()).unwrap_err(),
        BackupError::InvalidRequest(_)
    ));
}

#[test]
fn decrypt_rejects_truncated_bundle() {
    assert!(matches!(
        decrypt_bundle_bytes(b"short", "pass").unwrap_err(),
        BackupError::Integrity(_)
    ));
}

#[test]
fn decrypt_rejects_bad_magic() {
    let mut out = Vec::new();
    encrypt_to_writer(b"x", "pass", &mut out).unwrap();
    out[0] = b'X';
    assert!(matches!(
        decrypt_bundle_bytes(&out, "pass").unwrap_err(),
        BackupError::Integrity(_)
    ));
}

#[test]
fn decrypt_rejects_wrong_passphrase() {
    let mut out = Vec::new();
    encrypt_to_writer(b"x", "pass", &mut out).unwrap();
    assert!(matches!(
        decrypt_bundle_bytes(&out, "wrong").unwrap_err(),
        BackupError::Integrity(_)
    ));
}

#[test]
fn decrypt_from_reader_enforces_max_bytes() {
    let mut out = Vec::new();
    encrypt_to_writer(b"x", "pass", &mut out).unwrap();
    assert!(matches!(
        decrypt_from_reader(Cursor::new(out), "pass", 3).unwrap_err(),
        BackupError::BundleTooLarge { .. }
    ));
}

#[test]
fn decrypt_rejects_tampered_hmac() {
    let mut out = Vec::new();
    encrypt_to_writer(b"x", "pass", &mut out).unwrap();
    let last = out.len() - 1;
    out[last] ^= 1;
    assert!(matches!(
        decrypt_bundle_bytes(&out, "pass").unwrap_err(),
        BackupError::Integrity(_)
    ));
}

#[test]
fn validate_manifest_accepts_matching_hash_and_paths() {
    assert!(validate_manifest(&decoded(vec![file("config/a.yaml", b"a")])).is_ok());
}

#[test]
fn validate_manifest_rejects_bad_schema() {
    let mut decoded = decoded(vec![file("config/a.yaml", b"a")]);
    decoded.manifest.schema_version = 99;
    assert!(matches!(
        validate_manifest(&decoded).unwrap_err(),
        BackupError::UnsupportedSchema(_)
    ));
}

#[test]
fn validate_manifest_rejects_empty_backup_id() {
    let mut decoded = decoded(vec![file("config/a.yaml", b"a")]);
    decoded.manifest.backup_id = " ".into();
    assert!(matches!(
        validate_manifest(&decoded).unwrap_err(),
        BackupError::Integrity(_)
    ));
}

#[test]
fn validate_manifest_rejects_empty_source_did() {
    let mut decoded = decoded(vec![file("config/a.yaml", b"a")]);
    decoded.manifest.source_did = String::new();
    assert!(matches!(
        validate_manifest(&decoded).unwrap_err(),
        BackupError::Integrity(_)
    ));
}

#[test]
fn validate_manifest_rejects_component_schema() {
    let mut decoded = decoded(vec![file("config/a.yaml", b"a")]);
    decoded.manifest.components[0].schema_version = 99;
    assert!(matches!(
        validate_manifest(&decoded).unwrap_err(),
        BackupError::UnsupportedSchema(_)
    ));
}

#[test]
fn validate_manifest_rejects_plaintext_hash_mismatch() {
    let mut decoded = decoded(vec![file("config/a.yaml", b"a")]);
    decoded.manifest.plaintext_sha256 = "00".repeat(32);
    assert!(matches!(
        validate_manifest(&decoded).unwrap_err(),
        BackupError::Integrity(_)
    ));
}

#[test]
fn validate_manifest_rejects_manifest_path_mismatch() {
    let mut decoded = decoded(vec![file("config/a.yaml", b"a")]);
    decoded.manifest.components[0].paths = vec!["config/other.yaml".into()];
    assert!(matches!(
        validate_manifest(&decoded).unwrap_err(),
        BackupError::Integrity(_)
    ));
}

#[test]
fn validate_manifest_accepts_empty_identity_meta_component() {
    let decoded = DecodedBackup {
        manifest: Manifest {
            components: vec![ComponentManifest {
                component: Component::IdentityMeta,
                schema_version: COMPONENT_SCHEMA_VERSION,
                paths: vec![],
            }],
            ..manifest(&[])
        },
        files: vec![],
    };
    assert!(validate_manifest(&decoded).is_ok());
}
