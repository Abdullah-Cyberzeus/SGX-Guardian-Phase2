//! Unit coverage for PCR persistence/measurement helpers, key lifecycle
//! metadata, secure-boot models, and secure-element error contracts.

use chrono::{Duration, Utc};
use sgx_guardian_client::secure_element::error::SeError;
use sgx_guardian_client::secure_element::key_meta::{
    DkpKeyHistory, KeyMetadata, KeyStatus, DKP_ROTATION_INTERVAL_SECS, REVOCATION_GRACE_PERIOD_SECS,
};
use sgx_guardian_client::secure_element::pcr::{
    canonical_baseline_signing_payload, canonical_static_yaml_measurement, signature_format,
    verify_baseline_signature_bytes, PcrBaseline, PcrEngine, PcrMeasurementError, PcrSnapshot,
    MAX_PCR_SNAPSHOT_AGE_SECS, PCR_CONFIG, PCR_COUNT, PCR_SCHEMA_VERSION,
};
use sgx_guardian_client::secure_element::safe_mode::guard_crypto_operation;
use sgx_guardian_client::secure_element::secure_boot::BootChainStatus;
use sgx_guardian_client::secure_element::tamper::{is_tampered, TamperStatus};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

fn snapshot_at(measured_at: String) -> PcrSnapshot {
    PcrSnapshot {
        pcr_values: vec!["00".repeat(32); PCR_COUNT],
        composite_digest: "11".repeat(32),
        composite_signature: Some("signature".into()),
        nonce: "nonce".into(),
        measured_at,
        device_uid: "device-a".into(),
        key_version: 2,
        firmware_version: Some("1.2.3".into()),
        measurement_errors: vec![PcrMeasurementError {
            pcr_index: PCR_CONFIG,
            source: "config.yaml".into(),
            error: "optional input absent".into(),
        }],
        integrity_status: "DEGRADED".into(),
        schema_version: PCR_SCHEMA_VERSION,
    }
}

fn baseline(values: Vec<String>) -> PcrBaseline {
    PcrBaseline {
        pcr_values: values,
        composite_digest: "22".repeat(32),
        baseline_signature: String::new(),
        signing_backend: Some("software".into()),
        signing_public_key_sha256: Some("33".repeat(32)),
        signature_format: Some("ecdsa-p256-sha256-asn1".into()),
        created_at: "2026-01-01T00:00:00Z".into(),
        device_uid: "device-a".into(),
        key_version: 2,
        schema_version: PCR_SCHEMA_VERSION,
    }
}

fn key(version: u32) -> KeyMetadata {
    KeyMetadata::new(
        &format!("0x{:08x}", 0x2000_0010 + version - 1),
        &format!("dkp-v{version}"),
        "ECDSA-P256",
        version,
    )
}

#[test]
fn pcr_snapshot_and_baseline_persistence_cover_success_and_parse_errors() {
    let temp = TempDir::new().unwrap();
    let snapshot_path = temp.path().join("nested/snapshot.json");
    let baseline_path = temp.path().join("nested/baseline.json");
    let snapshot = snapshot_at(Utc::now().to_rfc3339());
    let expected_baseline = baseline(snapshot.pcr_values.clone());

    snapshot.save(snapshot_path.to_str().unwrap()).unwrap();
    expected_baseline
        .save(baseline_path.to_str().unwrap())
        .unwrap();
    let loaded_snapshot = PcrSnapshot::load(snapshot_path.to_str().unwrap()).unwrap();
    let loaded_baseline = PcrBaseline::load(baseline_path.to_str().unwrap()).unwrap();
    assert_eq!(loaded_snapshot.device_uid, "device-a");
    assert_eq!(loaded_snapshot.measurement_errors.len(), 1);
    assert_eq!(loaded_baseline.signing_backend.as_deref(), Some("software"));
    assert_eq!(loaded_baseline.key_version, 2);

    assert!(PcrSnapshot::load(temp.path().join("missing.json").to_str().unwrap()).is_err());
    assert!(
        PcrBaseline::load(temp.path().join("missing-baseline.json").to_str().unwrap()).is_err()
    );
    std::fs::write(&snapshot_path, "{bad json}").unwrap();
    std::fs::write(&baseline_path, "[]").unwrap();
    assert!(PcrSnapshot::load(snapshot_path.to_str().unwrap()).is_err());
    assert!(PcrBaseline::load(baseline_path.to_str().unwrap()).is_err());
}

#[test]
fn pcr_freshness_and_baseline_comparison_cover_boundaries_and_mismatches() {
    assert!(snapshot_at(Utc::now().to_rfc3339()).is_fresh());
    assert!(snapshot_at((Utc::now() + Duration::minutes(1)).to_rfc3339()).is_fresh());
    assert!(!snapshot_at(
        (Utc::now() - Duration::seconds(MAX_PCR_SNAPSHOT_AGE_SECS + 5)).to_rfc3339()
    )
    .is_fresh());
    assert!(!snapshot_at("not-a-timestamp".into()).is_fresh());

    let snapshot = snapshot_at(Utc::now().to_rfc3339());
    let same = baseline(snapshot.pcr_values.clone());
    assert_eq!(
        snapshot.compare_baseline(&same).unwrap(),
        Vec::<usize>::new()
    );

    let mut different = same;
    different.pcr_values[0] = "ff".repeat(32);
    different.pcr_values[3] = "aa".repeat(32);
    assert_eq!(snapshot.compare_baseline(&different).unwrap(), vec![0, 3]);
    different.pcr_values.pop();
    let error = snapshot.compare_baseline(&different).unwrap_err();
    assert!(error.contains("PCR count mismatch"));
}

#[test]
fn baseline_signing_payload_and_signature_detection_cover_invalid_shapes() {
    let digest = "ab".repeat(32);
    let created = "2026-01-01T00:00:00Z";
    let uid = "device-a";
    let payload = canonical_baseline_signing_payload(&digest, created, uid).unwrap();
    let mut raw = hex::decode(&digest).unwrap();
    raw.extend_from_slice(created.as_bytes());
    raw.extend_from_slice(uid.as_bytes());
    assert_eq!(payload, Sha256::digest(raw).to_vec());
    assert_eq!(payload.len(), 32);

    assert_eq!(
        canonical_baseline_signing_payload("not-hex", created, uid).unwrap_err(),
        "Invalid composite_digest"
    );
    assert!(canonical_baseline_signing_payload("aa", created, uid)
        .unwrap_err()
        .contains("must be 32 bytes"));

    assert_eq!(
        signature_format(&[0x30, 0x01, 0x00]),
        "ecdsa-p256-sha256-asn1"
    );
    assert_eq!(signature_format(&[0x30; 64]), "ecdsa-p256-sha256-fixed");
    assert_eq!(signature_format(&[0x01, 0x02]), "ecdsa-p256-sha256-fixed");
    assert!(!verify_baseline_signature_bytes(
        &payload,
        &[0x30, 0],
        &[0x04; 65]
    ));
    assert!(!verify_baseline_signature_bytes(
        &payload,
        &[0; 64],
        &[0x04; 65]
    ));

    let mut invalid = baseline(vec!["00".repeat(32); PCR_COUNT]);
    invalid.baseline_signature = "%%%".into();
    assert!(!invalid.verify_signature(&[0x04; 65]));
    invalid.baseline_signature =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 64]);
    invalid.composite_digest = "short".into();
    assert!(!invalid.verify_signature(&[0x04; 65]));
}

#[test]
fn pcr_engine_measures_small_large_missing_and_sorted_file_sets() {
    let temp = TempDir::new().unwrap();
    let alpha = temp.path().join("alpha.txt");
    let zeta = temp.path().join("zeta.txt");
    let large = temp.path().join("large.bin");
    let missing = temp.path().join("missing.txt");
    std::fs::write(&alpha, b"alpha contents").unwrap();
    std::fs::write(&zeta, b"zeta contents").unwrap();
    let large_file = std::fs::File::create(&large).unwrap();
    large_file.set_len(16 * 1024 * 1024 + 1).unwrap();

    let mut engine = PcrEngine::new();
    let alpha_hash = engine.extend_from_file(0, alpha.to_str().unwrap()).unwrap();
    assert_eq!(alpha_hash, hex::encode(Sha256::digest(b"alpha contents")));
    let large_hash = engine.extend_from_file(1, large.to_str().unwrap()).unwrap();
    assert_eq!(large_hash.len(), 64);
    assert!(engine
        .extend_from_file(2, missing.to_str().unwrap())
        .is_err());
    assert!(engine
        .extend_from_file(PCR_COUNT, alpha.to_str().unwrap())
        .is_err());

    let paths_forward = vec![
        zeta.to_string_lossy().into_owned(),
        missing.to_string_lossy().into_owned(),
        alpha.to_string_lossy().into_owned(),
    ];
    let mut paths_reverse = paths_forward.clone();
    paths_reverse.reverse();
    let mut first = PcrEngine::new();
    let mut second = PcrEngine::new();
    let first_errors = first.extend_from_files(3, &paths_forward);
    let second_errors = second.extend_from_files(3, &paths_reverse);
    assert_eq!(first.get_hex(3), second.get_hex(3));
    assert_eq!(first_errors.len(), 1);
    assert_eq!(second_errors.len(), 1);
    assert_eq!(first_errors[0].source, missing.to_string_lossy());
}

#[test]
fn pcr_engine_snapshot_names_invalid_indices_and_measurement_state_are_consistent() {
    let mut engine = PcrEngine::default();
    assert!(!engine.all_measured());
    assert_eq!(engine.get_hex(PCR_COUNT), "invalid");
    assert_eq!(PcrEngine::pcr_name(0), "BIOS/Bootloader");
    assert_eq!(PcrEngine::pcr_name(1), "Firmware/DTB");
    assert_eq!(PcrEngine::pcr_name(2), "Kernel");
    assert_eq!(PcrEngine::pcr_name(3), "RootFS");
    assert_eq!(PcrEngine::pcr_name(4), "Configuration");
    assert_eq!(PcrEngine::pcr_name(PCR_COUNT), "Unknown");

    for index in 0..PCR_COUNT {
        engine
            .extend_from_string(index, &format!("measurement-{index}"))
            .unwrap();
    }
    assert!(engine.all_measured());
    let snapshot = engine.snapshot();
    assert_eq!(snapshot.pcr_values.len(), PCR_COUNT);
    assert_eq!(
        snapshot.composite_digest,
        hex::encode(engine.composite_digest())
    );
    assert_eq!(snapshot.integrity_status, "UNKNOWN");
    assert_eq!(snapshot.schema_version, PCR_SCHEMA_VERSION);
    engine.print_status();
}

#[test]
fn canonical_static_yaml_removes_dynamic_keys_recursively_and_sorts_content() {
    let temp = TempDir::new().unwrap();
    let first = temp.path().join("first.yaml");
    let second = temp.path().join("second.yaml");
    std::fs::write(
        &first,
        r#"
zeta: 7
ip: 192.168.1.2
enabled: true
nested:
  endpoint: 192.168.1.2:5000
  stable: keep
  runtime:
    counter: 1
items:
  - observed_ip: 10.0.0.1
    name: alpha
  - name: beta
null_value: null
ratio: 1.5
"#,
    )
    .unwrap();
    std::fs::write(
        &second,
        r#"
ratio: 1.5
null_value: null
items:
  - name: alpha
    observed_ip: 203.0.113.9
  - name: beta
nested:
  runtime:
    counter: 999
  stable: keep
  endpoint: changed.example:9999
enabled: true
ip: 10.10.10.10
zeta: 7
"#,
    )
    .unwrap();

    let canonical_first = canonical_static_yaml_measurement(first.to_str().unwrap());
    let canonical_second = canonical_static_yaml_measurement(second.to_str().unwrap());
    assert_eq!(canonical_first, canonical_second);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&canonical_first).unwrap(),
        serde_json::json!({
            "enabled": true,
            "items": [{"name":"alpha"},{"name":"beta"}],
            "nested": {"stable":"keep"},
            "null_value": null,
            "ratio": 1.5,
            "zeta": 7
        })
    );
    assert!(!canonical_first.contains("192.168"));
    assert!(!canonical_first.contains("runtime"));

    let invalid = temp.path().join("invalid.yaml");
    std::fs::write(&invalid, "key: [unterminated").unwrap();
    assert_eq!(
        canonical_static_yaml_measurement(invalid.to_str().unwrap()),
        ""
    );
    assert_eq!(
        canonical_static_yaml_measurement(temp.path().join("missing.yaml").to_str().unwrap()),
        ""
    );
}

#[test]
fn key_metadata_lifecycle_covers_rotation_age_and_revocation_grace() {
    let mut active = key(1);
    assert!(active.can_sign());
    assert!(active.can_verify());
    assert!(!active.needs_rotation());
    assert!(active.age_display().contains("minutes"));

    active.created_at = Utc::now() - Duration::hours(3);
    assert!(active.age_display().contains("hours"));
    active.created_at = Utc::now() - Duration::days(30);
    assert_eq!(active.age_display(), "30 days");
    active.created_at = Utc::now() - Duration::days(800);
    assert!(active.age_display().starts_with("2 years"));
    active.created_at = Utc::now() - Duration::seconds(DKP_ROTATION_INTERVAL_SECS + 1);
    assert!(active.needs_rotation());

    active.deprecate();
    assert!(!active.can_sign());
    assert!(active.can_verify());
    assert!(!active.needs_rotation());

    let mut revoked_without_time = key(2);
    revoked_without_time.status = KeyStatus::Revoked;
    assert!(!revoked_without_time.can_verify());
    revoked_without_time.revoked_at = Some(Utc::now());
    assert!(revoked_without_time.can_verify());
    revoked_without_time.revoked_at =
        Some(Utc::now() - Duration::seconds(REVOCATION_GRACE_PERIOD_SECS + 1));
    assert!(!revoked_without_time.can_verify());
    revoked_without_time.revoke("compromised");
    assert_eq!(
        revoked_without_time.revoke_reason.as_deref(),
        Some("compromised")
    );

    assert_eq!(KeyStatus::Active.to_string(), "Active");
    assert_eq!(
        KeyStatus::Deprecated.to_string(),
        "Deprecated (verify-only)"
    );
    assert_eq!(KeyStatus::Revoked.to_string(), "Revoked");
}

#[test]
fn key_history_mutation_persistence_and_legacy_migration_cover_failures() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("nested/history.json");
    let legacy_path = temp.path().join("legacy.json");
    let malformed_path = temp.path().join("malformed.json");
    let mut history = DkpKeyHistory::new(key(1));
    assert_eq!(history.active_key().unwrap().version, 1);
    assert_eq!(history.get(1).unwrap().label, "dkp-v1");
    assert!(history.get(99).is_none());
    assert!(history.get_mut(99).is_none());

    assert!(history.revoke_version(1, "not allowed").is_err());
    assert!(history
        .revoke_version(99, "missing")
        .unwrap_err()
        .contains("not found"));
    assert!(history.deprecate_version(1));
    assert!(!history.deprecate_version(99));
    history.revoke_version(1, "retired").unwrap();
    assert_eq!(history.get(1).unwrap().status, KeyStatus::Revoked);
    assert!(history.active_key().is_none());

    let mut second = key(2);
    second.rotated_from = Some("0x20000010".into());
    second.public_key_path = Some("/tmp/dkp-v2.der".into());
    history.add(second);
    assert_eq!(history.active_key().unwrap().version, 2);
    history.save(path.to_str().unwrap()).unwrap();
    let loaded = DkpKeyHistory::load(path.to_str().unwrap()).unwrap();
    assert_eq!(loaded.keys.len(), 2);
    assert_eq!(loaded.active_key().unwrap().version, 2);

    let legacy = key(7);
    std::fs::write(&legacy_path, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();
    let migrated = DkpKeyHistory::load(legacy_path.to_str().unwrap()).unwrap();
    assert_eq!(migrated.keys.len(), 1);
    assert_eq!(migrated.keys[0].version, 7);

    std::fs::write(&malformed_path, "[bad json]").unwrap();
    assert!(DkpKeyHistory::load(malformed_path.to_str().unwrap()).is_err());
    assert!(DkpKeyHistory::load(temp.path().join("missing.json").to_str().unwrap()).is_err());
}

#[test]
fn secure_boot_unknown_measurement_save_and_cache_are_stable() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("nested/boot.json");
    let unknown = BootChainStatus::unknown();
    assert!(!unknown.hab_enabled);
    assert!(!unknown.device_closed);
    assert!(!unknown.hab_events_found);
    assert!(!unknown.boot_chain_intact);
    assert!(unknown
        .to_measurement_string()
        .contains("KERNEL_HASH:unknown"));

    let status = BootChainStatus {
        hab_enabled: true,
        device_closed: true,
        hab_events_found: false,
        hab_description: "HAB enforcing".into(),
        kernel_version: "Linux version test".into(),
        device_model: "Test Board".into(),
        guardian_binary_hash: Some("ab".repeat(32)),
        boot_chain_intact: true,
    };
    let expected_hash = hex::encode(Sha256::digest(status.kernel_version.as_bytes()));
    let measurement = status.to_measurement_string();
    assert!(measurement.contains("HAB:true"));
    assert!(measurement.contains("CLOSED:true"));
    assert!(measurement.contains("EVENTS:false"));
    assert!(measurement.contains("MODEL:Test Board"));
    assert!(measurement.contains(&expected_hash[..16]));
    status.save(path.to_str().unwrap()).unwrap();
    let decoded: BootChainStatus = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(decoded.device_model, "Test Board");
    assert!(decoded.boot_chain_intact);
    status.print();
}

#[test]
fn safe_mode_tamper_status_and_se_errors_have_stable_public_contracts() {
    assert!(
        !is_tampered(),
        "external test process should begin outside safe mode"
    );
    assert!(guard_crypto_operation("coverage signing").is_ok());
    assert_eq!(TamperStatus::None.to_string(), "Tamper: None");
    assert_eq!(TamperStatus::Detected.to_string(), "Tamper: DETECTED");
    assert_eq!(TamperStatus::Unknown.to_string(), "Tamper: Unknown");

    let errors = [
        SeError::ConnectionFailed("I2C timeout".into()).to_string(),
        SeError::CommandFailed {
            cmd: "se05x uid".into(),
            stderr: "missing".into(),
        }
        .to_string(),
        SeError::NotAvailable.to_string(),
        SeError::KeyError("slot full".into()).to_string(),
        SeError::CryptoError("rng".into()).to_string(),
        SeError::TamperDetected.to_string(),
    ];
    assert_eq!(errors[0], "SE050 connection failed: I2C timeout");
    assert!(errors[1].contains("ssscli failed: se05x uid"));
    assert_eq!(errors[2], "SE050 not available");
    assert_eq!(errors[3], "Key operation failed: slot full");
    assert_eq!(errors[4], "Crypto operation failed: rng");
    assert!(errors[5].contains("safe mode active"));
}
