use sgx_guardian_client::secure_element::dkp::DKP_BASE_KEY_ID;
use sgx_guardian_client::secure_element::pcr::PcrEngine;
use sgx_guardian_client::secure_element::pcr::{
    canonical_baseline_signing_payload, canonical_static_yaml_measurement, signature_format,
    PcrBaseline, PcrSnapshot, MAX_PCR_SNAPSHOT_AGE_SECS, PCR_BIOS, PCR_CONFIG, PCR_COUNT,
    PCR_FIRMWARE, PCR_KERNEL, PCR_ROOTFS, PCR_SCHEMA_VERSION,
};

#[test]
fn test_pcr_engine() {
    let mut engine = PcrEngine::new();
    assert!(!engine.all_measured());

    // Extend PCR 0
    let res = engine.extend_from_string(0, "test-measurement");
    assert!(res.is_ok());

    // Test snapshot
    let snapshot = engine.snapshot();
    assert_eq!(snapshot.pcr_values.len(), 5);

    // Test composite digest
    let composite = engine.composite_digest();
    assert!(!composite.is_empty());
}

fn snapshot(values: Vec<String>, measured_at: String) -> PcrSnapshot {
    PcrSnapshot {
        pcr_values: values,
        composite_digest: "00".repeat(32),
        composite_signature: None,
        nonce: "nonce".into(),
        measured_at,
        device_uid: "device".into(),
        key_version: 1,
        firmware_version: None,
        measurement_errors: Vec::new(),
        integrity_status: "UNKNOWN".into(),
        schema_version: PCR_SCHEMA_VERSION,
    }
}

fn baseline(values: Vec<String>) -> PcrBaseline {
    PcrBaseline {
        pcr_values: values,
        composite_digest: "00".repeat(32),
        baseline_signature: String::new(),
        signing_backend: None,
        signing_public_key_sha256: None,
        signature_format: None,
        created_at: "2026-01-01T00:00:00Z".into(),
        device_uid: "device".into(),
        key_version: 1,
        schema_version: PCR_SCHEMA_VERSION,
    }
}

#[test]
fn dkp_base_key_id_matches_expected_slot() {
    assert_eq!(DKP_BASE_KEY_ID, 0x20000010);
}

#[test]
fn dkp_key_version_offsets_are_contiguous() {
    assert_eq!(DKP_BASE_KEY_ID + 1, 0x20000011);
    assert_eq!(DKP_BASE_KEY_ID + 24, 0x20000028);
}

#[test]
fn dkp_key_hex_format_is_uppercase_width_eight() {
    assert_eq!(format!("0x{:08X}", DKP_BASE_KEY_ID), "0x20000010");
}

#[test]
fn dkp_public_path_suffix_is_stable() {
    assert!(sgx_guardian_client::secure_element::dkp::DKP_PUB_PATH.ends_with("dkp_pub.der"));
}

macro_rules! dkp_version_offset_tests {
    ($($name:ident => $version:expr, $expected:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            assert_eq!(DKP_BASE_KEY_ID + $version - 1, $expected);
            assert_eq!(format!("0x{:08X}", DKP_BASE_KEY_ID + $version - 1).len(), 10);
        }
    )+};
}

dkp_version_offset_tests! {
    dkp_version_01_slot => 1, 0x20000010,
    dkp_version_02_slot => 2, 0x20000011,
    dkp_version_03_slot => 3, 0x20000012,
    dkp_version_04_slot => 4, 0x20000013,
    dkp_version_05_slot => 5, 0x20000014,
    dkp_version_06_slot => 6, 0x20000015,
    dkp_version_07_slot => 7, 0x20000016,
    dkp_version_08_slot => 8, 0x20000017,
    dkp_version_09_slot => 9, 0x20000018,
    dkp_version_10_slot => 10, 0x20000019,
    dkp_version_11_slot => 11, 0x2000001A,
    dkp_version_12_slot => 12, 0x2000001B,
    dkp_version_13_slot => 13, 0x2000001C,
    dkp_version_14_slot => 14, 0x2000001D,
    dkp_version_15_slot => 15, 0x2000001E,
    dkp_version_16_slot => 16, 0x2000001F,
    dkp_version_17_slot => 17, 0x20000020,
    dkp_version_18_slot => 18, 0x20000021,
    dkp_version_19_slot => 19, 0x20000022,
    dkp_version_20_slot => 20, 0x20000023,
    dkp_version_21_slot => 21, 0x20000024,
}

#[test]
fn pcr_constants_cover_five_slots() {
    assert_eq!(PCR_COUNT, 5);
    assert_eq!(
        [PCR_BIOS, PCR_FIRMWARE, PCR_KERNEL, PCR_ROOTFS, PCR_CONFIG],
        [0, 1, 2, 3, 4]
    );
}

#[test]
fn pcr_names_cover_known_and_unknown_indexes() {
    assert_eq!(PcrEngine::pcr_name(PCR_BIOS), "BIOS/Bootloader");
    assert_eq!(PcrEngine::pcr_name(PCR_CONFIG), "Configuration");
    assert_eq!(PcrEngine::pcr_name(PCR_COUNT), "Unknown");
}

#[test]
fn invalid_pcr_get_hex_returns_invalid() {
    assert_eq!(PcrEngine::new().get_hex(PCR_COUNT), "invalid");
}

#[test]
fn invalid_pcr_extend_returns_range_error() {
    assert!(PcrEngine::new()
        .extend(PCR_COUNT, b"x")
        .unwrap_err()
        .contains("out of range"));
}

#[test]
fn empty_measurement_extend_is_allowed() {
    let mut engine = PcrEngine::new();
    assert!(engine.extend(PCR_BIOS, b"").is_ok());
    assert_ne!(engine.get_hex(PCR_BIOS), "00".repeat(32));
}

#[test]
fn extend_from_string_returns_sha256_hex() {
    let mut engine = PcrEngine::new();
    let digest = engine.extend_from_string(PCR_KERNEL, "kernel").unwrap();
    assert_eq!(digest.len(), 64);
    assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn extend_from_missing_file_records_error_in_multi_file_path() {
    let mut engine = PcrEngine::new();
    let errors = engine.extend_from_files(PCR_CONFIG, &["/tmp/sgx-missing-pcr-file".into()]);
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].pcr_index, PCR_CONFIG);
}

#[test]
fn extend_from_files_sorts_paths_for_determinism() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.txt");
    let b = dir.path().join("b.txt");
    std::fs::write(&a, b"a").unwrap();
    std::fs::write(&b, b"b").unwrap();
    let mut one = PcrEngine::new();
    let mut two = PcrEngine::new();
    assert!(one
        .extend_from_files(
            PCR_CONFIG,
            &[b.display().to_string(), a.display().to_string()]
        )
        .is_empty());
    assert!(two
        .extend_from_files(
            PCR_CONFIG,
            &[a.display().to_string(), b.display().to_string()]
        )
        .is_empty());
    assert_eq!(one.get_hex(PCR_CONFIG), two.get_hex(PCR_CONFIG));
}

#[test]
fn snapshot_save_and_load_round_trips() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let snap = PcrEngine::new().snapshot();
    snap.save(file.path().to_str().unwrap()).unwrap();
    assert_eq!(
        PcrSnapshot::load(file.path().to_str().unwrap())
            .unwrap()
            .schema_version,
        PCR_SCHEMA_VERSION
    );
}

#[test]
fn snapshot_load_missing_file_errors() {
    assert!(PcrSnapshot::load("/tmp/sgx-missing-pcr-snapshot.json").is_err());
}

#[test]
fn snapshot_load_malformed_json_errors() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), b"{").unwrap();
    assert!(PcrSnapshot::load(file.path().to_str().unwrap()).is_err());
}

#[test]
fn snapshot_fresh_when_recent() {
    assert!(snapshot(vec![], chrono::Utc::now().to_rfc3339()).is_fresh());
}

#[test]
fn snapshot_stale_when_too_old() {
    let old = chrono::Utc::now() - chrono::Duration::seconds(MAX_PCR_SNAPSHOT_AGE_SECS + 1);
    assert!(!snapshot(vec![], old.to_rfc3339()).is_fresh());
}

#[test]
fn snapshot_invalid_timestamp_is_not_fresh() {
    assert!(!snapshot(vec![], "not-time".into()).is_fresh());
}

#[test]
fn compare_baseline_detects_no_mismatch() {
    let values = vec!["a".into(), "b".into()];
    assert!(snapshot(values.clone(), chrono::Utc::now().to_rfc3339())
        .compare_baseline(&baseline(values))
        .unwrap()
        .is_empty());
}

#[test]
fn compare_baseline_detects_mismatch_indexes() {
    let got = snapshot(
        vec!["a".into(), "b".into()],
        chrono::Utc::now().to_rfc3339(),
    );
    assert_eq!(
        got.compare_baseline(&baseline(vec!["x".into(), "b".into()]))
            .unwrap(),
        vec![0]
    );
}

#[test]
fn compare_baseline_length_mismatch_errors() {
    assert!(snapshot(vec!["a".into()], chrono::Utc::now().to_rfc3339())
        .compare_baseline(&baseline(vec![]))
        .is_err());
}

#[test]
fn baseline_save_and_load_round_trips() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let base = baseline(vec!["a".into()]);
    base.save(file.path().to_str().unwrap()).unwrap();
    assert_eq!(
        PcrBaseline::load(file.path().to_str().unwrap())
            .unwrap()
            .pcr_values,
        vec!["a"]
    );
}

#[test]
fn baseline_verify_signature_rejects_invalid_base64() {
    assert!(!baseline(vec![]).verify_signature(b"not-a-key"));
}

#[test]
fn canonical_payload_rejects_non_hex_digest() {
    assert!(canonical_baseline_signing_payload("not-hex", "t", "d").is_err());
}

#[test]
fn canonical_payload_rejects_wrong_digest_length() {
    assert!(canonical_baseline_signing_payload("00", "t", "d").is_err());
}

#[test]
fn canonical_payload_returns_sha256_length() {
    assert_eq!(
        canonical_baseline_signing_payload(&"00".repeat(32), "t", "d")
            .unwrap()
            .len(),
        32
    );
}

#[test]
fn signature_format_detects_fixed_64_bytes() {
    assert_eq!(signature_format(&[0u8; 64]), "ecdsa-p256-sha256-fixed");
}

#[test]
fn signature_format_detects_asn1_der_prefix() {
    assert_eq!(signature_format(&[0x30, 1, 2]), "ecdsa-p256-sha256-asn1");
}

#[test]
fn signature_format_defaults_short_non_der_to_fixed() {
    assert_eq!(signature_format(&[1, 2, 3]), "ecdsa-p256-sha256-fixed");
}

#[test]
fn canonical_static_yaml_removes_dynamic_keys() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        file.path(),
        "ip: 10.0.0.1\nname: node\nnested:\n  endpoint: old\n  stable: yes\n",
    )
    .unwrap();
    let measured = canonical_static_yaml_measurement(file.path().to_str().unwrap());
    assert!(!measured.contains("10.0.0.1"));
    assert!(measured.contains("stable"));
}

#[test]
fn canonical_static_yaml_missing_file_is_empty() {
    assert_eq!(
        canonical_static_yaml_measurement("/tmp/sgx-missing-static-yaml.yaml"),
        ""
    );
}

#[test]
fn canonical_static_yaml_malformed_file_is_empty() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), "bad: [").unwrap();
    assert_eq!(
        canonical_static_yaml_measurement(file.path().to_str().unwrap()),
        ""
    );
}
