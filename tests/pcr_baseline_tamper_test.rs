use base64::{engine::general_purpose, Engine as _};
use sgx_guardian_client::key_manager::KeyManager;
use sgx_guardian_client::secure_element::pcr::{
    canonical_baseline_signing_payload, signature_format, PcrBaseline, PcrEngine, PcrSnapshot,
    PCR_COUNT, PCR_SCHEMA_VERSION,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

struct FileRestoreGuard {
    path: PathBuf,
    original: Vec<u8>,
}

impl FileRestoreGuard {
    fn new(path: PathBuf) -> Self {
        let original = fs::read(&path).expect("read original baseline");
        Self { path, original }
    }
}

impl Drop for FileRestoreGuard {
    fn drop(&mut self) {
        fs::write(&self.path, &self.original).expect("restore original baseline");
    }
}

fn make_snapshot_and_baseline(km: &KeyManager) -> (PcrSnapshot, PcrBaseline) {
    let mut engine = PcrEngine::new();
    for pcr in 0..PCR_COUNT {
        engine
            .extend_from_string(pcr, &format!("integration-baseline-tamper-pcr-{pcr}"))
            .expect("extend PCR");
    }

    let mut snapshot = engine.snapshot();
    snapshot.device_uid = "integration-device-uid".into();
    snapshot.key_version = km.dkp_version();
    snapshot.integrity_status = "PASS".into();

    let created_at = chrono::Utc::now().to_rfc3339();
    let payload = canonical_baseline_signing_payload(
        &snapshot.composite_digest,
        &created_at,
        "integration-device-uid",
    )
    .expect("canonical signing payload");
    let signature = km.sign(&payload).expect("sign baseline");

    let baseline = PcrBaseline {
        pcr_values: snapshot.pcr_values.clone(),
        composite_digest: snapshot.composite_digest.clone(),
        baseline_signature: general_purpose::STANDARD.encode(&signature),
        signing_backend: Some(km.backend_display_name().to_string()),
        signing_public_key_sha256: Some(hex::encode(Sha256::digest(
            km.pubkey_der().expect("public key"),
        ))),
        signature_format: Some(signature_format(&signature).to_string()),
        created_at,
        device_uid: snapshot.device_uid.clone(),
        key_version: km.dkp_version(),
        schema_version: PCR_SCHEMA_VERSION,
    };

    (snapshot, baseline)
}

#[test]
fn signed_pcr_baseline_tamper_paths_are_detected_and_restored() {
    let temp = tempfile::tempdir().expect("temp dir");
    let baseline_path = temp.path().join("pcr_nodeA_baseline.json");
    let key_path = temp.path().join("device_nodeA.key");
    let wrong_key_path = temp.path().join("device_nodeB.key");
    let km = KeyManager::load_or_generate(key_path.to_str().expect("key path"))
        .expect("software key manager");
    let wrong_km = KeyManager::load_or_generate(wrong_key_path.to_str().expect("wrong key path"))
        .expect("wrong software key manager");
    let (snapshot, baseline) = make_snapshot_and_baseline(&km);
    let pubkey = km.pubkey_der().expect("public key");
    let wrong_pubkey = wrong_km.pubkey_der().expect("wrong public key");

    baseline
        .save(baseline_path.to_str().expect("baseline path"))
        .expect("write baseline");
    let original_baseline = fs::read(&baseline_path).expect("read original baseline");
    let original_json: serde_json::Value =
        serde_json::from_slice(&original_baseline).expect("parse original baseline");

    assert!(original_json.pointer("/pcr_values/0").is_some());
    assert!(original_json.pointer("/composite_digest").is_some());
    assert!(original_json.pointer("/baseline_signature").is_some());
    assert!(original_json.pointer("/pcr0").is_none());
    assert!(original_json.pointer("/pcrs").is_none());
    assert!(baseline.verify_signature(&pubkey));
    assert!(!baseline.verify_signature(&wrong_pubkey));

    {
        let _restore = FileRestoreGuard::new(baseline_path.clone());
        let mut tampered = original_json.clone();
        let first_pcr = tampered
            .pointer_mut("/pcr_values/0")
            .expect("PCR field path /pcr_values/0 exists");
        let original = first_pcr
            .as_str()
            .expect("PCR value is a string")
            .to_string();
        *first_pcr = serde_json::Value::String(if original == "ff".repeat(32) {
            "00".repeat(32)
        } else {
            "ff".repeat(32)
        });
        fs::write(
            &baseline_path,
            serde_json::to_vec_pretty(&tampered).expect("serialize PCR tamper"),
        )
        .expect("write PCR tamper");

        let loaded = PcrBaseline::load(baseline_path.to_str().expect("baseline path"))
            .expect("load PCR-tampered baseline");
        assert!(loaded.verify_signature(&pubkey));
        assert_eq!(
            snapshot
                .compare_baseline(&loaded)
                .expect("compare PCR-tampered baseline"),
            vec![0]
        );
    }
    assert_eq!(
        fs::read(&baseline_path).expect("read restored baseline"),
        original_baseline
    );

    {
        let _restore = FileRestoreGuard::new(baseline_path.clone());
        let mut tampered = original_json;
        let composite = tampered
            .pointer_mut("/composite_digest")
            .expect("signed payload field path /composite_digest exists");
        let original = composite
            .as_str()
            .expect("composite digest is a string")
            .to_string();
        *composite = serde_json::Value::String(if original == "aa".repeat(32) {
            "bb".repeat(32)
        } else {
            "aa".repeat(32)
        });
        fs::write(
            &baseline_path,
            serde_json::to_vec_pretty(&tampered).expect("serialize digest tamper"),
        )
        .expect("write digest tamper");

        let loaded = PcrBaseline::load(baseline_path.to_str().expect("baseline path"))
            .expect("load digest-tampered baseline");
        let original_payload = canonical_baseline_signing_payload(
            &baseline.composite_digest,
            &baseline.created_at,
            &baseline.device_uid,
        )
        .expect("original canonical payload");
        let tampered_payload = canonical_baseline_signing_payload(
            &loaded.composite_digest,
            &loaded.created_at,
            &loaded.device_uid,
        )
        .expect("tampered canonical payload");
        assert_ne!(original_payload, tampered_payload);
        assert!(!loaded.verify_signature(&pubkey));
    }
    assert_eq!(
        fs::read(&baseline_path).expect("read restored baseline"),
        original_baseline
    );
}
