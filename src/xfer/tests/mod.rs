use crate::did::doc_persistence;
use crate::did::doc_sign;
use crate::did::document::{DidDocument, DocBuildInput};
use crate::did::{Did, Resolver};
use crate::key_manager::KeyManager;
use crate::xfer::manifest::{inspect_file_blocking, FileManifest, FileMaterial};
use crate::xfer::store;
use tempfile::TempDir;

struct EnvRestore {
    key: &'static str,
    previous: Option<String>,
}

impl EnvRestore {
    fn set(key: &'static str, value: &str) -> Self {
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

fn signed_peer_doc(temp: &TempDir) -> (String, KeyManager, DidDocument) {
    let key_path = temp.path().join("device_nodeB.key");
    let km = KeyManager::load_or_generate(key_path.to_str().expect("key path")).expect("key");
    let pubkey = km.pubkey_der().expect("pubkey");
    let did = Did::from_id_bytes(&[22u8; 32]).to_string();
    let mut doc = DidDocument::build(DocBuildInput {
        did: &did,
        node_name: Some("nodeB"),
        current_dkp_version: 1,
        current_dkp_pubkey_der: &pubkey,
        overlay_ip_cidr: Some("192.168.100.22/24"),
        attestation_bind: None,
        cert_bootstrap_bind: None,
        revoked: vec![],
        previous_version_id: 0,
        created_at: None,
        status: Some("active".into()),
    })
    .expect("build doc");
    let vm_ref = doc.verification_method.first().expect("vm").id.clone();
    doc_sign::sign_in_place(&mut doc, &km, &vm_ref).expect("sign doc");
    (did, km, doc)
}

#[tokio::test]
async fn manifest_round_trip_and_tamper_rejected() {
    let _env_lock = crate::xfer::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let peers_dir = temp.path().join("peers");
    let _peers_env = EnvRestore::set(
        crate::did::doc_persistence::PEERS_DOC_DIR_ENV,
        peers_dir.to_str().expect("peers dir"),
    );
    let (sender_did, km, doc) = signed_peer_doc(&temp);
    doc_persistence::save_peer(&doc).expect("save peer doc");

    let material = FileMaterial {
        filename: "payload.bin".into(),
        size: 1024,
        chunk_digests: vec!["aa".repeat(32), "bb".repeat(32)],
        file_sha256: "cc".repeat(32),
    };
    let manifest = FileManifest::build_signed(
        "guardian-circle-alpha",
        &sender_did,
        material,
        512,
        &km,
        &format!("{}#dkp-v1", sender_did),
    )
    .expect("manifest");
    let json = serde_json::to_string(&manifest).expect("json");
    let decoded: FileManifest = serde_json::from_str(&json).expect("decode");
    crate::xfer::verify::verify_manifest(
        &decoded,
        &Resolver::new(Default::default()),
        &sender_did,
        "guardian-circle-alpha",
    )
    .await
    .expect("verify");

    let mut tampered = decoded.clone();
    tampered.filename = "tampered.bin".into();
    let err = crate::xfer::verify::verify_manifest(
        &tampered,
        &Resolver::new(Default::default()),
        &sender_did,
        "guardian-circle-alpha",
    )
    .await
    .expect_err("tamper rejected");
    assert!(err.to_string().contains("invalid transfer proof"));
}

#[test]
fn inspect_file_material_splits_chunks() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("fixture.bin");
    std::fs::write(&path, vec![7u8; 1000]).expect("write");
    let material = inspect_file_blocking(path, 256, 10_000).expect("material");
    assert_eq!(material.size, 1000);
    assert_eq!(material.chunk_digests.len(), 4);
    assert_eq!(material.filename, "fixture.bin");
}

#[tokio::test]
async fn receiver_state_reloads_recorded_chunks() {
    let _env_lock = crate::xfer::lock_test_env().await;
    let temp = TempDir::new().expect("tempdir");
    let _base_env = EnvRestore::set(
        crate::xfer::persistence::XFER_BASE_ENV,
        temp.path().to_str().expect("xfer base"),
    );
    let manifest = FileManifest {
        transfer_id: "xfer-test".into(),
        circle_id: "guardian-circle-alpha".into(),
        sender_did: Did::from_id_bytes(&[33u8; 32]).to_string(),
        filename: "state.bin".into(),
        size: 10,
        chunk_bytes: 1,
        chunk_count: 10,
        chunk_digests: vec!["00".repeat(32); 10],
        file_sha256: "11".repeat(32),
        created_at: chrono::Utc::now().to_rfc3339(),
        proof: Default::default(),
    };

    store::prepare_receiver(&manifest).await.expect("prepare");
    for index in [0_u32, 2, 4, 6, 8] {
        store::record_chunk(&manifest, index)
            .await
            .expect("record chunk");
    }

    let reloaded = store::load_receiver_state(&manifest.circle_id, &manifest.transfer_id)
        .await
        .expect("load")
        .expect("state exists");
    assert_eq!(reloaded.have_chunks(), vec![0, 2, 4, 6, 8]);
}
