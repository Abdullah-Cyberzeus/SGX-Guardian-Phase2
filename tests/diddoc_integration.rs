use sgx_guardian_client::did::{doc_sign, document::*};
use sgx_guardian_client::key_manager::KeyManager;
use tempfile::TempDir;

fn make_doc_for_test(did: &str, node_name: &str, ip: &str) -> (KeyManager, DidDocument) {
    let td = TempDir::new().unwrap();
    let key_path = td.path().join("dev.key");
    let km = KeyManager::load_or_generate(key_path.to_str().unwrap()).unwrap();
    let der = km.pubkey_der().unwrap();
    let mut doc = DidDocument::build(DocBuildInput {
        did,
        node_name: Some(node_name),
        current_dkp_version: 1,
        current_dkp_pubkey_der: &der,
        overlay_ip_cidr: Some(ip),
        attestation_bind: Some((ip.split('/').next().unwrap_or("192.168.100.7"), 50057)),
        cert_bootstrap_bind: None,
        revoked: vec![],
        previous_version_id: 0,
        created_at: None,
        status: Some("active".to_string()),
    })
    .unwrap();
    let vm_ref = doc.verification_method[0].id.clone();
    doc_sign::sign_in_place(&mut doc, &km, &vm_ref).unwrap();
    (km, doc)
}

#[test]
fn test_key_rotation_moves_old_vm_to_revoked() {
    let (km1, doc_v1) = make_doc_for_test(
        "did:guardian:11111111111111111111111111111111111111111111",
        "nodeT",
        "192.168.100.7/24",
    );
    let _der1 = km1.pubkey_der().unwrap();
    assert_eq!(doc_v1.verification_method.len(), 1);
    assert_eq!(doc_v1.sgx_revoked_vm.len(), 0);
    assert_eq!(doc_v1.sgx_version_id, 1);

    let td = TempDir::new().unwrap();
    let key_path2 = td.path().join("dev2.key");
    let km2 = KeyManager::load_or_generate(key_path2.to_str().unwrap()).unwrap();
    let der2 = km2.pubkey_der().unwrap();

    let revoked = vec![RevokedVm {
        id: doc_v1.verification_method[0].id.clone(),
        revoked_at: chrono::Utc::now().to_rfc3339(),
        reason: "rotation".into(),
    }];
    let mut doc_v2 = DidDocument::build(DocBuildInput {
        did: &doc_v1.id,
        node_name: Some("nodeT"),
        current_dkp_version: 2,
        current_dkp_pubkey_der: &der2,
        overlay_ip_cidr: Some("192.168.100.7/24"),
        attestation_bind: Some(("192.168.100.7", 50057)),
        cert_bootstrap_bind: None,
        revoked,
        previous_version_id: 1,
        created_at: Some(doc_v1.sgx_created.clone()),
        status: Some("active".to_string()),
    })
    .unwrap();
    let vm_ref = doc_v2.verification_method[0].id.clone();
    doc_sign::sign_in_place(&mut doc_v2, &km2, &vm_ref).unwrap();

    assert_eq!(doc_v2.id, doc_v1.id);
    assert_eq!(doc_v2.verification_method.len(), 1);
    assert_eq!(doc_v2.sgx_revoked_vm.len(), 1);
    assert_eq!(doc_v2.sgx_version_id, 2);
    doc_sign::verify(&doc_v2).unwrap();
}

#[test]
fn test_aggregate_serde_roundtrip() {
    let (_, doc1) = make_doc_for_test(
        "did:guardian:11111111111111111111111111111111111111111111",
        "nodeT",
        "192.168.100.7/24",
    );
    let (_, doc2) = make_doc_for_test(
        "did:guardian:22222222222222222222222222222222222222222222",
        "nodeU",
        "192.168.100.8/24",
    );

    let json = serde_json::to_string_pretty(&vec![doc1.clone(), doc2.clone()]).unwrap();
    let loaded: Vec<DidDocument> = serde_json::from_str(&json).unwrap();
    assert_eq!(loaded.len(), 2);
    doc_sign::verify(&loaded[0]).unwrap();
    doc_sign::verify(&loaded[1]).unwrap();
}
