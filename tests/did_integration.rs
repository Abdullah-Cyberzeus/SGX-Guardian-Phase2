//! Integration tests for DID lifecycle.

use sgx_guardian_client::did::{self, method::create_if_absent};
use sgx_guardian_client::key_manager::KeyManager;
use tempfile::TempDir;

#[test]
fn test_create_then_load_then_deactivate() {
    let td = TempDir::new().unwrap();
    let key_path = td.path().join("device.key");
    let dkp_pub = td.path().join("dkp_pub.der");
    let did_path = td.path().join("did.json");

    let km = KeyManager::load_or_generate(key_path.to_str().unwrap()).unwrap();
    std::fs::write(&dkp_pub, km.pubkey_der().unwrap()).unwrap();

    let did1 = create_if_absent(
        "nodeT",
        &km,
        dkp_pub.to_str().unwrap(),
        did_path.to_str().unwrap(),
    )
    .unwrap();
    assert!(did1.as_str().starts_with("did:guardian:"));

    let did2 = create_if_absent(
        "nodeT",
        &km,
        dkp_pub.to_str().unwrap(),
        did_path.to_str().unwrap(),
    )
    .unwrap();
    assert_eq!(did1, did2);

    did::method::deactivate(did_path.to_str().unwrap(), "test").unwrap();
    let rec = did::DidRecord::load(did_path.to_str().unwrap()).unwrap();
    assert!(!rec.is_active());

    let err = did::method::deactivate(did_path.to_str().unwrap(), "test").unwrap_err();
    assert!(matches!(err, did::DidError::Deactivated(_)));
}

#[test]
fn test_derivation_mismatch_detected() {
    let td = TempDir::new().unwrap();
    let key_path1 = td.path().join("device1.key");
    let key_path2 = td.path().join("device2.key");
    let dkp_pub = td.path().join("dkp_pub.der");
    let did_path = td.path().join("did.json");

    let km1 = KeyManager::load_or_generate(key_path1.to_str().unwrap()).unwrap();
    std::fs::write(&dkp_pub, km1.pubkey_der().unwrap()).unwrap();
    create_if_absent(
        "nodeT",
        &km1,
        dkp_pub.to_str().unwrap(),
        did_path.to_str().unwrap(),
    )
    .unwrap();

    let km2 = KeyManager::load_or_generate(key_path2.to_str().unwrap()).unwrap();
    std::fs::write(&dkp_pub, km2.pubkey_der().unwrap()).unwrap();

    let err = create_if_absent(
        "nodeT",
        &km2,
        dkp_pub.to_str().unwrap(),
        did_path.to_str().unwrap(),
    )
    .unwrap_err();
    assert!(matches!(err, did::DidError::DerivationMismatch));
}
