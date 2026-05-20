use super::errors::DidError;
use super::method;
use super::persistence::{derivation_signing_bytes, DerivationProof, DidRecord};
use super::registry;
use super::{derive, Did};
use crate::key_manager::KeyManager;
use tempfile::TempDir;

#[test]
fn test_derive_is_deterministic() {
    let uid = b"se050-uid-fixture-18bytes";
    let pk = vec![0xAA; 91];
    let d1 = derive(uid, &pk);
    let d2 = derive(uid, &pk);
    assert_eq!(d1, d2);
}

#[test]
fn test_derive_changes_with_uid() {
    let pk = vec![0xAA; 91];
    let d1 = derive(b"uid-A", &pk);
    let d2 = derive(b"uid-B", &pk);
    assert_ne!(d1, d2);
}

#[test]
fn test_derive_changes_with_pubkey() {
    let uid = b"uid-fixed";
    let d1 = derive(uid, &[0xAA; 91]);
    let d2 = derive(uid, &[0xBB; 91]);
    assert_ne!(d1, d2);
}

#[test]
fn test_format_starts_with_prefix() {
    let d = derive(b"u", b"p");
    assert!(d.as_str().starts_with("did:guardian:"));
}

#[test]
fn test_msi_length_in_range() {
    let d = derive(b"u", b"p");
    let msi_len = d.msi().len();
    assert!(msi_len == 43 || msi_len == 44, "got {}", msi_len);
}

#[test]
fn test_parse_roundtrip() {
    let d = derive(b"u", b"p");
    let parsed = Did::parse(d.as_str()).unwrap();
    assert_eq!(d, parsed);
}

#[test]
fn test_parse_rejects_wrong_method() {
    let err = Did::parse("did:web:example.com").unwrap_err();
    match err {
        DidError::WrongMethod(m) => assert_eq!(m, "web"),
        _ => panic!("expected WrongMethod"),
    }
}

#[test]
fn test_parse_rejects_bad_msi() {
    let err = Did::parse("did:guardian:notbase58!!!").unwrap_err();
    assert!(matches!(
        err,
        DidError::Base58(_) | DidError::InvalidFormat(_)
    ));
}

#[test]
fn test_id_bytes_roundtrip() {
    let bytes = [0x42u8; 32];
    let d = Did::from_id_bytes(&bytes);
    assert_eq!(d.id_bytes(), bytes);
}

#[test]
fn test_persistence_save_load_roundtrip() {
    let td = TempDir::new().unwrap();
    let path = td.path().join("did.json");
    let path_s = path.to_str().unwrap();

    let rec = DidRecord {
        did: "did:guardian:11111111111111111111111111111111111111111111".into(),
        method: "guardian".into(),
        method_version: "1.0".into(),
        did_id_b58: "11111111111111111111111111111111111111111111".into(),
        did_id_hex: "00".repeat(32),
        created_at: "2026-04-26T10:00:00Z".into(),
        deactivated_at: None,
        derivation: DerivationProof {
            se050_uid: "fixture-uid".into(),
            se050_uid_source: "fallback".into(),
            dkp_v1_pubkey_sha256_b16: "ab".repeat(32),
            dkp_v1_pubkey_path: "/tmp/dkp_pub.der".into(),
            dkp_v1_pubkey_der_b64: None,
            dik_pubkey_sha256_b16: String::new(),
            dik_pubkey_der_b64: None,
        },
        current_dkp_version: 1,
        deriv_signature_b64: "Zm9v".into(),
    };

    rec.save(path_s).unwrap();
    let loaded = DidRecord::load(path_s).unwrap();
    assert_eq!(loaded.did, rec.did);
    assert!(loaded.is_active());
}

#[test]
fn test_atomic_write_does_not_leave_tmp_on_success() {
    let td = TempDir::new().unwrap();
    let path = td.path().join("did.json");
    let path_s = path.to_str().unwrap();

    let mut rec = DidRecord {
        did: "did:guardian:11111111111111111111111111111111111111111111".into(),
        method: "guardian".into(),
        method_version: "1.0".into(),
        did_id_b58: "1".repeat(44),
        did_id_hex: "00".repeat(32),
        created_at: "2026-04-26T10:00:00Z".into(),
        deactivated_at: None,
        derivation: DerivationProof {
            se050_uid: "u".into(),
            se050_uid_source: "fallback".into(),
            dkp_v1_pubkey_sha256_b16: "00".repeat(32),
            dkp_v1_pubkey_path: "/tmp/dkp.der".into(),
            dkp_v1_pubkey_der_b64: None,
            dik_pubkey_sha256_b16: String::new(),
            dik_pubkey_der_b64: None,
        },
        current_dkp_version: 1,
        deriv_signature_b64: "AAA=".into(),
    };
    rec.save(path_s).unwrap();
    rec.current_dkp_version = 2;
    rec.save(path_s).unwrap();

    let tmp_path = format!("{}.tmp", path.display());
    assert!(!std::path::Path::new(&tmp_path).exists());
}

#[test]
fn test_derivation_signing_bytes_stable() {
    let d = DerivationProof {
        se050_uid: "abc123".to_string(),
        se050_uid_source: "fallback".to_string(),
        dkp_v1_pubkey_sha256_b16: "11".repeat(32),
        dkp_v1_pubkey_path: "/tmp/dkp.der".to_string(),
        dkp_v1_pubkey_der_b64: None,
        dik_pubkey_sha256_b16: "22".repeat(32),
        dik_pubkey_der_b64: Some("AA==".to_string()),
    };
    let a = derivation_signing_bytes(&d);
    let b = derivation_signing_bytes(&d);
    assert_eq!(a, b);
    assert!(a.starts_with(b"sgx-guardian:did:guardian:v1:derivation:"));
}

#[test]
fn test_method_create_idempotent_and_deactivate() {
    let td = TempDir::new().unwrap();
    let key_path = td.path().join("device.key");
    let dkp_pub = td.path().join("dkp_pub.der");
    let did_path = td.path().join("did.json");

    let km = KeyManager::load_or_generate(key_path.to_str().unwrap()).unwrap();
    std::fs::write(&dkp_pub, km.pubkey_der().unwrap()).unwrap();

    let did1 = method::create_if_absent(
        "nodeT",
        &km,
        dkp_pub.to_str().unwrap(),
        did_path.to_str().unwrap(),
    )
    .unwrap();

    let did2 = method::create_if_absent(
        "nodeT",
        &km,
        dkp_pub.to_str().unwrap(),
        did_path.to_str().unwrap(),
    )
    .unwrap();
    assert_eq!(did1, did2);

    method::deactivate(did_path.to_str().unwrap(), "test").unwrap();
    let err = method::create_if_absent(
        "nodeT",
        &km,
        dkp_pub.to_str().unwrap(),
        did_path.to_str().unwrap(),
    )
    .unwrap_err();
    assert!(matches!(err, DidError::Deactivated(_)));
}

#[test]
fn test_method_uses_pinned_v1_pubkey_when_live_pubkey_changes() {
    let td = TempDir::new().unwrap();
    let key_path1 = td.path().join("device1.key");
    let key_path2 = td.path().join("device2.key");
    let dkp_pub = td.path().join("dkp_pub.der");
    let did_path = td.path().join("did.json");

    let km1 = KeyManager::load_or_generate(key_path1.to_str().unwrap()).unwrap();
    std::fs::write(&dkp_pub, km1.pubkey_der().unwrap()).unwrap();
    method::create_if_absent(
        "nodeT",
        &km1,
        dkp_pub.to_str().unwrap(),
        did_path.to_str().unwrap(),
    )
    .unwrap();

    let km2 = KeyManager::load_or_generate(key_path2.to_str().unwrap()).unwrap();
    std::fs::write(&dkp_pub, km2.pubkey_der().unwrap()).unwrap();
    let did2 = method::create_if_absent(
        "nodeT",
        &km2,
        dkp_pub.to_str().unwrap(),
        did_path.to_str().unwrap(),
    )
    .unwrap();
    let rec = DidRecord::load(did_path.to_str().unwrap()).unwrap();
    assert_eq!(did2.as_str(), rec.did);
}

#[test]
fn test_registry_upsert_get_list() {
    let td = TempDir::new().unwrap();
    let peers_dir = td.path().join("peers");
    let peers_dir_s = peers_dir.to_str().unwrap();
    let did = derive(b"uid", b"pub");

    let entry = registry::PeerDidEntry {
        did: did.as_str().to_string(),
        node_id: "nodeB".to_string(),
        current_pubkey_der_b64: "AA==".to_string(),
        current_dkp_version: 2,
        last_seen: "2026-04-26T10:00:00Z".to_string(),
        source: "test".to_string(),
    };

    registry::upsert(peers_dir_s, &entry).unwrap();
    let loaded = registry::get(peers_dir_s, &did).unwrap().unwrap();
    assert_eq!(loaded.node_id, "nodeB");

    let all = registry::list(peers_dir_s).unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].did, did.as_str());
}
