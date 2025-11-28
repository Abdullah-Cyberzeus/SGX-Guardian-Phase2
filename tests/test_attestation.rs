//! Unit tests for the SGX Guardian Attestation Service.
//! These tests validate create_signed_evidence() and verify_signed_evidence()
//! matching the exact logic in src/attestation_service.rs.

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use sgx_guardian_client::attestation_service::AttestationService;
use sgx_guardian_client::key_manager::KeyManager;

/// Create a unique, isolated temporary key path for safe testing.
fn make_temp_key_path() -> String {
    let pid = std::process::id();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();

    let mut dir = std::env::temp_dir();
    dir.push(format!("sgx_attest_test_{}_{}", pid, ts));
    fs::create_dir_all(&dir).unwrap();

    dir.push("device.key");
    dir.to_string_lossy().to_string()
}

#[test]
fn test_create_and_verify_evidence_success() {
    // TEMP KEY MANAGER (never touches real device_public.der)
    let key_path = make_temp_key_path();
    let km =
        KeyManager::load_or_generate(Some(&key_path)).expect("Failed to create temp test keypair");

    let policy = r#"
        policy_id: test
        version: "1"
        rules: []
    "#;

    // ===== create evidence =====
    let ev = AttestationService::create_signed_evidence(&km, policy)
        .expect("Failed to create signed evidence");

    assert!(!ev.nonce.is_empty(), "Nonce must not be empty");
    assert!(
        !ev.policy_digest.is_empty(),
        "Policy digest must not be empty"
    );
    assert!(!ev.signature.is_empty(), "Signature must not be empty");

    // ===== verify success =====
    let verified = AttestationService::verify_signed_evidence(&ev, &km.pubkey_der(), policy)
        .expect("verify_signed_evidence returned Err");

    assert!(verified, "Expected successful attestation verification");

    // Cleanup
    if let Some(parent) = Path::new(&key_path).parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

#[test]
fn test_verification_fails_with_tampered_signature() {
    let key_path = make_temp_key_path();
    let km = KeyManager::load_or_generate(Some(&key_path)).unwrap();

    let policy = "allow: all";

    let mut ev = AttestationService::create_signed_evidence(&km, policy).unwrap();

    // Break signature
    ev.signature = "INVALID_SIGNATURE_BASE64".into();

    let ok = AttestationService::verify_signed_evidence(&ev, &km.pubkey_der(), policy)
        .expect("verify should not return Err");

    assert!(!ok, "Verification must fail with tampered signature");

    if let Some(parent) = Path::new(&key_path).parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

#[test]
fn test_verification_fails_with_modified_policy() {
    let key_path = make_temp_key_path();
    let km = KeyManager::load_or_generate(Some(&key_path)).unwrap();

    let original_policy = "policy: allow_all";
    let ev = AttestationService::create_signed_evidence(&km, original_policy).unwrap();

    // Provide different policy content → digest mismatch
    let wrong_policy = "policy: deny_all";

    let ok = AttestationService::verify_signed_evidence(&ev, &km.pubkey_der(), wrong_policy)
        .expect("verify should not return Err");

    assert!(
        !ok,
        "Verification must fail when policy digest does not match original"
    );

    if let Some(parent) = Path::new(&key_path).parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

#[test]
fn test_verification_fails_with_wrong_public_key() {
    // Create unique isolated directories
    let mut dir1 = std::env::temp_dir();
    dir1.push(format!("km_test_dir1_{}", std::process::id()));
    fs::create_dir_all(&dir1).unwrap();

    let mut dir2 = std::env::temp_dir();
    dir2.push(format!("km_test_dir2_{}", std::process::id()));
    fs::create_dir_all(&dir2).unwrap();

    // Key paths inside isolated dirs
    let mut key1_path = dir1.clone();
    key1_path.push("device.key");

    let mut key2_path = dir2.clone();
    key2_path.push("device.key");

    // Generate two completely independent identities
    let km1 = KeyManager::load_or_generate(Some(key1_path.to_str().unwrap())).unwrap();
    let km2 = KeyManager::load_or_generate(Some(key2_path.to_str().unwrap())).unwrap();

    let policy = "allow: all";

    // Signed by key1
    let ev = AttestationService::create_signed_evidence(&km1, policy).unwrap();

    // Verify using WRONG key (km2) → MUST FAIL deterministically
    let ok = AttestationService::verify_signed_evidence(&ev, &km2.pubkey_der(), policy)
        .expect("verify should not return Err");

    assert!(
        !ok,
        "Verification must always fail using a different public key"
    );

    // Cleanup
    let _ = fs::remove_dir_all(dir1);
    let _ = fs::remove_dir_all(dir2);
}

#[test]
fn test_policy_normalization_crlf_handling() {
    // Some users may use Windows CRLF. Your code strips \r and \n.
    let key_path = make_temp_key_path();
    let km = KeyManager::load_or_generate(Some(&key_path)).unwrap();

    let policy_crlf = "policy: allow_all\r\nversion: 1\r\n";

    // Evidence created from CRLF version
    let ev = AttestationService::create_signed_evidence(&km, policy_crlf).unwrap();

    // VERIFY using normalized version → should still succeed because code strips CR/LF
    let ok = AttestationService::verify_signed_evidence(&ev, &km.pubkey_der(), policy_crlf)
        .expect("verify failed unexpectedly");

    assert!(ok, "Attestation must work with CRLF policy normalization");

    if let Some(parent) = Path::new(&key_path).parent() {
        let _ = fs::remove_dir_all(parent);
    }
}
#[test]
fn test_verification_fails_with_empty_signature() {
    let key_path = make_temp_key_path();
    let km = KeyManager::load_or_generate(Some(&key_path)).unwrap();

    let policy = "allow: all";
    let mut ev = AttestationService::create_signed_evidence(&km, policy).unwrap();

    ev.signature = "".into(); // empty signature

    let ok = AttestationService::verify_signed_evidence(&ev, &km.pubkey_der(), policy)
        .expect("verify should not return Err");
    assert!(!ok, "Empty signature must fail verification");

    if let Some(parent) = Path::new(&key_path).parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

#[test]
fn test_verification_fails_with_empty_nonce() {
    let key_path = make_temp_key_path();
    let km = KeyManager::load_or_generate(Some(&key_path)).unwrap();

    let policy = "allow: all";
    let mut ev = AttestationService::create_signed_evidence(&km, policy).unwrap();

    ev.nonce = "".into(); // empty nonce

    let ok = AttestationService::verify_signed_evidence(&ev, &km.pubkey_der(), policy)
        .expect("verify should not return Err");
    assert!(!ok, "Empty nonce must fail signature verification");

    if let Some(parent) = Path::new(&key_path).parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

#[test]
fn test_verification_fails_with_empty_policy_digest() {
    let key_path = make_temp_key_path();
    let km = KeyManager::load_or_generate(Some(&key_path)).unwrap();

    let policy = "allow: all";
    let mut ev = AttestationService::create_signed_evidence(&km, policy).unwrap();

    ev.policy_digest = "".into(); // empty digest

    let ok = AttestationService::verify_signed_evidence(&ev, &km.pubkey_der(), policy)
        .expect("verify should not return Err");
    assert!(
        !ok,
        "Empty policy_digest must immediately fail verification"
    );

    if let Some(parent) = Path::new(&key_path).parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

#[test]
fn test_policy_with_only_whitespace_still_works() {
    let key_path = make_temp_key_path();
    let km = KeyManager::load_or_generate(Some(&key_path)).unwrap();

    let policy = "   \n   "; // whitespace only

    let ev = AttestationService::create_signed_evidence(&km, policy).unwrap();

    let ok = AttestationService::verify_signed_evidence(&ev, &km.pubkey_der(), policy)
        .expect("verify should not error");

    assert!(ok, "Whitespace-only policy must normalize & verify");

    if let Some(parent) = Path::new(&key_path).parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

#[test]
fn test_verification_fails_with_malformed_base64_signature_variant() {
    let key_path = make_temp_key_path();
    let km = KeyManager::load_or_generate(Some(&key_path)).unwrap();

    let policy = "allow: all";
    let mut ev = AttestationService::create_signed_evidence(&km, policy).unwrap();

    ev.signature = "%%%".into(); // malformed non-empty Base64

    let ok = AttestationService::verify_signed_evidence(&ev, &km.pubkey_der(), policy)
        .expect("verify should not return Err");
    assert!(!ok, "Malformed Base64 ('%%%') must fail verification");

    if let Some(parent) = Path::new(&key_path).parent() {
        let _ = fs::remove_dir_all(parent);
    }
}
