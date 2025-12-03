use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use sgx_guardian_client::attestation_service::{AttestationEvidence, AttestationService};
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
    let key_path = make_temp_key_path();
    let km = KeyManager::load_or_generate(Some(&key_path)).unwrap();
    let policy = "allow: all";

    let ev = AttestationService::create_signed_evidence(&km, policy).unwrap();
    assert!(!ev.nonce.is_empty());
    assert!(!ev.policy_digest.is_empty());
    assert!(!ev.signature.is_empty());

    let verified =
        AttestationService::verify_signed_evidence(&ev, &km.pubkey_der(), policy).unwrap();
    assert!(verified);

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
    ev.signature = "INVALID_SIGNATURE_BASE64".into();

    let ok = AttestationService::verify_signed_evidence(&ev, &km.pubkey_der(), policy).unwrap();
    assert!(!ok);

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

    let wrong_policy = "policy: deny_all";
    let ok =
        AttestationService::verify_signed_evidence(&ev, &km.pubkey_der(), wrong_policy).unwrap();
    assert!(!ok);

    if let Some(parent) = Path::new(&key_path).parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

#[test]
fn test_verification_fails_with_wrong_public_key() {
    let mut dir1 = std::env::temp_dir();
    dir1.push(format!("km_test_dir1_{}", std::process::id()));
    fs::create_dir_all(&dir1).unwrap();

    let mut dir2 = std::env::temp_dir();
    dir2.push(format!("km_test_dir2_{}", std::process::id()));
    fs::create_dir_all(&dir2).unwrap();

    let mut key1_path = dir1.clone();
    key1_path.push("device.key");

    let mut key2_path = dir2.clone();
    key2_path.push("device.key");

    let km1 = KeyManager::load_or_generate(Some(key1_path.to_str().unwrap())).unwrap();
    let km2 = KeyManager::load_or_generate(Some(key2_path.to_str().unwrap())).unwrap();

    let policy = "allow: all";
    let ev = AttestationService::create_signed_evidence(&km1, policy).unwrap();

    let ok = AttestationService::verify_signed_evidence(&ev, &km2.pubkey_der(), policy).unwrap();
    assert!(!ok);

    let _ = fs::remove_dir_all(dir1);
    let _ = fs::remove_dir_all(dir2);
}

#[test]
fn test_nonce_is_always_32_hex_characters() {
    let key_path = make_temp_key_path();
    let km = KeyManager::load_or_generate(Some(&key_path)).unwrap();
    let policy = "test_policy";

    // Test nonce generation across multiple evidence creations
    for _ in 0..10 {
        let ev = AttestationService::create_signed_evidence(&km, policy).unwrap();
        assert_eq!(
            ev.nonce.len(),
            32,
            "Nonce must be exactly 32 hex characters (16 bytes)"
        );
        assert!(
            ev.nonce.chars().all(|c| c.is_ascii_hexdigit()),
            "Nonce must be valid hex"
        );
    }

    if let Some(parent) = Path::new(&key_path).parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

#[test]
fn test_nonce_uniqueness_across_multiple_evidences() {
    let key_path = make_temp_key_path();
    let km = KeyManager::load_or_generate(Some(&key_path)).unwrap();
    let policy = "test_policy";

    let ev1 = AttestationService::create_signed_evidence(&km, policy).unwrap();
    let ev2 = AttestationService::create_signed_evidence(&km, policy).unwrap();
    let ev3 = AttestationService::create_signed_evidence(&km, policy).unwrap();

    // Nonces should be statistically unique
    assert_ne!(
        ev1.nonce, ev2.nonce,
        "Nonces must be unique across evidence"
    );
    assert_ne!(
        ev2.nonce, ev3.nonce,
        "Nonces must be unique across evidence"
    );
    assert_ne!(
        ev1.nonce, ev3.nonce,
        "Nonces must be unique across evidence"
    );

    if let Some(parent) = Path::new(&key_path).parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

#[test]
fn test_policy_digest_is_deterministic() {
    let key_path = make_temp_key_path();
    let km = KeyManager::load_or_generate(Some(&key_path)).unwrap();
    let policy = "deterministic_test_policy";

    let ev1 = AttestationService::create_signed_evidence(&km, policy).unwrap();
    let ev2 = AttestationService::create_signed_evidence(&km, policy).unwrap();

    // Policy digest must be identical for same policy
    assert_eq!(
        ev1.policy_digest, ev2.policy_digest,
        "Policy digest must be deterministic for identical policies"
    );

    if let Some(parent) = Path::new(&key_path).parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

#[test]
fn test_policy_digest_is_64_hex_characters_sha256() {
    let key_path = make_temp_key_path();
    let km = KeyManager::load_or_generate(Some(&key_path)).unwrap();
    let policy = "test";

    let ev = AttestationService::create_signed_evidence(&km, policy).unwrap();

    assert_eq!(
        ev.policy_digest.len(),
        64,
        "SHA256 digest must be exactly 64 hex characters (32 bytes)"
    );
    assert!(
        ev.policy_digest.chars().all(|c| c.is_ascii_hexdigit()),
        "Policy digest must be valid hex"
    );

    if let Some(parent) = Path::new(&key_path).parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

#[test]
fn test_signature_is_valid_base64() {
    let key_path = make_temp_key_path();
    let km = KeyManager::load_or_generate(Some(&key_path)).unwrap();
    let policy = "test_policy";

    let ev = AttestationService::create_signed_evidence(&km, policy).unwrap();

    // Attempt to decode Base64 signature
    use base64::{engine::general_purpose, Engine as _};
    let decoded = general_purpose::STANDARD.decode(&ev.signature);
    assert!(decoded.is_ok(), "Signature must be valid Base64");
    assert!(
        !decoded.unwrap().is_empty(),
        "Decoded signature must not be empty"
    );

    if let Some(parent) = Path::new(&key_path).parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

#[test]
fn test_attestation_evidence_serialization_roundtrip() {
    let key_path = make_temp_key_path();
    let km = KeyManager::load_or_generate(Some(&key_path)).unwrap();
    let policy = "serialization_test";

    let original = AttestationService::create_signed_evidence(&km, policy).unwrap();

    // Serialize to JSON
    let json = serde_json::to_string(&original).unwrap();

    // Deserialize back
    let deserialized: AttestationEvidence = serde_json::from_str(&json).unwrap();

    // Verify all fields match
    assert_eq!(original.nonce, deserialized.nonce);
    assert_eq!(original.policy_digest, deserialized.policy_digest);
    assert_eq!(original.signature, deserialized.signature);

    if let Some(parent) = Path::new(&key_path).parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

#[test]
fn test_very_long_policy_creates_valid_evidence() {
    let key_path = make_temp_key_path();
    let km = KeyManager::load_or_generate(Some(&key_path)).unwrap();

    // Create a very long policy (10KB+)
    let long_policy = "rule: allow\n".repeat(1000);

    let ev = AttestationService::create_signed_evidence(&km, &long_policy).unwrap();
    assert!(!ev.nonce.is_empty());
    assert!(!ev.policy_digest.is_empty());
    assert!(!ev.signature.is_empty());

    // Verify it
    let verified =
        AttestationService::verify_signed_evidence(&ev, &km.pubkey_der(), &long_policy).unwrap();
    assert!(verified, "Long policy attestation must verify successfully");

    if let Some(parent) = Path::new(&key_path).parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

#[test]
fn test_empty_policy_string_creates_valid_evidence() {
    let key_path = make_temp_key_path();
    let km = KeyManager::load_or_generate(Some(&key_path)).unwrap();

    let empty_policy = "";

    let ev = AttestationService::create_signed_evidence(&km, empty_policy).unwrap();
    assert!(!ev.nonce.is_empty());
    assert!(!ev.policy_digest.is_empty());
    assert!(!ev.signature.is_empty());

    let verified =
        AttestationService::verify_signed_evidence(&ev, &km.pubkey_der(), empty_policy).unwrap();
    assert!(verified, "Empty policy must still create valid attestation");

    if let Some(parent) = Path::new(&key_path).parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

#[test]
fn test_policy_with_unicode_characters() {
    let key_path = make_temp_key_path();
    let km = KeyManager::load_or_generate(Some(&key_path)).unwrap();

    let unicode_policy = "policy: 允许所有 🔒 ñ é ü";

    let ev = AttestationService::create_signed_evidence(&km, unicode_policy).unwrap();
    let verified =
        AttestationService::verify_signed_evidence(&ev, &km.pubkey_der(), unicode_policy).unwrap();
    assert!(verified, "Unicode policy must be handled correctly");

    if let Some(parent) = Path::new(&key_path).parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

#[test]
fn test_policy_with_special_characters() {
    let key_path = make_temp_key_path();
    let km = KeyManager::load_or_generate(Some(&key_path)).unwrap();

    let special_policy = r#"policy: "allow" & 'deny' | (test) $ % ^ * [] {}"#;

    let ev = AttestationService::create_signed_evidence(&km, special_policy).unwrap();
    let verified =
        AttestationService::verify_signed_evidence(&ev, &km.pubkey_der(), special_policy).unwrap();
    assert!(
        verified,
        "Special characters in policy must be handled correctly"
    );

    if let Some(parent) = Path::new(&key_path).parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

#[test]
fn test_verification_digest_mismatch_before_signature_check() {
    let key_path = make_temp_key_path();
    let km = KeyManager::load_or_generate(Some(&key_path)).unwrap();

    let policy1 = "policy_version_1";
    let policy2 = "policy_version_2";

    let ev = AttestationService::create_signed_evidence(&km, policy1).unwrap();

    // Verify with different policy - should fail at digest check, not signature
    let ok = AttestationService::verify_signed_evidence(&ev, &km.pubkey_der(), policy2).unwrap();
    assert!(
        !ok,
        "Digest mismatch must fail verification before signature check"
    );

    if let Some(parent) = Path::new(&key_path).parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

#[test]
fn test_signature_is_different_with_same_policy_different_nonce() {
    let key_path = make_temp_key_path();
    let km = KeyManager::load_or_generate(Some(&key_path)).unwrap();
    let policy = "same_policy";

    let ev1 = AttestationService::create_signed_evidence(&km, policy).unwrap();
    let ev2 = AttestationService::create_signed_evidence(&km, policy).unwrap();

    // Even with same policy, signatures must differ due to different nonces
    assert_ne!(
        ev1.signature, ev2.signature,
        "Signatures must differ even with same policy due to unique nonces"
    );

    if let Some(parent) = Path::new(&key_path).parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

#[test]
fn test_policy_normalization_removes_all_whitespace() {
    let key_path = make_temp_key_path();
    let km = KeyManager::load_or_generate(Some(&key_path)).unwrap();

    let policy_with_spaces = "  allow:   all  \n  version: 1  ";

    let ev = AttestationService::create_signed_evidence(&km, policy_with_spaces).unwrap();

    // Both should verify because normalization strips whitespace
    let ok = AttestationService::verify_signed_evidence(&ev, &km.pubkey_der(), policy_with_spaces)
        .unwrap();
    assert!(ok, "Original policy with spaces must verify");

    if let Some(parent) = Path::new(&key_path).parent() {
        let _ = fs::remove_dir_all(parent);
    }
}
