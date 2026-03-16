use base64::{engine::general_purpose, Engine as _};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::SecretKey;
use sgx_guardian_client::attestation_service::{AttestationEvidence, AttestationService};
use sha2::{Digest, Sha256};

fn fixed_signing_key() -> SigningKey {
    let secret = SecretKey::from_slice(&[42u8; 32]).expect("valid deterministic secret key");
    SigningKey::from(secret)
}

fn normalize_policy(policy: &str) -> String {
    policy
        .replace("\r", "")
        .replace("\n", "")
        .trim()
        .to_string()
}

fn policy_digest_hex(policy: &str) -> String {
    let digest = Sha256::digest(normalize_policy(policy).as_bytes());
    hex::encode(digest)
}

fn spki_from_raw_p256_pubkey(raw_pubkey: &[u8]) -> Vec<u8> {
    // SE050-style SubjectPublicKeyInfo prefix for ECDSA P-256 public key.
    // Total length should be 91 bytes after appending 65-byte raw key.
    let mut spki = vec![
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08,
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    spki.extend_from_slice(raw_pubkey);
    spki
}

fn make_evidence(policy: &str, nonce: &str, use_spki_der: bool) -> AttestationEvidence {
    let signing_key = fixed_signing_key();
    let verify_key = signing_key.verifying_key();
    let raw_pubkey = verify_key.to_encoded_point(false).as_bytes().to_vec();
    assert_eq!(raw_pubkey.len(), 65);

    let digest = policy_digest_hex(policy);
    let msg = format!("{}{}", nonce, digest);

    // Current attestation verification expects ASN.1 DER ECDSA signature.
    let signature: Signature = signing_key.sign(msg.as_bytes());
    let sig_der = signature.to_der();

    let pubkey_bytes = if use_spki_der {
        let spki = spki_from_raw_p256_pubkey(&raw_pubkey);
        assert_eq!(spki.len(), 91);
        spki
    } else {
        raw_pubkey
    };

    AttestationEvidence {
        nonce: nonce.to_string(),
        policy_digest: digest,
        signature: general_purpose::STANDARD.encode(sig_der.as_bytes()),
        pubkey_der_b64: general_purpose::STANDARD.encode(pubkey_bytes),
    }
}

#[test]
fn test_verify_success_with_raw_public_key() {
    let policy = "allow: all";
    let nonce = "00112233445566778899aabbccddeeff";
    let ev = make_evidence(policy, nonce, false);

    let verified = AttestationService::verify_signed_evidence(&ev, policy).unwrap();
    assert!(verified);
}

#[test]
fn test_verify_success_with_spki_der_public_key() {
    let policy = "policy: allow_all";
    let nonce = "ffeeddccbbaa99887766554433221100";
    let ev = make_evidence(policy, nonce, true);

    let verified = AttestationService::verify_signed_evidence(&ev, policy).unwrap();
    assert!(verified);
}

#[test]
fn test_verification_fails_with_tampered_signature() {
    let policy = "policy: allow_all";
    let nonce = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut ev = make_evidence(policy, nonce, true);

    let mut sig = general_purpose::STANDARD.decode(&ev.signature).unwrap();
    sig[0] ^= 0x01;
    ev.signature = general_purpose::STANDARD.encode(sig);

    let ok = AttestationService::verify_signed_evidence(&ev, policy).unwrap();
    assert!(!ok);
}

#[test]
fn test_verification_fails_with_invalid_signature_base64() {
    let policy = "policy: allow_all";
    let nonce = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let mut ev = make_evidence(policy, nonce, true);
    ev.signature = "NOT_BASE64!!!".to_string();

    let ok = AttestationService::verify_signed_evidence(&ev, policy).unwrap();
    assert!(!ok);
}

#[test]
fn test_verification_fails_with_modified_policy() {
    let nonce = "cccccccccccccccccccccccccccccccc";
    let ev = make_evidence("policy: allow_all", nonce, true);

    let ok = AttestationService::verify_signed_evidence(&ev, "policy: deny_all").unwrap();
    assert!(!ok);
}

#[test]
fn test_policy_digest_has_sha256_format() {
    let policy = "allow: all";
    let nonce = "dddddddddddddddddddddddddddddddd";
    let ev = make_evidence(policy, nonce, true);

    assert_eq!(ev.policy_digest.len(), 64);
    assert!(ev.policy_digest.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_signature_is_valid_base64_and_non_empty() {
    let policy = "allow: all";
    let nonce = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    let ev = make_evidence(policy, nonce, true);

    let decoded = general_purpose::STANDARD.decode(&ev.signature).unwrap();
    assert!(!decoded.is_empty());
}

#[test]
fn test_attestation_evidence_serialization_roundtrip() {
    let policy = "serialization_test";
    let nonce = "ffffffffffffffffffffffffffffffff";
    let original = make_evidence(policy, nonce, true);

    let json = serde_json::to_string(&original).unwrap();
    let deserialized: AttestationEvidence = serde_json::from_str(&json).unwrap();

    assert_eq!(original.nonce, deserialized.nonce);
    assert_eq!(original.policy_digest, deserialized.policy_digest);
    assert_eq!(original.signature, deserialized.signature);
    assert_eq!(original.pubkey_der_b64, deserialized.pubkey_der_b64);
}

#[test]
fn test_policy_normalization_works_for_verification() {
    let pretty_policy = "  allow: all  \n  version: 1  ";
    let nonce = "11111111111111111111111111111111";
    // Build evidence with exactly the same normalization rules used by verifier.
    let ev = make_evidence(pretty_policy, nonce, true);

    let ok = AttestationService::verify_signed_evidence(&ev, pretty_policy).unwrap();
    assert!(ok);
}

#[test]
fn test_long_policy_verification_success() {
    let long_policy = "rule: allow\n".repeat(1000);
    let nonce = "22222222222222222222222222222222";
    let ev = make_evidence(&long_policy, nonce, true);

    let verified = AttestationService::verify_signed_evidence(&ev, &long_policy).unwrap();
    assert!(verified);
}
