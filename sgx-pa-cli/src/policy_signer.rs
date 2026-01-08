// src/policy_signer.rs
use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use sha2::{Digest, Sha256};
use std::fs;

#[derive(Debug, Clone)]
pub struct SignedPolicy {
    pub original_policy: String,
    pub digest_hex: String,
    pub signature_b64: String,
    pub pubkey_b64: String,
}

/// Deterministic SHA-256 digest for YAML.
/// Ensures stable digest despite whitespace differences.
pub fn compute_policy_digest(yaml: &str) -> String {
    let normalized = yaml.trim().replace("\r\n", "\n");
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    let digest = hasher.finalize();

    hex::encode(digest)
}

/// Load PKCS8 ECDSA P-256 private key
fn load_admin_key(path: &str) -> Result<EcdsaKeyPair> {
    let key_bytes = fs::read(path)
        .map_err(|e| anyhow::anyhow!("Failed to read admin private key {}: {}", path, e))?;

    let rng = SystemRandom::new();

    let keypair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &key_bytes, &rng)
        .map_err(|_| {
            anyhow::anyhow!("Invalid admin private key format (must be PKCS8 ECDSA P-256)")
        })?;

    Ok(keypair)
}

/// Signs a policy's SHA-256 digest using ECDSA P-256
pub fn sign_policy_internal(yaml_path: &str, admin_key_path: &str) -> Result<SignedPolicy> {
    // Load YAML
    let yaml = fs::read_to_string(yaml_path)
        .map_err(|e| anyhow::anyhow!("Failed to read policy YAML: {}", e))?;

    // Compute digest
    let digest_hex = compute_policy_digest(&yaml);
    let digest_bytes = hex::decode(&digest_hex)
        .map_err(|e| anyhow::anyhow!("Failed to decode digest hex: {}", e))?;

    // Load signing key
    let keypair = load_admin_key(admin_key_path)?;

    // RNG for ECDSA
    let rng = SystemRandom::new();

    // Sign digest bytes
    let signature = keypair
        .sign(&rng, &digest_bytes)
        .map_err(|_| anyhow::anyhow!("Failed to sign digest"))?;

    let signature_b64 = general_purpose::STANDARD.encode(signature.as_ref());

    // Encode public key
    let pubkey_der = keypair.public_key().as_ref();
    let pubkey_b64 = general_purpose::STANDARD.encode(pubkey_der);

    // Final output
    Ok(SignedPolicy {
        original_policy: yaml,
        digest_hex,
        signature_b64,
        pubkey_b64,
    })
}
