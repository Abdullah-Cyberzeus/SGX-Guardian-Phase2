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

#[cfg(test)]
mod tests {
    use super::{compute_policy_digest, sign_policy_internal};
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    #[test]
    fn compute_policy_digest_is_stable_across_whitespace_and_line_endings() {
        let a = compute_policy_digest("rules: []\n");
        let b = compute_policy_digest("  rules: []  \r\n");
        assert_eq!(a, b);
        assert_ne!(a, compute_policy_digest("rules: [1]"));
    }

    #[test]
    fn sign_policy_internal_signs_with_a_real_pkcs8_key() {
        let temp = tempfile::tempdir().unwrap();
        let yaml_path = temp.path().join("policy.yaml");
        std::fs::write(&yaml_path, "rules: []\n").unwrap();

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key_path = temp.path().join("admin.key");
        std::fs::write(&key_path, pkcs8.as_ref()).unwrap();

        let signed = sign_policy_internal(yaml_path.to_str().unwrap(), key_path.to_str().unwrap())
            .expect("sign_policy_internal should succeed with a real key");

        assert_eq!(signed.original_policy, "rules: []\n");
        assert_eq!(signed.digest_hex, compute_policy_digest("rules: []\n"));
        assert!(!signed.signature_b64.is_empty());
        assert!(!signed.pubkey_b64.is_empty());
    }

    #[test]
    fn sign_policy_internal_reports_missing_yaml() {
        let temp = tempfile::tempdir().unwrap();
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key_path = temp.path().join("admin.key");
        std::fs::write(&key_path, pkcs8.as_ref()).unwrap();

        let err = sign_policy_internal("/nonexistent/policy.yaml", key_path.to_str().unwrap())
            .expect_err("missing yaml");
        assert!(err.to_string().contains("Failed to read policy YAML"));
    }

    #[test]
    fn sign_policy_internal_reports_missing_admin_key() {
        let temp = tempfile::tempdir().unwrap();
        let yaml_path = temp.path().join("policy.yaml");
        std::fs::write(&yaml_path, "rules: []\n").unwrap();

        let err = sign_policy_internal(yaml_path.to_str().unwrap(), "/nonexistent/admin.key")
            .expect_err("missing key");
        assert!(err.to_string().contains("Failed to read admin private key"));
    }

    #[test]
    fn sign_policy_internal_rejects_a_malformed_admin_key() {
        let temp = tempfile::tempdir().unwrap();
        let yaml_path = temp.path().join("policy.yaml");
        std::fs::write(&yaml_path, "rules: []\n").unwrap();
        let key_path = temp.path().join("admin.key");
        std::fs::write(&key_path, b"not a real pkcs8 key").unwrap();

        let err = sign_policy_internal(yaml_path.to_str().unwrap(), key_path.to_str().unwrap())
            .expect_err("malformed key");
        assert!(err.to_string().contains("Invalid admin private key format"));
    }
}
