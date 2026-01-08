#![allow(dead_code)]

use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use anyhow::{anyhow, Result};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use std::{fs, path::Path};
use tracing::{info, warn};

/// Default key path
const DEFAULT_KEY_PATH: &str = "sgx-agent/device.key";

/// Manages the SG-X node identity keypair including generation,
/// secure persistence, loading from disk, and providing signing/public
/// key access for attestation workflows.
pub struct KeyManager {
    keypair: EcdsaKeyPair,
    key_path: String,
}
impl KeyManager {
    /// Loads the identity keypair from disk if it exists, otherwise generates
    /// a new ECDSA P-256 keypair and saves it to the configured path.
    /// Returns a fully initialized `KeyManager` instance.
    pub fn load_or_generate(custom_path: Option<&str>) -> Result<Self> {
        let rng = SystemRandom::new();
        let key_path_str = custom_path.unwrap_or(DEFAULT_KEY_PATH);
        let key_path = Path::new(key_path_str);
        fs::create_dir_all("sgx-agent").ok();
        // Read existing or generate new keypair
        let pkcs8_bytes = if key_path.exists() {
            info!("Loading existing identity key: {}", key_path.display());
            log_audit(
                "system",
                AuditCategory::Identity,
                AuditSeverity::Info,
                AuditAction::Loaded,
                "Existing node identity key loaded from disk",
            );
            fs::read(key_path)?
        } else {
            warn!("⚠️ Identity key not found, generating new one...");

            log_audit(
                "system",
                AuditCategory::Identity,
                AuditSeverity::Critical,
                AuditAction::Created,
                "New node identity key generated",
            );
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .map_err(|_| anyhow!("Failed to generate keypair"))?;
            fs::create_dir_all(
                key_path
                    .parent()
                    .ok_or_else(|| anyhow!("Invalid key path"))?,
            )?;
            fs::write(key_path, pkcs8.as_ref())?;
            info!("New identity key generated at {}", key_path.display());
            pkcs8.as_ref().to_vec()
        };
        // Load keypair (ring 0.17+ requires RNG on load)
        let keypair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8_bytes, &rng)
                .map_err(|_| anyhow!("Failed to load keypair from pkcs8"))?;
        // === Save public key as DER file (optional export for CLI/testing) ===
        let pub_der_path = "sgx-agent/device_public.der";
        log_audit(
            "system",
            AuditCategory::Identity,
            AuditSeverity::Info,
            AuditAction::Exported,
            "Node public key exported in DER format",
        );
        let pub_der = keypair.public_key().as_ref();
        fs::write(pub_der_path, pub_der).ok();
        Ok(Self {
            keypair,
            key_path: key_path_str.to_string(),
        })
    }
    /// Signs the provided message bytes using the node’s private ECDSA key.
    /// Returns the raw signature bytes, used in attestation messages.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        let sig = self
            .keypair
            .sign(&rng, data)
            .map_err(|_| anyhow!("Failed to sign data"))?;

        log_audit(
            "system",
            AuditCategory::Cryptography,
            AuditSeverity::Info,
            AuditAction::Used,
            "Node identity key used to sign data",
        );
        Ok(sig.as_ref().to_vec())
    }

    /// Returns the node’s public key encoded in DER format,
    /// used by peers during attestation verification.
    pub fn pubkey_der(&self) -> Vec<u8> {
        self.keypair.public_key().as_ref().to_vec()
    }

    /// Returns the filesystem path where the private key is stored.
    /// Useful for debugging and operational visibility.
    pub fn key_path(&self) -> &str {
        &self.key_path
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose, Engine as _};
    /// Ensures that identity keys persist across reloads and that signing works.
    /// This verifies the correctness of keypair storage + signature generation.
    #[test]
    fn test_key_persistence_and_sign() {
        let test_path = "/tmp/test_device.key";
        let km1 = KeyManager::load_or_generate(Some(test_path)).unwrap();
        let km2 = KeyManager::load_or_generate(Some(test_path)).unwrap();

        // Public keys must match across reloads (persistent identity)
        assert_eq!(
            general_purpose::STANDARD.encode(km1.pubkey_der()),
            general_purpose::STANDARD.encode(km2.pubkey_der())
        );

        // Signing + verification placeholder (we’ll add verify later)
        let data = b"guardian test message";
        let sig = km1.sign(data).unwrap();
        assert!(!sig.is_empty());

        // Cleanup test key file
        fs::remove_file(test_path).unwrap();
    }
}
