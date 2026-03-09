// src/cot/identity.rs
// ============================================================
// Identity-Based Addressing for CoT

use crate::cot::types::{CotError, CotResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Represents a device's cryptographic identity.
/// This is the core addressing primitive for the CoT layer.
///
/// Identity is derived from the device's public key:
///   device_id = hex(SHA-256(public_key_der_bytes))
///
/// This means:
/// - Same device always has the same identity (key doesn't change)
/// - Identity is independent of IP, MAC, or transport
/// - Identity can be verified by anyone who has the public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// Hex-encoded SHA-256 of the public key DER bytes.
    /// Example: "a3b2c1d4e5f6..."
    device_id: String,

    /// The raw public key bytes (DER-encoded).
    /// Stored so we can share it with peers for verification.
    public_key_der: Vec<u8>,

    display_name: Option<String>,
}

impl DeviceIdentity {
    /// Create a DeviceIdentity from raw public key DER bytes.
    /// This is the primary constructor — called once at startup
    /// after KeyManager loads the node's key pair.
    pub fn from_public_key(public_key_der: &[u8]) -> CotResult<Self> {
        if public_key_der.is_empty() {
            return Err(CotError::IdentityError(
                "Public key bytes cannot be empty".into(),
            ));
        }

        let device_id = Self::compute_fingerprint(public_key_der);

        Ok(Self {
            device_id,
            public_key_der: public_key_der.to_vec(),
            display_name: None,
        })
    }

    /// Create identity with a human-readable display name.
    pub fn from_public_key_with_name(public_key_der: &[u8], name: &str) -> CotResult<Self> {
        let mut identity = Self::from_public_key(public_key_der)?;
        identity.display_name = Some(name.to_string());
        Ok(identity)
    }

    /// Compute the SHA-256 fingerprint of public key bytes.
    /// This is a pure function — deterministic, no side effects.
    fn compute_fingerprint(public_key_der: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(public_key_der);
        let result = hasher.finalize();
        hex::encode(result)
    }

    /// Returns the device_id (hex fingerprint).
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Returns the short form of device_id (first 16 hex chars).
    /// Useful for logging without flooding output.
    pub fn short_id(&self) -> &str {
        if self.device_id.len() >= 16 {
            &self.device_id[..16]
        } else {
            &self.device_id
        }
    }

    /// Returns the raw public key bytes.
    pub fn public_key_der(&self) -> &[u8] {
        &self.public_key_der
    }

    /// Returns the display name if set.
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// Set or update the display name.
    pub fn set_display_name(&mut self, name: &str) {
        self.display_name = Some(name.to_string());
    }

    /// Verify that a given public key matches this identity.
    /// Used when a peer claims to be device_id "xyz" — we hash
    /// their presented public key and check if it matches.
    pub fn verify_public_key(&self, candidate_key_der: &[u8]) -> bool {
        let candidate_id = Self::compute_fingerprint(candidate_key_der);
        self.device_id == candidate_id
    }

    /// Static helper: compute a device_id from public key bytes
    /// without creating a full DeviceIdentity object.
    /// Useful when you just need the ID string for lookup.
    pub fn compute_id(public_key_der: &[u8]) -> String {
        Self::compute_fingerprint(public_key_der)
    }
}

impl fmt::Display for DeviceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.display_name {
            Some(name) => write!(f, "{}({})", name, self.short_id()),
            None => write!(f, "{}", self.short_id()),
        }
    }
}

impl PartialEq for DeviceIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.device_id == other.device_id
    }
}

impl Eq for DeviceIdentity {}

impl std::hash::Hash for DeviceIdentity {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.device_id.hash(state);
    }
}

// ----------------------------------------------------------
// Unit Tests
// ----------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key() -> Vec<u8> {
        // Simulated 65-byte uncompressed ECDSA P-256 public key
        let mut key = vec![0x04]; // uncompressed point prefix
        key.extend_from_slice(&[0xAA; 32]);
        key.extend_from_slice(&[0xBB; 32]);
        key
    }

    #[test]
    fn test_identity_from_public_key() {
        let key = sample_key();
        let id = DeviceIdentity::from_public_key(&key).unwrap();
        assert!(!id.device_id().is_empty());
        assert_eq!(id.device_id().len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn test_identity_deterministic() {
        let key = sample_key();
        let id1 = DeviceIdentity::from_public_key(&key).unwrap();
        let id2 = DeviceIdentity::from_public_key(&key).unwrap();
        assert_eq!(id1.device_id(), id2.device_id());
    }

    #[test]
    fn test_different_keys_different_ids() {
        let key1 = sample_key();
        let mut key2 = sample_key();
        key2[1] = 0xCC; // change one byte
        let id1 = DeviceIdentity::from_public_key(&key1).unwrap();
        let id2 = DeviceIdentity::from_public_key(&key2).unwrap();
        assert_ne!(id1.device_id(), id2.device_id());
    }

    #[test]
    fn test_verify_public_key_match() {
        let key = sample_key();
        let id = DeviceIdentity::from_public_key(&key).unwrap();
        assert!(id.verify_public_key(&key));
    }

    #[test]
    fn test_verify_public_key_mismatch() {
        let key = sample_key();
        let id = DeviceIdentity::from_public_key(&key).unwrap();
        let mut wrong_key = sample_key();
        wrong_key[1] = 0xFF;
        assert!(!id.verify_public_key(&wrong_key));
    }

    #[test]
    fn test_empty_key_rejected() {
        let result = DeviceIdentity::from_public_key(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_display_with_name() {
        let key = sample_key();
        let id = DeviceIdentity::from_public_key_with_name(&key, "nodeA").unwrap();
        let display = format!("{}", id);
        assert!(display.contains("nodeA"));
    }

    #[test]
    fn test_equality() {
        let key = sample_key();
        let id1 = DeviceIdentity::from_public_key(&key).unwrap();
        let id2 = DeviceIdentity::from_public_key(&key).unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_compute_id_static() {
        let key = sample_key();
        let id_str = DeviceIdentity::compute_id(&key);
        let id_obj = DeviceIdentity::from_public_key(&key).unwrap();
        assert_eq!(id_str, id_obj.device_id());
    }
}
