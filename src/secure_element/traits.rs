// src/secure_element/traits.rs
// ============================================================
// CryptoProvider trait — abstraction for HW/SW backends.
// Lets guardian code use SE050 or ring crate interchangeably.
// ============================================================

use anyhow::Result;

/// Abstraction trait for cryptographic operations.
/// Implementations:
///   - Se050Provider (hardware, production)
///   - SoftwareProvider (ring crate, dev/testing)
pub trait CryptoProvider: Send + Sync {
    fn random_bytes(&self, len: usize) -> Result<Vec<u8>>;
    fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>>;
    fn verify(&self, key_id: &str, data: &[u8], sig: &[u8]) -> Result<bool>;
    fn hash_sha256(&self, data: &[u8]) -> Vec<u8>;
    fn list_algorithms(&self) -> Vec<String>;
    fn provider_name(&self) -> &str;
}
