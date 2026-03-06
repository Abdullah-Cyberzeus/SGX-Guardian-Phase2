// src/secure_element/crypto.rs
// ============================================================
// Cryptographic subsystem backed by SE050 hardware.
// Maps to SE-002: Cryptographic Subsystem Activation.
//
// SE050 TRNG: ssscli se05x getrng → 10 bytes per call
// Output format: "Random number: 495b0ade5249153dbcac"
// For 32 bytes: call 4 times, concatenate, truncate
// ============================================================

use crate::secure_element::config::SeConfig;
use crate::secure_element::error::SeError;
use crate::secure_element::ssscli::SssCli;
use sha2::{Digest, Sha256};
use tracing::info;

pub struct SeCrypto {
    cli: SssCli,
    initialized: bool,
}

impl SeCrypto {
    pub fn new(config: &SeConfig) -> Result<Self, SeError> {
        let cli = SssCli::new(config.clone());
        cli.connect()?;
        info!("SE050 crypto subsystem initialized");
        Ok(Self {
            cli,
            initialized: true,
        })
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Generate random bytes using SE050 hardware TRNG.
    /// getrng returns 10 bytes per call in format: "Random number: <hex>"
    /// For more bytes, we call multiple times and concatenate.
    pub fn random(&self, length: usize) -> Result<Vec<u8>, SeError> {
        let mut result = Vec::with_capacity(length);
        let calls_needed = (length + 9) / 10;

        for _ in 0..calls_needed {
            let output = self.cli.get_rng()?;
            // Parse hex from "Random number: <hex>" line
            if let Some(hex_str) = Self::parse_rng_output(&output) {
                if let Ok(bytes) = hex::decode(&hex_str) {
                    result.extend_from_slice(&bytes);
                }
            }
        }

        result.truncate(length);

        if result.len() < length {
            return Err(SeError::CryptoError(format!(
                "RNG returned {} bytes, requested {}",
                result.len(),
                length
            )));
        }

        Ok(result)
    }

    /// Parse the hex value from getrng output.
    /// Looks for "Random number: <hex>" or "INFO:sss.se05x:<hex>"
    fn parse_rng_output(output: &str) -> Option<String> {
        for line in output.lines() {
            let trimmed = line.trim();
            // Primary: "Random number: 495b0ade5249153dbcac"
            if trimmed.starts_with("Random number:") {
                return Some(trimmed["Random number:".len()..].trim().to_string());
            }
            // Fallback: "INFO:sss.se05x:495b0ade5249153dbcac"
            if trimmed.contains("INFO:sss.se05x:") {
                if let Some(val) = trimmed.split("INFO:sss.se05x:").nth(1) {
                    return Some(val.trim().to_string());
                }
            }
        }
        None
    }

    /// Hash data using SHA-256 (software — identical to SE050 internal hash).
    pub fn hash_sha256(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    /// List algorithms supported by SE050F (SE050F2HQ1Z018HZ).
    pub fn list_algorithms() -> Vec<String> {
        vec![
            "AES-128-CBC".into(),
            "AES-256-CBC".into(),
            "AES-128-CTR".into(),
            "AES-256-CTR".into(),
            "ECDSA-P256 (NIST P-256 / NIST_P256)".into(),
            "ECDSA-P384 (NIST P-384 / NIST_P384)".into(),
            "Ed25519 (ED_25519)".into(),
            "X25519 (MONT_DH_25519)".into(),
            "RSA-2048".into(),
            "RSA-4096".into(),
            "SHA-256".into(),
            "SHA-384".into(),
            "HMAC-SHA256".into(),
        ]
    }
}

// ── Unit Tests (7 tests) ────────────────────────────────────
// Pure computation — no I/O, no subprocess, no network.
// Run: cargo test secure_element::crypto::tests -- --nocapture
#[cfg(test)]
mod tests {
    use super::*;

    /// Real output from: ssscli se05x getrng
    const REAL_GETRNG_OUTPUT: &str = "\
sss   :INFO :atr (Len=35)
      00 A0 00 00    03 96 04 03    E8 00 FE 02    0B 03 E8 08
      01 00 00 00    00 64 00 00    0A 4A 43 4F    50 34 20 41
      54 50 4F
sss   :INFO :Newer version of Applet Found
sss   :INFO :Compiled for 0x30100. Got newer 0x30600
INFO:sss.se05x:495b0ade5249153dbcac
Random number: 495b0ade5249153dbcac";

    #[test]
    fn test_parse_rng_from_real_board_output() {
        let hex_str = SeCrypto::parse_rng_output(REAL_GETRNG_OUTPUT);
        assert_eq!(hex_str.unwrap(), "495b0ade5249153dbcac");
    }

    #[test]
    fn test_parse_rng_decodes_to_10_bytes() {
        let hex_str = SeCrypto::parse_rng_output(REAL_GETRNG_OUTPUT).unwrap();
        let bytes = hex::decode(&hex_str).unwrap();
        assert_eq!(bytes.len(), 10, "getrng should return exactly 10 bytes");
    }

    #[test]
    fn test_sha256_known_empty_vector() {
        let hash = SeCrypto::hash_sha256(b"");
        assert_eq!(
            hex::encode(&hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_always_32_bytes() {
        assert_eq!(SeCrypto::hash_sha256(b"test string").len(), 32);
    }

    #[test]
    fn test_sha256_different_inputs_different_outputs() {
        assert_ne!(
            SeCrypto::hash_sha256(b"hello"),
            SeCrypto::hash_sha256(b"world")
        );
    }

    #[test]
    fn test_list_algorithms_has_key_types() {
        let algos = SeCrypto::list_algorithms();
        assert!(algos.len() >= 10);
        assert!(algos.iter().any(|a| a.contains("ECDSA-P256")));
        assert!(algos.iter().any(|a| a.contains("AES-256")));
        assert!(algos.iter().any(|a| a.contains("SHA-256")));
    }

    #[test]
    fn test_list_algorithms_includes_modern_curves() {
        let algos = SeCrypto::list_algorithms();
        assert!(algos.iter().any(|a| a.contains("Ed25519")));
        assert!(algos.iter().any(|a| a.contains("X25519")));
    }
}
