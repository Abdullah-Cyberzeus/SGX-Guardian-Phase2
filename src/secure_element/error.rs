// src/secure_element/error.rs
// ============================================================
// SE050-specific error types.
// All secure_element modules return SeError on failure.
// ============================================================

use std::fmt;

/// All errors that can occur in the SE050 layer.
/// Each variant maps to a specific failure domain.
#[derive(Debug)]
pub enum SeError {
    /// SE050 I2C connection or PlatformSCP session failed
    ConnectionFailed(String),
    /// ssscli subprocess returned non-zero exit code
    CommandFailed { cmd: String, stderr: String },
    /// SE050 chip not detected or disabled in config
    NotAvailable,
    /// Key generation, deletion, export, or access error
    KeyError(String),
    /// Encryption, signing, RNG, or hash operation error
    CryptoError(String),
    /// SE050 tamper mesh or integrity check triggered
    TamperDetected,
}

impl fmt::Display for SeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SeError::ConnectionFailed(msg) => write!(f, "SE050 connection failed: {}", msg),
            SeError::CommandFailed { cmd, stderr } => {
                write!(f, "ssscli failed: {} — {}", cmd, stderr)
            }
            SeError::NotAvailable => write!(f, "SE050 not available"),
            SeError::KeyError(msg) => write!(f, "Key operation failed: {}", msg),
            SeError::CryptoError(msg) => write!(f, "Crypto operation failed: {}", msg),
            SeError::TamperDetected => write!(f, "SE050 tamper detected — safe mode active"),
        }
    }
}

impl std::error::Error for SeError {}

// ── Unit Tests (6 tests) ────────────────────────────────────
// All pure string logic — no I/O, no network, no subprocess.
// Run: cargo test secure_element::error::tests -- --nocapture
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_failed_display() {
        let err = SeError::ConnectionFailed("I2C timeout".into());
        let msg = format!("{}", err);
        assert!(msg.contains("connection failed"));
        assert!(msg.contains("I2C timeout"));
    }

    #[test]
    fn test_command_failed_display() {
        let err = SeError::CommandFailed {
            cmd: "se05x uid".into(),
            stderr: "No such device".into(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("ssscli failed"));
        assert!(msg.contains("se05x uid"));
    }

    #[test]
    fn test_not_available_display() {
        assert!(format!("{}", SeError::NotAvailable).contains("not available"));
    }

    #[test]
    fn test_key_error_display() {
        assert!(format!("{}", SeError::KeyError("slot full".into())).contains("Key operation"));
    }

    #[test]
    fn test_crypto_error_display() {
        assert!(format!("{}", SeError::CryptoError("RNG fail".into())).contains("Crypto operation"));
    }

    #[test]
    fn test_tamper_detected_display() {
        let msg = format!("{}", SeError::TamperDetected);
        assert!(msg.contains("tamper detected"));
        assert!(msg.contains("safe mode"));
    }
}
