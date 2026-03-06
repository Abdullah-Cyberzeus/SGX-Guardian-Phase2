// src/secure_element/safe_mode.rs
// ============================================================
// Safe mode — blocks ALL crypto when tamper detected.
// ============================================================

use crate::secure_element::error::SeError;
use crate::secure_element::tamper;
use tracing::error;

pub fn guard_crypto_operation(operation: &str) -> Result<(), SeError> {
    if tamper::is_tampered() {
        error!("SAFE MODE: Blocked '{}' — tamper detected", operation);
        return Err(SeError::TamperDetected);
    }
    Ok(())
}

// ── Unit Tests (2 tests) ────────────────────────────────────
// Pure atomic boolean checks — no I/O, no subprocess.
// Run: cargo test secure_element::safe_mode::tests -- --nocapture
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_guard_allows_when_not_tampered() {
        tamper::TAMPER_DETECTED.store(false, Ordering::SeqCst);
        assert!(guard_crypto_operation("sign").is_ok());
    }

    #[test]
    fn test_guard_blocks_when_tampered() {
        tamper::TAMPER_DETECTED.store(true, Ordering::SeqCst);
        assert!(guard_crypto_operation("sign").is_err());
        tamper::TAMPER_DETECTED.store(false, Ordering::SeqCst);
    }
}
