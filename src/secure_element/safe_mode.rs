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
