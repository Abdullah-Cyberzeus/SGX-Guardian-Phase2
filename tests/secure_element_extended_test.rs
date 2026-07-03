// tests/secure_element_extended_test.rs
// Integration tests for src/secure_element logic

use sgx_guardian_client::secure_element::safe_mode;
use sgx_guardian_client::secure_element::tamper::{TamperStatus, is_tampered};

#[test]
fn test_tamper_status_display() {
    assert_eq!(format!("{}", TamperStatus::None), "Tamper: None");
    assert_eq!(format!("{}", TamperStatus::Detected), "Tamper: DETECTED");
    assert_eq!(format!("{}", TamperStatus::Unknown), "Tamper: Unknown");
}

#[test]
fn test_guard_crypto_operation_passes_when_not_tampered() {
    // The tamper flag should be false by default
    if !is_tampered() {
        let result = safe_mode::guard_crypto_operation("test_op");
        assert!(result.is_ok());
    }
}
