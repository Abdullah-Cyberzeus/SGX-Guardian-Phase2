// src/secure_element/tamper.rs
// ============================================================
// Tamper detection for SE050. Maps to SE-004.
// Detection: UID consistency, comm health, cert UID check.
// ============================================================

// use crate::secure_element::error::SeError;
use crate::secure_element::se050::Se050;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{error, info};

/// Global tamper flag — once set, blocks ALL crypto
pub static TAMPER_DETECTED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, PartialEq)]
pub enum TamperStatus {
    None,
    Detected,
    Unknown,
}

impl std::fmt::Display for TamperStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TamperStatus::None => write!(f, "Tamper: None"),
            TamperStatus::Detected => write!(f, "Tamper: DETECTED"),
            TamperStatus::Unknown => write!(f, "Tamper: Unknown"),
        }
    }
}

/// Check SE050 for tamper indicators.
pub fn check_tamper(se: &Se050) -> TamperStatus {
    // Check 1: Can we communicate?
    let current_uid = match se.cli.get_uid() {
        Ok(uid) => uid,
        Err(e) => {
            error!("SE050 comm lost: {}", e);
            set_tamper("Communication lost");
            return TamperStatus::Detected;
        }
    };

    // Check 2: UID changed? (chip swap)
    if let Some(ref original) = se.uid {
        if &current_uid != original {
            error!("UID mismatch: {} vs {}", original, current_uid);
            set_tamper("UID changed — chip swap");
            return TamperStatus::Detected;
        }
    }

    // Check 3: Cert UID consistency — fail closed on read error
    if let Some(ref orig_cert) = se.cert_uid {
        match se.cli.get_certuid() {
            Ok(cert) if &cert != orig_cert => {
                set_tamper("Cert UID changed");
                return TamperStatus::Detected;
            }
            Ok(_) => {}
            Err(e) => {
                error!("SE050 cert UID read failed: {}", e);
                set_tamper("Cert UID read failed — possible tamper");
                return TamperStatus::Detected;
            }
        }
    }

    if TAMPER_DETECTED.load(Ordering::SeqCst) {
        return TamperStatus::Detected;
    }

    info!("Tamper check: OK");
    TamperStatus::None
}

fn set_tamper(reason: &str) {
    TAMPER_DETECTED.store(true, Ordering::SeqCst);
    error!("SE050 TAMPER: {}", reason);
}

pub fn is_tampered() -> bool {
    TAMPER_DETECTED.load(Ordering::SeqCst)
}

/// Reset tamper flag. Test-only — production code must never clear tamper.
#[cfg(test)]
pub(crate) fn clear_tamper() {
    TAMPER_DETECTED.store(false, Ordering::SeqCst);
}

// ── Unit Tests (4 tests) ────────────────────────────────────
// Pure atomic boolean operations — no I/O, no subprocess.
// Run: cargo test secure_element::tamper::tests -- --nocapture
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TAMPER_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_tamper_status_display_strings() {
        assert_eq!(format!("{}", TamperStatus::None), "Tamper: None");
        assert_eq!(format!("{}", TamperStatus::Detected), "Tamper: DETECTED");
        assert_eq!(format!("{}", TamperStatus::Unknown), "Tamper: Unknown");
    }

    #[test]
    fn test_tamper_flag_starts_false() {
        let _guard = TAMPER_TEST_LOCK.lock().unwrap();
        clear_tamper();
        assert!(!is_tampered());
        clear_tamper();
    }

    #[test]
    fn test_tamper_flag_can_be_set() {
        let _guard = TAMPER_TEST_LOCK.lock().unwrap();
        clear_tamper();
        set_tamper("unit test");
        assert!(is_tampered());
        clear_tamper();
    }

    #[test]
    fn test_clear_tamper_resets_flag() {
        let _guard = TAMPER_TEST_LOCK.lock().unwrap();
        clear_tamper();
        set_tamper("unit test");
        clear_tamper();
        assert!(!is_tampered());
        clear_tamper();
    }
}
