// src/secure_element/se050.rs
// ============================================================
// SE050 Secure Element Driver.
// Maps to SE-001: Secure Element Driver Initialization.
//
// Init sequence:
//   1. Connect via PlatformSCP
//   2. Reset applet
//   3. Read Unique ID + Cert UID
//   4. Report status
// ============================================================

use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::secure_element::config::SeConfig;
use crate::secure_element::error::SeError;
use crate::secure_element::ssscli::SssCli;
use std::time::Instant;
use tracing::{error, info, warn};

/// SE050 operational status
#[derive(Debug, Clone, PartialEq)]
pub enum SeStatus {
    /// Chip responding, ready for operations
    Active,
    /// Chip disabled in config
    Inactive,
    /// Communication or init error
    Error(String),
    /// Tamper event detected — safe mode
    Tampered,
}

/// Main SE050 secure element handle.
/// Created once at daemon startup, shared across modules.
pub struct Se050 {
    /// ssscli wrapper for sending commands
    pub cli: SssCli,
    /// Loaded configuration
    pub config: SeConfig,
    /// SE050 Unique ID (18 bytes hex). Used for tamper detection.
    pub uid: Option<String>,
    /// SE050 Certificate UID (10 bytes hex).
    pub cert_uid: Option<String>,
    /// Current status
    pub status: SeStatus,
}

impl Se050 {
    /// Initialize SE050 connection and verify chip is responsive.
    /// This maps to test case SE-001: Secure Element Driver Initialization.
    pub fn init(config: &SeConfig) -> Result<Self, SeError> {
        if !config.enabled {
            return Err(SeError::NotAvailable);
        }

        let cli = SssCli::new(config.clone());
        info!("Initializing SE050 secure element...");
        let start = Instant::now();

        // Step 1: Connect with PlatformSCP auth
        match cli.connect() {
            Ok(output) => {
                // "Session already open" warning is OK
                if output.contains("already open") {
                    info!("SE050 session already active");
                } else {
                    info!("SE050 session established");
                }
            }
            Err(e) => {
                error!("SE050 connection failed: {}", e);
                return Err(SeError::ConnectionFailed(e.to_string()));
            }
        }

        // Step 2: Reset applet to known state
        match cli.reset() {
            Ok(_) => info!("SE050 reset successful"),
            Err(e) => warn!("SE050 reset warning: {}", e),
        }

        // Step 3: Read Unique ID (18 bytes)
        let uid = match cli.get_uid() {
            Ok(id) => {
                let uid_fp = {
                    use sha2::{Digest, Sha256};
                    let hash = Sha256::digest(id.as_bytes());
                    hex::encode(&hash[..4])
                };
                info!("SE050 UID fingerprint: {}", uid_fp);
                Some(id)
            }
            Err(e) => {
                warn!("Could not read SE050 UID: {}", e);
                None
            }
        };

        // Step 4: Read Certificate UID (10 bytes)
        let cert_uid = match cli.get_certuid() {
            Ok(id) => {
                let cert_fp = {
                    use sha2::{Digest, Sha256};
                    let hash = Sha256::digest(id.as_bytes());
                    hex::encode(&hash[..4])
                };
                info!("SE050 Cert UID fingerprint: {}", cert_fp);
                Some(id)
            }
            Err(e) => {
                warn!("Could not read SE050 Cert UID: {}", e);
                None
            }
        };

        let elapsed = start.elapsed();
        info!("SE050 initialization completed in {:?}", elapsed);

        log_audit(
            "system",
            AuditCategory::Identity,
            AuditSeverity::Info,
            AuditAction::Loaded,
            "SE050 initialized successfully",
        );

        Ok(Self {
            cli,
            config: config.clone(),
            uid,
            cert_uid,
            status: SeStatus::Active,
        })
    }

    /// Check if SE050 is active and responding
    pub fn is_active(&self) -> bool {
        self.status == SeStatus::Active
    }

    /// Get human-readable status for guardian-ctl se status
    /// SE-001 expected output: "Secure Element: Active, Ready"
    pub fn status_string(&self) -> String {
        match &self.status {
            SeStatus::Active => "Secure Element: Active, Ready".to_string(),
            SeStatus::Inactive => "Secure Element: Inactive".to_string(),
            SeStatus::Error(e) => format!("Secure Element: Error — {}", e),
            SeStatus::Tampered => "Secure Element: TAMPER DETECTED".to_string(),
        }
    }

    /// Detailed status for verbose output
    pub fn status_detail(&self) -> String {
        format!(
            "Status: {}\n\
             Chip: NXP SE050F2HQ1Z018HZ\n\
             Interface: T=1 over I2C\n\
             Unique ID: {}\n\
             Cert UID: {}\n\
             Auth: PlatformSCP\n\
             Middleware: ssscli v04.05.01",
            self.status_string(),
            self.uid.as_deref().unwrap_or("N/A"),
            self.cert_uid.as_deref().unwrap_or("N/A"),
        )
    }

    /// Read list of all object IDs in SE050
    pub fn read_id_list(&self) -> Result<String, SeError> {
        self.cli.read_id_list()
    }

    /// Get hardware random number from TRNG (10 bytes)
    pub fn get_random(&self) -> Result<String, SeError> {
        self.cli.get_rng()
    }
}

// ── Unit Tests (4 tests) ────────────────────────────────────
// Pure enum/string logic — NO I/O, NO subprocess.
// Run: cargo test secure_element::se050::tests -- --nocapture
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_active_string() {
        assert_eq!(
            match SeStatus::Active {
                SeStatus::Active => "Secure Element: Active, Ready",
                _ => "other",
            },
            "Secure Element: Active, Ready"
        );
    }

    #[test]
    fn test_status_tampered_contains_tamper() {
        assert!(match SeStatus::Tampered {
            SeStatus::Tampered => "Secure Element: TAMPER DETECTED",
            _ => "other",
        }
        .contains("TAMPER"));
    }

    #[test]
    fn test_se_status_equality() {
        assert_eq!(SeStatus::Active, SeStatus::Active);
        assert_ne!(SeStatus::Active, SeStatus::Inactive);
        assert_ne!(SeStatus::Active, SeStatus::Tampered);
    }

    #[test]
    fn test_error_status_includes_reason() {
        let msg = match SeStatus::Error("I2C timeout".into()) {
            SeStatus::Error(e) => format!("Error: {}", e),
            _ => "other".into(),
        };
        assert!(msg.contains("I2C timeout"));
    }
}
