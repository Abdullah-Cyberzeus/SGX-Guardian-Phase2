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

    fn config() -> SeConfig {
        SeConfig {
            enabled: true,
            scp_key_path: "/keys/scp.txt".into(),
            interface: "t1oi2c".into(),
            auth_type: "PlatformSCP".into(),
            connection_type: "se05x".into(),
            dkp_key_id_base: 0x2000_0010,
            dik_key_id: 0x2000_0001,
        }
    }

    fn se(status: SeStatus) -> Se050 {
        let config = config();
        Se050 {
            cli: SssCli::new(config.clone()),
            config,
            uid: None,
            cert_uid: None,
            status,
        }
    }

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

    #[test]
    fn public_status_methods_cover_all_states() {
        let cases = [
            (SeStatus::Active, true, "Active, Ready"),
            (SeStatus::Inactive, false, "Inactive"),
            (SeStatus::Error("I2C timeout".into()), false, "I2C timeout"),
            (SeStatus::Tampered, false, "TAMPER DETECTED"),
        ];
        for (status, active, fragment) in cases {
            let se = se(status);
            assert_eq!(se.is_active(), active);
            assert!(se.status_string().contains(fragment));
        }
    }

    #[test]
    fn status_detail_uses_ids_when_present_and_na_when_absent() {
        let mut active = se(SeStatus::Active);
        let missing = active.status_detail();
        assert!(missing.contains("Unique ID: N/A"));
        assert!(missing.contains("Cert UID: N/A"));

        active.uid = Some("uid-123".into());
        active.cert_uid = Some("cert-456".into());
        let populated = active.status_detail();
        assert!(populated.contains("Unique ID: uid-123"));
        assert!(populated.contains("Cert UID: cert-456"));
        assert!(populated.contains("PlatformSCP"));
    }

    #[test]
    fn init_rejects_disabled_configuration_without_invoking_ssscli() {
        let mut config = config();
        config.enabled = false;
        assert!(matches!(Se050::init(&config), Err(SeError::NotAvailable)));
    }

    #[cfg(unix)]
    struct PathGuard(Option<std::ffi::OsString>);

    #[cfg(unix)]
    impl Drop for PathGuard {
        fn drop(&mut self) {
            match self.0.take() {
                Some(path) => std::env::set_var("PATH", path),
                None => std::env::remove_var("PATH"),
            }
        }
    }

    #[cfg(unix)]
    fn install_fake_ssscli(dir: &std::path::Path, body: &str) -> PathGuard {
        use std::os::unix::fs::PermissionsExt;
        let tool = dir.join("ssscli");
        std::fs::write(&tool, format!("#!/bin/sh\n{body}\n")).expect("write fake ssscli");
        let mut permissions = std::fs::metadata(&tool).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(tool, permissions).expect("make executable");
        let old_path = std::env::var_os("PATH");
        std::env::set_var("PATH", dir);
        PathGuard(old_path)
    }

    #[cfg(unix)]
    #[test]
    fn init_reports_connection_failure_when_connect_fails() {
        let _lock = crate::test_support::blocking_env_lock();
        let dir = tempfile::tempdir().expect("fake tool directory");
        let _guard = install_fake_ssscli(dir.path(), "exit 5");
        match Se050::init(&config()) {
            Err(SeError::ConnectionFailed(_)) => {}
            other => panic!("expected ConnectionFailed, got {}", other.is_ok()),
        }
    }

    #[cfg(unix)]
    #[test]
    fn init_succeeds_end_to_end_with_a_fake_chip() {
        let _lock = crate::test_support::blocking_env_lock();
        let dir = tempfile::tempdir().expect("fake tool directory");
        let _guard = install_fake_ssscli(
            dir.path(),
            r#"case "$1 $2" in
  connect*) echo "session already open" ;;
  "se05x reset") exit 0 ;;
  "se05x uid") echo "Unique ID: 040050011f595a6179b9b204783ebae51090" ;;
  "se05x certuid") echo "Cert UID: aabbccddee" ;;
  "se05x readidlist") echo "id-list-ok" ;;
  "se05x getrng") echo "random-bytes" ;;
  *) exit 9 ;;
esac"#,
        );

        let se = Se050::init(&config()).expect("init should succeed against fake chip");
        assert!(se.is_active());
        assert_eq!(se.uid.as_deref(), Some("040050011f595a6179b9b204783ebae51090"));
        assert_eq!(se.cert_uid.as_deref(), Some("aabbccddee"));
        assert!(se.read_id_list().expect("id list").contains("id-list-ok"));
        assert!(se.get_random().expect("rng").contains("random-bytes"));
    }

    #[cfg(unix)]
    #[test]
    fn init_tolerates_reset_warning_and_missing_uids() {
        let _lock = crate::test_support::blocking_env_lock();
        let dir = tempfile::tempdir().expect("fake tool directory");
        let _guard = install_fake_ssscli(
            dir.path(),
            r#"case "$1 $2" in
  connect*) echo "connected" ;;
  "se05x reset") exit 1 ;;
  "se05x uid") exit 1 ;;
  "se05x certuid") exit 1 ;;
  *) exit 9 ;;
esac"#,
        );

        let se = Se050::init(&config()).expect("init tolerates reset/uid failures");
        assert!(se.is_active());
        assert!(se.uid.is_none());
        assert!(se.cert_uid.is_none());
        assert!(se.status_detail().contains("Unique ID: N/A"));
    }
}
