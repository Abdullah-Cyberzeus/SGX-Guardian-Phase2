// src/secure_element/key_storage.rs
// ============================================================
// Protected Key Storage — keys generated inside SE050.
// Maps to SE-003: Protected Key Storage Creation.
//
// Key ID range: 0x20000001 — 0x200000FF (Guardian keys)
// Syntax: ssscli generate ecc <keyid> <curve>
// Curves: NIST_P256, NIST_P384 (NOT prime256v1, secp384r1)
// ============================================================

use crate::secure_element::config::SeConfig;
use crate::secure_element::error::SeError;
use crate::secure_element::ssscli::SssCli;
use tracing::info;

#[derive(Debug, Clone)]
pub struct KeySlot {
    pub key_id: u32,
    pub label: String,
    pub algorithm: String,
    pub exportable: bool, // always false for SE050
    pub access: String,
}

pub struct SeKeyStorage {
    cli: SssCli,
}

impl SeKeyStorage {
    pub fn new(config: &SeConfig) -> Result<Self, SeError> {
        let cli = SssCli::new(config.clone());
        cli.connect()?;
        Ok(Self { cli })
    }

    /// Create ECDSA key pair inside SE050.
    /// key_id_offset: slot number (1 → 0x20000001)
    /// algorithm: "ecdsa" defaults to NIST_P256
    pub fn create_key_slot(
        &self,
        key_id_offset: u32,
        label: &str,
        algorithm: &str,
    ) -> Result<KeySlot, SeError> {
        let key_id = 0x20000000 + key_id_offset;
        let hex_id = format!("0x{:08X}", key_id);

        // Map algorithm name to ssscli curve name
        let curve = match algorithm.to_lowercase().as_str() {
            "ecdsa" | "ecdsa-p256" | "p256" | "nist_p256" => "NIST_P256",
            "ecdsa-p384" | "p384" | "nist_p384" => "NIST_P384",
            "ed25519" => "ED_25519",
            _ => "NIST_P256", // default
        };

        info!("Creating SE050 key: {} ({}) curve={}", label, hex_id, curve);
        self.cli.generate_ecc_key(&hex_id, curve)?;

        Ok(KeySlot {
            key_id,
            label: label.to_string(),
            algorithm: algorithm.to_string(),
            exportable: false,
            access: "Secure Element Only".to_string(),
        })
    }

    /// Export ONLY the public key (DER format).
    /// Syntax: ssscli get ecc pub <keyid> <filename>
    pub fn export_public_key(&self, key_id: u32, output: &str) -> Result<(), SeError> {
        let hex_id = format!("0x{:08X}", key_id);
        self.cli.get_ecc_pub(&hex_id, output)?;
        Ok(())
    }

    pub fn list_slots(&self) -> Result<String, SeError> {
        self.cli.read_id_list()
    }

    pub fn slot_info(&self, key_id: u32) -> KeySlot {
        KeySlot {
            key_id,
            label: format!("slot{:02}", key_id & 0xFF),
            algorithm: "ECDSA-P256".to_string(),
            exportable: false,
            access: "Secure Element Only".to_string(),
        }
    }

    /// Delete a key from SE050. Syntax: ssscli erase <keyid>
    pub fn delete_key(&self, key_id: u32) -> Result<(), SeError> {
        let hex_id = format!("0x{:08X}", key_id);
        self.cli.erase(&hex_id)?;
        Ok(())
    }
}

// ── Unit Tests (5 tests) ────────────────────────────────────
// Run: cargo test secure_element::key_storage::tests -- --nocapture
#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_element::ssscli::SssCli;
    use std::path::Path;

    struct PathGuard(Option<std::ffi::OsString>);

    impl Drop for PathGuard {
        fn drop(&mut self) {
            match self.0.take() {
                Some(path) => std::env::set_var("PATH", path),
                None => std::env::remove_var("PATH"),
            }
        }
    }

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

    #[cfg(unix)]
    fn storage_with_script(dir: &Path, log: &Path) -> (SeKeyStorage, PathGuard) {
        use std::os::unix::fs::PermissionsExt;

        let tool = dir.join("ssscli");
        std::fs::write(
            &tool,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\necho slots-ok\n",
                log.display()
            ),
        )
        .expect("write fake ssscli");
        let mut permissions = std::fs::metadata(&tool).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(tool, permissions).expect("make executable");
        let old_path = std::env::var_os("PATH");
        std::env::set_var("PATH", dir);
        (
            SeKeyStorage {
                cli: SssCli::new(config()),
            },
            PathGuard(old_path),
        )
    }

    #[test]
    fn test_key_id_calculation() {
        let key_id: u32 = 0x20000000 + 1;
        assert_eq!(key_id, 0x20000001);
        assert_eq!(format!("0x{:08X}", key_id), "0x20000001");
    }

    #[test]
    fn test_guardian_range_avoids_factory_and_test() {
        let guardian_end: u32 = 0x200000FF;
        assert!(guardian_end < 0x7FFF0000u32);
        assert!(guardian_end < 0xF0000000u32);
    }

    #[test]
    fn test_slot_always_non_exportable() {
        let slot = KeySlot {
            key_id: 0x20000001,
            label: "slot01".into(),
            algorithm: "ECDSA-P256".into(),
            exportable: false,
            access: "Secure Element Only".into(),
        };
        assert!(!slot.exportable);
        assert_eq!(slot.access, "Secure Element Only");
    }

    #[test]
    fn test_curve_name_mapping_to_ssscli_format() {
        // ssscli uses NIST_P256 not prime256v1
        let cases = vec![
            ("ecdsa", "NIST_P256"),
            ("ecdsa-p256", "NIST_P256"),
            ("p256", "NIST_P256"),
            ("nist_p256", "NIST_P256"),
            ("ecdsa-p384", "NIST_P384"),
            ("p384", "NIST_P384"),
            ("ed25519", "ED_25519"),
            ("unknown", "NIST_P256"),
        ];
        for (algo, expected) in cases {
            let curve = match algo.to_lowercase().as_str() {
                "ecdsa" | "ecdsa-p256" | "p256" | "nist_p256" => "NIST_P256",
                "ecdsa-p384" | "p384" | "nist_p384" => "NIST_P384",
                "ed25519" => "ED_25519",
                _ => "NIST_P256",
            };
            assert_eq!(curve, expected, "'{}' → '{}'", algo, expected);
        }
    }

    #[test]
    fn test_key_id_hex_formatting() {
        // Verify we generate correct hex format for ssscli
        for offset in [1u32, 2, 10, 255] {
            let hex_id = format!("0x{:08X}", 0x20000000 + offset);
            assert!(hex_id.starts_with("0x2000"));
            assert_eq!(hex_id.len(), 10); // "0x" + 8 hex digits
        }
    }

    #[test]
    fn slot_info_masks_label_and_exposes_safe_contract() {
        let storage = SeKeyStorage {
            cli: SssCli::new(config()),
        };
        let slot = storage.slot_info(0x2000_01ab);
        assert_eq!(slot.key_id, 0x2000_01ab);
        assert_eq!(slot.label, "slot171");
        assert_eq!(slot.algorithm, "ECDSA-P256");
        assert!(!slot.exportable);
        assert_eq!(slot.access, "Secure Element Only");
    }

    #[cfg(unix)]
    #[test]
    fn storage_operations_map_ids_curves_and_positional_commands() {
        let _lock = crate::test_support::blocking_env_lock();
        let dir = tempfile::tempdir().expect("fake tool directory");
        let log = dir.path().join("calls.log");
        let (storage, _guard) = storage_with_script(dir.path(), &log);

        for (offset, algorithm, curve) in [
            (1, "ecdsa", "NIST_P256"),
            (2, "nist_p384", "NIST_P384"),
            (3, "ed25519", "ED_25519"),
            (4, "unknown", "NIST_P256"),
        ] {
            let slot = storage
                .create_key_slot(offset, "label", algorithm)
                .expect("create slot");
            assert_eq!(slot.key_id, 0x2000_0000 + offset);
            assert_eq!(slot.algorithm, algorithm);
            let expected = format!("generate ecc 0x{:08X} {curve}", slot.key_id);
            assert!(std::fs::read_to_string(&log)
                .expect("command log")
                .lines()
                .any(|line| line == expected));
        }

        storage
            .export_public_key(0x2000_0010, "/tmp/key.der")
            .expect("export public key");
        assert!(storage
            .list_slots()
            .expect("slot list")
            .contains("slots-ok"));
        storage.delete_key(0x2000_0010).expect("delete key");
        let calls = std::fs::read_to_string(log).expect("command log");
        assert!(calls.contains("get ecc pub 0x20000010 /tmp/key.der"));
        assert!(calls.contains("se05x readidlist"));
        assert!(calls.contains("erase 0x20000010"));
    }
}
