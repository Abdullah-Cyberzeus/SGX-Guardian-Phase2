// src/secure_element/config.rs
// ============================================================
// SE050 connection configuration.
// Deserialized from the secure_element section in node YAML.
// ============================================================

use serde::Deserialize;

/// Configuration for SE050 secure element connection.
/// All values come from config/nodeA.yaml → secure_element section.
#[derive(Clone, Deserialize, Debug)]
pub struct SeConfig {
    /// Enable/disable SE050 integration (false = software-only mode)
    pub enabled: bool,
    /// Path to PlatformSCP key file for authenticated session
    pub scp_key_path: String,
    /// Physical interface: "t1oi2c" (T=1 over I2C)
    pub interface: String,
    /// Auth type: "PlatformSCP" (production authenticated channel)
    pub auth_type: String,
    /// Connection type: "se05x" (SE050 family)
    pub connection_type: String,
}

impl Default for SeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scp_key_path: "~/se05x_mw_v04.05.01/simw-top/scripts/se050F_scp_keys.txt".to_string(),
            interface: "t1oi2c".to_string(),
            auth_type: "PlatformSCP".to_string(),
            connection_type: "se05x".to_string(),
        }
    }
}

// ── Unit Tests (3 tests) ────────────────────────────────────
// Pure struct construction — no I/O, no network.
// Run: cargo test secure_element::config::tests -- --nocapture
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_values() {
        let cfg = SeConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.interface, "t1oi2c");
        assert_eq!(cfg.auth_type, "PlatformSCP");
        assert_eq!(cfg.connection_type, "se05x");
    }

    #[test]
    fn test_scp_key_path_contains_expected_segments() {
        let cfg = SeConfig::default();
        assert!(cfg.scp_key_path.contains("se050F_scp_keys.txt"));
        assert!(cfg.scp_key_path.contains("se05x_mw_v04.05.01"));
    }

    #[test]
    fn test_disabled_config_preserves_other_fields() {
        let cfg = SeConfig {
            enabled: false,
            ..SeConfig::default()
        };
        assert!(!cfg.enabled);
        assert_eq!(cfg.interface, "t1oi2c");
    }
}
