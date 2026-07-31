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
    /// DKP base key id (v1; version N = base + N - 1). Defaults to the
    /// long-standing hardcoded slot `dkp::DKP_BASE_KEY_ID`. Only override via
    /// `SGX_SE_DKP_KEY_ID_BASE` when several containers share one physical
    /// SE050 chip and must not collide on the same slot.
    pub dkp_key_id_base: u32,
    /// DIK key id. Defaults to the long-standing hardcoded slot
    /// `dik::DIK_KEY_ID`. Only override via `SGX_SE_DIK_KEY_ID` for the same
    /// multi-node-on-one-chip scenario as `dkp_key_id_base`.
    pub dik_key_id: u32,
}

impl Default for SeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scp_key_path: "/etc/sgx-guardian/se050_scp_keys.txt".to_string(),
            interface: "t1oi2c".to_string(),
            auth_type: "PlatformSCP".to_string(),
            connection_type: "se05x".to_string(),
            dkp_key_id_base: parse_key_id(
                "SGX_SE_DKP_KEY_ID_BASE",
                crate::secure_element::dkp::DKP_BASE_KEY_ID,
            ),
            dik_key_id: parse_key_id("SGX_SE_DIK_KEY_ID", crate::secure_element::dik::DIK_KEY_ID),
        }
    }
}

fn parse_key_id(var: &str, default: u32) -> u32 {
    std::env::var(var)
        .ok()
        .and_then(|value| {
            let value = value.trim();
            let value = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
                .unwrap_or(value);
            u32::from_str_radix(value, 16).ok()
        })
        .unwrap_or(default)
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
        assert!(cfg.scp_key_path.contains("se050_scp_keys.txt"));
        assert!(cfg.scp_key_path.contains("/etc/sgx-guardian"));
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
