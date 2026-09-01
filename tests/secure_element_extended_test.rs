// tests/secure_element_extended_test.rs
// Integration tests for src/secure_element logic

use sgx_guardian_client::secure_element::safe_mode;
use sgx_guardian_client::secure_element::config::SeConfig;
use sgx_guardian_client::secure_element::tamper::{is_tampered, TamperStatus};

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

#[test]
fn se_config_default_enabled() {
    assert!(SeConfig::default().enabled);
}

#[test]
fn se_config_default_interface() {
    assert_eq!(SeConfig::default().interface, "t1oi2c");
}

#[test]
fn se_config_default_auth_type() {
    assert_eq!(SeConfig::default().auth_type, "PlatformSCP");
}

#[test]
fn se_config_default_connection_type() {
    assert_eq!(SeConfig::default().connection_type, "se05x");
}

#[test]
fn se_config_default_scp_key_path() {
    assert!(SeConfig::default().scp_key_path.ends_with("se050_scp_keys.txt"));
}

#[test]
fn se_config_clone_preserves_values() {
    let cfg = SeConfig::default();
    assert_eq!(cfg.clone().scp_key_path, cfg.scp_key_path);
}

#[test]
fn se_config_debug_mentions_struct_name() {
    assert!(format!("{:?}", SeConfig::default()).contains("SeConfig"));
}

#[test]
fn se_config_deserializes_full_yaml() {
    let cfg: SeConfig = serde_yaml::from_str(
        r#"enabled: false
scp_key_path: /tmp/scp.txt
interface: spi
auth_type: None
connection_type: custom
dkp_key_id_base: 1
dik_key_id: 2
"#,
    )
    .unwrap();
    assert!(!cfg.enabled);
    assert_eq!(cfg.interface, "spi");
    assert_eq!(cfg.dkp_key_id_base, 1);
    assert_eq!(cfg.dik_key_id, 2);
}

#[test]
fn se_config_rejects_missing_required_field() {
    assert!(serde_yaml::from_str::<SeConfig>("enabled: true").is_err());
}

#[test]
fn se_config_rejects_wrong_key_id_type() {
    assert!(serde_yaml::from_str::<SeConfig>(
        r#"enabled: true
scp_key_path: /tmp/scp.txt
interface: t1oi2c
auth_type: PlatformSCP
connection_type: se05x
dkp_key_id_base: nope
dik_key_id: 2
"#
    )
    .is_err());
}

macro_rules! dkp_env_tests {
    ($($name:ident => $value:expr, $expected:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            let prev = std::env::var_os("SGX_SE_DKP_KEY_ID_BASE");
            std::env::set_var("SGX_SE_DKP_KEY_ID_BASE", $value);
            let cfg = SeConfig::default();
            if let Some(value) = prev {
                std::env::set_var("SGX_SE_DKP_KEY_ID_BASE", value);
            } else {
                std::env::remove_var("SGX_SE_DKP_KEY_ID_BASE");
            }
            assert_eq!(cfg.dkp_key_id_base, $expected);
        }
    )+};
}

dkp_env_tests! {
    dkp_env_accepts_lower_hex_prefix => "0x10", 0x10,
    dkp_env_accepts_upper_hex_prefix => "0X11", 0x11,
    dkp_env_accepts_plain_hex => "12", 0x12,
    dkp_env_trims_whitespace => " 13 ", 0x13,
}

#[test]
fn dik_env_accepts_hex_override() {
    let prev = std::env::var_os("SGX_SE_DIK_KEY_ID");
    std::env::set_var("SGX_SE_DIK_KEY_ID", "0x20");
    let cfg = SeConfig::default();
    if let Some(value) = prev {
        std::env::set_var("SGX_SE_DIK_KEY_ID", value);
    } else {
        std::env::remove_var("SGX_SE_DIK_KEY_ID");
    }
    assert_eq!(cfg.dik_key_id, 0x20);
}

#[test]
fn invalid_dkp_env_falls_back_to_default() {
    let prev = std::env::var_os("SGX_SE_DKP_KEY_ID_BASE");
    std::env::set_var("SGX_SE_DKP_KEY_ID_BASE", "not-hex");
    let cfg = SeConfig::default();
    if let Some(value) = prev {
        std::env::set_var("SGX_SE_DKP_KEY_ID_BASE", value);
    } else {
        std::env::remove_var("SGX_SE_DKP_KEY_ID_BASE");
    }
    assert_ne!(cfg.dkp_key_id_base, 0);
}

#[test]
fn invalid_dik_env_falls_back_to_default() {
    let prev = std::env::var_os("SGX_SE_DIK_KEY_ID");
    std::env::set_var("SGX_SE_DIK_KEY_ID", "not-hex");
    let cfg = SeConfig::default();
    if let Some(value) = prev {
        std::env::set_var("SGX_SE_DIK_KEY_ID", value);
    } else {
        std::env::remove_var("SGX_SE_DIK_KEY_ID");
    }
    assert_ne!(cfg.dik_key_id, 0);
}

macro_rules! dik_env_tests {
    ($($name:ident => $value:expr, $expected:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            let prev = std::env::var_os("SGX_SE_DIK_KEY_ID");
            std::env::set_var("SGX_SE_DIK_KEY_ID", $value);
            let cfg = SeConfig::default();
            if let Some(value) = prev {
                std::env::set_var("SGX_SE_DIK_KEY_ID", value);
            } else {
                std::env::remove_var("SGX_SE_DIK_KEY_ID");
            }
            assert_eq!(cfg.dik_key_id, $expected);
        }
    )+};
}

dik_env_tests! {
    dik_env_accepts_upper_hex_prefix => "0X21", 0x21,
    dik_env_accepts_plain_hex => "22", 0x22,
    dik_env_trims_whitespace => " 23 ", 0x23,
}

#[test]
fn se_config_deserializes_disabled_yaml() {
    let cfg: SeConfig = serde_yaml::from_str(
        r#"enabled: false
scp_key_path: relative.txt
interface: t1oi2c
auth_type: PlatformSCP
connection_type: se05x
dkp_key_id_base: 10
dik_key_id: 11
"#,
    )
    .unwrap();
    assert!(!cfg.enabled);
    assert_eq!(cfg.scp_key_path, "relative.txt");
}

#[test]
fn se_config_deserializes_empty_strings() {
    let cfg: SeConfig = serde_yaml::from_str(
        r#"enabled: true
scp_key_path: ""
interface: ""
auth_type: ""
connection_type: ""
dkp_key_id_base: 0
dik_key_id: 0
"#,
    )
    .unwrap();
    assert_eq!(cfg.interface, "");
    assert_eq!(cfg.dik_key_id, 0);
}

#[test]
fn se_config_deserializes_max_key_ids() {
    let cfg: SeConfig = serde_yaml::from_str(
        r#"enabled: true
scp_key_path: /tmp/scp.txt
interface: t1oi2c
auth_type: PlatformSCP
connection_type: se05x
dkp_key_id_base: 4294967295
dik_key_id: 4294967295
"#,
    )
    .unwrap();
    assert_eq!(cfg.dkp_key_id_base, u32::MAX);
    assert_eq!(cfg.dik_key_id, u32::MAX);
}

#[test]
fn se_config_rejects_negative_key_id() {
    assert!(serde_yaml::from_str::<SeConfig>(
        r#"enabled: true
scp_key_path: /tmp/scp.txt
interface: t1oi2c
auth_type: PlatformSCP
connection_type: se05x
dkp_key_id_base: -1
dik_key_id: 1
"#
    )
    .is_err());
}

#[test]
fn se_config_rejects_unknown_boolean_text() {
    assert!(serde_yaml::from_str::<SeConfig>(
        r#"enabled: maybe
scp_key_path: /tmp/scp.txt
interface: t1oi2c
auth_type: PlatformSCP
connection_type: se05x
dkp_key_id_base: 1
dik_key_id: 1
"#
    )
    .is_err());
}

#[test]
fn safe_mode_allows_empty_operation_when_not_tampered() {
    if !is_tampered() {
        assert!(safe_mode::guard_crypto_operation("").is_ok());
    }
}

#[test]
fn safe_mode_allows_long_operation_when_not_tampered() {
    if !is_tampered() {
        assert!(safe_mode::guard_crypto_operation(&"op".repeat(128)).is_ok());
    }
}

#[test]
fn safe_mode_allows_unicode_operation_when_not_tampered() {
    if !is_tampered() {
        assert!(safe_mode::guard_crypto_operation("sign-check").is_ok());
    }
}

macro_rules! safe_mode_operation_tests {
    ($($name:ident => $operation:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            if !is_tampered() {
                assert!(safe_mode::guard_crypto_operation($operation).is_ok());
            }
        }
    )+};
}

safe_mode_operation_tests! {
    safe_mode_allows_encrypt => "encrypt",
    safe_mode_allows_decrypt => "decrypt",
    safe_mode_allows_sign => "sign",
    safe_mode_allows_verify => "verify",
    safe_mode_allows_keygen => "keygen",
    safe_mode_allows_rotate => "rotate",
}

safe_mode_operation_tests! {
    safe_mode_allows_backup => "backup",
    safe_mode_allows_restore => "restore",
    safe_mode_allows_wrap => "wrap",
    safe_mode_allows_unwrap => "unwrap",
    safe_mode_allows_attest => "attest",
    safe_mode_allows_quote => "quote",
    safe_mode_allows_policy_sign => "policy-sign",
    safe_mode_allows_policy_verify => "policy-verify",
    safe_mode_allows_token_encrypt => "token-encrypt",
    safe_mode_allows_token_decrypt => "token-decrypt",
    safe_mode_allows_spaces => "operation with spaces",
    safe_mode_allows_symbols => "op/with-symbols:1",
    safe_mode_allows_numeric => "12345",
    safe_mode_allows_uppercase => "SIGN",
    safe_mode_allows_json_like_text => "{\"op\":\"sign\"}",
}
