use sgx_guardian_client::runtime::config_store::ConfigStore;
use sgx_guardian_client::runtime::models::GuardianConfig;
use std::fs;

fn setup_env() {
    std::env::set_var(
        "GUARDIAN_CONFIG_FILE",
        "/tmp/guardian_wifi_config_test.json",
    );
    std::env::set_var("GUARDIAN_KEY_FILE", "/tmp/guardian_wifi_key_test.bin");
}

fn with_temp_runtime_files<T>(f: impl FnOnce(std::path::PathBuf, std::path::PathBuf) -> T) -> T {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.json");
    let key = dir.path().join("key.bin");
    let prev_config = std::env::var_os("GUARDIAN_CONFIG_FILE");
    let prev_key = std::env::var_os("GUARDIAN_KEY_FILE");
    std::env::set_var("GUARDIAN_CONFIG_FILE", &config);
    std::env::set_var("GUARDIAN_KEY_FILE", &key);
    let out = f(config, key);
    if let Some(value) = prev_config {
        std::env::set_var("GUARDIAN_CONFIG_FILE", value);
    } else {
        std::env::remove_var("GUARDIAN_CONFIG_FILE");
    }
    if let Some(value) = prev_key {
        std::env::set_var("GUARDIAN_KEY_FILE", value);
    } else {
        std::env::remove_var("GUARDIAN_KEY_FILE");
    }
    out
}

#[test]
fn test_save_and_load_config() {
    setup_env();
    let config_file = "/tmp/guardian_wifi_config_test.json";

    let mut config = GuardianConfig::default();
    config.hotspot.ssid = "TestSSID".to_string();
    config.hotspot.password = "MySecurePass1!".to_string();
    config.uplink.networks = vec![sgx_guardian_client::runtime::models::SavedWifi {
        ssid: "UplinkSSID".to_string(),
        password: Some("UplinkPass!2".to_string()),
        bssid: None,
    }];

    // Save config
    let res = ConfigStore::save(&config);
    assert!(res.is_ok());

    // Read raw file to ensure passwords are encrypted
    let raw_content = fs::read_to_string(config_file).unwrap();
    assert!(!raw_content.contains("MySecurePass1!"));
    assert!(!raw_content.contains("UplinkPass!2"));

    // Load config and verify decryption
    let loaded = ConfigStore::load().unwrap();
    assert_eq!(loaded.hotspot.ssid, "TestSSID");
    assert_eq!(loaded.hotspot.password, "MySecurePass1!");
    assert_eq!(loaded.uplink.networks[0].ssid, "UplinkSSID");
    assert_eq!(
        loaded.uplink.networks[0].password.as_deref(),
        Some("UplinkPass!2")
    );
}

#[test]
fn test_load_non_existent() {
    setup_env();
    let config_file = "/tmp/guardian_wifi_config_test.json";
    // Ensure the file does not exist
    let _ = fs::remove_file(config_file);

    let loaded = ConfigStore::load();
    assert!(loaded.is_ok());
    // Should return default config
    assert_eq!(loaded.unwrap().hotspot.ssid, "");
}

#[test]
fn load_missing_temp_config_returns_default() {
    with_temp_runtime_files(|_, _| {
        assert_eq!(
            ConfigStore::load().unwrap().mode,
            sgx_guardian_client::runtime::models::RuntimeMode::Off
        )
    });
}

#[test]
fn save_creates_parent_directories() {
    with_temp_runtime_files(|config, _| {
        let nested = config.parent().unwrap().join("nested").join("config.json");
        std::env::set_var("GUARDIAN_CONFIG_FILE", &nested);
        ConfigStore::save(&GuardianConfig::default()).unwrap();
        assert!(nested.exists());
    });
}

#[test]
fn save_and_load_default_config_round_trips() {
    with_temp_runtime_files(|_, _| {
        let loaded = ConfigStore::load().unwrap();
        assert_eq!(
            loaded.mode,
            sgx_guardian_client::runtime::models::RuntimeMode::Off
        );
        assert!(loaded.hotspot.ssid.is_empty());
        assert!(loaded.uplink.networks.is_empty());
    });
}

#[test]
fn invalid_json_returns_invalid_config() {
    with_temp_runtime_files(|config, _| {
        std::fs::write(config, b"{").unwrap();
        assert!(ConfigStore::load().is_err());
    });
}

#[test]
fn plaintext_empty_password_is_not_encrypted_on_save() {
    with_temp_runtime_files(|config, _| {
        ConfigStore::save(&GuardianConfig::default()).unwrap();
        let raw = std::fs::read_to_string(config).unwrap();
        assert!(raw.contains("\"password\": \"\""));
    });
}

#[test]
fn hotspot_password_is_encrypted_at_rest_and_restored() {
    with_temp_runtime_files(|config, _| {
        let mut cfg = GuardianConfig::default();
        cfg.hotspot.password = "StrongPass!1".into();
        ConfigStore::save(&cfg).unwrap();
        assert!(!std::fs::read_to_string(config)
            .unwrap()
            .contains("StrongPass!1"));
        assert_eq!(
            ConfigStore::load().unwrap().hotspot.password,
            "StrongPass!1"
        );
    });
}

#[test]
fn empty_uplink_password_remains_empty() {
    with_temp_runtime_files(|_, _| {
        let mut cfg = GuardianConfig::default();
        cfg.uplink
            .networks
            .push(sgx_guardian_client::runtime::models::SavedWifi {
                ssid: "s".into(),
                bssid: None,
                password: Some(String::new()),
            });
        ConfigStore::save(&cfg).unwrap();
        assert_eq!(
            ConfigStore::load().unwrap().uplink.networks[0]
                .password
                .as_deref(),
            Some("")
        );
    });
}

#[test]
fn none_uplink_password_remains_none() {
    with_temp_runtime_files(|_, _| {
        let mut cfg = GuardianConfig::default();
        cfg.uplink
            .networks
            .push(sgx_guardian_client::runtime::models::SavedWifi {
                ssid: "s".into(),
                bssid: None,
                password: None,
            });
        ConfigStore::save(&cfg).unwrap();
        assert!(ConfigStore::load().unwrap().uplink.networks[0]
            .password
            .is_none());
    });
}

macro_rules! mode_roundtrip_tests {
    ($($name:ident => $mode:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            with_temp_runtime_files(|_, _| {
                let mut cfg = GuardianConfig::default();
                cfg.mode = $mode;
                ConfigStore::save(&cfg).unwrap();
                assert_eq!(ConfigStore::load().unwrap().mode, cfg.mode);
            });
        }
    )+};
}

mode_roundtrip_tests! {
    off_mode_round_trips => sgx_guardian_client::runtime::models::RuntimeMode::Off,
    hotspot_mode_round_trips => sgx_guardian_client::runtime::models::RuntimeMode::HotspotOnly,
    client_mode_round_trips => sgx_guardian_client::runtime::models::RuntimeMode::ClientOnly,
    dual_mode_round_trips => sgx_guardian_client::runtime::models::RuntimeMode::DualWifi,
}

#[test]
fn hotspot_fields_round_trip() {
    with_temp_runtime_files(|_, _| {
        let mut cfg = GuardianConfig::default();
        cfg.hotspot.interface = "uap0".into();
        cfg.hotspot.ssid = "ssid".into();
        cfg.hotspot.channel = 11;
        cfg.hotspot.band = Some("5ghz".into());
        cfg.hotspot.client_isolation = true;
        ConfigStore::save(&cfg).unwrap();
        let loaded = ConfigStore::load().unwrap();
        assert_eq!(loaded.hotspot.interface, "uap0");
        assert_eq!(loaded.hotspot.channel, 11);
        assert_eq!(loaded.hotspot.band.as_deref(), Some("5ghz"));
        assert!(loaded.hotspot.client_isolation);
    });
}

#[test]
fn uplink_interface_round_trips() {
    with_temp_runtime_files(|_, _| {
        let mut cfg = GuardianConfig::default();
        cfg.uplink.interface = "eth1".into();
        ConfigStore::save(&cfg).unwrap();
        assert_eq!(ConfigStore::load().unwrap().uplink.interface, "eth1");
    });
}

#[test]
fn restore_flag_round_trips() {
    with_temp_runtime_files(|_, _| {
        let mut cfg = GuardianConfig::default();
        cfg.flags.restore_on_boot = true;
        ConfigStore::save(&cfg).unwrap();
        assert!(ConfigStore::load().unwrap().flags.restore_on_boot);
    });
}

#[test]
fn multiple_uplink_networks_round_trip() {
    with_temp_runtime_files(|_, _| {
        let mut cfg = GuardianConfig::default();
        cfg.uplink.networks = vec![
            sgx_guardian_client::runtime::models::SavedWifi {
                ssid: "a".into(),
                bssid: Some("aa".into()),
                password: Some("Pass!123".into()),
            },
            sgx_guardian_client::runtime::models::SavedWifi {
                ssid: "b".into(),
                bssid: None,
                password: Some("Pass!456".into()),
            },
        ];
        ConfigStore::save(&cfg).unwrap();
        let loaded = ConfigStore::load().unwrap();
        assert_eq!(loaded.uplink.networks.len(), 2);
        assert_eq!(
            loaded.uplink.networks[0].password.as_deref(),
            Some("Pass!123")
        );
    });
}

#[test]
fn bad_encrypted_hotspot_password_returns_error() {
    with_temp_runtime_files(|config, _| {
        let mut cfg = GuardianConfig::default();
        cfg.hotspot.password = "not-base64".into();
        std::fs::write(config, serde_json::to_string(&cfg).unwrap()).unwrap();
        assert!(ConfigStore::load().is_err());
    });
}

#[test]
fn bad_encrypted_uplink_password_returns_error() {
    with_temp_runtime_files(|config, _| {
        let mut cfg = GuardianConfig::default();
        cfg.uplink
            .networks
            .push(sgx_guardian_client::runtime::models::SavedWifi {
                ssid: "s".into(),
                bssid: None,
                password: Some("not-base64".into()),
            });
        std::fs::write(config, serde_json::to_string(&cfg).unwrap()).unwrap();
        assert!(ConfigStore::load().is_err());
    });
}

#[test]
fn zero_channel_round_trips() {
    with_temp_runtime_files(|_, _| {
        let mut cfg = GuardianConfig::default();
        cfg.hotspot.channel = 0;
        ConfigStore::save(&cfg).unwrap();
        assert_eq!(ConfigStore::load().unwrap().hotspot.channel, 0);
    });
}

#[test]
fn max_channel_round_trips() {
    with_temp_runtime_files(|_, _| {
        let mut cfg = GuardianConfig::default();
        cfg.hotspot.channel = u8::MAX;
        ConfigStore::save(&cfg).unwrap();
        assert_eq!(ConfigStore::load().unwrap().hotspot.channel, u8::MAX);
    });
}

#[test]
fn empty_saved_wifi_ssid_round_trips() {
    with_temp_runtime_files(|_, _| {
        let mut cfg = GuardianConfig::default();
        cfg.uplink
            .networks
            .push(sgx_guardian_client::runtime::models::SavedWifi {
                ssid: String::new(),
                bssid: None,
                password: Some("Pass!789".into()),
            });
        ConfigStore::save(&cfg).unwrap();
        assert_eq!(ConfigStore::load().unwrap().uplink.networks[0].ssid, "");
    });
}

#[test]
fn unicode_like_ascii_fields_round_trip() {
    with_temp_runtime_files(|_, _| {
        let mut cfg = GuardianConfig::default();
        cfg.hotspot.ssid = "Cafe-Node-5G".into();
        cfg.uplink.interface = "wlan-backhaul".into();
        ConfigStore::save(&cfg).unwrap();
        let loaded = ConfigStore::load().unwrap();
        assert_eq!(loaded.hotspot.ssid, "Cafe-Node-5G");
        assert_eq!(loaded.uplink.interface, "wlan-backhaul");
    });
}

#[test]
fn saved_file_contains_mode_field() {
    with_temp_runtime_files(|config, _| {
        let mut cfg = GuardianConfig::default();
        cfg.mode = sgx_guardian_client::runtime::models::RuntimeMode::DualWifi;
        ConfigStore::save(&cfg).unwrap();
        assert!(std::fs::read_to_string(config)
            .unwrap()
            .contains("\"mode\": \"DualWifi\""));
    });
}
