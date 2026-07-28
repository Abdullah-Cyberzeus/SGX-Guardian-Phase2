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
