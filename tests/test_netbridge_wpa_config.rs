use sgx_guardian_client::netbridge::types::WifiClientSettings;
use sgx_guardian_client::netbridge::wpa_config::WpaConfigGenerator;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_wpa_config_generator_psk() {
    let dir = tempdir().unwrap();
    let template_path = dir.path().join("wpa.template");
    let output_path = dir.path().join("wpa.conf");

    fs::write(
        &template_path,
        "country={COUNTRY}\nnetwork={\nssid=\"{SSID}\"\npsk=\"{PASSWORD}\"\n{BSSID}\n}\n",
    )
    .unwrap();

    let generator = WpaConfigGenerator::new();
    let settings = WifiClientSettings {
        country: "US".to_string(),
        networks: vec![sgx_guardian_client::runtime::models::SavedWifi {
            ssid: "MyNetwork".to_string(),
            bssid: Some("AA:BB:CC:DD:EE:FF".to_string()),
            password: Some("MyPassword123".to_string()),
        }],
        ..Default::default()
    };

    generator
        .generate(&template_path, &output_path, &settings)
        .unwrap();

    let content = fs::read_to_string(&output_path).unwrap();
    assert!(content.contains("country=US"));
    assert!(content.contains("ssid=\"MyNetwork\""));
    assert!(content.contains("psk=\"MyPassword123\""));
    assert!(content.contains("bssid=AA:BB:CC:DD:EE:FF"));
}

#[test]
fn test_wpa_config_generator_open() {
    let dir = tempdir().unwrap();
    let template_path = dir.path().join("wpa.template");
    let output_path = dir.path().join("wpa.conf");

    fs::write(
        &template_path,
        "country={COUNTRY}\nnetwork={\nssid=\"{SSID}\"\npsk=\"{PASSWORD}\"\n{BSSID}\n}\n",
    )
    .unwrap();

    let generator = WpaConfigGenerator::new();
    let settings = WifiClientSettings {
        country: "CA".to_string(),
        networks: vec![sgx_guardian_client::runtime::models::SavedWifi {
            ssid: "PublicWifi".to_string(),
            bssid: None,
            password: None,
        }],
        ..Default::default()
    };

    generator
        .generate(&template_path, &output_path, &settings)
        .unwrap();

    let content = fs::read_to_string(&output_path).unwrap();
    assert!(content.contains("country=CA"));
    assert!(content.contains("ssid=\"PublicWifi\""));
    assert!(content.contains("key_mgmt=NONE"));
    assert!(!content.contains("bssid="));
}
