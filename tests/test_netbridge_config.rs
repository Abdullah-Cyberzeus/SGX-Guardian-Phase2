use sgx_guardian_client::netbridge::config::{ConfigGenerator, DnsmasqConfigGenerator};
use sgx_guardian_client::netbridge::types::ApSettings;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_hostapd_generator() {
    let dir = tempdir().unwrap();
    let template_path = dir.path().join("hostapd.template");
    let output_path = dir.path().join("hostapd.conf");

    // Write a mock template
    fs::write(
        &template_path,
        "interface={INTERFACE}\nssid={SSID}\nchannel={CHANNEL}\nhw_mode={HW_MODE}\nwpa_passphrase={WPA_PASSPHRASE}\nwpa={WPA}\nwpa_key_mgmt={WPA_KEY_MGMT}\nrsn_pairwise={RSN_PAIRWISE}\n"
    ).unwrap();

    let generator = ConfigGenerator::new();
    let settings = ApSettings {
        interface: "uap0".to_string(),
        ssid: "TestNet".to_string(),
        channel: 11,
        hw_mode: "g".to_string(),
        wpa_passphrase: Some("Secret123!".to_string()),
        ..Default::default()
    };

    generator
        .generate_config(&template_path, &output_path, &settings)
        .unwrap();

    let content = fs::read_to_string(&output_path).unwrap();
    assert!(content.contains("interface=uap0"));
    assert!(content.contains("ssid=TestNet"));
    assert!(content.contains("channel=11"));
    assert!(content.contains("wpa_passphrase=Secret123!"));
    assert!(content.contains("wpa=2"));
    assert!(content.contains("wpa_key_mgmt=WPA-PSK"));
}

#[test]
fn test_hostapd_generator_open_network() {
    let dir = tempdir().unwrap();
    let template_path = dir.path().join("hostapd.template");
    let output_path = dir.path().join("hostapd.conf");

    fs::write(
        &template_path,
        "wpa_passphrase={WPA_PASSPHRASE}\nwpa={WPA}\n",
    )
    .unwrap();

    let generator = ConfigGenerator::new();
    let settings = ApSettings {
        wpa_passphrase: None,
        ..Default::default()
    };

    generator
        .generate_config(&template_path, &output_path, &settings)
        .unwrap();

    let content = fs::read_to_string(&output_path).unwrap();
    assert!(content.contains("wpa_passphrase=\n"));
    assert!(content.contains("wpa=0"));
}

#[test]
fn test_dnsmasq_generator() {
    let dir = tempdir().unwrap();
    let template_path = dir.path().join("dnsmasq.template");
    let output_path = dir.path().join("dnsmasq.conf");

    fs::write(
        &template_path,
        "interface={INTERFACE}\ndhcp-range={DHCP_RANGE_START},{DHCP_RANGE_END}\ndhcp-option=3,{GATEWAY_IP}\nlocal=/{LOCAL_DOMAIN}/\n"
    ).unwrap();

    let generator = DnsmasqConfigGenerator::new();
    let settings = sgx_guardian_client::netbridge::types::DnsmasqSettings {
        interface: "uap1".to_string(),
        gateway_ip: "192.168.200.1".to_string(),
        dhcp_range_start: "192.168.200.100".to_string(),
        dhcp_range_end: "192.168.200.200".to_string(),
        local_domain: "test.local".to_string(),
    };

    generator
        .generate_config(&template_path, &output_path, &settings)
        .unwrap();

    let content = fs::read_to_string(&output_path).unwrap();
    assert!(content.contains("interface=uap1"));
    assert!(content.contains("dhcp-range=192.168.200.100,192.168.200.200"));
    assert!(content.contains("dhcp-option=3,192.168.200.1"));
    assert!(content.contains("local=/test.local/"));
}

// The tests below hit `replace_variables` directly (no filesystem involved) —
// these are the exact validation branches that produced a real boot failure:
// a saved hotspot config with an empty/invalid password made hostapd config
// generation fail every 10s forever with no fallback. Pinning these here
// prevents that regressing silently again.

#[test]
fn rejects_passphrase_shorter_than_8_characters() {
    let generator = ConfigGenerator::new();
    let settings = ApSettings {
        wpa_passphrase: Some("short1!".to_string()), // 7 chars
        ..Default::default()
    };

    let error = generator
        .replace_variables("wpa_passphrase={WPA_PASSPHRASE}", &settings)
        .unwrap_err();
    assert!(error.to_string().contains("8-63 characters"));
}

#[test]
fn rejects_passphrase_longer_than_63_characters() {
    let generator = ConfigGenerator::new();
    let settings = ApSettings {
        wpa_passphrase: Some("a".repeat(64)),
        ..Default::default()
    };

    let error = generator
        .replace_variables("wpa_passphrase={WPA_PASSPHRASE}", &settings)
        .unwrap_err();
    assert!(error.to_string().contains("8-63 characters"));
}

#[test]
fn accepts_passphrase_at_the_8_and_63_character_boundaries() {
    let generator = ConfigGenerator::new();

    let min_settings = ApSettings {
        wpa_passphrase: Some("a".repeat(8)),
        ..Default::default()
    };
    assert!(generator
        .replace_variables("{WPA_PASSPHRASE}", &min_settings)
        .is_ok());

    let max_settings = ApSettings {
        wpa_passphrase: Some("a".repeat(63)),
        ..Default::default()
    };
    assert!(generator
        .replace_variables("{WPA_PASSPHRASE}", &max_settings)
        .is_ok());
}

#[test]
fn rejects_passphrase_containing_newlines() {
    let generator = ConfigGenerator::new();
    let settings = ApSettings {
        wpa_passphrase: Some("Secret1!\nrogue=line".to_string()),
        ..Default::default()
    };

    let error = generator
        .replace_variables("{WPA_PASSPHRASE}", &settings)
        .unwrap_err();
    assert!(error.to_string().contains("newlines"));
}

#[test]
fn rejects_ssid_longer_than_32_bytes() {
    let generator = ConfigGenerator::new();
    let settings = ApSettings {
        ssid: "a".repeat(33),
        ..Default::default()
    };

    let error = generator
        .replace_variables("ssid={SSID}", &settings)
        .unwrap_err();
    assert!(error.to_string().contains("32 bytes"));
}

#[test]
fn accepts_ssid_at_the_32_byte_boundary() {
    let generator = ConfigGenerator::new();
    let settings = ApSettings {
        ssid: "a".repeat(32),
        ..Default::default()
    };

    assert!(generator
        .replace_variables("ssid={SSID}", &settings)
        .is_ok());
}

#[test]
fn rejects_ssid_containing_newlines_or_carriage_returns() {
    let generator = ConfigGenerator::new();

    let with_newline = ApSettings {
        ssid: "Evil\nSSID".to_string(),
        ..Default::default()
    };
    assert!(generator
        .replace_variables("ssid={SSID}", &with_newline)
        .unwrap_err()
        .to_string()
        .contains("newlines"));

    let with_carriage_return = ApSettings {
        ssid: "Evil\rSSID".to_string(),
        ..Default::default()
    };
    assert!(generator
        .replace_variables("ssid={SSID}", &with_carriage_return)
        .unwrap_err()
        .to_string()
        .contains("newlines"));
}
