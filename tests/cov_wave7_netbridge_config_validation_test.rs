use sgx_guardian_client::netbridge::config::{ConfigGenerator, DnsmasqConfigGenerator};
use sgx_guardian_client::netbridge::leases::LeaseManager;
use sgx_guardian_client::netbridge::types::{
    ApSettings, ApStatus, BootstrapOptions, DhcpLeaseState, DnsmasqSettings, NetbridgeError,
    ProcessStatus, UplinkState, ValidationResult, WifiClientSettings, WifiClientState, WifiNetwork,
};
use sgx_guardian_client::netbridge::validator::{ValidationError, Validator};
use sgx_guardian_client::netbridge::wpa_config::WpaConfigGenerator;
use sgx_guardian_client::runtime::models::SavedWifi;
use std::error::Error;
use std::fs;
use std::io;
use tempfile::tempdir;

fn saved_wifi(ssid: &str, password: Option<&str>, bssid: Option<&str>) -> SavedWifi {
    SavedWifi {
        ssid: ssid.to_string(),
        password: password.map(str::to_string),
        bssid: bssid.map(str::to_string),
    }
}

fn generate_wpa(settings: WifiClientSettings) -> Result<String, NetbridgeError> {
    let dir = tempdir().unwrap();
    let template = dir.path().join("wpa.template");
    let output = dir.path().join("nested/wpa.conf");
    fs::write(&template, "ctrl_interface=/run/wpa\ncountry={COUNTRY}\n").unwrap();
    WpaConfigGenerator.generate(template, output, &settings)
}

#[test]
fn netbridge_defaults_and_validation_result_cover_all_boolean_paths() {
    let ap = ApSettings::default();
    assert_eq!(ap.interface, "ap0");
    assert_eq!(ap.ssid, "ARMIA");
    assert_eq!(ap.wpa_passphrase.as_deref(), Some("P@ssword123"));
    assert_eq!((ap.channel, ap.hw_mode.as_str()), (6, "g"));
    assert_eq!(ap.country_code, "US");
    assert!(ap.client_isolation);

    let dns = DnsmasqSettings::default();
    assert_eq!(dns.interface, "ap0");
    assert_eq!(dns.gateway_ip, "192.168.200.1");
    assert_eq!(dns.dhcp_range_start, "192.168.200.100");
    assert_eq!(dns.dhcp_range_end, "192.168.200.254");
    assert!(!dns.local_domain.trim().is_empty());

    let bootstrap = BootstrapOptions::default();
    assert_eq!(bootstrap.runtime_dir, "/tmp/netbridge");
    assert!(bootstrap.template_path.ends_with("hostapd.conf.template"));
    assert!(bootstrap.output_config_path.ends_with("hostapd.conf"));

    let wifi = WifiClientSettings::default();
    assert_eq!(wifi.interface, "wlan1");
    assert_eq!(wifi.country, "US");
    assert!(wifi.networks.is_empty());

    let mut result = ValidationResult {
        interface_detected: true,
        ap_mode_supported: true,
        hostapd_installed: true,
        iw_installed: true,
    };
    assert!(result.is_valid());
    result.interface_detected = false;
    assert!(!result.is_valid());
    result.interface_detected = true;
    result.ap_mode_supported = false;
    assert!(!result.is_valid());
    result.ap_mode_supported = true;
    result.hostapd_installed = false;
    assert!(!result.is_valid());
    result.hostapd_installed = true;
    result.iw_installed = false;
    assert!(!result.is_valid());
}

#[test]
fn netbridge_public_states_and_wifi_network_have_stable_contracts() {
    assert_eq!(ProcessStatus::Starting, ProcessStatus::Starting);
    assert_ne!(ProcessStatus::Running, ProcessStatus::Stopped);
    assert_ne!(ProcessStatus::Stopped, ProcessStatus::Crashed);
    assert_eq!(ApStatus::Inactive, ApStatus::Inactive);
    assert_ne!(ApStatus::Initializing, ApStatus::Active);
    assert_eq!(
        ApStatus::Error("down".into()),
        ApStatus::Error("down".into())
    );
    assert_ne!(UplinkState::Unknown, UplinkState::Connected);
    assert_ne!(UplinkState::Disconnected, UplinkState::NoInternet);
    assert_ne!(WifiClientState::Disconnected, WifiClientState::Scanning);
    assert_ne!(WifiClientState::Authenticating, WifiClientState::Connected);
    assert_ne!(WifiClientState::AuthFailed, WifiClientState::Connected);
    assert_ne!(DhcpLeaseState::Unknown, DhcpLeaseState::Requesting);
    assert_ne!(DhcpLeaseState::Bound, DhcpLeaseState::Renewing);
    assert_ne!(DhcpLeaseState::Expired, DhcpLeaseState::Bound);

    let network = WifiNetwork {
        ssid: "Cafe".into(),
        bssid: "aa:bb:cc:dd:ee:ff".into(),
        signal_dbm: -54,
        band: "5GHz".into(),
        security: "WPA2".into(),
    };
    let json = serde_json::to_string(&network).unwrap();
    assert_eq!(serde_json::from_str::<WifiNetwork>(&json).unwrap(), network);
}

#[test]
fn netbridge_error_display_from_io_and_source_are_stable() {
    let cases = [
        (
            NetbridgeError::ValidationFailed("bad input".into()),
            "Validation Failed: bad input",
        ),
        (
            NetbridgeError::ConfigGenerationFailed("bad config".into()),
            "Config Generation Failed: bad config",
        ),
        (
            NetbridgeError::ProcessExecutionFailed("exit 1".into()),
            "Process Execution Failed: exit 1",
        ),
        (
            NetbridgeError::BootstrapFailed("setup".into()),
            "Bootstrap Failed: setup",
        ),
        (
            NetbridgeError::MissingDependency("iw".into()),
            "Missing Dependency: iw",
        ),
        (
            NetbridgeError::TemplateError("missing".into()),
            "Template Error: missing",
        ),
        (
            NetbridgeError::ConnectionFailed("offline".into()),
            "Connection Failed: offline",
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
        assert!(error.source().is_none());
    }

    let error: NetbridgeError = io::Error::new(io::ErrorKind::NotFound, "gone").into();
    assert_eq!(error.to_string(), "IO Error: gone");
    assert!(error.source().is_none());
}

#[test]
fn validation_error_display_covers_every_variant() {
    let cases = [
        (
            ValidationError::CommandExecutionFailed("iw dev".into()),
            "Failed to execute command: iw dev",
        ),
        (
            ValidationError::InterfaceNotFound,
            "No WiFi interface found",
        ),
        (
            ValidationError::APModeNotSupported,
            "WiFi interface does not support AP mode",
        ),
        (
            ValidationError::HostapdNotInstalled,
            "hostapd is not installed",
        ),
        (ValidationError::IwNotInstalled, "iw is not installed"),
        (
            ValidationError::DnsmasqNotInstalled,
            "dnsmasq is not installed",
        ),
        (
            ValidationError::PortInUse(53),
            "Port 53 is already in use by another service",
        ),
        (
            ValidationError::WpaSupplicantNotInstalled,
            "wpa_supplicant is not installed",
        ),
        (
            ValidationError::UdhcpcNotInstalled,
            "udhcpc is not installed",
        ),
        (
            ValidationError::InterfaceNotAvailable("wlan9".into()),
            "Interface wlan9 is not available or does not exist",
        ),
        (
            ValidationError::PermissionDenied,
            "Root permissions required to initialize network interfaces",
        ),
        (
            ValidationError::ClientModeNotSupported,
            "WiFi interface does not support managed (client) mode",
        ),
        (
            ValidationError::InterfaceBusy("wlan0".into()),
            "Interface wlan0 is currently busy or managed by another wpa_supplicant process",
        ),
        (
            ValidationError::ScanFailed("wlan1".into()),
            "Hardware WiFi scan failed on interface wlan1",
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
        assert!(error.source().is_none());
    }
    let _ = Validator::new();
    let _ = Validator;
}

#[test]
fn hostapd_replacement_covers_secure_open_and_all_placeholders() {
    let template = concat!(
        "interface={INTERFACE}\nssid={SSID}\nchannel={CHANNEL}\n",
        "hw_mode={HW_MODE}\ncountry={COUNTRY_CODE}\nwpa={WPA}\n",
        "wpa_passphrase={WPA_PASSPHRASE}\nwpa_key_mgmt={WPA_KEY_MGMT}\n",
        "wpa_pairwise={WPA_PAIRWISE}\nrsn_pairwise={RSN_PAIRWISE}\n",
    );
    let generator = ConfigGenerator;
    let secure = generator
        .replace_variables(
            template,
            &ApSettings {
                interface: "uap0".into(),
                ssid: "Guardian".into(),
                wpa_passphrase: Some("12345678".into()),
                channel: 11,
                hw_mode: "a".into(),
                country_code: "CA".into(),
                client_isolation: false,
            },
        )
        .unwrap();
    for expected in [
        "interface=uap0",
        "ssid=Guardian",
        "channel=11",
        "hw_mode=a",
        "country=CA",
        "wpa=2",
        "wpa_passphrase=12345678",
        "wpa_key_mgmt=WPA-PSK",
        "wpa_pairwise=CCMP",
        "rsn_pairwise=CCMP",
    ] {
        assert!(secure.contains(expected), "missing {expected}");
    }

    let open = generator
        .replace_variables(
            template,
            &ApSettings {
                wpa_passphrase: None,
                ..ApSettings::default()
            },
        )
        .unwrap();
    assert!(open.contains("wpa=0\n"));
    assert!(open.contains("wpa_passphrase=\n"));
    assert!(open.contains("wpa_key_mgmt=\n"));
    assert!(open.contains("wpa_pairwise=\n"));
    assert!(open.contains("rsn_pairwise=\n"));
}

#[test]
fn hostapd_validation_rejects_ssid_and_passphrase_boundaries() {
    let generator = ConfigGenerator::new();
    let invalid = [
        (
            "bad\nssid".to_string(),
            Some("password".to_string()),
            "SSID cannot contain newlines",
        ),
        (
            "x".repeat(33),
            Some("password".to_string()),
            "SSID must be at most 32 bytes",
        ),
        (
            "ok".to_string(),
            Some("1234567".to_string()),
            "WPA passphrase must be 8-63 characters",
        ),
        (
            "ok".to_string(),
            Some("x".repeat(64)),
            "WPA passphrase must be 8-63 characters",
        ),
        (
            "ok".to_string(),
            Some("password\r".to_string()),
            "WPA passphrase cannot contain newlines",
        ),
    ];
    for (ssid, wpa_passphrase, message) in invalid {
        let error = generator
            .replace_variables(
                "{SSID}:{WPA_PASSPHRASE}",
                &ApSettings {
                    ssid,
                    wpa_passphrase,
                    ..ApSettings::default()
                },
            )
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("Config Generation Failed: {message}")
        );
    }
}

#[test]
fn hostapd_and_dnsmasq_generators_create_parents_and_report_io_errors() {
    let dir = tempdir().unwrap();
    let host_template = dir.path().join("host.template");
    let host_output = dir.path().join("deep/hostapd/hostapd.conf");
    fs::write(&host_template, "ssid={SSID}\n").unwrap();
    let host = ConfigGenerator::new();
    assert_eq!(host.read_template(&host_template).unwrap(), "ssid={SSID}\n");
    host.generate_config(&host_template, &host_output, &ApSettings::default())
        .unwrap();
    assert_eq!(fs::read_to_string(host_output).unwrap(), "ssid=ARMIA\n");
    assert!(host.read_template(dir.path().join("absent")).is_err());
    assert!(host
        .generate_config(&host_template, dir.path(), &ApSettings::default())
        .is_err());

    let dns_template = dir.path().join("dns.template");
    let dns_output = dir.path().join("deep/dns/dnsmasq.conf");
    fs::write(
        &dns_template,
        "{INTERFACE}|{GATEWAY_IP}|{DHCP_RANGE_START}|{DHCP_RANGE_END}|{LOCAL_DOMAIN}",
    )
    .unwrap();
    let dns = DnsmasqConfigGenerator;
    assert!(dns
        .read_template(&dns_template)
        .unwrap()
        .contains("{INTERFACE}"));
    let dns_settings = DnsmasqSettings {
        local_domain: "guardian.local".into(),
        ..DnsmasqSettings::default()
    };
    dns.generate_config(&dns_template, &dns_output, &dns_settings)
        .unwrap();
    assert_eq!(
        fs::read_to_string(dns_output).unwrap(),
        "ap0|192.168.200.1|192.168.200.100|192.168.200.254|guardian.local"
    );
    assert!(dns.read_template(dir.path().join("missing-dns")).is_err());
    assert!(dns
        .generate_config(&dns_template, dir.path(), &dns_settings)
        .is_err());
}

#[test]
fn wpa_generator_handles_multiple_open_secure_and_optional_fields() {
    let dir = tempdir().unwrap();
    let template = dir.path().join("wpa.template");
    let output = dir.path().join("nested/config/wpa.conf");
    fs::write(&template, "country={COUNTRY}\n").unwrap();
    let settings = WifiClientSettings {
        interface: "wlan7".into(),
        country: "GB".into(),
        networks: vec![
            saved_wifi("Secure", Some("password"), Some("AA:bb:01:23:CD:ef")),
            saved_wifi("Blank", Some("   "), Some("")),
            saved_wifi("Open", None, None),
        ],
    };
    let returned = WpaConfigGenerator::new()
        .generate(&template, &output, &settings)
        .unwrap();
    assert_eq!(returned, output.to_string_lossy());
    let content = fs::read_to_string(output).unwrap();
    assert!(content.starts_with("country=GB\n"));
    assert_eq!(content.matches("network={").count(), 3);
    assert!(content.contains("psk=\"password\""));
    assert!(content.contains("bssid=AA:bb:01:23:CD:ef"));
    assert_eq!(content.matches("key_mgmt=NONE").count(), 2);
    assert_eq!(content.matches("bssid=").count(), 1);
}

#[test]
fn wpa_generator_rejects_country_ssid_password_and_bssid_inputs() {
    let cases = [
        (
            "U".to_string(),
            saved_wifi("ok", None, None),
            "Country code must be 2 ASCII letters",
        ),
        (
            "12".to_string(),
            saved_wifi("ok", None, None),
            "Country code must be 2 ASCII letters",
        ),
        (
            "US".to_string(),
            saved_wifi("bad\nssid", None, None),
            "SSID cannot contain newlines",
        ),
        (
            "US".to_string(),
            saved_wifi(&"x".repeat(33), None, None),
            "SSID must be at most 32 bytes",
        ),
        (
            "US".to_string(),
            saved_wifi("ok", Some("short"), None),
            "WPA passphrase must be 8-63 characters",
        ),
        (
            "US".to_string(),
            saved_wifi("ok", Some(&"x".repeat(64)), None),
            "WPA passphrase must be 8-63 characters",
        ),
        (
            "US".to_string(),
            saved_wifi("ok", Some("password\n"), None),
            "WPA passphrase cannot contain newlines",
        ),
        (
            "US".to_string(),
            saved_wifi("ok", None, Some("not-a-mac")),
            "Invalid BSSID format: not-a-mac",
        ),
        (
            "US".to_string(),
            saved_wifi("ok", None, Some("aa:bb:cc:dd:ee:gg")),
            "Invalid BSSID format: aa:bb:cc:dd:ee:gg",
        ),
    ];
    for (country, network, expected) in cases {
        let error = generate_wpa(WifiClientSettings {
            interface: "wlan1".into(),
            country,
            networks: vec![network],
        })
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("Config Generation Failed: {expected}")
        );
    }

    let dir = tempdir().unwrap();
    let error = WpaConfigGenerator::new()
        .generate(
            dir.path().join("missing-template"),
            dir.path().join("out"),
            &WifiClientSettings::default(),
        )
        .unwrap_err();
    assert!(error
        .to_string()
        .starts_with("Template Error: Failed to read"));

    let template = dir.path().join("valid-template");
    fs::write(&template, "country={COUNTRY}\n").unwrap();
    let write_error = WpaConfigGenerator::new()
        .generate(&template, dir.path(), &WifiClientSettings::default())
        .unwrap_err();
    assert!(write_error
        .to_string()
        .starts_with("Config Generation Failed: Failed to write"));
}

#[test]
fn lease_manager_parses_invalid_expiry_extra_fields_and_unreadable_paths() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("leases");
    fs::write(
        &path,
        concat!(
            "invalid aa:bb:cc:dd:ee:ff 10.0.0.2 host client extra\n",
            "123 aa:bb:cc:dd:ee:00 10.0.0.3 other *\n",
            "too few fields\n",
        ),
    )
    .unwrap();
    let leases = LeaseManager::new(path.to_str().unwrap())
        .get_active_leases()
        .unwrap();
    assert_eq!(leases.len(), 2);
    assert_eq!(leases[0].expiry, 0);
    assert_eq!(leases[0].hostname, "host");
    assert_eq!(leases[0].client_id, "client");
    assert_eq!(leases[1].expiry, 123);

    let json = serde_json::to_value(&leases[0]).unwrap();
    assert_eq!(json["ip_address"], "10.0.0.2");
    assert_eq!(json["mac_address"], "aa:bb:cc:dd:ee:ff");

    let missing = LeaseManager::new(dir.path().join("missing").to_str().unwrap());
    assert!(missing.get_active_leases().unwrap().is_empty());
    let directory = LeaseManager::new(dir.path().to_str().unwrap());
    assert!(directory.get_active_leases().is_err());
    let _ = LeaseManager::default();
}
