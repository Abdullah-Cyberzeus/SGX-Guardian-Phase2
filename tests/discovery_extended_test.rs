// tests/discovery_extended_test.rs
// Integration tests for src/discovery (whitelist and CIDR checking)

use sgx_guardian_client::discovery::connected_device::{ConnectedDevice, DeviceStatus};
use sgx_guardian_client::discovery::whitelist::{Whitelist, WhitelistEntry};
use std::collections::HashMap;

fn create_device(ip: &str, mac: Option<&str>) -> ConnectedDevice {
    ConnectedDevice {
        device_id: ConnectedDevice::compute_id(ip, mac),
        ip: ip.to_string(),
        mac: mac.map(|s| s.to_string()),
        vendor: None,
        hostname: None,
        os_fingerprint: None,
        os_cpe: vec![],
        open_ports: vec![],
        host_scripts: vec![],
        first_seen: chrono::Utc::now().to_rfc3339(),
        last_seen: chrono::Utc::now().to_rfc3339(),
        status: DeviceStatus::Unauthorized, // Set as unauthorized by default
        vuln_triaged: false,
    }
}

#[test]
fn test_whitelist_classification_mac_not_in_whitelist() {
    let wl = Whitelist::default(); // empty
    let mut dev = create_device("192.168.1.5", Some("AA:BB:CC:DD:EE:FF"));

    wl.classify(&mut dev);
    assert_eq!(dev.status, DeviceStatus::Unauthorized);
}

#[test]
fn test_whitelist_classification_mac_approved() {
    let mut entries = HashMap::new();
    entries.insert(
        "AA:BB:CC:DD:EE:FF".to_string(),
        WhitelistEntry {
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            label: None,
            expected_os: None,
            expected_ports: vec![],
            expected_ips: vec![], // No IP binding
        },
    );
    let wl = Whitelist { entries };

    let mut dev = create_device("192.168.1.5", Some("aa:bb:cc:dd:ee:ff")); // lower-case MAC should match

    wl.classify(&mut dev);
    assert_eq!(dev.status, DeviceStatus::Approved);
}

#[test]
fn test_whitelist_classification_with_expected_ip_match() {
    let mut entries = HashMap::new();
    entries.insert(
        "AA:BB:CC:DD:EE:FF".to_string(),
        WhitelistEntry {
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            label: None,
            expected_os: None,
            expected_ports: vec![],
            expected_ips: vec!["10.0.0.5".to_string()], // Exact IP match
        },
    );
    let wl = Whitelist { entries };

    let mut dev = create_device("10.0.0.5", Some("AA:BB:CC:DD:EE:FF"));
    wl.classify(&mut dev);
    assert_eq!(dev.status, DeviceStatus::Approved);
}

#[test]
fn test_whitelist_classification_with_expected_ip_mismatch() {
    let mut entries = HashMap::new();
    entries.insert(
        "AA:BB:CC:DD:EE:FF".to_string(),
        WhitelistEntry {
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            label: None,
            expected_os: None,
            expected_ports: vec![],
            expected_ips: vec!["10.0.0.5".to_string()], // Exact IP match
        },
    );
    let wl = Whitelist { entries };

    let mut dev = create_device("10.0.0.6", Some("AA:BB:CC:DD:EE:FF"));
    wl.classify(&mut dev);
    assert_eq!(dev.status, DeviceStatus::Unauthorized);
}

#[test]
fn test_whitelist_classification_with_cidr_match() {
    let mut entries = HashMap::new();
    entries.insert(
        "AA:BB:CC:DD:EE:FF".to_string(),
        WhitelistEntry {
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            label: None,
            expected_os: None,
            expected_ports: vec![],
            expected_ips: vec!["192.168.50.0/24".to_string()], // CIDR match
        },
    );
    let wl = Whitelist { entries };

    let mut dev = create_device("192.168.50.103", Some("AA:BB:CC:DD:EE:FF"));
    wl.classify(&mut dev);
    assert_eq!(dev.status, DeviceStatus::Approved);
}

#[test]
fn test_whitelist_classification_with_cidr_mismatch() {
    let mut entries = HashMap::new();
    entries.insert(
        "AA:BB:CC:DD:EE:FF".to_string(),
        WhitelistEntry {
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            label: None,
            expected_os: None,
            expected_ports: vec![],
            expected_ips: vec!["192.168.50.0/24".to_string()], // CIDR match
        },
    );
    let wl = Whitelist { entries };

    let mut dev = create_device("192.168.51.103", Some("AA:BB:CC:DD:EE:FF")); // different subnet
    wl.classify(&mut dev);
    assert_eq!(dev.status, DeviceStatus::Unauthorized);
}
