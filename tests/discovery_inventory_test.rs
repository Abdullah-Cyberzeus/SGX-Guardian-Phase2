use sgx_guardian_client::discovery::{
    config::{ScanIntensity, ScanSemantics},
    connected_device::{ConnectedDevice, DeviceStatus, OpenPort},
    inventory::Inventory,
};
use tempfile::tempdir;

fn test_device(id: &str, ip: &str, status: DeviceStatus) -> ConnectedDevice {
    ConnectedDevice {
        device_id: id.to_string(),
        ip: ip.to_string(),
        mac: Some("AA:BB:CC:11:22:33".to_string()),
        vendor: Some("TestVendor".to_string()),
        hostname: Some("test-device".to_string()),
        os_fingerprint: Some("Linux".to_string()),
        os_cpe: Vec::new(),
        open_ports: vec![OpenPort {
            port: 22,
            protocol: "tcp".to_string(),
            service: Some("ssh".to_string()),
            product_version: Some("OpenSSH".to_string()),
            cpe: Vec::new(),
            scripts: Vec::new(),
        }],
        host_scripts: Vec::new(),
        status,
        first_seen: "2026-05-11T00:00:00Z".to_string(),
        last_seen: "2026-05-11T00:00:00Z".to_string(),
        vuln_triaged: false,
    }
}

#[test]
fn inventory_adds_new_device() {
    let mut inv = Inventory::default();

    let delta = inv.merge(
        vec![test_device(
            "dev-1",
            "192.168.1.10",
            DeviceStatus::Unauthorized,
        )],
        ScanSemantics::for_intensity(ScanIntensity::Standard),
    );

    assert_eq!(delta.newly_seen, vec!["dev-1"]);
    assert!(delta.updated.is_empty());
    assert!(delta.marked_stale.is_empty());
    assert!(inv.by_id.contains_key("dev-1"));
}

#[test]
fn inventory_updates_existing_device_without_duplicate() {
    let mut inv = Inventory::default();

    inv.merge(
        vec![test_device(
            "dev-1",
            "192.168.1.10",
            DeviceStatus::Unauthorized,
        )],
        ScanSemantics::for_intensity(ScanIntensity::Standard),
    );

    let mut updated = test_device("dev-1", "192.168.1.20", DeviceStatus::Approved);
    updated.hostname = Some("updated-hostname".to_string());

    let delta = inv.merge(
        vec![updated],
        ScanSemantics::for_intensity(ScanIntensity::Standard),
    );

    assert!(delta.newly_seen.is_empty());
    assert_eq!(delta.updated, vec!["dev-1"]);
    assert_eq!(inv.by_id.len(), 1);

    let dev = inv.by_id.get("dev-1").unwrap();
    assert_eq!(dev.ip, "192.168.1.20");
    assert_eq!(dev.hostname.as_deref(), Some("updated-hostname"));
    assert_eq!(dev.status, DeviceStatus::Unauthorized);
}

#[test]
fn inventory_marks_device_stale_after_three_missed_scans() {
    let mut inv = Inventory::default();

    inv.merge(
        vec![test_device("dev-1", "192.168.1.10", DeviceStatus::Approved)],
        ScanSemantics::for_intensity(ScanIntensity::Standard),
    );

    let d1 = inv.merge(
        vec![],
        ScanSemantics::for_intensity(ScanIntensity::Standard),
    );
    assert!(d1.marked_stale.is_empty());

    let d2 = inv.merge(
        vec![],
        ScanSemantics::for_intensity(ScanIntensity::Standard),
    );
    assert!(d2.marked_stale.is_empty());

    let d3 = inv.merge(
        vec![],
        ScanSemantics::for_intensity(ScanIntensity::Standard),
    );
    assert_eq!(d3.marked_stale, vec!["dev-1"]);

    let dev = inv.by_id.get("dev-1").unwrap();
    assert_eq!(dev.status, DeviceStatus::Stale);
}

#[test]
fn inventory_save_and_load_roundtrip_works() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("inventory.json");

    let mut inv = Inventory::default();
    inv.merge(
        vec![test_device(
            "dev-1",
            "192.168.1.10",
            DeviceStatus::Unauthorized,
        )],
        ScanSemantics::for_intensity(ScanIntensity::Standard),
    );

    inv.save_atomic(&path).unwrap();

    assert!(path.exists());
    assert!(!path.with_extension("json.tmp").exists());

    let loaded = Inventory::load(&path).unwrap();

    assert_eq!(loaded.by_id.len(), 1);
    assert!(loaded.by_id.contains_key("dev-1"));
    assert_eq!(loaded.by_id.get("dev-1").unwrap().ip, "192.168.1.10");
}

#[test]
fn inventory_load_missing_file_returns_empty_inventory() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("missing_inventory.json");

    let inv = Inventory::load(&path).unwrap();

    assert!(inv.by_id.is_empty());
}
