use sgx_guardian_client::discovery::whitelist::Whitelist;
use sgx_guardian_client::discovery::{ConnectedDevice, DeviceStatus, OpenPort};

fn sample_device(mac: Option<&str>, os: Option<&str>, ports: Vec<u16>) -> ConnectedDevice {
    ConnectedDevice {
        device_id: "dev-1".to_string(),
        ip: "192.168.50.10".to_string(),
        mac: mac.map(ToString::to_string),
        vendor: Some("Acme".to_string()),
        hostname: Some("host.local".to_string()),
        os_fingerprint: os.map(ToString::to_string),
        os_cpe: Vec::new(),
        open_ports: ports
            .into_iter()
            .map(|p| OpenPort {
                port: p,
                protocol: "tcp".to_string(),
                service: None,
                product_version: None,
                cpe: Vec::new(),
                scripts: Vec::new(),
            })
            .collect(),
        host_scripts: Vec::new(),
        status: DeviceStatus::Unauthorized,
        first_seen: "2026-05-01T00:00:00Z".to_string(),
        last_seen: "2026-05-01T00:00:00Z".to_string(),
        vuln_triaged: false,
        last_scan_intensity: None,
    }
}

fn write_whitelist_yaml(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("whitelist.yaml");
    let yaml = r#"
version: "1.0"
devices:
  - mac: "aa:bb:cc:11:22:33"
    label: "Office printer"
    expected_os: "Linux"
    expected_ports: [9100]
"#;
    std::fs::write(&path, yaml).expect("whitelist fixture should be written");
    path
}

#[test]
fn classify_marks_device_approved_when_whitelist_matches() {
    let dir = tempfile::tempdir().expect("tempdir should be created");
    let path = write_whitelist_yaml(dir.path());
    let wl = Whitelist::load(&path).expect("whitelist should load");

    let mut device = sample_device(Some("AA:BB:CC:11:22:33"), Some("Linux 6.x"), vec![9100, 22]);
    wl.classify(&mut device);

    assert_eq!(device.status, DeviceStatus::Approved);
}

#[test]
fn classify_marks_device_drifted_when_expected_port_missing() {
    let dir = tempfile::tempdir().expect("tempdir should be created");
    let path = write_whitelist_yaml(dir.path());
    let wl = Whitelist::load(&path).expect("whitelist should load");

    let mut device = sample_device(Some("AA:BB:CC:11:22:33"), Some("Linux 6.x"), vec![22]);
    wl.classify(&mut device);

    assert_eq!(device.status, DeviceStatus::Drifted);
}

#[test]
fn classify_marks_device_unauthorized_when_mac_not_whitelisted() {
    let dir = tempfile::tempdir().expect("tempdir should be created");
    let path = write_whitelist_yaml(dir.path());
    let wl = Whitelist::load(&path).expect("whitelist should load");

    let mut device = sample_device(Some("00:11:22:33:44:55"), Some("Linux 6.x"), vec![9100]);
    wl.classify(&mut device);

    assert_eq!(device.status, DeviceStatus::Unauthorized);
}

#[test]
fn classify_rejects_mac_match_when_ip_outside_expected_cidr() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("whitelist.yaml");
    let yaml = r#"
version: "1.0"
devices:
  - mac: "B2:95:75:0E:06:6A"
    label: "Guardian nodeA real entry"
    expected_ips: ["192.168.50.103/32"]
"#;
    std::fs::write(&path, yaml).unwrap();
    let wl = Whitelist::load(&path).unwrap();

    let mut alias_device =
        sample_device(Some("B2:95:75:0E:06:6A"), Some("Linux 6.x"), vec![22, 8443]);
    alias_device.ip = "192.168.50.45".to_string();
    wl.classify(&mut alias_device);
    assert_eq!(alias_device.status, DeviceStatus::Unauthorized);

    let mut real_device = sample_device(Some("B2:95:75:0E:06:6A"), Some("Linux 6.x"), vec![]);
    real_device.ip = "192.168.50.103".to_string();
    wl.classify(&mut real_device);
    assert_eq!(real_device.status, DeviceStatus::Approved);
}

#[test]
fn classify_falls_back_to_mac_only_when_no_expected_ips() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("whitelist.yaml");
    let yaml = r#"
version: "1.0"
devices:
  - mac: "AA:BB:CC:11:22:33"
    label: "Office printer"
"#;
    std::fs::write(&path, yaml).unwrap();
    let wl = Whitelist::load(&path).unwrap();

    let mut device = sample_device(Some("AA:BB:CC:11:22:33"), None, vec![]);
    device.ip = "10.0.0.5".to_string();
    wl.classify(&mut device);
    assert_eq!(device.status, DeviceStatus::Approved);
}
