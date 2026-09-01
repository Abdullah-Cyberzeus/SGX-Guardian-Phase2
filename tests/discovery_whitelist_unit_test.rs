use sgx_guardian_client::discovery::whitelist::{
    enrich_entries, infer_label_for_mac, Whitelist, WhitelistEntry,
};
use sgx_guardian_client::discovery::{ConnectedDevice, DeviceStatus, OpenPort};

fn port(port: u16, service: Option<&str>, version: Option<&str>) -> OpenPort {
    OpenPort {
        port,
        protocol: "tcp".into(),
        service: service.map(str::to_string),
        product_version: version.map(str::to_string),
        cpe: Vec::new(),
        scripts: Vec::new(),
    }
}

fn device(mac: Option<&str>, ip: &str) -> ConnectedDevice {
    ConnectedDevice {
        device_id: format!("dev-{ip}"),
        ip: ip.into(),
        mac: mac.map(str::to_string),
        vendor: Some("Acme".into()),
        hostname: Some("printer".into()),
        os_fingerprint: Some("Linux 5.x".into()),
        os_cpe: Vec::new(),
        open_ports: vec![port(22, Some("ssh"), Some("OpenSSH"))],
        host_scripts: Vec::new(),
        status: DeviceStatus::Unauthorized,
        first_seen: "2026-06-12T00:00:00Z".into(),
        last_seen: "2026-06-12T01:00:00Z".into(),
        vuln_triaged: false,
        last_scan_intensity: None,
    }
}

fn entry() -> WhitelistEntry {
    WhitelistEntry {
        mac: "AA:BB:CC:11:22:33".into(),
        label: Some("Printer".into()),
        expected_os: None,
        expected_ports: Vec::new(),
        expected_ips: Vec::new(),
    }
}

#[test]
fn load_missing_file_returns_empty_whitelist() {
    let dir = tempfile::tempdir().unwrap();
    assert!(Whitelist::load(&dir.path().join("missing.yaml")).unwrap().entries.is_empty());
}

#[test]
fn load_empty_file_returns_empty_whitelist() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("whitelist.yaml");
    std::fs::write(&path, " \n\t").unwrap();
    assert!(Whitelist::load(&path).unwrap().entries.is_empty());
}

#[test]
fn load_yaml_normalizes_mac_key_and_defaults_vectors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("whitelist.yaml");
    std::fs::write(&path, "devices:\n  - mac: ' aa:bb:cc:11:22:33 '\n    label: Printer\n").unwrap();
    let loaded = Whitelist::load(&path).unwrap();
    let entry = loaded.entries.get("AA:BB:CC:11:22:33").unwrap();
    assert_eq!(entry.label.as_deref(), Some("Printer"));
    assert!(entry.expected_ports.is_empty());
    assert!(entry.expected_ips.is_empty());
}

#[test]
fn load_yaml_rejects_malformed_yaml() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("whitelist.yaml");
    std::fs::write(&path, "devices: [").unwrap();
    assert!(Whitelist::load(&path).is_err());
}

#[test]
fn duplicate_mac_last_entry_wins() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("whitelist.yaml");
    std::fs::write(
        &path,
        "devices:\n  - mac: AA:BB:CC:11:22:33\n    label: Old\n  - mac: aa:bb:cc:11:22:33\n    label: New\n",
    )
    .unwrap();
    let loaded = Whitelist::load(&path).unwrap();
    assert_eq!(loaded.entries.len(), 1);
    assert_eq!(
        loaded.entries.get("AA:BB:CC:11:22:33").unwrap().label.as_deref(),
        Some("New")
    );
}

#[test]
fn classify_without_matching_entry_marks_unauthorized() {
    let whitelist = Whitelist::default();
    let mut dev = device(Some("AA:BB:CC:11:22:33"), "192.168.50.103");
    whitelist.classify(&mut dev);
    assert_eq!(dev.status, DeviceStatus::Unauthorized);
}

#[test]
fn classify_missing_mac_marks_unauthorized() {
    let whitelist = Whitelist::default();
    let mut dev = device(None, "192.168.50.103");
    whitelist.classify(&mut dev);
    assert_eq!(dev.status, DeviceStatus::Unauthorized);
}

#[test]
fn classify_matching_mac_approves_without_expectations() {
    let mut whitelist = Whitelist::default();
    whitelist.entries.insert("AA:BB:CC:11:22:33".into(), entry());
    let mut dev = device(Some("aa:bb:cc:11:22:33"), "192.168.50.103");
    whitelist.classify(&mut dev);
    assert_eq!(dev.status, DeviceStatus::Approved);
}

#[test]
fn classify_expected_os_substring_match_approves() {
    let mut wl = entry();
    wl.expected_os = Some("Linux".into());
    let mut whitelist = Whitelist::default();
    whitelist.entries.insert("AA:BB:CC:11:22:33".into(), wl);
    let mut dev = device(Some("AA:BB:CC:11:22:33"), "192.168.50.103");
    whitelist.classify(&mut dev);
    assert_eq!(dev.status, DeviceStatus::Approved);
}

#[test]
fn classify_expected_os_mismatch_drifts() {
    let mut wl = entry();
    wl.expected_os = Some("Windows".into());
    let mut whitelist = Whitelist::default();
    whitelist.entries.insert("AA:BB:CC:11:22:33".into(), wl);
    let mut dev = device(Some("AA:BB:CC:11:22:33"), "192.168.50.103");
    whitelist.classify(&mut dev);
    assert_eq!(dev.status, DeviceStatus::Drifted);
}

#[test]
fn classify_missing_expected_port_drifts() {
    let mut wl = entry();
    wl.expected_ports = vec![22, 443];
    let mut whitelist = Whitelist::default();
    whitelist.entries.insert("AA:BB:CC:11:22:33".into(), wl);
    let mut dev = device(Some("AA:BB:CC:11:22:33"), "192.168.50.103");
    whitelist.classify(&mut dev);
    assert_eq!(dev.status, DeviceStatus::Drifted);
}

#[test]
fn classify_all_expected_ports_present_approves() {
    let mut wl = entry();
    wl.expected_ports = vec![22];
    let mut whitelist = Whitelist::default();
    whitelist.entries.insert("AA:BB:CC:11:22:33".into(), wl);
    let mut dev = device(Some("AA:BB:CC:11:22:33"), "192.168.50.103");
    whitelist.classify(&mut dev);
    assert_eq!(dev.status, DeviceStatus::Approved);
}

#[test]
fn classify_expected_exact_ip_match_approves() {
    let mut wl = entry();
    wl.expected_ips = vec!["192.168.50.103".into()];
    let mut whitelist = Whitelist::default();
    whitelist.entries.insert("AA:BB:CC:11:22:33".into(), wl);
    let mut dev = device(Some("AA:BB:CC:11:22:33"), "192.168.50.103");
    whitelist.classify(&mut dev);
    assert_eq!(dev.status, DeviceStatus::Approved);
}

#[test]
fn classify_expected_cidr_match_approves() {
    let mut wl = entry();
    wl.expected_ips = vec!["192.168.50.0/24".into()];
    let mut whitelist = Whitelist::default();
    whitelist.entries.insert("AA:BB:CC:11:22:33".into(), wl);
    let mut dev = device(Some("AA:BB:CC:11:22:33"), "192.168.50.103");
    whitelist.classify(&mut dev);
    assert_eq!(dev.status, DeviceStatus::Approved);
}

#[test]
fn classify_expected_ip_mismatch_marks_unauthorized() {
    let mut wl = entry();
    wl.expected_ips = vec!["10.0.0.1".into(), "bad-cidr".into()];
    let mut whitelist = Whitelist::default();
    whitelist.entries.insert("AA:BB:CC:11:22:33".into(), wl);
    let mut dev = device(Some("AA:BB:CC:11:22:33"), "192.168.50.103");
    whitelist.classify(&mut dev);
    assert_eq!(dev.status, DeviceStatus::Unauthorized);
}

#[test]
fn enrich_entries_attaches_matching_inventory_snapshot() {
    let views = enrich_entries(&[entry()], &[device(Some("AA:BB:CC:11:22:33"), "192.168.50.103")]);
    assert!(views[0].inventory_match);
    assert_eq!(views[0].current_devices[0].open_ports, vec!["22/tcp ssh (OpenSSH)"]);
}

#[test]
fn enrich_entries_sorts_matches_by_last_seen_desc_then_ip() {
    let mut a = device(Some("AA:BB:CC:11:22:33"), "192.168.50.20");
    a.last_seen = "2026-06-12T02:00:00Z".into();
    let mut b = device(Some("AA:BB:CC:11:22:33"), "192.168.50.10");
    b.last_seen = "2026-06-12T02:00:00Z".into();
    let mut c = device(Some("AA:BB:CC:11:22:33"), "192.168.50.200");
    c.last_seen = "2026-06-12T01:00:00Z".into();
    let views = enrich_entries(&[entry()], &[a, b, c]);
    assert_eq!(
        views[0].current_devices.iter().map(|d| d.ip.as_str()).collect::<Vec<_>>(),
        vec!["192.168.50.10", "192.168.50.20", "192.168.50.200"]
    );
}

#[test]
fn infer_label_prefers_vendor_then_hostname_then_ip() {
    let dev = device(Some("AA:BB:CC:11:22:33"), "192.168.50.103");
    assert_eq!(infer_label_for_mac("AA:BB:CC:11:22:33", &[dev]), Some("Acme".into()));
    let mut host = device(Some("AA:BB:CC:11:22:33"), "192.168.50.104");
    host.vendor = Some(" ".into());
    assert_eq!(infer_label_for_mac("AA:BB:CC:11:22:33", &[host]), Some("printer".into()));
    let mut ip = device(Some("AA:BB:CC:11:22:33"), "192.168.50.105");
    ip.vendor = None;
    ip.hostname = Some(" ".into());
    assert_eq!(infer_label_for_mac("AA:BB:CC:11:22:33", &[ip]), Some("192.168.50.105".into()));
}
