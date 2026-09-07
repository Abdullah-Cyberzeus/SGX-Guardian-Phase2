use crate::discovery::{
    connected_device::{ConnectedDevice, DeviceStatus, OpenPort},
    error::DiscoveryResult,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WhitelistEntry {
    pub mac: String,
    pub label: Option<String>,
    pub expected_os: Option<String>,
    #[serde(default)]
    pub expected_ports: Vec<u16>,
    /// Optional IPs/CIDRs this MAC is allowed to appear on.
    /// Empty = backward-compatible MAC-only match.
    /// Non-empty = STRICT: device IP must fall inside one of these to be Approved.
    /// Recommended for any whitelist deployed on a routed/multi-subnet network,
    /// where NMAP may report the gateway MAC for off-link IPs.
    #[serde(default)]
    pub expected_ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WhitelistInventoryDevice {
    pub device_id: String,
    pub ip: String,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub status: DeviceStatus,
    pub os_fingerprint: Option<String>,
    pub open_ports: Vec<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub vuln_triaged: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WhitelistEntryView {
    #[serde(flatten)]
    pub entry: WhitelistEntry,
    pub inventory_match: bool,
    pub current_devices: Vec<WhitelistInventoryDevice>,
}

#[derive(Debug, Clone, Default)]
pub struct Whitelist {
    pub entries: HashMap<String, WhitelistEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WhitelistFile {
    #[serde(default = "default_version")]
    version: String,
    #[serde(default)]
    devices: Vec<WhitelistEntry>,
}

fn default_version() -> String {
    "1.0".to_string()
}

impl Default for WhitelistFile {
    fn default() -> Self {
        Self {
            version: default_version(),
            devices: Vec::new(),
        }
    }
}

impl Whitelist {
    pub fn load(path: &Path) -> DiscoveryResult<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let text = std::fs::read_to_string(path)?;
        if text.trim().is_empty() {
            return Ok(Self::default());
        }

        let parsed: WhitelistFile = serde_yaml::from_str(&text)?;
        let _ = parsed.version;

        let mut entries = HashMap::with_capacity(parsed.devices.len());
        for entry in parsed.devices {
            let key = normalize_mac(&entry.mac);
            entries.insert(key, entry);
        }

        Ok(Self { entries })
    }

    pub fn classify(&self, dev: &mut ConnectedDevice) {
        let mac_key = dev.mac.as_deref().map(normalize_mac);
        match mac_key.as_deref().and_then(|m| self.entries.get(m)) {
            None => dev.status = DeviceStatus::Unauthorized,
            Some(wl) => {
                // === FIX #3: enforce IP binding if expected_ips is set ===
                // Whitelist entries that list expected_ips REQUIRE the device's IP
                // to be inside one of those CIDRs. This prevents a gateway MAC
                // (reported by NMAP for off-link hosts) from auto-approving every
                // IP that happens to share that MAC.
                if !wl.expected_ips.is_empty() {
                    let ip_ok = wl
                        .expected_ips
                        .iter()
                        .any(|cidr| cidr_or_ip_contains(cidr, &dev.ip));
                    if !ip_ok {
                        dev.status = DeviceStatus::Unauthorized;
                        return;
                    }
                }

                let os_match = match (&wl.expected_os, &dev.os_fingerprint) {
                    (Some(expected), Some(got)) => got.contains(expected),
                    _ => true,
                };
                let port_match = wl
                    .expected_ports
                    .iter()
                    .all(|p| dev.open_ports.iter().any(|op| op.port == *p));
                dev.status = if os_match && port_match {
                    DeviceStatus::Approved
                } else {
                    DeviceStatus::Drifted
                };
            }
        }
    }
}

pub fn enrich_entries(
    entries: &[WhitelistEntry],
    inventory: &[ConnectedDevice],
) -> Vec<WhitelistEntryView> {
    entries
        .iter()
        .cloned()
        .map(|entry| {
            let mut current_devices = inventory
                .iter()
                .filter(|device| device_matches_entry(&entry, device))
                .map(inventory_device_view)
                .collect::<Vec<_>>();

            current_devices.sort_by(|left, right| {
                right
                    .last_seen
                    .cmp(&left.last_seen)
                    .then_with(|| left.ip.cmp(&right.ip))
            });

            WhitelistEntryView {
                entry,
                inventory_match: !current_devices.is_empty(),
                current_devices,
            }
        })
        .collect()
}

pub fn infer_label_for_mac(mac: &str, inventory: &[ConnectedDevice]) -> Option<String> {
    let entry = WhitelistEntry {
        mac: mac.to_string(),
        label: None,
        expected_os: None,
        expected_ports: Vec::new(),
        expected_ips: Vec::new(),
    };

    let mut matches = inventory
        .iter()
        .filter(|device| device_matches_entry(&entry, device))
        .collect::<Vec<_>>();

    matches.sort_by(|left, right| {
        let left_stale = matches!(left.status, DeviceStatus::Stale);
        let right_stale = matches!(right.status, DeviceStatus::Stale);
        left_stale
            .cmp(&right_stale)
            .then_with(|| right.last_seen.cmp(&left.last_seen))
    });

    matches.into_iter().find_map(|device| {
        non_empty_clone(&device.vendor)
            .or_else(|| non_empty_clone(&device.hostname))
            .or_else(|| Some(device.ip.clone()))
    })
}

fn device_matches_entry(entry: &WhitelistEntry, device: &ConnectedDevice) -> bool {
    let Some(device_mac) = device.mac.as_deref() else {
        return false;
    };

    normalize_mac(device_mac) == normalize_mac(&entry.mac)
}

fn inventory_device_view(device: &ConnectedDevice) -> WhitelistInventoryDevice {
    WhitelistInventoryDevice {
        device_id: device.device_id.clone(),
        ip: device.ip.clone(),
        vendor: device.vendor.clone(),
        hostname: device.hostname.clone(),
        status: device.status,
        os_fingerprint: device.os_fingerprint.clone(),
        open_ports: device.open_ports.iter().map(format_open_port).collect(),
        first_seen: device.first_seen.clone(),
        last_seen: device.last_seen.clone(),
        vuln_triaged: device.vuln_triaged,
    }
}

fn format_open_port(port: &OpenPort) -> String {
    let mut out = format!("{}/{}", port.port, port.protocol);
    if let Some(service) = port
        .service
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        out.push(' ');
        out.push_str(service);
    }
    if let Some(version) = port
        .product_version
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        out.push_str(" (");
        out.push_str(version);
        out.push(')');
    }
    out
}

fn non_empty_clone(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn normalize_mac(mac: &str) -> String {
    mac.trim().to_uppercase()
}

/// Returns true if `target_ip` is contained in `cidr_or_ip`.
/// Accepts both `"192.168.50.103"` (exact match) and `"192.168.50.0/24"` (subnet).
fn cidr_or_ip_contains(cidr_or_ip: &str, target_ip: &str) -> bool {
    use std::net::IpAddr;

    let ip = match target_ip.parse::<IpAddr>() {
        Ok(v) => v,
        Err(_) => return false,
    };
    if cidr_or_ip.contains('/') {
        // CIDR comparison - minimal in-tree implementation to avoid pulling
        // a new dep just for this. Supports IPv4 only (Phase 2 scope).
        let (net_str, prefix_str) = match cidr_or_ip.rsplit_once('/') {
            Some(v) => v,
            None => return false,
        };
        let prefix: u8 = match prefix_str.parse() {
            Ok(v) if v <= 32 => v,
            _ => return false,
        };
        let net_ip = match net_str.parse::<IpAddr>() {
            Ok(IpAddr::V4(v)) => v,
            _ => return false,
        };
        let target_ip = match ip {
            IpAddr::V4(v) => v,
            _ => return false,
        };
        let mask: u32 = if prefix == 0 {
            0
        } else {
            !0u32 << (32 - prefix)
        };
        let net_u32 = u32::from(net_ip) & mask;
        let tgt_u32 = u32::from(target_ip) & mask;
        net_u32 == tgt_u32
    } else {
        cidr_or_ip == target_ip
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::{ConnectedDevice, DeviceStatus, OpenPort};

    fn device() -> ConnectedDevice {
        ConnectedDevice {
            device_id: "dev-1".into(),
            ip: "192.168.50.103".into(),
            mac: Some("AA:BB:CC:11:22:33".into()),
            vendor: Some("Acme".into()),
            hostname: Some("printer".into()),
            os_fingerprint: Some("Linux 5.x".into()),
            os_cpe: Vec::new(),
            open_ports: vec![OpenPort {
                port: 22,
                protocol: "tcp".into(),
                service: Some("ssh".into()),
                product_version: Some("OpenSSH".into()),
                cpe: Vec::new(),
                scripts: Vec::new(),
            }],
            host_scripts: Vec::new(),
            status: DeviceStatus::Approved,
            first_seen: "2026-06-12T00:00:00Z".into(),
            last_seen: "2026-06-12T01:00:00Z".into(),
            vuln_triaged: false,
            last_scan_intensity: None,
        }
    }

    #[test]
    fn enrich_entries_attaches_current_inventory_snapshot() {
        let entries = vec![WhitelistEntry {
            mac: "AA:BB:CC:11:22:33".into(),
            label: Some("Printer".into()),
            expected_os: None,
            expected_ports: Vec::new(),
            expected_ips: Vec::new(),
        }];

        let views = enrich_entries(&entries, &[device()]);

        assert!(views[0].inventory_match);
        assert_eq!(views[0].current_devices[0].ip, "192.168.50.103");
        assert_eq!(
            views[0].current_devices[0].open_ports,
            vec!["22/tcp ssh (OpenSSH)"]
        );
    }

    #[test]
    fn infer_label_prefers_inventory_vendor() {
        assert_eq!(
            infer_label_for_mac("AA:BB:CC:11:22:33", &[device()]),
            Some("Acme".into())
        );
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
    fn load_missing_and_empty_files_return_empty_whitelist() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(Whitelist::load(&dir.path().join("missing.yaml"))
            .expect("missing")
            .entries
            .is_empty());

        let path = dir.path().join("empty.yaml");
        std::fs::write(&path, " \n\t").expect("write empty");
        assert!(Whitelist::load(&path).expect("empty").entries.is_empty());
    }

    #[test]
    fn load_yaml_applies_defaults_and_normalizes_mac_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("whitelist.yaml");
        std::fs::write(
            &path,
            r#"
devices:
  - mac: " aa:bb:cc:11:22:33 "
    label: Printer
"#,
        )
        .expect("write yaml");
        let whitelist = Whitelist::load(&path).expect("load whitelist");
        let loaded = whitelist
            .entries
            .get("AA:BB:CC:11:22:33")
            .expect("normalized key");
        assert_eq!(loaded.label.as_deref(), Some("Printer"));
        assert!(loaded.expected_ports.is_empty());
        assert!(loaded.expected_ips.is_empty());
    }

    #[test]
    fn load_malformed_yaml_returns_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("whitelist.yaml");
        std::fs::write(&path, "devices: [").expect("write malformed");
        assert!(Whitelist::load(&path).is_err());
    }

    #[test]
    fn duplicate_mac_entries_last_entry_wins() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("whitelist.yaml");
        std::fs::write(
            &path,
            r#"
devices:
  - mac: "AA:BB:CC:11:22:33"
    label: Old
  - mac: "aa:bb:cc:11:22:33"
    label: New
"#,
        )
        .expect("write yaml");
        let whitelist = Whitelist::load(&path).expect("load");
        assert_eq!(whitelist.entries.len(), 1);
        assert_eq!(
            whitelist
                .entries
                .get("AA:BB:CC:11:22:33")
                .unwrap()
                .label
                .as_deref(),
            Some("New")
        );
    }

    #[test]
    fn classify_without_matching_mac_marks_unauthorized() {
        let whitelist = Whitelist {
            entries: HashMap::new(),
        };
        let mut dev = device();
        whitelist.classify(&mut dev);
        assert_eq!(dev.status, DeviceStatus::Unauthorized);

        let mut no_mac = device();
        no_mac.mac = None;
        whitelist.classify(&mut no_mac);
        assert_eq!(no_mac.status, DeviceStatus::Unauthorized);
    }

    #[test]
    fn classify_matching_mac_without_expectations_approves() {
        let mut whitelist = Whitelist::default();
        whitelist
            .entries
            .insert(normalize_mac(&entry().mac), entry());
        let mut dev = device();
        dev.status = DeviceStatus::Unauthorized;
        whitelist.classify(&mut dev);
        assert_eq!(dev.status, DeviceStatus::Approved);
    }

    #[test]
    fn classify_expected_os_mismatch_marks_drifted() {
        let mut whitelist = Whitelist::default();
        let mut wl = entry();
        wl.expected_os = Some("Windows".into());
        whitelist.entries.insert(normalize_mac(&wl.mac), wl);
        let mut dev = device();
        whitelist.classify(&mut dev);
        assert_eq!(dev.status, DeviceStatus::Drifted);
    }

    #[test]
    fn classify_expected_os_substring_match_approves() {
        let mut whitelist = Whitelist::default();
        let mut wl = entry();
        wl.expected_os = Some("Linux".into());
        whitelist.entries.insert(normalize_mac(&wl.mac), wl);
        let mut dev = device();
        whitelist.classify(&mut dev);
        assert_eq!(dev.status, DeviceStatus::Approved);
    }

    #[test]
    fn classify_missing_expected_port_marks_drifted() {
        let mut whitelist = Whitelist::default();
        let mut wl = entry();
        wl.expected_ports = vec![22, 443];
        whitelist.entries.insert(normalize_mac(&wl.mac), wl);
        let mut dev = device();
        whitelist.classify(&mut dev);
        assert_eq!(dev.status, DeviceStatus::Drifted);
    }

    #[test]
    fn classify_expected_ports_all_present_approves() {
        let mut whitelist = Whitelist::default();
        let mut wl = entry();
        wl.expected_ports = vec![22];
        whitelist.entries.insert(normalize_mac(&wl.mac), wl);
        let mut dev = device();
        whitelist.classify(&mut dev);
        assert_eq!(dev.status, DeviceStatus::Approved);
    }

    #[test]
    fn classify_expected_exact_ip_and_cidr_are_enforced() {
        let mut whitelist = Whitelist::default();
        let mut wl = entry();
        wl.expected_ips = vec!["10.0.0.1".into(), "192.168.50.0/24".into()];
        whitelist.entries.insert(normalize_mac(&wl.mac), wl);
        let mut dev = device();
        whitelist.classify(&mut dev);
        assert_eq!(dev.status, DeviceStatus::Approved);
    }

    #[test]
    fn classify_expected_ip_mismatch_marks_unauthorized_before_drift_checks() {
        let mut whitelist = Whitelist::default();
        let mut wl = entry();
        wl.expected_os = Some("Windows".into());
        wl.expected_ips = vec!["10.0.0.1".into()];
        whitelist.entries.insert(normalize_mac(&wl.mac), wl);
        let mut dev = device();
        whitelist.classify(&mut dev);
        assert_eq!(dev.status, DeviceStatus::Unauthorized);
    }

    #[test]
    fn cidr_or_ip_contains_handles_boundaries_and_invalid_inputs() {
        assert!(cidr_or_ip_contains("0.0.0.0/0", "192.168.50.103"));
        assert!(cidr_or_ip_contains("192.168.50.103/32", "192.168.50.103"));
        assert!(!cidr_or_ip_contains("192.168.50.103/32", "192.168.50.104"));
        assert!(!cidr_or_ip_contains("192.168.50.0/33", "192.168.50.103"));
        assert!(!cidr_or_ip_contains("bad-cidr", "192.168.50.103"));
        assert!(!cidr_or_ip_contains("192.168.50.0/24", "not-an-ip"));
        assert!(!cidr_or_ip_contains("2001:db8::/32", "2001:db8::1"));
    }

    #[test]
    fn enrich_entries_marks_no_match_and_preserves_entry() {
        let views = enrich_entries(
            &[WhitelistEntry {
                mac: "00:11:22:33:44:55".into(),
                label: Some("Unknown".into()),
                expected_os: None,
                expected_ports: Vec::new(),
                expected_ips: Vec::new(),
            }],
            &[device()],
        );
        assert!(!views[0].inventory_match);
        assert!(views[0].current_devices.is_empty());
        assert_eq!(views[0].entry.label.as_deref(), Some("Unknown"));
    }

    #[test]
    fn enrich_entries_sorts_matching_devices_by_last_seen_desc_then_ip() {
        let mut older = device();
        older.device_id = "older".into();
        older.ip = "192.168.50.200".into();
        older.last_seen = "2026-06-12T00:00:00Z".into();
        let mut newest_a = device();
        newest_a.device_id = "newest-a".into();
        newest_a.ip = "192.168.50.20".into();
        newest_a.last_seen = "2026-06-12T02:00:00Z".into();
        let mut newest_b = device();
        newest_b.device_id = "newest-b".into();
        newest_b.ip = "192.168.50.10".into();
        newest_b.last_seen = "2026-06-12T02:00:00Z".into();

        let views = enrich_entries(&[entry()], &[older, newest_a, newest_b]);
        assert_eq!(
            views[0]
                .current_devices
                .iter()
                .map(|device| device.device_id.as_str())
                .collect::<Vec<_>>(),
            vec!["newest-b", "newest-a", "older"]
        );
    }

    #[test]
    fn infer_label_prefers_non_stale_newest_then_vendor_hostname_ip() {
        let mut stale = device();
        stale.status = DeviceStatus::Stale;
        stale.vendor = Some("Stale Vendor".into());
        stale.last_seen = "2026-06-12T05:00:00Z".into();
        let mut current = device();
        current.status = DeviceStatus::Unauthorized;
        current.vendor = Some(" ".into());
        current.hostname = Some(" current-host ".into());
        current.last_seen = "2026-06-12T01:00:00Z".into();
        assert_eq!(
            infer_label_for_mac("aa:bb:cc:11:22:33", &[stale, current]),
            Some("current-host".into())
        );
    }

    #[test]
    fn infer_label_falls_back_to_ip_and_returns_none_without_match() {
        let mut dev = device();
        dev.vendor = None;
        dev.hostname = Some(" ".into());
        assert_eq!(
            infer_label_for_mac("AA:BB:CC:11:22:33", &[dev.clone()]),
            Some("192.168.50.103".into())
        );
        assert_eq!(infer_label_for_mac("00:11:22:33:44:55", &[dev]), None);
    }

    #[test]
    fn format_open_port_omits_blank_service_and_version() {
        let port = OpenPort {
            port: 443,
            protocol: "tcp".into(),
            service: Some(" ".into()),
            product_version: Some("\t".into()),
            cpe: Vec::new(),
            scripts: Vec::new(),
        };
        assert_eq!(format_open_port(&port), "443/tcp");
    }
}
