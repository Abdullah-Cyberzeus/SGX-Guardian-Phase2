use crate::discovery::{
    connected_device::{ConnectedDevice, DeviceStatus},
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
