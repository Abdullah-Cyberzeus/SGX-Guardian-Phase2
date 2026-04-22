// src/cot/interface_detector.rs
// ============================================================
// Network Interface Detector
//
// Auto-detects available network interfaces on the host,
// classifies them by transport type, and reports their status.
// No manual configuration required.
// ============================================================

use crate::cot::types::{CotError, CotResult, InterfaceInfo, InterfaceStatus, TransportType};
use network_interface::NetworkInterfaceConfig;
use std::net::IpAddr;
/// Detects and classifies network interfaces on the host.
/// This is a stateless utility — call `detect_all()` whenever
/// you need a fresh snapshot of available interfaces.
pub struct InterfaceDetector;

impl InterfaceDetector {
    /// Scan all network interfaces on the host.
    /// Returns a Vec<InterfaceInfo> sorted by priority (best first).
    ///
    /// Skips loopback and virtual/docker interfaces.
    /// On error (e.g., OS API failure), returns CotError.
    pub fn detect_all() -> CotResult<Vec<InterfaceInfo>> {
        let mut interfaces = Vec::new();

        let nic_list = network_interface::NetworkInterface::show().map_err(|e| {
            CotError::InterfaceDetectionFailed(format!("Failed to enumerate interfaces: {}", e))
        })?;

        for nic in nic_list {
            if nic.name == "lo" || nic.name.starts_with("lo") {
                continue;
            }

            if Self::is_virtual_interface(&nic.name) {
                continue;
            }

            if nic.name.starts_with("nebula") {
                continue;
            }

            let transport_type = match Self::classify_interface(&nic.name) {
                Some(t) => t,
                None => continue,
            };

            let ip_addr = nic.addr.iter().find_map(|addr| match addr {
                network_interface::Addr::V4(v4) => Some(IpAddr::V4(v4.ip)),
                network_interface::Addr::V6(_) => None,
            });

            let status = if ip_addr.is_some() {
                InterfaceStatus::Up
            } else {
                InterfaceStatus::Down
            };

            let info = InterfaceInfo::new(nic.name.clone(), transport_type, ip_addr, status);

            interfaces.push(info);
        }

        interfaces.sort_by_key(|i| i.priority);
        Ok(interfaces)
    }

    /// Detect only interfaces of a specific transport type.
    pub fn detect_by_type(target: TransportType) -> CotResult<Vec<InterfaceInfo>> {
        let all = Self::detect_all()?;
        Ok(all
            .into_iter()
            .filter(|i| i.transport_type == target)
            .collect())
    }

    /// Detect only interfaces that are currently usable (up + has IP).
    pub fn detect_usable() -> CotResult<Vec<InterfaceInfo>> {
        let all = Self::detect_all()?;
        Ok(all.into_iter().filter(|i| i.is_usable()).collect())
    }

    /// Get the single best (highest-priority, usable) interface.
    pub fn best_interface() -> CotResult<InterfaceInfo> {
        let usable = Self::detect_usable()?;
        usable
            .into_iter()
            .next()
            .ok_or(CotError::NoTransportAvailable)
    }

    /// Classify an interface name into a TransportType.
    /// Uses Linux naming conventions.
    fn classify_interface(name: &str) -> Option<TransportType> {
        let lower = name.to_lowercase();

        if Self::is_forced_satellite_interface(&lower) {
            return Some(TransportType::Satellite);
        }

        if lower.starts_with("ppp") {
            return Some(TransportType::Satellite);
        }
        if Self::is_satellite_usb_modem(name) {
            return Some(TransportType::Satellite);
        }
        if lower.starts_with("sat") {
            return Some(TransportType::Satellite);
        }

        if lower.starts_with("eth")
            || lower.starts_with("en")
            || lower.starts_with("eno")
            || lower.starts_with("enp")
        {
            return Some(TransportType::Ethernet);
        }

        if lower.starts_with("wlan") || lower.starts_with("wl") || lower.starts_with("wlp") {
            return Some(TransportType::WiFi);
        }

        if lower.starts_with("bnep") || lower.starts_with("bt") || lower.starts_with("hci") {
            return Some(TransportType::Bluetooth);
        }

        if lower.starts_with("wwan") || lower.starts_with("rmnet") || lower.starts_with("usb") {
            return Some(TransportType::Cellular);
        }

        None
    }

    fn is_forced_satellite_interface(lower_name: &str) -> bool {
        let Ok(raw) = std::env::var("SGX_SATELLITE_INTERFACES") else {
            return false;
        };
        raw.split(',')
            .map(|n| n.trim().to_lowercase())
            .filter(|n| !n.is_empty())
            .any(|n| n == lower_name)
    }

    fn is_satellite_usb_modem(iface_name: &str) -> bool {
        if !iface_name.to_lowercase().starts_with("usb") {
            return false;
        }

        let path = format!("/sys/class/net/{}/device/uevent", iface_name);
        let Ok(content) = std::fs::read_to_string(path) else {
            return false;
        };

        const SAT_VENDOR_IDS: &[&str] = &["1546", "1bc7", "0846", "1291"];
        for line in content.lines() {
            if let Some(vid) = line.strip_prefix("ID_VENDOR_ID=") {
                if SAT_VENDOR_IDS.contains(&vid.trim()) {
                    return true;
                }
            }
        }
        false
    }

    /// Returns true if the interface name looks like a virtual/container NIC.
    fn is_virtual_interface(name: &str) -> bool {
        let lower = name.to_lowercase();
        lower.starts_with("docker")
            || lower.starts_with("veth")
            || lower.starts_with("br-")
            || lower.starts_with("virbr")
            || lower.starts_with("vnet")
            || lower.starts_with("flannel")
            || lower.starts_with("cni")
            || lower.starts_with("cali")
            || lower == "docker0"
    }

    /// Check Linux operstate for more accurate link status.
    #[allow(dead_code)]
    fn read_linux_operstate(interface_name: &str) -> InterfaceStatus {
        let path = format!("/sys/class/net/{}/operstate", interface_name);
        match std::fs::read_to_string(&path) {
            Ok(state) => match state.trim() {
                "up" => InterfaceStatus::Up,
                "down" => InterfaceStatus::Down,
                _ => InterfaceStatus::Unknown,
            },
            Err(_) => InterfaceStatus::Unknown,
        }
    }
}

// ----------------------------------------------------------
// Unit Tests
// ----------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_ethernet() {
        assert_eq!(
            InterfaceDetector::classify_interface("eth0"),
            Some(TransportType::Ethernet)
        );
        assert_eq!(
            InterfaceDetector::classify_interface("enp0s3"),
            Some(TransportType::Ethernet)
        );
        assert_eq!(
            InterfaceDetector::classify_interface("eno1"),
            Some(TransportType::Ethernet)
        );
    }

    #[test]
    fn test_classify_wifi() {
        assert_eq!(
            InterfaceDetector::classify_interface("wlan0"),
            Some(TransportType::WiFi)
        );
        assert_eq!(
            InterfaceDetector::classify_interface("wlp2s0"),
            Some(TransportType::WiFi)
        );
    }

    #[test]
    fn test_classify_bluetooth() {
        assert_eq!(
            InterfaceDetector::classify_interface("bnep0"),
            Some(TransportType::Bluetooth)
        );
    }

    #[test]
    fn test_classify_cellular() {
        assert_eq!(
            InterfaceDetector::classify_interface("wwan0"),
            Some(TransportType::Cellular)
        );
        assert_eq!(
            InterfaceDetector::classify_interface("rmnet0"),
            Some(TransportType::Cellular)
        );
    }

    #[test]
    fn test_classify_satellite() {
        assert_eq!(
            InterfaceDetector::classify_interface("sat0"),
            Some(TransportType::Satellite)
        );
        assert_eq!(
            InterfaceDetector::classify_interface("ppp0"),
            Some(TransportType::Satellite)
        );
    }

    #[test]
    fn test_classify_unknown() {
        assert_eq!(InterfaceDetector::classify_interface("tun0"), None);
    }

    #[test]
    fn test_virtual_interface_detection() {
        assert!(InterfaceDetector::is_virtual_interface("docker0"));
        assert!(InterfaceDetector::is_virtual_interface("veth123abc"));
        assert!(InterfaceDetector::is_virtual_interface("br-abcdef"));
        assert!(!InterfaceDetector::is_virtual_interface("eth0"));
        assert!(!InterfaceDetector::is_virtual_interface("wlan0"));
    }

    #[test]
    fn test_classification_is_pure_and_stable() {
        let cases = [
            ("eth0", Some(TransportType::Ethernet)),
            ("wlan0", Some(TransportType::WiFi)),
            ("bnep0", Some(TransportType::Bluetooth)),
            ("wwan0", Some(TransportType::Cellular)),
            ("sat0", Some(TransportType::Satellite)),
            ("ppp0", Some(TransportType::Satellite)),
            ("tun0", None),
        ];

        for (name, expected) in cases {
            assert_eq!(InterfaceDetector::classify_interface(name), expected);
        }
    }

    #[test]
    fn test_classify_eth_with_env_override_as_satellite() {
        std::env::set_var("SGX_SATELLITE_INTERFACES", "ens37");
        assert_eq!(
            InterfaceDetector::classify_interface("ens37"),
            Some(TransportType::Satellite)
        );
        std::env::remove_var("SGX_SATELLITE_INTERFACES");
    }
}
