// src/cot/transports/bluetooth.rs
// ============================================================
// Bluetooth Transport (BLE / Classic) — Full Implementation
// Replaces the earlier stub implementation. Uses bnep0 (BT PAN) for TCP CoT.
// Board: BT 5.0 via hci0 interface
// ============================================================

use crate::cot::transport_trait::{Transport, TransportHealth, TransportMessage};
use crate::cot::types::{CotError, CotResult, InterfaceInfo, TransportPriority, TransportType};
use async_trait::async_trait;
use std::process::Command;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Source of adapter state. Real deployments shell out to the BlueZ tools;
/// tests inject fixed values so no adapter hardware is required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterProbe {
    /// Query `bluetoothctl`/`hcitool` on this host.
    System,
    /// Fixed values supplied by a caller (tests, simulations).
    Fixed { powered: bool, rssi: Option<i8> },
}

/// `bluetoothctl show` reports power state; `hciconfig` is the fallback when
/// bluetoothctl is unavailable.
pub fn parse_powered(bluetoothctl_stdout: Option<&str>, hciconfig_stdout: Option<&str>) -> bool {
    match bluetoothctl_stdout {
        Some(out) => out.contains("Powered: yes"),
        None => hciconfig_stdout
            .map(|out| out.contains("UP RUNNING"))
            .unwrap_or(false),
    }
}

/// Extract the first connected device MAC from `hcitool con` output.
/// Lines look like `\t< ACL AA:BB:CC:DD:EE:FF handle 12 state 1 lm MASTER`.
pub fn parse_connected_mac(con_stdout: &str) -> Option<&str> {
    con_stdout
        .lines()
        .find(|l| l.contains("ACL"))
        .and_then(|l| l.split_whitespace().nth(2))
}

/// Extract the signal strength from `hcitool rssi <mac>` output.
pub fn parse_rssi(rssi_stdout: &str) -> Option<i8> {
    rssi_stdout
        .lines()
        .find(|l| l.contains("RSSI"))
        .and_then(|l| l.split(':').next_back())
        .and_then(|v| v.trim().parse::<i8>().ok())
}

/// Map signal strength onto an estimated bandwidth in kbps. An unknown RSSI is
/// treated as a mid-range link rather than a bad one.
pub fn rssi_bandwidth(rssi: Option<i8>) -> u64 {
    match rssi {
        Some(r) if r > -50 => 3_000,
        Some(r) if r > -70 => 1_000,
        Some(_) => 500,
        None => 1_000,
    }
}

/// Pull Guardian/SGX device MACs out of `bluetoothctl scan on` output.
pub fn parse_scan_guardians(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter(|l| (l.contains("Guardian") || l.contains("SGX")) && l.contains("Device"))
        .filter_map(|l| l.split_whitespace().nth(2).map(|s| s.to_string()))
        .collect()
}

/// Keep only the `Device ...` rows of `bluetoothctl paired-devices` output.
pub fn parse_paired_devices(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter(|l| l.starts_with("Device"))
        .map(|l| l.to_string())
        .collect()
}

/// BlueZ D-Bus object path for a device on hci0.
pub fn pan_object_path(mac: &str) -> String {
    format!("/org/bluez/hci0/dev_{}", mac.replace(':', "_"))
}

#[derive(Debug, Clone)]
pub struct BluetoothTransport {
    interface: InterfaceInfo,
    probe: AdapterProbe,
}

impl BluetoothTransport {
    pub fn new(interface: InterfaceInfo) -> Self {
        // Unit tests must not depend on a real adapter being present.
        #[cfg(test)]
        let probe = AdapterProbe::Fixed {
            powered: false,
            rssi: None,
        };
        #[cfg(not(test))]
        let probe = AdapterProbe::System;

        Self { interface, probe }
    }

    /// Build a transport whose adapter state is supplied rather than probed.
    pub fn with_fixed_adapter(interface: InterfaceInfo, powered: bool, rssi: Option<i8>) -> Self {
        Self {
            interface,
            probe: AdapterProbe::Fixed { powered, rssi },
        }
    }

    fn adapter_powered(&self) -> bool {
        match self.probe {
            AdapterProbe::Fixed { powered, .. } => powered,
            AdapterProbe::System => {
                let bluetoothctl = Command::new("bluetoothctl")
                    .args(["show"])
                    .output()
                    .ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).into_owned());
                let hciconfig = if bluetoothctl.is_none() {
                    Command::new("hciconfig")
                        .args(["hci0"])
                        .output()
                        .ok()
                        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                } else {
                    None
                };
                parse_powered(bluetoothctl.as_deref(), hciconfig.as_deref())
            }
        }
    }

    fn get_rssi(&self) -> Option<i8> {
        match self.probe {
            AdapterProbe::Fixed { rssi, .. } => rssi,
            AdapterProbe::System => {
                // `hcitool rssi` requires a device MAC, not an interface name,
                // so find a connected device first.
                let con_output = Command::new("hcitool").args(["con"]).output().ok()?;
                let con_stdout = String::from_utf8_lossy(&con_output.stdout).into_owned();
                let mac = parse_connected_mac(&con_stdout)?;

                let output = Command::new("hcitool").args(["rssi", mac]).output().ok()?;
                parse_rssi(&String::from_utf8_lossy(&output.stdout))
            }
        }
    }

    pub fn scan_guardians() -> Vec<String> {
        Command::new("bluetoothctl")
            .args(["--timeout", "10", "scan", "on"])
            .output()
            .map(|o| parse_scan_guardians(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default()
    }
}

#[async_trait]
impl Transport for BluetoothTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Bluetooth
    }
    fn priority(&self) -> TransportPriority {
        self.interface.priority
    }
    fn interface_name(&self) -> &str {
        &self.interface.name
    }

    async fn is_available(&self) -> bool {
        self.interface.is_usable() && self.adapter_powered()
    }

    async fn send(&self, message: &TransportMessage) -> CotResult<()> {
        if !self.is_available().await {
            return Err(CotError::TransportError(format!(
                "Bluetooth {} not available",
                self.interface.name
            )));
        }
        let mut stream = TcpStream::connect(&message.target_address)
            .await
            .map_err(|e| CotError::TransportError(format!("BT send: {}", e)))?;
        let len = (message.payload.len() as u32).to_be_bytes();
        stream
            .write_all(&len)
            .await
            .map_err(|e| CotError::TransportError(format!("BT write: {}", e)))?;
        stream
            .write_all(&message.payload)
            .await
            .map_err(|e| CotError::TransportError(format!("BT payload: {}", e)))?;
        stream
            .flush()
            .await
            .map_err(|e| CotError::TransportError(format!("BT flush: {}", e)))?;
        Ok(())
    }

    async fn health_check(&self) -> TransportHealth {
        if !self.interface.is_usable() {
            return TransportHealth::unhealthy("BT interface not usable");
        }
        if !self.adapter_powered() {
            return TransportHealth::unhealthy("BT adapter not powered");
        }
        TransportHealth::healthy(15, rssi_bandwidth(self.get_rssi()))
    }

    fn display_name(&self) -> String {
        let rssi = self
            .get_rssi()
            .map(|r| format!(" rssi={}dBm", r))
            .unwrap_or_default();
        format!("Bluetooth({}){}", self.interface.name, rssi)
    }
}

pub struct BluetoothPairing;
impl BluetoothPairing {
    pub fn pair(mac: &str) -> Result<(), String> {
        Command::new("bluetoothctl")
            .args(["pair", mac])
            .output()
            .map_err(|e| format!("Pair: {}", e))
            .and_then(|o| {
                if o.status.success() {
                    Ok(())
                } else {
                    Err(format!(
                        "Pair failed: {}",
                        String::from_utf8_lossy(&o.stderr)
                    ))
                }
            })
    }
    pub fn list_paired() -> Vec<String> {
        Command::new("bluetoothctl")
            .args(["paired-devices"])
            .output()
            .map(|o| parse_paired_devices(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default()
    }
    pub fn setup_pan(mac: &str) -> Result<(), String> {
        Command::new("dbus-send")
            .args([
                "--system",
                "--type=method_call",
                "--dest=org.bluez",
                &pan_object_path(mac),
                "org.bluez.Network1.Connect",
                "string:nap",
            ])
            .output()
            .map_err(|e| format!("PAN: {}", e))
            .and_then(|o| {
                if o.status.success() {
                    Ok(())
                } else {
                    Err("PAN failed".into())
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cot::types::{InterfaceInfo, InterfaceStatus, TransportType};

    fn make_bt(status: InterfaceStatus) -> InterfaceInfo {
        InterfaceInfo::new(
            "bnep0".into(),
            TransportType::Bluetooth,
            if status == InterfaceStatus::Up {
                Some("172.20.10.1".parse().unwrap())
            } else {
                None
            },
            status,
        )
    }

    #[test]
    fn test_type() {
        assert_eq!(
            BluetoothTransport::new(make_bt(InterfaceStatus::Up)).transport_type(),
            TransportType::Bluetooth
        );
    }
    #[test]
    fn test_priority_40() {
        assert_eq!(
            BluetoothTransport::new(make_bt(InterfaceStatus::Up))
                .priority()
                .0,
            40
        );
    }
    #[test]
    fn test_display_name() {
        let n = BluetoothTransport::new(make_bt(InterfaceStatus::Up)).display_name();
        assert!(n.contains("Bluetooth"));
        assert!(n.contains("bnep0"));
        assert!(!n.to_lowercase().contains("stub"));
    }
    #[test]
    fn test_hci() {
        let i = InterfaceInfo::new(
            "hci0".into(),
            TransportType::Bluetooth,
            None,
            InterfaceStatus::Down,
        );
        assert!(BluetoothTransport::new(i).display_name().contains("hci0"));
    }
    #[test]
    fn test_preserves() {
        let t = BluetoothTransport::new(make_bt(InterfaceStatus::Down));
        assert_eq!(t.priority().0, 40);
    }

    #[tokio::test]
    async fn test_down_unhealthy() {
        let h = BluetoothTransport::new(make_bt(InterfaceStatus::Down))
            .health_check()
            .await;
        assert!(!h.is_healthy);
    }
    #[tokio::test]
    async fn test_send_fails_down() {
        let t = BluetoothTransport::new(make_bt(InterfaceStatus::Down));
        let msg = TransportMessage::new("a".into(), "b".into(), "127.0.0.1:9999".into(), vec![1]);
        assert!(t.send(&msg).await.is_err());
    }

    #[test]
    fn parse_powered_prefers_bluetoothctl() {
        assert!(parse_powered(Some("Controller AA\n\tPowered: yes\n"), None));
        assert!(!parse_powered(Some("\tPowered: no\n"), Some("UP RUNNING")));
    }

    #[test]
    fn parse_powered_falls_back_to_hciconfig() {
        assert!(parse_powered(None, Some("hci0:\tUP RUNNING PSCAN")));
        assert!(!parse_powered(None, Some("hci0:\tDOWN")));
        assert!(!parse_powered(None, None));
    }

    #[test]
    fn parse_connected_mac_reads_first_acl_row() {
        let out = "Connections:\n\t< ACL AA:BB:CC:DD:EE:FF handle 12 state 1\n\t< ACL 11:22:33:44:55:66 handle 13 state 1\n";
        assert_eq!(parse_connected_mac(out), Some("AA:BB:CC:DD:EE:FF"));
        assert_eq!(parse_connected_mac("Connections:\n"), None);
    }

    #[test]
    fn parse_rssi_reads_signed_value() {
        assert_eq!(parse_rssi("RSSI return value: -42\n"), Some(-42));
        assert_eq!(parse_rssi("RSSI return value: notanumber\n"), None);
        assert_eq!(parse_rssi("no signal line here\n"), None);
    }

    #[test]
    fn rssi_bandwidth_bands() {
        assert_eq!(rssi_bandwidth(Some(-20)), 3_000);
        assert_eq!(rssi_bandwidth(Some(-50)), 1_000);
        assert_eq!(rssi_bandwidth(Some(-69)), 1_000);
        assert_eq!(rssi_bandwidth(Some(-90)), 500);
        assert_eq!(rssi_bandwidth(None), 1_000);
    }

    #[test]
    fn parse_scan_guardians_keeps_only_matching_devices() {
        let out = concat!(
            "[NEW] Device AA:BB:CC:DD:EE:FF Guardian-01\n",
            "[NEW] Device 11:22:33:44:55:66 SGX-Node\n",
            "[NEW] Device 99:99:99:99:99:99 SomeHeadphones\n",
            "Guardian mentioned without a device row\n",
        );
        assert_eq!(
            parse_scan_guardians(out),
            vec![
                "AA:BB:CC:DD:EE:FF".to_string(),
                "11:22:33:44:55:66".to_string()
            ]
        );
        assert!(parse_scan_guardians("").is_empty());
    }

    #[test]
    fn parse_paired_devices_keeps_device_rows() {
        let out = "Device AA:BB:CC:DD:EE:FF Guardian-01\nAgent registered\n";
        assert_eq!(
            parse_paired_devices(out),
            vec!["Device AA:BB:CC:DD:EE:FF Guardian-01".to_string()]
        );
        assert!(parse_paired_devices("").is_empty());
    }

    #[test]
    fn pan_object_path_escapes_colons() {
        assert_eq!(
            pan_object_path("AA:BB:CC:DD:EE:FF"),
            "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF"
        );
    }

    #[test]
    fn new_uses_fixed_probe_under_test() {
        let t = BluetoothTransport::new(make_bt(InterfaceStatus::Up));
        assert_eq!(
            t.probe,
            AdapterProbe::Fixed {
                powered: false,
                rssi: None
            }
        );
    }

    #[tokio::test]
    async fn powered_adapter_on_usable_interface_is_available() {
        let t = BluetoothTransport::with_fixed_adapter(make_bt(InterfaceStatus::Up), true, None);
        assert!(t.is_available().await);

        let down =
            BluetoothTransport::with_fixed_adapter(make_bt(InterfaceStatus::Down), true, None);
        assert!(!down.is_available().await);
    }

    #[tokio::test]
    async fn health_check_reports_unpowered_adapter() {
        let t = BluetoothTransport::with_fixed_adapter(make_bt(InterfaceStatus::Up), false, None);
        let h = t.health_check().await;
        assert!(!h.is_healthy);
    }

    #[tokio::test]
    async fn health_check_uses_rssi_for_bandwidth() {
        let strong =
            BluetoothTransport::with_fixed_adapter(make_bt(InterfaceStatus::Up), true, Some(-30));
        let h = strong.health_check().await;
        assert!(h.is_healthy);
        assert_eq!(h.bandwidth_kbps, 3_000);

        let weak =
            BluetoothTransport::with_fixed_adapter(make_bt(InterfaceStatus::Up), true, Some(-95));
        assert_eq!(weak.health_check().await.bandwidth_kbps, 500);
    }

    #[test]
    fn display_name_includes_rssi_when_known() {
        let t =
            BluetoothTransport::with_fixed_adapter(make_bt(InterfaceStatus::Up), true, Some(-55));
        assert_eq!(t.display_name(), "Bluetooth(bnep0) rssi=-55dBm");
    }

    #[tokio::test]
    async fn send_writes_length_prefixed_payload() {
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            socket.read_to_end(&mut buf).await.unwrap();
            buf
        });

        let t = BluetoothTransport::with_fixed_adapter(make_bt(InterfaceStatus::Up), true, None);
        let msg = TransportMessage::new("a".into(), "b".into(), addr, vec![7, 8, 9]);
        t.send(&msg).await.expect("send succeeds");

        assert_eq!(server.await.unwrap(), vec![0, 0, 0, 3, 7, 8, 9]);
    }

    #[tokio::test]
    async fn send_fails_when_target_is_unreachable() {
        let t = BluetoothTransport::with_fixed_adapter(make_bt(InterfaceStatus::Up), true, None);
        // Port 0 is never connectable.
        let msg = TransportMessage::new("a".into(), "b".into(), "127.0.0.1:0".into(), vec![1]);
        assert!(t.send(&msg).await.is_err());
    }
}
