// src/cot/transports/bluetooth.rs
// ============================================================
// Bluetooth Transport (BLE / Classic) — Full Implementation
// Replaces Sprint 2 stub. Uses bnep0 (BT PAN) for TCP CoT.
// Board: BT 5.0 via hci0 interface
// ============================================================

use crate::cot::transport_trait::{Transport, TransportHealth, TransportMessage};
use crate::cot::types::{CotError, CotResult, InterfaceInfo, TransportPriority, TransportType};
use async_trait::async_trait;
use std::process::Command;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub struct BluetoothTransport {
    interface: InterfaceInfo,
}

impl BluetoothTransport {
    pub fn new(interface: InterfaceInfo) -> Self {
        Self { interface }
    }

    fn adapter_powered(&self) -> bool {
        Command::new("bluetoothctl")
            .args(["show"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("Powered: yes"))
            .unwrap_or_else(|_| {
                Command::new("hciconfig")
                    .args(["hci0"])
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).contains("UP RUNNING"))
                    .unwrap_or(false)
            })
    }

    fn get_rssi(&self) -> Option<i8> {
        // hcitool rssi requires a device MAC, not interface name.
        // Use hcitool con to find connected devices, then query RSSI.
        let con_output = Command::new("hcitool").args(["con"]).output().ok()?;
        let con_stdout = String::from_utf8_lossy(&con_output.stdout);
        // Extract first connected device MAC (format: "< ACL XX:XX:XX:XX:XX:XX ...")
        let mac = con_stdout
            .lines()
            .find(|l| l.contains("ACL"))
            .and_then(|l| l.split_whitespace().nth(2))?;

        let output = Command::new("hcitool").args(["rssi", mac]).output().ok()?;
        let s = String::from_utf8_lossy(&output.stdout);
        s.lines()
            .find(|l| l.contains("RSSI"))
            .and_then(|l| l.split(':').next_back())
            .and_then(|v| v.trim().parse::<i8>().ok())
    }

    pub fn scan_guardians() -> Vec<String> {
        Command::new("bluetoothctl")
            .args(["--timeout", "10", "scan", "on"])
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .filter(|l| {
                        (l.contains("Guardian") || l.contains("SGX")) && l.contains("Device")
                    })
                    .filter_map(|l| l.split_whitespace().nth(2).map(|s| s.to_string()))
                    .collect()
            })
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
        self.adapter_powered() && self.interface.is_usable()
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
        if !self.adapter_powered() {
            return TransportHealth::unhealthy("BT adapter not powered");
        }
        if !self.interface.is_usable() {
            return TransportHealth::unhealthy("BT interface not usable");
        }
        let bw = match self.get_rssi() {
            Some(r) if r > -50 => 3_000,
            Some(r) if r > -70 => 1_000,
            Some(_) => 500,
            None => 1_000,
        };
        TransportHealth::healthy(15, bw)
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
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .filter(|l| l.starts_with("Device"))
                    .map(|l| l.to_string())
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn setup_pan(mac: &str) -> Result<(), String> {
        Command::new("dbus-send")
            .args([
                "--system",
                "--type=method_call",
                "--dest=org.bluez",
                &format!("/org/bluez/hci0/dev_{}", mac.replace(':', "_")),
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
    async fn test_down_unavailable() {
        assert!(
            !BluetoothTransport::new(make_bt(InterfaceStatus::Down))
                .is_available()
                .await
        );
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
}
