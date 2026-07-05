// src/cot/transports/cellular.rs
// ============================================================
// Cellular Transport (LTE/5G) — Full Implementation
// Replaces the earlier stub implementation. Uses wwan0 for TCP CoT messaging.
// Same length-prefixed protocol as Ethernet/WiFi.
// Board: AERIS SIM via wwan0 interface
// ============================================================

use crate::cot::transport_trait::{Transport, TransportHealth, TransportMessage};
use crate::cot::types::{CotError, CotResult, InterfaceInfo, TransportPriority, TransportType};
use async_trait::async_trait;
use std::process::Command;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub struct CellularTransport {
    interface: InterfaceInfo,
}

impl CellularTransport {
    pub fn new(interface: InterfaceInfo) -> Self {
        Self { interface }
    }

    fn has_carrier(&self) -> bool {
        std::fs::read_to_string(format!("/sys/class/net/{}/carrier", self.interface.name))
            .map(|s| s.trim() == "1")
            .unwrap_or(false)
    }

    fn signal_quality(&self) -> Option<u8> {
        let o = Command::new("mmcli")
            .args(["-m", "0", "--signal-get"])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&o.stdout);
        s.lines()
            .find(|l| l.contains("quality:") || l.contains("rssi:"))
            .and_then(|l| l.split(':').next_back())
            .and_then(|v| v.trim().trim_end_matches('%').parse::<u8>().ok())
            .map(|v| v.min(100))
    }
}

#[async_trait]
impl Transport for CellularTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Cellular
    }
    fn priority(&self) -> TransportPriority {
        self.interface.priority
    }
    fn interface_name(&self) -> &str {
        &self.interface.name
    }

    async fn is_available(&self) -> bool {
        self.interface.is_usable() && self.has_carrier()
    }

    async fn send(&self, message: &TransportMessage) -> CotResult<()> {
        if !self.is_available().await {
            return Err(CotError::TransportError(format!(
                "Cellular {} not available",
                self.interface.name
            )));
        }
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TcpStream::connect(&message.target_address),
        )
        .await
        .map_err(|_| {
            CotError::TransportError(format!(
                "Cellular connect to {} timed out",
                message.target_address
            ))
        })?
        .map_err(|e| CotError::TransportError(format!("Cellular send: {}", e)))?;
        let len = (message.payload.len() as u32).to_be_bytes();
        tokio::time::timeout(std::time::Duration::from_secs(5), stream.write_all(&len))
            .await
            .map_err(|_| CotError::TransportError("Cell write timed out".into()))?
            .map_err(|e| CotError::TransportError(format!("Cell write: {}", e)))?;
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.write_all(&message.payload),
        )
        .await
        .map_err(|_| CotError::TransportError("Cell payload timed out".into()))?
        .map_err(|e| CotError::TransportError(format!("Cell payload: {}", e)))?;
        tokio::time::timeout(std::time::Duration::from_secs(5), stream.flush())
            .await
            .map_err(|_| CotError::TransportError("Cell flush timed out".into()))?
            .map_err(|e| CotError::TransportError(format!("Cell flush: {}", e)))?;
        Ok(())
    }

    async fn health_check(&self) -> TransportHealth {
        if !self.interface.is_usable() {
            return TransportHealth::unhealthy("Cellular not usable");
        }
        if !self.has_carrier() {
            return TransportHealth::unhealthy("No carrier signal");
        }
        let bw = match self.signal_quality() {
            Some(q) if q > 70 => 50_000,
            Some(q) if q > 40 => 10_000,
            Some(_) => 2_000,
            None => 5_000,
        };
        TransportHealth::healthy(30, bw)
    }

    fn display_name(&self) -> String {
        let sig = self
            .signal_quality()
            .map(|q| format!(" sig={}%", q))
            .unwrap_or_default();
        format!("Cellular({}){}", self.interface.name, sig)
    }
}

pub struct CellularDiagnostics;
impl CellularDiagnostics {
    pub fn registration_status() -> String {
        Command::new("mmcli")
            .args(["-m", "0"])
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .find(|l| l.contains("state:"))
                    .unwrap_or("unknown")
                    .trim()
                    .to_string()
            })
            .unwrap_or_else(|_| "mmcli unavailable".into())
    }
    pub fn carrier_name() -> Option<String> {
        let o = Command::new("mmcli").args(["-m", "0"]).output().ok()?;
        String::from_utf8_lossy(&o.stdout)
            .lines()
            .find(|l| l.contains("operator name:"))
            .and_then(|l| l.split(':').next_back().map(|s| s.trim().to_string()))
    }
    pub fn has_data_route() -> bool {
        Command::new("ip")
            .args(["route", "show", "dev", "wwan0"])
            .output()
            .map(|o| !String::from_utf8_lossy(&o.stdout).is_empty())
            .unwrap_or(false)
    }
    pub fn report() -> String {
        format!(
            "Cellular: reg={}, carrier={}, route={}",
            Self::registration_status(),
            Self::carrier_name().unwrap_or("unknown".into()),
            Self::has_data_route()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cot::types::{InterfaceInfo, InterfaceStatus, TransportType};

    fn make_cell(status: InterfaceStatus) -> InterfaceInfo {
        InterfaceInfo::new(
            "wwan0".into(),
            TransportType::Cellular,
            if status == InterfaceStatus::Up {
                Some("100.64.0.1".parse().unwrap())
            } else {
                None
            },
            status,
        )
    }

    #[test]
    fn test_type() {
        assert_eq!(
            CellularTransport::new(make_cell(InterfaceStatus::Up)).transport_type(),
            TransportType::Cellular
        );
    }
    #[test]
    fn test_display_name() {
        let n = CellularTransport::new(make_cell(InterfaceStatus::Up)).display_name();
        assert!(n.contains("Cellular"));
        assert!(n.contains("wwan0"));
        assert!(!n.to_lowercase().contains("stub"));
    }
    #[test]
    fn test_rmnet() {
        let i = InterfaceInfo::new(
            "rmnet0".into(),
            TransportType::Cellular,
            None,
            InterfaceStatus::Down,
        );
        assert!(CellularTransport::new(i).display_name().contains("rmnet0"));
    }
    #[tokio::test]
    async fn test_down_unavailable() {
        assert!(
            !CellularTransport::new(make_cell(InterfaceStatus::Down))
                .is_available()
                .await
        );
    }
    #[tokio::test]
    async fn test_down_unhealthy() {
        let h = CellularTransport::new(make_cell(InterfaceStatus::Down))
            .health_check()
            .await;
        assert!(!h.is_healthy);
    }
    #[tokio::test]
    async fn test_send_fails_down() {
        let t = CellularTransport::new(make_cell(InterfaceStatus::Down));
        let msg = TransportMessage::new("a".into(), "b".into(), "127.0.0.1:9999".into(), vec![1]);
        assert!(t.send(&msg).await.is_err());
    }
}
