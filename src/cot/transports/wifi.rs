// src/cot/transports/wifi.rs
use crate::cot::transport_trait::{Transport, TransportHealth, TransportMessage};
use crate::cot::types::{CotError, CotResult, InterfaceInfo, TransportPriority, TransportType};
use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpSocket, TcpStream};

#[derive(Debug, Clone)]
pub struct WiFiTransport {
    interface: InterfaceInfo,
}

impl WiFiTransport {
    pub fn new(interface: InterfaceInfo) -> Self {
        Self { interface }
    }

    fn has_operstate_up(&self) -> bool {
        std::fs::read_to_string(format!("/sys/class/net/{}/operstate", self.interface.name))
            .map(|s| s.trim() == "up")
            .unwrap_or(false)
    }

    fn has_carrier(&self) -> bool {
        std::fs::read_to_string(format!("/sys/class/net/{}/carrier", self.interface.name))
            .map(|s| s.trim() == "1")
            .unwrap_or(true)
    }

    fn has_default_route(&self) -> bool {
        let Ok(content) = std::fs::read_to_string("/proc/net/route") else {
            return false;
        };
        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 4 {
                continue;
            }
            if cols[0] == self.interface.name && cols[1] == "00000000" {
                let flags = u16::from_str_radix(cols[3], 16).unwrap_or(0);
                let is_up = flags & 0x1 != 0;
                let is_gateway = flags & 0x2 != 0;
                if is_up && is_gateway {
                    return true;
                }
            }
        }
        false
    }

    fn link_speed_kbps(&self) -> u64 {
        // /sys speed is not always reported for WiFi drivers.
        std::fs::read_to_string(format!("/sys/class/net/{}/speed", self.interface.name))
            .ok()
            .and_then(|s| s.trim().parse::<i64>().ok())
            .filter(|v| *v > 0)
            .map(|v| (v as u64).saturating_mul(1000))
            .unwrap_or(60_000)
    }

    async fn latency_probe_ms(&self) -> Option<u64> {
        let target = std::env::var("SGX_NET_PROBE_ADDR").unwrap_or_else(|_| "1.1.1.1:443".into());
        let remote: SocketAddr = target.parse().ok()?;
        let local_ip = self.interface.ip_addr?;
        let local = SocketAddr::new(local_ip, 0);
        let socket = match local_ip {
            IpAddr::V4(_) => TcpSocket::new_v4().ok()?,
            IpAddr::V6(_) => TcpSocket::new_v6().ok()?,
        };
        socket.bind(local).ok()?;
        let start = Instant::now();
        let stream = tokio::time::timeout(Duration::from_millis(1700), socket.connect(remote))
            .await
            .ok()?
            .ok()?;
        drop(stream);
        Some(start.elapsed().as_millis().max(1) as u64)
    }
}

#[async_trait]
impl Transport for WiFiTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::WiFi
    }
    fn priority(&self) -> TransportPriority {
        self.interface.priority
    }
    fn interface_name(&self) -> &str {
        &self.interface.name
    }
    async fn is_available(&self) -> bool {
        self.interface.ip_addr.is_some()
            && self.has_operstate_up()
            && self.has_carrier()
            && self.has_default_route()
    }

    async fn send(&self, message: &TransportMessage) -> CotResult<()> {
        let mut stream = TcpStream::connect(&message.target_address)
            .await
            .map_err(|e| {
                CotError::TransportError(format!(
                    "WiFi send to {} failed: {}",
                    message.target_address, e
                ))
            })?;
        let len = (message.payload.len() as u32).to_be_bytes();
        stream
            .write_all(&len)
            .await
            .map_err(|e| CotError::TransportError(format!("WiFi write failed: {}", e)))?;
        stream
            .write_all(&message.payload)
            .await
            .map_err(|e| CotError::TransportError(format!("WiFi write payload failed: {}", e)))?;
        stream
            .flush()
            .await
            .map_err(|e| CotError::TransportError(format!("WiFi flush failed: {}", e)))?;
        Ok(())
    }

    async fn health_check(&self) -> TransportHealth {
        if self.interface.ip_addr.is_none() {
            return TransportHealth::unhealthy("WiFi has no IP");
        }
        if !self.has_operstate_up() {
            return TransportHealth::unhealthy("WiFi operstate is down");
        }
        if !self.has_carrier() {
            return TransportHealth::unhealthy("WiFi link carrier is down");
        }
        if !self.has_default_route() {
            return TransportHealth::unhealthy("WiFi network not reachable (no default route)");
        }
        let bw = self.link_speed_kbps();
        let latency = self.latency_probe_ms().await.unwrap_or(12);
        TransportHealth::healthy(latency.max(1), bw.max(1))
    }

    fn display_name(&self) -> String {
        format!("WiFi({})", self.interface.name)
    }
}

//-----------------
//Unit Test

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cot::types::{InterfaceInfo, InterfaceStatus, TransportType};

    fn make_test_interface(status: InterfaceStatus) -> InterfaceInfo {
        InterfaceInfo::new(
            "wlan0".into(),
            TransportType::WiFi,
            Some("10.0.0.5".parse().unwrap()),
            status,
        )
    }

    #[test]
    fn test_wifi_transport_type() {
        let iface = make_test_interface(InterfaceStatus::Up);
        let transport = WiFiTransport::new(iface);
        assert_eq!(transport.transport_type(), TransportType::WiFi);
    }

    #[test]
    fn test_wifi_priority() {
        let iface = make_test_interface(InterfaceStatus::Up);
        let transport = WiFiTransport::new(iface);
        assert_eq!(transport.priority().0, 20); // WiFi default priority
    }

    #[test]
    fn test_wifi_display_name() {
        let iface = make_test_interface(InterfaceStatus::Up);
        let transport = WiFiTransport::new(iface);
        assert!(transport.display_name().contains("WiFi"));
        assert!(transport.display_name().contains("wlan0"));
    }

    #[test]
    fn test_wifi_creation_preserves_interface() {
        let iface = make_test_interface(InterfaceStatus::Down);
        let transport = WiFiTransport::new(iface.clone());
        assert_eq!(transport.transport_type(), TransportType::WiFi);
        assert_eq!(transport.priority().0, 20);
    }
}
