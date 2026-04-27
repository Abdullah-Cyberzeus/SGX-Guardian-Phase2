// src/cot/transports/ethernet.rs
use crate::cot::transport_trait::{Transport, TransportHealth, TransportMessage};
use crate::cot::types::{CotError, CotResult, InterfaceInfo, TransportPriority, TransportType};
use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpSocket, TcpStream};

#[derive(Debug, Clone)]
pub struct EthernetTransport {
    interface: InterfaceInfo,
}

impl EthernetTransport {
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
        let speed =
            std::fs::read_to_string(format!("/sys/class/net/{}/speed", self.interface.name))
                .ok()
                .and_then(|s| s.trim().parse::<i64>().ok())
                .filter(|v| *v > 0)
                .map(|v| v as u64)
                .unwrap_or(100);
        speed.saturating_mul(1000)
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
        let stream = tokio::time::timeout(Duration::from_millis(1500), socket.connect(remote))
            .await
            .ok()?
            .ok()?;
        drop(stream);
        Some(start.elapsed().as_millis().max(1) as u64)
    }
}

#[async_trait]
impl Transport for EthernetTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Ethernet
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
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TcpStream::connect(&message.target_address),
        )
        .await
        .map_err(|_| {
            CotError::TransportError(format!(
                "Ethernet connect to {} timed out",
                message.target_address
            ))
        })?
        .map_err(|e| {
            CotError::TransportError(format!(
                "Ethernet send to {} failed: {}",
                message.target_address, e
            ))
        })?;

        let len = (message.payload.len() as u32).to_be_bytes();
        tokio::time::timeout(std::time::Duration::from_secs(5), stream.write_all(&len))
            .await
            .map_err(|_| CotError::TransportError("Ethernet write length timed out".into()))?
            .map_err(|e| {
                CotError::TransportError(format!("Ethernet write length failed: {}", e))
            })?;
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.write_all(&message.payload),
        )
        .await
        .map_err(|_| CotError::TransportError("Ethernet write payload timed out".into()))?
        .map_err(|e| CotError::TransportError(format!("Ethernet write payload failed: {}", e)))?;
        tokio::time::timeout(std::time::Duration::from_secs(5), stream.flush())
            .await
            .map_err(|_| CotError::TransportError("Ethernet flush timed out".into()))?
            .map_err(|e| CotError::TransportError(format!("Ethernet flush failed: {}", e)))?;
        Ok(())
    }

    async fn health_check(&self) -> TransportHealth {
        if self.interface.ip_addr.is_none() {
            return TransportHealth::unhealthy("Ethernet has no IP");
        }
        if !self.has_operstate_up() {
            return TransportHealth::unhealthy("Ethernet operstate is down");
        }
        if !self.has_carrier() {
            return TransportHealth::unhealthy("Ethernet link carrier is down");
        }
        if !self.has_default_route() {
            return TransportHealth::unhealthy("Ethernet network not reachable (no default route)");
        }
        let bw = self.link_speed_kbps();
        let latency = self.latency_probe_ms().await.unwrap_or(5);
        if latency > 1200 {
            return TransportHealth::unhealthy("Ethernet network not reachable (probe timeout)");
        }
        if bw == 0 {
            return TransportHealth::unhealthy("Interface not usable");
        }
        TransportHealth::healthy(latency.max(1), bw)
    }

    fn display_name(&self) -> String {
        format!("Ethernet({})", self.interface.name)
    }
}

//--------------------
//Unit Test

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cot::types::{InterfaceInfo, InterfaceStatus, TransportType};

    fn make_test_interface(status: InterfaceStatus) -> InterfaceInfo {
        InterfaceInfo::new(
            "eth0".into(),
            TransportType::Ethernet,
            Some("192.168.1.10".parse().unwrap()),
            status,
        )
    }

    #[test]
    fn test_ethernet_transport_type() {
        let iface = make_test_interface(InterfaceStatus::Up);
        let transport = EthernetTransport::new(iface);
        assert_eq!(transport.transport_type(), TransportType::Ethernet);
    }

    #[test]
    fn test_ethernet_priority() {
        let iface = make_test_interface(InterfaceStatus::Up);
        let transport = EthernetTransport::new(iface);
        assert_eq!(transport.priority().0, 10); // Ethernet default priority
    }

    #[test]
    fn test_ethernet_display_name() {
        let iface = make_test_interface(InterfaceStatus::Up);
        let transport = EthernetTransport::new(iface);
        assert!(transport.display_name().contains("Ethernet"));
        assert!(transport.display_name().contains("eth0"));
    }

    #[test]
    fn test_ethernet_creation_preserves_interface() {
        let iface = make_test_interface(InterfaceStatus::Down);
        let transport = EthernetTransport::new(iface.clone());
        // Verify the transport stores the interface correctly
        assert_eq!(transport.transport_type(), TransportType::Ethernet);
        assert_eq!(transport.priority().0, 10);
    }
}
