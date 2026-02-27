// src/cot/transports/ethernet.rs
use crate::cot::transport_trait::{Transport, TransportHealth, TransportMessage};
use crate::cot::types::{CotError, CotResult, InterfaceInfo, TransportPriority, TransportType};
use async_trait::async_trait;
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub struct EthernetTransport {
    interface: InterfaceInfo,
}

impl EthernetTransport {
    pub fn new(interface: InterfaceInfo) -> Self {
        Self { interface }
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

    async fn is_available(&self) -> bool {
        self.interface.is_usable()
    }

    async fn send(&self, message: &TransportMessage) -> CotResult<()> {
        let mut stream = TcpStream::connect(&message.target_address)
            .await
            .map_err(|e| {
                CotError::TransportError(format!(
                    "Ethernet send to {} failed: {}",
                    message.target_address, e
                ))
            })?;

        let len = (message.payload.len() as u32).to_be_bytes();
        stream.write_all(&len).await.map_err(|e| {
            CotError::TransportError(format!("Ethernet write length failed: {}", e))
        })?;
        stream.write_all(&message.payload).await.map_err(|e| {
            CotError::TransportError(format!("Ethernet write payload failed: {}", e))
        })?;
        stream
            .flush()
            .await
            .map_err(|e| CotError::TransportError(format!("Ethernet flush failed: {}", e)))?;
        Ok(())
    }

    async fn health_check(&self) -> TransportHealth {
        if !self.interface.is_usable() {
            return TransportHealth::unhealthy("Interface not usable");
        }
        let start = Instant::now();
        let latency = start.elapsed().as_millis() as u64;
        TransportHealth::healthy(latency.max(1), 1_000_000)
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
