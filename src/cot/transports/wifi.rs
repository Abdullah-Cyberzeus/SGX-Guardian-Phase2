// src/cot/transports/wifi.rs
use crate::cot::transport_trait::{Transport, TransportHealth, TransportMessage};
use crate::cot::types::{CotError, CotResult, InterfaceInfo, TransportPriority, TransportType};
use async_trait::async_trait;
//use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub struct WiFiTransport {
    interface: InterfaceInfo,
}

impl WiFiTransport {
    pub fn new(interface: InterfaceInfo) -> Self {
        Self { interface }
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
        self.interface.is_usable()
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
        if !self.interface.is_usable() {
            return TransportHealth::unhealthy("WiFi interface not usable");
        }
        TransportHealth::healthy(5, 300_000)
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
