use crate::cot::transport_trait::{Transport, TransportHealth, TransportMessage};
use crate::cot::types::{CotError, CotResult, InterfaceInfo, TransportPriority, TransportType};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct WiFiTransport {
    interface: InterfaceInfo,
    availability: Arc<RwLock<bool>>,
}

impl WiFiTransport {
    pub fn new(interface: InterfaceInfo) -> Self {
        let availability = Arc::new(RwLock::new(interface.is_usable()));
        let iface_name = interface.name.clone();
        let availability_clone = availability.clone();

        // Non-blocking operstate monitoring
        tokio::spawn(async move {
            loop {
                let path = format!("/sys/class/net/{}/operstate", iface_name);
                let state = tokio::fs::read_to_string(&path).await;

                let is_up = match state {
                    Ok(content) => content.trim() == "up",
                    Err(_) => false,
                };

                {
                    let mut avail = availability_clone.write().await;
                    *avail = is_up;
                }

                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });

        Self {
            interface,
            availability,
        }
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

    async fn is_available(&self) -> bool {
        *self.availability.read().await
    }

    async fn send(&self, message: &TransportMessage) -> CotResult<()> {
        if message.payload.len() > 10_000_000 {
            return Err(CotError::TransportError(
                "Payload too large".into(),
            ));
        }

        let connect_future = TcpStream::connect(&message.target_address);

        let mut stream = timeout(Duration::from_secs(5), connect_future)
            .await
            .map_err(|_| CotError::TransportError("WiFi connect timeout".into()))?
            .map_err(|e| {
                CotError::TransportError(format!(
                    "WiFi connect to {} failed: {}",
                    message.target_address, e
                ))
            })?;

        let len = (message.payload.len() as u32).to_be_bytes();

        stream
            .write_all(&len)
            .await
            .map_err(|e| CotError::TransportError(format!("WiFi write length failed: {}", e)))?;

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
        if !self.is_available().await {
            return TransportHealth::unhealthy("WiFi interface down");
        }

        TransportHealth::healthy(10, 100_000)
    }

    fn display_name(&self) -> String {
        format!("WiFi({})", self.interface.name)
    }
}