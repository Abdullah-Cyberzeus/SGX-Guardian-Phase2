// src/cot/transports/cellular.rs
// STUB — replaced with full implementation in future.
use crate::cot::transport_trait::{Transport, TransportHealth, TransportMessage};
use crate::cot::types::{CotError, CotResult, InterfaceInfo, TransportPriority, TransportType};
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct CellularTransport {
    interface: InterfaceInfo,
}

impl CellularTransport {
    pub fn new(interface: InterfaceInfo) -> Self {
        Self { interface }
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
    async fn is_available(&self) -> bool {
        false
    }
    async fn send(&self, _message: &TransportMessage) -> CotResult<()> {
        Err(CotError::TransportError(
            "Cellular transport not yet implemented".into(),
        ))
    }
    async fn health_check(&self) -> TransportHealth {
        TransportHealth::unhealthy("Cellular transport not yet implemented")
    }
    fn display_name(&self) -> String {
        format!("Cellular({})[STUB]", self.interface.name)
    }
}
