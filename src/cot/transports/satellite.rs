// src/cot/transports/satellite.rs
// STUB — replaced with full implementation in Deliverable 14
use crate::cot::transport_trait::{Transport, TransportHealth, TransportMessage};
use crate::cot::types::{CotError, CotResult, InterfaceInfo, TransportPriority, TransportType};
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct SatelliteTransport {
    interface: InterfaceInfo,
}

impl SatelliteTransport {
    pub fn new(interface: InterfaceInfo) -> Self {
        Self { interface }
    }
}

#[async_trait]
impl Transport for SatelliteTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Satellite
    }
    fn priority(&self) -> TransportPriority {
        self.interface.priority
    }
    async fn is_available(&self) -> bool {
        false
    }
    async fn send(&self, _message: &TransportMessage) -> CotResult<()> {
        Err(CotError::TransportError(
            "Satellite transport not yet implemented".into(),
        ))
    }
    async fn health_check(&self) -> TransportHealth {
        TransportHealth::unhealthy("Satellite transport not yet implemented")
    }
    fn display_name(&self) -> String {
        format!("Satellite({})[STUB]", self.interface.name)
    }
}
