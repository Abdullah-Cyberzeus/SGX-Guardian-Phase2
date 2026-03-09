// src/cot/transports/bluetooth.rs
// STUB — replaced with full implementation in future.
use crate::cot::transport_trait::{Transport, TransportHealth, TransportMessage};
use crate::cot::types::{CotError, CotResult, InterfaceInfo, TransportPriority, TransportType};
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct BluetoothTransport {
    interface: InterfaceInfo,
}

impl BluetoothTransport {
    pub fn new(interface: InterfaceInfo) -> Self {
        Self { interface }
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
    async fn is_available(&self) -> bool {
        false
    }
    async fn send(&self, _message: &TransportMessage) -> CotResult<()> {
        Err(CotError::TransportError(
            "Bluetooth transport not yet implemented".into(),
        ))
    }
    async fn health_check(&self) -> TransportHealth {
        TransportHealth::unhealthy("Bluetooth transport not yet implemented")
    }
    fn display_name(&self) -> String {
        format!("Bluetooth({})[STUB]", self.interface.name)
    }
}
