// src/cot/transports/mod.rs
// ============================================================
// Concrete transport implementations sub-module.
// ============================================================

pub mod bluetooth;
pub mod cellular;
pub mod ethernet;
pub mod satellite;
pub mod wifi;

use crate::cot::interface_detector::InterfaceDetector;
use crate::cot::transport_trait::Transport;
use crate::cot::types::{CotResult, InterfaceInfo, TransportType};
use std::sync::Arc;

/// Factory: create a Transport from an InterfaceInfo.
pub fn create_transport(iface: &InterfaceInfo) -> Arc<dyn Transport> {
    match iface.transport_type {
        TransportType::Ethernet => Arc::new(ethernet::EthernetTransport::new(iface.clone())),
        TransportType::WiFi => Arc::new(wifi::WiFiTransport::new(iface.clone())),
        TransportType::Bluetooth => Arc::new(bluetooth::BluetoothTransport::new(iface.clone())),
        TransportType::Cellular => Arc::new(cellular::CellularTransport::new(iface.clone())),
        TransportType::Satellite => Arc::new(satellite::SatelliteTransport::new(iface.clone())),
    }
}

/// Auto-detect all interfaces and create transports for usable ones.
pub fn auto_create_transports() -> CotResult<Vec<Arc<dyn Transport>>> {
    let interfaces = InterfaceDetector::detect_usable()?;
    let transports: Vec<Arc<dyn Transport>> = interfaces
        .iter()
        .map(|iface| create_transport(iface))
        .collect();
    Ok(transports)
}
