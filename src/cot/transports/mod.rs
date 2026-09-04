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
    use crate::runtime_gates::GATES;
    let interfaces = InterfaceDetector::detect_usable()?;
    let transports: Vec<Arc<dyn Transport>> = interfaces
        .iter()
        .filter(|iface| match iface.transport_type {
            TransportType::Bluetooth if GATES.disable_cot_bluetooth => false,
            TransportType::Cellular if GATES.disable_cot_cellular => false,
            TransportType::Satellite if GATES.disable_cot_satellite => false,
            _ => true,
        })
        .map(|iface| create_transport(iface))
        .collect();
    Ok(transports)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cot::types::{InterfaceStatus, TransportPriority};

    fn iface(name: &str, transport_type: TransportType) -> InterfaceInfo {
        InterfaceInfo {
            name: name.to_string(),
            transport_type,
            ip_addr: None,
            status: InterfaceStatus::Up,
            priority: TransportPriority::default(),
        }
    }

    #[test]
    fn create_transport_builds_the_matching_transport_for_every_type() {
        for (name, transport_type) in [
            ("eth0", TransportType::Ethernet),
            ("wlan0", TransportType::WiFi),
            ("bnep0", TransportType::Bluetooth),
            ("wwan0", TransportType::Cellular),
            ("sat0", TransportType::Satellite),
        ] {
            let transport = create_transport(&iface(name, transport_type));
            assert_eq!(
                transport.transport_type(),
                transport_type,
                "factory returned the wrong transport for {name}"
            );
            assert_eq!(transport.interface_name(), name);
        }
    }

    #[test]
    fn auto_create_transports_scans_real_interfaces_and_honours_the_runtime_gates() {
        // Runs against this host's real interfaces via `InterfaceDetector`.
        // The assertion is on the invariant rather than on a specific set,
        // because which interfaces exist is a property of the machine.
        let transports = auto_create_transports().expect("interface scan succeeds");

        use crate::runtime_gates::GATES;
        for transport in &transports {
            let disabled = match transport.transport_type() {
                TransportType::Bluetooth => GATES.disable_cot_bluetooth,
                TransportType::Cellular => GATES.disable_cot_cellular,
                TransportType::Satellite => GATES.disable_cot_satellite,
                _ => false,
            };
            assert!(
                !disabled,
                "a gated-off transport ({:?}) must never be created",
                transport.transport_type()
            );
            assert!(!transport.interface_name().is_empty());
        }
    }
}
