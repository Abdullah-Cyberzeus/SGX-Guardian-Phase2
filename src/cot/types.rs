// src/cot/types.rs
// ============================================================
// Shared types, enums, errors for the CoT transport layer.
// All CoT modules import from here — single source of truth.
// ============================================================

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;

/// Result alias used throughout the CoT layer.
pub type CotResult<T> = Result<T, CotError>;

// ----------------------------------------------------------
// Transport Type Enum
// ----------------------------------------------------------

/// Enumerates all supported transport types.
/// The CoT layer uses this to identify which physical medium
/// a connection is flowing over — without coupling trust logic
/// to any specific transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportType {
    Ethernet,
    WiFi,
    Bluetooth,
    Cellular, // LTE / 5G
    Satellite,
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportType::Ethernet => write!(f, "Ethernet"),
            TransportType::WiFi => write!(f, "WiFi"),
            TransportType::Bluetooth => write!(f, "Bluetooth"),
            TransportType::Cellular => write!(f, "Cellular"),
            TransportType::Satellite => write!(f, "Satellite"),
        }
    }
}

impl TransportType {
    /// Returns the default priority for this transport type.
    /// Lower number = higher priority (preferred).
    /// Ethernet is most reliable, satellite is last resort.
    pub fn default_priority(&self) -> u8 {
        match self {
            TransportType::Ethernet => 10,
            TransportType::WiFi => 20,
            TransportType::Cellular => 30,
            TransportType::Bluetooth => 40,
            TransportType::Satellite => 50,
        }
    }
}

// ----------------------------------------------------------
// Transport Priority
// ----------------------------------------------------------

/// Wraps a priority value. Lower = better.
/// Used by the registry to pick the best available transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TransportPriority(pub u8);

impl TransportPriority {
    pub fn new(value: u8) -> Self {
        Self(value)
    }
}

impl Default for TransportPriority {
    fn default() -> Self {
        Self(255) // lowest priority
    }
}

// ----------------------------------------------------------
// Interface Status
// ----------------------------------------------------------

/// Represents the current link/availability state of a
/// network interface on the host machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterfaceStatus {
    Up,
    Down,
    Unknown,
}

impl fmt::Display for InterfaceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InterfaceStatus::Up => write!(f, "UP"),
            InterfaceStatus::Down => write!(f, "DOWN"),
            InterfaceStatus::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

// ----------------------------------------------------------
// Interface Info
// ----------------------------------------------------------

/// Describes a single network interface detected on the host.
/// This is the output of the interface detector (D3).
/// It maps a physical NIC name (like "eth0") to a transport type,
/// an IP address, and an up/down status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceInfo {
    /// OS-level interface name (e.g., "eth0", "wlan0", "bnep0")
    pub name: String,
    /// Which transport type this interface maps to
    pub transport_type: TransportType,
    /// IP address assigned to this interface (if any)
    pub ip_addr: Option<IpAddr>,
    /// Current link status
    pub status: InterfaceStatus,
    /// Priority (lower = better). Defaults from transport type.
    pub priority: TransportPriority,
}

impl InterfaceInfo {
    pub fn new(
        name: String,
        transport_type: TransportType,
        ip_addr: Option<IpAddr>,
        status: InterfaceStatus,
    ) -> Self {
        let priority = TransportPriority::new(transport_type.default_priority());
        Self {
            name,
            transport_type,
            ip_addr,
            status,
            priority,
        }
    }

    /// Returns true if the interface is usable (up + has IP).
    pub fn is_usable(&self) -> bool {
        self.status == InterfaceStatus::Up && self.ip_addr.is_some()
    }
}

// ----------------------------------------------------------
// Peer Endpoint
// ----------------------------------------------------------

/// Represents how to reach a peer through a specific transport.
/// Peers may have multiple endpoints (one per transport).
/// Trust is bound to device_id, NOT to any specific endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEndpoint {
    /// The device identity fingerprint (SHA-256 of public key)
    pub device_id: String,
    /// Transport used to reach this endpoint
    pub transport_type: TransportType,
    /// Address string — format depends on transport:
    ///   Ethernet/WiFi: "192.168.1.10:50051"
    ///   Bluetooth: "AA:BB:CC:DD:EE:FF"
    ///   Cellular: "10.0.0.5:50051"
    ///   Satellite: "sat://node-xyz"
    pub address: String,
    /// When this endpoint was last confirmed reachable
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
    /// Is this endpoint currently considered reachable?
    pub reachable: bool,
}

impl PeerEndpoint {
    pub fn new(device_id: String, transport_type: TransportType, address: String) -> Self {
        Self {
            device_id,
            transport_type,
            address,
            last_seen: None,
            reachable: false,
        }
    }
}

// ----------------------------------------------------------
// CoT Error
// ----------------------------------------------------------

/// All errors that can occur in the CoT layer.
/// Each variant maps to a specific failure domain.
#[derive(Debug)]
pub enum CotError {
    /// No usable transport is available
    NoTransportAvailable,
    /// The specified transport is not registered
    TransportNotRegistered(TransportType),
    /// The peer with this device_id is not known
    PeerNotFound(String),
    /// Session has expired or is invalid
    SessionInvalid(String),
    /// Trust verification failed
    TrustVerificationFailed(String),
    /// Circle membership denied
    MembershipDenied(String),
    /// Interface detection failed
    InterfaceDetectionFailed(String),
    /// Generic I/O or transport error
    TransportError(String),
    /// Configuration error
    ConfigError(String),
    /// Identity-related error
    IdentityError(String),
}

impl fmt::Display for CotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CotError::NoTransportAvailable => write!(f, "CoT: no usable transport available"),
            CotError::TransportNotRegistered(t) => write!(f, "CoT: transport {} not registered", t),
            CotError::PeerNotFound(id) => write!(f, "CoT: peer not found: {}", id),
            CotError::SessionInvalid(reason) => write!(f, "CoT: session invalid: {}", reason),
            CotError::TrustVerificationFailed(reason) => {
                write!(f, "CoT: trust verification failed: {}", reason)
            }
            CotError::MembershipDenied(reason) => write!(f, "CoT: membership denied: {}", reason),
            CotError::InterfaceDetectionFailed(reason) => {
                write!(f, "CoT: interface detection failed: {}", reason)
            }
            CotError::TransportError(msg) => write!(f, "CoT: transport error: {}", msg),
            CotError::ConfigError(msg) => write!(f, "CoT: config error: {}", msg),
            CotError::IdentityError(msg) => write!(f, "CoT: identity error: {}", msg),
        }
    }
}

impl std::error::Error for CotError {}

// ----------------------------------------------------------
// Unit Tests
// ----------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_type_display() {
        assert_eq!(format!("{}", TransportType::Ethernet), "Ethernet");
        assert_eq!(format!("{}", TransportType::Satellite), "Satellite");
    }

    #[test]
    fn test_transport_default_priority() {
        assert!(
            TransportType::Ethernet.default_priority() < TransportType::WiFi.default_priority()
        );
        assert!(
            TransportType::WiFi.default_priority() < TransportType::Satellite.default_priority()
        );
    }

    #[test]
    fn test_interface_info_usable() {
        let up_with_ip = InterfaceInfo::new(
            "eth0".into(),
            TransportType::Ethernet,
            Some("192.168.1.10".parse().unwrap()),
            InterfaceStatus::Up,
        );
        assert!(up_with_ip.is_usable());

        let down = InterfaceInfo::new(
            "eth0".into(),
            TransportType::Ethernet,
            Some("192.168.1.10".parse().unwrap()),
            InterfaceStatus::Down,
        );
        assert!(!down.is_usable());

        let no_ip = InterfaceInfo::new(
            "eth0".into(),
            TransportType::Ethernet,
            None,
            InterfaceStatus::Up,
        );
        assert!(!no_ip.is_usable());
    }

    #[test]
    fn test_cot_error_display() {
        let err = CotError::NoTransportAvailable;
        assert!(format!("{}", err).contains("no usable transport"));
    }

    #[test]
    fn test_peer_endpoint_creation() {
        let ep = PeerEndpoint::new(
            "abc123".into(),
            TransportType::WiFi,
            "192.168.1.5:50051".into(),
        );
        assert_eq!(ep.device_id, "abc123");
        assert!(!ep.reachable);
    }
}
