use async_trait::async_trait;

use crate::netbridge::types::WifiNetwork;

/// Current station default. Runtime configuration may select either physical
/// station interface without changing the backend implementation.
pub const DEFAULT_NM_UPLINK_INTERFACE: &str = "wlan0";
pub const NM_UPLINK_INTERFACES: [&str; 2] = ["wlan0", "wlan1"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkDeviceKind {
    Unknown,
    Ethernet,
    Wifi,
    Other(u32),
}

impl From<u32> for NetworkDeviceKind {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::Unknown,
            1 => Self::Ethernet,
            2 => Self::Wifi,
            other => Self::Other(other),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkDevice {
    pub object_path: String,
    pub interface: String,
    pub kind: NetworkDeviceKind,
    pub state: u32,
    pub managed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkManagerPreflight {
    pub version: String,
    pub state: u32,
    pub uplink: NetworkDevice,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NetworkBackendError {
    #[error("E_NM_UNAVAILABLE: {0}")]
    Unavailable(String),
    #[error("E_NM_TIMEOUT: NetworkManager did not answer within the configured timeout")]
    Timeout,
    #[error(
        "E_WIFI_ASSOC_TIMEOUT: Wi-Fi association did not complete within the configured timeout"
    )]
    AssociationTimeout,
    #[error(
        "E_WIFI_INTERFACE_DENIED: NetworkManager operations are restricted to wlan0/wlan1; refused {0}"
    )]
    InterfaceDenied(String),
    #[error("E_WIFI_DEVICE_NOT_FOUND: {0}")]
    DeviceNotFound(String),
    #[error("E_WIFI_DEVICE_UNMANAGED: {0}")]
    DeviceUnmanaged(String),
    #[error("E_WIFI_DEVICE_NOT_WIFI: {0}")]
    DeviceNotWifi(String),
    #[error("E_WIFI_SCAN_FAILED: {0}")]
    ScanFailed(String),
    #[error("E_WIFI_PROFILE_DBUS: {0}")]
    ProfileOperation(String),
    #[error("E_WIFI_ACTIVATION_FAILED: {0}")]
    ActivationFailed(String),
    #[error("E_WIFI_AUTH_FAILED: {0}")]
    AuthenticationFailed(String),
    #[error("E_WIFI_SSID_NOT_FOUND: {0}")]
    SsidNotFound(String),
    #[error("E_WIFI_IP_CONFIG_FAILED: {0}")]
    IpConfigFailed(String),
    #[error("E_WIFI_NO_IP: activated connection has no usable IPv4 address")]
    NoIpv4Address,
    #[error("E_WIFI_DEACTIVATION_FAILED: {0}")]
    DeactivationFailed(String),
}

impl NetworkBackendError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unavailable(_) => "E_NM_UNAVAILABLE",
            Self::Timeout => "E_NM_TIMEOUT",
            Self::AssociationTimeout => "E_WIFI_ASSOC_TIMEOUT",
            Self::InterfaceDenied(_) => "E_WIFI_INTERFACE_DENIED",
            Self::DeviceNotFound(_) => "E_WIFI_DEVICE_NOT_FOUND",
            Self::DeviceUnmanaged(_) => "E_WIFI_DEVICE_UNMANAGED",
            Self::DeviceNotWifi(_) => "E_WIFI_DEVICE_NOT_WIFI",
            Self::ScanFailed(_) => "E_WIFI_SCAN_FAILED",
            Self::ProfileOperation(_) => "E_WIFI_PROFILE_DBUS",
            Self::ActivationFailed(_) => "E_WIFI_ACTIVATION_FAILED",
            Self::AuthenticationFailed(_) => "E_WIFI_AUTH_FAILED",
            Self::SsidNotFound(_) => "E_WIFI_SSID_NOT_FOUND",
            Self::IpConfigFailed(_) => "E_WIFI_IP_CONFIG_FAILED",
            Self::NoIpv4Address => "E_WIFI_NO_IP",
            Self::DeactivationFailed(_) => "E_WIFI_DEACTIVATION_FAILED",
        }
    }
}

/// Refuses non-station targets. The caller's runtime configuration chooses
/// which of the two physical station interfaces is the current uplink.
pub fn require_nm_uplink(interface: &str) -> Result<(), NetworkBackendError> {
    if NM_UPLINK_INTERFACES.contains(&interface) {
        Ok(())
    } else {
        Err(NetworkBackendError::InterfaceDenied(interface.to_owned()))
    }
}

#[async_trait]
pub trait NetworkBackend: Send + Sync {
    /// Read-only inventory. Listing a device does not authorize changing it.
    async fn devices(&self) -> Result<Vec<NetworkDevice>, NetworkBackendError>;

    /// Read-only validation of the dedicated NetworkManager uplink.
    async fn preflight(
        &self,
        interface: &str,
    ) -> Result<NetworkManagerPreflight, NetworkBackendError>;

    /// Actively scan without creating or activating a connection profile.
    async fn scan(&self, interface: &str) -> Result<Vec<WifiNetwork>, NetworkBackendError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_station_interfaces_are_allowed_nm_targets() {
        assert!(require_nm_uplink("wlan0").is_ok());
        assert!(require_nm_uplink("wlan1").is_ok());

        for protected in ["uap0", "uap1", "wfd0", "eth0", "", "wlan10"] {
            let error = require_nm_uplink(protected).unwrap_err();
            assert_eq!(error.code(), "E_WIFI_INTERFACE_DENIED");
            assert!(error.to_string().contains(protected));
        }
    }

    #[test]
    fn network_manager_device_types_are_mapped_without_guessing() {
        assert_eq!(NetworkDeviceKind::from(0), NetworkDeviceKind::Unknown);
        assert_eq!(NetworkDeviceKind::from(1), NetworkDeviceKind::Ethernet);
        assert_eq!(NetworkDeviceKind::from(2), NetworkDeviceKind::Wifi);
        assert_eq!(NetworkDeviceKind::from(99), NetworkDeviceKind::Other(99));
    }
}
