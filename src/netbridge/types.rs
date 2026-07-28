use std::io;

/// Configuration options for the AP.
#[derive(Debug, Clone)]
pub struct ApSettings {
    pub interface: String,
    pub ssid: String,
    pub wpa_passphrase: Option<String>,
    pub channel: u8,
    pub hw_mode: String,
    pub country_code: String,
    pub client_isolation: bool,
}

impl Default for ApSettings {
    fn default() -> Self {
        ApSettings {
            interface: "ap0".to_string(),
            ssid: "ARMIA".to_string(),
            wpa_passphrase: Some("P@ssword123".to_string()),
            channel: 6,
            hw_mode: "g".to_string(),
            country_code: "US".to_string(),
            client_isolation: true,
        }
    }
}

/// Configuration options for DHCP/DNS (dnsmasq).
#[derive(Debug, Clone)]
pub struct DnsmasqSettings {
    pub interface: String,
    pub gateway_ip: String,
    pub dhcp_range_start: String,
    pub dhcp_range_end: String,
    pub local_domain: String,
}

impl Default for DnsmasqSettings {
    fn default() -> Self {
        DnsmasqSettings {
            interface: "ap0".to_string(),
            gateway_ip: "192.168.200.1".to_string(),
            dhcp_range_start: "192.168.200.100".to_string(),
            dhcp_range_end: "192.168.200.254".to_string(),
            local_domain: "guardian.local".to_string(),
        }
    }
}

/// Configuration options for the bootstrap process.
#[derive(Debug, Clone)]
pub struct BootstrapOptions {
    pub runtime_dir: String,
    pub template_path: String,
    pub output_config_path: String,
}

impl Default for BootstrapOptions {
    fn default() -> Self {
        BootstrapOptions {
            runtime_dir: "/tmp/netbridge".to_string(),
            template_path: "/etc/sgx-guardian/hostapd.conf.template".to_string(),
            output_config_path: "/tmp/netbridge/hostapd.conf".to_string(),
        }
    }
}

/// Process state enum to track hostapd's lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessStatus {
    Starting,
    Running,
    Stopped,
    Crashed,
}

/// Overall AP status used by higher-level orchestrator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApStatus {
    Inactive,
    Initializing,
    Active,
    Error(String),
}

/// Stores the result of system capability validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationResult {
    pub interface_detected: bool,
    pub ap_mode_supported: bool,
    pub hostapd_installed: bool,
    pub iw_installed: bool,
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        self.interface_detected
            && self.ap_mode_supported
            && self.hostapd_installed
            && self.iw_installed
    }
}

use crate::runtime::models::SavedWifi;

/// Configuration options for connecting to external WiFi (STA mode).
#[derive(Debug, Clone)]
pub struct WifiClientSettings {
    pub interface: String,
    pub networks: Vec<SavedWifi>,
    pub country: String,
}

impl Default for WifiClientSettings {
    fn default() -> Self {
        WifiClientSettings {
            interface: "wlan1".to_string(), // Typical secondary interface
            networks: Vec::new(),
            country: "US".to_string(),
        }
    }
}

use serde::{Deserialize, Serialize};

/// Represents a scanned Wi-Fi network.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WifiNetwork {
    pub ssid: String,
    pub bssid: String,
    pub signal_dbm: i32,
    pub band: String,
    pub security: String,
}

/// Represents the overall health and status of the upstream internet connection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UplinkState {
    Unknown,
    Connected,
    Disconnected,
    NoInternet,
}

/// Represents the internal state machine of the wpa_supplicant Wi-Fi client
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WifiClientState {
    Disconnected,
    Scanning,
    Authenticating,
    Connected,
    AuthFailed,
}

/// Represents the DHCP client lease status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpLeaseState {
    Unknown,
    Requesting,
    Bound,
    Renewing,
    Expired,
}

/// Shared error handling used by all netbridge modules.
#[derive(Debug)]
pub enum NetbridgeError {
    IoError(io::Error),
    ValidationFailed(String),
    ConfigGenerationFailed(String),
    ProcessExecutionFailed(String),
    BootstrapFailed(String),
    MissingDependency(String),
    TemplateError(String),
    ConnectionFailed(String),
}

impl From<io::Error> for NetbridgeError {
    fn from(error: io::Error) -> Self {
        NetbridgeError::IoError(error)
    }
}

impl std::fmt::Display for NetbridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetbridgeError::IoError(e) => write!(f, "IO Error: {}", e),
            NetbridgeError::ValidationFailed(msg) => write!(f, "Validation Failed: {}", msg),
            NetbridgeError::ConfigGenerationFailed(msg) => {
                write!(f, "Config Generation Failed: {}", msg)
            }
            NetbridgeError::ProcessExecutionFailed(msg) => {
                write!(f, "Process Execution Failed: {}", msg)
            }
            NetbridgeError::BootstrapFailed(msg) => write!(f, "Bootstrap Failed: {}", msg),
            NetbridgeError::MissingDependency(msg) => write!(f, "Missing Dependency: {}", msg),
            NetbridgeError::TemplateError(msg) => write!(f, "Template Error: {}", msg),
            NetbridgeError::ConnectionFailed(msg) => write!(f, "Connection Failed: {}", msg),
        }
    }
}

impl std::error::Error for NetbridgeError {}
