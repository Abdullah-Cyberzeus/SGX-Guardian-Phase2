use std::process::Command;
use std::str;

#[derive(Debug)]
pub enum ValidationError {
    CommandExecutionFailed(String),
    InterfaceNotFound,
    APModeNotSupported,
    HostapdNotInstalled,
    IwNotInstalled,
    DnsmasqNotInstalled,
    PortInUse(u16),
    WpaSupplicantNotInstalled,
    UdhcpcNotInstalled,
    InterfaceNotAvailable(String),
    PermissionDenied,
    ClientModeNotSupported,
    InterfaceBusy(String),
    ScanFailed(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::CommandExecutionFailed(cmd) => {
                write!(f, "Failed to execute command: {}", cmd)
            }
            ValidationError::InterfaceNotFound => write!(f, "No WiFi interface found"),
            ValidationError::APModeNotSupported => {
                write!(f, "WiFi interface does not support AP mode")
            }
            ValidationError::HostapdNotInstalled => write!(f, "hostapd is not installed"),
            ValidationError::IwNotInstalled => write!(f, "iw is not installed"),
            ValidationError::DnsmasqNotInstalled => write!(f, "dnsmasq is not installed"),
            ValidationError::PortInUse(port) => {
                write!(f, "Port {} is already in use by another service", port)
            }
            ValidationError::WpaSupplicantNotInstalled => {
                write!(f, "wpa_supplicant is not installed")
            }
            ValidationError::UdhcpcNotInstalled => write!(f, "udhcpc is not installed"),
            ValidationError::InterfaceNotAvailable(iface) => {
                write!(f, "Interface {} is not available or does not exist", iface)
            }
            ValidationError::PermissionDenied => write!(
                f,
                "Root permissions required to initialize network interfaces"
            ),
            ValidationError::ClientModeNotSupported => {
                write!(f, "WiFi interface does not support managed (client) mode")
            }
            ValidationError::InterfaceBusy(iface) => write!(
                f,
                "Interface {} is currently busy or managed by another wpa_supplicant process",
                iface
            ),
            ValidationError::ScanFailed(iface) => {
                write!(f, "Hardware WiFi scan failed on interface {}", iface)
            }
        }
    }
}

impl std::error::Error for ValidationError {}

pub struct Validator;

impl Validator {
    pub fn new() -> Self {
        Validator {}
    }
}

impl Default for Validator {
    fn default() -> Self {
        Self::new()
    }
}

impl Validator {
    /// Detects a WiFi interface on the system.
    /// Returns the name of the interface if found.
    pub fn detect_wifi_interface(&self) -> Result<String, ValidationError> {
        let output = Command::new("iw")
            .arg("dev")
            .output()
            .map_err(|_| ValidationError::IwNotInstalled)?;

        if !output.status.success() {
            return Err(ValidationError::CommandExecutionFailed(
                "iw dev".to_string(),
            ));
        }

        let output_str = str::from_utf8(&output.stdout).unwrap_or("");

        for line in output_str.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("Interface ") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    return Ok(parts[1].to_string());
                }
            }
        }

        Err(ValidationError::InterfaceNotFound)
    }

    /// Checks if the system's WiFi hardware supports AP mode.
    pub fn check_ap_mode_support(&self) -> Result<bool, ValidationError> {
        let output = Command::new("iw")
            .arg("list")
            .output()
            .map_err(|_| ValidationError::IwNotInstalled)?;

        if !output.status.success() {
            return Err(ValidationError::CommandExecutionFailed(
                "iw list".to_string(),
            ));
        }

        let output_str = str::from_utf8(&output.stdout).unwrap_or("");

        let mut in_supported_modes = false;
        for line in output_str.lines() {
            let trimmed = line.trim();
            if trimmed == "Supported interface modes:" {
                in_supported_modes = true;
                continue;
            }
            if in_supported_modes {
                if trimmed.starts_with('*') {
                    if trimmed == "* AP" {
                        return Ok(true);
                    }
                } else if !trimmed.is_empty() {
                    // Left the "Supported interface modes" block
                    in_supported_modes = false;
                }
            }
        }

        Ok(false)
    }

    /// Verifies if dnsmasq is installed on the system.
    pub fn check_dnsmasq_installed(&self) -> Result<(), ValidationError> {
        let output = Command::new("dnsmasq")
            .arg("--version")
            .output()
            .map_err(|_| ValidationError::DnsmasqNotInstalled)?;

        if !output.status.success() {
            return Err(ValidationError::DnsmasqNotInstalled);
        }
        Ok(())
    }

    /// Verifies if a specific UDP port is available for binding.
    pub fn check_port_available(&self, port: u16) -> Result<(), ValidationError> {
        let addr = format!("0.0.0.0:{}", port);
        match std::net::UdpSocket::bind(&addr) {
            Ok(_) => Ok(()),
            Err(_) => Err(ValidationError::PortInUse(port)),
        }
    }

    /// Validates required runtime conditions before hostapd starts.
    pub fn validate_runtime_conditions(&self) -> Result<(), ValidationError> {
        // Check if iw is installed
        Command::new("iw")
            .arg("--version")
            .output()
            .map_err(|_| ValidationError::IwNotInstalled)?;

        // Check if hostapd is installed
        Command::new("hostapd")
            .arg("-v")
            .output()
            .map_err(|_| ValidationError::HostapdNotInstalled)?;

        // Check if interface exists
        let _iface = self.detect_wifi_interface()?;

        // Check AP mode support
        if !self.check_ap_mode_support()? {
            return Err(ValidationError::APModeNotSupported);
        }

        Ok(())
    }
}
