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

    pub fn check_wpa_supplicant_installed(&self) -> Result<(), ValidationError> {
        let output = Command::new("wpa_supplicant")
            .arg("-v")
            .output()
            .map_err(|_| ValidationError::WpaSupplicantNotInstalled)?;
        if !output.status.success() {
            return Err(ValidationError::WpaSupplicantNotInstalled);
        }
        Ok(())
    }

    pub fn check_udhcpc_installed(&self) -> Result<(), ValidationError> {
        let output = Command::new("udhcpc")
            .arg("--version")
            .output()
            .map_err(|_| ValidationError::UdhcpcNotInstalled)?;
        // udhcpc --version returns error code 1 sometimes even when printing version,
        // so checking if it outputs string starting with "udhcpc" is safer.
        let output_str = str::from_utf8(&output.stderr).unwrap_or("");
        if !output_str.contains("udhcpc") {
            let stdout_str = str::from_utf8(&output.stdout).unwrap_or("");
            if !stdout_str.contains("udhcpc") {
                return Err(ValidationError::UdhcpcNotInstalled);
            }
        }
        Ok(())
    }

    pub fn check_interface_exists(&self, iface: &str) -> Result<(), ValidationError> {
        let output = Command::new("ip")
            .arg("link")
            .arg("show")
            .arg(iface)
            .output()
            .map_err(|_| ValidationError::CommandExecutionFailed("ip link".to_string()))?;
        if !output.status.success() {
            return Err(ValidationError::InterfaceNotAvailable(iface.to_string()));
        }
        Ok(())
    }

    pub fn check_root_permissions(&self) -> Result<(), ValidationError> {
        let output = Command::new("id")
            .arg("-u")
            .output()
            .map_err(|_| ValidationError::CommandExecutionFailed("id -u".to_string()))?;
        let output_str = str::from_utf8(&output.stdout).unwrap_or("");
        if output_str.trim() != "0" {
            return Err(ValidationError::PermissionDenied);
        }
        Ok(())
    }

    pub fn check_client_mode_support(&self) -> Result<bool, ValidationError> {
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
                    if trimmed == "* managed" || trimmed == "* station" {
                        return Ok(true);
                    }
                } else if !trimmed.is_empty() {
                    in_supported_modes = false;
                }
            }
        }
        Ok(false)
    }

    pub fn check_interface_not_busy(&self, iface: &str) -> Result<(), ValidationError> {
        // If wpa_cli status returns successfully on this interface, another instance is already managing it
        let output = Command::new("wpa_cli")
            .arg("-i")
            .arg(iface)
            .arg("status")
            .output();

        if let Ok(out) = output {
            let status_str = str::from_utf8(&out.stdout).unwrap_or("");
            if status_str.contains("wpa_state=") {
                return Err(ValidationError::InterfaceBusy(iface.to_string()));
            }
        }
        Ok(())
    }

    pub fn check_wifi_scan_works(&self, iface: &str) -> Result<(), ValidationError> {
        // Ensure interface is UP before scanning, otherwise scan will fail with "Network is down"
        let _ = Command::new("ip")
            .arg("link")
            .arg("set")
            .arg(iface)
            .arg("up")
            .output();

        // Give it a split second to bring up the radio
        std::thread::sleep(std::time::Duration::from_millis(200));

        let output = Command::new("iw")
            .arg("dev")
            .arg(iface)
            .arg("scan")
            .output()
            .map_err(|_| ValidationError::IwNotInstalled)?;

        // iw scan might return 0 but print "command failed: Network is down (-100)" to stderr
        // or just return a non-zero status. We check both.
        if !output.status.success() {
            return Err(ValidationError::ScanFailed(iface.to_string()));
        }

        let err_str = str::from_utf8(&output.stderr).unwrap_or("");
        if err_str.contains("failed") || err_str.contains("Network is down") {
            return Err(ValidationError::ScanFailed(iface.to_string()));
        }

        Ok(())
    }

    pub fn validate_uplink_runtime_conditions(&self, iface: &str) -> Result<(), ValidationError> {
        self.check_root_permissions()?;
        self.check_interface_exists(iface)?;
        self.check_wpa_supplicant_installed()?;
        self.check_udhcpc_installed()?;
        if !self.check_client_mode_support()? {
            return Err(ValidationError::ClientModeNotSupported);
        }
        self.check_interface_not_busy(iface)?;
        // Note: hardware scan validation removed — wpa_supplicant handles scanning internally.
        // Running iw scan here after a reset causes false failures on embedded hardware that
        // needs 1-2+ seconds to fully initialize the radio after being brought up.
        Ok(())
    }
}
