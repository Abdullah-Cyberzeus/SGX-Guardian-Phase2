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

#[cfg(test)]
mod tests {
    use super::*;

    // Every method on `Validator` other than `check_port_available` shells out
    // directly to an external binary (iw, hostapd, dnsmasq, wpa_supplicant,
    // udhcpc, ip, wpa_cli, id) via `std::process::Command` with no injectable
    // runner/trait seam (unlike `ProcessRunner` used elsewhere in this crate).
    // Their outcomes depend on which binaries exist on the host and, for
    // `check_root_permissions`, on whether the test process itself is root —
    // so they cannot be driven deterministically without touching real system
    // binaries/state. Per the isolation rules (no root, no mocked process
    // seam available), those methods are intentionally left uncovered here:
    // detect_wifi_interface, check_ap_mode_support, check_dnsmasq_installed,
    // validate_runtime_conditions, check_wpa_supplicant_installed,
    // check_udhcpc_installed, check_interface_exists, check_root_permissions,
    // check_client_mode_support, check_interface_not_busy,
    // check_wifi_scan_works, validate_uplink_runtime_conditions.

    #[test]
    fn display_command_execution_failed() {
        let err = ValidationError::CommandExecutionFailed("iw dev".to_string());
        assert_eq!(err.to_string(), "Failed to execute command: iw dev");
    }

    #[test]
    fn display_interface_not_found() {
        assert_eq!(
            ValidationError::InterfaceNotFound.to_string(),
            "No WiFi interface found"
        );
    }

    #[test]
    fn display_ap_mode_not_supported() {
        assert_eq!(
            ValidationError::APModeNotSupported.to_string(),
            "WiFi interface does not support AP mode"
        );
    }

    #[test]
    fn display_hostapd_not_installed() {
        assert_eq!(
            ValidationError::HostapdNotInstalled.to_string(),
            "hostapd is not installed"
        );
    }

    #[test]
    fn display_iw_not_installed() {
        assert_eq!(
            ValidationError::IwNotInstalled.to_string(),
            "iw is not installed"
        );
    }

    #[test]
    fn display_dnsmasq_not_installed() {
        assert_eq!(
            ValidationError::DnsmasqNotInstalled.to_string(),
            "dnsmasq is not installed"
        );
    }

    #[test]
    fn display_port_in_use() {
        assert_eq!(
            ValidationError::PortInUse(6767).to_string(),
            "Port 6767 is already in use by another service"
        );
    }

    #[test]
    fn display_wpa_supplicant_not_installed() {
        assert_eq!(
            ValidationError::WpaSupplicantNotInstalled.to_string(),
            "wpa_supplicant is not installed"
        );
    }

    #[test]
    fn display_udhcpc_not_installed() {
        assert_eq!(
            ValidationError::UdhcpcNotInstalled.to_string(),
            "udhcpc is not installed"
        );
    }

    #[test]
    fn display_interface_not_available() {
        assert_eq!(
            ValidationError::InterfaceNotAvailable("wlan9".to_string()).to_string(),
            "Interface wlan9 is not available or does not exist"
        );
    }

    #[test]
    fn display_permission_denied() {
        assert_eq!(
            ValidationError::PermissionDenied.to_string(),
            "Root permissions required to initialize network interfaces"
        );
    }

    #[test]
    fn display_client_mode_not_supported() {
        assert_eq!(
            ValidationError::ClientModeNotSupported.to_string(),
            "WiFi interface does not support managed (client) mode"
        );
    }

    #[test]
    fn display_interface_busy() {
        assert_eq!(
            ValidationError::InterfaceBusy("wlan0".to_string()).to_string(),
            "Interface wlan0 is currently busy or managed by another wpa_supplicant process"
        );
    }

    #[test]
    fn display_scan_failed() {
        assert_eq!(
            ValidationError::ScanFailed("wlan0".to_string()).to_string(),
            "Hardware WiFi scan failed on interface wlan0"
        );
    }

    #[test]
    fn validator_new_and_default_construct() {
        let _ = Validator::new();
        let _ = Validator::default();
    }

    #[test]
    fn check_port_available_reports_free_port() {
        let validator = Validator::new();
        // Bind to port 0 to let the OS pick a free ephemeral UDP port, then
        // release it immediately so the port is free again for the check.
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind probe socket");
        let port = probe.local_addr().expect("local addr").port();
        drop(probe);

        assert!(validator.check_port_available(port).is_ok());
    }

    #[test]
    fn check_port_available_reports_conflict() {
        let validator = Validator::new();
        // Hold a UDP socket open on 0.0.0.0 so the subsequent bind attempt
        // inside check_port_available (also on 0.0.0.0) collides with it.
        let held = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind held socket");
        let port = held.local_addr().expect("local addr").port();

        match validator.check_port_available(port) {
            Err(ValidationError::PortInUse(p)) => assert_eq!(p, port),
            other => panic!("expected PortInUse({}), got {:?}", port, other),
        }
        drop(held);
    }
}
