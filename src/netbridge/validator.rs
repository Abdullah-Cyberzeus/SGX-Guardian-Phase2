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

#[cfg(test)]
mod tests {
    use super::*;

    // Every method on `Validator` other than `check_port_available` shells out
    // directly to an external binary (iw, hostapd, dnsmasq) via
    // `std::process::Command` with no injectable runner/trait seam (unlike
    // `ProcessRunner` used elsewhere in this crate). `iw`, `hostapd`, and
    // `dnsmasq` are all confirmed absent in this sandbox (verified by hand:
    // `which <bin>` fails for each) — so every method's outcome is in fact
    // fully deterministic here, just not the "happy path" outcome.

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
        //
        // Releasing and re-checking is inherently racy: a concurrent test can
        // claim the just-freed ephemeral port in between. That is a lost race
        // rather than a real conflict, so retry with a fresh port instead of
        // failing the run on it.
        let mut last = None;
        for _ in 0..10 {
            let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind probe socket");
            let port = probe.local_addr().expect("local addr").port();
            drop(probe);

            match validator.check_port_available(port) {
                Ok(()) => return,
                other => last = Some((port, other)),
            }
        }
        panic!("no freed ephemeral port ever reported available; last: {last:?}");
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

    #[test]
    fn detect_wifi_interface_reports_iw_not_installed() {
        let validator = Validator::new();
        assert!(matches!(
            validator.detect_wifi_interface(),
            Err(ValidationError::IwNotInstalled)
        ));
    }

    #[test]
    fn check_ap_mode_support_reports_iw_not_installed() {
        let validator = Validator::new();
        assert!(matches!(
            validator.check_ap_mode_support(),
            Err(ValidationError::IwNotInstalled)
        ));
    }

    #[test]
    fn check_dnsmasq_installed_reports_not_installed() {
        let validator = Validator::new();
        assert!(matches!(
            validator.check_dnsmasq_installed(),
            Err(ValidationError::DnsmasqNotInstalled)
        ));
    }

    #[test]
    fn validate_runtime_conditions_short_circuits_on_missing_iw() {
        let validator = Validator::new();
        assert!(matches!(
            validator.validate_runtime_conditions(),
            Err(ValidationError::IwNotInstalled)
        ));
    }
}
