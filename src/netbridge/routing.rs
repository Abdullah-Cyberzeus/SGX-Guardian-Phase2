use crate::netbridge::types::NetbridgeError;
use std::fs;
use std::path::Path;
use tracing::{error, info};

pub struct RoutingManager;

impl RoutingManager {
    pub fn new() -> Self {
        RoutingManager {}
    }
}

impl Default for RoutingManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RoutingManager {
    /// Enables IPv4 kernel forwarding to allow traffic between interfaces.
    pub fn enable_forwarding(&self) -> Result<(), NetbridgeError> {
        info!("Enabling IPv4 kernel forwarding...");
        let path = "/proc/sys/net/ipv4/ip_forward";

        if Path::new(path).exists() {
            fs::write(path, "1\n").map_err(NetbridgeError::IoError)?;
            info!("IPv4 forwarding successfully enabled.");
            Ok(())
        } else {
            let err_msg =
                "IPv4 forwarding path does not exist in sysfs (/proc/sys/net/ipv4/ip_forward)";
            error!("{}", err_msg);
            Err(NetbridgeError::ValidationFailed(err_msg.to_string()))
        }
    }

    /// Validates if IPv4 forwarding is currently active.
    pub fn is_forwarding_enabled(&self) -> Result<bool, NetbridgeError> {
        let path = "/proc/sys/net/ipv4/ip_forward";

        if Path::new(path).exists() {
            let content = fs::read_to_string(path).map_err(NetbridgeError::IoError)?;
            Ok(content.trim() == "1")
        } else {
            Ok(false)
        }
    }

    /// Disables IPv4 kernel forwarding.
    pub fn disable_forwarding(&self) -> Result<(), NetbridgeError> {
        info!("Disabling IPv4 kernel forwarding...");
        let path = "/proc/sys/net/ipv4/ip_forward";

        if Path::new(path).exists() {
            fs::write(path, "0\n").map_err(NetbridgeError::IoError)?;
            info!("IPv4 forwarding successfully disabled.");
            Ok(())
        } else {
            let err_msg =
                "IPv4 forwarding path does not exist in sysfs (/proc/sys/net/ipv4/ip_forward)";
            error!("{}", err_msg);
            Err(NetbridgeError::ValidationFailed(err_msg.to_string()))
        }
    }
}
