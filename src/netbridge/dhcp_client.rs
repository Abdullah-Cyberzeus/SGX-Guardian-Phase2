use crate::netbridge::process::ProcessRunner;
use crate::netbridge::types::NetbridgeError;
use std::str;
use std::sync::Arc;
use tokio::process::Command;
use tracing::error;

pub struct DhcpClientOrchestrator {
    interface: String,
    runner: Option<Arc<ProcessRunner>>,
}

impl DhcpClientOrchestrator {
    pub fn new(interface: String) -> Self {
        DhcpClientOrchestrator {
            interface,
            runner: None,
        }
    }

    /// Starts the udhcpc DHCP client in the background on the specified interface.
    pub async fn start(&mut self) -> Result<(), NetbridgeError> {
        tracing::debug!(
            "Starting DHCP client (udhcpc) on interface {}...",
            self.interface
        );

        // Derive a stable DHCP client identifier from the interface's MAC address.
        // This allows the DHCP server to consistently re-assign the same IP across reconnects.
        let client_id = Self::get_mac_client_id(&self.interface).await;

        let mut args = vec![
            "-i".to_string(),
            self.interface.clone(),
            "-f".to_string(), // Run in foreground so tokio can monitor process lifecycle
        ];

        // Append stable client ID if we could read the MAC address
        if let Some(id) = client_id {
            args.push("-x".to_string());
            args.push(format!("0x3d:{}", id)); // Option 61 (Client ID) requires 0x3d: in busybox udhcpc
        }

        // Add a stable hostname so the device appears consistently in the router's DHCP table
        args.push("-x".to_string());
        args.push("hostname:sgx-guardian".to_string());

        let runner = Arc::new(ProcessRunner::new("udhcpc".to_string(), args));

        if let Err(e) = runner.start().await {
            error!("Failed to start udhcpc process: {}", e);
            return Err(NetbridgeError::ProcessExecutionFailed(e.to_string()));
        }

        // Enable the true process lifecycle manager
        runner.clone().enable_auto_restart();

        self.runner = Some(runner);
        tracing::debug!("DHCP client successfully started.");

        Ok(())
    }

    /// Reads the hardware MAC address of the interface and formats it as a stable DHCP client ID.
    async fn get_mac_client_id(interface: &str) -> Option<String> {
        let mac_path = format!("/sys/class/net/{}/address", interface);
        let mac = tokio::fs::read_to_string(&mac_path).await.ok()?;
        let mac = mac.trim().to_string();
        if mac.is_empty() || mac == "00:00:00:00:00:00" {
            return None;
        }
        // Format as a hex client ID: strip colons and prefix with 01 (hardware type = Ethernet)
        let hex = mac.replace(':', "");
        Some(format!("01{}", hex))
    }

    /// Checks if the interface has successfully obtained an IPv4 address.
    pub async fn is_network_ready(&self) -> bool {
        let output = Command::new("ip")
            .arg("-4")
            .arg("addr")
            .arg("show")
            .arg("dev")
            .arg(&self.interface)
            .output()
            .await;

        match output {
            Ok(out) => {
                let status_str = str::from_utf8(&out.stdout).unwrap_or("");
                // Output should contain "inet <IP>" if an address is assigned
                status_str.contains("inet ")
            }
            Err(_) => false,
        }
    }

    /// Stops the udhcpc process.
    pub async fn stop(&mut self) -> Result<(), NetbridgeError> {
        tracing::debug!("Stopping DHCP client (udhcpc)...");
        if let Some(runner) = &self.runner {
            if let Err(e) = runner.stop().await {
                error!("Failed to stop udhcpc process: {}", e);
                return Err(NetbridgeError::ProcessExecutionFailed(e.to_string()));
            }
        }
        self.runner = None;
        tracing::debug!("DHCP client stopped successfully.");
        Ok(())
    }
}
