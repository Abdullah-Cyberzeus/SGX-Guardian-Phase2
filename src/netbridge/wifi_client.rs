use crate::netbridge::process::ProcessRunner;
use crate::netbridge::types::{NetbridgeError, WifiClientSettings};
use std::sync::Arc;

use std::process::Command;
use std::str;
use tracing::{error, info};

pub struct WifiClientOrchestrator {
    pub settings: WifiClientSettings,
    pub runner: Option<Arc<ProcessRunner>>,
}

impl WifiClientOrchestrator {
    pub fn new(settings: WifiClientSettings) -> Self {
        WifiClientOrchestrator {
            settings,
            runner: None,
        }
    }

    /// Scans available Wi-Fi networks using `iw`.
    pub fn scan_networks(
        &self,
    ) -> Result<Vec<crate::netbridge::types::WifiNetwork>, NetbridgeError> {
        let output = Command::new("iw")
            .arg("dev")
            .arg(&self.settings.interface)
            .arg("scan")
            .output()
            .map_err(NetbridgeError::IoError)?;

        if !output.status.success() {
            let err = str::from_utf8(&output.stderr).unwrap_or("Unknown error");
            return Err(NetbridgeError::ProcessExecutionFailed(format!(
                "iw scan failed: {}",
                err
            )));
        }

        let mut networks = Vec::new();
        let output_str = str::from_utf8(&output.stdout).unwrap_or("");

        let mut current_ssid = String::new();
        let mut current_bssid = String::new();
        let mut current_signal = 0;
        let mut current_band = "2.4GHz".to_string();

        for line in output_str.lines() {
            let line = line.trim();
            if line.starts_with("BSS ") {
                if !current_ssid.is_empty() && !current_ssid.starts_with("\\x00") {
                    networks.push(crate::netbridge::types::WifiNetwork {
                        ssid: current_ssid.clone(),
                        bssid: current_bssid.clone(),
                        signal_dbm: current_signal,
                        band: current_band.clone(),
                        security: "WPA2".to_string(),
                    });
                }
                current_ssid.clear();
                current_signal = 0;
                current_band = "2.4GHz".to_string();
                if let Some(bssid_part) = line.strip_prefix("BSS ") {
                    current_bssid = bssid_part
                        .split('(')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_string();
                }
            } else if line.starts_with("signal:") {
                if let Some(sig_str) = line
                    .strip_prefix("signal:")
                    .and_then(|s| s.trim().split(' ').next())
                {
                    if let Ok(sig) = sig_str.parse::<f64>() {
                        current_signal = sig as i32;
                    }
                }
            } else if line.starts_with("SSID:") {
                if let Some(ssid) = line.strip_prefix("SSID:") {
                    current_ssid = ssid.trim().to_string();
                }
            } else if line.starts_with("freq:") {
                if let Some(freq_str) = line
                    .strip_prefix("freq:")
                    .and_then(|s| s.trim().split(' ').next())
                {
                    if let Ok(freq) = freq_str.parse::<i32>() {
                        if freq >= 5000 {
                            current_band = "5GHz".to_string();
                        } else {
                            current_band = "2.4GHz".to_string();
                        }
                    }
                }
            }
        }

        // Add the last network if valid
        if !current_ssid.is_empty() && !current_ssid.starts_with("\\x00") {
            networks.push(crate::netbridge::types::WifiNetwork {
                ssid: current_ssid,
                bssid: current_bssid,
                signal_dbm: current_signal,
                band: current_band,
                security: "WPA2".to_string(),
            });
        }

        Ok(networks)
    }

    /// Connects to an external Wi-Fi network and blocks until success or timeout.
    pub async fn connect(&mut self) -> Result<(), NetbridgeError> {
        info!("🔵 Connecting to external Wi-Fi...");

        // 1. Generate configuration using the dedicated generator module
        let generator = crate::netbridge::wpa_config::WpaConfigGenerator::new();
        let config_path = generator.generate_default(&self.settings)?;

        // 2. Cleanup any stale control sockets from an ungraceful crash
        let _ = std::fs::remove_file(format!(
            "/var/run/wpa_supplicant/{}",
            self.settings.interface
        ));

        // 3. Start wpa_supplicant in the background
        let args = vec![
            "-i".to_string(),
            self.settings.interface.clone(),
            "-c".to_string(),
            config_path,
        ];

        // Note: we do NOT pass -B (background) so our tokio ProcessRunner can monitor the daemon
        let runner = Arc::new(ProcessRunner::new("wpa_supplicant".to_string(), args));

        if let Err(e) = runner.start().await {
            error!("Failed to start wpa_supplicant process: {}", e);
            return Err(NetbridgeError::ProcessExecutionFailed(e.to_string()));
        }

        // Enable the true process lifecycle manager
        runner.clone().enable_auto_restart();

        self.runner = Some(runner);

        info!("✅ Wi-Fi connected successfully in the background.");
        Ok(())
    }

    /// Checks the current connection status using wpa_cli.
    pub fn is_connected(&self) -> bool {
        let output = Command::new("wpa_cli")
            .arg("-i")
            .arg(&self.settings.interface)
            .arg("status")
            .output();

        match output {
            Ok(out) => {
                let status_str = str::from_utf8(&out.stdout).unwrap_or("");
                status_str.contains("wpa_state=COMPLETED")
            }
            Err(_) => false,
        }
    }

    /// Stops the wpa_supplicant process and disconnects.
    pub async fn disconnect(&mut self) -> Result<(), NetbridgeError> {
        tracing::debug!("Disconnecting external WiFi...");
        if let Some(runner) = &self.runner {
            if let Err(e) = runner.stop().await {
                error!("Failed to stop wpa_supplicant process: {}", e);
                return Err(NetbridgeError::ProcessExecutionFailed(e.to_string()));
            }
        }
        self.runner = None;
        info!("🔴 Wi-Fi disconnected.");
        Ok(())
    }
}
