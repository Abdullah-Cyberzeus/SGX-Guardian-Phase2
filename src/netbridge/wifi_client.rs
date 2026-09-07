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
        // Attempt active scan first; if hardware radio is busy (e.g. AP mode active on uap1
        // or wpa_supplicant operating), trigger wpa_cli scan and fall back to iw scan dump.
        let active_output = Command::new("iw")
            .arg("dev")
            .arg(&self.settings.interface)
            .arg("scan")
            .output();

        let output_string;
        let output_str = match active_output {
            Ok(ref out) if out.status.success() => str::from_utf8(&out.stdout).unwrap_or(""),
            _ => {
                // Active scan failed (e.g. EBUSY -16).
                // Trigger wpa_cli scan asynchronously so wpa_supplicant updates cache
                let _ = Command::new("wpa_cli")
                    .arg("-i")
                    .arg(&self.settings.interface)
                    .arg("scan")
                    .output();

                // Fallback to reading the kernel BSS scan cache
                let dump_output = Command::new("iw")
                    .arg("dev")
                    .arg(&self.settings.interface)
                    .arg("scan")
                    .arg("dump")
                    .output()
                    .map_err(NetbridgeError::IoError)?;

                if !dump_output.status.success() {
                    let err = str::from_utf8(&dump_output.stderr).unwrap_or("Unknown error");
                    return Err(NetbridgeError::ProcessExecutionFailed(format!(
                        "iw scan dump failed: {}",
                        err
                    )));
                }

                output_string = String::from_utf8_lossy(&dump_output.stdout).to_string();
                &output_string
            }
        };

        let mut networks = Vec::new();
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

        // 2. Ensure interface link is UP and cleanup any stale control sockets
        let _ = tokio::process::Command::new("ip")
            .args(["link", "set", "dev", &self.settings.interface, "up"])
            .output()
            .await;

        let _ = std::fs::remove_file(format!(
            "/var/run/wpa_supplicant/{}",
            self.settings.interface
        ));

        // 3. Start wpa_supplicant with nl80211,wext driver support
        let args = vec![
            "-i".to_string(),
            self.settings.interface.clone(),
            "-D".to_string(),
            "nl80211,wext".to_string(),
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

        self.runner = Some(runner.clone());

        // Wait for wpa_supplicant to reach COMPLETED state (associated & authenticated)
        if let Err(error) = self.wait_for_association(40).await {
            let _ = runner.stop().await;
            self.runner = None;
            return Err(error);
        }

        info!("✅ Wi-Fi associated successfully.");
        Ok(())
    }

    /// Polls wpa_cli status until connection state is COMPLETED or timeout occurs.
    pub async fn wait_for_association(&self, timeout_secs: u64) -> Result<(), NetbridgeError> {
        info!(
            "Waiting for Wi-Fi association on {}...",
            self.settings.interface
        );
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_secs);
        let mut last_log = std::time::Instant::now();

        while start.elapsed() < timeout {
            let output = Command::new("wpa_cli")
                .arg("-i")
                .arg(&self.settings.interface)
                .arg("status")
                .output();

            if let Ok(out) = output {
                let status_str = str::from_utf8(&out.stdout).unwrap_or("");
                if status_str.contains("wpa_state=COMPLETED") {
                    info!("✅ Wi-Fi associated successfully (wpa_state=COMPLETED).");
                    return Ok(());
                }

                if last_log.elapsed() >= std::time::Duration::from_secs(3) {
                    for line in status_str.lines() {
                        if line.starts_with("wpa_state=") || line.starts_with("ssid=") {
                            tracing::debug!(
                                "wpa_supplicant [{}]: {}",
                                self.settings.interface,
                                line
                            );
                        }
                    }
                    last_log = std::time::Instant::now();
                }
            }

            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        let err_msg = format!(
            "Wi-Fi association timed out after {}s on {}",
            timeout_secs, self.settings.interface
        );
        error!("{}", err_msg);
        Err(NetbridgeError::ProcessExecutionFailed(err_msg))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netbridge::types::WifiClientSettings;

    /// An interface name guaranteed not to exist on the host, so `iw`,
    /// `wpa_cli` and friends deterministically fail/return no-match output
    /// without ever touching a real Wi-Fi radio.
    const BOGUS_IFACE: &str = "sgxtest-bogus0";

    fn settings() -> WifiClientSettings {
        WifiClientSettings {
            interface: BOGUS_IFACE.to_string(),
            networks: Vec::new(),
            country: "US".to_string(),
        }
    }

    // `connect()` is intentionally left uncovered: it calls
    // `WpaConfigGenerator::generate_default`, which reads a hardcoded
    // `/etc/sgx-guardian/wpa_supplicant.conf.template` and, on success,
    // spawns a real `wpa_supplicant` process via `ProcessRunner`. There is
    // no injectable path or runner seam for either step, so exercising it
    // would either be a no-op that depends on the template file's absence
    // (fragile across hosts) or would launch a real process/mutate real
    // filesystem state — both against the isolation rules.

    #[test]
    fn new_orchestrator_has_no_runner() {
        let orchestrator = WifiClientOrchestrator::new(settings());
        assert_eq!(orchestrator.settings.interface, BOGUS_IFACE);
        assert!(orchestrator.runner.is_none());
    }

    #[test]
    fn is_connected_false_for_missing_interface() {
        let orchestrator = WifiClientOrchestrator::new(settings());
        assert!(!orchestrator.is_connected());
    }

    #[test]
    fn scan_networks_errors_for_missing_interface() {
        // With no such interface, both the active `iw scan` and the
        // `iw scan dump` fallback fail (or fail to spawn if `iw` is not
        // installed), so this deterministically returns Err without
        // touching a real Wi-Fi interface.
        let orchestrator = WifiClientOrchestrator::new(settings());
        assert!(orchestrator.scan_networks().is_err());
    }

    #[tokio::test]
    async fn wait_for_association_times_out_immediately_with_zero_budget() {
        // timeout_secs = 0 short-circuits the polling loop before any
        // wpa_cli invocation, deterministically exercising the timeout
        // error path with zero real command invocations.
        let orchestrator = WifiClientOrchestrator::new(settings());
        let result = orchestrator.wait_for_association(0).await;
        match result {
            Err(NetbridgeError::ProcessExecutionFailed(msg)) => {
                assert!(msg.contains("timed out"), "unexpected message: {msg}");
                assert!(msg.contains(BOGUS_IFACE));
            }
            other => panic!(
                "expected ProcessExecutionFailed(..timed out..), got {:?}",
                other
            ),
        }
    }

    #[tokio::test]
    async fn disconnect_without_a_running_process_is_a_noop() {
        let mut orchestrator = WifiClientOrchestrator::new(settings());
        assert!(orchestrator.disconnect().await.is_ok());
        assert!(orchestrator.runner.is_none());
    }
}
