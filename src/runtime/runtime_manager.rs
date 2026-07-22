use crate::netbridge::nat::NatManager;
use crate::netbridge::routing::RoutingManager;
use crate::netbridge::types::{ApSettings, DnsmasqSettings, WifiClientSettings};
use crate::netbridge::{DualWifiOrchestrator, Netbridge, UplinkOrchestrator};
use crate::runtime::config_store::ConfigStore;
use crate::runtime::errors::RuntimeError;
use crate::runtime::models::{GuardianConfig, RuntimeMode};
use crate::runtime::state::SystemState;
use crate::runtime::state_machine::StateMachine;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

/// The unified orchestrator that coordinates the active networking stack based on the runtime state machine.
pub struct RuntimeManager {
    pub state_machine: Arc<StateMachine>,
    ap: Arc<Mutex<Option<Netbridge>>>,
    uplink: Arc<Mutex<Option<UplinkOrchestrator>>>,
    dual: Arc<Mutex<Option<DualWifiOrchestrator>>>,
    nat: Arc<Mutex<Option<NatManager>>>,
    routing: Arc<RoutingManager>,
    supervisor_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl RuntimeManager {
    pub fn new(state_machine: Arc<StateMachine>) -> Self {
        RuntimeManager {
            state_machine,
            ap: Arc::new(Mutex::new(None)),
            uplink: Arc::new(Mutex::new(None)),
            dual: Arc::new(Mutex::new(None)),
            nat: Arc::new(Mutex::new(None)),
            routing: Arc::new(RoutingManager::new()),
            supervisor_task: Arc::new(Mutex::new(None)),
        }
    }

    /// Dynamically detects the active default routing interface for WAN access
    pub fn get_default_uplink_interface() -> String {
        if let Ok(output) = std::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output()
        {
            if let Ok(route_str) = std::str::from_utf8(&output.stdout) {
                let parts: Vec<&str> = route_str.split_whitespace().collect();
                if let Some(pos) = parts.iter().position(|&x| x == "dev") {
                    if pos + 1 < parts.len() {
                        return parts[pos + 1].to_string();
                    }
                }
            }
        }
        "eth0".to_string() // Fallback standard
    }

    fn verify_interface_exists(iface: &str) -> bool {
        std::process::Command::new("ip")
            .args(["link", "show", "dev", iface])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Primary entry point for mode switching. Safely tears down the old mode and spins up the new mode.
    pub async fn handle_transition(&self, new_mode: RuntimeMode) -> Result<(), RuntimeError> {
        // Mark that we are transitioning
        self.state_machine
            .transition_to(SystemState::ApplyingChange)
            .await;

        tracing::debug!("🔴 Stopping all active networking stacks...");
        self.stop_all().await;

        let config = match ConfigStore::load() {
            Ok(c) => c,
            Err(e) => {
                self.state_machine
                    .set_error_state(format!("Config load failed: {}", e), None)
                    .await;
                return Err(e);
            }
        };

        if new_mode != RuntimeMode::Off {
            self.perform_system_cleanup().await;
        }

        tracing::debug!("Initiating transition to {:?}", new_mode);
        match new_mode {
            RuntimeMode::Off => {
                self.state_machine.reset_to_idle().await;
                Ok(())
            }
            RuntimeMode::HotspotOnly => self.start_hotspot_mode(&config).await,
            RuntimeMode::ClientOnly => self.start_client_mode(&config).await,
            RuntimeMode::DualWifi => self.start_dual_wifi_mode(&config).await,
        }
    }

    /// Spawns a resilient background supervisor that aborts any existing transitions and attempts to reach the target mode.
    pub async fn supervise_transition(self: Arc<Self>, new_mode: RuntimeMode) {
        // Abort any currently running supervisor task to prevent race conditions
        if let Some(task) = self.supervisor_task.lock().await.take() {
            task.abort();
            tracing::debug!("Aborted previous orchestration supervisor.");
        }

        let mgr_clone = self.clone();
        let target_mode = new_mode.clone();

        let task = tokio::spawn(async move {
            loop {
                match mgr_clone.handle_transition(target_mode.clone()).await {
                    Ok(_) => {
                        info!(
                            "✅ Orchestration successfully reached target mode: {:?}",
                            target_mode
                        );
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("⏳ Orchestration failed to reach target mode {:?}: {}. Retrying in 10 seconds...", target_mode, e);
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    }
                }
            }
        });

        *self.supervisor_task.lock().await = Some(task);
    }

    /// Loads the saved persistent config and bootstraps the requested mode if restore_on_boot is enabled.
    pub async fn apply_saved_state(self: Arc<Self>) -> Result<(), RuntimeError> {
        let config = ConfigStore::load()?;
        if config.flags.restore_on_boot {
            self.supervise_transition(config.mode).await;
        } else {
            self.supervise_transition(RuntimeMode::Off).await;
        }
        Ok(())
    }

    pub async fn start_hotspot_mode(&self, config: &GuardianConfig) -> Result<(), RuntimeError> {
        if !Self::verify_interface_exists(&config.hotspot.interface) {
            self.state_machine
                .set_error_state(
                    "Hotspot interface not detected".to_string(),
                    Some("E_WIFI_MODULE_NOT_FOUND".to_string()),
                )
                .await;
            return Err(RuntimeError::InvalidConfig(
                "Hotspot interface missing".to_string(),
            ));
        }

        self.state_machine
            .transition_to(SystemState::HotspotStarting)
            .await;

        let hw_mode = if config.hotspot.channel > 14 {
            "a".to_string() // 5GHz
        } else {
            "g".to_string() // 2.4GHz
        };

        let ap_settings = ApSettings {
            interface: config.hotspot.interface.clone(),
            ssid: config.hotspot.ssid.clone(),
            wpa_passphrase: Some(config.hotspot.password.clone()),
            channel: config.hotspot.channel,
            hw_mode,
            client_isolation: config.hotspot.client_isolation,
        };

        let dns_settings = DnsmasqSettings {
            interface: config.hotspot.interface.clone(),
            ..DnsmasqSettings::default()
        };

        let mut ap = Netbridge::new(ap_settings, dns_settings);

        if let Err(e) = ap.start().await {
            self.state_machine
                .set_error_state(
                    format!("Hotspot failed: {}", e),
                    Some("E_HOSTAPD_FAIL".to_string()),
                )
                .await;
            return Err(RuntimeError::InvalidConfig(e.to_string()));
        }

        *self.ap.lock().await = Some(ap);
        self.state_machine
            .transition_to(SystemState::HotspotActive)
            .await;

        // --- Establish Ethernet NAT Routing ---
        let uplink_iface = Self::get_default_uplink_interface();
        let nat_manager = NatManager::new();
        if let Err(e) = nat_manager.enable_nat(
            &config.hotspot.interface,
            &uplink_iface,
            config.hotspot.client_isolation,
        ) {
            tracing::error!(
                "Failed to apply Ethernet NAT routing (local Wi-Fi only): {}",
                e
            );
        } else {
            tracing::debug!(
                "Successfully established Ethernet NAT routing via {}",
                uplink_iface
            );

            if let Err(e) = self.routing.enable_forwarding() {
                tracing::error!("Failed to enable kernel IPv4 forwarding: {}", e);
            }

            *self.nat.lock().await = Some(nat_manager);
        }

        Ok(())
    }

    pub async fn start_client_mode(&self, config: &GuardianConfig) -> Result<(), RuntimeError> {
        if !Self::verify_interface_exists(&config.uplink.interface) {
            self.state_machine
                .set_error_state(
                    "Second Wi-Fi chip not detected".to_string(),
                    Some("E_WIFI_MODULE2_NOT_FOUND".to_string()),
                )
                .await;
            return Err(RuntimeError::InvalidConfig(
                "Hardware interface missing".to_string(),
            ));
        }

        self.state_machine
            .transition_to(SystemState::ClientConnecting)
            .await;

        let uplink_settings = WifiClientSettings {
            interface: config.uplink.interface.clone(),
            networks: config.uplink.networks.clone(),
            ..Default::default()
        };

        let mut uplink = UplinkOrchestrator::new(uplink_settings);

        if let Err(e) = uplink.start().await {
            let err_str = e.to_string();
            let code = if err_str.contains("E_WIFI_WRONG_PASSWORD") {
                Some("E_WIFI_WRONG_PASSWORD".to_string())
            } else if err_str.contains("E_WIFI_AP_NOT_FOUND") {
                Some("E_WIFI_AP_NOT_FOUND".to_string())
            } else {
                None
            };
            self.state_machine
                .set_error_state(format!("Client failed: {}", e), code)
                .await;
            return Err(RuntimeError::InvalidConfig(e.to_string()));
        }

        *self.uplink.lock().await = Some(uplink);
        self.state_machine
            .transition_to(SystemState::ClientConnected)
            .await;

        Ok(())
    }

    pub async fn start_dual_wifi_mode(&self, config: &GuardianConfig) -> Result<(), RuntimeError> {
        if !Self::verify_interface_exists(&config.uplink.interface) {
            self.state_machine
                .set_error_state(
                    "Second Wi-Fi chip not detected".to_string(),
                    Some("E_WIFI_MODULE2_NOT_FOUND".to_string()),
                )
                .await;
            return Err(RuntimeError::InvalidConfig(
                "Hardware interface missing".to_string(),
            ));
        }

        if !Self::verify_interface_exists(&config.hotspot.interface) {
            self.state_machine
                .set_error_state(
                    "Hotspot interface not detected".to_string(),
                    Some("E_WIFI_MODULE_NOT_FOUND".to_string()),
                )
                .await;
            return Err(RuntimeError::InvalidConfig(
                "Hotspot interface missing".to_string(),
            ));
        }

        self.state_machine
            .transition_to(SystemState::DualStarting)
            .await;

        let hw_mode = if config.hotspot.channel > 14 {
            "a".to_string() // 5GHz
        } else {
            "g".to_string() // 2.4GHz
        };

        let ap_settings = ApSettings {
            interface: config.hotspot.interface.clone(),
            ssid: config.hotspot.ssid.clone(),
            wpa_passphrase: Some(config.hotspot.password.clone()),
            channel: config.hotspot.channel,
            hw_mode,
            client_isolation: config.hotspot.client_isolation,
        };

        let dns_settings = DnsmasqSettings {
            interface: config.hotspot.interface.clone(),
            ..DnsmasqSettings::default()
        };
        let uplink_settings = WifiClientSettings {
            interface: config.uplink.interface.clone(),
            networks: config.uplink.networks.clone(),
            ..Default::default()
        };

        let mut dual = DualWifiOrchestrator::new(ap_settings, dns_settings, uplink_settings);

        if let Err(e) = dual.start().await {
            let err_str = e.to_string();
            let code = if err_str.contains("E_WIFI_WRONG_PASSWORD") {
                Some("E_WIFI_WRONG_PASSWORD".to_string())
            } else if err_str.contains("E_WIFI_AP_NOT_FOUND") {
                Some("E_WIFI_AP_NOT_FOUND".to_string())
            } else if err_str.contains("hostapd") {
                Some("E_HOSTAPD_FAIL".to_string())
            } else {
                None
            };
            self.state_machine
                .set_error_state(format!("Dual WiFi failed: {}", e), code)
                .await;
            return Err(RuntimeError::InvalidConfig(e.to_string()));
        }

        *self.dual.lock().await = Some(dual);
        self.state_machine
            .transition_to(SystemState::DualActive)
            .await;

        Ok(())
    }

    pub async fn perform_system_cleanup(&self) {
        tracing::info!("🧹 Performing pre-startup system process and interface cleanup...");

        // 1. Terminate conflicting processes globally
        let processes = ["hostapd", "dnsmasq", "wpa_supplicant", "udhcpc"];
        for proc in &processes {
            let _ = tokio::process::Command::new("killall")
                .args(["-q", "-9", proc])
                .output()
                .await;
        }

        // 2. Clear wireless interfaces (flush IP and bring DOWN)
        // Explicitly exclude Ethernet, loopback, and cellular to prevent network breakage.
        // Collect unique PHY names while iterating so we can disable power saving PHY-wide.
        let mut phy_names: std::collections::HashSet<String> = std::collections::HashSet::new();

        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    let lower = name.to_lowercase();
                    if lower == "lo"
                        || lower.starts_with("lo")
                        || lower.starts_with("eth")
                        || lower.starts_with("en")
                        || lower.starts_with("wwan")
                        || lower.starts_with("rmnet")
                        || lower.starts_with("usb")
                        || lower.starts_with("nebula")
                        || lower.starts_with("docker")
                        || lower.starts_with("veth")
                        || lower.starts_with("br-")
                    {
                        continue;
                    }

                    // Reset any wireless interface found on the system
                    if lower.starts_with("wlan")
                        || lower.starts_with("uap")
                        || lower.starts_with("wfd")
                        || lower.starts_with("ap")
                        || lower.starts_with("wl")
                    {
                        tracing::info!("Resetting wireless interface: {}", name);
                        let _ = tokio::process::Command::new("ip")
                            .args(["link", "set", "dev", name, "down"])
                            .output()
                            .await;
                        let _ = tokio::process::Command::new("ip")
                            .args(["addr", "flush", "dev", name])
                            .output()
                            .await;

                        // Discover the underlying PHY for this interface
                        // e.g. /sys/class/net/wlan1/phy80211/name → "phy0"
                        let phy_path = format!("/sys/class/net/{}/phy80211/name", name);
                        if let Ok(phy) = std::fs::read_to_string(&phy_path) {
                            let phy = phy.trim().to_string();
                            if !phy.is_empty() {
                                phy_names.insert(phy);
                            }
                        }
                    }
                }
            }
        }

        // 3. Disable Wi-Fi power saving at the PHY level for every discovered radio chip.
        // PHY-level is stronger than interface-level and persists across reconnects.
        for phy in &phy_names {
            tracing::info!("Disabling power saving on radio chip: {}", phy);
            let _ = tokio::process::Command::new("iw")
                .args(["phy", phy, "set", "power_save", "off"])
                .output()
                .await;
        }

        // Wait for radio hardware to fully settle after reset before hostapd attempts to
        // configure channels. Embedded Wi-Fi chips (e.g. mwiphy0) typically need 1-2 seconds
        // after interface reset to initialize firmware and release the channel lock.
        tracing::info!("⏳ Waiting for radio hardware to settle...");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        tracing::info!("✅ System cleanup complete. Ready to start orchestration.");
    }

    pub async fn stop_all(&self) {
        if let Some(mut ap) = self.ap.lock().await.take() {
            let _ = ap.stop().await;
        }
        if let Some(mut uplink) = self.uplink.lock().await.take() {
            let _ = uplink.stop().await;
        }
        if let Some(mut dual) = self.dual.lock().await.take() {
            let _ = dual.stop().await;
        }
        if let Some(nat) = self.nat.lock().await.take() {
            let _ = nat.disable_nat();
            let _ = self.routing.disable_forwarding();
        }
    }

    pub async fn restart(&self) -> Result<(), RuntimeError> {
        let config = ConfigStore::load()?;
        self.handle_transition(config.mode).await
    }
}
