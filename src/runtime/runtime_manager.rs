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
use tracing::{info, warn};

/// The unified orchestrator that coordinates the active networking stack based on the runtime state machine.
pub struct RuntimeManager {
    pub state_machine: Arc<StateMachine>,
    ap: Arc<Mutex<Option<Netbridge>>>,
    uplink: Arc<Mutex<Option<UplinkOrchestrator>>>,
    dual: Arc<Mutex<Option<DualWifiOrchestrator>>>,
    /// Holds the NatManager for HotspotOnly mode (Ethernet uplink NAT).
    /// DualWifi mode manages its own NAT internally.
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

    pub fn get_default_uplink_interface() -> String {
        let config = ConfigStore::load().unwrap_or_else(|_| GuardianConfig::default());
        Self::get_uplink_interface(&config).unwrap_or_else(|| "eth0".to_string())
    }

    /// Resolves the uplink interface for NAT purposes.
    /// Uses config.uplink.interface if set; otherwise falls back to detecting
    /// the first active Ethernet interface from the OS. Never reads from
    /// `ip route show default` — that would return whichever interface the
    /// kernel prefers at that moment, which may not be the selected uplink.
    fn get_uplink_interface(config: &crate::runtime::models::GuardianConfig) -> Option<String> {
        // 1. Explicit config takes priority — always trust what the operator configured
        if !config.uplink.interface.is_empty() {
            return Some(config.uplink.interface.clone());
        }

        // 2. NetworkSelector's selected interface — this is the live orchestration decision
        if let Some(selected) = crate::network_selector::selected_interface() {
            if !selected.is_empty() {
                return Some(selected);
            }
        }

        // 3. Final fallback: first active Ethernet interface found on the system
        // (only reached in HotspotOnly mode where no uplink is configured)
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    let lower = name.to_lowercase();
                    if lower.starts_with("eth") || lower.starts_with("en") {
                        let carrier_path = format!("/sys/class/net/{}/carrier", name);
                        if std::fs::read_to_string(&carrier_path)
                            .map(|c| c.trim() == "1")
                            .unwrap_or(false)
                        {
                            return Some(name.to_string());
                        }
                    }
                }
            }
        }

        None
    }

    fn verify_interface_exists(iface: &str) -> bool {
        std::process::Command::new("ip")
            .args(["link", "show", "dev", iface])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn mode_label(mode: &RuntimeMode) -> &'static str {
        match mode {
            RuntimeMode::Off => "Off",
            RuntimeMode::HotspotOnly => "HotspotOnly",
            RuntimeMode::ClientOnly => "ClientOnly",
            RuntimeMode::DualWifi => "DualWifi",
        }
    }

    fn references_wifi_capture(value: &str) -> bool {
        value
            .split(|character: char| character.is_whitespace() || character == ':')
            .any(|token| {
                let token = token
                    .trim_matches(|character: char| !character.is_ascii_alphanumeric())
                    .to_ascii_lowercase();
                token.starts_with("wlan") || token.starts_with("uap")
            })
    }

    async fn stop_unsafe_suricata_wifi_capture() {
        let config_uses_wifi = tokio::fs::read_to_string("/etc/suricata/suricata.yaml")
            .await
            .map(|config| Self::references_wifi_capture(&config))
            .unwrap_or(false);
        let unit_uses_wifi = tokio::process::Command::new("systemctl")
            .args(["show", "-p", "ExecStart", "--value", "suricata"])
            .output()
            .await
            .map(|output| Self::references_wifi_capture(&String::from_utf8_lossy(&output.stdout)))
            .unwrap_or(false);

        if !config_uses_wifi && !unit_uses_wifi {
            return;
        }

        warn!(
            "Guardian is configured to capture an NXP Wi-Fi interface; stopping it before DualWifi startup."
        );
        match tokio::process::Command::new("systemctl")
            .args(["stop", "suricata"])
            .output()
            .await
        {
            Ok(output) if output.status.success() => {}
            Ok(output) => warn!(
                "Failed to stop unsafe Guardian capture: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
            Err(error) => warn!("Failed to invoke systemctl to stop Guardian: {}", error),
        }
    }

    /// Primary entry point for mode switching. Safely tears down the old mode and spins up the new mode.
    pub async fn handle_transition(&self, new_mode: RuntimeMode) -> Result<(), RuntimeError> {
        info!(
            "Runtime transition requested: target_mode={}",
            Self::mode_label(&new_mode)
        );

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

        info!(
            "Loaded persisted runtime config before transition: saved_mode={}, hotspot_iface={}, uplink_iface={}, restore_on_boot={}",
            Self::mode_label(&config.mode),
            config.hotspot.interface,
            config.uplink.interface,
            config.flags.restore_on_boot
        );

        // Off means "stop networking owned by Guardian". It must never tear down
        // host networking (for example the Wi-Fi interface carrying the SSH session).
        // Active modes prepare only the interfaces explicitly assigned to Guardian.
        if new_mode != RuntimeMode::Off {
            self.perform_system_cleanup(&new_mode, &config).await;
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
        info!(
            "Supervisor received transition request: target_mode={}",
            Self::mode_label(&new_mode)
        );

        // Abort any currently running supervisor task to prevent race conditions
        if let Some(task) = self.supervisor_task.lock().await.take() {
            task.abort();
            warn!(
                "Aborted previous orchestration supervisor to start a new transition to {}",
                Self::mode_label(&new_mode)
            );
        }

        let mgr_clone = self.clone();
        let target_mode = new_mode.clone();

        let task = tokio::spawn(async move {
            loop {
                info!(
                    "Supervisor applying transition attempt: target_mode={}",
                    Self::mode_label(&target_mode)
                );
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
        info!(
            "Boot restore check: saved_mode={}, restore_on_boot={}",
            Self::mode_label(&config.mode),
            config.flags.restore_on_boot
        );
        if config.flags.restore_on_boot && config.mode != RuntimeMode::Off {
            // Reconstruct the stack so every daemon, health task, route, and NAT rule is
            // owned by this process. Merely observing AP + Wi-Fi state can report
            // DualActive while forwarding is absent and no recovery task exists.
            self.supervise_transition(config.mode).await;
        } else {
            // A disabled restore flag means "leave the host as it is", not "turn
            // every wireless interface off". A newly created manager is already Idle.
            info!("Wi-Fi restore disabled; preserving existing host networking");
            self.state_machine.reset_to_idle().await;
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
            country_code: "US".to_string(),
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
        // Use the uplink interface from config (or NetworkSelector), never from the kernel
        // routing table — the kernel's default route may point to eth0 regardless of
        // which interface the orchestration layer has selected as uplink.
        let nat_manager = NatManager::new();
        if let Some(uplink_iface) = Self::get_uplink_interface(config) {
            if let Err(e) = nat_manager.enable_nat(
                &config.hotspot.interface,
                &uplink_iface,
                config.hotspot.client_isolation,
            ) {
                tracing::error!(
                    "Failed to apply NAT routing via {} (local Wi-Fi only): {}",
                    uplink_iface,
                    e
                );
            } else {
                tracing::debug!("Successfully established NAT routing via {}", uplink_iface);

                if let Err(e) = self.routing.enable_forwarding() {
                    tracing::error!("Failed to enable kernel IPv4 forwarding: {}", e);
                }

                *self.nat.lock().await = Some(nat_manager);
            }
        } else {
            tracing::warn!(
                "No uplink interface configured or detected — hotspot will run without NAT."
            );
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
        Self::stop_unsafe_suricata_wifi_capture().await;

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
            country_code: "US".to_string(),
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

    fn managed_interfaces(mode: &RuntimeMode, config: &GuardianConfig) -> Vec<String> {
        let candidates: &[&str] = match mode {
            RuntimeMode::Off => &[],
            RuntimeMode::HotspotOnly => &[config.hotspot.interface.as_str()],
            RuntimeMode::ClientOnly => &[config.uplink.interface.as_str()],
            RuntimeMode::DualWifi => &[
                config.hotspot.interface.as_str(),
                config.uplink.interface.as_str(),
            ],
        };

        let mut interfaces = Vec::new();
        for interface in candidates {
            if !interface.is_empty() && !interfaces.iter().any(|item| item == interface) {
                interfaces.push((*interface).to_string());
            }
        }
        interfaces
    }

    async fn perform_system_cleanup(&self, mode: &RuntimeMode, config: &GuardianConfig) {
        let interfaces = Self::managed_interfaces(mode, config);
        tracing::info!(
            "🧹 Preparing Guardian-managed wireless interfaces: {:?}",
            interfaces
        );

        // ProcessRunner owns and stops Guardian's hostapd/wpa_supplicant/dnsmasq
        // children. Never use global killall here: those daemons may carry the host's
        // management connection or provide unrelated DNS/DHCP services.
        for interface in &interfaces {
            tracing::info!(
                "Resetting Guardian-managed wireless interface: {}",
                interface
            );
            let _ = tokio::process::Command::new("ip")
                .args(["link", "set", "dev", interface, "down"])
                .output()
                .await;
            let _ = tokio::process::Command::new("ip")
                .args(["addr", "flush", "dev", interface])
                .output()
                .await;

            // Remove only this interface's stale control sockets.
            let _ = std::fs::remove_file(format!("/var/run/hostapd/{}", interface));
            let _ = std::fs::remove_file(format!("/var/run/wpa_supplicant/{}", interface));

            // Interface-scoped power saving avoids changing sibling interfaces that
            // share a PHY with the board's management Wi-Fi connection.
            let _ = tokio::process::Command::new("iw")
                .args(["dev", interface, "set", "power_save", "off"])
                .output()
                .await;
        }

        // Wait for radio hardware to fully settle after reset before hostapd attempts to
        // configure channels. Embedded Wi-Fi chips (e.g. mwiphy0) typically need 1-2 seconds
        // after interface reset to initialize firmware and release the channel lock.
        tracing::info!("⏳ Waiting for radio hardware to settle...");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        tracing::info!("✅ Managed-interface preparation complete.");
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
        // Clean up HotspotOnly NAT if it was set
        if let Some(nat) = self.nat.lock().await.take() {
            let _ = nat.disable_nat();
            let _ = self.routing.disable_forwarding();
        }
    }

    pub async fn restart(&self) -> Result<(), RuntimeError> {
        let config = ConfigStore::load()?;
        warn!(
            "Runtime restart requested explicitly: saved_mode={}",
            Self::mode_label(&config.mode)
        );
        self.handle_transition(config.mode).await
    }
}

#[cfg(test)]
mod tests {
    use super::RuntimeManager;
    use crate::network_selector::set_selected_interface;
    use crate::runtime::errors::RuntimeError;
    use crate::runtime::event_bus::{EventBus, RuntimeEvent};
    use crate::runtime::models::{GuardianConfig, RuntimeMode};
    use crate::runtime::state::SystemState;
    use crate::runtime::state_machine::StateMachine;
    use crate::test_support::{async_env_lock, blocking_env_lock};
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::TempDir;

    fn new_manager() -> Arc<RuntimeManager> {
        let event_bus = Arc::new(EventBus::new());
        let state_machine = Arc::new(StateMachine::new(event_bus));
        Arc::new(RuntimeManager::new(state_machine))
    }

    /// Points `GUARDIAN_CONFIG_FILE` at a fresh, isolated temp file holding
    /// `config` so `ConfigStore::load()` never touches the real host config.
    fn write_config(dir: &TempDir, config: &GuardianConfig) -> std::path::PathBuf {
        let path = dir.path().join("wifi_config.json");
        std::fs::write(&path, serde_json::to_string(config).expect("serialize config"))
            .expect("write config file");
        path
    }

    #[test]
    fn detects_suricata_wifi_capture_references() {
        assert!(RuntimeManager::references_wifi_capture(
            "ExecStart=/opt/suricata/bin/suricata -i wlan0"
        ));
        assert!(RuntimeManager::references_wifi_capture("- interface: uap1"));
        assert!(!RuntimeManager::references_wifi_capture(
            "- interface: eth0"
        ));
    }

    #[test]
    fn prefers_configured_uplink_interface() {
        let _test_lock = blocking_env_lock();
        set_selected_interface(None);

        let mut config = GuardianConfig::default();
        config.uplink.interface = "eth9".to_string();

        assert_eq!(
            RuntimeManager::get_uplink_interface(&config).as_deref(),
            Some("eth9")
        );
    }

    #[test]
    fn falls_back_to_selected_uplink_interface() {
        let _test_lock = blocking_env_lock();
        set_selected_interface(Some("eth7".to_string()));

        let config = GuardianConfig::default();

        assert_eq!(
            RuntimeManager::get_uplink_interface(&config).as_deref(),
            Some("eth7")
        );

        set_selected_interface(None);
    }

    #[test]
    fn off_mode_never_selects_interfaces_for_cleanup() {
        let mut config = GuardianConfig::default();
        config.hotspot.interface = "uap0".to_string();
        config.uplink.interface = "wlan1".to_string();

        assert!(RuntimeManager::managed_interfaces(&RuntimeMode::Off, &config).is_empty());
    }

    #[test]
    fn cleanup_is_limited_to_interfaces_used_by_target_mode() {
        let mut config = GuardianConfig::default();
        config.hotspot.interface = "uap0".to_string();
        config.uplink.interface = "wlan1".to_string();

        assert_eq!(
            RuntimeManager::managed_interfaces(&RuntimeMode::HotspotOnly, &config),
            vec!["uap0"]
        );
        assert_eq!(
            RuntimeManager::managed_interfaces(&RuntimeMode::ClientOnly, &config),
            vec!["wlan1"]
        );
        assert_eq!(
            RuntimeManager::managed_interfaces(&RuntimeMode::DualWifi, &config),
            vec!["uap0", "wlan1"]
        );
    }

    #[test]
    fn cleanup_deduplicates_shared_interface_configuration() {
        let mut config = GuardianConfig::default();
        config.hotspot.interface = "wlan1".to_string();
        config.uplink.interface = "wlan1".to_string();

        assert_eq!(
            RuntimeManager::managed_interfaces(&RuntimeMode::DualWifi, &config),
            vec!["wlan1"]
        );
    }

    #[test]
    fn mode_label_matches_all_variants() {
        assert_eq!(RuntimeManager::mode_label(&RuntimeMode::Off), "Off");
        assert_eq!(
            RuntimeManager::mode_label(&RuntimeMode::HotspotOnly),
            "HotspotOnly"
        );
        assert_eq!(
            RuntimeManager::mode_label(&RuntimeMode::ClientOnly),
            "ClientOnly"
        );
        assert_eq!(
            RuntimeManager::mode_label(&RuntimeMode::DualWifi),
            "DualWifi"
        );
    }

    #[test]
    fn verify_interface_exists_true_for_loopback() {
        // "lo" is guaranteed to exist on any Linux host and querying it is a
        // read-only `ip link show`, so this is safe without root or real hardware.
        assert!(RuntimeManager::verify_interface_exists("lo"));
    }

    #[test]
    fn verify_interface_exists_false_for_missing_interface() {
        assert!(!RuntimeManager::verify_interface_exists(
            "definitely-not-a-real-iface-zzz"
        ));
    }

    #[tokio::test]
    async fn start_hotspot_mode_errors_when_interface_missing() {
        let manager = new_manager();
        let mut config = GuardianConfig::default();
        config.hotspot.interface = "zzz-fake-hotspot-iface".to_string();

        let err = manager
            .start_hotspot_mode(&config)
            .await
            .expect_err("a nonexistent hotspot interface must fail before any daemon starts");
        assert!(matches!(err, RuntimeError::InvalidConfig(_)));

        let status = manager.state_machine.get_status().await;
        assert_eq!(status.state, SystemState::Error);
        assert_eq!(
            status.metadata.error_code.as_deref(),
            Some("E_WIFI_MODULE_NOT_FOUND")
        );
    }

    #[tokio::test]
    async fn start_client_mode_errors_when_interface_missing() {
        let manager = new_manager();
        let mut config = GuardianConfig::default();
        config.uplink.interface = "zzz-fake-uplink-iface".to_string();

        let err = manager
            .start_client_mode(&config)
            .await
            .expect_err("a nonexistent uplink interface must fail before wifi_client starts");
        assert!(matches!(err, RuntimeError::InvalidConfig(_)));

        let status = manager.state_machine.get_status().await;
        assert_eq!(status.state, SystemState::Error);
        assert_eq!(
            status.metadata.error_code.as_deref(),
            Some("E_WIFI_MODULE2_NOT_FOUND")
        );
    }

    #[tokio::test]
    async fn start_dual_wifi_mode_errors_when_uplink_interface_missing() {
        let manager = new_manager();
        let mut config = GuardianConfig::default();
        // Both are fake; the uplink check runs first and must be what fails.
        config.uplink.interface = "zzz-fake-uplink-iface".to_string();
        config.hotspot.interface = "zzz-fake-hotspot-iface".to_string();

        let err = manager
            .start_dual_wifi_mode(&config)
            .await
            .expect_err("missing uplink interface must fail dual-wifi startup");
        assert!(matches!(err, RuntimeError::InvalidConfig(_)));

        let status = manager.state_machine.get_status().await;
        assert_eq!(status.state, SystemState::Error);
        assert_eq!(
            status.metadata.error_code.as_deref(),
            Some("E_WIFI_MODULE2_NOT_FOUND")
        );
    }

    #[tokio::test]
    async fn start_dual_wifi_mode_errors_when_hotspot_interface_missing_but_uplink_present() {
        let manager = new_manager();
        let mut config = GuardianConfig::default();
        // "lo" passes the first (uplink) check, isolating the second (hotspot) check.
        config.uplink.interface = "lo".to_string();
        config.hotspot.interface = "zzz-fake-hotspot-iface".to_string();

        let err = manager
            .start_dual_wifi_mode(&config)
            .await
            .expect_err("missing hotspot interface must still fail dual-wifi startup");
        assert!(matches!(err, RuntimeError::InvalidConfig(_)));

        let status = manager.state_machine.get_status().await;
        assert_eq!(status.state, SystemState::Error);
        assert_eq!(
            status.metadata.error_code.as_deref(),
            Some("E_WIFI_MODULE_NOT_FOUND")
        );
    }

    #[tokio::test]
    async fn supervise_transition_reaches_target_and_completes() {
        let manager = new_manager();

        manager.clone().supervise_transition(RuntimeMode::Off).await;

        let handle = manager
            .supervisor_task
            .lock()
            .await
            .take()
            .expect("supervisor task should be recorded");
        handle
            .await
            .expect("supervisor task should finish without panicking");

        let status = manager.state_machine.get_status().await;
        assert_eq!(status.state, SystemState::Idle);
    }

    #[tokio::test]
    async fn supervise_transition_aborts_previous_task_on_duplicate_call() {
        let _env_lock = async_env_lock().await;
        let dir = TempDir::new().expect("tempdir");
        // Default config has empty hotspot/uplink interfaces, so the first attempt
        // is guaranteed to fail deterministically regardless of the host's real NICs.
        write_config(&dir, &GuardianConfig::default());
        std::env::set_var("GUARDIAN_CONFIG_FILE", dir.path().join("wifi_config.json"));

        let event_bus = Arc::new(EventBus::new());
        let mut events = event_bus.subscribe();
        let state_machine = Arc::new(StateMachine::new(event_bus));
        let manager = Arc::new(RuntimeManager::new(state_machine));

        manager
            .clone()
            .supervise_transition(RuntimeMode::HotspotOnly)
            .await;

        // Wait for the first attempt to fail (it always will: no real interface
        // named "" exists) so the supervisor loop is parked in its 10s backoff.
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match events.recv().await.expect("event bus closed unexpectedly") {
                    RuntimeEvent::Error(_) => break,
                    _ => continue,
                }
            }
        })
        .await
        .expect("first supervised attempt did not fail within the timeout budget");

        {
            let guard = manager.supervisor_task.lock().await;
            let task = guard.as_ref().expect("supervisor task should be recorded");
            assert!(
                !task.is_finished(),
                "the first supervisor task should still be parked in its retry backoff"
            );
        }

        // A second call must abort the still-retrying first task and take over.
        manager.clone().supervise_transition(RuntimeMode::Off).await;

        let handle = manager
            .supervisor_task
            .lock()
            .await
            .take()
            .expect("replacement supervisor task should be recorded");
        handle
            .await
            .expect("replacement supervisor task should finish without panicking");

        std::env::remove_var("GUARDIAN_CONFIG_FILE");

        let status = manager.state_machine.get_status().await;
        assert_eq!(status.state, SystemState::Idle);
    }

    #[tokio::test]
    async fn restart_reflects_persisted_config_mode() {
        let _env_lock = async_env_lock().await;
        let dir = TempDir::new().expect("tempdir");
        let mut config = GuardianConfig::default();
        config.mode = RuntimeMode::Off;
        write_config(&dir, &config);
        std::env::set_var("GUARDIAN_CONFIG_FILE", dir.path().join("wifi_config.json"));

        let manager = new_manager();
        let res = manager.restart().await;
        std::env::remove_var("GUARDIAN_CONFIG_FILE");

        assert!(res.is_ok());
        let status = manager.state_machine.get_status().await;
        assert_eq!(status.state, SystemState::Idle);
    }

    #[tokio::test]
    async fn restart_propagates_config_load_failure() {
        let _env_lock = async_env_lock().await;
        let dir = TempDir::new().expect("tempdir");
        let config_path = dir.path().join("wifi_config.json");
        std::fs::write(&config_path, "{ not valid json").expect("write malformed config");
        std::env::set_var("GUARDIAN_CONFIG_FILE", &config_path);

        let manager = new_manager();
        let res = manager.restart().await;
        std::env::remove_var("GUARDIAN_CONFIG_FILE");

        assert!(matches!(res, Err(RuntimeError::InvalidConfig(_))));
    }

    #[tokio::test]
    async fn apply_saved_state_without_restore_flag_resets_idle() {
        let _env_lock = async_env_lock().await;
        let dir = TempDir::new().expect("tempdir");
        let mut config = GuardianConfig::default();
        config.mode = RuntimeMode::HotspotOnly; // a saved active mode...
        config.flags.restore_on_boot = false; // ...must still be ignored here
        write_config(&dir, &config);
        std::env::set_var("GUARDIAN_CONFIG_FILE", dir.path().join("wifi_config.json"));

        let manager = new_manager();
        let res = manager.clone().apply_saved_state().await;
        std::env::remove_var("GUARDIAN_CONFIG_FILE");

        assert!(res.is_ok());
        assert!(
            manager.supervisor_task.lock().await.is_none(),
            "restore disabled must never start a supervisor"
        );
        let status = manager.state_machine.get_status().await;
        assert_eq!(status.state, SystemState::Idle);
    }

    #[tokio::test]
    async fn apply_saved_state_off_mode_ignores_restore_flag() {
        let _env_lock = async_env_lock().await;
        let dir = TempDir::new().expect("tempdir");
        let mut config = GuardianConfig::default();
        config.mode = RuntimeMode::Off;
        config.flags.restore_on_boot = true; // restore is on, but saved mode is already Off
        write_config(&dir, &config);
        std::env::set_var("GUARDIAN_CONFIG_FILE", dir.path().join("wifi_config.json"));

        let manager = new_manager();
        let res = manager.clone().apply_saved_state().await;
        std::env::remove_var("GUARDIAN_CONFIG_FILE");

        assert!(res.is_ok());
        assert!(manager.supervisor_task.lock().await.is_none());
        let status = manager.state_machine.get_status().await;
        assert_eq!(status.state, SystemState::Idle);
    }

    #[tokio::test]
    async fn apply_saved_state_with_restore_enabled_spawns_supervisor() {
        let _env_lock = async_env_lock().await;
        let dir = TempDir::new().expect("tempdir");
        let mut config = GuardianConfig::default();
        config.mode = RuntimeMode::HotspotOnly;
        config.flags.restore_on_boot = true;
        write_config(&dir, &config);
        std::env::set_var("GUARDIAN_CONFIG_FILE", dir.path().join("wifi_config.json"));

        let manager = new_manager();
        let res = manager.clone().apply_saved_state().await;
        std::env::remove_var("GUARDIAN_CONFIG_FILE");

        assert!(res.is_ok());

        // A supervisor must have been started to try to reach the saved mode;
        // abort it immediately so it does not keep retrying past this test.
        let mut guard = manager.supervisor_task.lock().await;
        assert!(
            guard.is_some(),
            "restore_on_boot with a non-Off saved mode must start a supervisor"
        );
        if let Some(task) = guard.take() {
            task.abort();
        }
    }
}
