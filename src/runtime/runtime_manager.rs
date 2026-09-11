use crate::netbridge::nat::NatManager;
use crate::netbridge::routing::RoutingManager;
use crate::netbridge::types::{ApSettings, DnsmasqSettings};
use crate::netbridge::Netbridge;
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
    /// Holds the active NetworkManager station session for ClientOnly mode.
    nm_station_session: Arc<Mutex<Option<crate::netbridge::network_manager::StationSession>>>,
    /// Holds the NatManager for HotspotOnly mode (Ethernet uplink NAT).
    /// DualWifi mode manages its own NAT internally.
    nat: Arc<Mutex<Option<NatManager>>>,
    routing: Arc<RoutingManager>,
    supervisor_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Recovery task for DualWifi's NetworkManager-backed uplink leg. Keeps the
    /// legacy hostapd AP alive while only the NM station session is rebuilt.
    dual_nm_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Recovery task for ClientOnly's NetworkManager station session. Rebuilds
    /// only the station session in place, without the full stop_all/cleanup/
    /// restart cycle the generic supervisor used to do — that cycle raced with
    /// a physically flapping radio and produced repeated E_NM_TIMEOUT.
    client_nm_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl RuntimeManager {
    pub fn new(state_machine: Arc<StateMachine>) -> Self {
        RuntimeManager {
            state_machine,
            ap: Arc::new(Mutex::new(None)),
            nm_station_session: Arc::new(Mutex::new(None)),
            nat: Arc::new(Mutex::new(None)),
            routing: Arc::new(RoutingManager::new()),
            supervisor_task: Arc::new(Mutex::new(None)),
            dual_nm_task: Arc::new(Mutex::new(None)),
            client_nm_task: Arc::new(Mutex::new(None)),
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

    /// Default hotspot credentials, used only when the user has never
    /// configured a valid SSID/password. A user-configured hotspot config is
    /// always used as-is; this never overrides it.
    const DEFAULT_HOTSPOT_SSID: &'static str = "SGX_Hotspot";
    const DEFAULT_HOTSPOT_PASSWORD: &'static str = "Password123!";

    pub fn default_hotspot_ssid() -> &'static str {
        Self::DEFAULT_HOTSPOT_SSID
    }

    /// Resolves the SSID/password to actually start the hotspot with. Some
    /// REST paths (saving mode=Off or mode=ClientOnly) never validate the
    /// hotspot password, so a saved config can carry an empty/invalid one —
    /// that must not turn into a hard failure (and an infinite 10s retry
    /// loop) the moment a hotspot needs to start.
    fn effective_hotspot_credentials(config: &GuardianConfig) -> (String, String) {
        let ssid = if config.hotspot.ssid.trim().is_empty() {
            Self::DEFAULT_HOTSPOT_SSID.to_string()
        } else {
            config.hotspot.ssid.clone()
        };
        let password = if crate::runtime::crypto::validate_hotspot_password(
            &config.hotspot.password,
        )
        .is_ok()
        {
            config.hotspot.password.clone()
        } else {
            warn!("Saved hotspot password is unset or invalid; using the default hotspot password");
            Self::DEFAULT_HOTSPOT_PASSWORD.to_string()
        };
        (ssid, password)
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
            "Loaded persisted runtime config before transition: saved_mode={}, hotspot_iface={}, uplink_iface={}",
            Self::mode_label(&config.mode),
            config.hotspot.interface,
            config.uplink.interface
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

    /// Every boot always brings up HotspotOnly, unconditionally — regardless of
    /// what mode was last saved (Off, ClientOnly, DualWifi, or HotspotOnly).
    /// The hotspot is Guardian's guaranteed local access point; boot never
    /// restores a saved uplink or DualWifi state automatically.
    pub async fn apply_saved_state(self: Arc<Self>) -> Result<(), RuntimeError> {
        let config = ConfigStore::load()?;
        info!(
            "Boot restore: saved_mode={} -> boot_mode=HotspotOnly (hotspot always starts on boot)",
            Self::mode_label(&config.mode)
        );
        // Reconstruct the stack so every daemon, health task, route, and NAT rule is
        // owned by this process. Merely observing AP + Wi-Fi state can report
        // DualActive while forwarding is absent and no recovery task exists.
        self.supervise_transition(RuntimeMode::HotspotOnly).await;
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

        let (hotspot_ssid, hotspot_password) = Self::effective_hotspot_credentials(config);
        let ap_settings = ApSettings {
            interface: config.hotspot.interface.clone(),
            ssid: hotspot_ssid,
            wpa_passphrase: Some(hotspot_password),
            channel: config.hotspot.channel,
            hw_mode,
            country_code: "US".to_string(),
            client_isolation: config.hotspot.client_isolation,
        };

        let dns_settings = DnsmasqSettings {
            interface: config.hotspot.interface.clone(),
            ..DnsmasqSettings::default()
        };
        let hotspot_gateway_ip = dns_settings.gateway_ip.clone();

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

                // On boards without kernel policy-routing support, NAT/forward rules
                // alone aren't enough — the kernel's own default route decides which
                // interface forwarded traffic actually leaves through, and that can
                // point elsewhere (e.g. a lower-metric cellular route). This makes the
                // selected uplink win that decision so hotspot clients reliably get
                // internet through it regardless of what else is active.
                if let Some(hotspot_cidr) =
                    crate::netbridge::hotspot_subnet_cidr(&hotspot_gateway_ip)
                {
                    if let Err(e) =
                        RoutingManager::configure_hotspot_uplink(&hotspot_cidr, &uplink_iface)
                    {
                        tracing::warn!(
                            "Failed to pin hotspot traffic to uplink {}: {}",
                            uplink_iface,
                            e
                        );
                    }
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

        info!(
            "Starting ClientOnly mode via NetworkManager D-Bus backend on {}...",
            config.uplink.interface
        );
        let backend = match crate::netbridge::network_manager::NetworkManagerBackend::system(
            std::time::Duration::from_secs(5),
        )
        .await
        {
            Ok(b) => b,
            Err(e) => {
                self.state_machine
                    .set_error_state(
                        format!("NetworkManager unavailable: {}", e),
                        Some(e.code().to_string()),
                    )
                    .await;
                return Err(RuntimeError::InvalidConfig(e.to_string()));
            }
        };

        if config.uplink.networks.is_empty() {
            self.state_machine
                .set_error_state(
                    "No saved Wi-Fi networks configured".to_string(),
                    Some("E_WIFI_NO_SAVED_NETWORKS".to_string()),
                )
                .await;
            return Err(RuntimeError::InvalidConfig("No saved networks".to_string()));
        }

        let mut last_err = None;
        let mut connected_session = None;

        for (idx, network) in config.uplink.networks.iter().enumerate() {
            info!(
                "Attempting NetworkManager station connection to '{}' (priority {})",
                network.ssid, idx
            );
            let profile = match crate::netbridge::network_manager::station_profile::StationProfileBuilder::new(
                    &config.uplink.interface,
                )
                .and_then(|b| b.build(network, idx))
                {
                    Ok(p) => p,
                    Err(e) => {
                        warn!(
                            "Failed to build station profile for '{}': {}",
                            network.ssid, e
                        );
                        last_err = Some(e.to_string());
                        continue;
                    }
                };

            match backend
                .activate_station(&profile, std::time::Duration::from_secs(25))
                .await
            {
                Ok(session) => {
                    info!(
                        "✅ NetworkManager connected to '{}' on {} (IP: {}, Gateway: {:?})",
                        network.ssid,
                        config.uplink.interface,
                        session.addresses.join(", "),
                        session.gateway
                    );
                    connected_session = Some(session);
                    break;
                }
                Err(e) => {
                    warn!(
                        "NetworkManager station connection to '{}' failed: [{}] {}",
                        network.ssid,
                        e.code(),
                        e
                    );
                    last_err = Some(e.to_string());
                }
            }
        }

        if let Some(session) = connected_session {
            *self.nm_station_session.lock().await = Some(session);
            self.state_machine
                .transition_to(SystemState::ClientConnected)
                .await;

            let uplink_iface = config.uplink.interface.clone();
            let networks = config.uplink.networks.clone();
            let nm_session_slot = Arc::clone(&self.nm_station_session);
            let state_machine = Arc::clone(&self.state_machine);

            let task = tokio::spawn(async move {
                let mut consecutive_failures = 0_u8;
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

                    let session_now = nm_session_slot.lock().await.clone();
                    let Some(session_now) = session_now else {
                        continue;
                    };

                    let viable =
                        match crate::netbridge::network_manager::NetworkManagerBackend::system(
                            std::time::Duration::from_secs(5),
                        )
                        .await
                        {
                            Ok(backend) => backend
                                .station_session_is_viable(&session_now)
                                .await
                                .unwrap_or(false),
                            Err(_) => false,
                        };

                    if viable {
                        consecutive_failures = 0;
                        continue;
                    }

                    consecutive_failures = consecutive_failures.saturating_add(1);
                    warn!(
                        "ClientOnly NetworkManager station health check failed ({}/3)",
                        consecutive_failures
                    );
                    if consecutive_failures < 3 {
                        continue;
                    }
                    consecutive_failures = 0;

                    warn!(
                        "ClientOnly uplink session lost; rebuilding NetworkManager station on {}",
                        uplink_iface
                    );
                    let backend =
                        match crate::netbridge::network_manager::NetworkManagerBackend::system(
                            std::time::Duration::from_secs(5),
                        )
                        .await
                        {
                            Ok(b) => b,
                            Err(e) => {
                                warn!(
                                    "NetworkManager unavailable during ClientOnly rebuild: {}",
                                    e
                                );
                                continue;
                            }
                        };
                    let _ = backend.deactivate_station(&session_now).await;

                    let mut rebuilt = None;
                    for (idx, network) in networks.iter().enumerate() {
                        let profile = match crate::netbridge::network_manager::station_profile::StationProfileBuilder::new(
                                &uplink_iface,
                            )
                            .and_then(|b| b.build(network, idx))
                            {
                                Ok(p) => p,
                                Err(_) => continue,
                            };
                        match backend
                            .activate_station(&profile, std::time::Duration::from_secs(25))
                            .await
                        {
                            Ok(s) => {
                                rebuilt = Some(s);
                                break;
                            }
                            Err(e) => {
                                warn!("ClientOnly reconnect to '{}' failed: {}", network.ssid, e)
                            }
                        }
                    }

                    match rebuilt {
                        Some(s) => {
                            *nm_session_slot.lock().await = Some(s);
                            state_machine
                                .transition_to(SystemState::ClientConnected)
                                .await;
                            info!("✅ ClientOnly uplink reconnected on {}", uplink_iface);
                        }
                        None => {
                            warn!(
                                    "ClientOnly uplink rebuild failed on every saved network; will retry"
                                );
                            *nm_session_slot.lock().await = None;
                        }
                    }
                }
            });
            *self.client_nm_task.lock().await = Some(task);

            return Ok(());
        } else {
            let err_msg = last_err
                .unwrap_or_else(|| "Failed to connect to any configured Wi-Fi network".to_string());
            let code = if err_msg.contains("E_WIFI_AUTH_FAILED") {
                Some("E_WIFI_WRONG_PASSWORD".to_string())
            } else if err_msg.contains("E_WIFI_SSID_NOT_FOUND") {
                Some("E_WIFI_AP_NOT_FOUND".to_string())
            } else {
                None
            };
            self.state_machine
                .set_error_state(format!("Client failed: {}", err_msg), code)
                .await;
            return Err(RuntimeError::InvalidConfig(err_msg));
        }
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

        self.start_dual_wifi_mode_nm(config).await
    }

    /// DualWifi with the uplink leg (`wlan1`) managed over NetworkManager D-Bus
    /// while the hotspot leg stays on the legacy hostapd/dnsmasq path on `uap0`.
    /// The hotspot must never go down just because the uplink needs rebuilding,
    /// so uplink recovery is a dedicated task that only ever touches the NM
    /// station session, routing, and NAT — never `self.ap`.
    async fn start_dual_wifi_mode_nm(&self, config: &GuardianConfig) -> Result<(), RuntimeError> {
        info!(
            "Starting DualWifi via NetworkManager D-Bus uplink on {} (hotspot stays on legacy {})",
            config.uplink.interface, config.hotspot.interface
        );

        let hw_mode = if config.hotspot.channel > 14 {
            "a".to_string()
        } else {
            "g".to_string()
        };

        let (hotspot_ssid, hotspot_password) = Self::effective_hotspot_credentials(config);
        let ap_settings = ApSettings {
            interface: config.hotspot.interface.clone(),
            ssid: hotspot_ssid,
            wpa_passphrase: Some(hotspot_password),
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
                    format!("Dual WiFi AP failed: {}", e),
                    Some("E_HOSTAPD_FAIL".to_string()),
                )
                .await;
            return Err(RuntimeError::InvalidConfig(e.to_string()));
        }

        let backend = match crate::netbridge::network_manager::NetworkManagerBackend::system(
            std::time::Duration::from_secs(5),
        )
        .await
        {
            Ok(b) => b,
            Err(e) => {
                let _ = ap.stop().await;
                self.state_machine
                    .set_error_state(
                        format!("NetworkManager unavailable: {}", e),
                        Some(e.code().to_string()),
                    )
                    .await;
                return Err(RuntimeError::InvalidConfig(e.to_string()));
            }
        };

        if config.uplink.networks.is_empty() {
            let _ = ap.stop().await;
            self.state_machine
                .set_error_state(
                    "No saved Wi-Fi networks configured".to_string(),
                    Some("E_WIFI_NO_SAVED_NETWORKS".to_string()),
                )
                .await;
            return Err(RuntimeError::InvalidConfig("No saved networks".to_string()));
        }

        let mut last_err = None;
        let mut connected_session = None;
        for (idx, network) in config.uplink.networks.iter().enumerate() {
            let profile = match crate::netbridge::network_manager::station_profile::StationProfileBuilder::new(
                &config.uplink.interface,
            )
            .and_then(|b| b.build(network, idx))
            {
                Ok(p) => p,
                Err(e) => {
                    last_err = Some(e.to_string());
                    continue;
                }
            };
            match backend
                .activate_station(&profile, std::time::Duration::from_secs(25))
                .await
            {
                Ok(session) => {
                    connected_session = Some(session);
                    break;
                }
                Err(e) => {
                    last_err = Some(format!("[{}] {}", e.code(), e));
                }
            }
        }

        let session = match connected_session {
            Some(s) => s,
            None => {
                let _ = ap.stop().await;
                let err_msg = last_err.unwrap_or_else(|| {
                    "Failed to connect to any configured Wi-Fi network".to_string()
                });
                let code = if err_msg.contains("E_WIFI_AUTH_FAILED") {
                    Some("E_WIFI_WRONG_PASSWORD".to_string())
                } else if err_msg.contains("E_WIFI_SSID_NOT_FOUND") {
                    Some("E_WIFI_AP_NOT_FOUND".to_string())
                } else {
                    None
                };
                self.state_machine
                    .set_error_state(format!("Dual WiFi uplink failed: {}", err_msg), code)
                    .await;
                return Err(RuntimeError::InvalidConfig(err_msg));
            }
        };

        // Subnet-conflict check against the address NetworkManager assigned.
        if let Some(uplink_ipv4) = session.addresses.first().cloned() {
            if let Some(updated_dns) = crate::netbridge::select_non_conflicting_dns_settings(
                &ap.dnsmasq.settings,
                &uplink_ipv4,
            ) {
                warn!(
                    "Hotspot subnet {} conflicts with uplink {} on {}. Restarting AP on {}.",
                    ap.dnsmasq.settings.gateway_ip,
                    uplink_ipv4,
                    config.uplink.interface,
                    updated_dns.gateway_ip
                );
                if let Err(e) = ap.stop().await {
                    let _ = backend.deactivate_station(&session).await;
                    self.state_machine
                        .set_error_state(format!("Dual WiFi AP restart failed: {}", e), None)
                        .await;
                    return Err(RuntimeError::InvalidConfig(e.to_string()));
                }
                ap.dnsmasq.settings = updated_dns;
                if let Err(e) = ap.start().await {
                    let _ = backend.deactivate_station(&session).await;
                    self.state_machine
                        .set_error_state(
                            format!("Dual WiFi AP failed: {}", e),
                            Some("E_HOSTAPD_FAIL".to_string()),
                        )
                        .await;
                    return Err(RuntimeError::InvalidConfig(e.to_string()));
                }
            }
        }

        let hotspot_cidr =
            match crate::netbridge::hotspot_subnet_cidr(&ap.dnsmasq.settings.gateway_ip) {
                Some(cidr) => cidr,
                None => {
                    let _ = ap.stop().await;
                    let _ = backend.deactivate_station(&session).await;
                    self.state_machine
                        .set_error_state(
                            format!("invalid hotspot gateway {}", ap.dnsmasq.settings.gateway_ip),
                            None,
                        )
                        .await;
                    return Err(RuntimeError::InvalidConfig(
                        "invalid hotspot gateway".to_string(),
                    ));
                }
            };

        if let Err(e) =
            RoutingManager::configure_hotspot_uplink(&hotspot_cidr, &config.uplink.interface)
        {
            RoutingManager::remove_hotspot_uplink();
            let _ = ap.stop().await;
            let _ = backend.deactivate_station(&session).await;
            self.state_machine
                .set_error_state(format!("Dual WiFi routing failed: {}", e), None)
                .await;
            return Err(RuntimeError::InvalidConfig(e.to_string()));
        }

        if let Err(e) = self.routing.enable_forwarding() {
            RoutingManager::remove_hotspot_uplink();
            let _ = ap.stop().await;
            let _ = backend.deactivate_station(&session).await;
            self.state_machine
                .set_error_state(format!("Dual WiFi forwarding failed: {}", e), None)
                .await;
            return Err(RuntimeError::InvalidConfig(e.to_string()));
        }

        let nat_manager = NatManager::new();
        if let Err(e) = nat_manager.enable_nat(
            &config.hotspot.interface,
            &config.uplink.interface,
            config.hotspot.client_isolation,
        ) {
            RoutingManager::remove_hotspot_uplink();
            let _ = ap.stop().await;
            let _ = backend.deactivate_station(&session).await;
            self.state_machine
                .set_error_state(format!("Dual WiFi NAT failed: {}", e), None)
                .await;
            return Err(RuntimeError::InvalidConfig(e.to_string()));
        }

        *self.ap.lock().await = Some(ap);
        *self.nm_station_session.lock().await = Some(session);
        *self.nat.lock().await = Some(nat_manager);

        let hotspot_iface = config.hotspot.interface.clone();
        let uplink_iface = config.uplink.interface.clone();
        let client_isolation = config.hotspot.client_isolation;
        let networks = config.uplink.networks.clone();
        let nm_session_slot = Arc::clone(&self.nm_station_session);
        let nat_slot = Arc::clone(&self.nat);
        let hotspot_cidr_task = hotspot_cidr.clone();

        let task = tokio::spawn(async move {
            let mut consecutive_failures = 0_u8;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;

                let session_now = nm_session_slot.lock().await.clone();
                let Some(session_now) = session_now else {
                    continue;
                };

                let viable = match crate::netbridge::network_manager::NetworkManagerBackend::system(
                    std::time::Duration::from_secs(5),
                )
                .await
                {
                    Ok(backend) => backend
                        .station_session_is_viable(&session_now)
                        .await
                        .unwrap_or(false),
                    Err(_) => false,
                };

                if viable {
                    consecutive_failures = 0;
                    if !RoutingManager::hotspot_uplink_is_configured(
                        &hotspot_cidr_task,
                        &uplink_iface,
                    ) {
                        if let Err(e) = RoutingManager::configure_hotspot_uplink(
                            &hotspot_cidr_task,
                            &uplink_iface,
                        ) {
                            warn!(
                                "Failed to repair DualWifi policy route via {}: {}",
                                uplink_iface, e
                            );
                        }
                    }
                    let nat_guard = nat_slot.lock().await;
                    if let Some(nat) = nat_guard.as_ref() {
                        if !nat.kernel_rules_active(&hotspot_iface, &uplink_iface) {
                            info!(
                                "🌍 Restoring missing DualWifi NAT/security rules via {}.",
                                uplink_iface
                            );
                            if let Err(e) =
                                nat.enable_nat(&hotspot_iface, &uplink_iface, client_isolation)
                            {
                                warn!("Failed to reapply DualWifi NAT after recovery: {}", e);
                            }
                        }
                    }
                    drop(nat_guard);
                    continue;
                }

                consecutive_failures = consecutive_failures.saturating_add(1);
                warn!(
                    "DualWifi NetworkManager uplink health check failed ({}/3)",
                    consecutive_failures
                );
                if consecutive_failures < 3 {
                    continue;
                }
                consecutive_failures = 0;

                warn!(
                    "DualWifi uplink session lost; rebuilding NetworkManager station on {} while keeping the hotspot active",
                    uplink_iface
                );
                let backend =
                    match crate::netbridge::network_manager::NetworkManagerBackend::system(
                        std::time::Duration::from_secs(5),
                    )
                    .await
                    {
                        Ok(b) => b,
                        Err(e) => {
                            warn!(
                                "NetworkManager unavailable during DualWifi uplink rebuild: {}",
                                e
                            );
                            continue;
                        }
                    };
                let _ = backend.deactivate_station(&session_now).await;

                let mut rebuilt = None;
                for (idx, network) in networks.iter().enumerate() {
                    let profile = match crate::netbridge::network_manager::station_profile::StationProfileBuilder::new(
                        &uplink_iface,
                    )
                    .and_then(|b| b.build(network, idx))
                    {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    match backend
                        .activate_station(&profile, std::time::Duration::from_secs(25))
                        .await
                    {
                        Ok(s) => {
                            rebuilt = Some(s);
                            break;
                        }
                        Err(e) => warn!(
                            "DualWifi uplink reconnect to '{}' failed: {}",
                            network.ssid, e
                        ),
                    }
                }

                match rebuilt {
                    Some(s) => {
                        *nm_session_slot.lock().await = Some(s);
                        if let Err(e) = RoutingManager::configure_hotspot_uplink(
                            &hotspot_cidr_task,
                            &uplink_iface,
                        ) {
                            warn!(
                                "Failed to reconfigure DualWifi policy route after reconnect: {}",
                                e
                            );
                        }
                        let nat_guard = nat_slot.lock().await;
                        if let Some(nat) = nat_guard.as_ref() {
                            if let Err(e) =
                                nat.enable_nat(&hotspot_iface, &uplink_iface, client_isolation)
                            {
                                warn!("Failed to reapply DualWifi NAT after reconnect: {}", e);
                            }
                        }
                        drop(nat_guard);
                        info!(
                            "✅ DualWifi uplink reconnected on {} without dropping the hotspot",
                            uplink_iface
                        );
                    }
                    None => {
                        warn!(
                            "DualWifi uplink rebuild failed on every saved network; hotspot remains active, will retry"
                        );
                        *nm_session_slot.lock().await = None;
                    }
                }
            }
        });

        *self.dual_nm_task.lock().await = Some(task);

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

        // ProcessRunner owns and stops Guardian's hostapd/dnsmasq children. Never
        // use global killall here: those daemons may carry the host's management
        // connection or provide unrelated DNS/DHCP services.
        for interface in &interfaces {
            // The uplink interface is always NetworkManager-managed; never forcibly
            // down/flush it here.
            if interface == &config.uplink.interface {
                tracing::info!(
                    "Interface {} is managed by NetworkManager; skipping manual ip link/flush reset.",
                    interface
                );
                let _ = std::fs::remove_file(format!("/var/run/wpa_supplicant/{}", interface));
                continue;
            }

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
        if let Some(task) = self.dual_nm_task.lock().await.take() {
            task.abort();
        }
        if let Some(task) = self.client_nm_task.lock().await.take() {
            task.abort();
        }
        if let Some(session) = self.nm_station_session.lock().await.take() {
            tracing::info!(
                "Deactivating active NetworkManager station session: {}",
                session.profile_id
            );
            let mut cleaned = false;
            if let Ok(backend) = crate::netbridge::network_manager::NetworkManagerBackend::system(
                std::time::Duration::from_secs(5),
            )
            .await
            {
                if let Err(e) = backend.deactivate_station(&session).await {
                    tracing::warn!(
                        "Failed to cleanly deactivate NetworkManager station session: {}",
                        e
                    );
                } else {
                    cleaned = true;
                }
            }
            if !cleaned {
                *self.nm_station_session.lock().await = Some(session);
            }
        }
        if let Some(mut ap) = self.ap.lock().await.take() {
            let _ = ap.stop().await;
        }
        // Clean up HotspotOnly/DualWifi(NM) NAT and policy routing if set. Removing
        // the hotspot-uplink policy rule is a no-op when it was never configured
        // (HotspotOnly), so this is safe to call unconditionally here.
        if let Some(nat) = self.nat.lock().await.take() {
            let _ = nat.disable_nat();
            RoutingManager::remove_hotspot_uplink();
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
        std::fs::write(
            &path,
            serde_json::to_string(config).expect("serialize config"),
        )
        .expect("write config file");
        path
    }

    #[test]
    fn effective_hotspot_credentials_passes_through_a_valid_configured_hotspot() {
        let mut config = GuardianConfig::default();
        config.hotspot.ssid = "MyOwnHotspot".to_string();
        config.hotspot.password = "CorrectHorse1!".to_string();

        let (ssid, password) = RuntimeManager::effective_hotspot_credentials(&config);
        assert_eq!(ssid, "MyOwnHotspot");
        assert_eq!(password, "CorrectHorse1!");
    }

    #[test]
    fn effective_hotspot_credentials_falls_back_to_default_ssid_when_unset() {
        let mut config = GuardianConfig::default();
        config.hotspot.ssid = String::new();
        config.hotspot.password = "CorrectHorse1!".to_string();

        let (ssid, _password) = RuntimeManager::effective_hotspot_credentials(&config);
        assert_eq!(ssid, RuntimeManager::default_hotspot_ssid());
    }

    #[test]
    fn effective_hotspot_credentials_falls_back_to_default_ssid_when_only_whitespace() {
        let mut config = GuardianConfig::default();
        config.hotspot.ssid = "   ".to_string();

        let (ssid, _password) = RuntimeManager::effective_hotspot_credentials(&config);
        assert_eq!(ssid, RuntimeManager::default_hotspot_ssid());
    }

    #[test]
    fn effective_hotspot_credentials_falls_back_to_default_password_when_empty() {
        // This is the exact scenario that produced a real boot failure: saving
        // mode=Off or mode=ClientOnly never validates the hotspot password, so
        // a saved config can carry an empty one — starting the hotspot must not
        // hard-fail and retry forever when that happens.
        let mut config = GuardianConfig::default();
        config.hotspot.ssid = "MyOwnHotspot".to_string();
        config.hotspot.password = String::new();

        let (_ssid, password) = RuntimeManager::effective_hotspot_credentials(&config);
        assert_eq!(password, "Password123!");
        crate::runtime::crypto::validate_hotspot_password(&password)
            .expect("the default password must itself pass validation");
    }

    #[test]
    fn effective_hotspot_credentials_falls_back_to_default_password_when_too_short() {
        let mut config = GuardianConfig::default();
        config.hotspot.password = "short1!".to_string(); // 7 chars, fails validation

        let (_ssid, password) = RuntimeManager::effective_hotspot_credentials(&config);
        assert_eq!(password, "Password123!");
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

        let mut config = GuardianConfig::default();
        config.uplink.interface.clear();

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
    async fn apply_saved_state_always_boots_hotspot_even_when_saved_mode_is_off() {
        // The hotspot is Guardian's guaranteed local access point: it must come
        // up on every boot regardless of what mode was last saved, including an
        // explicit Off. There is no restore_on_boot flag anymore — this is
        // unconditional.
        let _env_lock = async_env_lock().await;
        let dir = TempDir::new().expect("tempdir");
        let mut config = GuardianConfig::default();
        config.mode = RuntimeMode::Off;
        write_config(&dir, &config);
        std::env::set_var("GUARDIAN_CONFIG_FILE", dir.path().join("wifi_config.json"));

        let manager = new_manager();
        let res = manager.clone().apply_saved_state().await;
        std::env::remove_var("GUARDIAN_CONFIG_FILE");

        assert!(res.is_ok());
        let mut guard = manager.supervisor_task.lock().await;
        assert!(
            guard.is_some(),
            "boot must always start a supervisor targeting HotspotOnly"
        );
        if let Some(task) = guard.take() {
            task.abort();
        }
    }

    #[tokio::test]
    async fn config_missing_the_legacy_flags_field_still_loads() {
        // Regression test: GuardianConfig used to require a `flags` field with
        // no serde default. A config file saved before that field was removed
        // (or one written by a client that no longer sends it) must still
        // deserialize instead of aborting boot before the hotspot ever starts.
        let _env_lock = async_env_lock().await;
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("wifi_config.json");
        std::fs::write(
            &path,
            r#"{"mode":"DualWifi","hotspot":{"interface":"uap0","ssid":"","password":"","channel":6,"band":null,"client_isolation":false},"uplink":{"interface":"wlan1","networks":[]}}"#,
        )
        .expect("write config file without a flags field");
        std::env::set_var("GUARDIAN_CONFIG_FILE", &path);

        let manager = new_manager();
        let res = manager.clone().apply_saved_state().await;
        std::env::remove_var("GUARDIAN_CONFIG_FILE");

        assert!(
            res.is_ok(),
            "config without `flags` must still load: {res:?}"
        );
        let mut guard = manager.supervisor_task.lock().await;
        assert!(guard.is_some());
        if let Some(task) = guard.take() {
            task.abort();
        }
    }

    #[tokio::test]
    async fn stop_unsafe_suricata_wifi_capture_is_a_safe_noop_when_nothing_uses_wifi() {
        // Neither /etc/suricata/suricata.yaml nor a real "suricata" systemd
        // unit exist in this sandbox, so both heuristics deterministically
        // report "no wifi capture configured" and the function returns
        // without ever reaching its real `systemctl stop` branch.
        RuntimeManager::stop_unsafe_suricata_wifi_capture().await;
    }

    #[tokio::test]
    async fn perform_system_cleanup_safely_no_ops_against_nonexistent_interfaces() {
        let manager = new_manager();
        let mut config = GuardianConfig::default();
        config.hotspot.interface = "zzz-fake-hotspot-iface".to_string();
        config.uplink.interface = "zzz-fake-uplink-iface".to_string();

        // Real `ip`/`iw` invocations against interfaces that don't exist
        // fail harmlessly (their output is discarded); this just confirms
        // the cleanup pass completes without panicking.
        manager
            .perform_system_cleanup(&RuntimeMode::DualWifi, &config)
            .await;
    }

    #[tokio::test]
    async fn apply_saved_state_boots_hotspot_when_saved_mode_was_dual_wifi() {
        let _env_lock = async_env_lock().await;
        let dir = TempDir::new().expect("tempdir");
        let mut config = GuardianConfig::default();
        config.mode = RuntimeMode::DualWifi;
        write_config(&dir, &config);
        std::env::set_var("GUARDIAN_CONFIG_FILE", dir.path().join("wifi_config.json"));

        let manager = new_manager();
        let res = manager.clone().apply_saved_state().await;
        std::env::remove_var("GUARDIAN_CONFIG_FILE");

        assert!(res.is_ok());

        // A supervisor must have been started to try to reach HotspotOnly, not
        // the saved DualWifi mode; abort it immediately so it does not keep
        // retrying past this test.
        let mut guard = manager.supervisor_task.lock().await;
        assert!(
            guard.is_some(),
            "boot must always start a supervisor targeting HotspotOnly"
        );
        if let Some(task) = guard.take() {
            task.abort();
        }
    }
}
