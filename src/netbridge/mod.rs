pub mod bootstrap;
pub mod config;
pub mod dhcp_client;
pub mod dhcp_dns;
pub mod leases;
pub mod nat;
pub mod process;
pub mod routing;
pub mod types;
pub mod uplink_monitor;
pub mod validator;
pub mod wifi_client;
pub mod wpa_config;

use self::bootstrap::{BootstrapOptions, Bootstrapper};
use self::config::ApSettings;
use self::process::ProcessRunner;
use tracing::{error, info};

use self::types::NetbridgeError;

/// Main Netbridge Orchestrator
pub struct Netbridge {
    settings: ApSettings,
    runner: Option<Arc<ProcessRunner>>,
    dnsmasq: dhcp_dns::DnsmasqOrchestrator,
}

impl Netbridge {
    /// Creates a new instance of the Netbridge orchestrator.
    pub fn new(settings: ApSettings, dnsmasq_settings: types::DnsmasqSettings) -> Self {
        Netbridge {
            settings,
            runner: None,
            dnsmasq: dhcp_dns::DnsmasqOrchestrator::new(dnsmasq_settings),
        }
    }

    /// Initializes and starts the AP flow: bootstrap -> config -> process -> AP flow.
    pub async fn start(&mut self) -> Result<(), NetbridgeError> {
        info!("Starting Netbridge orchestration flow...");

        // Provide default options for bootstrapping
        let options = BootstrapOptions::default();
        let bootstrapper = Bootstrapper::new(options);

        // 1. Bootstrap & Config Phase (validations, dir preparation, config generation)
        info!("Initiating bootstrap phase...");
        if let Err(e) = bootstrapper.initialize_ap_startup(&self.settings) {
            error!("Bootstrap failed: {}", e);
            return Err(NetbridgeError::BootstrapFailed(e.to_string()));
        }

        // 2. Process & AP Flow Phase
        // Initialize the asynchronous process runner with the newly generated config
        let config_path = "/tmp/netbridge/hostapd.conf".to_string();
        let runner = Arc::new(ProcessRunner::new("hostapd".to_string(), vec![config_path]));

        // Allow monitoring of the AP process status
        let _status_rx = runner.subscribe();

        // 3. Start the process asynchronously
        info!("Starting hostapd process...");
        if let Err(e) = runner.start().await {
            error!("Failed to start hostapd process: {}", e);
            return Err(NetbridgeError::ProcessExecutionFailed(e.to_string()));
        }

        // Enable the true process lifecycle manager to automatically restart it on crash
        runner.clone().enable_auto_restart();

        // Keep the runner instance alive to manage the process lifetime
        self.runner = Some(runner);

        info!("🔵 Starting Hotspot mode...");

        // Assign the static gateway IP to the AP interface so dnsmasq can bind to it
        let ip_addr = format!("{}/24", self.dnsmasq.settings.gateway_ip);
        let _ = tokio::process::Command::new("ip")
            .args(["addr", "flush", "dev", &self.settings.interface])
            .output()
            .await;
        let _ = tokio::process::Command::new("ip")
            .args(["addr", "add", &ip_addr, "dev", &self.settings.interface])
            .output()
            .await;
        let _ = tokio::process::Command::new("ip")
            .args(["link", "set", "dev", &self.settings.interface, "up"])
            .output()
            .await;

        info!("✅ Hotspot started successfully. Ready for devices to connect.");

        // 4. Start DNS/DHCP (dnsmasq) Orchestrator
        self.dnsmasq.start().await?;

        Ok(())
    }

    /// Gracefully stops the AP
    pub async fn stop(&mut self) -> Result<(), NetbridgeError> {
        tracing::debug!("Stopping Netbridge orchestration flow...");
        self.dnsmasq.stop().await?;
        if let Some(runner) = &self.runner {
            if let Err(e) = runner.stop().await {
                error!("Failed to stop hostapd process: {}", e);
                return Err(NetbridgeError::ProcessExecutionFailed(e.to_string()));
            }
        }

        // Forcefully bring the interface down so it stops broadcasting
        let _ = tokio::process::Command::new("ip")
            .args(["link", "set", "dev", &self.settings.interface, "down"])
            .output()
            .await;

        info!("🔴 Hotspot stopped successfully.");
        Ok(())
    }
}

use crate::netbridge::types::WifiClientSettings;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Uplink Orchestrator handling Station Mode (External Wi-Fi, DHCP, and Routing)
pub struct UplinkOrchestrator {
    settings: WifiClientSettings,
    wifi_client: wifi_client::WifiClientOrchestrator,
    dhcp_client: dhcp_client::DhcpClientOrchestrator,
    routing: routing::RoutingManager,
    monitor: Arc<Mutex<uplink_monitor::UplinkMonitor>>,
    monitor_task: Option<tokio::task::JoinHandle<()>>,
}

impl UplinkOrchestrator {
    pub fn new(settings: WifiClientSettings) -> Self {
        let interface = settings.interface.clone();
        UplinkOrchestrator {
            settings: settings.clone(),
            wifi_client: wifi_client::WifiClientOrchestrator::new(settings),
            dhcp_client: dhcp_client::DhcpClientOrchestrator::new(interface.clone()),
            routing: routing::RoutingManager::new(),
            monitor: Arc::new(Mutex::new(uplink_monitor::UplinkMonitor::new(interface))),
            monitor_task: None,
        }
    }

    /// Starts the upstream flow: WiFi Connect -> DHCP -> Routing -> Monitor
    pub async fn start(&mut self) -> Result<(), NetbridgeError> {
        info!("Starting Uplink Orchestration flow...");

        // 0. Bootstrap phase (uplink validations and dir prep)
        let options = crate::netbridge::bootstrap::BootstrapOptions::default();
        let bootstrapper = crate::netbridge::bootstrap::Bootstrapper::new(options);
        if let Err(e) = bootstrapper.initialize_uplink_startup(&self.settings) {
            error!("Uplink bootstrap failed: {}", e);
            return Err(NetbridgeError::BootstrapFailed(e.to_string()));
        }

        // 1. Connect to Wi-Fi (Blocks until COMPLETED or timeout)
        self.wifi_client.connect().await?;

        // 2. Start DHCP Client to obtain IP
        self.dhcp_client.start().await?;

        // 2.5 Disable Wi-Fi power saving on uplink to resolve packet loss and latency spikes
        info!(
            "Disabling Wi-Fi power saving on interface {} to stabilize connection...",
            &self.settings.interface
        );
        let _ = tokio::process::Command::new("iw")
            .args(["dev", &self.settings.interface, "set", "power_save", "off"])
            .output()
            .await;

        // 3. Enable kernel routing
        self.routing.enable_forwarding()?;

        // 4. Start background uplink monitor (yielding lock between cycles)
        let monitor_clone = Arc::clone(&self.monitor);
        let task = tokio::spawn(async move {
            let interval = std::time::Duration::from_secs(10);
            loop {
                {
                    let mut mon = monitor_clone.lock().await;
                    let previous_state = mon.current_state();
                    let new_state = mon.evaluate_health().await;

                    if new_state != previous_state {
                        info!(
                            "Uplink state changed: {:?} -> {:?}",
                            previous_state, new_state
                        );
                    }

                    if new_state == crate::netbridge::types::UplinkState::Disconnected
                        || new_state == crate::netbridge::types::UplinkState::NoInternet
                    {
                        error!("Uplink loss detected!");
                        mon.trigger_reconnect();
                    }
                } // Mutex guard drops here
                tokio::time::sleep(interval).await;
            }
        });
        self.monitor_task = Some(task);

        info!("Uplink successfully established and monitored.");
        Ok(())
    }

    /// Stops the upstream flow cleanly
    pub async fn stop(&mut self) -> Result<(), NetbridgeError> {
        info!("Stopping Uplink Orchestration flow...");

        // 1. Disable routing
        let _ = self.routing.disable_forwarding();

        // 2. Stop DHCP
        let _ = self.dhcp_client.stop().await;

        // 3. Disconnect Wi-Fi
        let _ = self.wifi_client.disconnect().await;

        // 4. Stop Monitor
        if let Some(task) = self.monitor_task.take() {
            task.abort();
        }

        // 5. Flush interface and bring it down to prevent blackhole routes
        let _ = tokio::process::Command::new("ip")
            .args(["addr", "flush", "dev", &self.settings.interface])
            .output()
            .await;
        
        let _ = tokio::process::Command::new("ip")
            .args(["link", "set", "dev", &self.settings.interface, "down"])
            .output()
            .await;

        info!("Uplink stopped successfully.");
        Ok(())
    }

    /// Exposes the current overall uplink state
    pub async fn current_state(&self) -> crate::netbridge::types::UplinkState {
        let mon = self.monitor.lock().await;
        mon.current_state()
    }

    /// Provides access to the shared monitor for higher-level orchestrators
    pub fn get_monitor(&self) -> Arc<Mutex<uplink_monitor::UplinkMonitor>> {
        Arc::clone(&self.monitor)
    }
}

/// Dual Wi-Fi Orchestrator (AP + Uplink + NAT/Firewall)
/// Guarantees exact startup order and fail-closed safety.
pub struct DualWifiOrchestrator {
    uplink: UplinkOrchestrator,
    ap: Netbridge,
    nat: Arc<nat::NatManager>,
}

impl DualWifiOrchestrator {
    pub fn new(
        ap_settings: ApSettings,
        dns_settings: types::DnsmasqSettings,
        uplink_settings: WifiClientSettings,
    ) -> Self {
        DualWifiOrchestrator {
            uplink: UplinkOrchestrator::new(uplink_settings),
            ap: Netbridge::new(ap_settings, dns_settings),
            nat: Arc::new(nat::NatManager::new()),
        }
    }

    /// Starts the dual-wifi flow: Uplink -> DHCP -> Routing -> NAT -> AP -> Dnsmasq
    pub async fn start(&mut self) -> Result<(), NetbridgeError> {
        info!("🔵 Starting Dual Wi-Fi Orchestration (Hotspot + External Wi-Fi)...");

        // 1. Access Point Phase (Ensures hotspot is always available for local management)
        if let Err(e) = self.ap.start().await {
            tracing::debug!("Dual-WiFi Failed at AP stage: {}", e);
            // Fail-closed cleanup
            let _ = self.nat.disable_nat();
            let _ = self.uplink.stop().await;
            return Err(e);
        }

        // 2. Uplink Phase (Connect, DHCP, Routing)
        // This is non-blocking and event-driven, allowing the AP to stay up even if uplink fails
        if let Err(e) = self.uplink.start().await {
            tracing::debug!("Dual-WiFi Failed at Uplink stage: {}", e);
            return Err(e);
        }

        // 3. Single event-driven NAT-recovery task — subscribes to the uplink watch channel.
        let nat_clone = Arc::clone(&self.nat);
        let monitor = self.uplink.get_monitor();
        let in_iface_clone = self.ap.settings.interface.clone();
        let out_iface_clone = self.uplink.settings.interface.clone();
        let client_isolation = self.ap.settings.client_isolation;

        tokio::spawn(async move {
            let interval = std::time::Duration::from_secs(5);
            let mut was_connected = false;

            loop {
                let state = monitor.lock().await.current_state();
                let is_connected = state == crate::netbridge::types::UplinkState::Connected;

                if was_connected && !is_connected {
                    tracing::info!(
                        "⚠️ Internet connection lost. Tearing down routing to protect the Hotspot."
                    );
                    let _ = nat_clone.disable_nat();
                    was_connected = false;
                } else if !was_connected && is_connected {
                    tracing::info!(
                        "🌍 Internet connection is active! Applying security and routing rules."
                    );
                    if let Err(e) =
                        nat_clone.enable_nat(&in_iface_clone, &out_iface_clone, client_isolation)
                    {
                        tracing::debug!("Failed to re-apply NAT after recovery: {}", e);
                    } else {
                        was_connected = true;
                    }
                }
                tokio::time::sleep(interval).await;
            }
        });

        info!("Dual Wi-Fi perfectly established with active NAT and Firewall isolation.");
        Ok(())
    }

    /// Safely shuts down the entire stack in reverse order
    pub async fn stop(&mut self) -> Result<(), NetbridgeError> {
        info!("Stopping Dual Wi-Fi Orchestrator...");

        // 1. Stop AP (dnsmasq, hostapd)
        let _ = self.ap.stop().await;

        // 2. Remove NAT & Firewall Rules (restore safety defaults)
        let _ = self.nat.disable_nat();

        // 3. Stop Uplink (Routing, DHCP, wpa_supplicant)
        let _ = self.uplink.stop().await;

        info!("Dual Wi-Fi cleanly stopped. Network secured.");
        Ok(())
    }
}
