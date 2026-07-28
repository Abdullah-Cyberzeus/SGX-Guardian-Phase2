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
use self::process::{ProcessRunner, ProcessStatus};
use tracing::{error, info};

use self::types::NetbridgeError;

/// Main Netbridge Orchestrator
pub struct Netbridge {
    settings: ApSettings,
    runner: Option<Arc<ProcessRunner>>,
    dnsmasq: dhcp_dns::DnsmasqOrchestrator,
    health_task: Option<tokio::task::JoinHandle<()>>,
}

impl Netbridge {
    /// Creates a new instance of the Netbridge orchestrator.
    pub fn new(settings: ApSettings, dnsmasq_settings: types::DnsmasqSettings) -> Self {
        Netbridge {
            settings,
            runner: None,
            dnsmasq: dhcp_dns::DnsmasqOrchestrator::new(dnsmasq_settings),
            health_task: None,
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
        // Ensure the AP interface is down and stale sockets removed so hostapd can bind nl80211 driver cleanly
        let _ = tokio::process::Command::new("ip")
            .args(["link", "set", "dev", &self.settings.interface, "down"])
            .output()
            .await;
        let ctrl_sock = format!("/var/run/hostapd/{}", self.settings.interface);
        let _ = std::fs::remove_file(ctrl_sock);

        // Initialize the asynchronous process runner with the newly generated config
        let config_path = "/tmp/netbridge/hostapd.conf".to_string();
        let runner = Arc::new(ProcessRunner::new("hostapd".to_string(), vec![config_path]));

        // 3. Start the process asynchronously
        info!("Starting hostapd process...");
        if let Err(e) = runner.start().await {
            error!("Failed to start hostapd process: {}", e);
            return Err(NetbridgeError::ProcessExecutionFailed(e.to_string()));
        }

        // Enable the true process lifecycle manager to automatically restart it on crash
        runner.clone().enable_auto_restart();

        // Keep the runner instance alive to manage the process lifetime
        self.runner = Some(runner.clone());

        if let Err(e) =
            wait_for_ap_ready(&self.settings.interface, &self.settings.ssid, &runner).await
        {
            if let Some(active_runner) = &self.runner {
                let _ = active_runner.stop().await;
            }
            self.runner = None;
            error!("hostapd failed to reach ready AP state: {}", e);
            return Err(e);
        }

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
        if let Err(error) = self.dnsmasq.start().await {
            let _ = runner.stop().await;
            self.runner = None;
            let _ = tokio::process::Command::new("ip")
                .args(["link", "set", "dev", &self.settings.interface, "down"])
                .output()
                .await;
            return Err(error);
        }

        let health_runner = runner;
        let health_interface = self.settings.interface.clone();
        let health_ssid = self.settings.ssid.clone();
        self.health_task = Some(tokio::spawn(async move {
            let mut consecutive_failures = 0u8;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;

                if health_runner.get_status() != ProcessStatus::Running {
                    consecutive_failures = 0;
                    continue;
                }

                if interface_has_ap_ssid(&health_interface, &health_ssid).await {
                    consecutive_failures = 0;
                    continue;
                }

                consecutive_failures = consecutive_failures.saturating_add(1);
                tracing::warn!(
                    "AP health check failed on {} ({}/3)",
                    health_interface,
                    consecutive_failures
                );
                if consecutive_failures >= 3 {
                    tracing::error!(
                        "AP state disappeared on {} while hostapd is alive; requesting daemon recovery.",
                        health_interface
                    );
                    let _ = health_runner.send_signal("TERM").await;
                    consecutive_failures = 0;
                }
            }
        }));

        Ok(())
    }

    /// Gracefully stops the AP
    pub async fn stop(&mut self) -> Result<(), NetbridgeError> {
        tracing::debug!("Stopping Netbridge orchestration flow...");
        if let Some(task) = self.health_task.take() {
            task.abort();
        }

        let dnsmasq_result = self.dnsmasq.stop().await;
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

        dnsmasq_result?;
        info!("🔴 Hotspot stopped successfully.");
        Ok(())
    }
}

impl Drop for Netbridge {
    fn drop(&mut self) {
        if let Some(task) = self.health_task.take() {
            task.abort();
        }
    }
}

use crate::netbridge::types::WifiClientSettings;
use std::sync::Arc;
use tokio::sync::Mutex;

fn parse_ipv4_octets(ip: &str) -> Option<[u8; 4]> {
    let mut parts = ip.split('.');
    Some([
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    ])
}

fn shares_subnet_24(lhs: &str, rhs: &str) -> bool {
    match (parse_ipv4_octets(lhs), parse_ipv4_octets(rhs)) {
        (Some(a), Some(b)) => a[..3] == b[..3],
        _ => false,
    }
}

fn hotspot_subnet_cidr(gateway_ip: &str) -> Option<String> {
    let octets = parse_ipv4_octets(gateway_ip)?;
    Some(format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]))
}

fn select_non_conflicting_dns_settings(
    current: &types::DnsmasqSettings,
    uplink_ipv4: &str,
) -> Option<types::DnsmasqSettings> {
    if !shares_subnet_24(&current.gateway_ip, uplink_ipv4) {
        return None;
    }

    let candidates = [
        ("10.42.0.1", "10.42.0.100", "10.42.0.254"),
        ("172.22.0.1", "172.22.0.100", "172.22.0.254"),
        ("192.168.250.1", "192.168.250.100", "192.168.250.254"),
    ];

    for (gateway_ip, range_start, range_end) in candidates {
        if !shares_subnet_24(gateway_ip, uplink_ipv4) {
            let mut updated = current.clone();
            updated.gateway_ip = gateway_ip.to_string();
            updated.dhcp_range_start = range_start.to_string();
            updated.dhcp_range_end = range_end.to_string();
            return Some(updated);
        }
    }

    None
}

async fn get_interface_ipv4(interface: &str) -> Option<String> {
    let output = tokio::process::Command::new("ip")
        .args(["-4", "addr", "show", "dev", interface])
        .output()
        .await
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("inet ") {
            let cidr = trimmed.split_whitespace().nth(1)?;
            return Some(cidr.split('/').next()?.to_string());
        }
    }

    None
}

async fn interface_has_ap_ssid(interface: &str, ssid: &str) -> bool {
    let output = match tokio::process::Command::new("iw").arg("dev").output().await {
        Ok(out) => out,
        Err(_) => return false,
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut in_target = false;
    let mut saw_ap_type = false;
    let mut saw_ssid = false;

    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(found_iface) = trimmed.strip_prefix("Interface ") {
            if in_target {
                return saw_ap_type && saw_ssid;
            }
            in_target = found_iface == interface;
            saw_ap_type = false;
            saw_ssid = false;
            continue;
        }

        if !in_target {
            continue;
        }

        if trimmed == "type AP" {
            saw_ap_type = true;
        } else if let Some(found_ssid) = trimmed.strip_prefix("ssid ") {
            saw_ssid = found_ssid == ssid;
        }
    }

    in_target && saw_ap_type && saw_ssid
}

async fn wait_for_ap_ready(
    interface: &str,
    ssid: &str,
    runner: &Arc<ProcessRunner>,
) -> Result<(), NetbridgeError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(12);
    let mut last_status = ProcessStatus::Starting;

    while std::time::Instant::now() < deadline {
        let status = runner.get_status();
        last_status = status.clone();

        if status == ProcessStatus::Running && interface_has_ap_ssid(interface, ssid).await {
            return Ok(());
        }

        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }

    Err(NetbridgeError::ProcessExecutionFailed(format!(
        "hostapd did not reach ready AP state on {} within 12s (last status: {:?})",
        interface, last_status
    )))
}

/// Uplink Orchestrator handling Station Mode (External Wi-Fi, DHCP, and Routing)
pub struct UplinkOrchestrator {
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
        if let Err(e) = bootstrapper.initialize_uplink_startup(&self.wifi_client.settings) {
            error!("Uplink bootstrap failed: {}", e);
            return Err(NetbridgeError::BootstrapFailed(e.to_string()));
        }

        // 1. Connect to Wi-Fi (Blocks until COMPLETED or timeout)
        self.wifi_client.connect().await?;

        // 2. Start DHCP Client to obtain IP
        if let Err(error) = self.dhcp_client.start().await {
            let _ = self.wifi_client.disconnect().await;
            return Err(error);
        }

        // 2.5 Disable Wi-Fi power saving on uplink to resolve packet loss and latency spikes
        info!(
            "Disabling Wi-Fi power saving on interface {} to stabilize connection...",
            &self.wifi_client.settings.interface
        );
        let _ = tokio::process::Command::new("iw")
            .args([
                "dev",
                &self.wifi_client.settings.interface,
                "set",
                "power_save",
                "off",
            ])
            .output()
            .await;

        // 3. Enable kernel IPv4 forwarding so AP clients can reach the uplink
        if let Err(error) = self.routing.enable_forwarding() {
            let _ = self.dhcp_client.stop().await;
            let _ = self.wifi_client.disconnect().await;
            return Err(error);
        }

        // 4. Start background uplink monitor (yielding lock between cycles)
        let monitor_clone = Arc::clone(&self.monitor);
        let dhcp_runner = self.dhcp_client.runner();
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
                        mon.trigger_reconnect(dhcp_runner.clone());
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

        let interface = self.wifi_client.settings.interface.clone();

        // 1. Stop Monitor before it can race with teardown or renew DHCP.
        if let Some(task) = self.monitor_task.take() {
            task.abort();
        }

        // 2. Disable forwarding
        let _ = self.routing.disable_forwarding();

        // 3. Stop DHCP
        let _ = self.dhcp_client.stop().await;

        // 4. Disconnect Wi-Fi
        let _ = self.wifi_client.disconnect().await;

        // 5. Flush interface and bring it down to prevent blackhole routes
        let _ = tokio::process::Command::new("ip")
            .args(["addr", "flush", "dev", &interface])
            .output()
            .await;

        let _ = tokio::process::Command::new("ip")
            .args(["link", "set", "dev", &interface, "down"])
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

impl Drop for UplinkOrchestrator {
    fn drop(&mut self) {
        if let Some(task) = self.monitor_task.take() {
            task.abort();
        }
    }
}

/// Dual Wi-Fi Orchestrator (AP + Uplink + NAT/Firewall)
/// Guarantees exact startup order and fail-closed safety.
pub struct DualWifiOrchestrator {
    uplink: UplinkOrchestrator,
    ap: Netbridge,
    nat: Arc<nat::NatManager>,
    nat_task: Option<tokio::task::JoinHandle<()>>,
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
            nat_task: None,
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
        if let Err(e) = self.uplink.start().await {
            tracing::debug!("Dual-WiFi Failed at Uplink stage: {}", e);
            let _ = self.ap.stop().await;
            return Err(e);
        }

        let in_iface_clone = self.ap.settings.interface.clone();
        let out_iface_clone = self.uplink.wifi_client.settings.interface.clone();
        let client_isolation = self.ap.settings.client_isolation;

        if let Some(uplink_ipv4) = get_interface_ipv4(&out_iface_clone).await {
            if let Some(updated_dns) =
                select_non_conflicting_dns_settings(&self.ap.dnsmasq.settings, &uplink_ipv4)
            {
                tracing::warn!(
                    "Hotspot subnet {} conflicts with uplink {} on {}. Restarting AP on {}.",
                    self.ap.dnsmasq.settings.gateway_ip,
                    uplink_ipv4,
                    out_iface_clone,
                    updated_dns.gateway_ip
                );
                if let Err(error) = self.ap.stop().await {
                    let _ = self.uplink.stop().await;
                    return Err(error);
                }
                self.ap.dnsmasq.settings = updated_dns;
                if let Err(error) = self.ap.start().await {
                    let _ = self.uplink.stop().await;
                    return Err(error);
                }
            }
        }

        let hotspot_cidr = match hotspot_subnet_cidr(&self.ap.dnsmasq.settings.gateway_ip) {
            Some(cidr) => cidr,
            None => {
                let _ = self.ap.stop().await;
                let _ = self.uplink.stop().await;
                return Err(NetbridgeError::ValidationFailed(format!(
                    "invalid hotspot gateway {}",
                    self.ap.dnsmasq.settings.gateway_ip
                )));
            }
        };
        if let Err(error) =
            routing::RoutingManager::configure_hotspot_uplink(&hotspot_cidr, &out_iface_clone)
        {
            routing::RoutingManager::remove_hotspot_uplink();
            let _ = self.ap.stop().await;
            let _ = self.uplink.stop().await;
            return Err(error);
        }

        if let Err(e) = self
            .nat
            .enable_nat(&in_iface_clone, &out_iface_clone, client_isolation)
        {
            routing::RoutingManager::remove_hotspot_uplink();
            let _ = self.ap.stop().await;
            let _ = self.uplink.stop().await;
            return Err(NetbridgeError::ProcessExecutionFailed(format!(
                "failed to apply hotspot NAT: {}",
                e
            )));
        }

        // 3. Single event-driven NAT-recovery task — subscribes to the uplink watch channel.
        let nat_clone = Arc::clone(&self.nat);
        let monitor = self.uplink.get_monitor();

        let task = tokio::spawn(async move {
            let interval = std::time::Duration::from_secs(5);
            let mut was_connected = true;

            loop {
                let state = monitor.lock().await.current_state();
                let is_connected = state == crate::netbridge::types::UplinkState::Connected;
                let is_disconnected = state == crate::netbridge::types::UplinkState::Disconnected;

                if was_connected && is_disconnected {
                    tracing::info!(
                        "⚠️ Physical Wi-Fi uplink disconnected. Preserving AP and NAT while Wi-Fi self-heals."
                    );
                } else if is_connected {
                    if !routing::RoutingManager::hotspot_uplink_is_configured(
                        &hotspot_cidr,
                        &out_iface_clone,
                    ) {
                        if let Err(error) = routing::RoutingManager::configure_hotspot_uplink(
                            &hotspot_cidr,
                            &out_iface_clone,
                        ) {
                            tracing::warn!(
                                "Failed to repair hotspot policy route via {}: {}",
                                out_iface_clone,
                                error
                            );
                        }
                    }

                    if !nat_clone.kernel_rules_active(&in_iface_clone, &out_iface_clone) {
                        tracing::info!(
                            "🌍 Restoring missing hotspot NAT/security rules via {}.",
                            out_iface_clone
                        );
                        if let Err(error) = nat_clone.enable_nat(
                            &in_iface_clone,
                            &out_iface_clone,
                            client_isolation,
                        ) {
                            tracing::warn!("Failed to re-apply NAT after recovery: {}", error);
                            was_connected = false;
                        } else {
                            was_connected = true;
                        }
                    } else {
                        was_connected = true;
                    }
                } else if was_connected && !is_connected {
                    tracing::debug!(
                        "Uplink state is {:?}, preserving NAT rules to allow self-healing.",
                        state
                    );
                }
                tokio::time::sleep(interval).await;
            }
        });
        self.nat_task = Some(task);

        info!("Dual Wi-Fi perfectly established with active NAT and Firewall isolation.");
        Ok(())
    }

    /// Safely shuts down the entire stack in reverse order
    pub async fn stop(&mut self) -> Result<(), NetbridgeError> {
        info!("Stopping Dual Wi-Fi Orchestrator...");

        // 1. Stop monitor before it can race with firewall teardown.
        if let Some(task) = self.nat_task.take() {
            task.abort();
        }

        // 2. Stop AP (dnsmasq, hostapd)
        let _ = self.ap.stop().await;

        // 3. Disable NAT / Firewall Rules (restore safety defaults)
        let _ = self.nat.disable_nat();
        routing::RoutingManager::remove_hotspot_uplink();

        // 4. Stop Uplink (Routing, DHCP, wpa_supplicant)
        let _ = self.uplink.stop().await;

        info!("Dual Wi-Fi cleanly stopped. Network secured.");
        Ok(())
    }
}

impl Drop for DualWifiOrchestrator {
    fn drop(&mut self) {
        if let Some(task) = self.nat_task.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{hotspot_subnet_cidr, select_non_conflicting_dns_settings, shares_subnet_24};
    use crate::netbridge::types::DnsmasqSettings;

    #[test]
    fn detects_matching_subnet_prefix() {
        assert!(shares_subnet_24("192.168.200.1", "192.168.200.29"));
        assert!(!shares_subnet_24("192.168.200.1", "192.168.201.29"));
    }

    #[test]
    fn picks_safe_hotspot_subnet_when_uplink_overlaps_default_lan() {
        let current = DnsmasqSettings::default();
        let updated = select_non_conflicting_dns_settings(&current, "192.168.200.29")
            .expect("overlap should trigger fallback subnet");

        assert_eq!(updated.gateway_ip, "10.42.0.1");
        assert_eq!(updated.dhcp_range_start, "10.42.0.100");
        assert_eq!(updated.dhcp_range_end, "10.42.0.254");
    }

    #[test]
    fn keeps_existing_hotspot_subnet_when_no_overlap_exists() {
        let current = DnsmasqSettings::default();
        let updated = select_non_conflicting_dns_settings(&current, "192.168.50.29");

        assert!(updated.is_none());
    }

    #[test]
    fn derives_hotspot_subnet_from_gateway() {
        assert_eq!(
            hotspot_subnet_cidr("192.168.200.1").as_deref(),
            Some("192.168.200.0/24")
        );
    }
}
