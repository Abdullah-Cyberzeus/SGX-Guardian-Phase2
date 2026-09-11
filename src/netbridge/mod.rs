pub mod backend;
pub mod bootstrap;
pub mod config;
pub mod dhcp_dns;
pub mod leases;
pub mod nat;
pub mod network_manager;
pub mod process;
pub mod routing;
pub mod types;
pub mod validator;

use self::bootstrap::{BootstrapOptions, Bootstrapper};
use self::config::ApSettings;
use self::process::{ProcessRunner, ProcessStatus};
use tracing::{error, info};

use self::types::NetbridgeError;

/// Main Netbridge Orchestrator
pub struct Netbridge {
    settings: ApSettings,
    runner: Option<Arc<ProcessRunner>>,
    pub(crate) dnsmasq: dhcp_dns::DnsmasqOrchestrator,
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

use std::sync::Arc;

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

pub(crate) fn hotspot_subnet_cidr(gateway_ip: &str) -> Option<String> {
    let octets = parse_ipv4_octets(gateway_ip)?;
    Some(format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]))
}

pub(crate) fn select_non_conflicting_dns_settings(
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

#[cfg(test)]
mod tests {
    use super::{
        hotspot_subnet_cidr, interface_has_ap_ssid, parse_ipv4_octets,
        select_non_conflicting_dns_settings, shares_subnet_24,
    };
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

    #[test]
    fn parses_well_formed_ipv4_octets() {
        assert_eq!(parse_ipv4_octets("192.168.1.5"), Some([192, 168, 1, 5]));
        assert_eq!(parse_ipv4_octets("0.0.0.0"), Some([0, 0, 0, 0]));
    }

    #[test]
    fn rejects_malformed_ipv4_octets() {
        assert_eq!(parse_ipv4_octets("192.168.1"), None);
        assert_eq!(parse_ipv4_octets("192.168.1.abc"), None);
        assert_eq!(parse_ipv4_octets("300.1.1.1"), None);
        assert_eq!(parse_ipv4_octets(""), None);
    }

    #[test]
    fn subnet_sharing_is_false_for_unparsable_addresses() {
        assert!(!shares_subnet_24("not-an-ip", "192.168.1.5"));
        assert!(!shares_subnet_24("192.168.1.5", "not-an-ip"));
        assert!(!shares_subnet_24("not-an-ip", "also-not-an-ip"));
    }

    #[test]
    fn hotspot_subnet_cidr_rejects_invalid_gateway() {
        assert!(hotspot_subnet_cidr("not-an-ip").is_none());
        assert!(hotspot_subnet_cidr("10.0.0").is_none());
    }

    #[test]
    fn selects_second_fallback_candidate_when_first_also_conflicts_with_uplink() {
        let mut current = DnsmasqSettings::default();
        current.gateway_ip = "10.42.0.1".to_string();

        let updated = select_non_conflicting_dns_settings(&current, "10.42.0.77")
            .expect("overlap with current gateway should trigger fallback search");

        // The first fallback candidate (10.42.0.1) shares a /24 with the uplink,
        // so selection must skip to the second candidate (172.22.0.1).
        assert_eq!(updated.gateway_ip, "172.22.0.1");
        assert_eq!(updated.dhcp_range_start, "172.22.0.100");
        assert_eq!(updated.dhcp_range_end, "172.22.0.254");
    }

    #[tokio::test]
    async fn interface_has_ap_ssid_returns_false_when_iw_is_not_installed() {
        // `iw` is genuinely absent from this sandbox, so this deterministically
        // exercises the "command failed to spawn" branch.
        assert!(
            which::which("iw").is_err(),
            "this test assumes iw is not installed"
        );
        assert!(!interface_has_ap_ssid("lo", "any-ssid").await);
    }
}
