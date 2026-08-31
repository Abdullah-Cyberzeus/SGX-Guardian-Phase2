use crate::netbridge::process::ProcessRunner;
use crate::netbridge::types::UplinkState;
use std::sync::Arc;
use tokio::process::Command;

/// Number of consecutive failed health-checks required before we declare uplink loss.
/// A value of 3 means transient disruptions (e.g. EAPOL-induced deauth or short DNS pauses)
/// must persist across 3 consecutive checks (30s) before state flips to loss.
const LOSS_DEBOUNCE_THRESHOLD: u8 = 3;

#[derive(Debug, PartialEq, Eq)]
pub enum ReachabilityStatus {
    InternetAvailable,
    NoInternet,
    NetworkNotReady,
}

pub struct UplinkMonitor {
    interface: String,
    state: UplinkState,
    /// Counts consecutive health-check failures to debounce transient disruptions.
    consecutive_failures: u8,
    last_reconnect_attempt: Option<std::time::Instant>,
}

impl UplinkMonitor {
    pub fn new(interface: String) -> Self {
        UplinkMonitor {
            interface,
            state: UplinkState::Unknown,
            consecutive_failures: 0,
            last_reconnect_attempt: None,
        }
    }

    /// Checks if wpa_supplicant is currently in the middle of a reconnect attempt
    /// (SCANNING, AUTHENTICATING, ASSOCIATING, or 4WAY_HANDSHAKE). When true,
    /// callers should skip NAT teardown — the driver is self-healing.
    pub async fn is_interface_reconnecting(&self) -> bool {
        let output = tokio::process::Command::new("wpa_cli")
            .arg("-i")
            .arg(&self.interface)
            .arg("status")
            .output()
            .await;

        match output {
            Ok(out) => {
                let s = std::str::from_utf8(&out.stdout).unwrap_or("");
                // Any of these states means wpa_supplicant is actively trying to reconnect.
                s.contains("wpa_state=SCANNING")
                    || s.contains("wpa_state=AUTHENTICATING")
                    || s.contains("wpa_state=ASSOCIATING")
                    || s.contains("wpa_state=ASSOCIATED")
                    || s.contains("wpa_state=4WAY_HANDSHAKE")
                    || s.contains("wpa_state=GROUP_HANDSHAKE")
            }
            Err(_) => false,
        }
    }

    /// Checks if the interface is physically/logically connected (link level)
    pub async fn check_link_connected(&self) -> bool {
        let output = Command::new("iw")
            .arg("dev")
            .arg(&self.interface)
            .arg("link")
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                let status_str = std::str::from_utf8(&out.stdout).unwrap_or("");
                status_str.contains("Connected to ")
            }
            _ => false,
        }
    }

    /// Checks internet reachability by attempting a TCP connection to well-known addresses.
    /// This is far more reliable than ICMP ping when the uplink is behind a NAT gateway
    /// (e.g. Windows Mobile Hotspot, shared Wi-Fi) that blocks ICMP forwarding.
    /// Checks internet reachability by attempting ICMP ping and socket checks bound to the uplink interface.
    pub async fn check_internet_reachability(&self) -> ReachabilityStatus {
        // First verify the interface is actually UP with an IPv4 address assigned
        let addr_out = Command::new("ip")
            .args(["-4", "addr", "show", "dev", &self.interface])
            .output()
            .await;

        let has_ip = match addr_out {
            Ok(out) => String::from_utf8_lossy(&out.stdout).contains("inet "),
            Err(_) => false,
        };

        if !has_ip {
            tracing::debug!(
                "Interface {} has no IPv4 address assigned yet.",
                self.interface
            );
            return ReachabilityStatus::NetworkNotReady;
        }

        // Ensure default route exists for this interface
        crate::netbridge::dhcp_client::DhcpClientOrchestrator::ensure_default_route_and_dns(
            &self.interface,
        )
        .await;

        // 1. Try ICMP ping to public endpoints bound to this specific interface.
        // -I <iface> is required: without it, Linux routes pings via the kernel default route
        // (e.g. eth0), not wlan0, giving a false healthy result when wlan0 is actually dead.
        let ping_targets = ["8.8.8.8", "1.1.1.1", "1.0.0.1"];
        let mut icmp_success = false;

        for target in &ping_targets {
            let out = Command::new("ping")
                .args(["-4", "-c", "1", "-W", "2", "-I", &self.interface, target])
                .output()
                .await;

            if let Ok(o) = out {
                if o.status.success() {
                    icmp_success = true;
                    tracing::debug!(
                        "ICMP internet ping succeeded to {} via {}",
                        target,
                        self.interface
                    );
                    break;
                }
            }
        }

        // 2. Try TCP connectivity to well-known endpoints as fallback if ICMP is blocked
        let mut tcp_success = false;
        if !icmp_success {
            let tcp_targets = [
                ("1.1.1.1", 53u16),
                ("8.8.8.8", 53u16),
                ("1.1.1.1", 80u16),
                ("8.8.8.8", 80u16),
            ];
            for (host, port) in &tcp_targets {
                if self.try_tcp_connect(host, *port).await {
                    tcp_success = true;
                    tracing::debug!(
                        "TCP connectivity confirmed via {}:{} on {}",
                        host,
                        port,
                        self.interface
                    );
                    break;
                }
            }
        }

        let ip_reachability_ok = icmp_success || tcp_success;

        // 3. Test DNS resolution bound to IPv4 on this interface
        let mut dns_success = false;
        if ip_reachability_ok {
            let dns_ping = Command::new("ping")
                .args([
                    "-4",
                    "-c",
                    "1",
                    "-W",
                    "3",
                    "-I",
                    &self.interface,
                    "google.com",
                ])
                .output()
                .await;

            if let Ok(o) = dns_ping {
                if o.status.success() {
                    dns_success = true;
                }
            }

            if !dns_success {
                // Try writing fallback resolvers. Do NOT mark dns_success = true here;
                // IP-layer reachability is confirmed, which is sufficient for InternetAvailable.
                // DNS will be re-evaluated on the next health-check cycle.
                crate::netbridge::dhcp_client::DhcpClientOrchestrator::ensure_fallback_dns().await;
                tracing::debug!("DNS resolution failed on {}; fallback resolvers written, will re-check next cycle.", self.interface);
            }
        } else {
            // Direct public IP check failed — fall back to local gateway ping as last-chance check
            if self.check_gateway_reachable().await {
                tracing::warn!(
                    target: "sgx_guardian_client::netbridge",
                    "Gateway is reachable on {}, but public internet checks failed.",
                    self.interface
                );
            }
        }

        let is_connected = ip_reachability_ok || dns_success;

        tracing::debug!(
            "Internet check on {}: icmp_ok={}, tcp_ok={}, dns_ok={}, connected={}",
            self.interface,
            icmp_success,
            tcp_success,
            dns_success,
            is_connected
        );

        if is_connected {
            ReachabilityStatus::InternetAvailable
        } else {
            ReachabilityStatus::NoInternet
        }
    }

    /// Attempts a raw TCP connection to the given host:port with a 3‑second timeout.
    /// The socket is explicitly bound to the IPv4 address of the monitored interface so the
    /// probe follows the same uplink that the rest of the health‑check logic uses.
    async fn try_tcp_connect(&self, host: &str, port: u16) -> bool {
        use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
        use tokio::net::TcpSocket;
        use tokio::time::{timeout, Duration};

        let dest = match format!("{}:{}", host, port).to_socket_addrs() {
            Ok(mut iter) => iter.find(|a| a.is_ipv4()),
            Err(_) => None,
        };

        let dest = match dest {
            Some(d) => d,
            None => return false,
        };

        let src_ip = match self.get_interface_ipv4().await {
            Some(ip) => ip,
            None => return false,
        };

        let socket = match dest {
            SocketAddr::V4(_) => TcpSocket::new_v4(),
            SocketAddr::V6(_) => TcpSocket::new_v6(),
        };

        let socket = match socket {
            Ok(s) => s,
            Err(_) => return false,
        };

        if socket.bind(SocketAddr::new(IpAddr::V4(src_ip), 0)).is_err() {
            return false;
        }

        matches!(
            timeout(Duration::from_secs(3), socket.connect(dest)).await,
            Ok(Ok(_))
        )
    }

    // Helper: fetch the IPv4 address assigned to the monitored interface.
    async fn get_interface_ipv4(&self) -> Option<std::net::Ipv4Addr> {
        let out = Command::new("ip")
            .args(["-4", "addr", "show", "dev", &self.interface])
            .output()
            .await
            .ok()?;
        let txt = String::from_utf8_lossy(&out.stdout);
        for line in txt.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("inet ") {
                // Example: "inet 192.168.200.23/24 brd 192.168.200.255 scope global wlan0"
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if let Some(cidr) = parts.get(1) {
                    let ip_str = cidr.split('/').next()?;
                    return ip_str.parse().ok();
                }
            }
        }
        None
    }

    /// Checks if the local gateway IP is pingable over this interface.
    pub async fn check_gateway_reachable(&self) -> bool {
        let gw_ip = match crate::netbridge::dhcp_client::DhcpClientOrchestrator::get_gateway_ip(
            &self.interface,
        )
        .await
        {
            Some(ip) => ip,
            None => return false,
        };

        let out = Command::new("ping")
            .arg("-4")
            .arg("-c")
            .arg("2")
            .arg("-W")
            .arg("2")
            .arg("-I")
            .arg(&self.interface)
            .arg(&gw_ip)
            .output()
            .await;

        if let Ok(o) = out {
            o.status.success()
        } else {
            false
        }
    }

    /// Evaluates the overall health of the uplink and updates the internal state.
    /// Uses a debounce counter: transient failures (e.g. EAPOL handshake deauth) must
    /// persist for LOSS_DEBOUNCE_THRESHOLD consecutive checks before state flips to loss.
    pub async fn evaluate_health(&mut self) -> UplinkState {
        let link_up = self.check_link_connected().await;

        let reachability = if link_up {
            self.check_internet_reachability().await
        } else {
            ReachabilityStatus::NetworkNotReady
        };

        if reachability == ReachabilityStatus::InternetAvailable {
            // Full recovery — reset debounce and move to Connected
            self.consecutive_failures = 0;
            self.state = UplinkState::Connected;
            return self.state.clone();
        }

        // Something is wrong — check if wpa_supplicant is already mid-reconnect
        if self.is_interface_reconnecting().await {
            // Give a transient reconnect time to recover, but do not hold the previous state
            // forever if the driver remains stuck in SCANNING or a handshake state.
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            tracing::debug!(
                "Interface {} is mid-reconnect (failure {}/{}); holding uplink state at {:?}.",
                self.interface,
                self.consecutive_failures,
                LOSS_DEBOUNCE_THRESHOLD,
                self.state
            );
            if self.consecutive_failures < LOSS_DEBOUNCE_THRESHOLD {
                return self.state.clone();
            }
        } else {
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        }

        if self.consecutive_failures >= LOSS_DEBOUNCE_THRESHOLD {
            // Confirmed loss after N consecutive failures
            self.state = if !link_up {
                UplinkState::Disconnected
            } else {
                UplinkState::NoInternet
            };
        }
        // If below threshold, state is unchanged — caller won't see a loss event yet
        self.state.clone()
    }

    /// Exposes the current known health state
    pub fn current_state(&self) -> UplinkState {
        self.state.clone()
    }

    /// Called when the monitor detects a confirmed uplink loss or NoInternet state.
    /// Since wpa_supplicant reconnects automatically, the main thing we need to do
    /// is force the DHCP client to renew its lease and rewrite the kernel routing table
    /// (which often gets wiped when the link drops).
    pub fn trigger_reconnect(&mut self, dhcp_runner: Option<Arc<ProcessRunner>>) {
        let now = std::time::Instant::now();
        if self
            .last_reconnect_attempt
            .is_some_and(|last| now.duration_since(last) < std::time::Duration::from_secs(30))
        {
            return;
        }
        self.last_reconnect_attempt = Some(now);

        let interface = self.interface.clone();
        tokio::spawn(async move {
            // Check wpa_supplicant association state before forcing a DHCP renew.
            // If wpa_state=COMPLETED, the Wi-Fi link is still alive — only internet routing
            // is broken (e.g. DFS channel pause). A DHCP renew is unnecessary and would
            // cause an IP address change. Let it recover on its own.
            let output = tokio::process::Command::new("wpa_cli")
                .arg("-i")
                .arg(&interface)
                .arg("status")
                .output()
                .await;

            let wpa_connected = match output {
                Ok(o) => {
                    let s = std::str::from_utf8(&o.stdout).unwrap_or("");
                    s.contains("wpa_state=COMPLETED")
                }
                Err(_) => false,
            };

            if wpa_connected {
                // Renew only the DHCP client owned by this orchestrator. A global killall
                // can hit eth0's DHCP client and make management SSH unreachable.
                if let Some(runner) = dhcp_runner {
                    tracing::info!(
                        "Uplink {} is associated but unhealthy; renewing its owned DHCP lease.",
                        interface
                    );
                    if let Err(error) = runner.send_signal("USR1").await {
                        tracing::warn!("Failed to renew DHCP on {}: {}", interface, error);
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    crate::netbridge::dhcp_client::DhcpClientOrchestrator::ensure_default_route_and_dns(
                        &interface,
                    )
                    .await;
                }
            } else {
                // wpa_supplicant already reconnects automatically. Renewing DHCP before
                // association exists only creates another failure/reset loop.
                tracing::debug!(
                    "Uplink {} is not associated; waiting for wpa_supplicant before DHCP renewal.",
                    interface
                );
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An interface name guaranteed not to exist on any host. Every helper
    /// below queries the kernel/wpa_supplicant control socket about this
    /// specific interface only (never a real one), so `ip`/`iw`/`wpa_cli`
    /// deterministically report "not found" without any real network I/O,
    /// without touching real routing/firewall/Wi-Fi state, and without root.
    /// This is the "bypass the actual reachability check" approach the task
    /// calls for in place of a mocked process seam (none exists here — these
    /// one-off `Command` calls, unlike `ProcessRunner`, have no injectable
    /// runner). `try_tcp_connect` is the one helper intentionally left
    /// untested: it opens a real outbound TCP socket and is only reachable
    /// through `check_internet_reachability`'s fallback path, which this
    /// suite never enters (see below).
    const BOGUS_IFACE: &str = "sgxtest-bogus0";

    #[test]
    fn reachability_status_equality() {
        assert_eq!(
            ReachabilityStatus::InternetAvailable,
            ReachabilityStatus::InternetAvailable
        );
        assert_ne!(
            ReachabilityStatus::InternetAvailable,
            ReachabilityStatus::NoInternet
        );
        assert_ne!(
            ReachabilityStatus::NoInternet,
            ReachabilityStatus::NetworkNotReady
        );
    }

    #[test]
    fn new_monitor_starts_unknown_with_no_failures() {
        let monitor = UplinkMonitor::new(BOGUS_IFACE.to_string());
        assert_eq!(monitor.interface, BOGUS_IFACE);
        assert_eq!(monitor.state, UplinkState::Unknown);
        assert_eq!(monitor.consecutive_failures, 0);
        assert!(monitor.last_reconnect_attempt.is_none());
        assert_eq!(monitor.current_state(), UplinkState::Unknown);
    }

    #[tokio::test]
    async fn check_link_connected_false_for_missing_interface() {
        let monitor = UplinkMonitor::new(BOGUS_IFACE.to_string());
        assert!(!monitor.check_link_connected().await);
    }

    #[tokio::test]
    async fn check_internet_reachability_reports_network_not_ready_without_ip() {
        // With no IPv4 address on the (nonexistent) interface, the function
        // must short-circuit to NetworkNotReady before attempting any ping,
        // TCP probe, or DNS/route mutation.
        let monitor = UplinkMonitor::new(BOGUS_IFACE.to_string());
        let status = monitor.check_internet_reachability().await;
        assert_eq!(status, ReachabilityStatus::NetworkNotReady);
    }

    #[tokio::test]
    async fn is_interface_reconnecting_false_for_missing_interface() {
        let monitor = UplinkMonitor::new(BOGUS_IFACE.to_string());
        assert!(!monitor.is_interface_reconnecting().await);
    }

    #[tokio::test]
    async fn check_gateway_reachable_false_without_a_route() {
        let monitor = UplinkMonitor::new(BOGUS_IFACE.to_string());
        assert!(!monitor.check_gateway_reachable().await);
    }

    #[tokio::test]
    async fn get_interface_ipv4_none_for_missing_interface() {
        let monitor = UplinkMonitor::new(BOGUS_IFACE.to_string());
        assert!(monitor.get_interface_ipv4().await.is_none());
    }

    #[tokio::test]
    async fn evaluate_health_debounces_before_declaring_loss() {
        let mut monitor = UplinkMonitor::new(BOGUS_IFACE.to_string());

        // LOSS_DEBOUNCE_THRESHOLD == 3: the first two consecutive failures
        // must hold the prior (Unknown) state rather than flipping to a loss
        // state immediately.
        let first = monitor.evaluate_health().await;
        assert_eq!(first, UplinkState::Unknown);
        assert_eq!(monitor.consecutive_failures, 1);

        let second = monitor.evaluate_health().await;
        assert_eq!(second, UplinkState::Unknown);
        assert_eq!(monitor.consecutive_failures, 2);

        // The third consecutive failure crosses the threshold. Since the
        // link itself never came up, the terminal state is Disconnected
        // (as opposed to NoInternet, which requires link_up == true).
        let third = monitor.evaluate_health().await;
        assert_eq!(third, UplinkState::Disconnected);
        assert_eq!(monitor.consecutive_failures, 3);
        assert_eq!(monitor.current_state(), UplinkState::Disconnected);
    }

    #[tokio::test]
    async fn evaluate_health_honors_a_preexisting_failure_count() {
        // Seeds the debounce counter as if two prior checks already failed
        // (e.g. resumed mid-cycle) and confirms the very next failure is the
        // one that crosses LOSS_DEBOUNCE_THRESHOLD and flips state.
        // Note: the InternetAvailable recovery branch (resets
        // consecutive_failures to 0, state to Connected) cannot be exercised
        // without a real reachable uplink, so it is intentionally left
        // uncovered here.
        let mut monitor = UplinkMonitor::new(BOGUS_IFACE.to_string());
        monitor.consecutive_failures = 2;
        monitor.state = UplinkState::Unknown;

        let result = monitor.evaluate_health().await;
        assert_eq!(result, UplinkState::Disconnected);
        assert_eq!(monitor.consecutive_failures, 3);
    }

    #[tokio::test]
    async fn trigger_reconnect_debounces_within_30_seconds() {
        let mut monitor = UplinkMonitor::new(BOGUS_IFACE.to_string());
        assert!(monitor.last_reconnect_attempt.is_none());

        monitor.trigger_reconnect(None);
        let first_attempt = monitor.last_reconnect_attempt;
        assert!(first_attempt.is_some());

        // A second call within the 30s debounce window must not update the
        // recorded timestamp (and, per the implementation, returns before
        // spawning another reconnect task at all).
        monitor.trigger_reconnect(None);
        assert_eq!(monitor.last_reconnect_attempt, first_attempt);
    }
}
