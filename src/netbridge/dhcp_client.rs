use crate::netbridge::process::ProcessRunner;
use crate::netbridge::types::NetbridgeError;
use std::path::Path;
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

        // Never kill every udhcpc instance: eth0 may use one for the management path.
        // Only remove a stale client that was bound to this orchestrated Wi-Fi interface.
        Self::terminate_stale_clients(&self.interface).await;

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

        // Advertise the node-specific label so a router whose local DNS
        // domain is `guardian` automatically publishes nodea.guardian, etc.
        let lan_hostname = std::env::var("SGX_LAN_HOSTNAME")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "sgx-guardian".to_string());
        args.push("-x".to_string());
        args.push(format!("hostname:{}", lan_hostname));

        // Specify BusyBox default script if available
        if std::path::Path::new("/usr/share/udhcpc/default.script").exists() {
            args.push("-s".to_string());
            args.push("/usr/share/udhcpc/default.script".to_string());
        } else if std::path::Path::new("/etc/udhcpc.user").exists() {
            args.push("-s".to_string());
            args.push("/etc/udhcpc.user".to_string());
        }

        let runner = Arc::new(ProcessRunner::new("udhcpc".to_string(), args));

        if let Err(e) = runner.start().await {
            error!("Failed to start udhcpc process: {}", e);
            return Err(NetbridgeError::ProcessExecutionFailed(e.to_string()));
        }

        // Enable the true process lifecycle manager
        runner.clone().enable_auto_restart();

        self.runner = Some(runner.clone());

        // Wait for DHCP server to assign an IP address
        if let Err(error) = self.wait_for_ip(15).await {
            let _ = runner.stop().await;
            self.runner = None;
            return Err(error);
        }

        tracing::debug!("DHCP client successfully started and IP assigned.");

        Ok(())
    }

    async fn terminate_stale_clients(interface: &str) {
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return;
        };
        let current_pid = std::process::id();
        let mut stale_pids = Vec::new();

        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            if pid == current_pid {
                continue;
            }

            let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) else {
                continue;
            };
            let args: Vec<&str> = cmdline
                .split(|byte| *byte == 0)
                .filter_map(|arg| std::str::from_utf8(arg).ok())
                .filter(|arg| !arg.is_empty())
                .collect();
            let is_udhcpc = args.iter().take(2).any(|arg| {
                Path::new(arg)
                    .file_name()
                    .is_some_and(|name| name == "udhcpc")
            });
            let matches_interface = args
                .windows(2)
                .any(|pair| pair[0] == "-i" && pair[1] == interface);

            if is_udhcpc && matches_interface {
                stale_pids.push(pid);
            }
        }

        for pid in &stale_pids {
            tracing::warn!(
                "Stopping stale udhcpc pid {} bound to {} before startup.",
                pid,
                interface
            );
            let _ = Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .output()
                .await;
        }

        if !stale_pids.is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        }
        for pid in stale_pids {
            if Path::new(&format!("/proc/{}", pid)).exists() {
                let _ = Command::new("kill")
                    .args(["-KILL", &pid.to_string()])
                    .output()
                    .await;
            }
        }
    }

    /// Polls until the interface receives an IPv4 address from DHCP.
    pub async fn wait_for_ip(&self, timeout_secs: u64) -> Result<(), NetbridgeError> {
        tracing::info!("Waiting for DHCP IP assignment on {}...", self.interface);
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_secs);

        while start.elapsed() < timeout {
            if self.is_network_ready().await {
                tracing::info!("✅ DHCP IP assigned on {}.", self.interface);
                Self::ensure_default_route_and_dns(&self.interface).await;
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        let err_msg = format!(
            "DHCP IP assignment timed out after {}s on {}",
            timeout_secs, self.interface
        );
        tracing::error!("{}", err_msg);
        Err(NetbridgeError::ProcessExecutionFailed(err_msg))
    }

    /// Extracts the gateway IP for the specified interface from the system routing table.
    pub async fn get_gateway_ip(interface: &str) -> Option<String> {
        let route_out = Command::new("ip")
            .args(["-4", "route", "show", "dev", interface])
            .output()
            .await
            .ok()?;

        let route_str = String::from_utf8_lossy(&route_out.stdout);
        for line in route_str.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(pos) = parts.iter().position(|&x| x == "via") {
                if pos + 1 < parts.len() {
                    return Some(parts[pos + 1].to_string());
                }
            }
        }

        // Fallback: Infer .1 from interface IPv4 address
        let addr_out = Command::new("ip")
            .args(["-4", "addr", "show", "dev", interface])
            .output()
            .await
            .ok()?;
        let addr_str = String::from_utf8_lossy(&addr_out.stdout);
        if let Some(pos) = addr_str.find("inet ") {
            let sub = &addr_str[pos + 5..];
            if let Some(ip_cidr) = sub.split_whitespace().next() {
                let ip_part = ip_cidr.split('/').next().unwrap_or("");
                let octets: Vec<&str> = ip_part.split('.').collect();
                if octets.len() == 4 {
                    return Some(format!("{}.{}.{}.1", octets[0], octets[1], octets[2]));
                }
            }
        }

        None
    }

    /// Ensures that a default route exists for the uplink interface and
    /// that /etc/resolv.conf contains working DNS servers.
    pub async fn ensure_default_route_and_dns(interface: &str) {
        // 1. Ensure a default route exists via this specific interface.
        // Uses the interface-scoped check in RoutingManager so we never
        // overwrite a system-wide route from a different interface.
        crate::netbridge::routing::RoutingManager::ensure_default_route_for_interface(interface);

        // 2. Ensure /etc/resolv.conf contains active nameservers
        Self::ensure_fallback_dns().await;
    }

    /// Ensures /etc/resolv.conf contains fallback DNS servers if missing or empty.
    pub async fn ensure_fallback_dns() {
        let dns_servers = ["8.8.8.8", "1.1.1.1"];
        if let Ok(content) = tokio::fs::read_to_string("/etc/resolv.conf").await {
            let has_dns = dns_servers.iter().any(|dns| content.contains(dns));
            if !has_dns {
                tracing::info!(target: "sgx_guardian_client::netbridge", "Ensuring fallback DNS servers (8.8.8.8, 1.1.1.1) in /etc/resolv.conf...");
                let dns_config = format!(
                    "{}\nnameserver 8.8.8.8\nnameserver 1.1.1.1\n",
                    content.trim()
                );
                let _ = tokio::fs::write("/etc/resolv.conf", dns_config).await;
            }
        } else {
            let dns_config = "nameserver 8.8.8.8\nnameserver 1.1.1.1\n";
            let _ = tokio::fs::write("/etc/resolv.conf", dns_config).await;
        }
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

    /// Returns the runner for interface-scoped lease renewals.
    pub fn runner(&self) -> Option<Arc<ProcessRunner>> {
        self.runner.clone()
    }

    /// Stops the udhcpc process.
    pub async fn stop(&mut self) -> Result<(), NetbridgeError> {
        tracing::debug!("Stopping DHCP client (udhcpc)...");
        // Take the runner out first so the auto-restart watcher loses its reference
        // and cannot race to restart a process we are intentionally killing.
        if let Some(runner) = self.runner.take() {
            if let Err(e) = runner.stop().await {
                error!("Failed to stop udhcpc process: {}", e);
                return Err(NetbridgeError::ProcessExecutionFailed(e.to_string()));
            }
        }
        tracing::debug!("DHCP client stopped successfully.");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An interface name guaranteed not to exist on the host. Read-only
    /// queries against it (`ip addr`, `ip route`, `/sys/class/net/.../address`,
    /// `/proc` scans) deterministically come back empty/negative on every
    /// platform, without any real network I/O and without touching real
    /// routing/DHCP/system-service state.
    const BOGUS_IFACE: &str = "sgxtest-bogus0";

    // `start()`/`connect()`-style methods that spawn a real `udhcpc` process
    // via `ProcessRunner`, and `ensure_default_route_and_dns` /
    // `ensure_fallback_dns` (which mutate the real routing table and
    // /etc/resolv.conf with no injectable path), are intentionally left
    // uncovered: there is no seam to redirect them to a fake binary or a
    // temp file, and exercising them for real would violate the "no real
    // process/network/system-state mutation" isolation rules.

    #[test]
    fn new_orchestrator_has_no_runner() {
        let orchestrator = DhcpClientOrchestrator::new(BOGUS_IFACE.to_string());
        assert_eq!(orchestrator.interface, BOGUS_IFACE);
        assert!(orchestrator.runner.is_none());
        assert!(orchestrator.runner().is_none());
    }

    #[tokio::test]
    async fn stop_without_a_running_process_is_a_noop() {
        let mut orchestrator = DhcpClientOrchestrator::new(BOGUS_IFACE.to_string());
        assert!(orchestrator.stop().await.is_ok());
        assert!(orchestrator.runner.is_none());
    }

    #[tokio::test]
    async fn is_network_ready_false_for_missing_interface() {
        let orchestrator = DhcpClientOrchestrator::new(BOGUS_IFACE.to_string());
        assert!(!orchestrator.is_network_ready().await);
    }

    #[tokio::test]
    async fn wait_for_ip_times_out_immediately_with_zero_budget() {
        // timeout_secs = 0 means the elapsed-time check is already false the
        // instant it is evaluated, so the loop body (and therefore
        // is_network_ready / ensure_default_route_and_dns) never runs at
        // all — this deterministically exercises the timeout error path
        // with zero real command invocations.
        let orchestrator = DhcpClientOrchestrator::new(BOGUS_IFACE.to_string());
        let result = orchestrator.wait_for_ip(0).await;
        match result {
            Err(NetbridgeError::ProcessExecutionFailed(msg)) => {
                assert!(msg.contains("timed out"), "unexpected message: {msg}");
                assert!(msg.contains(BOGUS_IFACE));
            }
            other => panic!("expected ProcessExecutionFailed(..timed out..), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn get_gateway_ip_none_for_missing_interface() {
        assert!(DhcpClientOrchestrator::get_gateway_ip(BOGUS_IFACE)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn get_mac_client_id_none_for_missing_interface() {
        // /sys/class/net/<BOGUS_IFACE>/address does not exist, so the read
        // fails and the function returns None without touching real
        // hardware.
        assert!(DhcpClientOrchestrator::get_mac_client_id(BOGUS_IFACE)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn terminate_stale_clients_is_a_noop_when_nothing_matches() {
        // No process on this host will have "-i sgxtest-bogus0" in its
        // /proc/<pid>/cmdline, so this exercises the /proc scan and filter
        // logic without ever issuing a `kill` against a real process.
        DhcpClientOrchestrator::terminate_stale_clients(BOGUS_IFACE).await;
    }
}
