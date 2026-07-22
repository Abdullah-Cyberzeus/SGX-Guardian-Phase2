use crate::netbridge::types::UplinkState;
use std::time::Duration;
use tokio::process::Command;

/// Number of consecutive failed health-checks required before we declare uplink loss.
/// A value of 2 means one transient glitch (e.g. EAPOL-induced deauth) is ignored.
const LOSS_DEBOUNCE_THRESHOLD: u8 = 2;

#[derive(Debug, PartialEq, Eq)]
pub enum ReachabilityStatus {
    InternetAvailable,
    NoInternet,
    NetworkNotReady,
}

pub struct UplinkMonitor {
    interface: String,
    state: UplinkState,
    test_ip: String,
    /// Counts consecutive health-check failures to debounce transient disruptions.
    consecutive_failures: u8,
}

impl UplinkMonitor {
    pub fn new(interface: String) -> Self {
        UplinkMonitor {
            interface,
            state: UplinkState::Unknown,
            test_ip: "8.8.8.8".to_string(), // Default ping target for reachability
            consecutive_failures: 0,
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
        let output = Command::new("ip")
            .arg("link")
            .arg("show")
            .arg("dev")
            .arg(&self.interface)
            .output()
            .await;

        match output {
            Ok(out) => {
                let status_str = std::str::from_utf8(&out.stdout).unwrap_or("");
                // Output should contain "state UP" if the interface is active
                status_str.contains("state UP")
            }
            Err(_) => false,
        }
    }

    /// Checks both IP connectivity and DNS resolution over the uplink, with retries.
    pub async fn check_internet_reachability(&self) -> ReachabilityStatus {
        let max_attempts = 3;
        let mut ping_success = false;
        let mut dns_success = false;

        for _attempt in 1..=max_attempts {
            // Test IP connectivity: send 3 packets, 0.5s interval, 5s total timeout.
            // Requires only 1/3 to succeed, making the check resilient to intermittent loss.
            if !ping_success {
                let out = Command::new("ping")
                    .arg("-c").arg("3")   // 3 packets per attempt
                    .arg("-W").arg("5")   // 5 second total timeout
                    .arg("-i").arg("0.5") // 0.5s between packets
                    .arg("-I").arg(&self.interface)
                    .arg(&self.test_ip)
                    .output().await;

                if let Ok(o) = out {
                    if o.status.success() {
                        ping_success = true;
                    }
                }
            }

            // Test DNS availability: same resilient approach — 3 packets, 1 pass = ok.
            if !dns_success {
                let out = Command::new("ping")
                    .arg("-c").arg("3")   // 3 packets per attempt
                    .arg("-W").arg("5")   // 5 second total timeout
                    .arg("-i").arg("0.5") // 0.5s between packets
                    .arg("-I").arg(&self.interface)
                    .arg("google.com")
                    .output().await;

                if let Ok(o) = out {
                    if o.status.success() {
                        dns_success = true;
                    }
                }
            }

            if ping_success && dns_success {
                break;
            }
        }

        let is_connected = ping_success && dns_success;
        
        let result = if is_connected {
            ReachabilityStatus::InternetAvailable
        } else {
            ReachabilityStatus::NoInternet
        };

        tracing::debug!(
            "Internet check on {}: attempts={}, ip_ok={}, dns_ok={}, result={:?}",
            self.interface, max_attempts, ping_success, dns_success, result
        );

        result
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
            // Driver is self-healing (e.g. post-EAPOL deauth). Hold the previous state
            // and do NOT increment the failure counter — this is expected transient noise.
            tracing::debug!(
                "Interface {} is mid-reconnect (wpa_state in handshake/scan). Holding uplink state at {:?}.",
                self.interface,
                self.state
            );
            return self.state.clone();
        }

        // Genuine failure — increment debounce counter
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);

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
    pub fn trigger_reconnect(&self) {
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
                // Wi-Fi association is intact — skip DHCP renew to preserve the IP address.
                tracing::debug!(
                    "Uplink loss on {} but wpa_state=COMPLETED — skipping DHCP renew to preserve IP.",
                    interface
                );
            } else {
                // Genuinely disconnected at the Wi-Fi layer — force DHCP renew after reassociation.
                tracing::debug!(
                    "Uplink genuinely disconnected on {} — triggering DHCP renew.",
                    interface
                );
                let _ = tokio::process::Command::new("killall")
                    .args(["-SIGUSR1", "udhcpc"])
                    .output()
                    .await;
            }
        });
    }

    /// A blocking background loop that periodically verifies connection status.
    /// Run this in a dedicated tokio task.
    pub async fn start_monitoring(
        &mut self,
        interval_secs: u64,
        mut cancel_rx: tokio::sync::mpsc::Receiver<()>,
    ) {
        tracing::debug!(
            "Starting uplink monitor loop for interface {} (interval: {}s)",
            self.interface,
            interval_secs
        );
        let interval = Duration::from_secs(interval_secs);

        loop {
            let previous_state = self.state.clone();
            let new_state = self.evaluate_health().await;

            if new_state != previous_state {
                tracing::debug!(
                    "Uplink state changed: {:?} -> {:?}",
                    previous_state,
                    new_state
                );

                if new_state == UplinkState::Disconnected || new_state == UplinkState::NoInternet {
                    tracing::debug!("Uplink loss detected on {}.", self.interface);
                    self.trigger_reconnect();
                }
            }

            tokio::select! {
                _ = cancel_rx.recv() => {
                    tracing::debug!("Uplink monitoring cancelled for {}", self.interface);
                    break;
                }
                _ = tokio::time::sleep(interval) => {}
            }
        }
    }
}
