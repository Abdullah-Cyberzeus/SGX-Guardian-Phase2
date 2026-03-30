// src/nebula/interface.rs
// ============================================================
// Nebula Virtual Interface Manager
//
// Verifies and monitors the nebula0 TUN interface created by
// the Nebula daemon. Provides status checks and diagnostics.
// ============================================================

use std::process::Command;

/// Manages the nebula0 virtual network interface.
pub struct NebulaInterface;

impl NebulaInterface {
    /// Check if nebula0 interface exists and is UP.
    pub fn is_up() -> bool {
        Command::new("ip")
            .args(["link", "show", "nebula0"])
            .output()
            .map(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout.contains("UP") || stdout.contains("state UP")
            })
            .unwrap_or(false)
    }

    /// Get the assigned IP address on nebula0.
    pub fn get_overlay_ip() -> Option<String> {
        let output = Command::new("ip")
            .args(["addr", "show", "nebula0"])
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .lines()
            .find(|l| l.trim().starts_with("inet ") && !l.contains("inet6"))
            .and_then(|l| l.split_whitespace().nth(1).map(|s| s.to_string()))
    }

    /// Verify the overlay IP matches what the pool assigned.
    pub fn verify_ip(expected_ip_cidr: &str) -> bool {
        Self::get_overlay_ip()
            .map(|actual| actual == expected_ip_cidr)
            .unwrap_or(false)
    }

    /// Ping a peer's overlay IP through nebula0.
    pub fn ping_peer(peer_overlay_ip: &str) -> bool {
        Command::new("ping")
            .args(["-c", "3", "-W", "2", "-I", "nebula0", peer_overlay_ip])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Get interface statistics (RX/TX bytes).
    pub fn get_stats() -> Option<(u64, u64)> {
        let rx = std::fs::read_to_string("/sys/class/net/nebula0/statistics/rx_bytes")
            .ok()?
            .trim()
            .parse()
            .ok()?;
        let tx = std::fs::read_to_string("/sys/class/net/nebula0/statistics/tx_bytes")
            .ok()?
            .trim()
            .parse()
            .ok()?;
        Some((rx, tx))
    }

    /// Full status report for logging.
    pub fn status_report() -> String {
        let up = Self::is_up();
        let ip = Self::get_overlay_ip().unwrap_or_else(|| "none".into());
        let stats = Self::get_stats()
            .map(|(rx, tx)| format!("rx={}B tx={}B", rx, tx))
            .unwrap_or_else(|| "no-stats".into());
        format!("nebula0: up={}, ip={}, {}", up, ip, stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_report_does_not_panic() {
        // On dev machine nebula0 doesn't exist — should return gracefully
        let report = NebulaInterface::status_report();
        assert!(report.contains("nebula0:"));
    }

    #[test]
    fn test_is_up_returns_false_on_dev() {
        assert!(!NebulaInterface::is_up());
    }

    #[test]
    fn test_get_overlay_ip_none_on_dev() {
        assert!(NebulaInterface::get_overlay_ip().is_none());
    }

    #[test]
    fn test_verify_ip_false_when_no_interface() {
        assert!(!NebulaInterface::verify_ip("192.168.100.1/24"));
    }
}
