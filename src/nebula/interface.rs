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
        format!("Guardian Mesh interface: up={}, ip={}, {}", up, ip, stats)
    }

    /// Manually assign IP to nebula0 if not set by daemon.
    pub fn assign_overlay_ip(ip_cidr: &str) -> Result<(), String> {
        let up_out = Command::new("ip")
            .args(["link", "set", "nebula0", "up"])
            .output()
            .map_err(|e| format!("ip link set up failed: {}", e))?;

        if !up_out.status.success() {
            let stderr = String::from_utf8_lossy(&up_out.stderr);
            if !stderr.contains("File exists") && !stderr.contains("already") {
                return Err(format!("Interface up failed: {}", stderr));
            }
        }

        let addr_out = Command::new("ip")
            .args(["addr", "add", ip_cidr, "dev", "nebula0"])
            .output()
            .map_err(|e| format!("ip addr add failed: {}", e))?;

        if !addr_out.status.success() {
            let stderr = String::from_utf8_lossy(&addr_out.stderr);
            if stderr.contains("File exists") {
                return Ok(());
            }
            return Err(format!("addr add failed: {}", stderr));
        }

        println!("✅ Guardian Mesh overlay IP assigned successfully");
        Ok(())
    }

    /// Wait for nebula0 to appear after daemon start.
    pub async fn wait_for_interface(timeout_secs: u64) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

        while std::time::Instant::now() < deadline {
            if Self::is_up() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        false
    }

    /// Verify nebula0 has the expected IP, fix it if not.
    pub fn verify_and_fix_ip(expected_ip_cidr: &str) -> Result<(), String> {
        match Self::get_overlay_ip() {
            Some(actual) if actual == expected_ip_cidr => {
                println!("✅ Guardian Mesh interface IP verified");
                Ok(())
            }
            Some(actual) => {
                eprintln!("⚠️  Guardian Mesh interface IP mismatch detected — removing old, assigning new");
                // Remove old IP first to avoid duplicate addresses
                let _ = Command::new("ip")
                    .args(["addr", "del", &actual, "dev", "nebula0"])
                    .output();
                Self::assign_overlay_ip(expected_ip_cidr)
            }
            None => {
                println!("📋 Guardian Mesh interface has no IP yet, assigning overlay address");
                Self::assign_overlay_ip(expected_ip_cidr)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_report_does_not_panic() {
        // On dev machine nebula0 doesn't exist — should return gracefully
        let report = NebulaInterface::status_report();
        assert!(report.contains("Guardian Mesh interface:"));
    }
}
