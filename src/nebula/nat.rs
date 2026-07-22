// src/nebula/nat.rs
// ============================================================
// NAT Traversal & Connectivity Diagnostics
// ============================================================

use std::process::Command;

pub struct NatDiagnostics;

impl NatDiagnostics {
    /// Check if a UDP port is listening on this machine.
    pub fn check_udp_port(port: u16) -> bool {
        let proc_hex = format!(":{:04X}", port);
        if let Ok(content) = std::fs::read_to_string("/proc/net/udp") {
            if content.lines().any(|line| {
                line.split_whitespace()
                    .nth(1)
                    .map(|addr| addr.ends_with(&proc_hex))
                    .unwrap_or(false)
            }) {
                return true;
            }
        }

        Command::new("ss")
            .args(["-ulnp"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&format!(":{}", port)))
            .unwrap_or(false)
    }

    /// Check if Nebula is listening on the default UDP port.
    pub fn nebula_listening() -> bool {
        Self::check_udp_port(4242)
    }

    pub fn report() -> String {
        format!(
            "NAT: udp_4242={}",
            if Self::nebula_listening() {
                "LISTENING"
            } else {
                "NOT_LISTENING"
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_no_panic() {
        let r = NatDiagnostics::report();
        assert!(r.contains("NAT:"));
    }

    #[test]
    fn test_check_udp_no_panic() {
        let _ = NatDiagnostics::check_udp_port(4242);
    }

    #[test]
    fn test_nebula_listening_consistent_with_port_check() {
        assert_eq!(
            NatDiagnostics::nebula_listening(),
            NatDiagnostics::check_udp_port(4242)
        );
    }

    #[test]
    fn test_report_has_state_keyword() {
        let r = NatDiagnostics::report();
        assert!(r.contains("LISTENING") || r.contains("NOT_LISTENING"));
    }
}
