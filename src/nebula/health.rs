//! Nebula Health Monitoring Module
//! Provides read-only health diagnostics for Nebula PKI and daemon state.

use crate::nebula::interface::NebulaInterface;
use crate::nebula::lighthouse::LighthouseRegistry;
use crate::nebula::nat::NatDiagnostics;
use crate::nebula::overlay::OverlayPool;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct NebulaHealthReport {
    pub ca_cert_present: bool,
    pub ca_key_present: bool,
    pub node_cert_present: bool,
    pub node_key_present: bool,
    pub daemon_running: bool,
    pub cert_days_remaining: Option<i64>,
}

impl NebulaHealthReport {
    pub fn summary(&self) -> String {
        format!(
            "CA Cert: {}\nCA Key: {}\nNode Cert: {}\nNode Key: {}\nDaemon Running: {}\nCert Days Remaining: {}",
            self.ca_cert_present,
            self.ca_key_present,
            self.node_cert_present,
            self.node_key_present,
            self.daemon_running,
            self.cert_days_remaining
                .map(|d| d.to_string())
                .unwrap_or_else(|| "Unknown".to_string())
        )
    }
}

pub struct NebulaHealth;

impl NebulaHealth {
    pub fn check(nebula_base_dir: &str, node_name: &str) -> NebulaHealthReport {
        let ca_cert_path = format!("{}/ca/ca.crt", nebula_base_dir);
        let ca_key_path = format!("{}/ca/ca.key", nebula_base_dir);
        let node_cert_path = format!("{}/nodes/{}.crt", nebula_base_dir, node_name);
        let node_key_path = format!("{}/nodes/{}.key", nebula_base_dir, node_name);

        let ca_cert_present = Path::new(&ca_cert_path).exists();
        let ca_key_present = Path::new(&ca_key_path).exists();
        let node_cert_present = Path::new(&node_cert_path).exists();
        let node_key_present = Path::new(&node_key_path).exists();

        let daemon_running = Self::check_daemon();

        let cert_days_remaining = if node_cert_present {
            Self::get_cert_days_remaining(&node_cert_path)
        } else {
            None
        };

        NebulaHealthReport {
            ca_cert_present,
            ca_key_present,
            node_cert_present,
            node_key_present,
            daemon_running,
            cert_days_remaining,
        }
    }

    fn check_daemon() -> bool {
        #[cfg(target_os = "linux")]
        {
            if let Ok(output) = Command::new("pgrep").arg("nebula").output() {
                return !output.stdout.is_empty();
            }
            false
        }

        #[cfg(target_os = "windows")]
        {
            if let Ok(output) = Command::new("tasklist").output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                return stdout.contains("nebula.exe");
            }
            false
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            false
        }
    }

    fn get_cert_days_remaining(cert_path: &str) -> Option<i64> {
        let output = Command::new("nebula-cert")
            .arg("print")
            .arg("-json")
            .arg("-path")
            .arg(cert_path)
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        let json: serde_json::Value = serde_json::from_str(&stdout).ok()?;

        let not_after = Self::extract_not_after(&json)?;

        let parsed = chrono::DateTime::parse_from_rfc3339(not_after).ok()?;

        let expiry = parsed.timestamp();
        let now = chrono::Utc::now().timestamp();

        let seconds_remaining = expiry - now;

        Some(seconds_remaining / 86400)
    }

    fn extract_not_after(json: &serde_json::Value) -> Option<&str> {
        // nebula-cert JSON shape can be either:
        // 1) object: {"details":{"notAfter":"..."}}
        // 2) array:  [{"details":{"notAfter":"..."}, ...}]
        if let Some(v) = json
            .get("details")
            .and_then(|d| d.get("notAfter"))
            .and_then(|n| n.as_str())
        {
            return Some(v);
        }
        json.as_array()?
            .first()?
            .get("details")?
            .get("notAfter")?
            .as_str()
    }
}

/// Overlay-specific health report.
#[derive(Debug, Clone)]
pub struct OverlayHealthReport {
    pub interface_up: bool,
    pub expected_ip: String,
    pub actual_ip: String,
    pub ip_correct: bool,
    pub pool_valid: bool,
    pub pool_summary: String,
}

#[derive(Debug, Clone)]
pub struct LighthouseHealthReport {
    pub is_lighthouse: bool,
    pub udp_listening: bool,
    pub active_count: usize,
    pub primary_active: bool,
}

impl LighthouseHealthReport {
    pub fn is_healthy(&self) -> bool {
        if self.is_lighthouse {
            self.udp_listening && self.primary_active
        } else {
            // Member nodes do not listen on UDP 4242; they are healthy
            // if a primary lighthouse is active in the registry.
            self.primary_active && self.active_count > 0
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "LH: is_lh={} udp={} primary={} active={} {}",
            self.is_lighthouse,
            if self.udp_listening { "OPEN" } else { "CLOSED" },
            self.primary_active,
            self.active_count,
            if self.is_healthy() { "✅" } else { "⚠️" }
        )
    }
}

impl OverlayHealthReport {
    pub fn is_healthy(&self) -> bool {
        self.interface_up && self.ip_correct && self.pool_valid
    }

    pub fn summary(&self) -> String {
        format!(
            "Overlay: up={} ip_match={} pool_ok={} [{}→{}] {}",
            self.interface_up,
            self.ip_correct,
            self.pool_valid,
            self.expected_ip,
            self.actual_ip,
            if self.is_healthy() {
                "✅ HEALTHY"
            } else {
                "❌ DEGRADED"
            }
        )
    }
}

impl NebulaHealth {
    /// Check overlay-specific health indicators.
    pub fn check_overlay(pool: &OverlayPool, node_name: &str) -> OverlayHealthReport {
        let interface_up = NebulaInterface::is_up();
        let expected_ip = pool.get_ip_cidr(node_name).unwrap_or_else(|| "none".into());
        let actual_ip = NebulaInterface::get_overlay_ip().unwrap_or_else(|| "none".into());
        let ip_correct = expected_ip == actual_ip && expected_ip != "none";

        let pool_valid = pool.allocated_count() > 0 && pool.get_ip(&pool.owner_node).is_some();

        OverlayHealthReport {
            interface_up,
            expected_ip,
            actual_ip,
            ip_correct,
            pool_valid,
            pool_summary: pool.summary(),
        }
    }

    pub fn check_lighthouse(
        registry: &LighthouseRegistry,
        node_name: &str,
    ) -> LighthouseHealthReport {
        LighthouseHealthReport {
            is_lighthouse: registry.is_lighthouse(node_name),
            udp_listening: NatDiagnostics::nebula_listening(),
            active_count: registry.active().len(),
            primary_active: registry.primary().map(|p| p.is_active).unwrap_or(false),
        }
    }
}

#[cfg(test)]
mod overlay_health_tests {
    use super::*;
    use crate::nebula::overlay::OverlayPool;

    #[test]
    fn test_overlay_health_summary_format() {
        let pool = OverlayPool::new("alpha", "192.168.100", "nodeA");
        let report = NebulaHealth::check_overlay(&pool, "nodeA");
        let s = report.summary();
        assert!(s.contains("Overlay:"));
        assert!(s.contains("up="));
        assert!(s.contains("ip_match="));
    }

    #[test]
    fn test_overlay_health_unknown_node() {
        let pool = OverlayPool::new("alpha", "192.168.100", "nodeA");
        let report = NebulaHealth::check_overlay(&pool, "nodeZ");
        assert!(!report.ip_correct); // nodeZ not in pool
        assert_eq!(report.expected_ip, "none");
    }

    #[test]
    fn test_lighthouse_health_summary_format() {
        let reg = LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "10.0.0.1:4242");
        let report = NebulaHealth::check_lighthouse(&reg, "nodeA");
        let summary = report.summary();
        assert!(summary.contains("LH:"));
        assert!(summary.contains("is_lh=true"));
        assert!(summary.contains("active=1"));
    }

    #[test]
    fn test_lighthouse_health_primary_state_drives_health() {
        let mut reg = LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "10.0.0.1:4242");
        reg.mark_inactive("nodeA");
        let report = NebulaHealth::check_lighthouse(&reg, "nodeB");
        assert!(!report.primary_active);
        assert!(!report.is_healthy());
    }
}
