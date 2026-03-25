//! Nebula Health Monitoring Module
//! Provides read-only health diagnostics for Nebula PKI and daemon state.

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
