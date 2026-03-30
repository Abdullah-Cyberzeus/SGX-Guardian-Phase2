use serde::Deserialize;
use std::error::Error;
use std::fs;

/// Represents the per-node configuration loaded from YAML,
/// including identity, networking, and public key parameters.
/// Configuration for the metrics server (optional, per-node)
#[derive(Debug, Deserialize, Clone)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub bind: String,
    pub port: u16,
}
#[derive(Debug, Deserialize, Clone)]
pub struct NodeConfig {
    pub node_id: String,
    pub hostname: String,
    pub ip: String,
    pub port: u16,
    pub public_key: String,
    pub metrics: Option<MetricsConfig>,
}
impl NodeConfig {
    /// Validates the node configuration fields, ensuring correct ID,
    /// hostname, IP format, port range, and non-empty public key.
    pub fn validate(&self) -> Result<(), String> {
        // Node ID must not be empty
        if self.node_id.trim().is_empty() {
            return Err("node_id cannot be empty".into());
        }

        // Hostname must not be empty
        if self.hostname.trim().is_empty() {
            return Err("hostname cannot be empty".into());
        }

        // Only check empty — dynamic IPs may be 0.0.0.0 during discovery
        if self.ip.trim().is_empty() {
            return Err("ip field cannot be empty".into());
        }

        // Validate valid port range
        if self.port == 0 {
            return Err(format!("Invalid port number: {}", self.port));
        }
        // Reject placeholder public keys
        if self.public_key.trim().is_empty() {
            return Err("public_key cannot be empty".into());
        }
        if let Some(metrics) = &self.metrics {
            if metrics.bind.parse::<std::net::IpAddr>().is_err() {
                return Err(format!("Invalid metrics.bind IP: {}", metrics.bind));
            }

            if metrics.port == 0 {
                return Err("metrics.port cannot be 0".into());
            }
        }
        Ok(())
    }
}

/// Loads a node configuration file from YAML, parses it into `NodeConfig`,
/// and performs validation to ensure correctness before returning it.
pub fn load_config(path: &str) -> Result<NodeConfig, Box<dyn Error>> {
    let data = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config file {}: {}", path, e))?;

    let config = serde_yaml::from_str::<NodeConfig>(&data)
        .map_err(|e| format!("Invalid YAML format in {}: {}", path, e))?;
    config
        .validate()
        .map_err(|e| format!("Config validation failed: {}", e))?;
    Ok(config)
}
// ================================
// Cloud uplink runtime configuration
// ================================

#[derive(Debug, Clone)]
pub struct CloudConfig {
    pub enabled: bool,
    pub endpoint: String,
}

impl CloudConfig {
    pub fn from_env() -> Self {
        Self {
            enabled: std::env::var("SGX_CLOUD_UPLINK_ENABLED").unwrap_or_else(|_| "false".into())
                == "true",

            endpoint: std::env::var("SGX_CLOUD_ENDPOINT").unwrap_or_else(|_| "".into()),
        }
    }
}
