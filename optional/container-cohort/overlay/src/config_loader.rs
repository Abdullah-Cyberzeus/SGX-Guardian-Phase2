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
pub struct RelayLimitsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_relay_max_peers")]
    pub max_peers: u32,
    #[serde(default = "default_relay_max_bandwidth_mbps")]
    pub max_bandwidth_mbps: u32,
    #[serde(default = "default_relay_alert_threshold_pct")]
    pub alert_threshold_pct: u8,
}

fn default_relay_max_peers() -> u32 {
    5
}

fn default_relay_max_bandwidth_mbps() -> u32 {
    10
}

fn default_relay_alert_threshold_pct() -> u8 {
    80
}

impl Default for RelayLimitsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_peers: default_relay_max_peers(),
            max_bandwidth_mbps: default_relay_max_bandwidth_mbps(),
            alert_threshold_pct: default_relay_alert_threshold_pct(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct PlatformConfig {
    #[serde(default = "default_platform_mode")]
    pub mode: String,
    #[serde(default = "default_virtual_pcr_seed")]
    pub virtual_pcr_seed: String,
}

fn default_platform_mode() -> String {
    "auto".to_string()
}

fn default_virtual_pcr_seed() -> String {
    "guardian-dev".to_string()
}

impl Default for PlatformConfig {
    fn default() -> Self {
        Self {
            mode: default_platform_mode(),
            virtual_pcr_seed: default_virtual_pcr_seed(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct AttestationConfig {
    #[serde(default)]
    pub accept_virtual_peers: bool,
    #[serde(default = "default_accept_legacy_v1_quotes")]
    pub accept_legacy_v1_quotes: bool,
}

fn default_accept_legacy_v1_quotes() -> bool {
    true
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            accept_virtual_peers: false,
            accept_legacy_v1_quotes: default_accept_legacy_v1_quotes(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct NodeConfig {
    pub node_id: String,
    pub hostname: String,
    pub ip: String,
    pub port: u16,
    pub public_key: String,
    pub metrics: Option<MetricsConfig>,
    pub relay: Option<RelayLimitsConfig>,
    #[serde(default)]
    pub platform: PlatformConfig,
    #[serde(default)]
    pub attestation: AttestationConfig,
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

        let ip = self.ip.trim();
        if ip.is_empty() {
            return Err("ip field cannot be empty".into());
        }
        if ip.parse::<std::net::Ipv4Addr>().is_err() {
            return Err(format!("Invalid node IP format: '{}'", self.ip));
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
        if let Some(relay) = &self.relay {
            if relay.alert_threshold_pct > 100 {
                return Err(format!(
                    "relay.alert_threshold_pct must be 0-100, got {}",
                    relay.alert_threshold_pct
                ));
            }
            if relay.max_peers == 0 {
                return Err("relay.max_peers cannot be 0".into());
            }
        }
        let platform_mode = self.platform.mode.trim().to_ascii_lowercase();
        if !matches!(platform_mode.as_str(), "auto" | "real" | "virtual") {
            return Err(format!(
                "platform.mode must be auto, real, or virtual; got {}",
                self.platform.mode
            ));
        }
        Ok(())
    }

    pub fn relay_or_default(&self) -> RelayLimitsConfig {
        self.relay.clone().unwrap_or_default()
    }

    pub fn platform_or_default(&self) -> PlatformConfig {
        self.platform.clone()
    }

    pub fn attestation_or_default(&self) -> AttestationConfig {
        self.attestation.clone()
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
