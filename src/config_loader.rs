use serde::{Deserialize, Serialize};
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

fn default_offline_mode() -> u8 {
    1
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

#[derive(Debug, Deserialize, Clone, Default)]
pub struct ApiTlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub cert_path: Option<String>,
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default)]
    pub require_https: bool,
}

impl ApiTlsConfig {
    pub fn resolved_cert_path(&self, node_id: &str) -> String {
        self.cert_path.clone().unwrap_or_else(|| {
            format!(
                "/var/lib/sgx-guardian/sgx-agent/device_{}_cert.der",
                node_id
            )
        })
    }

    pub fn resolved_key_path(&self, node_id: &str) -> String {
        self.key_path
            .clone()
            .unwrap_or_else(|| format!("/var/lib/sgx-guardian/sgx-agent/device_{}.key", node_id))
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct ApiConfig {
    #[serde(default)]
    pub tls: ApiTlsConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NodeConfig {
    pub node_id: String,
    #[serde(default)]
    pub device_name: Option<String>,
    pub hostname: String,
    #[serde(default)]
    pub display_hostname: Option<String>,
    pub ip: String,
    pub port: u16,
    pub public_key: String,
    #[serde(default = "default_offline_mode")]
    pub offline_mode: u8,
    pub metrics: Option<MetricsConfig>,
    pub relay: Option<RelayLimitsConfig>,
    #[serde(default)]
    pub api: Option<ApiConfig>,
    #[serde(default)]
    pub vps: Option<CloudBrokerConfig>,
    /// Explicit service ports (P0.7).
    ///
    /// Before Phase 0 every port was a `match` on the node's *name*, which is
    /// what made the three-node limit literal: a Guardian named anything other
    /// than nodeA/B/C collided with the CA's ports. Setting this block makes a
    /// Guardian's ports a property of its configuration instead of its name, so
    /// any number of Guardians can coexist — including several on one host.
    ///
    /// Absent, the loader falls back to the legacy name-derived map and then to
    /// the documented defaults, so existing config files keep working unchanged.
    #[serde(default)]
    pub ports: Option<NodePorts>,
}

/// Per-Guardian service ports.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Default)]
pub struct NodePorts {
    /// mTLS gRPC (peer, ping, attestation handshake). Default 50051.
    #[serde(default)]
    pub grpc: Option<u16>,
    /// Plaintext chat gRPC over the overlay. Default 50251.
    #[serde(default)]
    pub chat: Option<u16>,
    /// Attestation listener. Defaults to `grpc + 100`, which is the
    /// relationship the pre-Phase-0 code hardcoded.
    #[serde(default)]
    pub attest: Option<u16>,
}

impl NodePorts {
    /// Resolves the attestation port, applying the `grpc + 100` convention when
    /// only `grpc` is given.
    pub fn attest_port(&self, resolved_grpc: u16) -> u16 {
        self.attest.unwrap_or(
            resolved_grpc.saturating_add(crate::mesh::legacy::ATTESTATION_PORT_OFFSET),
        )
    }
}

/// The gRPC, chat and attestation ports for `node_id`.
///
/// Resolution order, which is what makes ports name-independent (P0.7):
///   1. the `ports:` block in that node's config file
///   2. the legacy name-derived map, for config files that predate it
///   3. the documented defaults
///
/// Step 2 is why a legacy nodeB keeps 50052/50252 with no config change, while
/// a Guardian called `edge-7` gets 50051/50251 rather than inheriting a port
/// from a name it merely resembles.
pub fn resolve_ports(config: Option<&NodeConfig>, node_id: &str) -> (u16, u16, u16) {
    let declared = config.and_then(|c| c.ports);
    let legacy = crate::mesh::legacy::legacy_ports_for(node_id);

    let grpc = declared
        .and_then(|p| p.grpc)
        .or_else(|| legacy.map(|(g, _)| g))
        .unwrap_or(crate::mesh::legacy::DEFAULT_GRPC_PORT);
    let chat = declared
        .and_then(|p| p.chat)
        .or_else(|| legacy.map(|(_, c)| c))
        .unwrap_or(crate::mesh::legacy::DEFAULT_CHAT_PORT);
    let attest = declared.unwrap_or_default().attest_port(grpc);
    (grpc, chat, attest)
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct CloudBrokerConfig {
    #[serde(default)]
    pub broker_url: Option<String>,
    #[serde(default)]
    pub broker_token: Option<String>,
    #[serde(default)]
    pub vps_public_ip: Option<String>,
    #[serde(default)]
    pub vps_overlay_ip: Option<String>,
}

/// Resolves the VPS Cloud Broker configuration for a given node.
/// Merges environment variables with settings from /etc/sgx-guardian/config.yaml
/// and /etc/sgx-guardian/config/{node_id}.yaml.
pub fn resolve_vps_config(node_id: &str) -> CloudBrokerConfig {
    let mut config = CloudBrokerConfig::default();

    // 1. Try reading from config files
    let paths = [
        "/etc/sgx-guardian/config.yaml".to_string(),
        format!("/etc/sgx-guardian/config/{}.yaml", node_id),
        format!("/etc/sgx-guardian/{}.yaml", node_id),
        format!("config/{}.yaml", node_id),
        "config/config.yaml".to_string(),
    ];

    for path in &paths {
        if let Ok(data) = fs::read_to_string(path) {
            // First check if it's a NodeConfig with a vps section
            if let Ok(node_cfg) = serde_yaml::from_str::<NodeConfig>(&data) {
                if let Some(vps) = node_cfg.vps {
                    if config.broker_url.is_none() {
                        config.broker_url = vps.broker_url;
                    }
                    if config.broker_token.is_none() {
                        config.broker_token = vps.broker_token;
                    }
                    if config.vps_public_ip.is_none() {
                        config.vps_public_ip = vps.vps_public_ip;
                    }
                    if config.vps_overlay_ip.is_none() {
                        config.vps_overlay_ip = vps.vps_overlay_ip;
                    }
                }
            } else if let Ok(direct_vps) = serde_yaml::from_str::<serde_yaml::Value>(&data) {
                // Also check if the YAML has a top-level `vps:` key
                if let Some(vps_val) = direct_vps.get("vps") {
                    if let Ok(vps) = serde_yaml::from_value::<CloudBrokerConfig>(vps_val.clone()) {
                        if config.broker_url.is_none() {
                            config.broker_url = vps.broker_url;
                        }
                        if config.broker_token.is_none() {
                            config.broker_token = vps.broker_token;
                        }
                        if config.vps_public_ip.is_none() {
                            config.vps_public_ip = vps.vps_public_ip;
                        }
                        if config.vps_overlay_ip.is_none() {
                            config.vps_overlay_ip = vps.vps_overlay_ip;
                        }
                    }
                }
            }
        }
    }

    // 2. Environment variables override file config
    if let Ok(env_url) = std::env::var("SGX_BROKER_URL") {
        if !env_url.trim().is_empty() {
            config.broker_url = Some(env_url.trim().to_string());
        }
    }
    if let Ok(env_tok) = std::env::var("SGX_BROKER_TOKEN") {
        if !env_tok.trim().is_empty() {
            config.broker_token = Some(env_tok.trim().to_string());
        }
    }
    if let Ok(env_pub) = std::env::var("SGX_VPS_PUBLIC_IP") {
        if !env_pub.trim().is_empty() {
            config.vps_public_ip = Some(env_pub.trim().to_string());
        }
    }
    if let Ok(env_ovl) = std::env::var("SGX_VPS_OVERLAY_IP") {
        if !env_ovl.trim().is_empty() {
            config.vps_overlay_ip = Some(env_ovl.trim().to_string());
        }
    }

    // 3. Fallback inference: if vps_public_ip is set but broker_url is not
    // Default fallback values if unconfigured (zero-config out-of-the-box operation)
    if config.vps_public_ip.is_none() && config.broker_url.is_none() {
        config.vps_public_ip = Some("159.203.186.55".to_string());
        config.broker_url = Some("http://159.203.186.55:8080".to_string());
    } else if config.broker_url.is_none() {
        if let Some(ref pub_ip) = config.vps_public_ip {
            config.broker_url = Some(format!("http://{}:8080", pub_ip));
        }
    } else if config.vps_public_ip.is_none() {
        if let Some(ref url) = config.broker_url {
            let host = url
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .trim_start_matches("ws://")
                .trim_start_matches("wss://")
                .split(':')
                .next()
                .unwrap_or("");
            if !host.is_empty() {
                config.vps_public_ip = Some(host.to_string());
            }
        }
    }

    // Default overlay IP (P0.6): the VPS lighthouse's well-known address
    // within this circle's overlay.
    if config.vps_overlay_ip.is_none() {
        config.vps_overlay_ip = Some(crate::mesh::overlay_host(10));
    }

    config
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
        if self.offline_mode > 1 {
            return Err(format!(
                "offline_mode must be 0 or 1, got {}",
                self.offline_mode
            ));
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
        Ok(())
    }

    pub fn relay_or_default(&self) -> RelayLimitsConfig {
        self.relay.clone().unwrap_or_default()
    }

    pub fn api_or_default(&self) -> ApiConfig {
        self.api.clone().unwrap_or_default()
    }

    pub fn offline_cache_enabled(&self) -> bool {
        self.offline_mode == 1
    }

    pub fn load(path: &str) -> Result<Self, Box<dyn Error>> {
        load_config(path)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_vps_config_defaults() {
        let cfg = resolve_vps_config("node_test_nonexistent");
        assert_eq!(cfg.vps_overlay_ip.as_deref(), Some("192.168.100.10"));
    }

    #[test]
    fn test_node_config_with_vps_section() {
        let yaml = r#"
node_id: "nodeB"
hostname: "nodeb.guardian"
ip: "172.31.250.11"
port: 50052
public_key: "dummy-key-for-test"
vps:
  broker_url: "http://159.203.186.55:8080"
  broker_token: "test-token"
  vps_public_ip: "159.203.186.55"
  vps_overlay_ip: "192.168.100.10"
"#;
        let node_cfg: NodeConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(node_cfg.node_id, "nodeB");
        assert!(node_cfg.vps.is_some());
        let vps = node_cfg.vps.unwrap();
        assert_eq!(
            vps.broker_url.as_deref(),
            Some("http://159.203.186.55:8080")
        );
        assert_eq!(vps.broker_token.as_deref(), Some("test-token"));
        assert_eq!(vps.vps_public_ip.as_deref(), Some("159.203.186.55"));
        assert_eq!(vps.vps_overlay_ip.as_deref(), Some("192.168.100.10"));
    }
}
