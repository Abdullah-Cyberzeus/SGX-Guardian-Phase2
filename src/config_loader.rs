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

    fn base_yaml() -> String {
        "node_id: nodeA\nhostname: guardian-node-A\nip: 10.0.0.5\nport: 50051\npublic_key: abc123\n"
            .to_string()
    }

    fn parse(yaml: &str) -> NodeConfig {
        serde_yaml::from_str(yaml).expect("valid YAML")
    }

    fn write_config(dir: &std::path::Path, name: &str, yaml: &str) -> String {
        let path = dir.join(name);
        std::fs::write(&path, yaml).expect("write config");
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn tls_paths_default_to_the_per_node_device_certificate() {
        let tls = ApiTlsConfig::default();

        assert_eq!(
            tls.resolved_cert_path("nodeB"),
            "/var/lib/sgx-guardian/sgx-agent/device_nodeB_cert.der"
        );
        assert_eq!(
            tls.resolved_key_path("nodeB"),
            "/var/lib/sgx-guardian/sgx-agent/device_nodeB.key"
        );
        assert!(!tls.enabled);
        assert!(!tls.require_https);
    }

    #[test]
    fn explicit_tls_paths_override_the_defaults() {
        let tls = ApiTlsConfig {
            enabled: true,
            cert_path: Some("/opt/cert.der".into()),
            key_path: Some("/opt/key.der".into()),
            require_https: true,
        };

        assert_eq!(tls.resolved_cert_path("nodeA"), "/opt/cert.der");
        assert_eq!(tls.resolved_key_path("nodeA"), "/opt/key.der");
    }

    #[test]
    fn a_minimal_config_is_valid_and_uses_documented_defaults() {
        let config = parse(&base_yaml());

        config.validate().expect("minimal config is valid");
        assert_eq!(config.offline_mode, 1);
        assert!(config.offline_cache_enabled());
        assert!(config.metrics.is_none());
        // An absent relay/api block falls back to the built-in defaults.
        assert_eq!(config.relay_or_default().max_peers, 5);
        assert_eq!(config.relay_or_default().max_bandwidth_mbps, 10);
        assert_eq!(config.relay_or_default().alert_threshold_pct, 80);
        assert!(!config.relay_or_default().enabled);
        assert!(!config.api_or_default().tls.enabled);
    }

    #[test]
    fn identity_fields_must_not_be_blank() {
        for (field, replacement) in [
            ("node_id: nodeA", "node_id: \"   \""),
            ("hostname: guardian-node-A", "hostname: \"  \""),
            ("public_key: abc123", "public_key: \" \""),
        ] {
            let config = parse(&base_yaml().replace(field, replacement));
            assert!(
                config.validate().is_err(),
                "{field} must be rejected when blank"
            );
        }
    }

    #[test]
    fn the_ip_must_be_a_parseable_ipv4_address() {
        let empty = parse(&base_yaml().replace("ip: 10.0.0.5", "ip: \"  \""));
        assert_eq!(
            empty.validate().unwrap_err(),
            "ip field cannot be empty",
            "whitespace is treated as absent"
        );

        let malformed = parse(&base_yaml().replace("ip: 10.0.0.5", "ip: not-an-ip"));
        assert!(malformed
            .validate()
            .unwrap_err()
            .contains("Invalid node IP format"));

        // IPv6 is not accepted: the overlay and broadcast paths are IPv4-only.
        let ipv6 = parse(&base_yaml().replace("ip: 10.0.0.5", "ip: \"::1\""));
        assert!(ipv6.validate().is_err());

        let unspecified = parse(&base_yaml().replace("ip: 10.0.0.5", "ip: 0.0.0.0"));
        assert!(
            unspecified.validate().is_ok(),
            "0.0.0.0 is the pre-discovery placeholder and must stay loadable"
        );
    }

    #[test]
    fn port_zero_is_rejected() {
        let config = parse(&base_yaml().replace("port: 50051", "port: 0"));
        assert!(config
            .validate()
            .unwrap_err()
            .contains("Invalid port number"));
    }

    #[test]
    fn offline_mode_must_be_zero_or_one() {
        let disabled = parse(&format!("{}offline_mode: 0\n", base_yaml()));
        disabled.validate().expect("0 is valid");
        assert!(!disabled.offline_cache_enabled());

        let invalid = parse(&format!("{}offline_mode: 2\n", base_yaml()));
        assert!(invalid
            .validate()
            .unwrap_err()
            .contains("offline_mode must be 0 or 1"));
    }

    #[test]
    fn the_metrics_block_is_validated_when_present() {
        let valid = parse(&format!(
            "{}metrics:\n  enabled: true\n  bind: 127.0.0.1\n  port: 9100\n",
            base_yaml()
        ));
        valid.validate().expect("a well-formed metrics block");

        let bad_bind = parse(&format!(
            "{}metrics:\n  enabled: true\n  bind: not-an-ip\n  port: 9100\n",
            base_yaml()
        ));
        assert!(bad_bind
            .validate()
            .unwrap_err()
            .contains("Invalid metrics.bind IP"));

        let zero_port = parse(&format!(
            "{}metrics:\n  enabled: true\n  bind: 127.0.0.1\n  port: 0\n",
            base_yaml()
        ));
        assert_eq!(
            zero_port.validate().unwrap_err(),
            "metrics.port cannot be 0"
        );
    }

    #[test]
    fn the_relay_block_is_validated_when_present() {
        let valid = parse(&format!(
            "{}relay:\n  enabled: true\n  max_peers: 8\n  alert_threshold_pct: 100\n",
            base_yaml()
        ));
        valid.validate().expect("a well-formed relay block");
        assert_eq!(valid.relay_or_default().max_peers, 8);

        let over_threshold = parse(&format!(
            "{}relay:\n  enabled: true\n  alert_threshold_pct: 101\n",
            base_yaml()
        ));
        assert!(over_threshold
            .validate()
            .unwrap_err()
            .contains("relay.alert_threshold_pct must be 0-100"));

        let zero_peers = parse(&format!(
            "{}relay:\n  enabled: true\n  max_peers: 0\n",
            base_yaml()
        ));
        assert_eq!(
            zero_peers.validate().unwrap_err(),
            "relay.max_peers cannot be 0"
        );
    }

    #[test]
    fn loading_reports_missing_files_unparseable_yaml_and_invalid_values() {
        let temp = tempfile::tempdir().expect("create sandbox");

        let missing = load_config(&temp.path().join("absent.yaml").to_string_lossy())
            .expect_err("a missing file must not load");
        assert!(missing.to_string().contains("Failed to read config file"));

        let malformed = write_config(temp.path(), "bad.yaml", "node_id: [unterminated");
        let error = load_config(&malformed).expect_err("unparseable YAML must not load");
        assert!(error.to_string().contains("Invalid YAML format"));

        let invalid = write_config(
            temp.path(),
            "invalid.yaml",
            &base_yaml().replace("port: 50051", "port: 0"),
        );
        let error = load_config(&invalid).expect_err("an invalid config must not load");
        assert!(error.to_string().contains("Config validation failed"));
    }

    #[test]
    fn a_valid_file_loads_through_both_entry_points() {
        let temp = tempfile::tempdir().expect("create sandbox");
        let path = write_config(temp.path(), "nodeA.yaml", &base_yaml());

        let via_function = load_config(&path).expect("load via function");
        let via_method = NodeConfig::load(&path).expect("load via method");

        assert_eq!(via_function.node_id, "nodeA");
        assert_eq!(via_function.ip, "10.0.0.5");
        assert_eq!(via_method.node_id, via_function.node_id);
        assert_eq!(via_method.port, via_function.port);
    }

    #[test]
    fn cloud_config_is_disabled_unless_explicitly_enabled() {
        let _lock = crate::test_support::blocking_env_lock();
        let previous_enabled = std::env::var_os("SGX_CLOUD_UPLINK_ENABLED");
        let previous_endpoint = std::env::var_os("SGX_CLOUD_ENDPOINT");

        std::env::remove_var("SGX_CLOUD_UPLINK_ENABLED");
        std::env::remove_var("SGX_CLOUD_ENDPOINT");
        let default = CloudConfig::from_env();
        assert!(!default.enabled);
        assert_eq!(default.endpoint, "");

        std::env::set_var("SGX_CLOUD_UPLINK_ENABLED", "true");
        std::env::set_var("SGX_CLOUD_ENDPOINT", "https://cloud.example/uplink");
        let enabled = CloudConfig::from_env();
        assert!(enabled.enabled);
        assert_eq!(enabled.endpoint, "https://cloud.example/uplink");

        // Only the exact string "true" enables the uplink — anything else
        // leaves outbound telemetry off.
        for value in ["1", "TRUE", "yes", "on", ""] {
            std::env::set_var("SGX_CLOUD_UPLINK_ENABLED", value);
            assert!(!CloudConfig::from_env().enabled, "{value:?}");
        }

        match previous_enabled {
            Some(value) => std::env::set_var("SGX_CLOUD_UPLINK_ENABLED", value),
            None => std::env::remove_var("SGX_CLOUD_UPLINK_ENABLED"),
        }
        match previous_endpoint {
            Some(value) => std::env::set_var("SGX_CLOUD_ENDPOINT", value),
            None => std::env::remove_var("SGX_CLOUD_ENDPOINT"),
        }
    }
}
