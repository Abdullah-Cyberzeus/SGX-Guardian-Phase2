use serde::Deserialize;
use std::error::Error;
use std::fs;

#[derive(Debug, Deserialize, Clone)]
pub struct NodeConfig {
    pub node_id: String,
    pub hostname: String,
    pub ip: String,
    pub port: u16,
    pub public_key: String,
}
impl NodeConfig {
    pub fn validate(&self) -> Result<(), String> {
        // Node ID must not be empty
        if self.node_id.trim().is_empty() {
            return Err("node_id cannot be empty".into());
        }

        // Hostname must not be empty
        if self.hostname.trim().is_empty() {
            return Err("hostname cannot be empty".into());
        }

        // Validate IP address format
        if self.ip.parse::<std::net::IpAddr>().is_err() {
            return Err(format!("Invalid IP address: {}", self.ip));
        }

        // Validate valid port range
        if self.port == 0 {
            return Err(format!("Invalid port number: {}", self.port));
        }
        // Reject placeholder public keys
        if self.public_key.trim().is_empty() {
            return Err("public_key cannot be empty".into());
        }

        Ok(())
    }
}

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
