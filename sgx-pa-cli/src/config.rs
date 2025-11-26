use serde::Deserialize;
use std::fs;
/// Represents the on-disk YAML configuration used by the `sgx-pa-cli`,
/// containing node identity, network settings, and its public key.
#[derive(Debug, Deserialize)]
pub struct NodeConfig {
    pub node_id: String,
    pub hostname: String,
    pub ip: String,
    pub port: u16,
    pub public_key: String,
}
impl NodeConfig {
    /// Loads a YAML configuration file from the given path and deserializes it
    /// into a `NodeConfig`. Returns an error if the file is unreadable or invalid.
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let data = fs::read_to_string(path)?;
        let cfg = serde_yaml::from_str::<NodeConfig>(&data)?;
        Ok(cfg)
    }
}
