use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
pub struct NodeConfig {
    pub node_id: String,
    pub hostname: String,
    pub ip: String,
    pub port: u16,
    pub public_key: String,
}
impl NodeConfig {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let data = fs::read_to_string(path)?;
        let cfg = serde_yaml::from_str::<NodeConfig>(&data)?;
        Ok(cfg)
    }
}
