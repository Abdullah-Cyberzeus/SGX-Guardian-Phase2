use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize, Clone)]
pub struct NodeConfig {
    pub node_id: String,
    pub hostname: String,
    pub ip: String,
    pub port: u16,
    pub public_key: String,
}
pub fn load_config(path: &str) -> NodeConfig {
    let data = fs::read_to_string(path).expect("Failed to read config file");
    serde_yaml::from_str::<NodeConfig>(&data).expect("Invalid YAML format")
}
