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
    pub fn load(path: &str) -> Self {
        let data = fs::read_to_string(path).expect("Unable to read node config");
        serde_yaml::from_str::<NodeConfig>(&data).expect("Invalid YAML structure")
    }
}
