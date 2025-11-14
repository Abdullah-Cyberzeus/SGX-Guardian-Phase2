use crate::config::NodeConfig;

pub fn run() {
    let node_config = NodeConfig::load("../config/nodeA.yaml");
    println!("🟢 Node Status:");
    println!(
        " - ID: {}\n - Hostname: {}\n - IP: {}\n - Port: {}\n - Public Key: {}",
        node_config.node_id,
        node_config.hostname,
        node_config.ip,
        node_config.port,
        node_config.public_key
    );
}
