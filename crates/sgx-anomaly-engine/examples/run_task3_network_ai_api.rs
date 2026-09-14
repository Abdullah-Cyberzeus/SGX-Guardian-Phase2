//! D18 local authenticated API host. Use Ctrl+C to stop.

use anyhow::Result;
use sgx_anomaly_engine::{
    application_host::application_router,
    network_ai::{NetworkAiApiState, NetworkAiConfig},
};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = "config/network_ai.example.json";
    let config = NetworkAiConfig::load_json(config_path)?;
    let state = NetworkAiApiState::new(
        "data/network_ai/d16_config_demo",
        config_path,
        config,
        vec!["nodeA".to_string()],
    );
    let address: SocketAddr = "127.0.0.1:8093".parse()?;
    println!("Task3 API listening at http://{address}");
    println!("Use header x-operator-id: nodeA");
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, application_router(state)).await?;
    Ok(())
}
