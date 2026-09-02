//! SGX Guardian Cloud Enrollment Broker
//!
//! Lightweight Axum server that runs on a public VPS.
//! Acts as a message relay between remote nodes (HTTP) and the
//! Home CA node (persistent WebSocket).
//!
//! Usage:
//!   SGX_BROKER_TOKEN=mysecret ./sgx-broker
//!
//! Environment variables:
//!   SGX_BROKER_PORT   — listen port (default: 8080)
//!   SGX_BROKER_TOKEN  — pre-shared auth token for WS bridge (optional)
//!   RUST_LOG          — log level (default: info)

use sgx_broker::create_app;
use sgx_broker::state::AppState;
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let port: u16 = std::env::var("SGX_BROKER_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let state = AppState::new();
    let app = create_app(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    println!();
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║       SGX Guardian Cloud Enrollment Broker          ║");
    println!("╠══════════════════════════════════════════════════════╣");
    println!("║  HTTP Listen : http://0.0.0.0:{}                  ║", port);
    println!("╠══════════════════════════════════════════════════════╣");
    println!("║  Endpoints:                                        ║");
    println!("║    GET  /health          — Liveness check          ║");
    println!("║    POST /api/v1/enroll   — Remote node enrollment  ║");
    println!("║    GET  /ws/ca-bridge    — CA WebSocket bridge     ║");
    println!("╚══════════════════════════════════════════════════════╝");
    println!();

    let token_set = std::env::var("SGX_BROKER_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
        .is_some();
    if token_set {
        tracing::info!("🔑 Auth token configured (SGX_BROKER_TOKEN is set)");
    } else {
        tracing::warn!("⚠️  No auth token set (SGX_BROKER_TOKEN is empty) — WS bridge is open");
    }

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind TCP listener");

    tracing::info!("🚀 Broker listening on http://{}", addr);

    axum::serve(listener, app)
        .await
        .expect("Broker server failed");
}
