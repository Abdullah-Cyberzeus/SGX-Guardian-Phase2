//! Metrics HTTP server
//!
//! Exposes Prometheus-style metrics at:
//!   GET /metrics
//!
//! Read-only, local-only, zero-trust safe.

use crate::metrics::Metrics;
use axum::{extract::State, http::header, routing::get, Router};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// Start metrics HTTP server (local-only).
pub async fn start_metrics_server(metrics: Arc<Mutex<Metrics>>, bind_addr: ([u8; 4], u16)) {
    let app = Router::new()
        .route("/metrics", get(handle_metrics))
        .with_state(metrics);
    let listener = TcpListener::bind(SocketAddr::from(bind_addr))
        .await
        .expect("bind metrics listener");

    axum::serve(listener, app)
        .await
        .expect("metrics server failed");
}

/// Handle GET /metrics
async fn handle_metrics(
    State(metrics): State<Arc<Mutex<Metrics>>>,
) -> impl axum::response::IntoResponse {
    let snapshot = {
        let m = metrics.lock().await;
        m.snapshot()
    };

    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        snapshot.to_prometheus(),
    )
}
