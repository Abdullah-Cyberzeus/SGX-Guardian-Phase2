//! Metrics HTTP server
//!
//! Exposes Prometheus-style metrics at:
//!   GET /metrics
//!
//! Read-only, local-only, zero-trust safe.

use crate::metrics::Metrics;
use std::sync::Arc;
use tokio::sync::Mutex;
use warp::Filter;

/// Start metrics HTTP server (local-only).
pub async fn start_metrics_server(metrics: Arc<Mutex<Metrics>>, bind_addr: ([u8; 4], u16)) {
    let metrics_route = warp::path!("metrics")
        .and(warp::get())
        .and(with_metrics(metrics))
        .and_then(handle_metrics);

    warp::serve(metrics_route).run(bind_addr).await;
}

/// Inject shared metrics into request handler
fn with_metrics(
    metrics: Arc<Mutex<Metrics>>,
) -> impl Filter<Extract = (Arc<Mutex<Metrics>>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || metrics.clone())
}

/// Handle GET /metrics
async fn handle_metrics(metrics: Arc<Mutex<Metrics>>) -> Result<impl warp::Reply, warp::Rejection> {
    let snapshot = {
        let m = metrics.lock().await;
        m.snapshot()
    };

    Ok(warp::reply::with_header(
        snapshot.to_prometheus(),
        "Content-Type",
        "text/plain; version=0.0.4",
    ))
}
