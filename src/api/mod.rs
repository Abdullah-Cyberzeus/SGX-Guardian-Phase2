//! REST API module for the SG-X Guardian admin console.
//! Runs as a tokio task alongside the existing gRPC server.
//! Port: 8443 (separate listener from the :50051 mTLS gRPC endpoint).

use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

pub mod error;
pub mod handlers;
pub mod state;

use state::AppState;

/// Build the full axum router with all v1 routes.
pub fn build_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        // Phase 1 - read endpoints
        .route("/api/v1/node/status", get(handlers::node::status))
        .route("/api/v1/node/boot-status", get(handlers::node::boot_status))
        .route("/api/v1/node/restart", post(handlers::node::restart))
        .route("/api/v1/peers", get(handlers::peers::list))
        .route("/api/v1/attestation", get(handlers::attestation::last))
        .route("/api/v1/logs", get(handlers::logs::tail))
        .route("/api/v1/dkp/status", get(handlers::dkp::status))
        .route("/api/v1/pcr/status", get(handlers::pcr::status))
        .route(
            "/api/v1/discovery/devices",
            get(handlers::discovery::list_devices),
        )
        .route(
            "/api/v1/discovery/list",
            get(handlers::discovery::list_devices),
        )
        .route(
            "/api/v1/discovery/inventory/list",
            get(handlers::discovery::list_devices),
        )
        .route(
            "/api/v1/discovery/devices/unauthorized",
            get(handlers::discovery::list_unauthorized),
        )
        .route(
            "/api/v1/discovery/unauthorized",
            get(handlers::discovery::list_unauthorized),
        )
        .route(
            "/api/v1/discovery/scan",
            post(handlers::discovery::scan_now),
        )
        .route(
            "/api/v1/discovery/scan/stealth",
            post(handlers::discovery::scan_stealth),
        )
        .route(
            "/api/v1/discovery/scan/standard",
            post(handlers::discovery::scan_standard),
        )
        .route(
            "/api/v1/discovery/scan/aggressive",
            post(handlers::discovery::scan_aggressive),
        )
        .route(
            "/api/v1/discovery/approve",
            post(handlers::discovery::approve_device),
        )
        .route(
            "/api/v1/discovery/whitelist",
            get(handlers::discovery::get_whitelist),
        )
        .route(
            "/api/v1/discovery/whitelist",
            axum::routing::put(handlers::discovery::put_whitelist),
        )
        .route(
            "/api/v1/discovery/schedule",
            get(handlers::discovery::get_schedule),
        )
        .route(
            "/api/v1/discovery/schedule",
            axum::routing::put(handlers::discovery::put_schedule),
        )
        // Phase 2 - action endpoints
        .route("/api/v1/dkp/rotate", post(handlers::dkp::rotate))
        .route("/api/v1/dkp/revoke", post(handlers::dkp::revoke))
        .route(
            "/api/v1/dkp/emergency-rotate",
            post(handlers::dkp::emergency_rotate),
        )
        .route(
            "/api/v1/pcr/baseline/create",
            post(handlers::pcr::baseline_create),
        )
        // alias expected by frontend service
        .route(
            "/api/v1/pcr/baseline/update",
            post(handlers::pcr::baseline_create),
        )
        .route(
            "/api/v1/pcr/baseline/verify",
            post(handlers::pcr::baseline_verify),
        )
        // alias expected by frontend service
        .route("/api/v1/pcr/verify", post(handlers::pcr::baseline_verify))
        .route("/api/v1/policy/sign", post(handlers::policy::sign))
        .route("/api/v1/policy/verify", post(handlers::policy::verify))
        .route("/api/v1/policy/current", get(handlers::policy::current))
        .route(
            "/api/v1/policy/current",
            axum::routing::put(handlers::policy::save_current),
        )
        .route(
            "/api/v1/policy/sign-deploy-current",
            post(handlers::policy::sign_deploy_current),
        )
        // Health
        .route("/api/v1/health", get(|| async { "ok" }))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Entry point. Spawned from main.rs as a tokio task.
pub async fn serve(state: Arc<AppState>, bind: SocketAddr) -> anyhow::Result<()> {
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!("Admin REST API listening on http://{}", bind);
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}
