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
        .route(
            "/api/v1/policy/verify-deployed",
            post(handlers::policy::verify_deployed),
        )
        .route("/api/v1/policy/current", get(handlers::policy::current))
        .route("/api/v1/policy/backup", get(handlers::policy::backup))
        .route(
            "/api/v1/policy/current",
            axum::routing::put(handlers::policy::save_current),
        )
        .route(
            "/api/v1/guardian/key/status",
            get(handlers::guardian_keys::status),
        )
        .route(
            "/api/v1/guardian/key/generate",
            post(handlers::guardian_keys::generate),
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

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::StatusCode;
    use serde_json::Value;

    const DEPLOYED_SIG_PATH: &str = "/etc/sgx-guardian/policies/policy.sig";

    fn test_state() -> Arc<AppState> {
        Arc::new(AppState {
            node_id: "test-nodeA".into(),
            config_dir: "/tmp/config".into(),
            boot_dir: "/tmp/boot".into(),
            keys_dir: "/tmp/keys".into(),
            pcr_dir: "/tmp/pcr".into(),
            pcr_baseline_dir: "/tmp".into(),
            log_dir_primary: "/tmp/logs".into(),
            log_dir_fallback: "/tmp/logs-fallback".into(),
        })
    }

    async fn spawn_api() -> (String, tokio::task::JoinHandle<()>) {
        let app = build_router(test_state());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app.into_make_service()).await;
        });
        (format!("http://{}", addr), handle)
    }

    #[tokio::test]
    async fn verify_deployed_does_not_require_multipart_upload() {
        let (base_url, handle) = spawn_api().await;
        let url = format!("{}/api/v1/policy/verify-deployed", base_url);
        let response = reqwest::Client::new()
            .post(url)
            .send()
            .await
            .expect("request verify-deployed");
        handle.abort();
        assert_ne!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn verify_deployed_missing_signature_returns_not_found() {
        if std::path::Path::new(DEPLOYED_SIG_PATH).is_file() {
            // This assertion specifically validates the missing-file behavior.
            // Skip in environments where the deployed policy signature already exists.
            return;
        }

        let (base_url, handle) = spawn_api().await;
        let url = format!("{}/api/v1/policy/verify-deployed", base_url);
        let response = reqwest::Client::new()
            .post(url)
            .send()
            .await
            .expect("request verify-deployed");
        let status = response.status();
        let body: Value = response.json().await.expect("json error body");
        handle.abort();

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "NOT_FOUND");
        assert_eq!(
            body["error"]["message"],
            format!(
                "deployed policy signature not found at {}",
                DEPLOYED_SIG_PATH
            )
        );
    }

    #[tokio::test]
    async fn verify_upload_endpoint_still_requires_multipart_body() {
        let (base_url, handle) = spawn_api().await;
        let url = format!("{}/api/v1/policy/verify", base_url);
        let response = reqwest::Client::new()
            .post(url)
            .send()
            .await
            .expect("request verify");
        handle.abort();
        assert!(
            matches!(
                response.status(),
                StatusCode::BAD_REQUEST | StatusCode::UNSUPPORTED_MEDIA_TYPE
            ),
            "expected multipart validation failure, got {}",
            response.status()
        );
    }
}
