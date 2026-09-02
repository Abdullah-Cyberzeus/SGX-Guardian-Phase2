pub mod handlers;
pub mod models;
pub mod state;

use axum::{
    routing::{get, post},
    Router,
};
use state::AppState;

/// Creates the Axum router for the SGX Cloud Enrollment Broker.
pub fn create_app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(handlers::health))
        .route("/api/v1/enroll", post(handlers::handle_enroll))
        .route("/ws/ca-bridge", get(handlers::handle_ca_ws))
        .with_state(state)
}
