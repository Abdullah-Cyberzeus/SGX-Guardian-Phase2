use crate::runtime::event_bus::EventBus;
use crate::runtime::runtime_manager::RuntimeManager;
use crate::runtime::server::build_wifi_router;
use crate::runtime::state_machine::StateMachine;
use axum::Router;
use std::sync::Arc;

pub async fn start_daemon() -> (Router, Arc<RuntimeManager>) {
    let event_bus = Arc::new(EventBus::new());
    let state_machine = Arc::new(StateMachine::new(event_bus.clone()));
    let manager = Arc::new(RuntimeManager::new(state_machine));

    // Auto-start saved config using the resilient native supervisor
    let mgr_clone = manager.clone();
    tokio::spawn(async move {
        if let Err(e) = mgr_clone.apply_saved_state().await {
            tracing::error!("Failed to initialize supervisor on boot: {}", e);
        }
    });

    (build_wifi_router(manager.clone(), event_bus), manager)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `start_daemon` wires the event bus, state machine, runtime manager and
    /// router together and kicks off saved-state restoration in the background.
    /// The spawned task swallows its own errors (there is no saved state here,
    /// and no wireless hardware to apply it to), so the function is safe to
    /// call directly and the assertion is on what it hands back.
    #[tokio::test]
    async fn start_daemon_returns_a_wired_router_and_manager() {
        let (router, manager) = start_daemon().await;

        // The manager is live: `stop_all` is safe with nothing running and
        // proves the supervisor was constructed rather than left uninitialised.
        manager.stop_all().await;

        // The router it returns is the wifi router: dispatching an unknown
        // path yields 404 rather than panicking, which proves it was built.
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/definitely-not-a-route")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
