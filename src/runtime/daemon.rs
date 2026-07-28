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
