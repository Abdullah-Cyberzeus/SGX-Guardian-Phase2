use sgx_guardian_client::runtime::event_bus::EventBus;
use sgx_guardian_client::runtime::models::RuntimeMode;
use sgx_guardian_client::runtime::runtime_manager::RuntimeManager;
use sgx_guardian_client::runtime::state::SystemState;
use sgx_guardian_client::runtime::state_machine::StateMachine;
use std::sync::Arc;

#[tokio::test]
async fn test_handle_transition_to_off() {
    let event_bus = Arc::new(EventBus::new());
    let state_machine = Arc::new(StateMachine::new(event_bus));
    let manager = RuntimeManager::new(state_machine.clone());

    let res = manager.handle_transition(RuntimeMode::Off).await;
    assert!(res.is_ok());

    let status = manager.state_machine.get_status().await;
    assert_eq!(status.state, SystemState::Idle);
}

#[test]
fn test_get_default_uplink_interface() {
    // We just verify it doesn't crash and returns some string.
    let iface = RuntimeManager::get_default_uplink_interface();
    assert!(!iface.is_empty());
}

#[tokio::test]
async fn test_stop_all_empty() {
    let event_bus = Arc::new(EventBus::new());
    let state_machine = Arc::new(StateMachine::new(event_bus));
    let manager = RuntimeManager::new(state_machine.clone());

    // Should not crash when all locks are None
    manager.stop_all().await;
}
