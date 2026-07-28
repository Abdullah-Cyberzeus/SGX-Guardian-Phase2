use sgx_guardian_client::runtime::event_bus::EventBus;
use sgx_guardian_client::runtime::state::SystemState;
use sgx_guardian_client::runtime::state_machine::StateMachine;
use std::sync::Arc;

#[tokio::test]
async fn test_initial_state() {
    let bus = Arc::new(EventBus::new());
    let sm = StateMachine::new(bus);
    let status = sm.get_status().await;
    assert_eq!(status.state, SystemState::Idle);
    assert!(status.metadata.message.is_none());
}

#[tokio::test]
async fn test_transition_to() {
    let bus = Arc::new(EventBus::new());
    let sm = StateMachine::new(bus);

    sm.transition_to(SystemState::HotspotStarting).await;

    let status = sm.get_status().await;
    assert_eq!(status.state, SystemState::HotspotStarting);
}

#[tokio::test]
async fn test_set_error_state() {
    let bus = Arc::new(EventBus::new());
    let sm = StateMachine::new(bus);

    sm.set_error_state(
        "Failed to start hostapd".to_string(),
        Some("E_HOSTAPD_FAIL".to_string()),
    )
    .await;

    let status = sm.get_status().await;
    assert_eq!(status.state, SystemState::Error);
    assert_eq!(
        status.metadata.message.as_deref(),
        Some("Failed to start hostapd")
    );
    assert_eq!(
        status.metadata.error_code.as_deref(),
        Some("E_HOSTAPD_FAIL")
    );
}

#[tokio::test]
async fn test_reset_to_idle() {
    let bus = Arc::new(EventBus::new());
    let sm = StateMachine::new(bus);

    sm.transition_to(SystemState::DualActive).await;
    sm.reset_to_idle().await;

    let status = sm.get_status().await;
    assert_eq!(status.state, SystemState::Idle);
}
