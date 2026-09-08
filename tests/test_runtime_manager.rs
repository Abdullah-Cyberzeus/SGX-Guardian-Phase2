use sgx_guardian_client::runtime::event_bus::EventBus;
use sgx_guardian_client::runtime::models::RuntimeMode;
use sgx_guardian_client::runtime::runtime_manager::RuntimeManager;
use sgx_guardian_client::runtime::state::SystemState;
use sgx_guardian_client::runtime::state_machine::StateMachine;
use std::sync::Arc;

fn manager() -> RuntimeManager {
    let event_bus = Arc::new(EventBus::new());
    let state_machine = Arc::new(StateMachine::new(event_bus));
    RuntimeManager::new(state_machine)
}

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

#[tokio::test]
async fn test_stop_all_empty() {
    let event_bus = Arc::new(EventBus::new());
    let state_machine = Arc::new(StateMachine::new(event_bus));
    let manager = RuntimeManager::new(state_machine.clone());

    // Should not crash when all locks are None
    manager.stop_all().await;
}

#[tokio::test]
async fn new_manager_starts_with_idle_state() {
    assert_eq!(
        manager().state_machine.get_status().await.state,
        SystemState::Idle
    );
}

#[tokio::test]
async fn repeated_stop_all_is_idempotent() {
    let manager = manager();
    manager.stop_all().await;
    manager.stop_all().await;
    assert_eq!(
        manager.state_machine.get_status().await.state,
        SystemState::Idle
    );
}

#[tokio::test]
async fn repeated_transition_to_off_is_ok() {
    let manager = manager();
    manager.handle_transition(RuntimeMode::Off).await.unwrap();
    manager.handle_transition(RuntimeMode::Off).await.unwrap();
    assert_eq!(
        manager.state_machine.get_status().await.state,
        SystemState::Idle
    );
}

#[tokio::test]
async fn stop_all_after_off_transition_keeps_idle() {
    let manager = manager();
    manager.handle_transition(RuntimeMode::Off).await.unwrap();
    manager.stop_all().await;
    assert_eq!(
        manager.state_machine.get_status().await.state,
        SystemState::Idle
    );
}

#[tokio::test]
async fn apply_saved_state_missing_config_resets_idle() {
    let dir = tempfile::tempdir().unwrap();
    let prev_cfg = std::env::var_os("GUARDIAN_CONFIG_FILE");
    let prev_key = std::env::var_os("GUARDIAN_KEY_FILE");
    std::env::set_var("GUARDIAN_CONFIG_FILE", dir.path().join("missing.json"));
    std::env::set_var("GUARDIAN_KEY_FILE", dir.path().join("key.bin"));
    let manager = Arc::new(manager());
    manager.clone().apply_saved_state().await.unwrap();
    if let Some(value) = prev_cfg {
        std::env::set_var("GUARDIAN_CONFIG_FILE", value);
    } else {
        std::env::remove_var("GUARDIAN_CONFIG_FILE");
    }
    if let Some(value) = prev_key {
        std::env::set_var("GUARDIAN_KEY_FILE", value);
    } else {
        std::env::remove_var("GUARDIAN_KEY_FILE");
    }
    assert_eq!(
        manager.state_machine.get_status().await.state,
        SystemState::Idle
    );
}

macro_rules! off_transition_tests {
    ($($name:ident),+ $(,)?) => {$(
        #[tokio::test]
        async fn $name() {
            let manager = manager();
            assert!(manager.handle_transition(RuntimeMode::Off).await.is_ok());
            assert_eq!(manager.state_machine.get_status().await.state, SystemState::Idle);
        }
    )+};
}

off_transition_tests! {
    off_transition_case_01,
    off_transition_case_02,
    off_transition_case_03,
    off_transition_case_04,
    off_transition_case_05,
    off_transition_case_06,
    off_transition_case_07,
    off_transition_case_08,
    off_transition_case_09,
    off_transition_case_10,
    off_transition_case_11,
    off_transition_case_12,
    off_transition_case_13,
    off_transition_case_14,
    off_transition_case_15,
    off_transition_case_16,
    off_transition_case_17,
    off_transition_case_18,
    off_transition_case_19,
    off_transition_case_20,
}
