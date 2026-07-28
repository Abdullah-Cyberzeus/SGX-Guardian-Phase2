use super::event_bus::{EventBus, RuntimeEvent};
use super::state::{RuntimeStatus, StateMetadata, SystemState};
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct StateMachine {
    current_state: RwLock<RuntimeStatus>,
    event_bus: Arc<EventBus>,
}

impl StateMachine {
    pub fn new(event_bus: Arc<EventBus>) -> Self {
        Self {
            current_state: RwLock::new(RuntimeStatus {
                state: SystemState::Idle,
                metadata: StateMetadata {
                    message: None,
                    error_code: None,
                },
            }),
            event_bus,
        }
    }

    pub async fn transition_to(&self, new_state: SystemState) {
        let mut state = self.current_state.write().await;
        state.state = new_state;
        state.metadata = StateMetadata {
            message: None,
            error_code: None,
        };
        self.event_bus
            .publish(RuntimeEvent::StateChanged(new_state));
    }

    pub async fn set_error_state(&self, message: String, code: Option<String>) {
        let mut state = self.current_state.write().await;
        state.state = SystemState::Error;
        state.metadata = StateMetadata {
            message: Some(message.clone()),
            error_code: code,
        };
        self.event_bus.publish(RuntimeEvent::Error(message));
    }

    pub async fn reset_to_idle(&self) {
        self.transition_to(SystemState::Idle).await;
    }

    pub async fn get_status(&self) -> RuntimeStatus {
        self.current_state.read().await.clone()
    }
}
