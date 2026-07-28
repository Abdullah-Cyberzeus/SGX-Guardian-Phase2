use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuntimeEvent {
    StateChanged(super::state::SystemState),
    UplinkDisconnected,
    HotspotStarted,
    Error(String),
}

pub struct EventBus {
    tx: broadcast::Sender<RuntimeEvent>,
}

impl EventBus {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(100);
        Self { tx }
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    pub fn subscribe(&self) -> broadcast::Receiver<RuntimeEvent> {
        self.tx.subscribe()
    }

    pub fn publish(&self, event: RuntimeEvent) {
        let _ = self.tx.send(event);
    }
}
