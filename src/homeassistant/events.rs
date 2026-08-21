use serde_json::Value;
use std::sync::Arc;
use tokio::sync::broadcast::{self, Receiver, Sender};
use tracing::{info, warn};

/// Home Assistant Event Wrapper
#[derive(Debug, Clone)]
pub enum HaEvent {
    StateChanged(Value),
    DeviceRegistryUpdated(Value),
    EntityRegistryUpdated(Value),
    NotificationCreated {
        id: String,
        title: String,
        message: String,
        severity: String,
    },
    Unknown(Value),
}

/// Global Event Bus for Home Assistant Events
pub struct EventBus {
    sender: Sender<HaEvent>,
}

impl EventBus {
    /// Initialize a new bounded event bus with a capacity of 1024
    pub fn new() -> Arc<Self> {
        let (sender, _) = broadcast::channel(1024);
        Arc::new(Self { sender })
    }

    /// Publish an event to the bus
    pub fn publish(&self, event: HaEvent) {
        // broadcast sends to all active receivers. If there are no receivers, it returns an error
        // which we can safely ignore (meaning nobody is listening yet).
        let _ = self.sender.send(event);
    }

    /// Subscribe to the event bus
    pub fn subscribe(&self) -> Receiver<HaEvent> {
        self.sender.subscribe()
    }
}

/// Start the Event Dispatcher loop to process events
/// (In future phases, this will fan out to Device Manager, Automation Engine, etc.)
pub async fn start_event_dispatcher(bus: Arc<EventBus>) {
    let mut receiver = bus.subscribe();

    info!("🚀 Event Dispatcher started.");

    tokio::spawn(async move {
        loop {
            match receiver.recv().await {
                Ok(event) => {
                    // Dispatch logic will go here
                    // For now, we just log debug level
                    tracing::debug!("Dispatched Event: {:?}", event);
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(
                        "Event Dispatcher lagged behind! Skipped {} dropped messages to keep up.",
                        skipped
                    );
                }
                Err(broadcast::error::RecvError::Closed) => {
                    warn!("Event Bus closed. Stopping dispatcher.");
                    break;
                }
            }
        }
    });
}
