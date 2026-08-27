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
        if let Err(_) = self.sender.send(event) {
            // No listeners, safe to ignore
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_event_bus_publish_and_subscribe() {
        let bus = EventBus::new();
        let mut sub1 = bus.subscribe();
        let mut sub2 = bus.subscribe();

        let event = HaEvent::NotificationCreated {
            id: "notif-1".to_string(),
            title: "Door Opened".to_string(),
            message: "Front door sensor triggered".to_string(),
            severity: "warning".to_string(),
        };

        bus.publish(event);

        // Both subscribers receive the event
        match sub1.recv().await.unwrap() {
            HaEvent::NotificationCreated { id, title, .. } => {
                assert_eq!(id, "notif-1");
                assert_eq!(title, "Door Opened");
            }
            _ => panic!("unexpected event variant"),
        }

        match sub2.recv().await.unwrap() {
            HaEvent::NotificationCreated { id, message, severity, .. } => {
                assert_eq!(id, "notif-1");
                assert_eq!(message, "Front door sensor triggered");
                assert_eq!(severity, "warning");
            }
            _ => panic!("unexpected event variant"),
        }
    }

    #[tokio::test]
    async fn test_event_bus_state_changed_payload() {
        let bus = EventBus::new();
        let mut sub = bus.subscribe();

        let state_val = json!({
            "entity_id": "light.living_room",
            "state": "on",
            "attributes": {
                "brightness": 255
            }
        });

        bus.publish(HaEvent::StateChanged(state_val.clone()));

        match sub.recv().await.unwrap() {
            HaEvent::StateChanged(val) => {
                assert_eq!(val["entity_id"], "light.living_room");
                assert_eq!(val["state"], "on");
                assert_eq!(val["attributes"]["brightness"], 255);
            }
            _ => panic!("unexpected event variant"),
        }
    }

    #[test]
    fn test_event_bus_publish_without_subscribers_does_not_panic() {
        let bus = EventBus::new();
        // Publishing when no receiver is subscribed should cleanly no-op
        bus.publish(HaEvent::Unknown(json!({"raw": "data"})));
    }
}

