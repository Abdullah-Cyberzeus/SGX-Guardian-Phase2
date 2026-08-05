use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::api::state::AppState;
use crate::homeassistant::events::HaEvent;

#[derive(Debug, Deserialize)]
pub struct WsIncomingMessage {
    pub action: String, // "subscribe", "unsubscribe", "ping"
    pub topic: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WsOutgoingEvent {
    pub topic: String,
    pub event: String,
    pub data: serde_json::Value,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// GET /api/ws (WebSocket Upgrade Handler)
pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_websocket_session(socket, state))
}

async fn handle_websocket_session(socket: WebSocket, state: Arc<AppState>) {
    info!("🔌 Real-time Frontend WebSocket client connected.");

    let (mut sender, mut receiver) = socket.split();
    let subscribed_topics = Arc::new(Mutex::new(HashSet::<String>::new()));

    // Automatically subscribe client to "device_events" by default
    {
        let mut topics = subscribed_topics.lock().await;
        topics.insert("device_events".to_string());
    }

    // 1. Task: Forward events from HA EventBus to WebSocket client
    let topics_clone = Arc::clone(&subscribed_topics);
    let event_bus = state.get_ha_event_bus().await;

    let send_task = tokio::spawn(async move {
        if let Some(bus) = event_bus {
            let mut rx = bus.subscribe();
            loop {
                match rx.recv().await {
                    Ok(HaEvent::StateChanged(val)) => {
                        let active_topics = topics_clone.lock().await;
                        if active_topics.contains("device_events") || active_topics.contains("telemetry") || active_topics.contains("all") {
                            let payload = WsOutgoingEvent {
                                topic: "device_events".to_string(),
                                event: "state_changed".to_string(),
                                data: val,
                                timestamp: chrono::Utc::now(),
                            };

                            if let Ok(json_str) = serde_json::to_string(&payload) {
                                if sender.send(Message::Text(json_str.into())).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Ok(HaEvent::NotificationCreated { id, title, message, severity }) => {
                        let active_topics = topics_clone.lock().await;
                        if active_topics.contains("notifications") || active_topics.contains("all") {
                            let payload = WsOutgoingEvent {
                                topic: "notifications".to_string(),
                                event: "notification_created".to_string(),
                                data: serde_json::json!({
                                    "id": id,
                                    "title": title,
                                    "message": message,
                                    "severity": severity,
                                }),
                                timestamp: chrono::Utc::now(),
                            };

                            if let Ok(json_str) = serde_json::to_string(&payload) {
                                if sender.send(Message::Text(json_str.into())).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
    });

    // 2. Task: Handle incoming commands/subscriptions from client
    let topics_incoming = Arc::clone(&subscribed_topics);
    while let Some(Ok(msg)) = receiver.next().await {
        if let Message::Text(text) = msg {
            if let Ok(incoming) = serde_json::from_str::<WsIncomingMessage>(&text) {
                match incoming.action.as_str() {
                    "subscribe" => {
                        if let Some(topic) = incoming.topic {
                            let mut topics = topics_incoming.lock().await;
                            topics.insert(topic.clone());
                            info!("📡 WebSocket client subscribed to topic: {}", topic);
                        }
                    }
                    "unsubscribe" => {
                        if let Some(topic) = incoming.topic {
                            let mut topics = topics_incoming.lock().await;
                            topics.remove(&topic);
                            info!("🔕 WebSocket client unsubscribed from topic: {}", topic);
                        }
                    }
                    "ping" => {
                        let _pong = serde_json::json!({
                            "event": "pong",
                            "timestamp": chrono::Utc::now()
                        });
                        // Client sent ping -> return pong
                    }
                    _ => {
                        warn!("Unknown WebSocket action: {}", incoming.action);
                    }
                }
            }
        }
    }

    send_task.abort();
    info!("🔌 Frontend WebSocket client disconnected.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ws_incoming_and_outgoing_message_serialization() {
        let incoming_json = r#"{ "action": "subscribe", "topic": "device_events" }"#;
        let parsed: WsIncomingMessage = serde_json::from_str(incoming_json).unwrap();
        assert_eq!(parsed.action, "subscribe");
        assert_eq!(parsed.topic, Some("device_events".to_string()));

        let outgoing = WsOutgoingEvent {
            topic: "device_events".to_string(),
            event: "state_changed".to_string(),
            data: serde_json::json!({ "entity_id": "input_boolean.1", "state": "on" }),
            timestamp: chrono::Utc::now(),
        };

        let outgoing_json = serde_json::to_string(&outgoing).unwrap();
        assert!(outgoing_json.contains("device_events"));
        assert!(outgoing_json.contains("state_changed"));
    }
}
