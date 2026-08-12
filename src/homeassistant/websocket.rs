use crate::homeassistant::events::EventBus;
use crate::homeassistant::HomeAssistantConfig;
use crate::logging::log_event;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::sync::Arc;
use tokio::time::{sleep, timeout, Duration};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};

async fn ws_connection_loop(
    config: &HomeAssistantConfig,
    event_bus: &Arc<EventBus>,
) -> Result<(), String> {
    let mut ws_url = config
        .url
        .replace("http://", "ws://")
        .replace("https://", "wss://");
    ws_url.push_str("/api/websocket");

    // Attempt connection
    let (ws_stream, _) = match timeout(Duration::from_secs(10), connect_async(&ws_url)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => return Err(format!("WS Connect Error: {}", e)),
        Err(_) => return Err("WS Connect Timeout".to_string()),
    };

    println!("✅ Connected to Home Assistant WebSocket!");

    let (mut write, mut read) = ws_stream.split();
    let mut current_id = 1;

    // Wait for auth_required
    if let Some(msg) = read.next().await {
        let msg = msg.map_err(|e| e.to_string())?;
        if let Message::Text(text) = msg {
            let parsed: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| e.to_string())?;
            if parsed["type"] == "auth_required" {
                println!("🔐 Authenticating with Home Assistant...");
                let auth_msg = json!({
                    "type": "auth",
                    "access_token": config.token
                });
                write
                    .send(Message::Text(auth_msg.to_string().into()))
                    .await
                    .map_err(|e| e.to_string())?;
            }
        }
    }

    // Wait for auth_ok
    if let Some(msg) = read.next().await {
        let msg = msg.map_err(|e| e.to_string())?;
        if let Message::Text(text) = msg {
            let parsed: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| e.to_string())?;
            if parsed["type"] == "auth_ok" {
                println!("🎉 Successfully authenticated with Home Assistant!");
                log_event("homeassistant", "WebSocket authenticated successfully");
            } else {
                eprintln!("❌ Authentication failed: {:?}", parsed);
                return Err("HA Auth Failed".into());
            }
        }
    }

    // Requirement: Subscribe to state_changed, device_registry_updated, entity_registry_updated
    let events = vec![
        "state_changed",
        "device_registry_updated",
        "entity_registry_updated",
    ];
    for event_type in events {
        let sub_msg = json!({
            "id": current_id,
            "type": "subscribe_events",
            "event_type": event_type
        });
        write
            .send(Message::Text(sub_msg.to_string().into()))
            .await
            .map_err(|e| e.to_string())?;
        current_id += 1;
    }
    println!("📡 Subscribed to HA event streams.");

    // Requirement: Ping/Pong Heartbeat (30s interval, 10s timeout)
    let mut last_ping = tokio::time::Instant::now();
    let mut ping_id;
    let mut waiting_for_pong = false;

    loop {
        // We use tokio::select! to handle reading messages OR sending the ping timer
        tokio::select! {
            // Read incoming WS messages
            msg_opt = read.next() => {
                match msg_opt {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
                            // Handle Pong response
                            if parsed["type"] == "pong" {
                                waiting_for_pong = false;
                            } else if parsed["type"] == "event" {
                                if let Some(event_type) = parsed.get("event").and_then(|e| e.get("event_type")).and_then(|s| s.as_str()) {
                                    let event_data = parsed.get("event").cloned().unwrap_or_default();
                                    let ha_event = match event_type {
                                        "state_changed" => crate::homeassistant::events::HaEvent::StateChanged(event_data),
                                        "device_registry_updated" => crate::homeassistant::events::HaEvent::DeviceRegistryUpdated(event_data),
                                        "entity_registry_updated" => crate::homeassistant::events::HaEvent::EntityRegistryUpdated(event_data),
                                        _ => crate::homeassistant::events::HaEvent::Unknown(event_data),
                                    };
                                    event_bus.publish(ha_event);
                                }
                            }
                        }
                    }
                    Some(Err(e)) => {
                        return Err(format!("WS Read Error: {}", e));
                    }
                    None => {
                        return Err("WS Stream closed by remote".to_string());
                    }
                    _ => {}
                }
            }
            // Timer for ping (30 seconds)
            _ = sleep(Duration::from_millis(500)) => {
                let now = tokio::time::Instant::now();
                if waiting_for_pong && now.duration_since(last_ping) > Duration::from_secs(10) {
                    return Err("Pong timeout (10s) exceeded".to_string());
                }

                if now.duration_since(last_ping) >= Duration::from_secs(30) {
                    // Send Ping
                    waiting_for_pong = true;
                    last_ping = now;
                    ping_id = current_id;
                    current_id += 1;
                    let ping_msg = json!({
                        "id": ping_id,
                        "type": "ping"
                    });
                    if let Err(e) = write.send(Message::Text(ping_msg.to_string().into())).await {
                        return Err(format!("Failed to send ping: {}", e));
                    }
                }
            }
        }
    }
}

/// Start the WebSocket client with Reconnect & Exponential Backoff
pub async fn start_websocket_client(config: HomeAssistantConfig, event_bus: Arc<EventBus>) {
    tokio::spawn(async move {
        let mut backoff = 1; // Start with 1s backoff
        loop {
            println!("🔄 Starting Home Assistant WebSocket Connection...");
            match ws_connection_loop(&config, &event_bus).await {
                Ok(_) => {
                    println!("🔌 WS Loop exited normally (unexpected).");
                    backoff = 1;
                }
                Err(e) => {
                    eprintln!("⚠️ HA WebSocket Disconnected: {}", e);
                }
            }

            // Reconnect with exponential backoff capped at 60s
            println!("⏱️ Reconnecting in {} seconds...", backoff);
            sleep(Duration::from_secs(backoff)).await;
            backoff = std::cmp::min(backoff * 2, 60);
        }
    });
}
