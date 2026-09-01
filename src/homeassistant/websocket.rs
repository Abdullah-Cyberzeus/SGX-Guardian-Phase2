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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::homeassistant::events::HaEvent;
    use std::net::SocketAddr;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_tungstenite::WebSocketStream;

    /// Reserves an ephemeral loopback port and immediately releases it, so a connection
    /// attempt against it fails fast with "connection refused" instead of hanging.
    async fn unused_loopback_addr() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        drop(listener);
        addr
    }

    fn test_config(addr: SocketAddr) -> HomeAssistantConfig {
        HomeAssistantConfig {
            url: format!("http://{}", addr),
            token: "test-token".to_string(),
        }
    }

    /// Spawns a one-shot loopback WebSocket "server" that runs `script` against the first
    /// accepted connection, then returns the address to connect to.
    async fn spawn_mock_server<F, Fut>(script: F) -> SocketAddr
    where
        F: FnOnce(WebSocketStream<TcpStream>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let ws = tokio_tungstenite::accept_async(stream)
                .await
                .expect("ws handshake");
            script(ws).await;
        });
        addr
    }

    #[tokio::test]
    async fn connect_error_when_nothing_listening() {
        let addr = unused_loopback_addr().await;
        let config = test_config(addr);
        let event_bus = EventBus::new();

        let result = timeout(
            Duration::from_secs(5),
            ws_connection_loop(&config, &event_bus),
        )
        .await
        .expect("loop should not hang against a closed port");

        let err = result.expect_err("connecting to a closed port must fail");
        assert!(
            err.contains("WS Connect Error") || err.contains("Timeout"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn initial_non_json_message_is_reported_as_parse_error() {
        let addr = spawn_mock_server(|ws| async move {
            let (mut write, _read) = ws.split();
            // Not valid JSON — the connect loop must surface this as an error rather than
            // panicking while waiting for `auth_required`.
            let _ = write.send(Message::Text("not-json".into())).await;
        })
        .await;

        let config = test_config(addr);
        let event_bus = EventBus::new();

        let result = timeout(
            Duration::from_secs(5),
            ws_connection_loop(&config, &event_bus),
        )
        .await
        .expect("loop should finish");

        assert!(result.is_err(), "malformed auth message must error out");
    }

    #[tokio::test]
    async fn auth_rejection_is_reported() {
        let addr = spawn_mock_server(|ws| async move {
            let (mut write, mut read) = ws.split();
            write
                .send(Message::Text(
                    json!({ "type": "auth_required" }).to_string().into(),
                ))
                .await
                .expect("send auth_required");
            let _auth_msg = read.next().await; // consume the client's `auth` message
            write
                .send(Message::Text(
                    json!({ "type": "auth_invalid", "message": "bad token" })
                        .to_string()
                        .into(),
                ))
                .await
                .expect("send auth_invalid");
        })
        .await;

        let config = test_config(addr);
        let event_bus = EventBus::new();

        let result = timeout(
            Duration::from_secs(5),
            ws_connection_loop(&config, &event_bus),
        )
        .await
        .expect("loop should finish");

        let err = result.expect_err("rejected auth must be surfaced as an error");
        assert_eq!(err, "HA Auth Failed");
    }

    #[tokio::test]
    async fn successful_auth_and_event_publishes_to_bus() {
        let addr = spawn_mock_server(|ws| async move {
            let (mut write, mut read) = ws.split();
            write
                .send(Message::Text(
                    json!({ "type": "auth_required" }).to_string().into(),
                ))
                .await
                .expect("send auth_required");
            let _auth_msg = read.next().await;
            write
                .send(Message::Text(
                    json!({ "type": "auth_ok" }).to_string().into(),
                ))
                .await
                .expect("send auth_ok");

            // Consume the three subscribe_events messages the client sends after auth.
            for _ in 0..3 {
                let _ = read.next().await;
            }

            let event = json!({
                "type": "event",
                "event": {
                    "event_type": "state_changed",
                    "data": { "entity_id": "light.kitchen", "state": "on" }
                }
            });
            write
                .send(Message::Text(event.to_string().into()))
                .await
                .expect("send state_changed event");

            // Let the client drain the message before we drop the connection.
            tokio::time::sleep(Duration::from_millis(150)).await;
        })
        .await;

        let config = test_config(addr);
        let event_bus = EventBus::new();
        let mut rx = event_bus.subscribe();

        let result = timeout(
            Duration::from_secs(5),
            ws_connection_loop(&config, &event_bus),
        )
        .await
        .expect("loop should finish once the mock server closes the socket");

        // The mock server closes the connection after sending the event, so the loop must
        // report the disconnect.
        assert!(result.is_err());

        let received = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("event should have been published")
            .expect("channel should not be closed");

        match received {
            HaEvent::StateChanged(val) => {
                // `event_data` in the connection loop is the whole `event` payload
                // (`{event_type, data}`), not just its inner `data` — the fields under
                // test live at `val["data"]`, not directly on `val`.
                assert_eq!(val["data"]["entity_id"], "light.kitchen");
                assert_eq!(val["data"]["state"], "on");
            }
            other => panic!("expected StateChanged, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_event_type_is_published_as_unknown() {
        let addr = spawn_mock_server(|ws| async move {
            let (mut write, mut read) = ws.split();
            write
                .send(Message::Text(
                    json!({ "type": "auth_required" }).to_string().into(),
                ))
                .await
                .expect("send auth_required");
            let _auth_msg = read.next().await;
            write
                .send(Message::Text(
                    json!({ "type": "auth_ok" }).to_string().into(),
                ))
                .await
                .expect("send auth_ok");
            for _ in 0..3 {
                let _ = read.next().await;
            }

            let event = json!({
                "type": "event",
                "event": {
                    "event_type": "some_custom_event",
                    "data": { "foo": "bar" }
                }
            });
            write
                .send(Message::Text(event.to_string().into()))
                .await
                .expect("send custom event");
            tokio::time::sleep(Duration::from_millis(150)).await;
        })
        .await;

        let config = test_config(addr);
        let event_bus = EventBus::new();
        let mut rx = event_bus.subscribe();

        let _ = timeout(
            Duration::from_secs(5),
            ws_connection_loop(&config, &event_bus),
        )
        .await
        .expect("loop should finish");

        let received = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("event should have been published")
            .expect("channel should not be closed");

        assert!(matches!(received, HaEvent::Unknown(_)));
    }

    #[tokio::test]
    async fn malformed_event_message_is_ignored_not_fatal() {
        let addr = spawn_mock_server(|ws| async move {
            let (mut write, mut read) = ws.split();
            write
                .send(Message::Text(
                    json!({ "type": "auth_required" }).to_string().into(),
                ))
                .await
                .expect("send auth_required");
            let _auth_msg = read.next().await;
            write
                .send(Message::Text(
                    json!({ "type": "auth_ok" }).to_string().into(),
                ))
                .await
                .expect("send auth_ok");
            for _ in 0..3 {
                let _ = read.next().await;
            }

            // Malformed JSON during the steady-state loop must be swallowed, not crash the
            // connection — only the closing of the socket below should end the loop.
            let _ = write.send(Message::Text("{ not valid".into())).await;
            tokio::time::sleep(Duration::from_millis(150)).await;
        })
        .await;

        let config = test_config(addr);
        let event_bus = EventBus::new();
        let mut rx = event_bus.subscribe();

        let result = timeout(
            Duration::from_secs(5),
            ws_connection_loop(&config, &event_bus),
        )
        .await
        .expect("loop should finish once the mock server closes the socket");

        assert!(result.is_err());
        assert!(
            rx.try_recv().is_err(),
            "no event should have been published for malformed input"
        );
    }

    #[tokio::test]
    async fn device_and_entity_registry_events_dispatch_to_their_own_variants() {
        let addr = spawn_mock_server(|ws| async move {
            let (mut write, mut read) = ws.split();
            write
                .send(Message::Text(
                    json!({ "type": "auth_required" }).to_string().into(),
                ))
                .await
                .expect("send auth_required");
            let _auth_msg = read.next().await;
            write
                .send(Message::Text(
                    json!({ "type": "auth_ok" }).to_string().into(),
                ))
                .await
                .expect("send auth_ok");
            for _ in 0..3 {
                let _ = read.next().await;
            }

            for event_type in ["device_registry_updated", "entity_registry_updated"] {
                let event = json!({
                    "type": "event",
                    "event": { "event_type": event_type, "data": { "action": "update" } }
                });
                write
                    .send(Message::Text(event.to_string().into()))
                    .await
                    .expect("send registry event");
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        })
        .await;

        let config = test_config(addr);
        let event_bus = EventBus::new();
        let mut rx = event_bus.subscribe();

        let _ = timeout(
            Duration::from_secs(5),
            ws_connection_loop(&config, &event_bus),
        )
        .await
        .expect("loop should finish");

        let first = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("first registry event")
            .expect("channel open");
        assert!(matches!(first, HaEvent::DeviceRegistryUpdated(_)));

        let second = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("second registry event")
            .expect("channel open");
        assert!(matches!(second, HaEvent::EntityRegistryUpdated(_)));
    }

    // The ping-send (30s) and pong-timeout (10s) branches are real-time-gated inside the
    // same `select!` as the message-read arm and aren't reachable without either a genuine
    // multi-second wait or fighting `tokio::time::pause`'s auto-advance semantics against a
    // concurrently IO-blocked mock server task — not attempted this pass; same category as
    // the other daemon/heartbeat loops left as a structural ceiling elsewhere in this wave.
}
