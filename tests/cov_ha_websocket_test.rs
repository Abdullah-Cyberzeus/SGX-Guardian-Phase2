// Integration test for the real-time frontend WebSocket handler
// (src/api/handlers/ha_websocket.rs). This handler's core logic lives
// entirely inside `handle_websocket_session`, spawned from a real
// `axum::extract::ws::WebSocket` -- there's no way to construct one of those
// synthetically outside axum's own upgrade machinery, so this test binds a
// real loopback TCP listener and drives the handler with a real WebSocket
// client (`tokio-tungstenite`), matching the pattern already used by
// `tests/api_handler_test.rs` for plain HTTP.

use futures_util::{SinkExt, StreamExt};
use sgx_guardian_client::api::state::AppState;
use sgx_guardian_client::homeassistant::events::{EventBus, HaEvent};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as WsMessage;

/// Issues a real bearer token for a device-level Owner admin, the same way
/// `tests/wave_b_support::Env::owner_token` does -- duplicated here rather
/// than shared since that fixture's Circle-owner bootstrap isn't needed for
/// a WebSocket-only test.
async fn owner_token(state: &Arc<AppState>) -> String {
    use sgx_guardian_client::api::auth::session;
    use sgx_guardian_client::api::auth::store::{NewUser, UserRole};

    let user = state
        .admin
        .users
        .create(NewUser {
            name: "WS Test Owner".into(),
            email: format!("ws-test-owner-{}@example.com", uuid::Uuid::new_v4()),
            pw_hash: "test-hash".into(),
            role: UserRole::Owner,
            oidc_sub: None,
        })
        .await
        .expect("seed owner user");
    let (token, _, session_rec) = session::issue(
        state.signer.clone(),
        &state.device_did,
        &user,
        std::time::Duration::from_secs(300),
    )
    .await
    .expect("issue token");
    state
        .admin
        .sessions
        .put(session_rec)
        .await
        .expect("store session");
    token
}

async fn spawn_router_with_event_bus(
    temp_dir: &std::path::Path,
) -> (String, Arc<AppState>, Arc<EventBus>, String) {
    let state = AppState::for_tests(
        temp_dir,
        "nodeA",
        temp_dir.join("config").to_string_lossy().to_string(),
    );
    let bus = EventBus::new();
    *state.ha_event_bus.write().await = Some(bus.clone());
    let token = owner_token(&state).await;
    let app = sgx_guardian_client::api::build_router(state.clone(), axum::Router::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    (format!("ws://{addr}/api/v1/ha/ws"), state, bus, token)
}

fn authed_ws_request(
    ws_url: &str,
    token: &str,
) -> tokio_tungstenite::tungstenite::http::Request<()> {
    let mut request = ws_url.into_client_request().expect("valid ws request");
    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {token}")
            .parse()
            .expect("valid header value"),
    );
    request
}

#[tokio::test]
async fn forwards_subscribed_state_changed_events_to_the_client() {
    let temp = TempDir::new().unwrap();
    let (ws_url, _state, bus, token) = spawn_router_with_event_bus(temp.path()).await;

    let (mut socket, _response) =
        tokio_tungstenite::connect_async(authed_ws_request(&ws_url, &token))
            .await
            .expect("websocket upgrade succeeds");

    // The client is auto-subscribed to "device_events" on connect, so a
    // StateChanged event is forwarded without any subscribe message needed.
    // Give the server's send task a moment to finish spawning and subscribing.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    bus.publish(HaEvent::StateChanged(
        serde_json::json!({"entity_id": "light.kitchen", "state": "on"}),
    ));

    let message = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
        .await
        .expect("event arrives before timeout")
        .expect("stream yields a message")
        .expect("message is not an error");
    let WsMessage::Text(text) = message else {
        panic!("expected a text frame, got {message:?}");
    };
    let payload: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
    assert_eq!(payload["topic"], "device_events");
    assert_eq!(payload["event"], "state_changed");
    assert_eq!(payload["data"]["entity_id"], "light.kitchen");

    socket.close(None).await.ok();
}

#[tokio::test]
async fn does_not_forward_notifications_until_the_client_subscribes() {
    let temp = TempDir::new().unwrap();
    let (ws_url, _state, bus, token) = spawn_router_with_event_bus(temp.path()).await;
    let (mut socket, _) = tokio_tungstenite::connect_async(authed_ws_request(&ws_url, &token))
        .await
        .expect("websocket upgrade succeeds");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Not subscribed to "notifications" yet: publishing one must not arrive.
    bus.publish(HaEvent::NotificationCreated {
        id: "notif-1".into(),
        title: "Test".into(),
        message: "Hello".into(),
        severity: "info".into(),
    });
    let unsubscribed_result =
        tokio::time::timeout(std::time::Duration::from_millis(300), socket.next()).await;
    assert!(
        unsubscribed_result.is_err(),
        "must not receive a notification before subscribing"
    );

    // Subscribe, then the same kind of event must arrive.
    socket
        .send(WsMessage::Text(
            serde_json::json!({"action": "subscribe", "topic": "notifications"})
                .to_string()
                .into(),
        ))
        .await
        .expect("send subscribe");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    bus.publish(HaEvent::NotificationCreated {
        id: "notif-2".into(),
        title: "Test 2".into(),
        message: "Hello again".into(),
        severity: "warning".into(),
    });
    let message = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
        .await
        .expect("event arrives before timeout")
        .expect("stream yields a message")
        .expect("message is not an error");
    let WsMessage::Text(text) = message else {
        panic!("expected a text frame, got {message:?}");
    };
    let payload: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
    assert_eq!(payload["topic"], "notifications");
    assert_eq!(payload["data"]["id"], "notif-2");

    socket.close(None).await.ok();
}

#[tokio::test]
async fn unsubscribing_stops_further_delivery_and_unknown_actions_are_ignored() {
    let temp = TempDir::new().unwrap();
    let (ws_url, _state, bus, token) = spawn_router_with_event_bus(temp.path()).await;
    let (mut socket, _) = tokio_tungstenite::connect_async(authed_ws_request(&ws_url, &token))
        .await
        .expect("websocket upgrade succeeds");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // An unrecognized action is logged and otherwise ignored -- must not
    // crash the session or affect the default "device_events" subscription.
    socket
        .send(WsMessage::Text(
            serde_json::json!({"action": "not-a-real-action"})
                .to_string()
                .into(),
        ))
        .await
        .expect("send unknown action");

    // Unsubscribe from the default topic.
    socket
        .send(WsMessage::Text(
            serde_json::json!({"action": "unsubscribe", "topic": "device_events"})
                .to_string()
                .into(),
        ))
        .await
        .expect("send unsubscribe");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    bus.publish(HaEvent::StateChanged(
        serde_json::json!({"entity_id": "light.kitchen", "state": "off"}),
    ));
    let result = tokio::time::timeout(std::time::Duration::from_millis(300), socket.next()).await;
    assert!(
        result.is_err(),
        "must not receive state_changed after unsubscribing from device_events"
    );

    socket.close(None).await.ok();
}
