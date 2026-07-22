use crate::runtime::config_store::ConfigStore;
use crate::runtime::event_bus::EventBus;
use crate::runtime::models::GuardianConfig;
use crate::runtime::runtime_manager::RuntimeManager;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
pub struct RuntimeApiState {
    pub manager: Arc<RuntimeManager>,
    pub event_bus: Arc<EventBus>,
}

pub fn build_wifi_router(manager: Arc<RuntimeManager>, event_bus: Arc<EventBus>) -> Router {
    let state = RuntimeApiState { manager, event_bus };
    Router::new()
        .route("/mode", get(get_mode).post(set_mode))
        .route("/scan", get(scan_networks))
        .route("/clients", get(get_connected_clients))
        .route("/stream", get(ws_handler))
        .with_state(state)
}

async fn get_mode(State(state): State<RuntimeApiState>) -> impl IntoResponse {
    let status = state.manager.state_machine.get_status().await;
    let config = ConfigStore::load().unwrap_or_default();

    let mode_str = match config.mode {
        crate::runtime::models::RuntimeMode::DualWifi => "dual",
        crate::runtime::models::RuntimeMode::HotspotOnly => "hotspot_only",
        crate::runtime::models::RuntimeMode::ClientOnly => "client_only",
        crate::runtime::models::RuntimeMode::Off => "off",
    };

    Json(json!({
        "mode": mode_str,
        "status": status,
        "module1": {
            "role": "ap",
            "ssid": config.hotspot.ssid,
            "channel": config.hotspot.channel
        },
        "module2": {
            "role": "client",
            "saved_networks": config.uplink.networks.iter().map(|n| n.ssid.clone()).collect::<Vec<String>>()
        },
        "security": {
            "zero_trust_active": status.state == crate::runtime::state::SystemState::DualActive,
            "suricata_running": false
        }
    }))
}

async fn set_mode(
    State(state): State<RuntimeApiState>,
    Json(payload): Json<GuardianConfig>,
) -> axum::response::Response {
    if payload.mode != crate::runtime::models::RuntimeMode::Off
        && payload.mode != crate::runtime::models::RuntimeMode::ClientOnly
    {
        if let Err(e) = crate::runtime::crypto::validate_hotspot_password(&payload.hotspot.password)
        {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": "error",
                    "message": e
                })),
            )
                .into_response();
        }
    }

    if let Err(e) = ConfigStore::save(&payload) {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "message": format!("Failed to persist configuration: {}", e)
            })),
        )
            .into_response();
    }

    let mgr = state.manager.clone();
    let mode = payload.mode;
    tokio::spawn(async move {
        mgr.supervise_transition(mode).await;
    });

    (
        axum::http::StatusCode::OK,
        Json(json!({
            "status": "applying",
            "estimated_downtime_seconds": 3
        })),
    )
        .into_response()
}

async fn scan_networks() -> impl IntoResponse {
    let settings = crate::netbridge::types::WifiClientSettings {
        interface: "wlan0".to_string(),
        ..Default::default()
    };
    let orchestrator = crate::netbridge::wifi_client::WifiClientOrchestrator::new(settings);

    let networks = orchestrator.scan_networks().unwrap_or_else(|e| {
        tracing::warn!("Network scan failed: {}", e);
        Vec::new()
    });

    Json(json!({
        "networks": networks
    }))
}

async fn get_connected_clients() -> impl IntoResponse {
    let manager = crate::netbridge::leases::LeaseManager::default();
    let leases = manager.get_active_leases().unwrap_or_else(|e| {
        tracing::warn!("Failed to read active DHCP leases: {}", e);
        Vec::new()
    });

    Json(json!({
        "clients": leases
    }))
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<RuntimeApiState>,
) -> impl IntoResponse {
    let event_bus = state.event_bus.clone();
    ws.on_upgrade(move |socket| handle_socket(socket, event_bus))
}

async fn handle_socket(mut socket: WebSocket, event_bus: Arc<EventBus>) {
    let mut rx = event_bus.subscribe();

    while let Ok(event) = rx.recv().await {
        if let Ok(msg) = serde_json::to_string(&event) {
            if socket.send(Message::Text(msg)).await.is_err() {
                break;
            }
        }
    }
}
