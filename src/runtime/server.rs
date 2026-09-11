use crate::netbridge::backend::NetworkBackend;
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
    let suricata_running = tokio::process::Command::new("systemctl")
        .args(["is-active", "--quiet", "suricata"])
        .status()
        .await
        .map(|status| status.success())
        .unwrap_or(false);

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
            "suricata_running": suricata_running
        }
    }))
}

async fn set_mode(
    State(state): State<RuntimeApiState>,
    Json(payload): Json<GuardianConfig>,
) -> axum::response::Response {
    tracing::info!(
        "REST /wifi/mode POST received: target_mode={:?}, hotspot_iface={}, hotspot_ssid={}, uplink_iface={}, uplink_networks={}",
        payload.mode,
        payload.hotspot.interface,
        payload.hotspot.ssid,
        payload.uplink.interface,
        payload
            .uplink
            .networks
            .iter()
            .map(|n| n.ssid.clone())
            .collect::<Vec<String>>()
            .join(",")
    );

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

async fn scan_networks() -> axum::response::Response {
    let config = ConfigStore::load().unwrap_or_default();
    let uplink_iface = if !config.uplink.interface.is_empty() {
        config.uplink.interface
    } else {
        crate::netbridge::backend::DEFAULT_NM_UPLINK_INTERFACE.to_string()
    };

    let result = match crate::netbridge::network_manager::NetworkManagerBackend::system(
        std::time::Duration::from_secs(5),
    )
    .await
    {
        Ok(backend) => backend.scan(&uplink_iface).await,
        Err(error) => Err(error),
    };
    match result {
        Ok(mut networks) => {
            // Never list Guardian's own hotspot as a connectable upstream network —
            // the uplink radio can physically hear the AP radio's beacon on some
            // boards, but this is our own broadcast, not a real upstream option.
            let own_hotspot_ssid = if config.hotspot.ssid.trim().is_empty() {
                RuntimeManager::default_hotspot_ssid().to_string()
            } else {
                config.hotspot.ssid.clone()
            };
            networks.retain(|network| network.ssid != own_hotspot_ssid);
            Json(json!({ "networks": networks })).into_response()
        }
        Err(error) => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "networks": [],
                "error": { "code": error.code(), "message": error.to_string() }
            })),
        )
            .into_response(),
    }
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
            if socket.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    }
}
