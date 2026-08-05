use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::api::handlers::pagination::{PaginatedResponse, PaginationParams};
use crate::api::state::AppState;
use crate::device::state::Device;

#[derive(Deserialize)]
pub struct DeviceFilterParams {
    pub room: Option<String>,
    pub device_type: Option<String>,
    pub search: Option<String>,
    #[serde(flatten)]
    pub pagination: PaginationParams,
}

#[derive(Deserialize)]
pub struct DeviceCommandPayload {
    pub command: String,
    pub domain: Option<String>,
    pub params: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct CommandResponse {
    pub status: String,
    pub command_id: String,
    pub message: String,
}

/// GET /api/devices?page=1&per_page=20&room=living_room&device_type=thermostat
pub async fn list_devices(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DeviceFilterParams>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let dm = match state.get_device_manager().await {
        Some(m) => m,
        None => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "DeviceManager not initialized" })),
            ))
        }
    };

    let all_devices = dm.get_registry().get_all_devices().await;

    let filtered: Vec<Device> = all_devices
        .into_iter()
        .filter(|d| {
            if let Some(ref room) = query.room {
                if d.room.as_deref() != Some(room.as_str()) {
                    return false;
                }
            }
            if let Some(ref dt) = query.device_type {
                if &d.device_type != dt {
                    return false;
                }
            }
            if let Some(ref search) = query.search {
                let term = search.to_lowercase();
                let matches_name = d.friendly_name.to_lowercase().contains(&term);
                let matches_entity = d.ha_entity_id.to_lowercase().contains(&term);
                if !matches_name && !matches_entity {
                    return false;
                }
            }
            true
        })
        .collect();

    let paginated = PaginatedResponse::paginate(filtered, &query.pagination, 20);

    Ok((StatusCode::OK, Json(serde_json::json!(paginated))))
}

async fn find_device(dm: &crate::device::manager::DeviceManager, id: &str) -> Option<Device> {
    let registry = dm.get_registry();
    if let Some(d) = registry.get_device(id).await {
        return Some(d);
    }
    registry.get_device_by_entity_id(id).await
}

/// GET /api/devices/{id}
pub async fn get_device(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let dm = match state.get_device_manager().await {
        Some(m) => m,
        None => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "DeviceManager not initialized" })),
            ))
        }
    };

    let device = find_device(&dm, &id).await.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("Device '{}' not found", id) })),
        )
    })?;

    Ok((StatusCode::OK, Json(serde_json::json!(device))))
}

/// GET /api/devices/{id}/state
pub async fn get_device_state(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let dm = match state.get_device_manager().await {
        Some(m) => m,
        None => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "DeviceManager not initialized" })),
            ))
        }
    };

    let device = find_device(&dm, &id).await.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("Device '{}' not found", id) })),
        )
    })?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "id": device.id,
            "ha_entity_id": device.ha_entity_id,
            "current_state": device.current_state,
            "health_status": device.health_status,
            "last_seen": device.last_seen,
        })),
    ))
}

/// POST /api/devices/{id}/command
pub async fn execute_device_command(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(payload): Json<DeviceCommandPayload>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let dm = match state.get_device_manager().await {
        Some(m) => m,
        None => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "DeviceManager not initialized" })),
            ))
        }
    };

    let device = find_device(&dm, &id).await.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("Device '{}' not found", id) })),
        )
    })?;

    // 1. Schema & Parameter Bounds Validation
    if let Err(e) = crate::api::auth::command_auth::CommandAuthorizer::validate_command_schema(
        &device.device_type,
        &payload.command,
        &payload.params,
    ) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        ));
    }

    // 2. Per-Device Rate Limiting (10 commands/min)
    if let Err(e) = state.device_rate_limiter.check_rate_limit(&device.id).await {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({ "error": e.to_string() })),
        ));
    }

    // 3. No-Op Command Rejection
    if let Err(e) = crate::api::auth::command_auth::CommandAuthorizer::check_no_op(
        &device.current_state,
        &payload.command,
        &payload.params,
    ) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        ));
    }

    let domain = payload.domain.unwrap_or_else(|| {
        device
            .ha_entity_id
            .split('.')
            .next()
            .unwrap_or("homeassistant")
            .to_string()
    });

    dm.send_command(
        &device.ha_entity_id,
        &domain,
        &payload.command,
        payload.params,
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e }))))?;

    let cmd_id = format!("cmd_{}", uuid::Uuid::new_v4().simple());

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "pending",
            "command_id": cmd_id,
            "message": format!("Command '{}' dispatched to {}", payload.command, device.friendly_name)
        })),
    ))
}

/// POST /api/devices/sync
pub async fn sync_devices(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let dm = match state.get_device_manager().await {
        Some(m) => m,
        None => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "DeviceManager not initialized" })),
            ))
        }
    };

    dm.reconcile_state().await;

    let devices = dm.get_registry().get_all_devices().await;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "synced",
            "total_devices": devices.len(),
            "message": format!("Successfully reconciled {} devices with Home Assistant", devices.len())
        })),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::state::Device;

    #[test]
    fn test_device_filter_and_command_payload_json() {
        let payload_json = r#"{
            "command": "turn_on",
            "domain": "light",
            "params": { "brightness": 255 }
        }"#;

        let parsed: DeviceCommandPayload = serde_json::from_str(payload_json).unwrap();
        assert_eq!(parsed.command, "turn_on");
        assert_eq!(parsed.domain, Some("light".to_string()));
        assert!(parsed.params.is_some());

        let dev = Device {
            id: "dev_test_001".to_string(),
            ha_entity_id: "light.living_room_light".to_string(),
            vendor: "Home Assistant".to_string(),
            device_type: "light".to_string(),
            room: Some("Living Room".to_string()),
            friendly_name: "Living Room Light".to_string(),
            current_state: "on".to_string(),
            health_status: crate::device::state::DeviceHealth::Online,
            last_seen: chrono::Utc::now(),
        };
        assert_eq!(dev.ha_entity_id, "light.living_room_light");
    }
}
