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
            // Live readings (current temperature, humidity, hvac_action, ...) so the control
            // dialog can refresh without re-fetching the full capability document.
            "attributes": device.attributes,
            "temperature_unit": dm.temperature_unit().await,
        })),
    ))
}

/// GET /api/devices/{id}/capabilities
///
/// Describes what this device can actually do, derived from its Home Assistant attributes.
/// The UI renders its controls exclusively from this, so an option appears only when the
/// device really supports it.
pub async fn get_device_capabilities(
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

    let mut device = find_device(&dm, &id).await.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("Device '{}' not found", id) })),
        )
    })?;

    // A registry entry written before attributes were captured (or one that has not been
    // reconciled yet) carries none. Fetch them on demand so the dialog is never empty.
    if device.attributes.is_empty() {
        match dm.refresh_device_attributes(&device.ha_entity_id).await {
            Ok(Some(refreshed)) => device = refreshed,
            Ok(None) => {}
            Err(e) => {
                // Degrade to whatever is cached rather than failing the request — an HA
                // outage must not blank out the controls.
                tracing::warn!(
                    "Could not refresh attributes for {}: {}",
                    device.ha_entity_id,
                    e
                );
            }
        }
    }

    let caps = dm.capabilities_for(&device).await;
    Ok((StatusCode::OK, Json(serde_json::json!(caps))))
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

    // 1. Schema & Parameter Bounds Validation, against this device's real capabilities
    let caps = dm.capabilities_for(&device).await;
    if let Err(e) = crate::api::auth::command_auth::CommandAuthorizer::validate_command_schema(
        &caps,
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
        &device,
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

    // Generated before dispatch so the id appears in logs alongside the attempt.
    let cmd_id = format!("cmd_{}", uuid::Uuid::new_v4().simple());
    let echoed_params = payload.params.clone();

    if let Err(e) = dm
        .send_command(
            &device.ha_entity_id,
            &domain,
            &payload.command,
            payload.params,
        )
        .await
    {
        // Distinguish caller error from upstream failure instead of collapsing to a 500.
        let status = if e.starts_with("invalid command:") {
            StatusCode::BAD_REQUEST
        } else if e.contains("not found in registry") {
            StatusCode::NOT_FOUND
        } else if e.contains("Circuit breaker") {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            // Home Assistant refused or was unreachable — an upstream problem.
            StatusCode::BAD_GATEWAY
        };
        return Err((
            status,
            Json(serde_json::json!({ "error": e, "command_id": cmd_id })),
        ));
    }

    // Home Assistant returns 2xx only after the service handler completes, so the command
    // is accepted at this point. The confirmed state arrives over the WebSocket shortly after.
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "accepted",
            "command_id": cmd_id,
            "entity_id": device.ha_entity_id,
            "command": payload.command,
            "params": echoed_params,
            "accepted_at": chrono::Utc::now(),
            "message": format!("{} sent to {}", payload.command, device.friendly_name)
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
            attributes: Default::default(),
        };
        assert_eq!(dev.ha_entity_id, "light.living_room_light");
    }

    #[tokio::test]
    async fn every_device_handler_reports_service_unavailable_without_manager() {
        let temp = tempfile::tempdir().expect("state directory");
        let state = AppState::for_tests(temp.path(), "nodeA", temp.path().to_string_lossy());
        let query = DeviceFilterParams {
            room: Some("Kitchen".into()),
            device_type: Some("light".into()),
            search: Some("lamp".into()),
            pagination: PaginationParams {
                page: Some(1),
                per_page: Some(10),
            },
        };
        assert_eq!(
            list_devices(State(state.clone()), Query(query))
                .await
                .err()
                .expect("list without manager")
                .0,
            StatusCode::SERVICE_UNAVAILABLE
        );

        let id = || Path("missing-device".to_string());
        let statuses = [
            get_device(State(state.clone()), id())
                .await
                .err()
                .expect("get without manager")
                .0,
            get_device_state(State(state.clone()), id())
                .await
                .err()
                .expect("state without manager")
                .0,
            get_device_capabilities(State(state.clone()), id())
                .await
                .err()
                .expect("capabilities without manager")
                .0,
            execute_device_command(
                State(state.clone()),
                id(),
                Json(DeviceCommandPayload {
                    command: "turn_on".into(),
                    domain: None,
                    params: None,
                }),
            )
            .await
            .err()
            .expect("command without manager")
            .0,
            sync_devices(State(state))
                .await
                .err()
                .expect("sync without manager")
                .0,
        ];
        assert!(statuses
            .into_iter()
            .all(|status| status == StatusCode::SERVICE_UNAVAILABLE));
    }
}
