use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use crate::api::handlers::pagination::{PaginatedResponse, PaginationParams};
use crate::api::state::AppState;
use crate::device::state::DeviceHealth;
use crate::storage::resolve_telemetry_dir;

#[derive(Deserialize)]
pub struct TelemetryQueryParams {
    pub device_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    #[serde(flatten)]
    pub pagination: PaginationParams,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TelemetryRecord {
    pub entity_id: String,
    pub state: String,
    pub attributes: serde_json::Value,
    pub timestamp: String,
}

#[derive(Serialize)]
pub struct DeviceHealthSummary {
    pub total_devices: usize,
    pub online_devices: usize,
    pub offline_devices: usize,
    pub error_devices: usize,
    pub healthy_percentage: f64,
}

/// GET /api/telemetry?page=1&per_page=50&from=...&to=...
pub async fn list_telemetry(
    State(_state): State<Arc<AppState>>,
    Query(query): Query<TelemetryQueryParams>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let records = read_telemetry_logs(query.device_id.as_deref());
    let paginated = PaginatedResponse::paginate(records, &query.pagination, 50);

    Ok((StatusCode::OK, Json(serde_json::json!(paginated))))
}

/// GET /api/telemetry/{device_id}?page=1&per_page=50
pub async fn get_device_telemetry(
    State(_state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Query(query): Query<TelemetryQueryParams>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let records = read_telemetry_logs(Some(&device_id));
    let paginated = PaginatedResponse::paginate(records, &query.pagination, 50);

    Ok((StatusCode::OK, Json(serde_json::json!(paginated))))
}

/// GET /api/device-health
pub async fn get_device_health(
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

    let devices = dm.get_registry().get_all_devices().await;

    let total = devices.len();
    let mut online = 0;
    let mut offline = 0;
    let mut error = 0;
    for d in &devices {
        match d.health_status {
            DeviceHealth::Online => online += 1,
            DeviceHealth::Offline => offline += 1,
            _ => error += 1,
        }
    }

    let pct = if total == 0 {
        100.0
    } else {
        (online as f64 / total as f64) * 100.0
    };

    let summary = DeviceHealthSummary {
        total_devices: total,
        online_devices: online,
        offline_devices: offline,
        error_devices: error,
        healthy_percentage: pct,
    };

    Ok((StatusCode::OK, Json(serde_json::json!(summary))))
}

/// Helper function to parse telemetry JSON logs from telemetry directory
fn read_telemetry_logs(filter_entity: Option<&str>) -> Vec<TelemetryRecord> {
    let mut records = Vec::new();
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let filename = format!("ha_telemetry_{}.log", today);
    let log_dir = resolve_telemetry_dir();
    let log_path = log_dir.join(&filename);

    let content = match fs::read_to_string(&log_path) {
        Ok(c) => c,
        Err(_) => {
            // Fallback: search local telemetry/ directory
            let local_path = PathBuf::from("telemetry").join(&filename);
            fs::read_to_string(&local_path).unwrap_or_default()
        }
    };

    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(record) = serde_json::from_str::<TelemetryRecord>(line) {
            if let Some(target) = filter_entity {
                if record.entity_id != target {
                    continue;
                }
            }
            records.push(record);
        }
    }

    records.reverse(); // Newest first
    records
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_record_parsing() {
        let json_line = r#"{"attributes":{"friendly_name":"Toggle 1"},"entity_id":"input_boolean.1","state":"on","timestamp":"2026-07-25T10:00:00Z"}"#;
        let record: TelemetryRecord = serde_json::from_str(json_line).unwrap();

        assert_eq!(record.entity_id, "input_boolean.1");
        assert_eq!(record.state, "on");
        assert_eq!(record.attributes["friendly_name"], "Toggle 1");
    }

    #[tokio::test]
    async fn telemetry_handlers_cover_empty_logs_filters_and_missing_device_manager() {
        let temp = tempfile::tempdir().expect("state directory");
        let state = AppState::for_tests(temp.path(), "nodeA", temp.path().to_string_lossy());
        let query = || TelemetryQueryParams {
            device_id: Some("missing.entity".into()),
            from: Some("2026-01-01T00:00:00Z".into()),
            to: Some("2026-12-31T00:00:00Z".into()),
            pagination: PaginationParams {
                page: Some(99),
                per_page: Some(1),
            },
        };

        assert_eq!(
            list_telemetry(State(state.clone()), Query(query()))
                .await
                .expect("list telemetry")
                .into_response()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            get_device_telemetry(
                State(state.clone()),
                Path("missing.entity".into()),
                Query(query()),
            )
            .await
            .expect("device telemetry")
            .into_response()
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            get_device_health(State(state))
                .await
                .err()
                .expect("health without manager")
                .0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(read_telemetry_logs(Some("definitely.missing")).is_empty());
    }
}
