use crate::api::{error::ApiError, state::AppState};
use axum::{
    extract::{Path, State},
    Json,
};
use serde_json::{json, Value};
use sgx_anomaly_engine::threat_prediction::ThreatPredictionConfig;
use std::fs;
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;

pub async fn status(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    if let Some(handle) = state.task4_threat_prediction.read().await.clone() {
        return Ok(Json(serde_json::to_value(handle.status().await)?));
    }
    read_runtime_json(&state, "runtime_status.json").map(Json)
}

pub async fn get_config(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let handle = state
        .task4_threat_prediction
        .read()
        .await
        .clone()
        .ok_or_else(|| ApiError::ServiceUnavailable {
            code: "TASK4_RUNTIME_UNAVAILABLE",
            message: "Task4 threat prediction runtime is unavailable".into(),
        })?;

    Ok(Json(serde_json::to_value(
        handle.prediction_config().await,
    )?))
}

pub async fn set_config(
    State(state): State<Arc<AppState>>,
    Json(config): Json<ThreatPredictionConfig>,
) -> Result<Json<Value>, ApiError> {
    config
        .validate()
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;

    let handle = state
        .task4_threat_prediction
        .read()
        .await
        .clone()
        .ok_or_else(|| ApiError::ServiceUnavailable {
            code: "TASK4_RUNTIME_UNAVAILABLE",
            message: "Task4 threat prediction runtime is unavailable".into(),
        })?;

    let status = handle
        .update_prediction_config(config)
        .await
        .map_err(|error| ApiError::Internal(error.to_string()))?;

    Ok(Json(json!({
        "schema_version": "task4-runtime-config-update-v1",
        "updated": true,
        "enabled": status.enabled,
        "status": status
    })))
}

pub async fn enable(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    set_enabled(state, true).await
}

pub async fn disable(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    set_enabled(state, false).await
}

async fn set_enabled(state: Arc<AppState>, enabled: bool) -> Result<Json<Value>, ApiError> {
    let handle = state
        .task4_threat_prediction
        .read()
        .await
        .clone()
        .ok_or_else(|| ApiError::ServiceUnavailable {
            code: "TASK4_RUNTIME_UNAVAILABLE",
            message: "Task4 threat prediction runtime is unavailable".into(),
        })?;

    let status = handle
        .set_enabled(enabled)
        .await
        .map_err(|error| ApiError::Internal(error.to_string()))?;

    Ok(Json(json!({
        "schema_version": "task4-runtime-enable-state-v1",
        "enabled": status.enabled,
        "status": status
    })))
}

pub async fn forecasts(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    read_runtime_json(&state, "current_forecasts.json").map(Json)
}

pub async fn forecast_by_id(
    State(state): State<Arc<AppState>>,
    Path(forecast_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let current = read_runtime_json(&state, "current_forecasts.json")?;
    let forecast = current
        .get("forecasts")
        .and_then(Value::as_array)
        .and_then(|forecasts| {
            forecasts.iter().find(|forecast| {
                forecast.get("forecast_id").and_then(Value::as_str) == Some(forecast_id.as_str())
            })
        })
        .cloned()
        .ok_or_else(|| ApiError::NotFound(format!("forecast '{forecast_id}' is not active")))?;
    Ok(Json(forecast))
}

pub async fn history(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    read_runtime_jsonl(&state, "forecast_history.jsonl", 200).map(Json)
}

pub async fn source_health(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    if let Some(handle) = state.task4_threat_prediction.read().await.clone() {
        return Ok(Json(json!({
            "schema_version": "task4-source-health-api-v1",
            "sources": handle.source_health().await
        })));
    }
    read_runtime_json(&state, "source_health.json").map(Json)
}

fn runtime_root(state: &AppState) -> PathBuf {
    PathBuf::from(&state.threat_prediction_state_dir)
}

fn read_runtime_json(state: &AppState, file_name: &str) -> Result<Value, ApiError> {
    read_json_file(runtime_root(state).join(file_name))
}

fn read_runtime_jsonl(state: &AppState, file_name: &str, limit: usize) -> Result<Value, ApiError> {
    let path = runtime_root(state).join(file_name);
    let raw = fs::read_to_string(&path)
        .map_err(|_| ApiError::NotFound(format!("{} is not available yet", path.display())))?;
    let mut values = raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect::<Vec<_>>();
    if values.len() > limit {
        values = values.split_off(values.len() - limit);
    }
    Ok(json!({
        "schema_version": "task4-threat-prediction-jsonl-api-v1",
        "source_path": path.display().to_string(),
        "count": values.len(),
        "items": values
    }))
}

fn read_json_file(path: impl AsRef<FsPath>) -> Result<Value, ApiError> {
    let path = path.as_ref();
    let raw = fs::read_to_string(path)
        .map_err(|_| ApiError::NotFound(format!("{} is not available yet", path.display())))?;
    serde_json::from_str(&raw)
        .map_err(|err| ApiError::Internal(format!("failed to parse {}: {}", path.display(), err)))
}
