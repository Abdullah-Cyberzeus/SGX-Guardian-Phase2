use crate::api::auth::middleware::AuthenticatedSession;
use crate::api::{error::ApiError, state::AppState};
use axum::{extract::State, Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sgx_anomaly_engine::network_ai::{
    NetworkAiConfig, NetworkAiRuntimeMode, NETWORK_AI_CONFIG_VERSION,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const ACTIVE_EVIDENCE_MAX_AGE_MS: u64 = 300_000;

#[derive(Debug, Deserialize)]
pub struct NetworkAiModeUpdateRequest {
    pub mode: NetworkAiRuntimeMode,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct NetworkAiModeUpdateResponse {
    pub config: NetworkAiConfig,
    pub updated_by: String,
    pub reason: String,
}

pub async fn status(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let mut status = read_runtime_json(&state, "runtime_status.json")?;

    if let Ok(rl_policy) = read_runtime_json(&state, "rl_policy.json") {
        if let Some(rl_version) = rl_policy.get("rl_version").and_then(Value::as_str) {
            if let Some(object) = status.as_object_mut() {
                object.insert(
                    "model_version".to_string(),
                    Value::String(rl_version.to_string()),
                );
            }
        }
    }

    Ok(Json(status))
}

pub async fn candidates(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let runtime_root = runtime_root(&state);
    let mut candidates = read_json_file(runtime_root.join("route_candidates.json"))?;
    let eligible = read_json_file(runtime_root.join("eligible_routes.json"))?;

    let eligible_routes = eligible
        .get("eligible")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let rejected_routes = eligible
        .get("rejected")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    if let Some(candidate_list) = candidates
        .get_mut("candidates")
        .and_then(Value::as_array_mut)
    {
        for candidate in candidate_list {
            let route_id = candidate
                .get("route_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();

            let is_eligible = eligible_routes.iter().any(|route| {
                route.get("route_id").and_then(Value::as_str) == Some(route_id.as_str())
            });

            let rejection = rejected_routes.iter().find(|route| {
                route.get("route_id").and_then(Value::as_str) == Some(route_id.as_str())
                    || route
                        .get("candidate")
                        .and_then(|candidate| candidate.get("route_id"))
                        .and_then(Value::as_str)
                        == Some(route_id.as_str())
            });

            if let Some(object) = candidate.as_object_mut() {
                object.insert("eligible".to_string(), Value::Bool(is_eligible));

                let reason = if is_eligible {
                    "passed Task2 trust/policy and route availability/health eligibility checks"
                        .to_string()
                } else if let Some(rejected) = rejection {
                    rejected
                        .get("reason")
                        .map(|reason| match reason {
                            Value::String(text) => text.clone(),
                            other => other.to_string(),
                        })
                        .unwrap_or_else(|| {
                            "rejected by Task3 route eligibility evaluation".to_string()
                        })
                } else {
                    "not present in the current Task2-eligible route set".to_string()
                };

                object.insert("eligibility_reason".to_string(), Value::String(reason));
            }
        }
    }

    Ok(Json(json!({
        "schema_version": "task3-network-ai-candidates-api-v1",
        "source": "production runtime snapshots",
        "candidates": candidates,
        "eligible_routes": eligible
    })))
}

pub async fn current_decision(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    read_runtime_json(&state, "current_decision.json").map(Json)
}

pub async fn history(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    read_runtime_jsonl(&state, "route_history.jsonl", 200).map(Json)
}

pub async fn rewards(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    read_runtime_jsonl(&state, "rewards.jsonl", 200).map(Json)
}

pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Result<Json<NetworkAiConfig>, ApiError> {
    let config = load_or_seed_config(&config_path(&state))?;
    Ok(Json(config))
}

pub async fn recommendation(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let runtime_root = runtime_root(&state);
    let advisory = runtime_root.join("advisory_route_recommendation.json");
    if advisory.exists() {
        return read_json_file(advisory).map(Json);
    }
    read_json_file(runtime_root.join("shadow_route_decision.json")).map(Json)
}

pub async fn safety(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    read_runtime_json(&state, "safety_runtime_status.json").map(Json)
}

pub async fn set_mode(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Json(update): Json<NetworkAiModeUpdateRequest>,
) -> Result<Json<NetworkAiModeUpdateResponse>, ApiError> {
    let actor = mode_update_actor(&state, session)?;
    let path = config_path(&state);
    let mut config = load_or_seed_config(&path)?;

    if update.mode == NetworkAiRuntimeMode::Active {
        require_active_mode_evidence(&state)?;
    }

    config.mode = update.mode;
    config.config_version = NETWORK_AI_CONFIG_VERSION.to_string();
    config
        .validate()
        .map_err(|err| ApiError::BadRequest(err.to_string()))?;
    write_config(&path, &config)?;

    Ok(Json(NetworkAiModeUpdateResponse {
        config,
        updated_by: actor,
        reason: update
            .reason
            .unwrap_or_else(|| "operator requested Network AI runtime mode update".to_string()),
    }))
}

fn mode_update_actor(
    state: &AppState,
    session: Option<Extension<AuthenticatedSession>>,
) -> Result<String, ApiError> {
    if crate::runtime_gates::login_disabled() {
        return Ok(session
            .map(|Extension(session)| session.claims.sub)
            .unwrap_or_else(|| state.node_id.clone()));
    }

    let session = session
        .map(|Extension(session)| session)
        .ok_or_else(|| ApiError::Unauthorized("missing bearer token".into()))?;
    if !matches!(session.claims.role.as_str(), "owner" | "admin") {
        return Err(ApiError::Forbidden(
            "network AI mode updates require owner or admin access".into(),
        ));
    }
    Ok(session.claims.sub)
}

fn require_active_mode_evidence(state: &AppState) -> Result<(), ApiError> {
    let root = runtime_root(state);
    let eligible = read_json_file(root.join("eligible_routes.json"))?;
    let eligible_count = eligible
        .get("eligible")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    if eligible_count == 0 {
        return Err(ApiError::Conflict(
            "active mode rejected: no fresh Task2-eligible production route evidence".into(),
        ));
    }

    let advisory_path = root.join("advisory_route_recommendation.json");
    if advisory_path.exists() {
        let advisory = read_json_file(advisory_path)?;
        let ts_ms = advisory.get("ts_ms").and_then(Value::as_u64).unwrap_or(0);
        let safe = advisory
            .get("safety_allowed_if_activated")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if safe && fresh(ts_ms) {
            return Ok(());
        }
    }

    let safety_path = root.join("safety_runtime_status.json");
    if safety_path.exists() {
        let safety = read_json_file(safety_path)?;
        let ts_ms = safety.get("ts_ms").and_then(Value::as_u64).unwrap_or(0);
        let evaluated = safety
            .get("safety_evaluated")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let blocked = safety
            .get("blocked_by")
            .is_some_and(|value| !value.is_null());
        if evaluated && !blocked && fresh(ts_ms) {
            return Ok(());
        }
    }

    Err(ApiError::Conflict(
        "active mode rejected: missing fresh production safety evidence".into(),
    ))
}

fn fresh(ts_ms: u64) -> bool {
    now_ms().saturating_sub(ts_ms) <= ACTIVE_EVIDENCE_MAX_AGE_MS
}

fn config_path(state: &AppState) -> PathBuf {
    std::env::var("SGX_NETWORK_AI_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(&state.threat_state_dir)
                .join("network_ai")
                .join("config")
                .join("network_ai.json")
        })
}

fn runtime_root(state: &AppState) -> PathBuf {
    PathBuf::from(&state.threat_state_dir)
        .join("network_ai")
        .join("runtime")
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
        "schema_version": "task3-network-ai-jsonl-api-v1",
        "source_path": path.display().to_string(),
        "count": values.len(),
        "items": values
    }))
}

fn read_json_file(path: impl AsRef<Path>) -> Result<Value, ApiError> {
    let path = path.as_ref();
    let raw = fs::read_to_string(path)
        .map_err(|_| ApiError::NotFound(format!("{} is not available yet", path.display())))?;
    serde_json::from_str(&raw)
        .map_err(|err| ApiError::Internal(format!("failed to parse {}: {}", path.display(), err)))
}

fn load_or_seed_config(path: &Path) -> Result<NetworkAiConfig, ApiError> {
    if path.exists() {
        return NetworkAiConfig::load_json(path)
            .map_err(|err| ApiError::BadRequest(err.to_string()));
    }
    let config = NetworkAiConfig::default();
    write_config(path, &config)?;
    Ok(config)
}

fn write_config(path: &Path, config: &NetworkAiConfig) -> Result<(), ApiError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(config)?;
    fs::write(&tmp, body)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
