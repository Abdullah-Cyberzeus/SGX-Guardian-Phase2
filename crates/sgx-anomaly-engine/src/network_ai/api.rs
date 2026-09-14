//! Task 3 Deliverable 18: authenticated, safe client-facing API.
//!
//! The API exposes bounded audit data only. It deliberately never returns
//! signing material, private keys, tokens, or raw Task2 credential data.

use super::{NetworkAiConfig, NetworkAiRuntimeMode};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Clone)]
pub struct NetworkAiApiState {
    evidence_root: PathBuf,
    config_path: PathBuf,
    authorized_operators: Vec<String>,
    config: Arc<Mutex<NetworkAiConfig>>,
}

impl NetworkAiApiState {
    pub fn new(
        evidence_root: impl Into<PathBuf>,
        config_path: impl Into<PathBuf>,
        config: NetworkAiConfig,
        authorized_operators: Vec<String>,
    ) -> Self {
        Self {
            evidence_root: evidence_root.into(),
            config_path: config_path.into(),
            config: Arc::new(Mutex::new(config)),
            authorized_operators,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct NetworkAiApiError {
    pub error: String,
}
type ApiResult<T> = Result<Json<T>, (StatusCode, Json<NetworkAiApiError>)>;

fn error(status: StatusCode, message: impl Into<String>) -> (StatusCode, Json<NetworkAiApiError>) {
    (
        status,
        Json(NetworkAiApiError {
            error: message.into(),
        }),
    )
}

fn authorized(
    state: &NetworkAiApiState,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<NetworkAiApiError>)> {
    let actor = headers
        .get("x-operator-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "x-operator-id header is required"))?;
    if !state
        .authorized_operators
        .iter()
        .any(|allowed| allowed == actor)
    {
        return Err(error(
            StatusCode::FORBIDDEN,
            "operator is not authorized for Task3 network AI",
        ));
    }
    Ok(actor.to_string())
}

fn read_json(path: &Path) -> Result<Value, (StatusCode, Json<NetworkAiApiError>)> {
    let raw = fs::read_to_string(path).map_err(|_| {
        error(
            StatusCode::NOT_FOUND,
            "requested Task3 evidence is not available",
        )
    })?;
    serde_json::from_str(&raw).map_err(|_| {
        error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Task3 evidence is malformed",
        )
    })
}

fn read_jsonl_bounded(path: &Path) -> Result<Vec<Value>, (StatusCode, Json<NetworkAiApiError>)> {
    let raw = fs::read_to_string(path).map_err(|_| {
        error(
            StatusCode::NOT_FOUND,
            "requested Task3 history is not available",
        )
    })?;
    Ok(raw
        .lines()
        .rev()
        .take(100)
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect())
}

async fn status(State(state): State<NetworkAiApiState>, headers: HeaderMap) -> ApiResult<Value> {
    authorized(&state, &headers)?;
    let config = state
        .config
        .lock()
        .map_err(|_| {
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Task3 config lock unavailable",
            )
        })?
        .clone();
    let mode = read_json(&state.evidence_root.join("runtime_mode_decision.json"))
        .ok()
        .and_then(|value| value.get("mode").cloned())
        .unwrap_or_else(|| serde_json::json!(config.mode));
    Ok(Json(serde_json::json!({
        "enabled": config.enabled, "mode": mode, "config_version": config.config_version,
        "model_version": "route-quality-v1-interpretable", "feature_schema_version": "network-ai-v1"
    })))
}

async fn candidates(
    State(state): State<NetworkAiApiState>,
    headers: HeaderMap,
) -> ApiResult<Value> {
    authorized(&state, &headers)?;
    read_json(&state.evidence_root.join("eligible_routes.json")).map(Json)
}

async fn current_decision(
    State(state): State<NetworkAiApiState>,
    headers: HeaderMap,
) -> ApiResult<Value> {
    authorized(&state, &headers)?;
    read_json(&state.evidence_root.join("current_decision.json")).map(Json)
}

async fn history(
    State(state): State<NetworkAiApiState>,
    headers: HeaderMap,
) -> ApiResult<Vec<Value>> {
    authorized(&state, &headers)?;
    read_jsonl_bounded(&state.evidence_root.join("decisions.jsonl")).map(Json)
}

async fn rewards(
    State(state): State<NetworkAiApiState>,
    headers: HeaderMap,
) -> ApiResult<Vec<Value>> {
    authorized(&state, &headers)?;
    read_jsonl_bounded(&state.evidence_root.join("rewards.jsonl")).map(Json)
}

#[derive(Debug, Deserialize)]
pub struct ModeUpdateRequest {
    pub mode: String,
}

async fn update_mode(
    State(state): State<NetworkAiApiState>,
    headers: HeaderMap,
    Json(request): Json<ModeUpdateRequest>,
) -> ApiResult<Value> {
    let actor = authorized(&state, &headers)?;
    let mode = NetworkAiRuntimeMode::parse(&request.mode).ok_or_else(|| {
        error(
            StatusCode::BAD_REQUEST,
            "mode must be shadow, advisory, or active",
        )
    })?;
    let mut config = state.config.lock().map_err(|_| {
        error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Task3 config lock unavailable",
        )
    })?;
    config.mode = mode;
    config
        .validate()
        .map_err(|validation_error| error(StatusCode::BAD_REQUEST, validation_error.to_string()))?;
    write_config_atomic(&state.config_path, &config)
        .map_err(|write_error| error(StatusCode::INTERNAL_SERVER_ERROR, write_error))?;
    Ok(Json(
        serde_json::json!({"mode": mode, "config_version": config.config_version, "updated_by": actor}),
    ))
}

fn write_config_atomic(path: &Path, config: &NetworkAiConfig) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let temporary = path.with_extension("json.tmp");
    fs::write(
        &temporary,
        serde_json::to_vec_pretty(config).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    fs::rename(&temporary, path).map_err(|error| error.to_string())
}

/// Existing host/router code can nest this router under its authenticated
/// service. This standalone crate applies the existing operator allow-list.
pub fn router(state: NetworkAiApiState) -> Router {
    Router::new()
        .route("/api/v1/network-ai/status", get(status))
        .route("/api/v1/network-ai/candidates", get(candidates))
        .route("/api/v1/network-ai/decision/current", get(current_decision))
        .route("/api/v1/network-ai/history", get(history))
        .route("/api/v1/network-ai/rewards", get(rewards))
        .route("/api/v1/network-ai/mode", post(update_mode))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn state() -> (NetworkAiApiState, PathBuf) {
        let nonce = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("network-ai-api-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("current_decision.json"),
            r#"{"selected_route_id":"relay-safe","selected_reason":"trusted"}"#,
        )
        .unwrap();
        fs::write(root.join("eligible_routes.json"), r#"{"eligible":["relay-safe"],"rejected":[{"route_id":"relay-bad","reason":"QuarantinedPeer"}]}"#).unwrap();
        fs::write(root.join("decisions.jsonl"), r#"{"decision_id":"d1"}"#).unwrap();
        fs::write(
            root.join("rewards.jsonl"),
            r#"{"decision_id":"d1","reward":5}"#,
        )
        .unwrap();
        let config_path = root.join("network_ai.json");
        (
            NetworkAiApiState::new(
                &root,
                &config_path,
                NetworkAiConfig::default(),
                vec!["nodeA".into()],
            ),
            root,
        )
    }
    fn headers(actor: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(actor) = actor {
            headers.insert("x-operator-id", actor.parse().unwrap());
        }
        headers
    }
    #[tokio::test]
    async fn rejects_missing_or_unauthorized_operators() {
        let (state, root) = state();
        assert_eq!(
            status(State(state.clone()), headers(None))
                .await
                .unwrap_err()
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(State(state), headers(Some("nodeX")))
                .await
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );
        let _ = fs::remove_dir_all(root);
    }
    #[tokio::test]
    async fn exposes_safe_status_candidates_decision_history_and_rewards() {
        let (state, root) = state();
        assert!(status(State(state.clone()), headers(Some("nodeA")))
            .await
            .is_ok());
        assert!(candidates(State(state.clone()), headers(Some("nodeA")))
            .await
            .is_ok());
        assert!(
            current_decision(State(state.clone()), headers(Some("nodeA")))
                .await
                .is_ok()
        );
        assert!(history(State(state.clone()), headers(Some("nodeA")))
            .await
            .is_ok());
        assert!(rewards(State(state), headers(Some("nodeA"))).await.is_ok());
        let _ = fs::remove_dir_all(root);
    }
    #[tokio::test]
    async fn authorized_mode_update_validates_and_persists() {
        let (state, root) = state();
        assert_eq!(
            update_mode(
                State(state.clone()),
                headers(Some("nodeA")),
                Json(ModeUpdateRequest { mode: "bad".into() })
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::BAD_REQUEST
        );
        let response = update_mode(
            State(state.clone()),
            headers(Some("nodeA")),
            Json(ModeUpdateRequest {
                mode: "advisory".into(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(response.0["mode"], "advisory");
        assert!(state.config_path.exists());
        let _ = fs::remove_dir_all(root);
    }
}
