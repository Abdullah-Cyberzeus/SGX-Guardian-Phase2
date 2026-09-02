use crate::advisory::AnomalyScoringRuntime;
use crate::api::auth::middleware::AuthenticatedSession;
use crate::api::{error::ApiError, state::AppState};
use crate::task1_ai::{
    load_recent_full_ml_alerts, RecommendedThresholdRanges, Task1FullMlAlertRecord,
    Task1RuntimeTracker, Task1ThresholdDefaults, Task1ThresholdSettings,
    Task1ThresholdSettingsService, Task1ThresholdUpdate,
};
use axum::{
    extract::{Query, State},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize)]
pub struct Task1ThresholdConfigResponse {
    pub schema_version: u32,
    pub settings_version: u64,
    pub detection_threshold: f32,
    pub high_threshold: f32,
    pub critical_threshold: f32,
    pub defaults: Task1ThresholdDefaults,
    pub recommended: RecommendedThresholdRanges,
    pub updated_by: String,
    pub updated_at: String,
    pub reason: String,
}

impl From<Task1ThresholdSettings> for Task1ThresholdConfigResponse {
    fn from(settings: Task1ThresholdSettings) -> Self {
        Self {
            schema_version: settings.schema_version,
            settings_version: settings.settings_version,
            detection_threshold: settings.detection_threshold,
            high_threshold: settings.high_threshold,
            critical_threshold: settings.critical_threshold,
            defaults: Task1ThresholdSettings::defaults(),
            recommended: Task1ThresholdSettings::recommended_ranges(),
            updated_by: settings.updated_by,
            updated_at: settings.updated_at,
            reason: settings.reason,
        }
    }
}

pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Task1ThresholdConfigResponse>, ApiError> {
    let service = Task1ThresholdSettingsService::for_state_dir(&state.threat_state_dir);
    let settings = service
        .load_or_create()
        .map_err(|err| ApiError::Internal(err.to_string()))?;
    Ok(Json(settings.into()))
}

pub async fn get_runtime(
    State(state): State<Arc<AppState>>,
) -> Result<Json<AnomalyScoringRuntime>, ApiError> {
    // Fast path: the full ML runtime continuously persists this snapshot.
    // Reading it avoids reloading/validating the Isolation Forest model on
    // every status request.
    if let Some(runtime) =
        crate::task1_ai::baseline::load_full_ml_runtime_status(&state.threat_state_dir)
    {
        return Ok(Json(runtime));
    }

    // Compatibility fallback when the runtime snapshot does not exist yet.
    let runtime = Task1RuntimeTracker::for_state_dir(&state.node_id, &state.threat_state_dir);
    Ok(Json(runtime.current_runtime()))
}

#[derive(Debug, Deserialize)]
pub struct Task1AlertsQuery {
    #[serde(default = "default_alert_limit")]
    pub limit: usize,
}

fn default_alert_limit() -> usize {
    50
}

pub async fn list_full_ml_alerts(
    State(state): State<Arc<AppState>>,
    Query(query): Query<Task1AlertsQuery>,
) -> Result<Json<Vec<Task1FullMlAlertRecord>>, ApiError> {
    let limit = query.limit.clamp(1, 200);
    let alerts = load_recent_full_ml_alerts(&state.threat_state_dir, limit)
        .map_err(|err| ApiError::Internal(err.to_string()))?;
    Ok(Json(alerts))
}

pub async fn put_config(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Json(update): Json<Task1ThresholdUpdate>,
) -> Result<Json<Task1ThresholdConfigResponse>, ApiError> {
    let actor = threshold_update_actor(&state, session)?;
    let service = Task1ThresholdSettingsService::for_state_dir(&state.threat_state_dir);
    let settings = service
        .update(&actor, update)
        .map_err(|err| ApiError::BadRequest(err.to_string()))?;
    Ok(Json(settings.into()))
}

fn threshold_update_actor(
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
            "task1 threshold updates require owner or admin access".into(),
        ));
    }
    Ok(session.claims.sub)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_includes_defaults_and_recommended_ranges() {
        let response =
            Task1ThresholdConfigResponse::from(Task1ThresholdSettings::default_settings());
        assert_eq!(response.detection_threshold, 0.50);
        assert_eq!(response.defaults.high_threshold, 0.75);
        assert!(response.recommended.critical.max >= 0.95);
    }
}
