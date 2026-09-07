use crate::advisory::{AdvisoryConfig, AdvisoryRules, store};
use crate::api::{error::ApiError, state::AppState};
use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub limit: Option<usize>,
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<crate::advisory::RemediationRecommendation>>, ApiError> {
    let config = AdvisoryConfig::from_state_dirs(&state.threat_state_dir);
    let limit = query.limit.unwrap_or(500).min(10_000);
    let recommendations = store::list_recent(&config.recommendations_path(), limit)
        .await
        .map_err(|err| ApiError::Internal(err.to_string()))?;
    Ok(Json(recommendations))
}

pub async fn for_alert(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<crate::advisory::RemediationRecommendation>, ApiError> {
    let config = AdvisoryConfig::from_state_dirs(&state.threat_state_dir);
    let recommendation = store::find_for_alert(&config.recommendations_path(), &id)
        .await
        .map_err(|err| ApiError::Internal(err.to_string()))?
        .ok_or_else(|| ApiError::NotFound(format!("no recommendation for alert {}", id)))?;
    Ok(Json(recommendation))
}

pub async fn get_rules(
    State(state): State<Arc<AppState>>,
) -> Result<Json<AdvisoryRules>, ApiError> {
    let config = AdvisoryConfig::from_state_dirs(&state.threat_state_dir);
    Ok(Json(AdvisoryRules::load_or_default(&config.rules_path())))
}

pub async fn put_rules(
    State(state): State<Arc<AppState>>,
    Json(rules): Json<AdvisoryRules>,
) -> Result<Json<AdvisoryRules>, ApiError> {
    let config = AdvisoryConfig::from_state_dirs(&state.threat_state_dir);
    rules
        .save_atomic(&config.rules_path())
        .map_err(|err| ApiError::BadRequest(err.to_string()))?;
    Ok(Json(rules))
}
