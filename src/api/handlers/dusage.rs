use crate::api::error::ApiError;
use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct PutQuotaRequest {
    pub quota_bytes: u64,
    pub period: String,
}

#[derive(Debug, Serialize)]
pub struct ResetResponse {
    pub status: String,
    pub snapshot: crate::dusage::model::UsageSnapshot,
}

pub async fn current(
    State(_state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<crate::dusage::model::UsageSnapshot>, ApiError> {
    Ok(Json(crate::dusage::current_snapshot().await?))
}

pub async fn history(
    State(_state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<Vec<crate::dusage::model::UsageSnapshot>>, ApiError> {
    Ok(Json(crate::dusage::history().await?))
}

pub async fn get_quota(
    State(_state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<Option<crate::dusage::model::DusageQuota>>, ApiError> {
    Ok(Json(crate::dusage::get_quota().await?))
}

pub async fn put_quota(
    State(_state): State<Arc<crate::api::state::AppState>>,
    Json(body): Json<PutQuotaRequest>,
) -> Result<Json<crate::dusage::model::DusageQuota>, ApiError> {
    Ok(Json(
        crate::dusage::put_quota(body.quota_bytes, body.period).await?,
    ))
}

pub async fn reset(
    State(_state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<ResetResponse>, ApiError> {
    let snapshot = crate::dusage::reset_now().await?;
    Ok(Json(ResetResponse {
        status: "success".to_string(),
        snapshot,
    }))
}
