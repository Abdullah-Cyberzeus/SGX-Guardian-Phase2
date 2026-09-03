use crate::advisory::AnomalyScoringRuntime;
use crate::api::auth::middleware::AuthenticatedSession;
use crate::api::{error::ApiError, state::AppState};
use crate::task1_ai::{
    load_recent_full_ml_alerts, process_task2_owner_decision, RecommendedThresholdRanges,
    Task1FullMlAlertRecord, Task1RuntimeTracker, Task1ThresholdDefaults, Task1ThresholdSettings,
    Task1ThresholdSettingsService, Task1ThresholdUpdate, Task2OwnerDecisionRuntimeResult,
};
use axum::{
    extract::{Path, Query, State},
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

#[derive(Debug, Deserialize)]
pub struct Task2OwnerDecisionRequest {
    pub reason: Option<String>,
}

/// Real owner/admin approval of one persisted Task1 remediation plan.
///
/// HTTP authentication authorizes the human/operator request.
/// The local Guardian node identity remains the Circle Owner identity used by
/// the standalone Virtual Shift ReviewQueue role registry.
pub async fn approve_remediation_review(
    State(state): State<Arc<AppState>>,
    Path(plan_id): Path<String>,
    session: Option<Extension<AuthenticatedSession>>,
    Json(request): Json<Task2OwnerDecisionRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    authorize_task2_owner_decision(&state, session)?;

    let result = process_task2_owner_decision(
        &state.node_id,
        &state.threat_state_dir,
        &plan_id,
        true,
        request.reason,
    )
    .map_err(|error| ApiError::BadRequest(error.to_string()))?;

    let mut response =
        serde_json::to_value(&result).map_err(|error| ApiError::Internal(error.to_string()))?;

    let gossip = if let Some(alert_pb_path) = result.alert_protobuf_path.as_deref() {
        match std::fs::read(alert_pb_path) {
            Ok(alert_bytes) => {
                match sgx_anomaly_engine::virtual_shift::VShiftAlert::decode(&alert_bytes) {
                    Ok(alert) => {
                        match crate::crl::gossip::vshift::broadcast_vshift_alert(
                            &state.node_id,
                            &alert,
                        )
                        .await
                        {
                            Ok(receipt) => {
                                println!(
                                    "Task2 VS15 real gossip completed alert_id={} origin={} delivered={} pending={} duplicate_suppressed={}",
                                    receipt.alert_id,
                                    receipt.origin_node,
                                    receipt.delivered.len(),
                                    receipt.pending_offline_nodes.len(),
                                    receipt.duplicate_suppressed
                                );

                                serde_json::to_value(receipt).unwrap_or_else(|error| {
                                    serde_json::json!({
                                        "status": "broadcast_receipt_serialization_failed",
                                        "error": error.to_string()
                                    })
                                })
                            }
                            Err(error) => {
                                tracing::error!(
                                    "Task2 VS15 real gossip failed plan_id={} error={}",
                                    plan_id,
                                    error
                                );

                                serde_json::json!({
                                    "status": "broadcast_failed",
                                    "error": error.to_string()
                                })
                            }
                        }
                    }
                    Err(error) => {
                        tracing::error!(
                            "Task2 VS15 alert decode failed plan_id={} path={} error={}",
                            plan_id,
                            alert_pb_path,
                            error
                        );

                        serde_json::json!({
                            "status": "alert_decode_failed",
                            "error": error.to_string()
                        })
                    }
                }
            }
            Err(error) => {
                tracing::error!(
                    "Task2 VS15 alert read failed plan_id={} path={} error={}",
                    plan_id,
                    alert_pb_path,
                    error
                );

                serde_json::json!({
                    "status": "alert_read_failed",
                    "error": error.to_string()
                })
            }
        }
    } else {
        serde_json::json!({
            "status": "no_signed_alert_to_broadcast"
        })
    };

    if let Some(object) = response.as_object_mut() {
        object.insert("gossip".into(), gossip);
    }

    Ok(Json(response))
}

/// Retry VS15 delivery for the exact VS14 alert of an already-approved plan.
///
/// This operation never repeats owner approval and never creates/signs a new
/// policy. It only re-broadcasts the existing persisted VSHIFT_ALERT.
pub async fn retry_remediation_gossip(
    State(state): State<Arc<AppState>>,
    Path(plan_id): Path<String>,
    session: Option<Extension<AuthenticatedSession>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    authorize_task2_owner_decision(&state, session)?;

    let (alert, alert_protobuf_path) =
        crate::task1_ai::runtime::load_approved_task2_vshift_alert_for_retry(
            &state.threat_state_dir,
            &plan_id,
        )
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;

    let receipt = crate::crl::gossip::vshift::broadcast_vshift_alert(&state.node_id, &alert)
        .await
        .map_err(|error| ApiError::ServiceUnavailable {
            code: "TASK2_GOSSIP_RETRY_FAILED",
            message: error.to_string(),
        })?;

    println!(
        "Task2 VS15 retry completed plan_id={} alert_id={} delivered={} pending={} duplicate_suppressed={}",
        plan_id,
        receipt.alert_id,
        receipt.delivered.len(),
        receipt.pending_offline_nodes.len(),
        receipt.duplicate_suppressed
    );

    Ok(Json(serde_json::json!({
        "schema_version": 1,
        "operation": "retry_existing_vshift_alert",
        "retry_only": true,
        "plan_id": plan_id,
        "alert_id": alert.alert_id,
        "alert_protobuf_path": alert_protobuf_path.display().to_string(),
        "gossip": receipt
    })))
}

/// Real owner/admin rejection of one persisted Task1 remediation plan.
/// Rejection finalizes the review and must not build/sign/broadcast a policy.
pub async fn reject_remediation_review(
    State(state): State<Arc<AppState>>,
    Path(plan_id): Path<String>,
    session: Option<Extension<AuthenticatedSession>>,
    Json(request): Json<Task2OwnerDecisionRequest>,
) -> Result<Json<Task2OwnerDecisionRuntimeResult>, ApiError> {
    authorize_task2_owner_decision(&state, session)?;

    let result = process_task2_owner_decision(
        &state.node_id,
        &state.threat_state_dir,
        &plan_id,
        false,
        request.reason,
    )
    .map_err(|error| ApiError::BadRequest(error.to_string()))?;

    Ok(Json(result))
}

fn authorize_task2_owner_decision(
    state: &AppState,
    session: Option<Extension<AuthenticatedSession>>,
) -> Result<(), ApiError> {
    if crate::runtime_gates::login_disabled() {
        let _ = state;
        return Ok(());
    }

    let session = session
        .map(|Extension(session)| session)
        .ok_or_else(|| ApiError::Unauthorized("missing bearer token".into()))?;

    if !matches!(session.claims.role.as_str(), "owner" | "admin") {
        return Err(ApiError::Forbidden(
            "Task2 remediation decisions require owner or admin access".into(),
        ));
    }

    Ok(())
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
