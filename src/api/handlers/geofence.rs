use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::geofence::actions::ZoneAutomation;
use crate::geofence::errors::GeofenceError;
use crate::geofence::model::{
    Fix, GeofenceEvent, GeofenceZone, RfSignature, StoredLocation, ZoneKind, ZoneStatus,
};
use crate::geofence::{alerts as geofence_alerts, persistence, sources, zones};
use crate::threat::threat_alert::ThreatAlert;
use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct CreateZoneRequest {
    pub name: String,
    pub kind: ZoneKind,
    pub center_lat: Option<f64>,
    pub center_lng: Option<f64>,
    pub radius_m: Option<f64>,
    pub rf_signature: Option<RfSignature>,
    #[serde(default)]
    pub on_entry: bool,
    #[serde(default = "default_true")]
    pub on_exit: bool,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default)]
    pub automation: ZoneAutomation,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct EditZoneRequest {
    pub name: Option<String>,
    pub kind: Option<ZoneKind>,
    pub center_lat: Option<Option<f64>>,
    pub center_lng: Option<Option<f64>>,
    pub radius_m: Option<Option<f64>>,
    pub rf_signature: Option<Option<RfSignature>>,
    pub on_entry: Option<bool>,
    pub on_exit: Option<bool>,
    pub severity: Option<String>,
    pub automation: Option<ZoneAutomation>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ReportLocationRequest {
    pub lat: f64,
    pub lng: f64,
    pub accuracy_m: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct ZonesResponse {
    pub count: usize,
    pub zones: Vec<GeofenceZone>,
}

#[derive(Debug, Serialize)]
pub struct ZoneResponse {
    pub zone: GeofenceZone,
}

#[derive(Debug, Serialize)]
pub struct LocationResponse {
    pub location: Option<StoredLocation>,
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub source: String,
    pub selection_mode: String,
    pub source_reason: String,
    pub location: Option<StoredLocation>,
    pub zones: Vec<ZoneStatus>,
}

#[derive(Debug, Serialize)]
pub struct EventsResponse {
    pub count: usize,
    pub events: Vec<GeofenceEvent>,
}

#[derive(Debug, Serialize)]
pub struct AlertsResponse {
    pub count: usize,
    pub alerts: Vec<ThreatAlert>,
}

#[derive(Debug, Serialize)]
pub struct ActionsResponse {
    pub zone_id: String,
    pub automation: ZoneAutomation,
}

#[derive(Debug, Deserialize)]
pub struct TestActionsRequest {
    pub zone_id: String,
    pub transition: String,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
}

pub async fn list_zones(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<ZonesResponse>, ApiError> {
    let zones = zones::list_zones().map_err(api_error)?;
    Ok(Json(ZonesResponse {
        count: zones.len(),
        zones,
    }))
}

pub async fn create_zone(
    State(_state): State<Arc<AppState>>,
    Json(request): Json<CreateZoneRequest>,
) -> Result<Json<ZoneResponse>, ApiError> {
    let zone = zones::new_zone(zones::NewZoneInput {
        name: request.name,
        kind: request.kind,
        center_lat: request.center_lat,
        center_lng: request.center_lng,
        radius_m: request.radius_m,
        rf_signature: request.rf_signature,
        on_entry: request.on_entry,
        on_exit: request.on_exit,
        severity: request.severity,
        automation: request.automation,
        enabled: request.enabled,
    });
    let zone = zones::create_zone(zone).map_err(api_error)?;
    Ok(Json(ZoneResponse { zone }))
}

pub async fn edit_zone(
    State(_state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(request): Json<EditZoneRequest>,
) -> Result<Json<ZoneResponse>, ApiError> {
    let patch = zones::ZonePatch {
        name: request.name,
        kind: request.kind,
        center_lat: request.center_lat,
        center_lng: request.center_lng,
        radius_m: request.radius_m,
        rf_signature: request.rf_signature,
        on_entry: request.on_entry,
        on_exit: request.on_exit,
        severity: request.severity,
        automation: request.automation,
        enabled: request.enabled,
    };
    let zone = zones::update_zone(&id, patch).map_err(api_error)?;
    Ok(Json(ZoneResponse { zone }))
}

pub async fn delete_zone(
    State(_state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ZoneResponse>, ApiError> {
    let zone = zones::delete_zone(&id).map_err(api_error)?;
    Ok(Json(ZoneResponse { zone }))
}

pub async fn capture_rf(
    State(_state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ZoneResponse>, ApiError> {
    let signature = sources::rf::capture_signature().await.map_err(api_error)?;
    let zone = zones::update_zone(
        &id,
        zones::ZonePatch {
            kind: Some(ZoneKind::RfSignature),
            rf_signature: Some(Some(signature)),
            ..Default::default()
        },
    )
    .map_err(api_error)?;
    Ok(Json(ZoneResponse { zone }))
}

pub async fn get_location(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<LocationResponse>, ApiError> {
    Ok(Json(LocationResponse {
        location: persistence::load_location().map_err(api_error)?,
    }))
}

pub async fn report_location(
    State(_state): State<Arc<AppState>>,
    Json(request): Json<ReportLocationRequest>,
) -> Result<Json<LocationResponse>, ApiError> {
    zones::validate_coordinate(request.lat, request.lng).map_err(api_error)?;
    if let Some(accuracy) = request.accuracy_m {
        if !accuracy.is_finite() || accuracy < 0.0 {
            return Err(ApiError::BadRequest(
                "accuracy_m must be a non-negative finite number".to_string(),
            ));
        }
    }
    let source = match sources::SourceKind::from_env().unwrap_or(sources::SourceKind::Auto) {
        sources::SourceKind::Manual => "manual",
        _ => "reported",
    };
    let location = StoredLocation::new(
        source,
        Fix::coordinate(request.lat, request.lng, request.accuracy_m),
    );
    persistence::save_reported_location(&location).map_err(api_error)?;
    persistence::save_location(&location).map_err(api_error)?;
    Ok(Json(LocationResponse {
        location: Some(location),
    }))
}

pub async fn status(State(_state): State<Arc<AppState>>) -> Result<Json<StatusResponse>, ApiError> {
    let configured_source = sources::SourceKind::from_env().unwrap_or(sources::SourceKind::Auto);
    let location = persistence::load_location().map_err(api_error)?;
    let selection = persistence::load_source_selection().map_err(api_error)?;
    let selection_mode = selection
        .as_ref()
        .map(|selection| selection.selection_mode.clone())
        .unwrap_or_else(|| {
            if configured_source == sources::SourceKind::Auto {
                "auto".to_string()
            } else {
                "forced".to_string()
            }
        });
    let source = selection
        .as_ref()
        .and_then(|selection| selection.active_source.clone())
        .or_else(|| location.as_ref().map(|location| location.source.clone()))
        .unwrap_or_else(|| {
            if configured_source == sources::SourceKind::Auto {
                "unavailable".to_string()
            } else {
                configured_source.id().to_string()
            }
        });
    let source_reason = selection
        .map(|selection| selection.source_reason)
        .unwrap_or_else(|| {
            if configured_source == sources::SourceKind::Auto {
                "auto source has not selected a provider yet".to_string()
            } else {
                format!("forced {}", configured_source.id())
            }
        });
    let statuses = match persistence::load_statuses().map_err(api_error)? {
        Some(statuses) => statuses,
        None => {
            let registry = zones::load_or_seed_registry().map_err(api_error)?;
            match location.as_ref().map(|location| &location.fix) {
                Some(fix) => registry
                    .zones
                    .iter()
                    .map(|zone| zones::evaluate_zone(zone, fix))
                    .collect(),
                None => registry
                    .zones
                    .iter()
                    .map(|zone| ZoneStatus {
                        zone_id: zone.zone_id.clone(),
                        zone_name: zone.name.clone(),
                        enabled: zone.enabled,
                        inside: None,
                        distance_m: None,
                        rf_score: None,
                    })
                    .collect(),
            }
        }
    };
    Ok(Json(StatusResponse {
        source,
        selection_mode,
        source_reason,
        location,
        zones: statuses,
    }))
}

pub async fn events(State(_state): State<Arc<AppState>>) -> Result<Json<EventsResponse>, ApiError> {
    let events = persistence::list_events().map_err(api_error)?;
    Ok(Json(EventsResponse {
        count: events.len(),
        events,
    }))
}

pub async fn alerts(State(_state): State<Arc<AppState>>) -> Result<Json<AlertsResponse>, ApiError> {
    let alerts = geofence_alerts::list_alerts().map_err(api_error)?;
    Ok(Json(AlertsResponse {
        count: alerts.len(),
        alerts,
    }))
}

pub async fn get_actions(
    State(_state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ActionsResponse>, ApiError> {
    let zone = zones::list_zones()
        .map_err(api_error)?
        .into_iter()
        .find(|zone| zone.zone_id == id)
        .ok_or_else(|| ApiError::NotFound(id.clone()))?;
    Ok(Json(ActionsResponse {
        zone_id: id,
        automation: zone.automation,
    }))
}

pub async fn put_actions(
    State(_state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(automation): Json<ZoneAutomation>,
) -> Result<Json<ActionsResponse>, ApiError> {
    crate::geofence::actions::validate(&automation).map_err(ApiError::BadRequest)?;
    let zone = zones::update_zone(
        &id,
        zones::ZonePatch {
            automation: Some(automation),
            ..Default::default()
        },
    )
    .map_err(api_error)?;
    Ok(Json(ActionsResponse {
        zone_id: id,
        automation: zone.automation,
    }))
}

pub async fn test_actions(
    State(state): State<Arc<AppState>>,
    Json(request): Json<TestActionsRequest>,
) -> Result<Json<ActionsResponse>, ApiError> {
    if request.transition != "entry" && request.transition != "exit" {
        return Err(ApiError::BadRequest(
            "transition must be entry or exit".to_string(),
        ));
    }
    let zone = zones::list_zones()
        .map_err(api_error)?
        .into_iter()
        .find(|zone| zone.zone_id == request.zone_id)
        .ok_or_else(|| ApiError::NotFound(request.zone_id.clone()))?;
    crate::geofence::actions::executor::dispatch(
        &state.node_id,
        &zone,
        &request.transition,
        request.confidence,
    )
    .await;
    Ok(Json(ActionsResponse {
        zone_id: zone.zone_id,
        automation: zone.automation,
    }))
}

fn default_true() -> bool {
    true
}

fn default_severity() -> String {
    "high".to_string()
}

fn default_confidence() -> f64 {
    1.0
}

fn api_error(error: GeofenceError) -> ApiError {
    match error {
        GeofenceError::NotFound(message) => ApiError::NotFound(message),
        GeofenceError::InvalidInput(message) => ApiError::BadRequest(message),
        GeofenceError::UnsupportedSource(message) => ApiError::BadRequest(message),
        GeofenceError::RfScanBusy(message) => ApiError::ServiceUnavailable {
            code: "RF_SCAN_BUSY",
            message,
        },
        GeofenceError::RfUnavailable(message) => ApiError::ServiceUnavailable {
            code: "RF_SCAN_UNAVAILABLE",
            message,
        },
        GeofenceError::InvalidProof => {
            ApiError::Internal("geofence registry proof invalid".to_string())
        }
        GeofenceError::Io(error) => ApiError::Internal(format!("geofence io: {}", error)),
        GeofenceError::Json(error) => ApiError::Internal(format!("geofence json: {}", error)),
    }
}
