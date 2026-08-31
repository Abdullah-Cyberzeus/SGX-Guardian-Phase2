use crate::api::error::ApiError;
use crate::api::state::AppState;
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::geofence::actions::{GeofenceAction, ZoneAutomation};
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
    #[serde(default)]
    pub topology_node_ref: Option<String>,
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
    pub topology_node_ref: Option<Option<String>>,
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
    State(state): State<Arc<AppState>>,
    Json(request): Json<CreateZoneRequest>,
) -> Result<Json<ZoneResponse>, ApiError> {
    let zone = zones::new_zone(zones::NewZoneInput {
        name: request.name,
        topology_node_ref: request.topology_node_ref,
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
    log_audit(
        &state.node_id,
        AuditCategory::Geofence,
        AuditSeverity::Info,
        AuditAction::Created,
        &format!("Geofence zone created: {} ({})", zone.zone_id, zone.name),
    );
    Ok(Json(ZoneResponse { zone }))
}

pub async fn edit_zone(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(request): Json<EditZoneRequest>,
) -> Result<Json<ZoneResponse>, ApiError> {
    let patch = zones::ZonePatch {
        name: request.name,
        topology_node_ref: request.topology_node_ref,
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
    log_audit(
        &state.node_id,
        AuditCategory::Geofence,
        AuditSeverity::Info,
        AuditAction::Updated,
        &format!("Geofence zone updated: {} ({})", zone.zone_id, zone.name),
    );
    Ok(Json(ZoneResponse { zone }))
}

pub async fn delete_zone(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ZoneResponse>, ApiError> {
    let zone = zones::delete_zone(&id).map_err(api_error)?;
    log_audit(
        &state.node_id,
        AuditCategory::Geofence,
        AuditSeverity::Warning,
        AuditAction::Succeeded,
        &format!("Geofence zone deleted: {} ({})", zone.zone_id, zone.name),
    );
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
        location: persistence::load_coordinate_location().map_err(api_error)?,
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
    let location = persistence::load_coordinate_location().map_err(api_error)?;
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
            let rf_location = persistence::load_rf_location().map_err(api_error)?;
            crate::geofence::eval::evaluate_registry_with_observations(
                &registry,
                location.as_ref().map(|location| &location.fix),
                rf_location.as_ref().map(|location| &location.fix),
            )
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
    State(state): State<Arc<AppState>>,
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
    log_audit(
        &state.node_id,
        AuditCategory::Geofence,
        AuditSeverity::Info,
        AuditAction::Updated,
        &format!("Geofence zone automation updated: {}", id),
    );
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
    if !request.confidence.is_finite() || !(0.0..=1.0).contains(&request.confidence) {
        return Err(ApiError::BadRequest(
            "confidence must be between 0.0 and 1.0".to_string(),
        ));
    }
    let zone = zones::list_zones()
        .map_err(api_error)?
        .into_iter()
        .find(|zone| zone.zone_id == request.zone_id)
        .ok_or_else(|| ApiError::NotFound(request.zone_id.clone()))?;
    zones::validate_zone(&zone).map_err(api_error)?;
    let dry_run = crate::geofence::actions::executor::dry_run_enabled();
    let fix = simulated_fix_for_zone(&zone);
    if !dry_run {
        let mut event = GeofenceEvent::new(&zone, &request.transition, &fix);
        event.origin = Some("manual_test".to_string());
        persistence::append_event(&event).map_err(api_error)?;
        if transition_actions(&zone, &request.transition)
            .iter()
            .any(|action| matches!(action, GeofenceAction::RaiseAlert { .. }))
        {
            geofence_alerts::emit_transition_alert(
                &state.node_id,
                &zone,
                &request.transition,
                &fix,
            )
            .await
            .map_err(api_error)?;
        }
    }
    crate::geofence::actions::executor::dispatch_without_state(
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

fn simulated_fix_for_zone(zone: &GeofenceZone) -> Fix {
    match zone.kind {
        ZoneKind::Coordinate => Fix::coordinate(
            zone.center_lat.unwrap_or_default(),
            zone.center_lng.unwrap_or_default(),
            None,
        ),
        ZoneKind::RfSignature => Fix::RfSignature {
            aps: zone
                .rf_signature
                .as_ref()
                .map(|signature| signature.aps.clone())
                .unwrap_or_default(),
        },
    }
}

fn transition_actions<'a>(zone: &'a GeofenceZone, transition: &str) -> &'a [GeofenceAction] {
    if transition == "entry" {
        &zone.automation.on_entry
    } else {
        &zone.automation.on_exit
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geofence::actions::{GeofenceAction, ZoneAutomation};
    use crate::geofence::model::{GeofenceRegistry, ZoneKind};
    use std::sync::MutexGuard;

    struct EnvGuard {
        original: Vec<(&'static str, Option<String>)>,
        _lock: MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn set_many(set: &[(&'static str, &str)], remove: &[&'static str]) -> Self {
            let lock = persistence::TEST_ENV_LOCK
                .lock()
                .expect("env lock poisoned");
            let mut keys = Vec::new();
            for (key, _) in set {
                if !keys.contains(key) {
                    keys.push(*key);
                }
            }
            for key in remove {
                if !keys.contains(key) {
                    keys.push(*key);
                }
            }
            let original = keys
                .into_iter()
                .map(|key| (key, std::env::var(key).ok()))
                .collect::<Vec<_>>();
            for (key, value) in set {
                std::env::set_var(key, value);
            }
            for key in remove {
                if !set.iter().any(|(set_key, _)| set_key == key) {
                    std::env::remove_var(key);
                }
            }
            Self {
                original,
                _lock: lock,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.original {
                if let Some(value) = value {
                    std::env::set_var(key, value);
                } else {
                    std::env::remove_var(key);
                }
            }
        }
    }

    fn test_state(temp: &tempfile::TempDir) -> Arc<AppState> {
        let config_dir = temp.path().join("config");
        std::fs::create_dir_all(&config_dir).expect("config dir");
        AppState::for_tests(temp.path(), "nodeA", config_dir.display().to_string())
    }

    fn save_zone(automation: ZoneAutomation) -> GeofenceZone {
        let zone = zones::new_zone(zones::NewZoneInput {
            name: "Coordinate Zone".to_string(),
            topology_node_ref: None,
            kind: ZoneKind::Coordinate,
            center_lat: Some(24.8607),
            center_lng: Some(67.0011),
            radius_m: Some(100.0),
            rf_signature: None,
            on_entry: true,
            on_exit: true,
            severity: "high".to_string(),
            automation,
            enabled: true,
        });
        let mut registry = GeofenceRegistry {
            zones: vec![zone.clone()],
            ..GeofenceRegistry::default()
        };
        zones::seal_registry(&mut registry).expect("seal registry");
        persistence::save_registry(&registry).expect("save registry");
        zone
    }

    async fn simulate(state: Arc<AppState>, zone_id: &str, transition: &str) -> ActionsResponse {
        let axum::Json(response) = test_actions(
            axum::extract::State(state),
            axum::Json(TestActionsRequest {
                zone_id: zone_id.to_string(),
                transition: transition.to_string(),
                confidence: 1.0,
            }),
        )
        .await
        .expect("test actions");
        response
    }

    #[tokio::test]
    async fn dry_run_simulation_creates_no_event_or_alert() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[
                (
                    persistence::GEOFENCE_BASE_ENV,
                    temp.path().to_str().expect("temp path"),
                ),
                ("SGX_GEOFENCE_ACTIONS_DRYRUN", "1"),
            ],
            &[],
        );
        let zone = save_zone(ZoneAutomation::default());

        simulate(test_state(&temp), &zone.zone_id, "exit").await;

        assert!(persistence::list_events().expect("events").is_empty());
        assert!(geofence_alerts::list_alerts().expect("alerts").is_empty());
    }

    #[tokio::test]
    async fn live_entry_simulation_creates_one_simulated_event() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[
                (
                    persistence::GEOFENCE_BASE_ENV,
                    temp.path().to_str().expect("temp path"),
                ),
                ("SGX_GEOFENCE_ACTIONS_DRYRUN", "0"),
            ],
            &[],
        );
        let zone = save_zone(ZoneAutomation::default());

        simulate(test_state(&temp), &zone.zone_id, "entry").await;

        let events = persistence::list_events().expect("events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].transition, "entry");
        assert_eq!(events[0].origin.as_deref(), Some("manual_test"));
        assert!(geofence_alerts::list_alerts().expect("alerts").is_empty());
    }

    #[tokio::test]
    async fn live_exit_with_raise_alert_creates_one_event_and_one_alert() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[
                (
                    persistence::GEOFENCE_BASE_ENV,
                    temp.path().to_str().expect("temp path"),
                ),
                ("SGX_GEOFENCE_ACTIONS_DRYRUN", "0"),
            ],
            &[],
        );
        let zone = save_zone(ZoneAutomation::default());

        simulate(test_state(&temp), &zone.zone_id, "exit").await;

        let events = persistence::list_events().expect("events");
        let alerts = geofence_alerts::list_alerts().expect("alerts");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].transition, "exit");
        assert_eq!(events[0].origin.as_deref(), Some("manual_test"));
        assert_eq!(alerts.len(), 1);
    }

    #[tokio::test]
    async fn notify_simulation_does_not_create_security_alert() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[
                (
                    persistence::GEOFENCE_BASE_ENV,
                    temp.path().to_str().expect("temp path"),
                ),
                ("SGX_GEOFENCE_ACTIONS_DRYRUN", "0"),
            ],
            &[],
        );
        let zone = save_zone(ZoneAutomation {
            on_entry: vec![GeofenceAction::Notify { severity: None }],
            on_exit: Vec::new(),
            allow_destructive: false,
            min_confidence: 0.0,
        });

        simulate(test_state(&temp), &zone.zone_id, "entry").await;

        assert_eq!(persistence::list_events().expect("events").len(), 1);
        assert!(geofence_alerts::list_alerts().expect("alerts").is_empty());
    }

    #[tokio::test]
    async fn simulation_does_not_change_real_zone_status() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[
                (
                    persistence::GEOFENCE_BASE_ENV,
                    temp.path().to_str().expect("temp path"),
                ),
                ("SGX_GEOFENCE_ACTIONS_DRYRUN", "0"),
            ],
            &[],
        );
        let zone = save_zone(ZoneAutomation::default());
        persistence::save_statuses(&[ZoneStatus {
            zone_id: zone.zone_id.clone(),
            zone_name: zone.name.clone(),
            enabled: true,
            inside: Some(true),
            distance_m: Some(0.0),
            rf_score: None,
        }])
        .expect("save statuses");

        simulate(test_state(&temp), &zone.zone_id, "exit").await;

        let statuses = persistence::load_statuses()
            .expect("statuses")
            .expect("stored statuses");
        assert_eq!(statuses[0].inside, Some(true));
    }

    fn valid_create_request(name: &str) -> CreateZoneRequest {
        CreateZoneRequest {
            name: name.to_string(),
            topology_node_ref: None,
            kind: ZoneKind::Coordinate,
            center_lat: Some(24.8607),
            center_lng: Some(67.0011),
            radius_m: Some(100.0),
            rf_signature: None,
            on_entry: true,
            on_exit: true,
            severity: "high".to_string(),
            automation: ZoneAutomation::default(),
            enabled: true,
        }
    }

    #[tokio::test]
    async fn create_zone_rejects_missing_coordinate_fields() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[(
                persistence::GEOFENCE_BASE_ENV,
                temp.path().to_str().expect("temp path"),
            )],
            &[],
        );
        let mut request = valid_create_request("Missing Fields");
        request.center_lat = None;

        let err = create_zone(axum::extract::State(test_state(&temp)), axum::Json(request))
            .await
            .expect_err("should reject missing coordinate fields");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn create_zone_rejects_out_of_range_latitude() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[(
                persistence::GEOFENCE_BASE_ENV,
                temp.path().to_str().expect("temp path"),
            )],
            &[],
        );
        let mut request = valid_create_request("Bad Latitude");
        request.center_lat = Some(200.0);

        let err = create_zone(axum::extract::State(test_state(&temp)), axum::Json(request))
            .await
            .expect_err("should reject out-of-range latitude");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn create_zone_rejects_non_positive_radius() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[(
                persistence::GEOFENCE_BASE_ENV,
                temp.path().to_str().expect("temp path"),
            )],
            &[],
        );
        let mut request = valid_create_request("Zero Radius");
        request.radius_m = Some(0.0);

        let err = create_zone(axum::extract::State(test_state(&temp)), axum::Json(request))
            .await
            .expect_err("should reject non-positive radius");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn create_zone_rejects_invalid_severity() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[(
                persistence::GEOFENCE_BASE_ENV,
                temp.path().to_str().expect("temp path"),
            )],
            &[],
        );
        let mut request = valid_create_request("Bad Severity");
        request.severity = "catastrophic".to_string();

        let err = create_zone(axum::extract::State(test_state(&temp)), axum::Json(request))
            .await
            .expect_err("should reject invalid severity");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn create_zone_rejects_empty_name() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[(
                persistence::GEOFENCE_BASE_ENV,
                temp.path().to_str().expect("temp path"),
            )],
            &[],
        );
        let request = valid_create_request("   ");

        let err = create_zone(axum::extract::State(test_state(&temp)), axum::Json(request))
            .await
            .expect_err("should reject empty name");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn create_zone_succeeds_and_appears_in_list() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[(
                persistence::GEOFENCE_BASE_ENV,
                temp.path().to_str().expect("temp path"),
            )],
            &[],
        );
        let request = valid_create_request("Living Room");

        let axum::Json(created) = create_zone(
            axum::extract::State(test_state(&temp)),
            axum::Json(request),
        )
        .await
        .expect("create zone");

        let axum::Json(listed) = list_zones(axum::extract::State(test_state(&temp)))
            .await
            .expect("list zones");
        assert_eq!(listed.count, 1);
        assert_eq!(listed.zones[0].zone_id, created.zone.zone_id);
        assert_eq!(listed.zones[0].name, "Living Room");
    }

    #[tokio::test]
    async fn edit_zone_missing_id_returns_not_found() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[(
                persistence::GEOFENCE_BASE_ENV,
                temp.path().to_str().expect("temp path"),
            )],
            &[],
        );
        let request = EditZoneRequest {
            name: Some("New Name".to_string()),
            topology_node_ref: None,
            kind: None,
            center_lat: None,
            center_lng: None,
            radius_m: None,
            rf_signature: None,
            on_entry: None,
            on_exit: None,
            severity: None,
            automation: None,
            enabled: None,
        };

        let err = edit_zone(
            axum::extract::State(test_state(&temp)),
            axum::extract::Path("does-not-exist".to_string()),
            axum::Json(request),
        )
        .await
        .expect_err("should not find zone");
        assert!(matches!(err, ApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn edit_zone_rejects_invalid_patch() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[(
                persistence::GEOFENCE_BASE_ENV,
                temp.path().to_str().expect("temp path"),
            )],
            &[],
        );
        let zone = save_zone(ZoneAutomation::default());
        let request = EditZoneRequest {
            name: None,
            topology_node_ref: None,
            kind: None,
            center_lat: None,
            center_lng: None,
            radius_m: None,
            rf_signature: None,
            on_entry: None,
            on_exit: None,
            severity: Some("unknown-severity".to_string()),
            automation: None,
            enabled: None,
        };

        let err = edit_zone(
            axum::extract::State(test_state(&temp)),
            axum::extract::Path(zone.zone_id.clone()),
            axum::Json(request),
        )
        .await
        .expect_err("should reject invalid severity patch");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn delete_zone_missing_id_returns_not_found() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[(
                persistence::GEOFENCE_BASE_ENV,
                temp.path().to_str().expect("temp path"),
            )],
            &[],
        );

        let err = delete_zone(
            axum::extract::State(test_state(&temp)),
            axum::extract::Path("does-not-exist".to_string()),
        )
        .await
        .expect_err("should not find zone to delete");
        assert!(matches!(err, ApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn delete_zone_removes_zone_from_registry() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[(
                persistence::GEOFENCE_BASE_ENV,
                temp.path().to_str().expect("temp path"),
            )],
            &[],
        );
        let zone = save_zone(ZoneAutomation::default());

        let axum::Json(deleted) = delete_zone(
            axum::extract::State(test_state(&temp)),
            axum::extract::Path(zone.zone_id.clone()),
        )
        .await
        .expect("delete zone");
        assert_eq!(deleted.zone.zone_id, zone.zone_id);

        let axum::Json(listed) = list_zones(axum::extract::State(test_state(&temp)))
            .await
            .expect("list zones");
        assert!(listed.zones.is_empty());
    }

    #[tokio::test]
    async fn report_location_rejects_out_of_range_coordinates() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[(
                persistence::GEOFENCE_BASE_ENV,
                temp.path().to_str().expect("temp path"),
            )],
            &[],
        );

        let err = report_location(
            axum::extract::State(test_state(&temp)),
            axum::Json(ReportLocationRequest {
                lat: 500.0,
                lng: 0.0,
                accuracy_m: None,
            }),
        )
        .await
        .expect_err("should reject out-of-range latitude");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn report_location_rejects_negative_accuracy() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[(
                persistence::GEOFENCE_BASE_ENV,
                temp.path().to_str().expect("temp path"),
            )],
            &[],
        );

        let err = report_location(
            axum::extract::State(test_state(&temp)),
            axum::Json(ReportLocationRequest {
                lat: 24.8607,
                lng: 67.0011,
                accuracy_m: Some(-5.0),
            }),
        )
        .await
        .expect_err("should reject negative accuracy");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn report_location_rejects_non_finite_accuracy() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[(
                persistence::GEOFENCE_BASE_ENV,
                temp.path().to_str().expect("temp path"),
            )],
            &[],
        );

        let err = report_location(
            axum::extract::State(test_state(&temp)),
            axum::Json(ReportLocationRequest {
                lat: 24.8607,
                lng: 67.0011,
                accuracy_m: Some(f64::NAN),
            }),
        )
        .await
        .expect_err("should reject NaN accuracy");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn report_location_persists_and_is_retrievable() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[(
                persistence::GEOFENCE_BASE_ENV,
                temp.path().to_str().expect("temp path"),
            )],
            &[],
        );

        let axum::Json(reported) = report_location(
            axum::extract::State(test_state(&temp)),
            axum::Json(ReportLocationRequest {
                lat: 24.8607,
                lng: 67.0011,
                accuracy_m: Some(12.5),
            }),
        )
        .await
        .expect("report location");
        assert!(reported.location.is_some());

        let axum::Json(fetched) = get_location(axum::extract::State(test_state(&temp)))
            .await
            .expect("get location");
        assert!(fetched.location.is_some());
    }

    #[tokio::test]
    async fn get_location_returns_none_when_missing() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[(
                persistence::GEOFENCE_BASE_ENV,
                temp.path().to_str().expect("temp path"),
            )],
            &[],
        );

        let axum::Json(fetched) = get_location(axum::extract::State(test_state(&temp)))
            .await
            .expect("get location");
        assert!(fetched.location.is_none());
    }

    #[tokio::test]
    async fn list_zones_and_events_and_alerts_start_empty() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[(
                persistence::GEOFENCE_BASE_ENV,
                temp.path().to_str().expect("temp path"),
            )],
            &["SGX_GEOFENCE_SEED_DEMO_ZONES"],
        );

        let axum::Json(zones_resp) = list_zones(axum::extract::State(test_state(&temp)))
            .await
            .expect("list zones");
        assert_eq!(zones_resp.count, 0);

        let axum::Json(events_resp) = events(axum::extract::State(test_state(&temp)))
            .await
            .expect("events");
        assert_eq!(events_resp.count, 0);

        let axum::Json(alerts_resp) = alerts(axum::extract::State(test_state(&temp)))
            .await
            .expect("alerts");
        assert_eq!(alerts_resp.count, 0);
    }

    #[tokio::test]
    async fn get_actions_missing_zone_returns_not_found() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[(
                persistence::GEOFENCE_BASE_ENV,
                temp.path().to_str().expect("temp path"),
            )],
            &[],
        );

        let err = get_actions(
            axum::extract::State(test_state(&temp)),
            axum::extract::Path("does-not-exist".to_string()),
        )
        .await
        .expect_err("should not find zone actions");
        assert!(matches!(err, ApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn get_actions_returns_zone_automation() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[(
                persistence::GEOFENCE_BASE_ENV,
                temp.path().to_str().expect("temp path"),
            )],
            &[],
        );
        let zone = save_zone(ZoneAutomation::default());

        let axum::Json(response) = get_actions(
            axum::extract::State(test_state(&temp)),
            axum::extract::Path(zone.zone_id.clone()),
        )
        .await
        .expect("get actions");
        assert_eq!(response.zone_id, zone.zone_id);
    }

    #[tokio::test]
    async fn put_actions_rejects_invalid_min_confidence() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[(
                persistence::GEOFENCE_BASE_ENV,
                temp.path().to_str().expect("temp path"),
            )],
            &[],
        );
        let zone = save_zone(ZoneAutomation::default());
        let automation = ZoneAutomation {
            on_entry: Vec::new(),
            on_exit: Vec::new(),
            allow_destructive: false,
            min_confidence: 1.5,
        };

        let err = put_actions(
            axum::extract::State(test_state(&temp)),
            axum::extract::Path(zone.zone_id.clone()),
            axum::Json(automation),
        )
        .await
        .expect_err("should reject out-of-range min_confidence");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn put_actions_updates_zone_automation() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[(
                persistence::GEOFENCE_BASE_ENV,
                temp.path().to_str().expect("temp path"),
            )],
            &[],
        );
        let zone = save_zone(ZoneAutomation::default());
        let automation = ZoneAutomation {
            on_entry: vec![GeofenceAction::Notify { severity: None }],
            on_exit: Vec::new(),
            allow_destructive: false,
            min_confidence: 0.5,
        };

        let axum::Json(response) = put_actions(
            axum::extract::State(test_state(&temp)),
            axum::extract::Path(zone.zone_id.clone()),
            axum::Json(automation),
        )
        .await
        .expect("put actions");
        assert_eq!(response.automation.min_confidence, 0.5);
        assert_eq!(response.automation.on_entry.len(), 1);
    }

    #[tokio::test]
    async fn test_actions_rejects_invalid_transition() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[
                (
                    persistence::GEOFENCE_BASE_ENV,
                    temp.path().to_str().expect("temp path"),
                ),
                ("SGX_GEOFENCE_ACTIONS_DRYRUN", "1"),
            ],
            &[],
        );
        let zone = save_zone(ZoneAutomation::default());

        let err = test_actions(
            axum::extract::State(test_state(&temp)),
            axum::Json(TestActionsRequest {
                zone_id: zone.zone_id.clone(),
                transition: "sideways".to_string(),
                confidence: 1.0,
            }),
        )
        .await
        .expect_err("should reject invalid transition");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn test_actions_rejects_out_of_range_confidence() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[
                (
                    persistence::GEOFENCE_BASE_ENV,
                    temp.path().to_str().expect("temp path"),
                ),
                ("SGX_GEOFENCE_ACTIONS_DRYRUN", "1"),
            ],
            &[],
        );
        let zone = save_zone(ZoneAutomation::default());

        let err = test_actions(
            axum::extract::State(test_state(&temp)),
            axum::Json(TestActionsRequest {
                zone_id: zone.zone_id.clone(),
                transition: "entry".to_string(),
                confidence: 1.5,
            }),
        )
        .await
        .expect_err("should reject out-of-range confidence");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn test_actions_missing_zone_returns_not_found() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[
                (
                    persistence::GEOFENCE_BASE_ENV,
                    temp.path().to_str().expect("temp path"),
                ),
                ("SGX_GEOFENCE_ACTIONS_DRYRUN", "1"),
            ],
            &[],
        );

        let err = test_actions(
            axum::extract::State(test_state(&temp)),
            axum::Json(TestActionsRequest {
                zone_id: "does-not-exist".to_string(),
                transition: "entry".to_string(),
                confidence: 1.0,
            }),
        )
        .await
        .expect_err("should not find zone");
        assert!(matches!(err, ApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn status_route_reflects_configured_source_when_unset() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[(
                persistence::GEOFENCE_BASE_ENV,
                temp.path().to_str().expect("temp path"),
            )],
            &["SGX_GEOFENCE_SEED_DEMO_ZONES", "SGX_GEOFENCE_SOURCE"],
        );

        let axum::Json(response) = status(axum::extract::State(test_state(&temp)))
            .await
            .expect("status");
        assert_eq!(response.selection_mode, "auto");
        assert!(response.location.is_none());
    }

    #[test]
    fn api_error_maps_not_found_to_404_kind() {
        let mapped = api_error(GeofenceError::NotFound("zone-1".to_string()));
        assert!(matches!(mapped, ApiError::NotFound(message) if message == "zone-1"));
    }

    #[test]
    fn api_error_maps_rf_scan_busy_to_service_unavailable() {
        let mapped = api_error(GeofenceError::RfScanBusy("busy".to_string()));
        assert!(matches!(
            mapped,
            ApiError::ServiceUnavailable {
                code: "RF_SCAN_BUSY",
                ..
            }
        ));
    }

    #[test]
    fn api_error_maps_invalid_proof_to_internal() {
        let mapped = api_error(GeofenceError::InvalidProof);
        assert!(matches!(mapped, ApiError::Internal(_)));
    }
}
