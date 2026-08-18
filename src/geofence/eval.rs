use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::geofence::errors::GeofenceResult;
use crate::geofence::model::{Fix, GeofenceEvent, GeofenceRegistry, StoredLocation, ZoneStatus};
use crate::geofence::sources::LocationSource;
use crate::geofence::{persistence, sources, zones};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::{interval, MissedTickBehavior};

#[derive(Debug, Clone, Copy, Default)]
struct ZoneRuntimeState {
    confirmed_inside: bool,
    candidate_inside: Option<bool>,
    candidate_count: u64,
}

pub async fn evaluation_loop(node_id: String, config: crate::geofence::GeofenceConfig) {
    let source = match sources::from_env() {
        Ok(source) => source,
        Err(error) => {
            tracing::warn!("Geofence source configuration invalid: {}", error);
            return;
        }
    };
    let mut ticker = interval(Duration::from_secs(config.eval_secs));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut states: HashMap<String, ZoneRuntimeState> = HashMap::new();

    loop {
        ticker.tick().await;
        match run_evaluation_cycle(&node_id, source.as_ref(), &config, &mut states).await {
            Ok(Some(statuses)) => {
                tracing::debug!(
                    source = source.id(),
                    zones_evaluated = statuses.len(),
                    "geofence evaluation cycle completed"
                );
            }
            Ok(None) => {
                tracing::warn!(
                    source = source.id(),
                    "geofence evaluation cycle produced no location fix"
                );
            }
            Err(error) => {
                tracing::warn!(
                    source = source.id(),
                    error = %error,
                    "geofence evaluation cycle failed"
                );
            }
        }
    }
}

async fn run_evaluation_cycle(
    node_id: &str,
    source: &dyn LocationSource,
    config: &crate::geofence::GeofenceConfig,
    states: &mut HashMap<String, ZoneRuntimeState>,
) -> GeofenceResult<Option<Vec<ZoneStatus>>> {
    let Some(fix) = source.current().await else {
        persistence::save_source_selection(&crate::geofence::model::SourceSelectionStatus::new(
            source.selection_mode(),
            None,
            source.source_reason(),
        ))?;
        let coordinate_location = persistence::load_coordinate_location()?;
        let rf_location = persistence::load_rf_location()?;
        if coordinate_location.is_some() || rf_location.is_some() {
            let registry = zones::load_or_seed_registry()?;
            let statuses = evaluate_registry_with_observations(
                &registry,
                coordinate_location.as_ref().map(|location| &location.fix),
                rf_location.as_ref().map(|location| &location.fix),
            );
            persistence::save_statuses(&statuses)?;
            return Ok(Some(statuses));
        }
        if should_preserve_last_fix(source)
            && last_location_is_fresh(sources::configured_freshness())?
        {
            tracing::warn!(
                source = source.id(),
                freshness_secs = sources::configured_freshness().as_secs(),
                "geofence evaluation preserving last valid fix after temporary source miss"
            );
            return Ok(None);
        }
        persistence::clear_location()?;
        persistence::clear_statuses()?;
        return Ok(None);
    };

    let active_source = source.active_id();
    persist_observation(&active_source, &fix)?;
    persistence::save_source_selection(&crate::geofence::model::SourceSelectionStatus::new(
        source.selection_mode(),
        Some(active_source.clone()),
        source.source_reason(),
    ))?;
    tracing::debug!(
        source = active_source,
        selection_mode = source.selection_mode(),
        fix_summary = %fix.summary(),
        "geofence evaluation stored current location"
    );

    let registry = zones::load_or_seed_registry()?;
    let coordinate_location = persistence::load_coordinate_location()?;
    let rf_location = persistence::load_rf_location()?;
    let coordinate_fix = coordinate_location.as_ref().map(|location| &location.fix);
    let rf_fix = rf_location.as_ref().map(|location| &location.fix);
    let mut statuses = Vec::new();
    for zone in registry.zones.iter().filter(|zone| zone.enabled) {
        let Some(zone_fix) = fix_for_zone(zone, coordinate_fix, rf_fix) else {
            statuses.push(zones::status_without_fix(zone));
            continue;
        };
        let status = zones::evaluate_zone(zone, zone_fix);
        let Some(observed_inside) = status.inside else {
            statuses.push(status);
            continue;
        };
        let state = states.entry(zone.zone_id.clone()).or_default();
        if observed_inside == state.confirmed_inside {
            state.candidate_inside = None;
            state.candidate_count = 0;
            statuses.push(status);
            continue;
        }
        if state.candidate_inside == Some(observed_inside) {
            state.candidate_count += 1;
        } else {
            state.candidate_inside = Some(observed_inside);
            state.candidate_count = 1;
        }
        if state.candidate_count < config.hysteresis {
            statuses.push(status);
            continue;
        }

        state.confirmed_inside = observed_inside;
        state.candidate_inside = None;
        state.candidate_count = 0;

        let transition = if observed_inside { "entry" } else { "exit" };
        if (observed_inside && !zone.on_entry) || (!observed_inside && !zone.on_exit) {
            statuses.push(status);
            continue;
        }
        let confidence = status.rf_score.unwrap_or(1.0);
        emit_transition(node_id, zone, transition, zone_fix);
        let zone_cloned = zone.clone();
        let node = node_id.to_string();
        tokio::spawn(async move {
            crate::geofence::actions::executor::dispatch(
                &node,
                &zone_cloned,
                transition,
                confidence,
            )
            .await;
        });
        statuses.push(status);
    }

    persistence::save_statuses(&statuses)?;
    Ok(Some(statuses))
}

fn persist_observation(active_source: &str, fix: &Fix) -> GeofenceResult<()> {
    let location = StoredLocation::new(active_source.to_string(), fix.clone());
    match fix {
        Fix::Coordinate { .. } => {
            persistence::save_reported_location(&location)?;
            persistence::save_location(&location)?;
        }
        Fix::RfSignature { .. } => {
            persistence::save_rf_location(&location)?;
        }
    }
    Ok(())
}

fn fix_for_zone<'a>(
    zone: &crate::geofence::model::GeofenceZone,
    coordinate_fix: Option<&'a Fix>,
    rf_fix: Option<&'a Fix>,
) -> Option<&'a Fix> {
    match zone.kind {
        crate::geofence::model::ZoneKind::Coordinate => coordinate_fix,
        crate::geofence::model::ZoneKind::RfSignature => rf_fix,
    }
}

pub(crate) fn evaluate_registry_with_observations(
    registry: &GeofenceRegistry,
    coordinate_fix: Option<&Fix>,
    rf_fix: Option<&Fix>,
) -> Vec<ZoneStatus> {
    registry
        .zones
        .iter()
        .map(|zone| {
            fix_for_zone(zone, coordinate_fix, rf_fix)
                .map(|fix| zones::evaluate_zone(zone, fix))
                .unwrap_or_else(|| zones::status_without_fix(zone))
        })
        .collect()
}

fn should_preserve_last_fix(source: &dyn LocationSource) -> bool {
    matches!(source.id(), "rf" | "auto")
}

fn last_location_is_fresh(freshness: Duration) -> GeofenceResult<bool> {
    let Some(location) = persistence::load_location()? else {
        return Ok(false);
    };
    let Ok(updated_at) = DateTime::parse_from_rfc3339(&location.updated_at) else {
        return Ok(false);
    };
    let age = Utc::now().signed_duration_since(updated_at.with_timezone(&Utc));
    Ok(age.num_seconds() >= 0 && age <= chrono::Duration::from_std(freshness).unwrap_or_default())
}

fn emit_transition(
    node_id: &str,
    zone: &crate::geofence::model::GeofenceZone,
    transition: &str,
    fix: &Fix,
) {
    let event = GeofenceEvent::new(zone, transition, fix);
    if let Err(error) = persistence::append_event(&event) {
        tracing::warn!("failed to persist geofence event {}: {}", event.id, error);
        return;
    }
    log_audit(
        node_id,
        AuditCategory::Geofence,
        if event.severity == "critical" {
            AuditSeverity::Critical
        } else if event.severity == "info" || event.severity == "low" {
            AuditSeverity::Info
        } else {
            AuditSeverity::Warning
        },
        AuditAction::Detected,
        &format!(
            "Geofence {} for zone {} ({}) via {}",
            transition, event.zone_name, event.zone_id, event.fix_summary
        ),
    );
    let node = node_id.to_string();
    let zone = zone.clone();
    let transition = transition.to_string();
    let fix = fix.clone();
    tokio::spawn(async move {
        if let Err(error) =
            crate::geofence::alerts::emit_transition_alert(&node, &zone, &transition, &fix).await
        {
            tracing::warn!("failed to emit geofence alert: {}", error);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geofence::actions::ZoneAutomation;
    use crate::geofence::model::{
        ApObservation, GeofenceRegistry, GeofenceZone, RfSignature, ZoneKind,
    };
    use async_trait::async_trait;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    struct MockRfSource {
        fix: Option<Fix>,
    }

    #[async_trait]
    impl LocationSource for MockRfSource {
        fn id(&self) -> &'static str {
            "rf"
        }

        async fn current(&self) -> Option<Fix> {
            self.fix.clone()
        }
    }

    struct SequenceRfSource {
        fixes: Arc<Mutex<VecDeque<Option<Fix>>>>,
    }

    #[async_trait]
    impl LocationSource for SequenceRfSource {
        fn id(&self) -> &'static str {
            "rf"
        }

        async fn current(&self) -> Option<Fix> {
            self.fixes
                .lock()
                .expect("fixes lock poisoned")
                .pop_front()
                .flatten()
        }
    }

    struct EnvGuard {
        key: &'static str,
        original: Option<String>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let lock = persistence::TEST_ENV_LOCK
                .lock()
                .expect("env lock poisoned");
            let original = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self {
                key,
                original,
                _lock: lock,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(value) = &self.original {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn ap(bssid: &str) -> ApObservation {
        ApObservation {
            bssid: bssid.to_string(),
            signal_dbm: Some(-55),
        }
    }

    fn rf_zone() -> GeofenceZone {
        GeofenceZone {
            zone_id: "rf-zone".to_string(),
            name: "RF Zone".to_string(),
            topology_node_ref: None,
            kind: ZoneKind::RfSignature,
            center_lat: None,
            center_lng: None,
            radius_m: None,
            rf_signature: Some(RfSignature {
                aps: vec![ap("00:11:22:33:44:55"), ap("aa:bb:cc:dd:ee:ff")],
                threshold: 0.5,
            }),
            on_entry: false,
            on_exit: false,
            severity: "high".to_string(),
            automation: ZoneAutomation::default(),
            enabled: true,
            created_at: "2026-07-28T00:00:00Z".to_string(),
            updated_at: "2026-07-28T00:00:00Z".to_string(),
        }
    }

    fn coord_zone() -> GeofenceZone {
        GeofenceZone {
            zone_id: "coord-zone".to_string(),
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
            automation: ZoneAutomation {
                on_entry: Vec::new(),
                on_exit: Vec::new(),
                allow_destructive: false,
                min_confidence: 0.0,
            },
            enabled: true,
            created_at: "2026-07-28T00:00:00Z".to_string(),
            updated_at: "2026-07-28T00:00:00Z".to_string(),
        }
    }

    fn save_registry_with_zone(zone: GeofenceZone) {
        save_registry_with_zones(vec![zone]);
    }

    fn save_registry_with_zones(registry_zones: Vec<GeofenceZone>) {
        let mut registry = GeofenceRegistry {
            zones: registry_zones,
            ..GeofenceRegistry::default()
        };
        zones::seal_registry(&mut registry).expect("seal registry");
        persistence::save_registry(&registry).expect("save registry");
    }

    #[tokio::test]
    async fn mock_rf_source_updates_location_and_rf_zone_score() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set(
            crate::geofence::persistence::GEOFENCE_BASE_ENV,
            temp.path().to_str().expect("temp path"),
        );

        save_registry_with_zone(rf_zone());

        let source = MockRfSource {
            fix: Some(Fix::RfSignature {
                aps: vec![ap("00:11:22:33:44:55")],
            }),
        };
        let config = crate::geofence::GeofenceConfig {
            eval_secs: 30,
            hysteresis: 1,
        };
        let mut states = HashMap::new();

        let statuses = run_evaluation_cycle("nodeA", &source, &config, &mut states)
            .await
            .expect("cycle")
            .expect("fix");

        assert!(persistence::load_location()
            .expect("load legacy current location")
            .is_none());
        let stored = persistence::load_rf_location()
            .expect("load rf observation")
            .expect("stored rf observation");
        assert_eq!(stored.source, "rf");
        assert!(matches!(stored.fix, Fix::RfSignature { .. }));
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].zone_id, "rf-zone");
        assert_eq!(statuses[0].rf_score, Some(0.5));
        assert_eq!(statuses[0].inside, Some(true));

        let config_dir = temp.path().join("config");
        std::fs::create_dir_all(&config_dir).expect("config dir");
        let state = crate::api::state::AppState::for_tests(
            temp.path(),
            "nodeA",
            config_dir.display().to_string(),
        );
        let axum::Json(response) =
            crate::api::handlers::geofence::status(axum::extract::State(state))
                .await
                .expect("status response");
        assert_eq!(response.zones.len(), 1);
        assert_eq!(response.zones[0].zone_id, "rf-zone");
        assert_eq!(response.zones[0].rf_score, Some(0.5));
        assert_eq!(response.zones[0].inside, Some(true));
    }

    #[tokio::test]
    async fn temporary_rf_failure_preserves_fresh_location_and_zone_status() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set(
            crate::geofence::persistence::GEOFENCE_BASE_ENV,
            temp.path().to_str().expect("temp path"),
        );
        save_registry_with_zone(rf_zone());

        let source = SequenceRfSource {
            fixes: Arc::new(Mutex::new(
                vec![
                    Some(Fix::RfSignature {
                        aps: vec![ap("00:11:22:33:44:55")],
                    }),
                    None,
                ]
                .into(),
            )),
        };
        let config = crate::geofence::GeofenceConfig {
            eval_secs: 30,
            hysteresis: 1,
        };
        let mut states = HashMap::new();

        let first = run_evaluation_cycle("nodeA", &source, &config, &mut states)
            .await
            .expect("first cycle")
            .expect("first fix");
        assert_eq!(first[0].inside, Some(true));
        assert_eq!(first[0].rf_score, Some(0.5));

        let second = run_evaluation_cycle("nodeA", &source, &config, &mut states)
            .await
            .expect("temporary miss should not fail");
        let second = second.expect("stored rf status should be reused");
        assert_eq!(second[0].inside, Some(true));
        assert_eq!(second[0].rf_score, Some(0.5));

        let stored = persistence::load_rf_location()
            .expect("load rf observation")
            .expect("fresh rf observation should remain");
        assert_eq!(stored.source, "rf");
        let statuses = persistence::load_statuses()
            .expect("load statuses")
            .expect("statuses should remain");
        assert_eq!(statuses[0].inside, Some(true));
        assert_eq!(statuses[0].rf_score, Some(0.5));
    }

    #[tokio::test]
    async fn reported_coordinate_remains_after_rf_scan_and_status_reports_it() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set(
            crate::geofence::persistence::GEOFENCE_BASE_ENV,
            temp.path().to_str().expect("temp path"),
        );
        save_registry_with_zones(vec![coord_zone(), rf_zone()]);
        let reported =
            StoredLocation::new("reported", Fix::coordinate(24.8607, 67.0011, Some(5.0)));
        persistence::save_reported_location(&reported).expect("save reported");
        persistence::save_location(&reported).expect("save legacy coordinate");
        let source = MockRfSource {
            fix: Some(Fix::RfSignature {
                aps: vec![ap("00:11:22:33:44:55")],
            }),
        };
        let config = crate::geofence::GeofenceConfig {
            eval_secs: 30,
            hysteresis: 1,
        };
        let mut states = HashMap::new();

        run_evaluation_cycle("nodeA", &source, &config, &mut states)
            .await
            .expect("cycle")
            .expect("fix");

        let coordinate = persistence::load_coordinate_location()
            .expect("load coordinate")
            .expect("coordinate remains");
        assert_eq!(coordinate.source, "reported");
        assert!(matches!(coordinate.fix, Fix::Coordinate { .. }));
        let selection = persistence::load_source_selection()
            .expect("load selection")
            .expect("selection");
        assert_eq!(selection.active_source.as_deref(), Some("rf"));

        let config_dir = temp.path().join("config");
        std::fs::create_dir_all(&config_dir).expect("config dir");
        let state = crate::api::state::AppState::for_tests(
            temp.path(),
            "nodeA",
            config_dir.display().to_string(),
        );
        let axum::Json(response) =
            crate::api::handlers::geofence::status(axum::extract::State(state))
                .await
                .expect("status response");
        assert_eq!(response.source, "rf");
        assert!(matches!(
            response.location.expect("reported location").fix,
            Fix::Coordinate { .. }
        ));
    }

    #[tokio::test]
    async fn coordinate_zone_does_not_exit_when_rf_becomes_active() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set(
            crate::geofence::persistence::GEOFENCE_BASE_ENV,
            temp.path().to_str().expect("temp path"),
        );
        let coordinate_zone = coord_zone();
        save_registry_with_zones(vec![coordinate_zone.clone(), rf_zone()]);
        let reported =
            StoredLocation::new("reported", Fix::coordinate(24.8607, 67.0011, Some(5.0)));
        persistence::save_reported_location(&reported).expect("save reported");
        persistence::save_location(&reported).expect("save legacy coordinate");
        let source = MockRfSource {
            fix: Some(Fix::RfSignature {
                aps: vec![ap("00:11:22:33:44:55")],
            }),
        };
        let config = crate::geofence::GeofenceConfig {
            eval_secs: 30,
            hysteresis: 1,
        };
        let mut states = HashMap::new();
        states.insert(
            coordinate_zone.zone_id.clone(),
            ZoneRuntimeState {
                confirmed_inside: true,
                candidate_inside: None,
                candidate_count: 0,
            },
        );

        let statuses = run_evaluation_cycle("nodeA", &source, &config, &mut states)
            .await
            .expect("cycle")
            .expect("fix");

        let coordinate_status = statuses
            .iter()
            .find(|status| status.zone_id == "coord-zone")
            .expect("coordinate status");
        assert_eq!(coordinate_status.inside, Some(true));
        assert!(persistence::list_events().expect("events").is_empty());
    }

    #[tokio::test]
    async fn reported_coordinate_survives_restart_after_rf_scan() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set(
            crate::geofence::persistence::GEOFENCE_BASE_ENV,
            temp.path().to_str().expect("temp path"),
        );
        save_registry_with_zone(rf_zone());
        let reported =
            StoredLocation::new("reported", Fix::coordinate(24.8607, 67.0011, Some(5.0)));
        persistence::save_reported_location(&reported).expect("save reported");
        persistence::save_location(&reported).expect("save legacy coordinate");
        let source = MockRfSource {
            fix: Some(Fix::RfSignature {
                aps: vec![ap("00:11:22:33:44:55")],
            }),
        };
        let config = crate::geofence::GeofenceConfig {
            eval_secs: 30,
            hysteresis: 1,
        };
        let mut states = HashMap::new();

        run_evaluation_cycle("nodeA", &source, &config, &mut states)
            .await
            .expect("cycle");
        let restarted_coordinate = persistence::load_coordinate_location()
            .expect("load after restart")
            .expect("coordinate after restart");

        assert_eq!(restarted_coordinate, reported);
    }

    #[tokio::test]
    async fn rf_and_coordinate_zones_evaluate_independently() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set(
            crate::geofence::persistence::GEOFENCE_BASE_ENV,
            temp.path().to_str().expect("temp path"),
        );
        save_registry_with_zones(vec![coord_zone(), rf_zone()]);
        let reported =
            StoredLocation::new("reported", Fix::coordinate(24.8607, 67.0011, Some(5.0)));
        persistence::save_reported_location(&reported).expect("save reported");
        persistence::save_location(&reported).expect("save legacy coordinate");
        let source = MockRfSource {
            fix: Some(Fix::RfSignature {
                aps: vec![ap("00:11:22:33:44:55")],
            }),
        };
        let config = crate::geofence::GeofenceConfig {
            eval_secs: 30,
            hysteresis: 1,
        };
        let mut states = HashMap::new();

        let statuses = run_evaluation_cycle("nodeA", &source, &config, &mut states)
            .await
            .expect("cycle")
            .expect("fix");

        assert_eq!(
            statuses
                .iter()
                .find(|status| status.zone_id == "coord-zone")
                .expect("coordinate status")
                .inside,
            Some(true)
        );
        assert_eq!(
            statuses
                .iter()
                .find(|status| status.zone_id == "rf-zone")
                .expect("rf status")
                .inside,
            Some(true)
        );
    }
}
