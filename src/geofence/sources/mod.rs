use crate::geofence::errors::{GeofenceError, GeofenceResult};
use crate::geofence::model::{Fix, SourceSelectionStatus};
use crate::geofence::persistence;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub mod gnss;
pub mod manual;
pub mod reported;
pub mod rf;

#[async_trait]
pub trait LocationSource: Send + Sync {
    fn id(&self) -> &'static str;
    fn active_id(&self) -> String {
        self.id().to_string()
    }
    fn selection_mode(&self) -> &'static str {
        "forced"
    }
    fn source_reason(&self) -> String {
        format!("forced {}", self.id())
    }
    async fn current(&self) -> Option<Fix>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Auto,
    Manual,
    Reported,
    Rf,
    Gnss,
}

impl SourceKind {
    pub fn from_env() -> GeofenceResult<Self> {
        match std::env::var("SGX_GEOFENCE_SOURCE")
            .unwrap_or_else(|_| "auto".to_string())
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "" | "auto" => Ok(Self::Auto),
            "manual" => Ok(Self::Manual),
            "reported" => Ok(Self::Reported),
            "rf" | "rf_signature" | "rf-signature" => Ok(Self::Rf),
            "gnss" | "gps" => Ok(Self::Gnss),
            other => Err(GeofenceError::UnsupportedSource(other.to_string())),
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Manual => "manual",
            Self::Reported => "reported",
            Self::Rf => "rf",
            Self::Gnss => "gnss",
        }
    }
}

pub fn from_env() -> GeofenceResult<Box<dyn LocationSource>> {
    Ok(match SourceKind::from_env()? {
        SourceKind::Auto => Box::new(AutoSource::default()),
        SourceKind::Manual => Box::new(manual::ManualSource),
        SourceKind::Reported => Box::new(reported::ReportedSource),
        SourceKind::Rf => Box::new(rf::RfSource),
        SourceKind::Gnss => Box::new(gnss::GnssSource),
    })
}

#[derive(Debug, Clone)]
struct AutoConfig {
    freshness: Duration,
    confirmation_successes: u64,
    failure_threshold: u64,
    hold_down: Duration,
}

impl AutoConfig {
    fn from_env() -> Self {
        Self {
            freshness: env_duration("SGX_GEOFENCE_SOURCE_FRESHNESS_SECS", 120),
            confirmation_successes: env_u64("SGX_GEOFENCE_SOURCE_CONFIRM_SUCCESSES", 3).max(1),
            failure_threshold: env_u64("SGX_GEOFENCE_SOURCE_FAILURE_THRESHOLD", 3).max(1),
            hold_down: env_duration("SGX_GEOFENCE_SOURCE_HOLD_DOWN_SECS", 60),
        }
    }
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(default)
}

fn env_duration(key: &str, default_secs: u64) -> Duration {
    Duration::from_secs(env_u64(key, default_secs))
}

pub fn configured_freshness() -> Duration {
    env_duration("SGX_GEOFENCE_SOURCE_FRESHNESS_SECS", 120)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AutoProviderKind {
    Gnss,
    Rf,
    Reported,
}

impl AutoProviderKind {
    fn id(self) -> &'static str {
        match self {
            Self::Gnss => "gnss",
            Self::Rf => "rf",
            Self::Reported => "reported",
        }
    }

    fn priority(self) -> u8 {
        match self {
            Self::Gnss => 0,
            Self::Rf => 1,
            Self::Reported => 2,
        }
    }
}

#[derive(Debug, Clone)]
struct AutoCandidate {
    kind: AutoProviderKind,
    fix: Fix,
    reason: String,
}

#[derive(Debug, Clone)]
struct AutoState {
    active: Option<AutoProviderKind>,
    active_failures: u64,
    candidate: Option<AutoProviderKind>,
    candidate_successes: u64,
    hold_down_until: Option<Instant>,
    active_id: String,
    reason: String,
}

impl Default for AutoState {
    fn default() -> Self {
        Self {
            active: None,
            active_failures: 0,
            candidate: None,
            candidate_successes: 0,
            hold_down_until: None,
            active_id: "none".to_string(),
            reason: "auto source has not selected a provider yet".to_string(),
        }
    }
}

pub struct AutoSource {
    gnss: Box<dyn LocationSource>,
    rf: Box<dyn LocationSource>,
    config: AutoConfig,
    state: Mutex<AutoState>,
}

impl Default for AutoSource {
    fn default() -> Self {
        Self {
            gnss: Box::new(gnss::GnssSource),
            rf: Box::new(rf::RfSource),
            config: AutoConfig::from_env(),
            state: Mutex::new(AutoState::default()),
        }
    }
}

impl AutoSource {
    #[cfg(test)]
    fn with_sources(
        gnss: Box<dyn LocationSource>,
        rf: Box<dyn LocationSource>,
        config: AutoConfig,
    ) -> Self {
        Self {
            gnss,
            rf,
            config,
            state: Mutex::new(AutoState::default()),
        }
    }

    async fn candidates(&self) -> Vec<AutoCandidate> {
        let mut candidates = Vec::new();
        if let Some(fix) = self.gnss.current().await.filter(valid_fix) {
            candidates.push(AutoCandidate {
                kind: AutoProviderKind::Gnss,
                fix,
                reason: "fresh valid GNSS fix".to_string(),
            });
        }
        if let Some(fix) = self.rf.current().await.filter(valid_fix) {
            candidates.push(AutoCandidate {
                kind: AutoProviderKind::Rf,
                fix,
                reason: "RF signature available".to_string(),
            });
        }
        if let Some(candidate) = reported_candidate(self.config.freshness).await {
            candidates.push(candidate);
        }
        candidates.sort_by_key(|candidate| candidate.kind.priority());
        candidates
    }

    fn choose(&self, candidates: &[AutoCandidate]) -> Option<AutoCandidate> {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let active_available = state
            .active
            .is_some_and(|active| candidates.iter().any(|candidate| candidate.kind == active));
        if active_available {
            state.active_failures = 0;
        } else if state.active.is_some() {
            state.active_failures += 1;
        }

        let best = candidates.first().cloned();
        let Some(best) = best else {
            state.reason = match state.active {
                Some(active) => format!(
                    "no valid auto providers; active {} failure count {}",
                    active.id(),
                    state.active_failures
                ),
                None => "no valid auto providers".to_string(),
            };
            state.active_id = "none".to_string();
            return None;
        };

        if state.active == Some(best.kind) {
            state.candidate = None;
            state.candidate_successes = 0;
            state.active_id = best.kind.id().to_string();
            state.reason = best.reason.clone();
            return Some(best);
        }

        let in_hold_down = state.hold_down_until.is_some_and(|until| until > now);
        let active_candidate = state
            .active
            .and_then(|active| candidates.iter().find(|candidate| candidate.kind == active))
            .cloned();
        let active_failed = state.active_failures >= self.config.failure_threshold;
        if in_hold_down && !active_failed {
            if let Some(active_candidate) = active_candidate {
                state.reason = format!(
                    "holding {} during source hold-down",
                    active_candidate.kind.id()
                );
                state.active_id = active_candidate.kind.id().to_string();
                return Some(active_candidate);
            }
        }

        if state.candidate == Some(best.kind) {
            state.candidate_successes += 1;
        } else {
            state.candidate = Some(best.kind);
            state.candidate_successes = 1;
        }

        if state.active.is_some()
            && state.candidate_successes < self.config.confirmation_successes
            && !active_failed
        {
            if let Some(active_candidate) = active_candidate {
                state.reason = format!(
                    "holding {} until {} confirms for {} cycles",
                    active_candidate.kind.id(),
                    best.kind.id(),
                    self.config.confirmation_successes
                );
                state.active_id = active_candidate.kind.id().to_string();
                return Some(active_candidate);
            }
        }

        if state.active.is_none() && state.candidate_successes < self.config.confirmation_successes
        {
            state.reason = format!(
                "waiting for {} auto confirmation {}/{}",
                best.kind.id(),
                state.candidate_successes,
                self.config.confirmation_successes
            );
            state.active_id = "none".to_string();
            return None;
        }

        state.active = Some(best.kind);
        state.active_failures = 0;
        state.candidate = None;
        state.candidate_successes = 0;
        state.hold_down_until = Some(now + self.config.hold_down);
        state.active_id = best.kind.id().to_string();
        state.reason = best.reason.clone();
        Some(best)
    }
}

#[async_trait]
impl LocationSource for AutoSource {
    fn id(&self) -> &'static str {
        "auto"
    }

    fn active_id(&self) -> String {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .active_id
            .clone()
    }

    fn selection_mode(&self) -> &'static str {
        "auto"
    }

    fn source_reason(&self) -> String {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .reason
            .clone()
    }

    async fn current(&self) -> Option<Fix> {
        let candidates = self.candidates().await;
        let selected = self.choose(&candidates);
        let status = SourceSelectionStatus::new(
            "auto",
            selected
                .as_ref()
                .map(|candidate| candidate.kind.id().to_string()),
            self.source_reason(),
        );
        if let Err(error) = persistence::save_source_selection(&status) {
            tracing::warn!("failed to persist geofence source selection: {}", error);
        }
        selected.map(|candidate| candidate.fix)
    }
}

async fn reported_candidate(freshness: Duration) -> Option<AutoCandidate> {
    let location = persistence::load_reported_location_async()
        .await
        .ok()
        .flatten()?;
    if location.source != "reported" || !fresh_location(&location, freshness) {
        return None;
    }
    let fix = location.fix;
    if !valid_fix(&fix) {
        return None;
    }
    Some(AutoCandidate {
        kind: AutoProviderKind::Reported,
        fix,
        reason: "fresh signed reported location".to_string(),
    })
}

fn fresh_location(location: &crate::geofence::model::StoredLocation, freshness: Duration) -> bool {
    DateTime::parse_from_rfc3339(&location.updated_at)
        .map(|updated_at| {
            let age = Utc::now().signed_duration_since(updated_at.with_timezone(&Utc));
            age.num_seconds() >= 0
                && age <= chrono::Duration::from_std(freshness).unwrap_or_default()
        })
        .unwrap_or(false)
}

fn valid_fix(fix: &Fix) -> bool {
    match fix {
        Fix::Coordinate {
            lat,
            lng,
            accuracy_m,
        } => {
            lat.is_finite()
                && lng.is_finite()
                && (-90.0..=90.0).contains(lat)
                && (-180.0..=180.0).contains(lng)
                && accuracy_m.is_none_or(|accuracy| accuracy.is_finite() && accuracy >= 0.0)
        }
        Fix::RfSignature { aps } => !aps.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geofence::model::{ApObservation, StoredLocation};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex, MutexGuard};

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

    struct SequenceSource {
        id: &'static str,
        fixes: Arc<Mutex<VecDeque<Option<Fix>>>>,
        last: Arc<Mutex<Option<Fix>>>,
    }

    impl SequenceSource {
        fn new(id: &'static str, fixes: Vec<Option<Fix>>) -> Self {
            Self {
                id,
                fixes: Arc::new(Mutex::new(fixes.into())),
                last: Arc::new(Mutex::new(None)),
            }
        }
    }

    #[async_trait]
    impl LocationSource for SequenceSource {
        fn id(&self) -> &'static str {
            self.id
        }

        async fn current(&self) -> Option<Fix> {
            let mut fixes = self.fixes.lock().expect("fixes lock poisoned");
            if let Some(next) = fixes.pop_front() {
                *self.last.lock().expect("last lock poisoned") = next.clone();
                next
            } else {
                self.last.lock().expect("last lock poisoned").clone()
            }
        }
    }

    fn config() -> AutoConfig {
        AutoConfig {
            freshness: Duration::from_secs(30),
            confirmation_successes: 3,
            failure_threshold: 1,
            hold_down: Duration::ZERO,
        }
    }

    fn coord(lat: f64, lng: f64) -> Fix {
        Fix::Coordinate {
            lat,
            lng,
            accuracy_m: Some(5.0),
        }
    }

    fn rf_fix() -> Fix {
        Fix::RfSignature {
            aps: vec![ApObservation {
                bssid: "00:11:22:33:44:55".to_string(),
                signal_dbm: Some(-55),
            }],
        }
    }

    async fn current_id_after(source: &AutoSource, cycles: usize) -> Option<String> {
        let mut fix = None;
        for _ in 0..cycles {
            fix = source.current().await;
        }
        fix.map(|_| source.active_id())
    }

    #[tokio::test]
    async fn auto_selects_rf_when_gnss_is_unavailable() {
        let _env = EnvGuard::set_many(&[], &[crate::geofence::persistence::GEOFENCE_BASE_ENV]);
        let source = AutoSource::with_sources(
            Box::new(SequenceSource::new("gnss", vec![None])),
            Box::new(SequenceSource::new("rf", vec![Some(rf_fix())])),
            config(),
        );

        assert_eq!(current_id_after(&source, 3).await.as_deref(), Some("rf"));
    }

    #[tokio::test]
    async fn auto_falls_back_from_gnss_to_rf() {
        let _env = EnvGuard::set_many(&[], &[crate::geofence::persistence::GEOFENCE_BASE_ENV]);
        let source = AutoSource::with_sources(
            Box::new(SequenceSource::new(
                "gnss",
                vec![
                    Some(coord(24.0, 67.0)),
                    Some(coord(24.0, 67.0)),
                    Some(coord(24.0, 67.0)),
                    None,
                    None,
                    None,
                ],
            )),
            Box::new(SequenceSource::new("rf", vec![Some(rf_fix())])),
            config(),
        );

        assert_eq!(current_id_after(&source, 3).await.as_deref(), Some("gnss"));
        assert_eq!(current_id_after(&source, 3).await.as_deref(), Some("rf"));
    }

    #[tokio::test]
    async fn auto_recovers_to_gnss_after_confirmation() {
        let _env = EnvGuard::set_many(&[], &[crate::geofence::persistence::GEOFENCE_BASE_ENV]);
        let source = AutoSource::with_sources(
            Box::new(SequenceSource::new(
                "gnss",
                vec![None, None, None, Some(coord(24.0, 67.0))],
            )),
            Box::new(SequenceSource::new("rf", vec![Some(rf_fix())])),
            config(),
        );

        assert_eq!(current_id_after(&source, 3).await.as_deref(), Some("rf"));
        assert_eq!(current_id_after(&source, 3).await.as_deref(), Some("gnss"));
    }

    #[tokio::test]
    async fn auto_rejects_stale_reported_location() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _env = EnvGuard::set_many(
            &[(
                crate::geofence::persistence::GEOFENCE_BASE_ENV,
                temp.path().to_str().expect("temp path"),
            )],
            &[],
        );
        let stale = StoredLocation {
            source: "reported".to_string(),
            fix: coord(24.0, 67.0),
            updated_at: (Utc::now() - chrono::Duration::seconds(120)).to_rfc3339(),
        };
        persistence::save_reported_location(&stale).expect("save stale reported");
        let source = AutoSource::with_sources(
            Box::new(SequenceSource::new("gnss", vec![None])),
            Box::new(SequenceSource::new("rf", vec![None])),
            AutoConfig {
                freshness: Duration::from_secs(30),
                ..config()
            },
        );

        assert!(source.current().await.is_none());
    }

    #[tokio::test]
    async fn auto_does_not_flap_on_single_higher_priority_success() {
        let _env = EnvGuard::set_many(&[], &[crate::geofence::persistence::GEOFENCE_BASE_ENV]);
        let source = AutoSource::with_sources(
            Box::new(SequenceSource::new(
                "gnss",
                vec![None, None, None, Some(coord(24.0, 67.0)), None],
            )),
            Box::new(SequenceSource::new("rf", vec![Some(rf_fix())])),
            config(),
        );

        assert_eq!(current_id_after(&source, 3).await.as_deref(), Some("rf"));
        assert_eq!(current_id_after(&source, 1).await.as_deref(), Some("rf"));
    }

    #[test]
    fn forced_modes_and_auto_env_are_compatible() {
        let _env = EnvGuard::set_many(&[], &["SGX_GEOFENCE_SOURCE"]);
        assert_eq!(
            SourceKind::from_env().expect("auto default"),
            SourceKind::Auto
        );

        for (raw, expected) in [
            ("auto", SourceKind::Auto),
            ("manual", SourceKind::Manual),
            ("reported", SourceKind::Reported),
            ("rf", SourceKind::Rf),
            ("gnss", SourceKind::Gnss),
        ] {
            std::env::set_var("SGX_GEOFENCE_SOURCE", raw);
            assert_eq!(SourceKind::from_env().expect("source kind"), expected);
        }
    }
}
