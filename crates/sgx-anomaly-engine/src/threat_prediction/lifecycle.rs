//! Task 4 Deliverable 9: explainable forecast persistence and lifecycle audit.

use super::{ForecastSeverity, ForecastStatus, ThreatForecast, ThreatPredictionError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const DAY_MS: u64 = 24 * 60 * 60 * 1_000;
const MAX_EXPLANATION_SUMMARY_BYTES: usize = 4_096;
const MAX_FACTOR_NAME_BYTES: usize = 160;
const MAX_EVIDENCE_ID_BYTES: usize = 160;
const MAX_TRANSITION_REASON_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForecastAuditRecord {
    pub forecast: ThreatForecast,
    pub recorded_at_ms: u64,
    pub prior_status: Option<ForecastStatus>,
    pub transition_reason: String,
    pub retention_expires_at_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ForecastStore {
    root: PathBuf,
    retention_days: u32,
}

impl ForecastStore {
    pub fn new(root: impl AsRef<Path>, retention_days: u32) -> Result<Self, ThreatPredictionError> {
        if retention_days == 0 {
            return Err(ThreatPredictionError::InvalidConfig(
                "forecast retention_days must be greater than zero".into(),
            ));
        }
        let store = Self {
            root: root.as_ref().to_path_buf(),
            retention_days,
        };
        fs::create_dir_all(store.forecasts_dir()).map_err(io_error)?;
        fs::create_dir_all(store.history_dir()).map_err(io_error)?;
        Ok(store)
    }

    pub fn persist_initial(
        &self,
        forecast: ThreatForecast,
        recorded_at_ms: u64,
    ) -> Result<ForecastAuditRecord, ThreatPredictionError> {
        validate_persistable_forecast(&forecast)?;
        if recorded_at_ms < forecast.generated_at_ms {
            return Err(ThreatPredictionError::InvalidTimestamp(
                "forecast audit time cannot precede forecast generation".into(),
            ));
        }
        let current = self.current_path(&forecast.forecast_id)?;
        if current.exists() {
            return Err(ThreatPredictionError::InvalidForecast(
                "forecast already exists; use a lifecycle transition instead of overwrite".into(),
            ));
        }
        let record = self.record(forecast, recorded_at_ms, None, "initial forecast")?;
        write_json(&current, &record)?;
        self.write_history(&record)?;
        Ok(record)
    }

    pub fn load_current(
        &self,
        forecast_id: &str,
    ) -> Result<ForecastAuditRecord, ThreatPredictionError> {
        read_json(&self.current_path(forecast_id)?)
    }

    pub fn transition(
        &self,
        forecast_id: &str,
        next_status: ForecastStatus,
        recorded_at_ms: u64,
        reason: impl Into<String>,
    ) -> Result<ForecastAuditRecord, ThreatPredictionError> {
        let current_path = self.current_path(forecast_id)?;
        let current = read_json::<ForecastAuditRecord>(&current_path)?;
        if recorded_at_ms < current.recorded_at_ms {
            return Err(ThreatPredictionError::InvalidTimestamp(
                "lifecycle transition time cannot move backwards".into(),
            ));
        }
        if !transition_allowed(current.forecast.status, next_status) {
            return Err(ThreatPredictionError::InvalidForecast(format!(
                "invalid forecast lifecycle transition {:?} -> {:?}",
                current.forecast.status, next_status
            )));
        }
        let mut forecast = current.forecast.clone();
        let prior_status = forecast.status;
        forecast.status = next_status;
        let record = self.record(forecast, recorded_at_ms, Some(prior_status), reason.into())?;
        // Both states are immutable history entries; only the current-state pointer changes.
        self.write_history(&record)?;
        write_json(&current_path, &record)?;
        Ok(record)
    }

    pub fn history(
        &self,
        forecast_id: &str,
    ) -> Result<Vec<ForecastAuditRecord>, ThreatPredictionError> {
        let directory = self.history_dir().join(safe_id(forecast_id)?);
        if !directory.exists() {
            return Ok(Vec::new());
        }
        let mut records: Vec<ForecastAuditRecord> = Vec::new();
        for entry in fs::read_dir(directory).map_err(io_error)? {
            let path = entry.map_err(io_error)?.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                records.push(read_json(&path)?);
            }
        }
        records.sort_by(|left, right| {
            left.recorded_at_ms
                .cmp(&right.recorded_at_ms)
                .then_with(|| {
                    format!("{:?}", left.forecast.status)
                        .cmp(&format!("{:?}", right.forecast.status))
                })
        });
        Ok(records)
    }

    /// Deletes only records whose configured retention has expired.
    pub fn prune_expired(&self, evaluated_at_ms: u64) -> Result<usize, ThreatPredictionError> {
        let mut removed = 0;
        for entry in fs::read_dir(self.forecasts_dir()).map_err(io_error)? {
            let path = entry.map_err(io_error)?.path();
            if path.extension().is_none_or(|extension| extension != "json") {
                continue;
            }
            let record: ForecastAuditRecord = read_json(&path)?;
            if record.retention_expires_at_ms <= evaluated_at_ms {
                let id = record.forecast.forecast_id;
                fs::remove_file(path).map_err(io_error)?;
                let history = self.history_dir().join(safe_id(&id)?);
                if history.exists() {
                    fs::remove_dir_all(history).map_err(io_error)?;
                }
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn record(
        &self,
        forecast: ThreatForecast,
        recorded_at_ms: u64,
        prior_status: Option<ForecastStatus>,
        transition_reason: impl Into<String>,
    ) -> Result<ForecastAuditRecord, ThreatPredictionError> {
        let retention_ms = u64::from(self.retention_days)
            .checked_mul(DAY_MS)
            .ok_or_else(|| {
                ThreatPredictionError::InvalidConfig("forecast retention overflow".into())
            })?;
        let transition_reason = transition_reason.into();
        validate_bounded_text(
            "lifecycle transition reason",
            &transition_reason,
            MAX_TRANSITION_REASON_BYTES,
        )?;
        Ok(ForecastAuditRecord {
            retention_expires_at_ms: forecast.generated_at_ms.saturating_add(retention_ms),
            forecast,
            recorded_at_ms,
            prior_status,
            transition_reason,
        })
    }

    fn write_history(&self, record: &ForecastAuditRecord) -> Result<(), ThreatPredictionError> {
        let directory = self
            .history_dir()
            .join(safe_id(&record.forecast.forecast_id)?);
        fs::create_dir_all(&directory).map_err(io_error)?;
        let mut sequence = 0_u32;
        loop {
            let candidate = directory.join(format!(
                "{:020}-{:?}-{sequence}.json",
                record.recorded_at_ms, record.forecast.status
            ));
            if !candidate.exists() {
                return write_json(&candidate, record);
            }
            sequence = sequence.checked_add(1).ok_or_else(|| {
                ThreatPredictionError::InvalidForecast("forecast history sequence overflow".into())
            })?;
        }
    }

    fn forecasts_dir(&self) -> PathBuf {
        self.root.join("forecasts")
    }

    fn history_dir(&self) -> PathBuf {
        self.root.join("forecast_history")
    }

    fn current_path(&self, forecast_id: &str) -> Result<PathBuf, ThreatPredictionError> {
        Ok(self
            .forecasts_dir()
            .join(format!("{}.json", safe_id(forecast_id)?)))
    }
}

fn transition_allowed(current: ForecastStatus, next: ForecastStatus) -> bool {
    current == ForecastStatus::Active
        && matches!(
            next,
            ForecastStatus::Superseded
                | ForecastStatus::Expired
                | ForecastStatus::Confirmed
                | ForecastStatus::FalsePositive
                | ForecastStatus::Mitigated
        )
}

fn validate_persistable_forecast(forecast: &ThreatForecast) -> Result<(), ThreatPredictionError> {
    forecast.validate()?;
    if let Some(calibration) = &forecast.explanation.calibration {
        calibration.validate()?;
    }
    validate_bounded_text(
        "forecast explanation summary",
        &forecast.explanation.summary,
        MAX_EXPLANATION_SUMMARY_BYTES,
    )?;
    let forecast_evidence = forecast.evidence_ids.iter().collect::<BTreeSet<_>>();
    for evidence_id in &forecast.evidence_ids {
        validate_bounded_text("forecast evidence ID", evidence_id, MAX_EVIDENCE_ID_BYTES)?;
    }
    for factor in &forecast.explanation.top_factors {
        validate_bounded_text("forecast factor name", &factor.name, MAX_FACTOR_NAME_BYTES)?;
        if factor.evidence_ids.is_empty() {
            return Err(ThreatPredictionError::InvalidForecast(
                "every contributing factor requires at least one evidence ID".into(),
            ));
        }
        for evidence_id in &factor.evidence_ids {
            validate_bounded_text("factor evidence ID", evidence_id, MAX_EVIDENCE_ID_BYTES)?;
            if !forecast_evidence.contains(evidence_id) {
                return Err(ThreatPredictionError::InvalidForecast(
                    "factor evidence ID must be present in forecast evidence IDs".into(),
                ));
            }
        }
    }
    if matches!(
        forecast.severity,
        ForecastSeverity::Advisory | ForecastSeverity::UrgentReview | ForecastSeverity::Critical
    ) && (forecast.evidence_ids.is_empty() || forecast.explanation.top_factors.is_empty())
    {
        return Err(ThreatPredictionError::InvalidForecast(
            "actionable forecast requires evidence IDs and explanatory factors".into(),
        ));
    }
    Ok(())
}

fn validate_bounded_text(
    field: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), ThreatPredictionError> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(ThreatPredictionError::InvalidForecast(format!(
            "{field} must be non-empty and at most {max_bytes} bytes"
        )));
    }
    Ok(())
}

fn safe_id(id: &str) -> Result<&str, ThreatPredictionError> {
    if id.is_empty()
        || id.len() > 160
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(ThreatPredictionError::InvalidForecast(
            "forecast_id must be a bounded safe identifier".into(),
        ));
    }
    Ok(id)
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), ThreatPredictionError> {
    let parent = path.parent().ok_or_else(|| {
        ThreatPredictionError::Io("forecast persistence path has no parent directory".into())
    })?;
    fs::create_dir_all(parent).map_err(io_error)?;
    let raw = serde_json::to_vec_pretty(value)
        .map_err(|error| ThreatPredictionError::Serialization(error.to_string()))?;
    fs::write(path, raw).map_err(io_error)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, ThreatPredictionError> {
    let raw = fs::read(path).map_err(io_error)?;
    serde_json::from_slice(&raw)
        .map_err(|error| ThreatPredictionError::Serialization(error.to_string()))
}

fn io_error(error: std::io::Error) -> ThreatPredictionError {
    ThreatPredictionError::Io(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat_prediction::{
        ForecastExplanation, ForecastFactor, PredictedThreatType, THREAT_FORECAST_SCHEMA_VERSION,
    };

    fn forecast() -> ThreatForecast {
        ThreatForecast {
            schema_version: THREAT_FORECAST_SCHEMA_VERSION.into(),
            forecast_id: "d9-nodeb-ddos-001".into(),
            model_version: "task4-model-v1".into(),
            generated_at_ms: 1_000,
            horizon_start_ms: 1_000,
            horizon_end_ms: 301_000,
            threat_type: PredictedThreatType::Ddos,
            target_nodes: vec!["nodeB".into()],
            probability: 0.85,
            confidence: 0.80,
            severity: ForecastSeverity::UrgentReview,
            evidence_ids: vec!["evidence-1".into()],
            feature_snapshot_id: "features-1".into(),
            explanation: ForecastExplanation {
                summary: "sample explainable forecast".into(),
                top_factors: vec![ForecastFactor {
                    name: "traffic_growth".into(),
                    contribution: 0.85,
                    evidence_ids: vec!["evidence-1".into()],
                }],
                precursor_sequence_ids: Vec::new(),
                missing_evidence: Vec::new(),
                relationship_reasons: Vec::new(),
                calibration: None,
            },
            status: ForecastStatus::Active,
        }
    }

    fn temporary_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("task4-d9-{name}-{}", std::process::id()))
    }

    #[test]
    fn persistence_reloads_and_preserves_superseded_history() {
        let root = temporary_root("restart");
        let _ = fs::remove_dir_all(&root);
        let store = ForecastStore::new(&root, 90).unwrap();
        store.persist_initial(forecast(), 1_001).unwrap();
        assert!(store.persist_initial(forecast(), 1_001).is_err());
        let restarted = ForecastStore::new(&root, 90).unwrap();
        assert_eq!(
            restarted
                .load_current("d9-nodeb-ddos-001")
                .unwrap()
                .forecast,
            forecast()
        );
        let superseded = restarted
            .transition(
                "d9-nodeb-ddos-001",
                ForecastStatus::Superseded,
                1_002,
                "newer forecast for same target",
            )
            .unwrap();
        assert_eq!(superseded.prior_status, Some(ForecastStatus::Active));
        assert_eq!(superseded.forecast.status, ForecastStatus::Superseded);
        let history = restarted.history("d9-nodeb-ddos-001").unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].forecast.status, ForecastStatus::Active);
        assert_eq!(history[1].forecast.status, ForecastStatus::Superseded);
        assert!(restarted
            .transition(
                "d9-nodeb-ddos-001",
                ForecastStatus::Confirmed,
                1_003,
                "must not transition terminal status",
            )
            .is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn every_terminal_lifecycle_status_is_supported_from_active_only() {
        for status in [
            ForecastStatus::Superseded,
            ForecastStatus::Expired,
            ForecastStatus::Confirmed,
            ForecastStatus::FalsePositive,
            ForecastStatus::Mitigated,
        ] {
            let root = temporary_root(&format!("status-{status:?}"));
            let _ = fs::remove_dir_all(&root);
            let store = ForecastStore::new(&root, 90).unwrap();
            let mut item = forecast();
            item.forecast_id = format!("d9-nodeb-ddos-{status:?}").to_lowercase();
            store.persist_initial(item.clone(), 1_001).unwrap();
            let transitioned = store
                .transition(&item.forecast_id, status, 1_002, "terminal test transition")
                .unwrap();
            assert_eq!(transitioned.forecast.status, status);
            assert!(store
                .transition(
                    &item.forecast_id,
                    ForecastStatus::Confirmed,
                    1_003,
                    "invalid"
                )
                .is_err());
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn actionable_explanation_and_retention_are_enforced() {
        let root = temporary_root("retention");
        let _ = fs::remove_dir_all(&root);
        let store = ForecastStore::new(&root, 1).unwrap();
        let mut unexplained = forecast();
        unexplained.explanation.top_factors.clear();
        assert!(store.persist_initial(unexplained, 1_001).is_err());
        store.persist_initial(forecast(), 1_001).unwrap();
        assert_eq!(store.prune_expired(1_000 + DAY_MS - 1).unwrap(), 0);
        assert_eq!(store.prune_expired(1_000 + DAY_MS).unwrap(), 1);
        assert!(store.load_current("d9-nodeb-ddos-001").is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn explainability_fields_and_factor_evidence_links_are_strictly_validated() {
        let root = temporary_root("explainability");
        let _ = fs::remove_dir_all(&root);
        let store = ForecastStore::new(&root, 90).unwrap();

        let mut blank_summary = forecast();
        blank_summary.explanation.summary.clear();
        assert!(store.persist_initial(blank_summary, 1_001).is_err());
        let mut oversized_summary = forecast();
        oversized_summary.explanation.summary = "x".repeat(MAX_EXPLANATION_SUMMARY_BYTES + 1);
        assert!(store.persist_initial(oversized_summary, 1_001).is_err());

        let mut blank_factor = forecast();
        blank_factor.explanation.top_factors[0].name.clear();
        assert!(store.persist_initial(blank_factor, 1_001).is_err());
        let mut oversized_factor = forecast();
        oversized_factor.explanation.top_factors[0].name = "x".repeat(MAX_FACTOR_NAME_BYTES + 1);
        assert!(store.persist_initial(oversized_factor, 1_001).is_err());
        let mut missing_factor_evidence = forecast();
        missing_factor_evidence.explanation.top_factors[0]
            .evidence_ids
            .clear();
        assert!(store
            .persist_initial(missing_factor_evidence, 1_001)
            .is_err());
        let mut untraceable_factor_evidence = forecast();
        untraceable_factor_evidence.explanation.top_factors[0].evidence_ids =
            vec!["other-id".into()];
        assert!(store
            .persist_initial(untraceable_factor_evidence, 1_001)
            .is_err());

        let valid = store.persist_initial(forecast(), 1_001).unwrap();
        assert_eq!(
            valid.forecast.explanation.top_factors[0].evidence_ids,
            vec!["evidence-1"]
        );
        assert!(store
            .transition("d9-nodeb-ddos-001", ForecastStatus::Confirmed, 1_002, "")
            .is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn equivalent_persistence_operations_have_deterministic_history_ordering() {
        let first_root = temporary_root("deterministic-first");
        let second_root = temporary_root("deterministic-second");
        let _ = fs::remove_dir_all(&first_root);
        let _ = fs::remove_dir_all(&second_root);
        for root in [&first_root, &second_root] {
            let store = ForecastStore::new(root, 90).unwrap();
            store.persist_initial(forecast(), 1_001).unwrap();
            store
                .transition(
                    "d9-nodeb-ddos-001",
                    ForecastStatus::Superseded,
                    1_002,
                    "equivalent replacement",
                )
                .unwrap();
        }
        let first = ForecastStore::new(&first_root, 90)
            .unwrap()
            .history("d9-nodeb-ddos-001")
            .unwrap();
        let second = ForecastStore::new(&second_root, 90)
            .unwrap()
            .history("d9-nodeb-ddos-001")
            .unwrap();
        assert_eq!(first, second);
        let _ = fs::remove_dir_all(first_root);
        let _ = fs::remove_dir_all(second_root);
    }
}
