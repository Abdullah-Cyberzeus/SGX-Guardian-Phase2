use super::{
    validate_unit_interval, ForecastSeverity, PredictedThreatType, ProbabilityCalibrationConfig,
    ThreatPredictionError, MAX_IMMINENT_FORECAST_HORIZON_MINUTES,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub const THREAT_PREDICTION_CONFIG_VERSION: &str = "task4-threat-prediction-config-v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventDrivenRecalculationConfig {
    pub enabled: bool,
    pub debounce_and_coalesce_duplicates: bool,
    pub triggers: Vec<RecalculationTrigger>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecalculationTrigger {
    SignificantTask1Anomaly,
    RelevantSuricataAlert,
    MaterialNetworkOrTopologyChange,
    Task2PolicyApplyRevertOrReplacement,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskThresholdProfile {
    pub observation_below: f64,
    pub monitoring_min: f64,
    pub advisory_min: f64,
    pub urgent_task2_review_min: f64,
    pub critical_min: f64,
}

impl RiskThresholdProfile {
    pub fn severity_for(&self, probability: f64) -> ForecastSeverity {
        if probability >= self.critical_min {
            ForecastSeverity::Critical
        } else if probability >= self.urgent_task2_review_min {
            ForecastSeverity::UrgentReview
        } else if probability >= self.advisory_min {
            ForecastSeverity::Advisory
        } else if probability >= self.monitoring_min {
            ForecastSeverity::Monitoring
        } else {
            ForecastSeverity::Observation
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatPredictionConfig {
    pub config_version: String,
    pub enabled: bool,
    pub forecast_interval_minutes: u32,
    pub event_driven_recalculation: EventDrivenRecalculationConfig,
    pub forecast_horizons_minutes: BTreeMap<PredictedThreatType, Vec<u32>>,
    pub minimum_action_confidence: f64,
    pub thresholds: RiskThresholdProfile,
    pub forecast_retention_days: u32,
    #[serde(default)]
    pub probability_calibration: ProbabilityCalibrationConfig,
}

impl Default for ThreatPredictionConfig {
    fn default() -> Self {
        let mut forecast_horizons_minutes = BTreeMap::new();
        for threat_type in [
            PredictedThreatType::Ddos,
            PredictedThreatType::ReconnaissanceEscalation,
            PredictedThreatType::BruteForce,
            PredictedThreatType::ExploitationAttempt,
            PredictedThreatType::ProtocolAbuse,
            PredictedThreatType::PeerCompromiseCascade,
        ] {
            forecast_horizons_minutes.insert(
                threat_type,
                threat_type.phase_one_horizons_minutes().to_vec(),
            );
        }
        Self {
            config_version: THREAT_PREDICTION_CONFIG_VERSION.to_string(),
            enabled: false,
            forecast_interval_minutes: 5,
            event_driven_recalculation: EventDrivenRecalculationConfig {
                enabled: true,
                debounce_and_coalesce_duplicates: true,
                triggers: vec![
                    RecalculationTrigger::SignificantTask1Anomaly,
                    RecalculationTrigger::RelevantSuricataAlert,
                    RecalculationTrigger::MaterialNetworkOrTopologyChange,
                    RecalculationTrigger::Task2PolicyApplyRevertOrReplacement,
                ],
            },
            forecast_horizons_minutes,
            minimum_action_confidence: 0.70,
            thresholds: RiskThresholdProfile {
                observation_below: 0.50,
                monitoring_min: 0.50,
                advisory_min: 0.70,
                urgent_task2_review_min: 0.85,
                critical_min: 0.95,
            },
            forecast_retention_days: 90,
            probability_calibration: ProbabilityCalibrationConfig::default(),
        }
    }
}

impl ThreatPredictionConfig {
    pub fn load_json(path: impl AsRef<Path>) -> Result<Self, ThreatPredictionError> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .map_err(|error| ThreatPredictionError::Io(format!("{}: {error}", path.display())))?;
        let config: Self = serde_json::from_str(&raw)
            .map_err(|error| ThreatPredictionError::Serialization(error.to_string()))?;
        config.validate()?;
        Ok(config)
    }
    pub fn is_actionable(
        &self,
        probability: f64,
        confidence: f64,
    ) -> Result<bool, ThreatPredictionError> {
        validate_unit_interval("probability", probability, true)?;
        validate_unit_interval("confidence", confidence, false)?;
        Ok(probability >= self.thresholds.advisory_min
            && confidence >= self.minimum_action_confidence)
    }
    pub fn validate(&self) -> Result<(), ThreatPredictionError> {
        if self.config_version != THREAT_PREDICTION_CONFIG_VERSION {
            return Err(ThreatPredictionError::InvalidConfig(format!(
                "unsupported config_version '{}'",
                self.config_version
            )));
        }
        if self.forecast_interval_minutes != 5 {
            return Err(ThreatPredictionError::InvalidConfig(
                "Phase 1 forecast_interval_minutes must be 5".to_string(),
            ));
        }
        if self.forecast_retention_days == 0 {
            return Err(ThreatPredictionError::InvalidConfig(
                "forecast_retention_days must be greater than zero".to_string(),
            ));
        }
        self.probability_calibration.validate()?;
        validate_unit_interval(
            "minimum_action_confidence",
            self.minimum_action_confidence,
            false,
        )?;
        let values = [
            self.thresholds.observation_below,
            self.thresholds.monitoring_min,
            self.thresholds.advisory_min,
            self.thresholds.urgent_task2_review_min,
            self.thresholds.critical_min,
        ];
        for value in values {
            validate_unit_interval("threshold", value, true)?;
        }
        if self.thresholds.observation_below != self.thresholds.monitoring_min
            || !(self.thresholds.monitoring_min < self.thresholds.advisory_min
                && self.thresholds.advisory_min < self.thresholds.urgent_task2_review_min
                && self.thresholds.urgent_task2_review_min < self.thresholds.critical_min)
        {
            return Err(ThreatPredictionError::InvalidConfig(
                "thresholds must be ordered as 0.50/0.70/0.85/0.95".to_string(),
            ));
        }
        if self.event_driven_recalculation.enabled
            && (!self
                .event_driven_recalculation
                .debounce_and_coalesce_duplicates
                || self.event_driven_recalculation.triggers.is_empty())
        {
            return Err(ThreatPredictionError::InvalidConfig(
                "event-driven recalculation requires debounce/coalescing and triggers".to_string(),
            ));
        }
        for threat_type in [
            PredictedThreatType::Ddos,
            PredictedThreatType::ReconnaissanceEscalation,
            PredictedThreatType::BruteForce,
            PredictedThreatType::ExploitationAttempt,
            PredictedThreatType::ProtocolAbuse,
            PredictedThreatType::PeerCompromiseCascade,
        ] {
            let horizons = self
                .forecast_horizons_minutes
                .get(&threat_type)
                .ok_or_else(|| {
                    ThreatPredictionError::InvalidHorizon(format!(
                        "missing required Phase 1 horizons for {threat_type:?}"
                    ))
                })?;
            let allowed = threat_type.phase_one_horizons_minutes();
            if horizons.is_empty()
                || horizons.iter().any(|horizon| {
                    *horizon > MAX_IMMINENT_FORECAST_HORIZON_MINUTES || !allowed.contains(horizon)
                })
            {
                return Err(ThreatPredictionError::InvalidHorizon(format!(
                    "{threat_type:?} horizons must be a non-empty subset of {allowed:?}"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_match_confirmed_phase_one_policy() {
        let config = ThreatPredictionConfig::default();
        config.validate().unwrap();
        assert_eq!(config.forecast_interval_minutes, 5);
        assert_eq!(config.forecast_retention_days, 90);
        assert_eq!(
            config.thresholds.severity_for(0.85),
            ForecastSeverity::UrgentReview
        );
        assert!(config.is_actionable(0.70, 0.70).unwrap());
        assert!(!config.is_actionable(0.70, 0.69).unwrap());
    }
    #[test]
    fn invalid_horizon_and_config_are_rejected_safely() {
        let mut config = ThreatPredictionConfig::default();
        config
            .forecast_horizons_minutes
            .insert(PredictedThreatType::Ddos, vec![120]);
        assert!(matches!(
            config.validate(),
            Err(ThreatPredictionError::InvalidHorizon(_))
        ));
        let mut config = ThreatPredictionConfig::default();
        config
            .forecast_horizons_minutes
            .insert(PredictedThreatType::PeerCompromiseCascade, vec![31]);
        assert!(matches!(
            config.validate(),
            Err(ThreatPredictionError::InvalidHorizon(_))
        ));
        let mut config = ThreatPredictionConfig::default();
        config.forecast_interval_minutes = 0;
        assert!(matches!(
            config.validate(),
            Err(ThreatPredictionError::InvalidConfig(_))
        ));
        let mut config = ThreatPredictionConfig::default();
        config
            .forecast_horizons_minutes
            .remove(&PredictedThreatType::PeerCompromiseCascade);
        assert!(matches!(
            config.validate(),
            Err(ThreatPredictionError::InvalidHorizon(_))
        ));
    }
    #[test]
    fn config_json_round_trip_is_validated() {
        let path = std::env::temp_dir().join(format!("task4-config-{}.json", std::process::id()));
        fs::write(
            &path,
            serde_json::to_string(&ThreatPredictionConfig::default()).unwrap(),
        )
        .unwrap();
        let loaded = ThreatPredictionConfig::load_json(&path).unwrap();
        assert_eq!(loaded, ThreatPredictionConfig::default());
        let _ = fs::remove_file(path);
    }
}
