use super::{CalibrationMetadata, ThreatPredictionError};
use serde::{Deserialize, Serialize};

pub const THREAT_FORECAST_SCHEMA_VERSION: &str = "task4-threat-forecast-v1";
pub const MAX_IMMINENT_FORECAST_HORIZON_MINUTES: u32 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PredictedThreatType {
    Ddos,
    ReconnaissanceEscalation,
    BruteForce,
    ExploitationAttempt,
    ProtocolAbuse,
    PeerCompromiseCascade,
}

impl PredictedThreatType {
    pub fn phase_one_horizons_minutes(self) -> &'static [u32] {
        match self {
            Self::Ddos => &[5, 15, 30],
            Self::ReconnaissanceEscalation | Self::BruteForce | Self::ExploitationAttempt => {
                &[10, 30]
            }
            Self::ProtocolAbuse => &[5, 15, 30],
            Self::PeerCompromiseCascade => &[15, 30],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForecastSeverity {
    Observation,
    Monitoring,
    Advisory,
    UrgentReview,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForecastStatus {
    Active,
    Superseded,
    Expired,
    Confirmed,
    FalsePositive,
    Mitigated,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForecastFactor {
    pub name: String,
    pub contribution: f64,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForecastExplanation {
    pub summary: String,
    pub top_factors: Vec<ForecastFactor>,
    pub precursor_sequence_ids: Vec<String>,
    pub missing_evidence: Vec<String>,
    #[serde(default)]
    pub relationship_reasons: Vec<String>,
    #[serde(default)]
    pub calibration: Option<CalibrationMetadata>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatForecast {
    pub schema_version: String,
    pub forecast_id: String,
    pub model_version: String,
    pub generated_at_ms: u64,
    pub horizon_start_ms: u64,
    pub horizon_end_ms: u64,
    pub threat_type: PredictedThreatType,
    pub target_nodes: Vec<String>,
    pub probability: f64,
    pub confidence: f64,
    pub severity: ForecastSeverity,
    pub evidence_ids: Vec<String>,
    pub feature_snapshot_id: String,
    pub explanation: ForecastExplanation,
    pub status: ForecastStatus,
}

impl ThreatForecast {
    pub fn validate(&self) -> Result<(), ThreatPredictionError> {
        if self.schema_version != THREAT_FORECAST_SCHEMA_VERSION {
            return Err(ThreatPredictionError::InvalidForecast(format!(
                "unsupported schema_version '{}'",
                self.schema_version
            )));
        }
        if self.forecast_id.trim().is_empty() || self.model_version.trim().is_empty() {
            return Err(ThreatPredictionError::InvalidForecast(
                "forecast_id and model_version are required".to_string(),
            ));
        }
        if self.target_nodes.is_empty()
            || self.target_nodes.iter().any(|node| node.trim().is_empty())
        {
            return Err(ThreatPredictionError::InvalidForecast(
                "at least one non-empty target node is required".to_string(),
            ));
        }
        validate_unit_interval("probability", self.probability, true)?;
        validate_unit_interval("confidence", self.confidence, false)?;
        if self.horizon_start_ms < self.generated_at_ms
            || self.horizon_end_ms <= self.horizon_start_ms
        {
            return Err(ThreatPredictionError::InvalidHorizon(
                "forecast horizon must start at/after generation and end after start".to_string(),
            ));
        }
        let duration_ms = self.horizon_end_ms - self.horizon_start_ms;
        if duration_ms % 60_000 != 0 {
            return Err(ThreatPredictionError::InvalidHorizon(
                "forecast horizon must be an exact whole number of minutes".to_string(),
            ));
        }
        let duration_minutes = duration_ms / 60_000;
        if duration_minutes > u64::from(MAX_IMMINENT_FORECAST_HORIZON_MINUTES) {
            return Err(ThreatPredictionError::InvalidHorizon(format!(
                "imminent forecast horizon {duration_minutes} minutes exceeds the maximum {} minutes",
                MAX_IMMINENT_FORECAST_HORIZON_MINUTES
            )));
        }
        let allowed = self.threat_type.phase_one_horizons_minutes();
        if !allowed
            .iter()
            .any(|allowed_minutes| u64::from(*allowed_minutes) == duration_minutes)
        {
            return Err(ThreatPredictionError::InvalidHorizon(format!(
                "{:?} forecast horizon {duration_minutes} minutes is not allowed; expected one of {allowed:?}",
                self.threat_type
            )));
        }
        Ok(())
    }
}

pub(crate) fn validate_unit_interval(
    field: &str,
    value: f64,
    probability: bool,
) -> Result<(), ThreatPredictionError> {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        let message = format!("{field} must be finite and within [0.0, 1.0]");
        return Err(if probability {
            ThreatPredictionError::InvalidProbability(message)
        } else {
            ThreatPredictionError::InvalidConfidence(message)
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn valid_forecast() -> ThreatForecast {
        ThreatForecast {
            schema_version: THREAT_FORECAST_SCHEMA_VERSION.to_string(),
            forecast_id: "forecast-nodeb-ddos-001".to_string(),
            model_version: "task4-baseline-v1".to_string(),
            generated_at_ms: 1_000,
            horizon_start_ms: 1_000,
            horizon_end_ms: 1_801_000,
            threat_type: PredictedThreatType::Ddos,
            target_nodes: vec!["nodeB".to_string()],
            probability: 0.85,
            confidence: 0.82,
            severity: ForecastSeverity::UrgentReview,
            evidence_ids: vec!["task1-nodeb-001".to_string()],
            feature_snapshot_id: "features-001".to_string(),
            explanation: ForecastExplanation {
                summary: "synthetic DDoS precursor match".to_string(),
                top_factors: Vec::new(),
                precursor_sequence_ids: Vec::new(),
                missing_evidence: Vec::new(),
                relationship_reasons: Vec::new(),
                calibration: None,
            },
            status: ForecastStatus::Active,
        }
    }
    #[test]
    fn forecast_round_trip_and_validation_succeeds() {
        let forecast = valid_forecast();
        forecast.validate().unwrap();
        let round_trip: ThreatForecast =
            serde_json::from_str(&serde_json::to_string(&forecast).unwrap()).unwrap();
        assert_eq!(round_trip, forecast);
    }
    #[test]
    fn invalid_probability_and_confidence_are_rejected() {
        let mut forecast = valid_forecast();
        forecast.probability = 1.01;
        assert!(matches!(
            forecast.validate(),
            Err(ThreatPredictionError::InvalidProbability(_))
        ));
        let mut forecast = valid_forecast();
        forecast.confidence = f64::NAN;
        assert!(matches!(
            forecast.validate(),
            Err(ThreatPredictionError::InvalidConfidence(_))
        ));
    }

    #[test]
    fn allowed_phase_one_forecast_horizons_pass() {
        for (threat_type, minutes) in [
            (PredictedThreatType::Ddos, 5),
            (PredictedThreatType::ReconnaissanceEscalation, 30),
            (PredictedThreatType::BruteForce, 10),
            (PredictedThreatType::ExploitationAttempt, 30),
            (PredictedThreatType::ProtocolAbuse, 15),
            (PredictedThreatType::PeerCompromiseCascade, 30),
        ] {
            let mut forecast = valid_forecast();
            forecast.threat_type = threat_type;
            forecast.horizon_end_ms = forecast.horizon_start_ms + minutes * 60_000;
            forecast.validate().unwrap();
        }
    }

    #[test]
    fn horizons_over_30_minutes_are_rejected_for_every_threat_type() {
        for threat_type in [
            PredictedThreatType::Ddos,
            PredictedThreatType::ReconnaissanceEscalation,
            PredictedThreatType::BruteForce,
            PredictedThreatType::ExploitationAttempt,
            PredictedThreatType::ProtocolAbuse,
            PredictedThreatType::PeerCompromiseCascade,
        ] {
            let mut forecast = valid_forecast();
            forecast.threat_type = threat_type;
            forecast.horizon_end_ms = forecast.horizon_start_ms + 31 * 60_000;
            assert!(matches!(
                forecast.validate(),
                Err(ThreatPredictionError::InvalidHorizon(_))
            ));
        }

        let mut forecast = valid_forecast();
        forecast.horizon_end_ms = forecast.horizon_start_ms + 120 * 60_000;
        assert!(matches!(
            forecast.validate(),
            Err(ThreatPredictionError::InvalidHorizon(_))
        ));

        let mut forecast = valid_forecast();
        forecast.horizon_end_ms = forecast.horizon_start_ms + 30_500;
        assert!(matches!(
            forecast.validate(),
            Err(ThreatPredictionError::InvalidHorizon(_))
        ));
    }
}
