//! Task 4 Deliverable 8: confidence, calibration, and optional geo-evidence contract.
//!
//! This module deliberately does not collect an external threat feed. Adapters supply
//! normalized geo evidence; the AI engine validates its provenance and freshness.

use super::{validate_unit_interval, EvidenceSource, ThreatPredictionError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::str::FromStr;

const MAX_TEXT_BYTES: usize = 160;
const MAX_REGION_BYTES: usize = 80;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CalibrationMetadata {
    pub model_version: String,
    pub calibration_version: String,
    pub training_period: String,
    pub validation_period: String,
    pub threshold_profile_version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CalibrationPoint {
    pub raw_probability: f64,
    pub calibrated_probability: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbabilityCalibrationConfig {
    pub metadata: CalibrationMetadata,
    pub points: Vec<CalibrationPoint>,
}

impl Default for ProbabilityCalibrationConfig {
    fn default() -> Self {
        Self {
            metadata: CalibrationMetadata {
                model_version: "task4-d6-deterministic-baseline-v1".into(),
                calibration_version: "task4-calibration-identity-v1".into(),
                training_period: "controlled-fixtures-2026q3".into(),
                validation_period: "controlled-fixtures-2026q3".into(),
                threshold_profile_version: "task4-thresholds-v1".into(),
            },
            points: vec![
                CalibrationPoint {
                    raw_probability: 0.0,
                    calibrated_probability: 0.0,
                },
                CalibrationPoint {
                    raw_probability: 1.0,
                    calibrated_probability: 1.0,
                },
            ],
        }
    }
}

impl ProbabilityCalibrationConfig {
    pub fn validate(&self) -> Result<(), ThreatPredictionError> {
        self.metadata.validate()?;
        if self.points.len() < 2 || self.points.len() > 32 {
            return Err(ThreatPredictionError::InvalidConfig(
                "calibration requires between 2 and 32 ordered points".into(),
            ));
        }
        let mut previous_raw = None;
        let mut previous_calibrated = None;
        for point in &self.points {
            validate_unit_interval("calibration raw_probability", point.raw_probability, true)?;
            validate_unit_interval(
                "calibration calibrated_probability",
                point.calibrated_probability,
                true,
            )?;
            if previous_raw.is_some_and(|value| point.raw_probability <= value)
                || previous_calibrated.is_some_and(|value| point.calibrated_probability < value)
            {
                return Err(ThreatPredictionError::InvalidConfig(
                    "calibration points must be strictly raw-ordered and monotonic".into(),
                ));
            }
            previous_raw = Some(point.raw_probability);
            previous_calibrated = Some(point.calibrated_probability);
        }
        if self
            .points
            .first()
            .is_none_or(|point| point.raw_probability != 0.0)
            || self
                .points
                .last()
                .is_none_or(|point| point.raw_probability != 1.0)
        {
            return Err(ThreatPredictionError::InvalidConfig(
                "calibration points must cover raw probabilities from 0.0 through 1.0".into(),
            ));
        }
        Ok(())
    }

    pub fn calibrate_probability(
        &self,
        raw_probability: f64,
        model_version: &str,
    ) -> Result<f64, ThreatPredictionError> {
        self.validate()?;
        validate_unit_interval("raw probability", raw_probability, true)?;
        if self.metadata.model_version != model_version {
            return Err(ThreatPredictionError::InvalidConfig(
                "calibration model_version does not match predictor model_version".into(),
            ));
        }
        for pair in self.points.windows(2) {
            let lower = &pair[0];
            let upper = &pair[1];
            if raw_probability >= lower.raw_probability && raw_probability <= upper.raw_probability
            {
                let fraction = (raw_probability - lower.raw_probability)
                    / (upper.raw_probability - lower.raw_probability);
                let calibrated = lower.calibrated_probability
                    + fraction * (upper.calibrated_probability - lower.calibrated_probability);
                validate_unit_interval("calibrated probability", calibrated, true)?;
                return Ok(calibrated);
            }
        }
        Err(ThreatPredictionError::InvalidConfig(
            "calibration points did not cover raw probability".into(),
        ))
    }
}

impl CalibrationMetadata {
    pub fn validate(&self) -> Result<(), ThreatPredictionError> {
        for (field, value) in [
            ("model_version", &self.model_version),
            ("calibration_version", &self.calibration_version),
            ("training_period", &self.training_period),
            ("validation_period", &self.validation_period),
            ("threshold_profile_version", &self.threshold_profile_version),
        ] {
            if value.trim().is_empty() || value.len() > MAX_TEXT_BYTES {
                return Err(ThreatPredictionError::InvalidConfig(format!(
                    "{field} must be non-empty and at most {MAX_TEXT_BYTES} bytes"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceContext {
    pub contributing_sources: Vec<EvidenceSource>,
    pub stale_sources: u32,
    pub missing_sources: u32,
    pub history_sufficient: bool,
    pub source_health_degraded: bool,
    pub topology_complete: bool,
    pub geo_feed_available: bool,
    pub calibration_matches_model: bool,
}

impl Default for ConfidenceContext {
    fn default() -> Self {
        Self {
            contributing_sources: Vec::new(),
            stale_sources: 0,
            missing_sources: 0,
            history_sufficient: true,
            source_health_degraded: false,
            topology_complete: true,
            geo_feed_available: true,
            calibration_matches_model: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceAssessment {
    pub confidence: f64,
    pub distinct_source_count: usize,
    pub reductions: Vec<String>,
    pub calibration: CalibrationMetadata,
}

/// Calculates reliability of a threat probability from supplied evidence quality.
/// It never changes the probability; callers must keep probability and confidence separate.
pub fn assess_confidence(
    context: &ConfidenceContext,
    calibration: CalibrationMetadata,
) -> Result<ConfidenceAssessment, ThreatPredictionError> {
    calibration.validate()?;
    let sources = context
        .contributing_sources
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut confidence = 0.90_f64;
    let mut reductions = Vec::new();
    match sources.len() {
        0 => {
            confidence -= 0.30;
            reductions.push("no independent evidence source".into());
        }
        1 => {
            confidence -= 0.12;
            reductions.push("only one independent evidence source".into());
        }
        _ => {}
    }
    if context.stale_sources > 0 {
        confidence -= (f64::from(context.stale_sources) * 0.08).min(0.30);
        reductions.push("stale evidence source".into());
    }
    if context.missing_sources > 0 {
        confidence -= (f64::from(context.missing_sources) * 0.10).min(0.30);
        reductions.push("required evidence source missing".into());
    }
    for (present, deduction, reason) in [
        (context.history_sufficient, 0.12, "insufficient history"),
        (
            !context.source_health_degraded,
            0.10,
            "source health degraded",
        ),
        (context.topology_complete, 0.08, "topology incomplete"),
        (
            context.geo_feed_available,
            0.04,
            "optional geo feed unavailable",
        ),
        (
            context.calibration_matches_model,
            0.15,
            "model/calibration mismatch",
        ),
    ] {
        if !present {
            confidence -= deduction;
            reductions.push(reason.into());
        }
    }
    confidence = confidence.clamp(0.05, 0.95);
    validate_unit_interval("assessed confidence", confidence, false)?;
    Ok(ConfidenceAssessment {
        confidence,
        distinct_source_count: sources.len(),
        reductions,
        calibration,
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeoThreatSignal {
    pub source_ip: String,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub reputation_score: Option<f64>,
    pub feed_id: String,
    pub observed_at_ms: u64,
    pub expires_at_ms: u64,
}

impl GeoThreatSignal {
    pub fn validate_at(&self, evaluated_at_ms: u64) -> Result<(), ThreatPredictionError> {
        let ip = IpAddr::from_str(&self.source_ip).map_err(|_| {
            ThreatPredictionError::InvalidConfig("geo source_ip must be a valid IP address".into())
        })?;
        if ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_multicast()
            || matches!(ip, IpAddr::V4(address) if address.is_private() || address.is_link_local())
            || matches!(ip, IpAddr::V6(address) if address.is_unique_local() || address.is_unicast_link_local())
        {
            return Err(ThreatPredictionError::InvalidConfig(
                "private/local IP data is not geographic threat intelligence".into(),
            ));
        }
        if self.source_ip.len() > 45
            || self.feed_id.trim().is_empty()
            || self.feed_id.len() > MAX_TEXT_BYTES
            || self
                .country_code
                .as_ref()
                .is_some_and(|value| value.len() != 2)
            || self
                .region
                .as_ref()
                .is_some_and(|value| value.len() > MAX_REGION_BYTES)
            || self.observed_at_ms == 0
            || self.observed_at_ms > evaluated_at_ms
            || self.expires_at_ms <= self.observed_at_ms
            || self.expires_at_ms < evaluated_at_ms
        {
            return Err(ThreatPredictionError::InvalidConfig(
                "invalid, future, or stale geographic threat evidence".into(),
            ));
        }
        if let Some(score) = self.reputation_score {
            validate_unit_interval("geo reputation_score", score, true)?;
        }
        Ok(())
    }
}

/// Geo evidence may support an evidence-backed forecast, but can never by itself
/// authorise an actionable or high-impact recommendation.
pub fn geo_can_support_evidence_backed_forecast(
    signal: &GeoThreatSignal,
    evaluated_at_ms: u64,
    has_independent_security_evidence: bool,
) -> Result<bool, ThreatPredictionError> {
    signal.validate_at(evaluated_at_ms)?;
    Ok(has_independent_security_evidence)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata() -> CalibrationMetadata {
        CalibrationMetadata {
            model_version: "task4-d6-v1".into(),
            calibration_version: "task4-calibration-v1".into(),
            training_period: "controlled-fixtures-2026q3".into(),
            validation_period: "controlled-fixtures-2026q3".into(),
            threshold_profile_version: "task4-thresholds-v1".into(),
        }
    }

    fn geo() -> GeoThreatSignal {
        GeoThreatSignal {
            source_ip: "8.8.8.8".into(),
            country_code: Some("US".into()),
            region: Some("sample-region".into()),
            reputation_score: Some(0.80),
            feed_id: "sample-authorized-feed".into(),
            observed_at_ms: 900,
            expires_at_ms: 1_200,
        }
    }

    #[test]
    fn confidence_is_distinct_and_reduces_for_stale_missing_or_weak_evidence() {
        let strong = assess_confidence(
            &ConfidenceContext {
                contributing_sources: vec![EvidenceSource::Task1Anomaly, EvidenceSource::Suricata],
                ..Default::default()
            },
            metadata(),
        )
        .unwrap();
        let weak = assess_confidence(
            &ConfidenceContext {
                contributing_sources: vec![EvidenceSource::Task1Anomaly],
                stale_sources: 1,
                missing_sources: 1,
                history_sufficient: false,
                source_health_degraded: true,
                topology_complete: false,
                geo_feed_available: false,
                calibration_matches_model: false,
            },
            metadata(),
        )
        .unwrap();
        assert!((0.0..=1.0).contains(&strong.confidence));
        assert!(weak.confidence < strong.confidence);
        assert!(weak.reductions.iter().any(|item| item.contains("stale")));
        assert_eq!(strong.distinct_source_count, 2);
    }

    #[test]
    fn calibration_metadata_and_geo_contract_are_safe_and_round_trip() {
        metadata().validate().unwrap();
        let serialized = serde_json::to_string(&metadata()).unwrap();
        assert_eq!(
            serde_json::from_str::<CalibrationMetadata>(&serialized).unwrap(),
            metadata()
        );
        assert!(geo().validate_at(1_000).is_ok());
        assert!(!geo_can_support_evidence_backed_forecast(&geo(), 1_000, false).unwrap());
        assert!(geo_can_support_evidence_backed_forecast(&geo(), 1_000, true).unwrap());
        let mut private = geo();
        private.source_ip = "10.0.0.7".into();
        assert!(private.validate_at(1_000).is_err());
        let mut stale = geo();
        stale.expires_at_ms = 999;
        assert!(stale.validate_at(1_000).is_err());
        let mut future = geo();
        future.observed_at_ms = 1_001;
        assert!(future.validate_at(1_000).is_err());
        let mut blank_metadata = metadata();
        blank_metadata.calibration_version.clear();
        assert!(blank_metadata.validate().is_err());
        let mut blank_feed = geo();
        blank_feed.feed_id.clear();
        assert!(blank_feed.validate_at(1_000).is_err());
        let mut invalid_score = geo();
        invalid_score.reputation_score = Some(1.01);
        assert!(invalid_score.validate_at(1_000).is_err());
    }

    #[test]
    fn calibration_is_deterministic_bounded_and_rejects_invalid_or_unavailable_data() {
        let mut calibration = ProbabilityCalibrationConfig::default();
        calibration.points = vec![
            CalibrationPoint {
                raw_probability: 0.0,
                calibrated_probability: 0.0,
            },
            CalibrationPoint {
                raw_probability: 1.0,
                calibrated_probability: 0.80,
            },
        ];
        let first = calibration
            .calibrate_probability(0.75, "task4-d6-deterministic-baseline-v1")
            .unwrap();
        let second = calibration
            .calibrate_probability(0.75, "task4-d6-deterministic-baseline-v1")
            .unwrap();
        assert!((first - 0.60).abs() < f64::EPSILON);
        assert_eq!(first, second);
        assert!(calibration
            .calibrate_probability(0.75, "missing-model")
            .is_err());
        calibration.points[1].raw_probability = 0.0;
        assert!(calibration.validate().is_err());
    }
}
