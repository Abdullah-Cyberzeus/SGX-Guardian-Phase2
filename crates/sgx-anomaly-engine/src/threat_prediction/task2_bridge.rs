//! Task 4 Deliverable 10: AI-side predictive-hardening recommendation contract.
//!
//! This module selects only admin-configured Task 2 action categories. It never
//! approves, signs, gossips, applies, rolls back, or otherwise enforces a policy.

use super::{PredictedThreatType, ThreatForecast, ThreatPredictionConfig, ThreatPredictionError};
use crate::policy::{PolicyAction, PolicyTemplates};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

pub const PREDICTIVE_HARDENING_RECOMMENDATION_VERSION: &str = "task4-task2-recommendation-v1";
const MAX_REASON_BYTES: usize = 4_096;
const MAX_EVIDENCE_ID_BYTES: usize = 160;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HardeningRecommendationConfig {
    pub config_version: String,
    pub actions_by_threat: BTreeMap<PredictedThreatType, Vec<PolicyAction>>,
}

impl Default for HardeningRecommendationConfig {
    fn default() -> Self {
        use PolicyAction::{
            EnableAdditionalLogging, IncreaseAttestationFrequency, QuarantinePeer, TightenFirewall,
        };
        Self {
            config_version: PREDICTIVE_HARDENING_RECOMMENDATION_VERSION.into(),
            actions_by_threat: BTreeMap::from([
                (
                    PredictedThreatType::Ddos,
                    vec![TightenFirewall, EnableAdditionalLogging],
                ),
                (
                    PredictedThreatType::ReconnaissanceEscalation,
                    vec![TightenFirewall, EnableAdditionalLogging],
                ),
                (
                    PredictedThreatType::BruteForce,
                    vec![IncreaseAttestationFrequency, EnableAdditionalLogging],
                ),
                (
                    PredictedThreatType::ExploitationAttempt,
                    vec![TightenFirewall, EnableAdditionalLogging],
                ),
                (
                    PredictedThreatType::ProtocolAbuse,
                    vec![EnableAdditionalLogging, TightenFirewall],
                ),
                (
                    PredictedThreatType::PeerCompromiseCascade,
                    vec![QuarantinePeer, IncreaseAttestationFrequency],
                ),
            ]),
        }
    }
}

impl HardeningRecommendationConfig {
    pub fn load_json(path: impl AsRef<Path>) -> Result<Self, ThreatPredictionError> {
        let path = path.as_ref();
        let text = fs::read_to_string(path)
            .map_err(|error| ThreatPredictionError::Io(format!("{}: {error}", path.display())))?;
        let config: Self = serde_json::from_str(&text)
            .map_err(|error| ThreatPredictionError::Serialization(error.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ThreatPredictionError> {
        if self.config_version != PREDICTIVE_HARDENING_RECOMMENDATION_VERSION {
            return Err(ThreatPredictionError::InvalidConfig(
                "unsupported Task4 predictive hardening config version".into(),
            ));
        }
        for threat in all_threat_types() {
            let actions = self.actions_by_threat.get(&threat).ok_or_else(|| {
                ThreatPredictionError::InvalidConfig(format!(
                    "missing predictive hardening mapping for {threat:?}"
                ))
            })?;
            if actions.is_empty() || actions.len() > 4 {
                return Err(ThreatPredictionError::InvalidConfig(
                    "each predictive hardening mapping must contain 1 to 4 actions".into(),
                ));
            }
            if actions.iter().copied().collect::<BTreeSet<_>>().len() != actions.len() {
                return Err(ThreatPredictionError::InvalidConfig(
                    "predictive hardening mapping must not duplicate actions".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PredictiveHardeningRecommendation {
    pub schema_version: String,
    pub recommendation_id: String,
    pub source: String,
    pub forecast_id: String,
    pub target_nodes: Vec<String>,
    pub threat_type: PredictedThreatType,
    pub probability: f64,
    pub confidence: f64,
    pub task2_template_version: u32,
    pub actions: Vec<PolicyAction>,
    pub requires_task2_review: bool,
    pub evidence_ids: Vec<String>,
    pub reason: String,
}

/// Converts one actionable Task 4 forecast into a validated Task 2 review request.
/// The returned data is advisory only and cannot enact any Task 2 operation.
pub fn recommend_predictive_hardening(
    forecast: &ThreatForecast,
    prediction_config: &ThreatPredictionConfig,
    hardening_config: &HardeningRecommendationConfig,
    task2_templates: &PolicyTemplates,
) -> Result<PredictiveHardeningRecommendation, ThreatPredictionError> {
    prediction_config.validate()?;
    hardening_config.validate()?;
    forecast.validate()?;
    if !prediction_config.is_actionable(forecast.probability, forecast.confidence)? {
        return Err(ThreatPredictionError::InvalidForecast(
            "only advisory-or-higher forecasts with sufficient confidence may request Task 2 review"
                .into(),
        ));
    }
    if forecast.explanation.top_factors.is_empty()
        || forecast.explanation.summary.trim().is_empty()
        || forecast.explanation.summary.len() > MAX_REASON_BYTES
    {
        return Err(ThreatPredictionError::InvalidForecast(
            "actionable forecast requires bounded explanation, factors, and evidence".into(),
        ));
    }
    validate_traceable_evidence(forecast)?;
    task2_templates
        .validate()
        .map_err(|error| ThreatPredictionError::InvalidConfig(error.to_string()))?;
    let actions = hardening_config.actions_by_threat[&forecast.threat_type].clone();
    for action in &actions {
        let template = task2_templates
            .templates
            .iter()
            .find(|template| template.action == *action)
            .ok_or_else(|| {
                ThreatPredictionError::InvalidConfig(
                    "Task 2 policy template is missing for recommended action".into(),
                )
            })?;
        if !template.enabled || !template.approval_required {
            return Err(ThreatPredictionError::InvalidConfig(
                "Task 4 may only recommend enabled Task 2 actions requiring approval".into(),
            ));
        }
    }
    Ok(PredictiveHardeningRecommendation {
        schema_version: PREDICTIVE_HARDENING_RECOMMENDATION_VERSION.into(),
        recommendation_id: format!("task4-task2-{}", forecast.forecast_id),
        source: "task4_threat_prediction".into(),
        forecast_id: forecast.forecast_id.clone(),
        target_nodes: forecast.target_nodes.clone(),
        threat_type: forecast.threat_type,
        probability: forecast.probability,
        confidence: forecast.confidence,
        task2_template_version: task2_templates.version,
        actions,
        requires_task2_review: true,
        evidence_ids: forecast.evidence_ids.clone(),
        reason: forecast.explanation.summary.clone(),
    })
}

/// Validates the evidence supplied at the Task 2 recommendation boundary.
/// A forecast can reach D10 before D9 persistence, so D10 independently
/// requires reviewer-visible evidence to be bounded and traceable.
fn validate_traceable_evidence(forecast: &ThreatForecast) -> Result<(), ThreatPredictionError> {
    if forecast.evidence_ids.is_empty() {
        return Err(ThreatPredictionError::InvalidForecast(
            "actionable forecast requires at least one evidence ID".into(),
        ));
    }

    let mut forecast_evidence = BTreeSet::new();
    for evidence_id in &forecast.evidence_ids {
        validate_evidence_id("forecast evidence ID", evidence_id)?;
        forecast_evidence.insert(evidence_id.as_str());
    }
    for factor in &forecast.explanation.top_factors {
        if factor.evidence_ids.is_empty() {
            return Err(ThreatPredictionError::InvalidForecast(
                "every contributing factor requires at least one evidence ID".into(),
            ));
        }
        for evidence_id in &factor.evidence_ids {
            validate_evidence_id("factor evidence ID", evidence_id)?;
            if !forecast_evidence.contains(evidence_id.as_str()) {
                return Err(ThreatPredictionError::InvalidForecast(
                    "factor evidence ID must be present in forecast evidence IDs".into(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_evidence_id(field: &str, value: &str) -> Result<(), ThreatPredictionError> {
    if value.trim().is_empty() || value.len() > MAX_EVIDENCE_ID_BYTES {
        return Err(ThreatPredictionError::InvalidForecast(format!(
            "{field} must be non-empty and at most {MAX_EVIDENCE_ID_BYTES} bytes"
        )));
    }
    Ok(())
}

fn all_threat_types() -> [PredictedThreatType; 6] {
    [
        PredictedThreatType::Ddos,
        PredictedThreatType::ReconnaissanceEscalation,
        PredictedThreatType::BruteForce,
        PredictedThreatType::ExploitationAttempt,
        PredictedThreatType::ProtocolAbuse,
        PredictedThreatType::PeerCompromiseCascade,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat_prediction::{
        ForecastExplanation, ForecastFactor, ForecastSeverity, THREAT_FORECAST_SCHEMA_VERSION,
    };

    fn forecast(threat_type: PredictedThreatType) -> ThreatForecast {
        let horizon_minutes = match threat_type {
            PredictedThreatType::Ddos | PredictedThreatType::ProtocolAbuse => 5,
            PredictedThreatType::ReconnaissanceEscalation
            | PredictedThreatType::BruteForce
            | PredictedThreatType::ExploitationAttempt => 10,
            PredictedThreatType::PeerCompromiseCascade => 15,
        };
        ThreatForecast {
            schema_version: THREAT_FORECAST_SCHEMA_VERSION.into(),
            forecast_id: format!("task4-{threat_type:?}").to_lowercase(),
            model_version: "task4-test-model-v1".into(),
            generated_at_ms: 1_000,
            horizon_start_ms: 1_000,
            horizon_end_ms: 1_000 + horizon_minutes * 60_000,
            threat_type,
            target_nodes: vec!["nodeB".into()],
            probability: 0.85,
            confidence: 0.80,
            severity: ForecastSeverity::UrgentReview,
            evidence_ids: vec!["evidence-1".into()],
            feature_snapshot_id: "features-1".into(),
            explanation: ForecastExplanation {
                summary: "evidence-backed Task4 forecast".into(),
                top_factors: vec![ForecastFactor {
                    name: "sample_factor".into(),
                    contribution: 0.85,
                    evidence_ids: vec!["evidence-1".into()],
                }],
                precursor_sequence_ids: Vec::new(),
                missing_evidence: Vec::new(),
                relationship_reasons: Vec::new(),
                calibration: None,
            },
            status: crate::threat_prediction::ForecastStatus::Active,
        }
    }

    fn templates() -> PolicyTemplates {
        PolicyTemplates::from_path("config/policy_action_templates.json").unwrap()
    }

    #[test]
    fn every_task4_threat_maps_to_enabled_approval_bound_task2_actions() {
        for threat_type in all_threat_types() {
            let recommendation = recommend_predictive_hardening(
                &forecast(threat_type),
                &ThreatPredictionConfig::default(),
                &HardeningRecommendationConfig::default(),
                &templates(),
            )
            .unwrap();
            assert_eq!(recommendation.source, "task4_threat_prediction");
            assert_eq!(
                recommendation.forecast_id,
                forecast(threat_type).forecast_id
            );
            assert_eq!(recommendation.evidence_ids, vec!["evidence-1"]);
            assert!(recommendation.requires_task2_review);
            assert!(!recommendation.actions.is_empty());
        }
    }

    #[test]
    fn non_actionable_or_invalid_template_recommendations_fail_safely() {
        let mut low_confidence = forecast(PredictedThreatType::Ddos);
        low_confidence.confidence = 0.69;
        assert!(recommend_predictive_hardening(
            &low_confidence,
            &ThreatPredictionConfig::default(),
            &HardeningRecommendationConfig::default(),
            &templates(),
        )
        .is_err());
        let mut invalid_config = HardeningRecommendationConfig::default();
        invalid_config
            .actions_by_threat
            .remove(&PredictedThreatType::Ddos);
        assert!(recommend_predictive_hardening(
            &forecast(PredictedThreatType::Ddos),
            &ThreatPredictionConfig::default(),
            &invalid_config,
            &templates(),
        )
        .is_err());
    }

    #[test]
    fn malformed_or_untraceable_evidence_is_rejected_before_task2_handoff() {
        let config = ThreatPredictionConfig::default();
        let hardening = HardeningRecommendationConfig::default();

        let mut blank_forecast_evidence = forecast(PredictedThreatType::Ddos);
        blank_forecast_evidence.evidence_ids = vec!["   ".into()];
        assert!(recommend_predictive_hardening(
            &blank_forecast_evidence,
            &config,
            &hardening,
            &templates(),
        )
        .is_err());

        let mut oversized_forecast_evidence = forecast(PredictedThreatType::Ddos);
        oversized_forecast_evidence.evidence_ids = vec!["x".repeat(MAX_EVIDENCE_ID_BYTES + 1)];
        assert!(recommend_predictive_hardening(
            &oversized_forecast_evidence,
            &config,
            &hardening,
            &templates(),
        )
        .is_err());

        let mut blank_factor_evidence = forecast(PredictedThreatType::Ddos);
        blank_factor_evidence.explanation.top_factors[0].evidence_ids = vec!["\t".into()];
        assert!(recommend_predictive_hardening(
            &blank_factor_evidence,
            &config,
            &hardening,
            &templates(),
        )
        .is_err());

        let mut oversized_factor_evidence = forecast(PredictedThreatType::Ddos);
        oversized_factor_evidence.explanation.top_factors[0].evidence_ids =
            vec!["x".repeat(MAX_EVIDENCE_ID_BYTES + 1)];
        assert!(recommend_predictive_hardening(
            &oversized_factor_evidence,
            &config,
            &hardening,
            &templates(),
        )
        .is_err());

        let mut untraceable_factor_evidence = forecast(PredictedThreatType::Ddos);
        untraceable_factor_evidence.explanation.top_factors[0].evidence_ids =
            vec!["untraceable-evidence".into()];
        assert!(recommend_predictive_hardening(
            &untraceable_factor_evidence,
            &config,
            &hardening,
            &templates(),
        )
        .is_err());
    }

    #[test]
    fn disabled_or_unapproved_task2_templates_are_rejected_safely() {
        let config = ThreatPredictionConfig::default();
        let hardening = HardeningRecommendationConfig::default();

        let mut disabled_templates = templates();
        disabled_templates
            .templates
            .iter_mut()
            .find(|template| template.action == PolicyAction::TightenFirewall)
            .unwrap()
            .enabled = false;
        assert!(recommend_predictive_hardening(
            &forecast(PredictedThreatType::Ddos),
            &config,
            &hardening,
            &disabled_templates,
        )
        .is_err());

        let mut unapproved_templates = templates();
        unapproved_templates
            .templates
            .iter_mut()
            .find(|template| template.action == PolicyAction::TightenFirewall)
            .unwrap()
            .approval_required = false;
        assert!(recommend_predictive_hardening(
            &forecast(PredictedThreatType::Ddos),
            &config,
            &hardening,
            &unapproved_templates,
        )
        .is_err());
    }

    #[test]
    fn recommendation_is_deterministic_and_round_trips_for_audit() {
        let forecast = forecast(PredictedThreatType::Ddos);
        let config = ThreatPredictionConfig::default();
        let hardening = HardeningRecommendationConfig::default();
        let templates = templates();
        let first =
            recommend_predictive_hardening(&forecast, &config, &hardening, &templates).unwrap();
        let second =
            recommend_predictive_hardening(&forecast, &config, &hardening, &templates).unwrap();
        assert_eq!(first, second);

        let serialized = serde_json::to_string(&first).unwrap();
        let restored: PredictiveHardeningRecommendation =
            serde_json::from_str(&serialized).unwrap();
        assert_eq!(restored, first);
        assert_eq!(restored.forecast_id, forecast.forecast_id);
        assert_eq!(restored.evidence_ids, forecast.evidence_ids);
    }
}
