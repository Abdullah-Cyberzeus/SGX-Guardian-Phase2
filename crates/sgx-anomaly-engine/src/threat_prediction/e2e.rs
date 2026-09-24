//! Task 4 Deliverable 12: bounded end-to-end pipeline and controlled metrics.

use super::{
    match_precursor_sequence, predict_peer_cascade, recommend_predictive_hardening,
    BruteForcePredictor, DdosPredictor, ExploitationPredictor, ForecastAuditRecord, ForecastStore,
    HardeningRecommendationConfig, PeerRelationship, PrecursorSequenceDefinition,
    PredictiveHardeningRecommendation, ProtocolAbusePredictor, ReconEscalationPredictor,
    SecurityEvent, Task3ContextConfig, TemporalFeatureConfig, TemporalFeatureEngine,
    ThreatForecast, ThreatPredictionConfig, ThreatPredictionError, ThreatPredictor,
    ThreatPredictorInput,
};
use crate::policy::PolicyTemplates;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

/// Chooses an existing D6 predictor for the canonical D12 flow. This does not
/// implement scoring here; it simply routes normalized evidence to D6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum E2ePrimaryPredictor {
    Ddos,
    ReconnaissanceEscalation,
    BruteForce,
    ExploitationAttempt,
    ProtocolAbuse,
}

#[derive(Debug, Clone)]
pub struct E2eCycleInput {
    /// Safe, caller-supplied identifier that associates audit and benchmark artifacts.
    pub evaluation_id: String,
    pub node_id: String,
    pub evaluated_at_ms: u64,
    /// Already-normalized optional evidence. D12 can also load real D3/D11 artifacts below.
    pub events: Vec<SecurityEvent>,
    pub task1_recommendation_path: Option<PathBuf>,
    pub task3_degradation_path: Option<PathBuf>,
    pub task3_peer_id: Option<String>,
    pub task3_context_config: Task3ContextConfig,
    pub temporal_config: TemporalFeatureConfig,
    pub prediction_config: ThreatPredictionConfig,
    pub primary_predictor: E2ePrimaryPredictor,
    pub sequence_definition: PrecursorSequenceDefinition,
    pub peer_relationship: Option<PeerRelationship>,
    pub source_compromise_probability: Option<f64>,
    pub hardening_config: HardeningRecommendationConfig,
    pub task2_templates: PolicyTemplates,
    pub audit_root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct E2eResourceMetrics {
    pub accepted_event_count: usize,
    pub rejected_or_replayed_event_count: usize,
    pub future_event_count: usize,
    pub temporal_max_events: usize,
    pub temporal_window_count: usize,
    pub forecast_count: usize,
    pub inference_latency_micros: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eCycleOutput {
    pub evaluation_id: String,
    pub forecast: Option<ThreatForecast>,
    pub cascade_forecast: Option<ThreatForecast>,
    pub recommendation: Option<PredictiveHardeningRecommendation>,
    /// The exact existing D10 review-only contract, persisted only when an
    /// actionable forecast produced an advisory.
    pub recommendation_artifact_path: Option<PathBuf>,
    pub lifecycle_record: Option<ForecastAuditRecord>,
    pub forecast_artifact_path: Option<PathBuf>,
    pub accepted_event_ids: Vec<String>,
    pub task1_event_ids: Vec<String>,
    pub task3_event_ids: Vec<String>,
    pub task3_decision_ids: Vec<String>,
    pub sequence_id: String,
    pub sequence_matched_event_ids: Vec<String>,
    pub sequence_matched_steps: usize,
    pub metrics: E2eResourceMetrics,
}

/// Runs the canonical Task 4 flow using existing D1-D11 contracts only. It
/// creates advisory data and a D9 audit record; it cannot enforce Task2 policy
/// or mutate Task3 routing.
pub fn run_e2e_cycle(input: E2eCycleInput) -> Result<E2eCycleOutput, ThreatPredictionError> {
    let started = Instant::now();
    validate_evaluation_id(&input.evaluation_id)?;
    input.prediction_config.validate()?;
    input.hardening_config.validate()?;
    input.task3_context_config.validate()?;
    let max_events = input.temporal_config.max_events;
    let mut temporal = TemporalFeatureEngine::new(input.temporal_config)?;
    let mut supplied_events = input.events;
    let mut task1_event_ids = Vec::new();
    let mut task3_event_ids = Vec::new();
    let mut task3_decision_ids = Vec::new();
    if let Some(path) = &input.task1_recommendation_path {
        let events = super::read_task1_anomalies(path)?;
        task1_event_ids.extend(events.iter().map(|event| event.event_id.clone()));
        supplied_events.extend(events);
    }
    if let Some(path) = &input.task3_degradation_path {
        let events = super::read_task3_degradation_events_at(
            path,
            &input.node_id,
            input.task3_peer_id.as_deref(),
            input.evaluated_at_ms,
            &input.task3_context_config,
        )?;
        task3_event_ids.extend(events.iter().map(|event| event.event_id.clone()));
        task3_decision_ids.extend(
            events
                .iter()
                .filter_map(|event| event.attributes.get("task3_decision_id").cloned()),
        );
        supplied_events.extend(events);
    }
    let mut accepted = Vec::new();
    let mut rejected_or_replayed = 0;
    for event in supplied_events {
        if temporal.ingest(event.clone())? {
            accepted.push(event);
        } else {
            rejected_or_replayed += 1;
        }
    }
    let features = temporal.features_for_node_at(&input.node_id, input.evaluated_at_ms);
    // Ingestion retains bounded history; only non-future evidence may reach D5-D7.
    let future_event_count = accepted
        .iter()
        .filter(|event| event.observed_at_ms > input.evaluated_at_ms)
        .count();
    let analysis_events: Vec<SecurityEvent> = accepted
        .iter()
        .filter(|event| event.observed_at_ms <= input.evaluated_at_ms)
        .cloned()
        .collect();
    let sequence = match_precursor_sequence(
        &input.sequence_definition,
        &input.node_id,
        &analysis_events,
        input.evaluated_at_ms,
    )?;
    let predictor_input = ThreatPredictorInput {
        node_id: &input.node_id,
        evaluated_at_ms: input.evaluated_at_ms,
        temporal_features: &features,
        events: &analysis_events,
        precursor_sequence: Some(&sequence),
        config: &input.prediction_config,
    };
    let primary_forecast = predict_primary(input.primary_predictor, &predictor_input)?;
    let cascade = match (
        &input.peer_relationship,
        input.source_compromise_probability,
    ) {
        (Some(relationship), Some(probability)) => predict_peer_cascade(
            probability,
            relationship,
            &analysis_events,
            input.evaluated_at_ms,
            &input.prediction_config,
        )?,
        _ => None,
    };
    let forecast_count = usize::from(primary_forecast.is_some()) + usize::from(cascade.is_some());
    let forecast = primary_forecast.clone().or_else(|| cascade.clone());
    let mut recommendation = None;
    let mut recommendation_artifact_path = None;
    let mut lifecycle_record = None;
    let mut forecast_artifact_path = None;
    if let Some(forecast) = &forecast {
        if input
            .prediction_config
            .is_actionable(forecast.probability, forecast.confidence)?
        {
            recommendation = Some(recommend_predictive_hardening(
                forecast,
                &input.prediction_config,
                &input.hardening_config,
                &input.task2_templates,
            )?);
        }
        let store = ForecastStore::new(
            &input.audit_root,
            input.prediction_config.forecast_retention_days,
        )?;
        lifecycle_record = Some(store.persist_initial(forecast.clone(), input.evaluated_at_ms)?);
        forecast_artifact_path = Some(
            input
                .audit_root
                .join("forecasts")
                .join(format!("{}.json", forecast.forecast_id)),
        );
        if let Some(advisory) = &recommendation {
            let path = input.audit_root.join("task2_review_advisory.json");
            let json = serde_json::to_vec_pretty(advisory)
                .map_err(|error| ThreatPredictionError::Serialization(error.to_string()))?;
            fs::write(&path, json).map_err(|error| {
                ThreatPredictionError::Io(format!("writing {}: {error}", path.display()))
            })?;
            recommendation_artifact_path = Some(path);
        }
    }
    Ok(E2eCycleOutput {
        evaluation_id: input.evaluation_id,
        forecast,
        cascade_forecast: cascade,
        recommendation,
        recommendation_artifact_path,
        lifecycle_record,
        forecast_artifact_path,
        accepted_event_ids: accepted
            .iter()
            .map(|event| event.event_id.clone())
            .collect(),
        task1_event_ids,
        task3_event_ids,
        task3_decision_ids,
        sequence_id: sequence.sequence_id.clone(),
        sequence_matched_event_ids: sequence.matched_event_ids.clone(),
        sequence_matched_steps: sequence.matched_steps,
        metrics: E2eResourceMetrics {
            accepted_event_count: accepted.len(),
            rejected_or_replayed_event_count: rejected_or_replayed,
            future_event_count,
            temporal_max_events: max_events,
            temporal_window_count: features.windows.len(),
            forecast_count,
            inference_latency_micros: started.elapsed().as_micros(),
        },
    })
}

fn predict_primary(
    predictor: E2ePrimaryPredictor,
    input: &ThreatPredictorInput<'_>,
) -> Result<Option<ThreatForecast>, ThreatPredictionError> {
    match predictor {
        E2ePrimaryPredictor::Ddos => DdosPredictor.predict(input),
        E2ePrimaryPredictor::ReconnaissanceEscalation => ReconEscalationPredictor.predict(input),
        E2ePrimaryPredictor::BruteForce => BruteForcePredictor.predict(input),
        E2ePrimaryPredictor::ExploitationAttempt => ExploitationPredictor.predict(input),
        E2ePrimaryPredictor::ProtocolAbuse => ProtocolAbusePredictor.predict(input),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlledCaseResult {
    pub expected_threat: bool,
    pub forecast_created: bool,
    /// Fixed-time ground-truth timestamp. For true positives, lead time is
    /// `known_threat_at_ms - evaluated_at_ms`, never a wall-clock estimate.
    pub evaluated_at_ms: u64,
    pub known_threat_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlledEvaluationMetrics {
    pub true_positive: u32,
    pub false_positive: u32,
    pub true_negative: u32,
    pub false_negative: u32,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub false_positive_rate: f64,
    pub mean_lead_time_ms: u64,
    pub lead_time_sample_count: u32,
    pub calibration_mean_absolute_error: f64,
}

pub fn evaluate_controlled_cases(
    cases: &[ControlledCaseResult],
    forecast_probabilities: &[f64],
) -> Result<ControlledEvaluationMetrics, ThreatPredictionError> {
    if cases.is_empty() || cases.len() != forecast_probabilities.len() {
        return Err(ThreatPredictionError::InvalidConfig(
            "controlled cases and probabilities must be non-empty and aligned".into(),
        ));
    }
    let mut tp = 0_u32;
    let mut fp = 0_u32;
    let mut tn = 0_u32;
    let mut fn_ = 0_u32;
    let mut calibration_error = 0.0;
    let mut total_lead_time_ms = 0_u64;
    let mut lead_time_sample_count = 0_u32;
    for (case, probability) in cases.iter().zip(forecast_probabilities) {
        if !probability.is_finite() || !(0.0..=1.0).contains(probability) {
            return Err(ThreatPredictionError::InvalidProbability(
                "controlled forecast probability must be within [0,1]".into(),
            ));
        }
        calibration_error += (probability - f64::from(case.expected_threat)).abs();
        match (case.expected_threat, case.forecast_created) {
            (true, true) => {
                tp += 1;
                if let Some(known_threat_at_ms) = case.known_threat_at_ms {
                    if known_threat_at_ms >= case.evaluated_at_ms {
                        total_lead_time_ms = total_lead_time_ms
                            .saturating_add(known_threat_at_ms - case.evaluated_at_ms);
                        lead_time_sample_count += 1;
                    }
                }
            }
            (false, true) => fp += 1,
            (false, false) => tn += 1,
            (true, false) => fn_ += 1,
        }
    }
    let precision = ratio(tp, tp + fp);
    let recall = ratio(tp, tp + fn_);
    let f1 = if precision + recall == 0.0 {
        0.0
    } else {
        2.0 * precision * recall / (precision + recall)
    };
    Ok(ControlledEvaluationMetrics {
        true_positive: tp,
        false_positive: fp,
        true_negative: tn,
        false_negative: fn_,
        precision,
        recall,
        f1,
        false_positive_rate: ratio(fp, fp + tn),
        mean_lead_time_ms: if lead_time_sample_count == 0 {
            0
        } else {
            total_lead_time_ms / u64::from(lead_time_sample_count)
        },
        lead_time_sample_count,
        calibration_mean_absolute_error: calibration_error / cases.len() as f64,
    })
}

/// One persisted, run-oriented D12 artifact. Resource fields are bounded
/// capacity indicators, intentionally not platform-specific process memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eEvaluationArtifact {
    pub schema_version: String,
    pub evaluation_id: String,
    pub evaluated_at_ms: u64,
    pub config_version: String,
    pub maximum_imminent_horizon_minutes: u32,
    pub cycle: E2eCycleOutput,
    pub quality_metrics: ControlledEvaluationMetrics,
}

pub fn persist_e2e_evaluation_artifact(
    output: E2eCycleOutput,
    config: &ThreatPredictionConfig,
    quality_metrics: ControlledEvaluationMetrics,
    output_root: impl Into<PathBuf>,
) -> Result<PathBuf, ThreatPredictionError> {
    config.validate()?;
    validate_evaluation_id(&output.evaluation_id)?;
    let directory = output_root.into().join(&output.evaluation_id);
    fs::create_dir_all(&directory).map_err(|error| {
        ThreatPredictionError::Io(format!("creating D12 output directory: {error}"))
    })?;
    let path = directory.join("evaluation_summary.json");
    let artifact = E2eEvaluationArtifact {
        schema_version: "task4-d12-evaluation-v1".into(),
        evaluation_id: output.evaluation_id.clone(),
        evaluated_at_ms: output
            .forecast
            .as_ref()
            .map_or(0, |forecast| forecast.generated_at_ms),
        config_version: config.config_version.clone(),
        maximum_imminent_horizon_minutes: super::MAX_IMMINENT_FORECAST_HORIZON_MINUTES,
        cycle: output,
        quality_metrics,
    };
    fs::write(
        &path,
        serde_json::to_vec_pretty(&artifact)
            .map_err(|error| ThreatPredictionError::Serialization(error.to_string()))?,
    )
    .map_err(|error| {
        ThreatPredictionError::Io(format!("writing D12 evaluation artifact: {error}"))
    })?;
    Ok(path)
}

fn validate_evaluation_id(value: &str) -> Result<(), ThreatPredictionError> {
    if value.is_empty()
        || value.len() > 160
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(ThreatPredictionError::InvalidConfig(
            "D12 evaluation_id must be a bounded safe identifier".into(),
        ));
    }
    Ok(())
}

fn ratio(numerator: u32, denominator: u32) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        f64::from(numerator) / f64::from(denominator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat_prediction::{
        EventSeverity, EvidenceSource, SecurityEventType, SECURITY_EVENT_SCHEMA_VERSION,
    };
    use std::collections::BTreeMap;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    const REFERENCE: u64 = 3_000_000;
    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn traffic_event(
        id: &str,
        observed_at_ms: u64,
        source_ip: &str,
        destination_ip: &str,
        traffic_bytes: u64,
        connection_count: u64,
    ) -> SecurityEvent {
        SecurityEvent {
            schema_version: SECURITY_EVENT_SCHEMA_VERSION,
            event_id: id.into(),
            observed_at_ms,
            source: EvidenceSource::Task1Anomaly,
            node_id: "nodeB".into(),
            peer_id: Some("nodeA".into()),
            source_ip: Some(source_ip.into()),
            destination_ip: Some(destination_ip.into()),
            source_port: None,
            destination_port: Some(443),
            event_type: SecurityEventType::TrafficAnomaly,
            severity: EventSeverity::High,
            confidence: 0.9,
            attributes: BTreeMap::from([
                ("task1_anomaly_score".into(), "0.9".into()),
                ("traffic_bytes".into(), traffic_bytes.to_string()),
                ("connection_count".into(), connection_count.to_string()),
            ]),
        }
    }

    fn input(events: Vec<SecurityEvent>, suffix: &str) -> E2eCycleInput {
        let root = std::env::temp_dir().join(format!(
            "task4-d12-{suffix}-{}-{}",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        E2eCycleInput {
            evaluation_id: format!("task4-d12-{suffix}"),
            node_id: "nodeB".into(),
            evaluated_at_ms: REFERENCE,
            events,
            task1_recommendation_path: None,
            task3_degradation_path: None,
            task3_peer_id: None,
            task3_context_config: Task3ContextConfig::default(),
            temporal_config: TemporalFeatureConfig::default(),
            prediction_config: ThreatPredictionConfig::default(),
            primary_predictor: E2ePrimaryPredictor::Ddos,
            sequence_definition: PrecursorSequenceDefinition::recon_to_compromise(),
            peer_relationship: None,
            source_compromise_probability: None,
            hardening_config: HardeningRecommendationConfig::default(),
            task2_templates: PolicyTemplates::from_path("config/policy_action_templates.json")
                .unwrap(),
            audit_root: root,
        }
    }

    fn positive_events() -> Vec<SecurityEvent> {
        vec![
            traffic_event(
                "previous",
                REFERENCE - 6 * 60_000,
                "10.0.0.1",
                "10.0.0.20",
                10,
                1,
            ),
            traffic_event(
                "current-a",
                REFERENCE - 60_000,
                "10.0.0.2",
                "10.0.0.21",
                300,
                100,
            ),
            traffic_event(
                "current-b",
                REFERENCE - 60_000,
                "10.0.0.3",
                "10.0.0.22",
                300,
                100,
            ),
            traffic_event(
                "current-c",
                REFERENCE - 60_000,
                "10.0.0.4",
                "10.0.0.23",
                300,
                100,
            ),
        ]
    }

    fn temporary_path(name: &str, extension: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "task4-d12-{name}-{}-{}.{}",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed),
            extension
        ))
    }

    fn write_task1_artifact(path: &PathBuf) {
        let json = serde_json::json!({
            "schema_version": 1,
            "node": "nodeB",
            "recommendations": [{
                "rec_id": "d12-task1-record-001",
                "alert_id": "d12-task1-alert-001",
                "source_time_ms": REFERENCE - 60_000,
                "decision": "ANOMALY",
                "score": 0.91,
                "model_confidence": 0.90,
                "severity": "High",
                "evidence_features": ["traffic_bytes", "connection_count"],
                "anomaly_type": "ddos",
                "anomaly": {"detector": "task1-fixture", "contributors": []},
                "port_security_context": {"target_ip": "10.0.0.20", "target_port": 443}
            }]
        });
        fs::write(path, serde_json::to_vec(&json).unwrap()).unwrap();
    }

    fn write_task3_artifact(path: &PathBuf) {
        let row = serde_json::json!({
            "decision_id": "task3-d12-decision-001",
            "ts_ms": REFERENCE - 60_000,
            "prediction": {
                "model_version": "task3-degradation-v1",
                "route_id": "relay-nodeA-nodeB",
                "probability": 0.82,
                "horizon_seconds": 60,
                "contributors": ["packet_loss_rising"],
                "reason": "bounded D12 Task3 fixture"
            }
        });
        fs::write(path, serde_json::to_vec(&row).unwrap()).unwrap();
    }

    fn related_peer() -> PeerRelationship {
        PeerRelationship {
            relationship_id: "d12-related-nodea-nodeb".into(),
            provenance: "d12-authorized-topology".into(),
            reasons: vec![
                "same_network_segment".into(),
                "recent_direct_communication".into(),
            ],
            observed_at_ms: REFERENCE - 60_000,
            expires_at_ms: REFERENCE + 60_000,
            source_node: "nodeA".into(),
            target_node: "nodeB".into(),
            same_segment: true,
            recent_direct_communication: true,
            shared_service_or_relay: true,
            topology_dependency: false,
            relevant_exposed_port: true,
        }
    }

    fn cascade_event(id: &str, source: EvidenceSource) -> SecurityEvent {
        SecurityEvent {
            schema_version: SECURITY_EVENT_SCHEMA_VERSION,
            event_id: id.into(),
            observed_at_ms: REFERENCE - 60_000,
            source,
            node_id: "nodeB".into(),
            peer_id: Some("nodeA".into()),
            source_ip: Some("10.0.0.1".into()),
            destination_ip: Some("10.0.0.20".into()),
            source_port: None,
            destination_port: Some(443),
            event_type: SecurityEventType::TrustDegradation,
            severity: EventSeverity::High,
            confidence: 0.90,
            attributes: BTreeMap::new(),
        }
    }

    #[test]
    fn complete_pipeline_persists_review_only_forecast_and_is_repeatable() {
        let first = run_e2e_cycle(input(positive_events(), "first")).unwrap();
        assert!(first.forecast.is_some());
        assert!(first.recommendation.is_some());
        assert!(first
            .recommendation_artifact_path
            .as_ref()
            .is_some_and(|path| path.is_file()));
        assert!(first.lifecycle_record.is_some());
        assert_eq!(first.metrics.accepted_event_count, 4);
        assert_eq!(first.metrics.temporal_window_count, 7);
        assert!(first.metrics.inference_latency_micros > 0);

        let second = run_e2e_cycle(input(positive_events(), "second")).unwrap();
        assert_eq!(first.forecast, second.forecast);
    }

    #[test]
    fn controlled_fixture_metrics_cover_positive_and_benign_cases() {
        let positive = run_e2e_cycle(input(positive_events(), "positive")).unwrap();
        let benign = run_e2e_cycle(input(Vec::new(), "benign")).unwrap();
        let metrics = evaluate_controlled_cases(
            &[
                ControlledCaseResult {
                    expected_threat: true,
                    forecast_created: positive.forecast.is_some(),
                    evaluated_at_ms: REFERENCE,
                    known_threat_at_ms: Some(REFERENCE + 5 * 60_000),
                },
                ControlledCaseResult {
                    expected_threat: false,
                    forecast_created: benign.forecast.is_some(),
                    evaluated_at_ms: REFERENCE,
                    known_threat_at_ms: None,
                },
            ],
            &[
                positive
                    .forecast
                    .as_ref()
                    .map_or(0.0, |forecast| forecast.probability),
                benign
                    .forecast
                    .as_ref()
                    .map_or(0.0, |forecast| forecast.probability),
            ],
        )
        .unwrap();
        assert_eq!((metrics.true_positive, metrics.false_positive), (1, 0));
        assert_eq!((metrics.true_negative, metrics.false_negative), (1, 0));
        assert_eq!(metrics.precision, 1.0);
        assert_eq!(metrics.recall, 1.0);
        assert_eq!(metrics.f1, 1.0);
        assert_eq!(metrics.false_positive_rate, 0.0);
        assert_eq!(metrics.mean_lead_time_ms, 5 * 60_000);
    }

    #[test]
    fn e2e_uses_real_task1_task3_bridges_and_persists_full_traceability() {
        let task1_path = temporary_path("task1", "json");
        let task3_path = temporary_path("task3", "jsonl");
        write_task1_artifact(&task1_path);
        write_task3_artifact(&task3_path);
        let mut cycle_input = input(positive_events(), "bridges");
        cycle_input.task1_recommendation_path = Some(task1_path.clone());
        cycle_input.task3_degradation_path = Some(task3_path.clone());
        cycle_input.task3_peer_id = Some("nodeA".into());
        let output = run_e2e_cycle(cycle_input).unwrap();
        let forecast = output.forecast.as_ref().unwrap();
        let recommendation = output.recommendation.as_ref().unwrap();
        assert_eq!(
            output.task1_event_ids,
            vec!["task4-task1:d12-task1-record-001"]
        );
        assert_eq!(output.task3_event_ids.len(), 1);
        assert_eq!(output.task3_decision_ids, vec!["task3-d12-decision-001"]);
        assert!(output
            .accepted_event_ids
            .contains(&output.task1_event_ids[0]));
        assert!(output
            .accepted_event_ids
            .contains(&output.task3_event_ids[0]));
        assert_eq!(recommendation.forecast_id, forecast.forecast_id);
        assert!(recommendation.requires_task2_review);
        assert!(!recommendation.actions.is_empty());
        assert!(output.forecast_artifact_path.as_ref().unwrap().exists());
        assert_eq!(
            output.lifecycle_record.as_ref().unwrap().forecast.status,
            forecast.status
        );
        assert!(forecast
            .explanation
            .top_factors
            .iter()
            .all(|factor| !factor.evidence_ids.is_empty()));
        let metrics = evaluate_controlled_cases(
            &[ControlledCaseResult {
                expected_threat: true,
                forecast_created: true,
                evaluated_at_ms: REFERENCE,
                known_threat_at_ms: Some(REFERENCE + 60_000),
            }],
            &[forecast.probability],
        )
        .unwrap();
        let artifact_root = temporary_path("evaluation-artifact", "dir");
        let artifact = persist_e2e_evaluation_artifact(
            output.clone(),
            &ThreatPredictionConfig::default(),
            metrics,
            &artifact_root,
        )
        .unwrap();
        let saved: E2eEvaluationArtifact =
            serde_json::from_slice(&fs::read(&artifact).unwrap()).unwrap();
        assert_eq!(saved.evaluation_id, output.evaluation_id);
        assert_eq!(
            saved.cycle.forecast.as_ref().unwrap().forecast_id,
            forecast.forecast_id
        );
        assert_eq!(
            saved
                .cycle
                .recommendation
                .as_ref()
                .unwrap()
                .recommendation_id,
            recommendation.recommendation_id
        );
        // The D11 adapter is read-only: its source JSONL remains unchanged.
        assert!(fs::read_to_string(&task3_path)
            .unwrap()
            .contains("relay-nodeA-nodeB"));
        let _ = fs::remove_file(task1_path);
        let _ = fs::remove_file(task3_path);
        let _ = fs::remove_dir_all(artifact_root);
    }

    #[test]
    fn e2e_exercises_related_cascade_and_blocks_circle_only_propagation() {
        let mut related_input = input(
            vec![
                cascade_event("d12-task1", EvidenceSource::Task1Anomaly),
                cascade_event("d12-trust", EvidenceSource::CircleTrust),
            ],
            "cascade-related",
        );
        related_input.peer_relationship = Some(related_peer());
        related_input.source_compromise_probability = Some(0.95);
        let related = run_e2e_cycle(related_input).unwrap();
        let cascade = related.cascade_forecast.as_ref().unwrap();
        assert_eq!(
            cascade.threat_type,
            super::super::PredictedThreatType::PeerCompromiseCascade
        );
        assert!(cascade.evidence_ids.contains(&"d12-task1".into()));
        assert!(cascade
            .explanation
            .relationship_reasons
            .contains(&"same_network_segment".into()));
        assert!(!cascade.explanation.summary.contains("compromised"));

        let mut circle_only = input(
            vec![cascade_event(
                "d12-circle-only",
                EvidenceSource::CircleTrust,
            )],
            "cascade-circle-only",
        );
        circle_only.peer_relationship = Some(related_peer());
        circle_only.source_compromise_probability = Some(0.95);
        assert!(run_e2e_cycle(circle_only)
            .unwrap()
            .cascade_forecast
            .is_none());

        let mut unrelated = input(
            vec![cascade_event(
                "d12-unrelated-task1",
                EvidenceSource::Task1Anomaly,
            )],
            "cascade-unrelated",
        );
        let mut unrelated_relationship = related_peer();
        unrelated_relationship.target_node = "nodeC".into();
        unrelated.peer_relationship = Some(unrelated_relationship);
        unrelated.source_compromise_probability = Some(0.95);
        assert!(run_e2e_cycle(unrelated).unwrap().cascade_forecast.is_none());
    }

    #[test]
    fn e2e_filters_future_replays_rejects_malformed_and_enforces_configured_horizons() {
        let mut events = positive_events();
        events.push(events[0].clone());
        events.push(traffic_event(
            "future-event",
            REFERENCE + 60_000,
            "10.0.0.99",
            "10.0.0.20",
            9_999,
            9_999,
        ));
        let output = run_e2e_cycle(input(events, "safety")).unwrap();
        let baseline = run_e2e_cycle(input(positive_events(), "future-baseline")).unwrap();
        assert_eq!(output.metrics.rejected_or_replayed_event_count, 1);
        assert_eq!(output.metrics.future_event_count, 1);
        let forecast = output.forecast.unwrap();
        assert_eq!(Some(forecast.clone()), baseline.forecast);
        assert!((0.0..=1.0).contains(&forecast.probability));
        assert!((0.0..=1.0).contains(&forecast.confidence));
        assert!(forecast.horizon_end_ms - forecast.horizon_start_ms <= 30 * 60_000);

        let mut malformed = input(positive_events(), "malformed");
        malformed.events[0].node_id.clear();
        assert!(run_e2e_cycle(malformed).is_err());

        let mut bounded = input(positive_events(), "bounded");
        bounded.temporal_config.max_events = 2;
        let bounded_output = run_e2e_cycle(bounded).unwrap();
        assert_eq!(bounded_output.metrics.temporal_max_events, 2);
        assert_eq!(bounded_output.metrics.accepted_event_count, 4);

        let mut invalid_horizon = input(positive_events(), "invalid-horizon");
        invalid_horizon
            .prediction_config
            .forecast_horizons_minutes
            .insert(super::super::PredictedThreatType::Ddos, vec![120]);
        assert!(run_e2e_cycle(invalid_horizon).is_err());
    }

    #[test]
    fn controlled_metrics_include_fpr_lead_time_and_safe_zero_denominators() {
        let metrics = evaluate_controlled_cases(
            &[
                ControlledCaseResult {
                    expected_threat: true,
                    forecast_created: true,
                    evaluated_at_ms: 100,
                    known_threat_at_ms: Some(400),
                },
                ControlledCaseResult {
                    expected_threat: false,
                    forecast_created: true,
                    evaluated_at_ms: 100,
                    known_threat_at_ms: None,
                },
                ControlledCaseResult {
                    expected_threat: false,
                    forecast_created: false,
                    evaluated_at_ms: 100,
                    known_threat_at_ms: None,
                },
                ControlledCaseResult {
                    expected_threat: true,
                    forecast_created: false,
                    evaluated_at_ms: 100,
                    known_threat_at_ms: Some(400),
                },
            ],
            &[0.9, 0.7, 0.1, 0.2],
        )
        .unwrap();
        assert_eq!(
            (
                metrics.true_positive,
                metrics.false_positive,
                metrics.true_negative,
                metrics.false_negative
            ),
            (1, 1, 1, 1)
        );
        assert_eq!(metrics.precision, 0.5);
        assert_eq!(metrics.recall, 0.5);
        assert_eq!(metrics.f1, 0.5);
        assert_eq!(metrics.false_positive_rate, 0.5);
        assert_eq!(metrics.mean_lead_time_ms, 300);
        assert!(metrics.calibration_mean_absolute_error.is_finite());

        let zero = evaluate_controlled_cases(
            &[ControlledCaseResult {
                expected_threat: false,
                forecast_created: false,
                evaluated_at_ms: 1,
                known_threat_at_ms: None,
            }],
            &[0.0],
        )
        .unwrap();
        assert_eq!(
            (
                zero.precision,
                zero.recall,
                zero.f1,
                zero.false_positive_rate
            ),
            (0.0, 0.0, 0.0, 0.0)
        );
        assert_eq!(zero.mean_lead_time_ms, 0);
    }

    #[test]
    fn benchmark_fields_are_repeatable_while_latency_is_observational() {
        let first = run_e2e_cycle(input(positive_events(), "benchmark-one")).unwrap();
        let second = run_e2e_cycle(input(positive_events(), "benchmark-two")).unwrap();
        assert_eq!(first.forecast, second.forecast);
        assert_eq!(
            first.metrics.accepted_event_count,
            second.metrics.accepted_event_count
        );
        assert_eq!(
            first.metrics.rejected_or_replayed_event_count,
            second.metrics.rejected_or_replayed_event_count
        );
        assert_eq!(
            first.metrics.temporal_max_events,
            second.metrics.temporal_max_events
        );
        assert_eq!(
            first.metrics.temporal_window_count,
            second.metrics.temporal_window_count
        );
        assert_eq!(first.metrics.forecast_count, second.metrics.forecast_count);
        assert!(first.metrics.inference_latency_micros > 0);
        assert!(second.metrics.inference_latency_micros > 0);
    }
}
