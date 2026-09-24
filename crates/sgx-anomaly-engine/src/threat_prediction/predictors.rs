//! Task 4 Deliverable 6: deterministic imminent-threat predictors.
//!
//! These baseline predictors consume normalized source evidence, retained
//! temporal features and (where relevant) Deliverable 5 sequence output. They
//! do not collect telemetry, rerun Task 1, construct Nmap commands, or apply
//! any security control.

use super::{
    assess_confidence, ConfidenceContext, EvidenceSource, ForecastExplanation, ForecastFactor,
    ForecastStatus, PrecursorSequenceMatch, PredictedThreatType, SecurityEvent, SecurityEventType,
    TemporalFeatures, TemporalWindowFeatures, ThreatForecast, ThreatPredictionConfig,
    ThreatPredictionError, THREAT_FORECAST_SCHEMA_VERSION,
};
use std::collections::{BTreeMap, BTreeSet};

const MINUTE_MS: u64 = 60_000;
const MODEL_VERSION: &str = "task4-d6-deterministic-baseline-v1";

pub struct ThreatPredictorInput<'a> {
    pub node_id: &'a str,
    pub evaluated_at_ms: u64,
    pub temporal_features: &'a TemporalFeatures,
    pub events: &'a [SecurityEvent],
    pub precursor_sequence: Option<&'a PrecursorSequenceMatch>,
    pub config: &'a ThreatPredictionConfig,
}

pub trait ThreatPredictor {
    fn predict(
        &self,
        input: &ThreatPredictorInput<'_>,
    ) -> Result<Option<ThreatForecast>, ThreatPredictionError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct DdosPredictor;

#[derive(Debug, Default, Clone, Copy)]
pub struct ReconEscalationPredictor;

#[derive(Debug, Default, Clone, Copy)]
pub struct BruteForcePredictor;

#[derive(Debug, Default, Clone, Copy)]
pub struct ExploitationPredictor;

#[derive(Debug, Default, Clone, Copy)]
pub struct ProtocolAbusePredictor;

impl ThreatPredictor for DdosPredictor {
    fn predict(
        &self,
        input: &ThreatPredictorInput<'_>,
    ) -> Result<Option<ThreatForecast>, ThreatPredictionError> {
        let recent_window = window(input, 5)?;
        let persistent_window = window(input, 15)?;
        let evidence = merge_evidence(
            evidence_ids(input, &[SecurityEventType::TrafficAnomaly])?,
            evidence_ids(
                input,
                &[
                    SecurityEventType::TrustDegradation,
                    SecurityEventType::PeerCompromiseIndicator,
                ],
            )?,
        );
        let mut factors = Vec::new();
        add_factor(
            &mut factors,
            "traffic_growth",
            recent_window.traffic_growth_rate_per_minute > 0.0,
            0.30,
            &evidence,
        );
        add_factor(
            &mut factors,
            "target_concentration",
            target_concentration(input, &[SecurityEventType::TrafficAnomaly])? >= 3,
            0.10,
            &evidence,
        );
        add_factor(
            &mut factors,
            "time_of_day_deviation",
            input.temporal_features.time_of_day.seasonal_deviation_score >= 0.50,
            0.10,
            &evidence,
        );
        add_factor(
            &mut factors,
            "multi_window_persistence",
            recent_window.traffic_growth_rate_per_minute > 0.0
                && persistent_window.traffic_growth_rate_per_minute > 0.0,
            0.10,
            &evidence,
        );
        add_factor(
            &mut factors,
            "circle_observation",
            has_circle_observation(input)?,
            0.10,
            &evidence,
        );
        add_factor(
            &mut factors,
            "connection_acceleration",
            recent_window.connection_rate_delta_per_minute > 0.0,
            0.25,
            &evidence,
        );
        add_factor(
            &mut factors,
            "unique_source_growth",
            recent_window.unique_source_count >= 3,
            0.20,
            &evidence,
        );
        add_factor(
            &mut factors,
            "task1_anomaly",
            recent_window.anomaly_score_max.unwrap_or(0.0) >= 0.70,
            0.15,
            &evidence,
        );
        add_factor(
            &mut factors,
            "traffic_anomaly_evidence",
            !evidence.is_empty(),
            0.10,
            &evidence,
        );
        forecast_from_factors(
            input,
            PredictedThreatType::Ddos,
            5,
            "DDoS indicators: traffic and connection burst",
            factors,
            evidence,
            0.50,
        )
    }
}

impl ThreatPredictor for ReconEscalationPredictor {
    fn predict(
        &self,
        input: &ThreatPredictorInput<'_>,
    ) -> Result<Option<ThreatForecast>, ThreatPredictionError> {
        let window = window(input, 30)?;
        let evidence = evidence_ids(
            input,
            &[
                SecurityEventType::Reconnaissance,
                SecurityEventType::PortDiscovery,
                SecurityEventType::ExposureDiscovery,
            ],
        )?;
        let mut factors = Vec::new();
        add_factor(
            &mut factors,
            "scan_velocity",
            window.scan_velocity_per_minute > 0.0,
            0.25,
            &evidence,
        );
        add_factor(
            &mut factors,
            "repeated_source",
            repeated_source(
                input,
                &[
                    SecurityEventType::Reconnaissance,
                    SecurityEventType::PortDiscovery,
                    SecurityEventType::ExposureDiscovery,
                ],
            )?,
            0.10,
            &evidence,
        );
        add_factor(
            &mut factors,
            "multi_peer_or_target",
            multi_peer_or_target(
                input,
                &[
                    SecurityEventType::Reconnaissance,
                    SecurityEventType::PortDiscovery,
                    SecurityEventType::ExposureDiscovery,
                ],
            )?,
            0.10,
            &evidence,
        );
        add_factor(
            &mut factors,
            "multiple_target_ports",
            window.unique_destination_port_count >= 2,
            0.20,
            &evidence,
        );
        add_factor(
            &mut factors,
            "exposed_service",
            window.vulnerable_service_count > 0 || window.new_open_port_rate_per_minute > 0.0,
            0.20,
            &evidence,
        );
        add_factor(
            &mut factors,
            "task1_port_anomaly",
            window.anomaly_score_max.unwrap_or(0.0) >= 0.70,
            0.15,
            &evidence,
        );
        add_factor(
            &mut factors,
            "ordered_precursor_sequence",
            input
                .precursor_sequence
                .is_some_and(|sequence| sequence.fresh),
            0.20,
            &evidence,
        );
        forecast_from_factors(
            input,
            PredictedThreatType::ReconnaissanceEscalation,
            30,
            "Reconnaissance indicators may escalate",
            factors,
            evidence,
            0.50,
        )
    }
}

impl ThreatPredictor for BruteForcePredictor {
    fn predict(
        &self,
        input: &ThreatPredictorInput<'_>,
    ) -> Result<Option<ThreatForecast>, ThreatPredictionError> {
        let window = window(input, 15)?;
        let evidence = evidence_ids(input, &[SecurityEventType::AuthenticationFailure])?;
        let mut factors = Vec::new();
        add_factor(
            &mut factors,
            "failed_authentication_rate",
            window.failed_auth_rate_per_minute >= 0.20,
            0.45,
            &evidence,
        );
        add_factor(
            &mut factors,
            "source_repetition",
            repeated_source(input, &[SecurityEventType::AuthenticationFailure])?,
            0.10,
            &evidence,
        );
        add_factor(
            &mut factors,
            "suricata_authentication_evidence",
            has_source_evidence(
                input,
                &[SecurityEventType::AuthenticationFailure],
                EvidenceSource::Suricata,
            )?,
            0.10,
            &evidence,
        );
        add_factor(
            &mut factors,
            "reconnaissance_history",
            window.scan_velocity_per_minute > 0.0,
            0.20,
            &evidence,
        );
        add_factor(
            &mut factors,
            "exposed_authentication_service",
            window.vulnerable_service_count > 0 || window.new_open_port_rate_per_minute > 0.0,
            0.20,
            &evidence,
        );
        add_factor(
            &mut factors,
            "task1_anomaly",
            window.anomaly_score_max.unwrap_or(0.0) >= 0.70,
            0.15,
            &evidence,
        );
        forecast_from_factors(
            input,
            PredictedThreatType::BruteForce,
            10,
            "Repeated authentication failures indicate brute-force risk",
            factors,
            evidence,
            0.45,
        )
    }
}

impl ThreatPredictor for ExploitationPredictor {
    fn predict(
        &self,
        input: &ThreatPredictorInput<'_>,
    ) -> Result<Option<ThreatForecast>, ThreatPredictionError> {
        let exposure_window = window(input, 30)?;
        let auth_window = window(input, 15)?;
        let evidence = evidence_ids(input, &[SecurityEventType::ExposureDiscovery])?;
        let mut factors = Vec::new();
        add_factor(
            &mut factors,
            "vulnerable_service_exposure",
            exposure_window.vulnerable_service_count > 0,
            0.40,
            &evidence,
        );
        add_factor(
            &mut factors,
            "failed_authentication_trend",
            auth_window.failed_auth_rate_per_minute >= 0.20,
            0.15,
            &evidence,
        );
        add_factor(
            &mut factors,
            "ids_exploit_evidence",
            has_ids_exploit_evidence(input)?,
            0.15,
            &evidence,
        );
        add_factor(
            &mut factors,
            "source_repetition",
            repeated_source(input, &[SecurityEventType::ExposureDiscovery])?,
            0.10,
            &evidence,
        );
        add_factor(
            &mut factors,
            "recent_service_exposure",
            exposure_window.new_open_port_rate_per_minute > 0.0,
            0.20,
            &evidence,
        );
        add_factor(
            &mut factors,
            "task1_anomaly",
            exposure_window.anomaly_score_max.unwrap_or(0.0) >= 0.70,
            0.20,
            &evidence,
        );
        add_factor(
            &mut factors,
            "reconnaissance_history",
            exposure_window.scan_velocity_per_minute > 0.0,
            0.20,
            &evidence,
        );
        forecast_from_factors(
            input,
            PredictedThreatType::ExploitationAttempt,
            30,
            "Exposed service and attack indicators suggest exploitation risk",
            factors,
            evidence,
            0.50,
        )
    }
}

impl ThreatPredictor for ProtocolAbusePredictor {
    fn predict(
        &self,
        input: &ThreatPredictorInput<'_>,
    ) -> Result<Option<ThreatForecast>, ThreatPredictionError> {
        let window = window(input, 15)?;
        let evidence = evidence_ids(input, &[SecurityEventType::ProtocolViolation])?;
        let invalid_message_rate = protocol_invalid_message_rate(input, 15)?;
        let mut factors = Vec::new();
        add_factor(
            &mut factors,
            "protocol_alert_evidence",
            !evidence.is_empty(),
            0.40,
            &evidence,
        );
        add_factor(
            &mut factors,
            "invalid_message_rate",
            invalid_message_rate >= 0.20,
            0.15,
            &evidence,
        );
        add_factor(
            &mut factors,
            "connection_churn",
            window.connection_rate_delta_per_minute > 0.0,
            0.20,
            &evidence,
        );
        add_factor(
            &mut factors,
            "traffic_abnormality",
            window.traffic_growth_rate_per_minute > 0.0,
            0.15,
            &evidence,
        );
        add_factor(
            &mut factors,
            "task1_anomaly",
            window.anomaly_score_max.unwrap_or(0.0) >= 0.70,
            0.25,
            &evidence,
        );
        forecast_from_factors(
            input,
            PredictedThreatType::ProtocolAbuse,
            15,
            "Protocol-security indicators suggest abuse risk",
            factors,
            evidence,
            0.45,
        )
    }
}

fn window(
    input: &ThreatPredictorInput<'_>,
    minutes: u32,
) -> Result<TemporalWindowFeatures, ThreatPredictionError> {
    input.config.validate()?;
    if input.temporal_features.reference_time_ms != input.evaluated_at_ms {
        return Err(ThreatPredictionError::InvalidConfig(
            "predictor evaluation time must match the temporal feature reference time".to_string(),
        ));
    }
    input
        .temporal_features
        .windows
        .get(&minutes)
        .cloned()
        .ok_or_else(|| {
            ThreatPredictionError::InvalidConfig(format!(
                "missing required {minutes}-minute feature window"
            ))
        })
}

fn evidence_ids(
    input: &ThreatPredictorInput<'_>,
    types: &[SecurityEventType],
) -> Result<Vec<String>, ThreatPredictionError> {
    Ok(matching_events(input, types)?
        .into_iter()
        .map(|event| event.event_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn matching_events<'a>(
    input: &'a ThreatPredictorInput<'a>,
    types: &[SecurityEventType],
) -> Result<Vec<&'a SecurityEvent>, ThreatPredictionError> {
    let mut matching = Vec::new();
    for event in input.events {
        if event.node_id != input.node_id || event.observed_at_ms > input.evaluated_at_ms {
            continue;
        }
        event.validate()?;
        if types.contains(&event.event_type) {
            matching.push(event);
        }
    }
    Ok(matching)
}

fn merge_evidence(mut left: Vec<String>, right: Vec<String>) -> Vec<String> {
    left.extend(right);
    left.sort();
    left.dedup();
    left
}

fn target_concentration(
    input: &ThreatPredictorInput<'_>,
    types: &[SecurityEventType],
) -> Result<usize, ThreatPredictionError> {
    let mut counts = BTreeMap::new();
    for event in matching_events(input, types)? {
        let target = match (&event.destination_ip, event.destination_port) {
            (Some(ip), Some(port)) => format!("{ip}:{port}"),
            (Some(ip), None) => ip.clone(),
            (None, Some(port)) => format!("{}:{port}", event.node_id),
            (None, None) => format!("node:{}", event.node_id),
        };
        *counts.entry(target).or_insert(0usize) += 1;
    }
    Ok(counts.into_values().max().unwrap_or(0))
}

fn repeated_source(
    input: &ThreatPredictorInput<'_>,
    types: &[SecurityEventType],
) -> Result<bool, ThreatPredictionError> {
    let mut counts = BTreeMap::new();
    for event in matching_events(input, types)? {
        let source = event
            .source_ip
            .clone()
            .unwrap_or_else(|| format!("node:{}", event.node_id));
        *counts.entry(source).or_insert(0usize) += 1;
    }
    Ok(counts.into_values().any(|count| count >= 2))
}

fn multi_peer_or_target(
    input: &ThreatPredictorInput<'_>,
    types: &[SecurityEventType],
) -> Result<bool, ThreatPredictionError> {
    let events = matching_events(input, types)?;
    let peers = events
        .iter()
        .filter_map(|event| event.peer_id.as_deref())
        .collect::<BTreeSet<_>>();
    let targets = events
        .iter()
        .filter_map(|event| event.destination_ip.as_deref())
        .collect::<BTreeSet<_>>();
    Ok(peers.len() >= 2 || targets.len() >= 2)
}

fn has_source_evidence(
    input: &ThreatPredictorInput<'_>,
    types: &[SecurityEventType],
    source: EvidenceSource,
) -> Result<bool, ThreatPredictionError> {
    Ok(matching_events(input, types)?
        .iter()
        .any(|event| event.source == source))
}

fn has_circle_observation(input: &ThreatPredictorInput<'_>) -> Result<bool, ThreatPredictionError> {
    Ok(matching_events(
        input,
        &[
            SecurityEventType::TrustDegradation,
            SecurityEventType::PeerCompromiseIndicator,
        ],
    )?
    .iter()
    .any(|event| event.source == EvidenceSource::CircleTrust))
}

fn has_ids_exploit_evidence(
    input: &ThreatPredictorInput<'_>,
) -> Result<bool, ThreatPredictionError> {
    Ok(matching_events(
        input,
        &[
            SecurityEventType::ExposureDiscovery,
            SecurityEventType::ProtocolViolation,
        ],
    )?
    .iter()
    .any(|event| {
        event.source == EvidenceSource::Suricata
            && event
                .attributes
                .get("ids_exploit_alert")
                .is_some_and(|value| value.eq_ignore_ascii_case("true"))
    }))
}

fn protocol_invalid_message_rate(
    input: &ThreatPredictorInput<'_>,
    minutes: u32,
) -> Result<f64, ThreatPredictionError> {
    let count = matching_events(input, &[SecurityEventType::ProtocolViolation])?
        .iter()
        .filter_map(|event| event.attributes.get("invalid_message_count"))
        .filter_map(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value >= 0.0)
        .sum::<f64>();
    Ok(count / f64::from(minutes))
}

fn add_factor(
    factors: &mut Vec<ForecastFactor>,
    name: &str,
    present: bool,
    contribution: f64,
    evidence_ids: &[String],
) {
    if present {
        factors.push(ForecastFactor {
            name: name.to_string(),
            contribution,
            evidence_ids: evidence_ids.to_vec(),
        });
    }
}

fn forecast_from_factors(
    input: &ThreatPredictorInput<'_>,
    threat_type: PredictedThreatType,
    horizon_minutes: u64,
    summary: &str,
    factors: Vec<ForecastFactor>,
    evidence_ids: Vec<String>,
    minimum_probability: f64,
) -> Result<Option<ThreatForecast>, ThreatPredictionError> {
    input.config.validate()?;
    let horizon_minutes_u32 = u32::try_from(horizon_minutes).map_err(|_| {
        ThreatPredictionError::InvalidHorizon("predictor horizon exceeds u32 range".to_string())
    })?;
    let enabled_horizons = input
        .config
        .forecast_horizons_minutes
        .get(&threat_type)
        .ok_or_else(|| {
            ThreatPredictionError::InvalidHorizon(format!(
                "missing configured horizons for {threat_type:?}"
            ))
        })?;
    if !enabled_horizons.contains(&horizon_minutes_u32) {
        return Ok(None);
    }
    let raw_probability = factors
        .iter()
        .map(|factor| factor.contribution)
        .sum::<f64>()
        .min(1.0);
    let probability = input
        .config
        .probability_calibration
        .calibrate_probability(raw_probability, MODEL_VERSION)?;
    if probability < minimum_probability || evidence_ids.is_empty() {
        return Ok(None);
    }
    let assessment = assess_confidence(
        &confidence_context(input, &evidence_ids)?,
        input.config.probability_calibration.metadata.clone(),
    )?;
    let confidence = assessment.confidence;
    let threat_slug = format!("{threat_type:?}").to_lowercase();
    let forecast = ThreatForecast {
        schema_version: THREAT_FORECAST_SCHEMA_VERSION.to_string(),
        forecast_id: format!(
            "task4-d6-{threat_slug}-{}-{}",
            input.node_id, input.evaluated_at_ms
        ),
        model_version: MODEL_VERSION.to_string(),
        generated_at_ms: input.evaluated_at_ms,
        horizon_start_ms: input.evaluated_at_ms,
        horizon_end_ms: input.evaluated_at_ms + horizon_minutes * MINUTE_MS,
        threat_type,
        target_nodes: vec![input.node_id.to_string()],
        probability,
        confidence,
        severity: input.config.thresholds.severity_for(probability),
        evidence_ids,
        feature_snapshot_id: format!("task4-temporal-{}-{}", input.node_id, input.evaluated_at_ms),
        explanation: ForecastExplanation {
            summary: summary.to_string(),
            top_factors: factors,
            precursor_sequence_ids: input
                .precursor_sequence
                .filter(|sequence| sequence.fresh)
                .map(|sequence| vec![sequence.sequence_id.clone()])
                .unwrap_or_default(),
            missing_evidence: Vec::new(),
            relationship_reasons: Vec::new(),
            calibration: Some(assessment.calibration),
        },
        status: ForecastStatus::Active,
    };
    forecast.validate()?;
    Ok(Some(forecast))
}

fn confidence_context(
    input: &ThreatPredictorInput<'_>,
    evidence_ids: &[String],
) -> Result<ConfidenceContext, ThreatPredictionError> {
    let evidence_ids = evidence_ids.iter().collect::<BTreeSet<_>>();
    let mut sources = BTreeSet::new();
    let mut stale_sources = BTreeSet::new();
    for event in input.events {
        if event.node_id != input.node_id || !evidence_ids.contains(&event.event_id) {
            continue;
        }
        event.validate_at(input.evaluated_at_ms)?;
        sources.insert(event.source);
        if input.evaluated_at_ms.saturating_sub(event.observed_at_ms) > 30 * MINUTE_MS {
            stale_sources.insert(event.source);
        }
    }
    Ok(ConfidenceContext {
        contributing_sources: sources.into_iter().collect(),
        stale_sources: u32::try_from(stale_sources.len()).unwrap_or(u32::MAX),
        missing_sources: u32::from(evidence_ids.is_empty()),
        history_sufficient: input
            .temporal_features
            .windows
            .get(&1_440)
            .is_some_and(|window| window.event_count > 0),
        source_health_degraded: false,
        topology_complete: true,
        geo_feed_available: true,
        calibration_matches_model: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat_prediction::{
        EventSeverity, EvidenceSource, TemporalWindowFeatures, TimeOfDayBaseline,
        SECURITY_EVENT_SCHEMA_VERSION,
    };
    use std::collections::BTreeMap;

    const REFERENCE: u64 = 10_000_000;

    fn features() -> TemporalFeatures {
        let empty_window = |minutes| TemporalWindowFeatures {
            window_minutes: minutes,
            event_count: 0,
            event_rate_per_minute: 0.0,
            alert_rate_per_minute: 0.0,
            critical_alert_rate_per_minute: 0.0,
            connection_rate_per_minute: 0.0,
            connection_rate_delta_per_minute: 0.0,
            unique_source_count: 0,
            unique_destination_count: 0,
            unique_destination_port_count: 0,
            failed_auth_rate_per_minute: 0.0,
            scan_velocity_per_minute: 0.0,
            traffic_bytes_rate_per_minute: 0.0,
            traffic_growth_rate_per_minute: 0.0,
            anomaly_score_mean: None,
            anomaly_score_max: None,
            attestation_failure_rate_per_minute: 0.0,
            peer_trust_failure_rate_per_minute: 0.0,
            policy_change_rate_per_minute: 0.0,
            network_degradation_rate_per_minute: 0.0,
            network_degradation_probability_max: None,
            new_device_rate_per_minute: 0.0,
            new_open_port_rate_per_minute: 0.0,
            vulnerable_service_count: 0,
        };
        TemporalFeatures {
            reference_time_ms: REFERENCE,
            history_start_ms: 0,
            history_event_count: 0,
            windows: [5, 15, 30, 60, 120, 360, 1_440]
                .into_iter()
                .map(|minutes| (minutes, empty_window(minutes)))
                .collect(),
            time_of_day: TimeOfDayBaseline {
                hour_of_day: 0,
                day_of_week: 0,
                weekday: true,
                current_window_rate_per_minute: 0.0,
                same_hour_historical_mean: 0.0,
                same_hour_historical_stddev: 0.0,
                seasonal_deviation_score: 0.0,
            },
        }
    }

    fn event(id: &str, event_type: SecurityEventType) -> SecurityEvent {
        SecurityEvent {
            schema_version: SECURITY_EVENT_SCHEMA_VERSION,
            event_id: id.to_string(),
            observed_at_ms: REFERENCE - MINUTE_MS,
            source: EvidenceSource::Suricata,
            node_id: "nodeB".to_string(),
            peer_id: None,
            source_ip: Some("10.0.0.99".to_string()),
            destination_ip: Some("10.0.0.20".to_string()),
            source_port: None,
            destination_port: Some(443),
            event_type,
            severity: EventSeverity::High,
            confidence: 0.9,
            attributes: BTreeMap::new(),
        }
    }

    fn predict(
        predictor: &impl ThreatPredictor,
        features: &TemporalFeatures,
        events: &[SecurityEvent],
    ) -> Option<ThreatForecast> {
        let config = ThreatPredictionConfig::default();
        predict_with(predictor, features, events, None, &config).unwrap()
    }

    fn predict_with(
        predictor: &(impl ThreatPredictor + ?Sized),
        features: &TemporalFeatures,
        events: &[SecurityEvent],
        precursor_sequence: Option<&PrecursorSequenceMatch>,
        config: &ThreatPredictionConfig,
    ) -> Result<Option<ThreatForecast>, ThreatPredictionError> {
        predictor.predict(&ThreatPredictorInput {
            node_id: "nodeB",
            evaluated_at_ms: REFERENCE,
            temporal_features: features,
            events,
            precursor_sequence,
            config,
        })
    }

    fn assert_forecast_contract(
        forecast: &ThreatForecast,
        threat_type: PredictedThreatType,
        horizon_minutes: u64,
        evidence_id: &str,
    ) {
        assert_eq!(forecast.threat_type, threat_type);
        assert_eq!(forecast.target_nodes, vec!["nodeB"]);
        assert_eq!(forecast.generated_at_ms, REFERENCE);
        assert_eq!(forecast.horizon_start_ms, REFERENCE);
        assert_eq!(
            forecast.horizon_end_ms - forecast.horizon_start_ms,
            horizon_minutes * MINUTE_MS
        );
        assert!(forecast.probability.is_finite() && (0.0..=1.0).contains(&forecast.probability));
        assert!(forecast.confidence.is_finite() && (0.0..=1.0).contains(&forecast.confidence));
        assert!(forecast.evidence_ids.iter().any(|id| id == evidence_id));
        assert!(!forecast.explanation.top_factors.is_empty());
        forecast.validate().unwrap();
    }

    #[test]
    fn ddos_predictor_has_positive_negative_and_deterministic_fixtures() {
        let mut positive = features();
        let window = positive.windows.get_mut(&5).unwrap();
        window.traffic_growth_rate_per_minute = 1.0;
        window.connection_rate_delta_per_minute = 1.0;
        window.unique_source_count = 3;
        window.anomaly_score_max = Some(0.9);
        let events = vec![event("ddos-1", SecurityEventType::TrafficAnomaly)];
        let first = predict(&DdosPredictor, &positive, &events).unwrap();
        assert_forecast_contract(&first, PredictedThreatType::Ddos, 5, "ddos-1");
        assert_eq!(
            Some(first.clone()),
            predict(&DdosPredictor, &positive, &events)
        );
        assert_eq!(None, predict(&DdosPredictor, &features(), &events));
    }

    #[test]
    fn recon_predictor_has_positive_and_negative_fixtures() {
        let mut positive = features();
        let window = positive.windows.get_mut(&30).unwrap();
        window.scan_velocity_per_minute = 1.0;
        window.unique_destination_port_count = 2;
        window.anomaly_score_max = Some(0.8);
        let events = vec![event("recon-1", SecurityEventType::Reconnaissance)];
        let first = predict(&ReconEscalationPredictor, &positive, &events).unwrap();
        assert_forecast_contract(
            &first,
            PredictedThreatType::ReconnaissanceEscalation,
            30,
            "recon-1",
        );
        assert_eq!(
            Some(first),
            predict(&ReconEscalationPredictor, &positive, &events)
        );
        assert_eq!(
            None,
            predict(&ReconEscalationPredictor, &features(), &events)
        );
    }

    #[test]
    fn brute_force_predictor_has_positive_and_negative_fixtures() {
        let mut positive = features();
        positive
            .windows
            .get_mut(&15)
            .unwrap()
            .failed_auth_rate_per_minute = 0.3;
        let events = vec![event("auth-1", SecurityEventType::AuthenticationFailure)];
        let first = predict(&BruteForcePredictor, &positive, &events).unwrap();
        assert_forecast_contract(&first, PredictedThreatType::BruteForce, 10, "auth-1");
        assert_eq!(
            Some(first),
            predict(&BruteForcePredictor, &positive, &events)
        );
        assert_eq!(None, predict(&BruteForcePredictor, &features(), &events));
    }

    #[test]
    fn exploitation_predictor_has_positive_and_negative_fixtures() {
        let mut positive = features();
        let window = positive.windows.get_mut(&30).unwrap();
        window.vulnerable_service_count = 1;
        window.new_open_port_rate_per_minute = 0.1;
        let events = vec![event("exposure-1", SecurityEventType::ExposureDiscovery)];
        let first = predict(&ExploitationPredictor, &positive, &events).unwrap();
        assert_forecast_contract(
            &first,
            PredictedThreatType::ExploitationAttempt,
            30,
            "exposure-1",
        );
        assert_eq!(
            Some(first),
            predict(&ExploitationPredictor, &positive, &events)
        );
        assert_eq!(None, predict(&ExploitationPredictor, &features(), &events));
    }

    #[test]
    fn protocol_predictor_has_positive_and_negative_fixtures() {
        let mut positive = features();
        positive.windows.get_mut(&15).unwrap().anomaly_score_max = Some(0.8);
        let events = vec![event("protocol-1", SecurityEventType::ProtocolViolation)];
        let first = predict(&ProtocolAbusePredictor, &positive, &events).unwrap();
        assert_forecast_contract(&first, PredictedThreatType::ProtocolAbuse, 15, "protocol-1");
        assert_eq!(
            Some(first),
            predict(&ProtocolAbusePredictor, &positive, &events)
        );
        assert_eq!(None, predict(&ProtocolAbusePredictor, &features(), &events));
    }

    #[test]
    fn predictors_do_not_emit_horizons_disabled_by_configuration() {
        let cases: Vec<(
            Box<dyn ThreatPredictor>,
            PredictedThreatType,
            TemporalFeatures,
            Vec<SecurityEvent>,
            u32,
        )> = vec![
            (
                Box::new(DdosPredictor),
                PredictedThreatType::Ddos,
                {
                    let mut value = features();
                    let window = value.windows.get_mut(&5).unwrap();
                    window.traffic_growth_rate_per_minute = 1.0;
                    window.connection_rate_delta_per_minute = 1.0;
                    window.unique_source_count = 3;
                    value
                },
                vec![event("disabled-ddos", SecurityEventType::TrafficAnomaly)],
                30,
            ),
            (
                Box::new(ReconEscalationPredictor),
                PredictedThreatType::ReconnaissanceEscalation,
                {
                    let mut value = features();
                    let window = value.windows.get_mut(&30).unwrap();
                    window.scan_velocity_per_minute = 1.0;
                    window.unique_destination_port_count = 2;
                    window.anomaly_score_max = Some(0.8);
                    value
                },
                vec![event("disabled-recon", SecurityEventType::Reconnaissance)],
                10,
            ),
            (
                Box::new(BruteForcePredictor),
                PredictedThreatType::BruteForce,
                {
                    let mut value = features();
                    value
                        .windows
                        .get_mut(&15)
                        .unwrap()
                        .failed_auth_rate_per_minute = 0.3;
                    value
                },
                vec![event(
                    "disabled-auth",
                    SecurityEventType::AuthenticationFailure,
                )],
                30,
            ),
            (
                Box::new(ExploitationPredictor),
                PredictedThreatType::ExploitationAttempt,
                {
                    let mut value = features();
                    let window = value.windows.get_mut(&30).unwrap();
                    window.vulnerable_service_count = 1;
                    window.new_open_port_rate_per_minute = 0.1;
                    value
                },
                vec![event(
                    "disabled-exploit",
                    SecurityEventType::ExposureDiscovery,
                )],
                10,
            ),
            (
                Box::new(ProtocolAbusePredictor),
                PredictedThreatType::ProtocolAbuse,
                {
                    let mut value = features();
                    value.windows.get_mut(&15).unwrap().anomaly_score_max = Some(0.8);
                    value
                },
                vec![event(
                    "disabled-protocol",
                    SecurityEventType::ProtocolViolation,
                )],
                5,
            ),
        ];

        for (predictor, threat_type, features, events, enabled_horizon) in cases {
            let mut config = ThreatPredictionConfig::default();
            config
                .forecast_horizons_minutes
                .insert(threat_type, vec![enabled_horizon]);
            assert_eq!(
                None,
                predict_with(predictor.as_ref(), &features, &events, None, &config).unwrap(),
                "{threat_type:?} must not emit its disabled hardcoded horizon"
            );
        }
    }

    #[test]
    fn new_ddos_signals_are_evidence_based() {
        let mut value = features();
        let recent = value.windows.get_mut(&5).unwrap();
        recent.traffic_growth_rate_per_minute = 1.0;
        recent.connection_rate_delta_per_minute = 1.0;
        recent.unique_source_count = 3;
        value
            .windows
            .get_mut(&15)
            .unwrap()
            .traffic_growth_rate_per_minute = 1.0;
        value.time_of_day.seasonal_deviation_score = 0.7;
        let mut events = vec![event("ddos-1", SecurityEventType::TrafficAnomaly)];
        for index in 2..=3 {
            let mut repeated_target =
                event(&format!("ddos-{index}"), SecurityEventType::TrafficAnomaly);
            repeated_target.source_ip = Some(format!("10.0.0.{index}"));
            events.push(repeated_target);
        }
        let mut circle = event("circle-1", SecurityEventType::TrustDegradation);
        circle.source = EvidenceSource::CircleTrust;
        events.push(circle);
        let forecast = predict(&DdosPredictor, &value, &events).unwrap();
        let names: BTreeSet<_> = forecast
            .explanation
            .top_factors
            .iter()
            .map(|factor| factor.name.as_str())
            .collect();
        for factor in [
            "target_concentration",
            "time_of_day_deviation",
            "multi_window_persistence",
            "circle_observation",
        ] {
            assert!(names.contains(factor));
        }
    }

    #[test]
    fn recon_sequence_and_normalized_source_target_signals_affect_result() {
        let mut value = features();
        let window = value.windows.get_mut(&30).unwrap();
        window.scan_velocity_per_minute = 1.0;
        window.unique_destination_port_count = 2;
        let events = vec![event("recon-sequence", SecurityEventType::Reconnaissance)];
        assert_eq!(None, predict(&ReconEscalationPredictor, &value, &events));
        let sequence = PrecursorSequenceMatch {
            sequence_id: "recon-to-compromise-v1".to_string(),
            node_id: "nodeB".to_string(),
            evaluated_at_ms: REFERENCE,
            matched_steps: 6,
            total_steps: 6,
            score: 1.0,
            fresh: true,
            target_correlation_key: "10.0.0.20:443".to_string(),
            matched_event_ids: vec!["recon-sequence".to_string()],
            evidence_source_count: 2,
            repetition_count: 1,
        };
        let config = ThreatPredictionConfig::default();
        let forecast = predict_with(
            &ReconEscalationPredictor,
            &value,
            &events,
            Some(&sequence),
            &config,
        )
        .unwrap()
        .unwrap();
        assert!(forecast
            .explanation
            .top_factors
            .iter()
            .any(|factor| factor.name == "ordered_precursor_sequence"));
        assert_eq!(
            forecast.explanation.precursor_sequence_ids,
            vec!["recon-to-compromise-v1"]
        );

        let mut source_target_features = features();
        let window = source_target_features.windows.get_mut(&30).unwrap();
        window.scan_velocity_per_minute = 1.0;
        window.unique_destination_port_count = 2;
        window.anomaly_score_max = Some(0.8);
        let mut second_target = event("recon-second-target", SecurityEventType::PortDiscovery);
        second_target.destination_ip = Some("10.0.0.21".to_string());
        second_target.peer_id = Some("nodeC".to_string());
        let source_target_forecast = predict(
            &ReconEscalationPredictor,
            &source_target_features,
            &[
                event("recon-first-target", SecurityEventType::Reconnaissance),
                second_target,
            ],
        )
        .unwrap();
        for name in ["repeated_source", "multi_peer_or_target"] {
            assert!(source_target_forecast
                .explanation
                .top_factors
                .iter()
                .any(|factor| factor.name == name));
        }
    }

    #[test]
    fn brute_exploitation_and_protocol_extra_signals_are_tested() {
        let mut brute_features = features();
        brute_features
            .windows
            .get_mut(&15)
            .unwrap()
            .failed_auth_rate_per_minute = 0.3;
        let mut auth_two = event("auth-2", SecurityEventType::AuthenticationFailure);
        auth_two.observed_at_ms -= 1;
        let brute = predict(
            &BruteForcePredictor,
            &brute_features,
            &[
                event("auth-1", SecurityEventType::AuthenticationFailure),
                auth_two,
            ],
        )
        .unwrap();
        assert!(brute
            .explanation
            .top_factors
            .iter()
            .any(|factor| factor.name == "source_repetition"));
        assert!(brute
            .explanation
            .top_factors
            .iter()
            .any(|factor| factor.name == "suricata_authentication_evidence"));

        let mut exploit_features = features();
        let exposure = exploit_features.windows.get_mut(&30).unwrap();
        exposure.vulnerable_service_count = 1;
        exposure.new_open_port_rate_per_minute = 0.1;
        exploit_features
            .windows
            .get_mut(&15)
            .unwrap()
            .failed_auth_rate_per_minute = 0.3;
        let mut exposure_one = event("exposure-1", SecurityEventType::ExposureDiscovery);
        exposure_one
            .attributes
            .insert("ids_exploit_alert".to_string(), "true".to_string());
        let mut exposure_two = exposure_one.clone();
        exposure_two.event_id = "exposure-2".to_string();
        exposure_two.observed_at_ms -= 1;
        let exploit = predict(
            &ExploitationPredictor,
            &exploit_features,
            &[exposure_one, exposure_two],
        )
        .unwrap();
        for name in [
            "failed_authentication_trend",
            "ids_exploit_evidence",
            "source_repetition",
        ] {
            assert!(exploit
                .explanation
                .top_factors
                .iter()
                .any(|factor| factor.name == name));
        }

        let mut protocol = event("protocol-metric", SecurityEventType::ProtocolViolation);
        protocol
            .attributes
            .insert("invalid_message_count".to_string(), "5".to_string());
        let forecast = predict(&ProtocolAbusePredictor, &features(), &[protocol]).unwrap();
        assert!(forecast
            .explanation
            .top_factors
            .iter()
            .any(|factor| factor.name == "invalid_message_rate"));
        assert_eq!(
            None,
            predict(
                &ProtocolAbusePredictor,
                &features(),
                &[event(
                    "protocol-without-metric",
                    SecurityEventType::ProtocolViolation
                )]
            )
        );
    }

    #[test]
    fn predictor_input_failures_are_safe() {
        let mut malformed = event("bad", SecurityEventType::TrafficAnomaly);
        malformed.event_id.clear();
        assert!(matches!(
            predict_with(
                &DdosPredictor,
                &features(),
                &[malformed],
                None,
                &ThreatPredictionConfig::default(),
            ),
            Err(ThreatPredictionError::MalformedEvent(_))
        ));

        let mut missing_window = features();
        missing_window.windows.remove(&5);
        assert!(matches!(
            predict_with(
                &DdosPredictor,
                &missing_window,
                &[event("missing-window", SecurityEventType::TrafficAnomaly)],
                None,
                &ThreatPredictionConfig::default(),
            ),
            Err(ThreatPredictionError::InvalidConfig(_))
        ));

        let mut wrong_time = features();
        wrong_time.reference_time_ms += 1;
        assert!(matches!(
            predict_with(
                &DdosPredictor,
                &wrong_time,
                &[event("wrong-time", SecurityEventType::TrafficAnomaly)],
                None,
                &ThreatPredictionConfig::default(),
            ),
            Err(ThreatPredictionError::InvalidConfig(_))
        ));

        let mut invalid_config = ThreatPredictionConfig::default();
        invalid_config.forecast_interval_minutes = 4;
        assert!(matches!(
            predict_with(
                &DdosPredictor,
                &features(),
                &[event("invalid-config", SecurityEventType::TrafficAnomaly)],
                None,
                &invalid_config,
            ),
            Err(ThreatPredictionError::InvalidConfig(_))
        ));
    }

    #[test]
    fn d6_uses_central_d8_confidence_and_configured_calibration_deterministically() {
        let mut positive = features();
        let window = positive.windows.get_mut(&5).unwrap();
        window.traffic_growth_rate_per_minute = 1.0;
        window.connection_rate_delta_per_minute = 1.0;
        window.unique_source_count = 3;
        window.anomaly_score_max = Some(0.9);
        let events = vec![event("d8-integrated", SecurityEventType::TrafficAnomaly)];
        let mut config = ThreatPredictionConfig::default();
        config.probability_calibration.points[1].calibrated_probability = 0.80;
        config.probability_calibration.validate().unwrap();

        let first = predict_with(&DdosPredictor, &positive, &events, None, &config)
            .unwrap()
            .unwrap();
        let second = predict_with(&DdosPredictor, &positive, &events, None, &config)
            .unwrap()
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.probability, 0.80);
        assert_eq!(first.confidence, 0.66);
        assert_eq!(
            first
                .explanation
                .calibration
                .as_ref()
                .unwrap()
                .calibration_version,
            config.probability_calibration.metadata.calibration_version
        );

        let mut unavailable = config;
        unavailable.probability_calibration.metadata.model_version = "missing-model".into();
        assert!(matches!(
            predict_with(&DdosPredictor, &positive, &events, None, &unavailable),
            Err(ThreatPredictionError::InvalidConfig(_))
        ));
    }
}
