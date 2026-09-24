//! Task 4 Deliverable 7: explainable peer-risk cascade prediction.
use super::{
    EvidenceSource, ForecastExplanation, ForecastFactor, ForecastStatus, PredictedThreatType,
    SecurityEvent, ThreatForecast, ThreatPredictionConfig, ThreatPredictionError,
    THREAT_FORECAST_SCHEMA_VERSION,
};

const MINUTE_MS: u64 = 60_000;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PeerRelationship {
    pub relationship_id: String,
    pub provenance: String,
    pub reasons: Vec<String>,
    pub observed_at_ms: u64,
    pub expires_at_ms: u64,
    pub source_node: String,
    pub target_node: String,
    pub same_segment: bool,
    pub recent_direct_communication: bool,
    pub shared_service_or_relay: bool,
    pub topology_dependency: bool,
    pub relevant_exposed_port: bool,
}

impl PeerRelationship {
    pub fn validate_at(&self, evaluated_at_ms: u64) -> Result<(), ThreatPredictionError> {
        if self.relationship_id.trim().is_empty()
            || self.relationship_id.len() > 160
            || self.provenance.len() > 160
            || self.source_node.len() > 128
            || self.target_node.len() > 128
            || self.provenance.trim().is_empty()
            || self.source_node.trim().is_empty()
            || self.target_node.trim().is_empty()
            || self.reasons.is_empty()
            || self.observed_at_ms == 0
            || self.observed_at_ms > evaluated_at_ms
            || self.expires_at_ms <= self.observed_at_ms
            || self.expires_at_ms < evaluated_at_ms
        {
            return Err(ThreatPredictionError::InvalidConfig(
                "invalid, missing, or stale peer relationship evidence".into(),
            ));
        }
        if self.reasons.len() > 8
            || self
                .reasons
                .iter()
                .any(|reason| reason.trim().is_empty() || reason.len() > 160)
        {
            return Err(ThreatPredictionError::InvalidConfig(
                "peer relationship reasons must be bounded non-empty text".into(),
            ));
        }
        Ok(())
    }
    pub fn strength(&self) -> f64 {
        [
            self.same_segment,
            self.recent_direct_communication,
            self.shared_service_or_relay,
            self.topology_dependency,
            self.relevant_exposed_port,
        ]
        .into_iter()
        .filter(|present| *present)
        .count() as f64
            / 5.0
    }
}

pub fn predict_peer_cascade(
    source_compromise_probability: f64,
    relationship: &PeerRelationship,
    events: &[SecurityEvent],
    evaluated_at_ms: u64,
    config: &ThreatPredictionConfig,
) -> Result<Option<ThreatForecast>, ThreatPredictionError> {
    config.validate()?;
    relationship.validate_at(evaluated_at_ms)?;
    if !source_compromise_probability.is_finite()
        || !(0.0..=1.0).contains(&source_compromise_probability)
    {
        return Err(ThreatPredictionError::InvalidProbability(
            "source cascade probability must be within [0,1]".into(),
        ));
    }
    let horizon = 15_u32;
    if !config.forecast_horizons_minutes[&PredictedThreatType::PeerCompromiseCascade]
        .contains(&horizon)
    {
        return Ok(None);
    }
    let relationship_strength = relationship.strength();
    if relationship_strength == 0.0 {
        return Ok(None);
    }
    let mut evidence_ids = Vec::new();
    let mut task1_or_suricata = false;
    let mut trust_degraded = false;
    for event in events {
        if event.node_id != relationship.target_node
            || event.observed_at_ms > evaluated_at_ms
            || event.observed_at_ms + 30 * MINUTE_MS < evaluated_at_ms
        {
            continue;
        }
        event.validate()?;
        if matches!(
            event.source,
            EvidenceSource::Task1Anomaly | EvidenceSource::Suricata
        ) {
            task1_or_suricata = true;
            evidence_ids.push(event.event_id.clone());
        }
        if event.source == EvidenceSource::CircleTrust {
            trust_degraded = true;
            evidence_ids.push(event.event_id.clone());
        }
    }
    // CircleTrust is strengthening evidence only, never independent propagation.
    if !task1_or_suricata {
        return Ok(None);
    }
    evidence_ids.sort();
    evidence_ids.dedup();
    let exposure = if relationship.relevant_exposed_port {
        0.9
    } else {
        0.7
    };
    let newest_evidence = events
        .iter()
        .filter(|event| {
            event.node_id == relationship.target_node && event.observed_at_ms <= evaluated_at_ms
        })
        .map(|event| event.observed_at_ms)
        .max()
        .unwrap_or(0);
    let age_ms = evaluated_at_ms.saturating_sub(newest_evidence.max(relationship.observed_at_ms));
    let freshness = (1.0 - age_ms as f64 / (30.0 * MINUTE_MS as f64)).clamp(0.0, 1.0);
    let trust = if trust_degraded { 0.9 } else { 0.7 };
    // D7 cascade risk combines source compromise likelihood with the
    // independently verified relationship strength. Relationship strength
    // remains mandatory (zero-strength relationships are rejected above),
    // while real target Task1/Suricata evidence is also required.
    //
    // Do not multiply relationship strength directly into the entire score:
    // a valid DirectP2P relationship has strength 0.4 and could otherwise
    // never reach the 0.30 emission threshold, even with a fully compromised
    // source and fresh target evidence.
    let propagation_factor = 0.5 + (0.5 * relationship_strength);

    let probability =
        (source_compromise_probability * propagation_factor * exposure * freshness * trust)
            .min(1.0);

    if probability < 0.30 {
        return Ok(None);
    }
    let confidence = (0.45
        + relationship_strength * 0.25
        + if task1_or_suricata { 0.15 } else { 0.0 }
        + if trust_degraded { 0.10 } else { 0.0 })
    .min(0.90);
    let mut factors = vec![ForecastFactor {
        name: "relationship_strength".into(),
        contribution: relationship_strength,
        evidence_ids: evidence_ids.clone(),
    }];
    if task1_or_suricata {
        factors.push(ForecastFactor {
            name: "task1_or_suricata_evidence".into(),
            contribution: 0.15,
            evidence_ids: evidence_ids.clone(),
        });
    }
    if trust_degraded {
        factors.push(ForecastFactor {
            name: "trust_degradation".into(),
            contribution: 0.10,
            evidence_ids: evidence_ids.clone(),
        });
    }
    let forecast = ThreatForecast {
        schema_version: THREAT_FORECAST_SCHEMA_VERSION.into(),
        forecast_id: format!(
            "task4-d7-cascade-{}-{}",
            relationship.target_node, evaluated_at_ms
        ),
        model_version: "task4-d7-cascade-v1".into(),
        generated_at_ms: evaluated_at_ms,
        horizon_start_ms: evaluated_at_ms,
        horizon_end_ms: evaluated_at_ms + u64::from(horizon) * MINUTE_MS,
        threat_type: PredictedThreatType::PeerCompromiseCascade,
        target_nodes: vec![relationship.target_node.clone()],
        probability,
        confidence,
        severity: config.thresholds.severity_for(probability),
        evidence_ids: evidence_ids.clone(),
        feature_snapshot_id: format!("task4-cascade-{}", relationship.target_node),
        explanation: ForecastExplanation {
            summary:
                "Related peer has elevated cascade risk; this is not a compromise declaration."
                    .into(),
            top_factors: {
                factors.push(ForecastFactor {
                    name: format!("relationship:{}", relationship.relationship_id),
                    contribution: relationship_strength,
                    evidence_ids: evidence_ids.clone(),
                });
                factors
            },
            precursor_sequence_ids: Vec::new(),
            missing_evidence: Vec::new(),
            relationship_reasons: relationship.reasons.clone(),
            calibration: None,
        },
        status: ForecastStatus::Active,
    };
    forecast.validate()?;
    Ok(Some(forecast))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat_prediction::{
        EventSeverity, SecurityEventType, SECURITY_EVENT_SCHEMA_VERSION,
    };
    use std::collections::BTreeMap;
    fn event(id: &str, source: EvidenceSource) -> SecurityEvent {
        SecurityEvent {
            schema_version: SECURITY_EVENT_SCHEMA_VERSION,
            event_id: id.into(),
            observed_at_ms: 1_000,
            source,
            node_id: "nodeB".into(),
            peer_id: Some("nodeA".into()),
            source_ip: None,
            destination_ip: None,
            source_port: None,
            destination_port: None,
            event_type: SecurityEventType::TrustDegradation,
            severity: EventSeverity::High,
            confidence: 0.9,
            attributes: BTreeMap::new(),
        }
    }
    fn related() -> PeerRelationship {
        PeerRelationship {
            relationship_id: "rel-a-b".into(),
            provenance: "sample-topology".into(),
            reasons: vec!["same_segment".into()],
            observed_at_ms: 900,
            expires_at_ms: 31 * MINUTE_MS,
            source_node: "nodeA".into(),
            target_node: "nodeB".into(),
            same_segment: true,
            recent_direct_communication: true,
            shared_service_or_relay: true,
            topology_dependency: true,
            relevant_exposed_port: true,
        }
    }
    #[test]
    fn related_peer_receives_explainable_risk_and_is_not_declared_compromised() {
        let out = predict_peer_cascade(
            0.95,
            &related(),
            &[
                event("task1", EvidenceSource::Task1Anomaly),
                event("trust", EvidenceSource::CircleTrust),
            ],
            1_100,
            &ThreatPredictionConfig::default(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(out.threat_type, PredictedThreatType::PeerCompromiseCascade);
        assert_eq!(out.target_nodes, vec!["nodeB"]);
        assert!(out.probability > 0.5);
        assert!(out
            .explanation
            .summary
            .contains("not a compromise declaration"));
        assert_eq!(out.status, ForecastStatus::Active);
    }
    #[test]
    fn circle_membership_or_unrelated_peer_does_not_propagate() {
        let unrelated = PeerRelationship {
            relationship_id: "rel-none".into(),
            provenance: "sample-topology".into(),
            reasons: vec!["circle_membership_only".into()],
            observed_at_ms: 900,
            expires_at_ms: 31 * MINUTE_MS,
            source_node: "nodeA".into(),
            target_node: "nodeB".into(),
            same_segment: false,
            recent_direct_communication: false,
            shared_service_or_relay: false,
            topology_dependency: false,
            relevant_exposed_port: false,
        };
        assert_eq!(
            predict_peer_cascade(
                0.95,
                &unrelated,
                &[event("task1", EvidenceSource::Task1Anomaly)],
                1_100,
                &ThreatPredictionConfig::default()
            )
            .unwrap(),
            None
        );
    }
    #[test]
    fn cascade_contract_handles_trust_freshness_replays_config_and_invalid_input() {
        let config = ThreatPredictionConfig::default();
        let threat = event("task1", EvidenceSource::Task1Anomaly);
        let trust = event("trust", EvidenceSource::CircleTrust);
        let base = predict_peer_cascade(0.95, &related(), &[threat.clone()], 1_100, &config)
            .unwrap()
            .unwrap();
        let strengthened = predict_peer_cascade(
            0.95,
            &related(),
            &[threat.clone(), trust.clone()],
            1_100,
            &config,
        )
        .unwrap()
        .unwrap();
        assert!(strengthened.confidence > base.confidence);
        assert!(strengthened.probability > base.probability);
        assert_eq!(
            predict_peer_cascade(0.95, &related(), &[trust.clone()], 1_100, &config).unwrap(),
            None
        );
        assert!(strengthened.evidence_ids.contains(&"task1".to_string()));
        assert_eq!(
            strengthened.explanation.relationship_reasons,
            vec!["same_segment"]
        );
        assert_eq!(
            strengthened,
            predict_peer_cascade(
                0.95,
                &related(),
                &[threat.clone(), trust.clone(), threat.clone()],
                1_100,
                &config
            )
            .unwrap()
            .unwrap()
        );
        assert!(
            strengthened.probability.is_finite() && (0.0..=1.0).contains(&strengthened.probability)
        );
        assert!(
            strengthened.confidence.is_finite() && (0.0..=1.0).contains(&strengthened.confidence)
        );
        let mut future = threat.clone();
        future.observed_at_ms = 1_101;
        assert_eq!(
            predict_peer_cascade(0.95, &related(), &[future], 1_100, &config).unwrap(),
            None
        );
        let mut future_relationship = related();
        future_relationship.observed_at_ms = 1_101;
        future_relationship.expires_at_ms = 31 * MINUTE_MS;
        assert!(predict_peer_cascade(
            0.95,
            &future_relationship,
            &[threat.clone()],
            1_100,
            &config
        )
        .is_err());
        let mut stale_relationship = related();
        stale_relationship.expires_at_ms = 1_099;
        assert!(
            predict_peer_cascade(0.95, &stale_relationship, &[threat.clone()], 1_100, &config)
                .is_err()
        );
        let mut stale_event = threat.clone();
        stale_event.observed_at_ms = 1;
        let mut current_relationship = related();
        current_relationship.expires_at_ms = 40 * MINUTE_MS;
        assert_eq!(
            predict_peer_cascade(
                0.95,
                &current_relationship,
                &[stale_event],
                31 * MINUTE_MS,
                &config
            )
            .unwrap(),
            None
        );
        let mut disabled = config.clone();
        disabled
            .forecast_horizons_minutes
            .insert(PredictedThreatType::PeerCompromiseCascade, vec![30]);
        assert_eq!(
            predict_peer_cascade(0.95, &related(), &[threat.clone()], 1_100, &disabled).unwrap(),
            None
        );
        let mut malformed_relationship = related();
        malformed_relationship.relationship_id.clear();
        assert!(predict_peer_cascade(
            0.95,
            &malformed_relationship,
            &[threat.clone()],
            1_100,
            &config
        )
        .is_err());
        let mut malformed_event = threat;
        malformed_event.event_id.clear();
        assert!(
            predict_peer_cascade(0.95, &related(), &[malformed_event], 1_100, &config).is_err()
        );
        let round_trip: PeerRelationship =
            serde_json::from_str(&serde_json::to_string(&related()).unwrap()).unwrap();
        assert_eq!(round_trip, related());
    }
}
