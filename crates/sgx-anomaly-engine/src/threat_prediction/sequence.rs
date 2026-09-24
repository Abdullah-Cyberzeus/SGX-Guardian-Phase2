//! Task 4 Deliverable 5: deterministic ordered precursor-chain matching.

use super::{
    EventSeverity, EvidenceSource, SecurityEvent, SecurityEventType, ThreatPredictionError,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MINUTE_MS: u64 = 60_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrecursorSequenceDefinition {
    pub sequence_id: String,
    pub steps: Vec<SecurityEventType>,
    pub max_event_gap_minutes: u32,
    pub max_sequence_age_minutes: u32,
    pub minimum_severity: EventSeverity,
}

impl PrecursorSequenceDefinition {
    pub fn validate(&self) -> Result<(), ThreatPredictionError> {
        if self.sequence_id.trim().is_empty() || self.steps.len() < 2 {
            return Err(ThreatPredictionError::InvalidConfig(
                "a precursor sequence needs an ID and at least two ordered steps".to_string(),
            ));
        }
        if self.max_event_gap_minutes == 0 || self.max_sequence_age_minutes == 0 {
            return Err(ThreatPredictionError::InvalidConfig(
                "precursor sequence gaps and freshness must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }

    pub fn recon_to_compromise() -> Self {
        Self {
            sequence_id: "recon-to-compromise-v1".to_string(),
            steps: vec![
                SecurityEventType::Reconnaissance,
                SecurityEventType::PortDiscovery,
                SecurityEventType::ExposureDiscovery,
                SecurityEventType::AuthenticationFailure,
                SecurityEventType::ProtocolViolation,
                SecurityEventType::TrafficAnomaly,
            ],
            max_event_gap_minutes: 10,
            max_sequence_age_minutes: 30,
            minimum_severity: EventSeverity::Medium,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrecursorSequenceMatch {
    pub sequence_id: String,
    pub node_id: String,
    pub evaluated_at_ms: u64,
    pub matched_steps: usize,
    pub total_steps: usize,
    pub score: f64,
    pub fresh: bool,
    pub target_correlation_key: String,
    pub matched_event_ids: Vec<String>,
    pub evidence_source_count: usize,
    pub repetition_count: usize,
}

/// Match ordered source events without inferring new events or changing their
/// classification. Callers supply a fixed evaluation time for repeatability.
pub fn match_precursor_sequence(
    definition: &PrecursorSequenceDefinition,
    node_id: &str,
    events: &[SecurityEvent],
    evaluated_at_ms: u64,
) -> Result<PrecursorSequenceMatch, ThreatPredictionError> {
    definition.validate()?;
    let freshness_start =
        evaluated_at_ms.saturating_sub(u64::from(definition.max_sequence_age_minutes) * MINUTE_MS);
    let mut unique_candidates: BTreeMap<String, &SecurityEvent> = BTreeMap::new();
    for event in events {
        // Future source evidence is deliberately ignored for a fixed-time
        // evaluation. Historical evidence must satisfy the shared canonical
        // SecurityEvent contract before it can influence a sequence.
        if event.observed_at_ms > evaluated_at_ms {
            continue;
        }
        event.validate()?;
        if event.node_id != node_id || event.observed_at_ms < freshness_start {
            continue;
        }

        let deduplication_key = event.deduplication_key();
        match unique_candidates.get(&deduplication_key) {
            Some(existing) if existing.event_id <= event.event_id => {}
            _ => {
                unique_candidates.insert(deduplication_key, event);
            }
        }
    }
    let mut candidates: Vec<&SecurityEvent> = unique_candidates.into_values().collect();
    candidates.sort_by(|left, right| {
        left.observed_at_ms
            .cmp(&right.observed_at_ms)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });

    let mut matched: Vec<&SecurityEvent> = Vec::new();
    let mut next_step = 0;
    let mut target_key: Option<String> = None;
    let mut source_key: Option<String> = None;
    let max_gap_ms = u64::from(definition.max_event_gap_minutes) * MINUTE_MS;
    for event in candidates {
        if next_step == definition.steps.len()
            || event.event_type != definition.steps[next_step]
            || event.severity < definition.minimum_severity
        {
            continue;
        }
        if let Some(previous) = matched.last() {
            if event.observed_at_ms.saturating_sub(previous.observed_at_ms) > max_gap_ms {
                continue;
            }
        }
        // Cross-source Task4 evidence does not always carry the same
        // addressing detail. Bind only when an explicit destination host
        // is present. Missing destination identity is non-binding.
        if let Some(event_target) = target_correlation_key(event) {
            if let Some(expected_target) = &target_key {
                if expected_target != &event_target {
                    continue;
                }
            } else {
                target_key = Some(event_target);
            }
        }
        // Source correlation is strict when the source adapter actually
        // provides an attributable source IP. Some production evidence
        // sources (for example Guardian-owned NMAP discovery and Task1
        // anomaly records) do not carry an attacker/source IP. Missing
        // attribution must not be converted into a synthetic node identity,
        // otherwise heterogeneous evidence can never truthfully correlate.
        if let Some(event_source) = source_correlation_key(event) {
            if let Some(expected_source) = &source_key {
                if expected_source != &event_source {
                    continue;
                }
            } else {
                source_key = Some(event_source);
            }
        }
        matched.push(event);
        next_step += 1;
    }

    let matched_steps = matched.len();
    let total_steps = definition.steps.len();
    let sources: BTreeSet<EvidenceSource> = matched.iter().map(|event| event.source).collect();
    let repetitions = matched
        .iter()
        .filter(|event| event.event_type == definition.steps.first().copied().unwrap())
        .count();
    // Score rewards correct ordered progress and independent evidence sources.
    let progress = matched_steps as f64 / total_steps as f64;
    let diversity_bonus = (sources.len().min(3) as f64 / 3.0) * 0.15;
    let score = (progress * 0.85 + diversity_bonus).min(1.0);
    Ok(PrecursorSequenceMatch {
        sequence_id: definition.sequence_id.clone(),
        node_id: node_id.to_string(),
        evaluated_at_ms,
        matched_steps,
        total_steps,
        score,
        fresh: matched_steps == total_steps,
        target_correlation_key: target_key.unwrap_or_else(|| format!("node:{node_id}")),
        matched_event_ids: matched.iter().map(|event| event.event_id.clone()).collect(),
        evidence_source_count: sources.len(),
        repetition_count: repetitions,
    })
}

fn source_correlation_key(event: &SecurityEvent) -> Option<String> {
    event.source_ip.clone()
}

fn target_correlation_key(event: &SecurityEvent) -> Option<String> {
    // A precursor sequence identifies the destination host, not an
    // individual service/port. Cross-source evidence may omit destination
    // information; absence therefore remains non-binding instead of
    // fabricating a node/port identity.
    event.destination_ip.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat_prediction::{EventSeverity, SECURITY_EVENT_SCHEMA_VERSION};
    use std::collections::BTreeMap;

    fn event(id: &str, timestamp: u64, kind: SecurityEventType, target_port: u16) -> SecurityEvent {
        SecurityEvent {
            schema_version: SECURITY_EVENT_SCHEMA_VERSION,
            event_id: id.to_string(),
            observed_at_ms: timestamp,
            source: match kind {
                SecurityEventType::Reconnaissance => EvidenceSource::NmapDiscovery,
                SecurityEventType::PortDiscovery => EvidenceSource::Suricata,
                _ => EvidenceSource::Task1Anomaly,
            },
            node_id: "nodeB".to_string(),
            peer_id: None,
            source_ip: Some("10.0.0.99".to_string()),
            destination_ip: Some("10.0.0.20".to_string()),
            source_port: Some(45_000),
            destination_port: Some(target_port),
            event_type: kind,
            severity: EventSeverity::High,
            confidence: 0.8,
            attributes: BTreeMap::new(),
        }
    }

    fn ordered_events(reference: u64) -> Vec<SecurityEvent> {
        PrecursorSequenceDefinition::recon_to_compromise()
            .steps
            .iter()
            .enumerate()
            .map(|(index, kind)| {
                event(
                    &format!("event-{index}"),
                    reference - 6 * MINUTE_MS + index as u64 * MINUTE_MS,
                    *kind,
                    443,
                )
            })
            .collect()
    }

    #[test]
    fn correct_order_scores_higher_than_shuffled_order() {
        let reference = 24 * 60 * MINUTE_MS;
        let definition = PrecursorSequenceDefinition::recon_to_compromise();
        let ordered =
            match_precursor_sequence(&definition, "nodeB", &ordered_events(reference), reference)
                .unwrap();
        let mut shuffled = ordered_events(reference);
        let reversed_types: Vec<_> = shuffled
            .iter()
            .map(|event| event.event_type)
            .rev()
            .collect();
        for (event, kind) in shuffled.iter_mut().zip(reversed_types) {
            event.event_type = kind;
        }
        let shuffled =
            match_precursor_sequence(&definition, "nodeB", &shuffled, reference).unwrap();
        assert!(ordered.fresh);
        assert!(ordered.score > shuffled.score);
    }

    #[test]
    fn stale_sequences_expire_and_unrelated_targets_do_not_combine() {
        let reference = 24 * 60 * MINUTE_MS;
        let definition = PrecursorSequenceDefinition::recon_to_compromise();
        let stale: Vec<_> = ordered_events(reference)
            .into_iter()
            .map(|mut event| {
                event.observed_at_ms -= 31 * MINUTE_MS;
                event
            })
            .collect();
        assert_eq!(
            match_precursor_sequence(&definition, "nodeB", &stale, reference)
                .unwrap()
                .matched_steps,
            0
        );

        let mut unrelated = ordered_events(reference);
        unrelated[2].destination_ip = Some("10.0.0.21".to_string());
        let result = match_precursor_sequence(&definition, "nodeB", &unrelated, reference).unwrap();
        assert!(result.matched_steps < definition.steps.len());
    }

    #[test]
    fn node_and_source_correlation_mismatches_do_not_combine() {
        let reference = 24 * 60 * MINUTE_MS;
        let definition = PrecursorSequenceDefinition::recon_to_compromise();

        let mut another_node = ordered_events(reference);
        another_node[2].node_id = "nodeC".to_string();
        assert!(
            match_precursor_sequence(&definition, "nodeB", &another_node, reference)
                .unwrap()
                .matched_steps
                < definition.steps.len()
        );

        let mut another_source = ordered_events(reference);
        another_source[3].source_ip = Some("10.0.0.100".to_string());
        assert!(
            match_precursor_sequence(&definition, "nodeB", &another_source, reference)
                .unwrap()
                .matched_steps
                < definition.steps.len()
        );
    }

    #[test]
    fn event_gap_boundary_and_severity_are_enforced() {
        let reference = 24 * 60 * MINUTE_MS;
        let mut definition = PrecursorSequenceDefinition::recon_to_compromise();
        definition.steps.truncate(3);

        let mut boundary = ordered_events(reference);
        boundary.truncate(3);
        for (index, event) in boundary.iter_mut().enumerate() {
            event.observed_at_ms = reference - (2 - index as u64) * 10 * MINUTE_MS;
        }
        assert!(
            match_precursor_sequence(&definition, "nodeB", &boundary, reference)
                .unwrap()
                .fresh
        );

        let mut over_gap = boundary.clone();
        over_gap[0].observed_at_ms = reference - 21 * MINUTE_MS;
        assert!(
            !match_precursor_sequence(&definition, "nodeB", &over_gap, reference)
                .unwrap()
                .fresh
        );

        let mut low_severity = boundary;
        low_severity[1].severity = EventSeverity::Low;
        assert!(
            !match_precursor_sequence(&definition, "nodeB", &low_severity, reference)
                .unwrap()
                .fresh
        );
    }

    #[test]
    fn matched_ids_replays_and_fixed_time_results_are_safe_and_deterministic() {
        let reference = 24 * 60 * MINUTE_MS;
        let definition = PrecursorSequenceDefinition::recon_to_compromise();
        let events = ordered_events(reference);
        let first = match_precursor_sequence(&definition, "nodeB", &events, reference).unwrap();
        let repeated = match_precursor_sequence(&definition, "nodeB", &events, reference).unwrap();
        assert_eq!(first, repeated);
        assert_eq!(
            first.matched_event_ids,
            (0..definition.steps.len())
                .map(|index| format!("event-{index}"))
                .collect::<Vec<_>>()
        );

        let mut replayed = events.clone();
        replayed.extend(events.clone());
        let replay_result =
            match_precursor_sequence(&definition, "nodeB", &replayed, reference).unwrap();
        assert_eq!(replay_result.matched_steps, first.matched_steps);
        assert_eq!(replay_result.score, first.score);

        let mut without_last = events[..events.len() - 1].to_vec();
        let mut future_last = events.last().unwrap().clone();
        future_last.observed_at_ms = reference + MINUTE_MS;
        without_last.push(future_last);
        assert!(
            !match_precursor_sequence(&definition, "nodeB", &without_last, reference)
                .unwrap()
                .fresh
        );
    }

    #[test]
    fn malformed_historical_events_are_rejected_without_panic() {
        let reference = 24 * 60 * MINUTE_MS;
        let definition = PrecursorSequenceDefinition::recon_to_compromise();
        let mut malformed = ordered_events(reference);
        malformed[0].event_id.clear();
        assert!(matches!(
            match_precursor_sequence(&definition, "nodeB", &malformed, reference),
            Err(ThreatPredictionError::MalformedEvent(_))
        ));

        let mut invalid = ordered_events(reference);
        invalid[0].confidence = f64::NAN;
        assert!(matches!(
            match_precursor_sequence(&definition, "nodeB", &invalid, reference),
            Err(ThreatPredictionError::InvalidConfidence(_))
        ));
    }
}
