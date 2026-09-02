//! Adapter from the completed Task 1 alert contract to Virtual Shift.

use crate::alert::{AnomalyAlert, Severity};
use crate::policy_candidate::Task1RecommendationRecord;

use super::errors::VirtualShiftError;
use super::model::{AnomalyEvent, AnomalyEvidence, AnomalyType};

/// Convert an existing Task 1 alert into a validated Virtual Shift event.
///
/// The caller supplies an externally stable `anomaly_id` and only trusted
/// affected-peer identifiers. This adapter deliberately does not guess an IP,
/// peer ID, or target from telemetry features.
pub fn anomaly_event_from_alert(
    anomaly_id: impl Into<String>,
    alert: &AnomalyAlert,
    affected_peers: Vec<String>,
) -> Result<AnomalyEvent, VirtualShiftError> {
    let event = AnomalyEvent {
        anomaly_id: anomaly_id.into(),
        source_node: alert.node.trim().to_owned(),
        anomaly_type: anomaly_type_for(alert.action.as_ref().map(|action| action.kind.as_str())),
        score: alert.score,
        confidence: alert.confidence,
        severity: alert.severity,
        affected_peers: affected_peers
            .into_iter()
            .map(|peer| peer.trim().to_owned())
            .collect(),
        observed_at_ms: alert.ts,
        evidence: alert
            .topk
            .iter()
            .map(|feature| AnomalyEvidence {
                feature: feature.trim().to_owned(),
            })
            .collect(),
        reason: alert.reason.clone(),
        recommendation: alert.recommendation.clone(),
        proposed_action: alert.action.clone(),
    };
    event.validate()?;
    Ok(event)
}

/// Convert one persisted Task 1 recommendation record into VS1 input.
/// Older JSON without the final Task 1 model confidence is intentionally
/// refused: VS2 must never invent confidence merely to start a policy workflow.
pub fn anomaly_event_from_task1_record(
    source_node: &str,
    record: &Task1RecommendationRecord,
    affected_peers: Vec<String>,
) -> anyhow::Result<AnomalyEvent> {
    if record.decision != "ANOMALY" {
        anyhow::bail!("only Task 1 ANOMALY records can enter Virtual Shift");
    }
    let confidence = record.confidence.ok_or_else(|| {
        anyhow::anyhow!(
            "this older Task 1 record has no saved confidence; run the live Task 1 demo again to create a VS-compatible JSON"
        )
    })?;
    let severity = match record.severity.as_str() {
        "Low" => Severity::Low,
        "Medium" => Severity::Medium,
        "High" => Severity::High,
        "Critical" => Severity::Critical,
        value => anyhow::bail!("unknown Task 1 severity '{value}'"),
    };
    let event = AnomalyEvent {
        anomaly_id: format!("task1-{source_node}-{}", record.display_row),
        source_node: source_node.trim().to_owned(),
        anomaly_type: anomaly_type_for_task1_action(record.proposed_action.as_ref()),
        score: record.score,
        confidence,
        severity,
        affected_peers: affected_peers
            .into_iter()
            .map(|peer| peer.trim().to_owned())
            .collect(),
        observed_at_ms: record.source_time_ms,
        evidence: record
            .evidence_features
            .iter()
            .map(|feature| AnomalyEvidence {
                feature: feature.trim().to_owned(),
            })
            .collect(),
        reason: format!("Task 1 anomaly on display row {}", record.display_row),
        recommendation: record.recommendation.clone(),
        proposed_action: record.proposed_action.clone(),
    };
    event.validate()?;
    Ok(event)
}

fn anomaly_type_for(action_kind: Option<&str>) -> AnomalyType {
    match action_kind {
        Some("rate_limit_peer") => AnomalyType::ConnectionScan,
        Some("rate_limit_traffic") => AnomalyType::TrafficFlood,
        Some("inspect_node_resources") => AnomalyType::ResourceExhaustion,
        Some("review_audit_logs") => AnomalyType::ProtocolViolation,
        Some("inspect_overlay_peers") => AnomalyType::PeerAnomaly,
        _ => AnomalyType::Generic,
    }
}

/// Task 1 sometimes records a conservative `investigate_anomaly` top-level
/// action with its concrete evidence-driven next steps in `candidate_actions`.
/// Preserve that useful semantic information for *suggestion only*.  It never
/// applies a network policy itself: the Circle Owner must still review it.
fn anomaly_type_for_task1_action(action: Option<&crate::rules::ActionDefinition>) -> AnomalyType {
    let direct = anomaly_type_for(action.map(|value| value.kind.as_str()));
    if direct != AnomalyType::Generic {
        return direct;
    }
    let Some(action) = action else {
        return AnomalyType::Generic;
    };
    if action.kind != "investigate_anomaly" {
        return AnomalyType::Generic;
    }
    let Some(candidates) = action
        .params
        .get("candidate_actions")
        .and_then(serde_json::Value::as_array)
    else {
        return AnomalyType::Generic;
    };
    let contains = |needle: &str| {
        candidates
            .iter()
            .any(|value| value.as_str() == Some(needle))
    };
    if contains("review_audit_logs") {
        AnomalyType::ProtocolViolation
    } else if contains("inspect_overlay_peers") {
        AnomalyType::PeerAnomaly
    } else if contains("inspect_node_resources") {
        AnomalyType::ResourceExhaustion
    } else {
        AnomalyType::Generic
    }
}

#[cfg(test)]
mod tests {
    use crate::alert::{AlertTier, AnomalyAlert, Severity};
    use crate::roles::NodeRole;
    use crate::rules::ActionDefinition;

    use super::*;
    use crate::virtual_shift::{AnomalyEventRegistration, AnomalyEventRegistry, VirtualShiftError};

    fn persisted_record(confidence: Option<f64>) -> Task1RecommendationRecord {
        Task1RecommendationRecord {
            display_row: 42,
            source_time_ms: 42_000,
            decision: "ANOMALY".into(),
            score: 0.93,
            confidence,
            severity: "High".into(),
            evidence_features: vec!["conn_rate".into()],
            recommendation: "inspect the source peer".into(),
            proposed_action: Some(ActionDefinition {
                kind: "rate_limit_peer".into(),
                params: serde_json::json!({}),
            }),
        }
    }

    fn alert() -> AnomalyAlert {
        AnomalyAlert {
            ts: 1_720_000,
            node: "node-c".into(),
            role: NodeRole::Member,
            score: 0.92,
            confidence: 0.94,
            severity: Severity::High,
            topk: vec!["conn_rate".into(), "net_rx_pkts_rate".into()],
            reason: "unexpected connection activity".into(),
            recommendation: "review peer and restrict if confirmed".into(),
            action: Some(ActionDefinition {
                kind: "rate_limit_peer".into(),
                params: serde_json::json!({}),
            }),
            tier: AlertTier::Tier2,
        }
    }

    #[test]
    fn valid_task1_alert_becomes_a_normalized_virtual_shift_event() {
        let event =
            anomaly_event_from_alert("anom-001", &alert(), vec![" peer-c ".into()]).unwrap();

        assert_eq!(event.anomaly_id, "anom-001");
        assert_eq!(event.source_node, "node-c");
        assert_eq!(event.affected_peers, vec!["peer-c"]);
        assert_eq!(event.anomaly_type, AnomalyType::ConnectionScan);
        assert_eq!(event.evidence.len(), 2);
    }

    #[test]
    fn invalid_task1_score_is_rejected_before_virtual_shift() {
        let mut input = alert();
        input.score = f64::NAN;
        assert_eq!(
            anomaly_event_from_alert("anom-002", &input, vec![]).unwrap_err(),
            VirtualShiftError::InvalidScore
        );
    }

    #[test]
    fn invalid_confidence_and_timestamp_are_rejected_before_virtual_shift() {
        let mut invalid_confidence = alert();
        invalid_confidence.confidence = 1.01;
        assert_eq!(
            anomaly_event_from_alert("anom-002-confidence", &invalid_confidence, vec![])
                .unwrap_err(),
            VirtualShiftError::InvalidConfidence
        );

        let mut invalid_timestamp = alert();
        invalid_timestamp.ts = 0;
        assert_eq!(
            anomaly_event_from_alert("anom-002-time", &invalid_timestamp, vec![]).unwrap_err(),
            VirtualShiftError::InvalidTimestamp
        );
    }

    #[test]
    fn malformed_peer_and_unknown_evidence_are_rejected() {
        assert_eq!(
            anomaly_event_from_alert("anom-003", &alert(), vec![" ".into()]).unwrap_err(),
            VirtualShiftError::EmptyAffectedPeer
        );

        let mut input = alert();
        input.topk = vec!["not_a_locked_feature".into()];
        assert_eq!(
            anomaly_event_from_alert("anom-004", &input, vec![]).unwrap_err(),
            VirtualShiftError::UnknownEvidenceFeature("not_a_locked_feature".into())
        );

        assert_eq!(
            anomaly_event_from_alert(
                "anom-004-duplicate-peer",
                &alert(),
                vec!["nodeC".into(), " nodeC ".into()],
            )
            .unwrap_err(),
            VirtualShiftError::DuplicateAffectedPeer("nodeC".into())
        );
    }

    #[test]
    fn duplicate_anomaly_id_is_recognized() {
        let event = anomaly_event_from_alert("anom-005", &alert(), vec![]).unwrap();
        let mut registry = AnomalyEventRegistry::default();
        assert_eq!(registry.register(&event), AnomalyEventRegistration::New);
        assert_eq!(
            registry.register(&event),
            AnomalyEventRegistration::Duplicate
        );
    }

    #[test]
    fn fresh_persisted_task1_record_preserves_score_confidence_and_evidence() {
        let event = anomaly_event_from_task1_record(
            "nodeA",
            &persisted_record(Some(1.0)),
            vec!["nodeC".into()],
        )
        .unwrap();
        assert_eq!(event.anomaly_id, "task1-nodeA-42");
        assert_eq!(event.confidence, 1.0);
        assert_eq!(event.anomaly_type, AnomalyType::ConnectionScan);
        assert_eq!(event.affected_peers, vec!["nodeC"]);
    }

    #[test]
    fn old_persisted_record_without_confidence_is_refused() {
        assert!(anomaly_event_from_task1_record("nodeA", &persisted_record(None), vec![]).is_err());
    }
}
