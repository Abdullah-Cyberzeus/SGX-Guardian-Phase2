//! Task 4 Deliverable 3: read-only conversion of Task 1 anomaly evidence.
//!
//! This adapter does not perform anomaly detection. It preserves a Task 1
//! anomaly record as canonical Task 4 evidence for later temporal/prediction
//! deliverables.

use super::{
    validate_unit_interval, EventSeverity, EvidenceSource, SecurityEvent, SecurityEventType,
    ThreatPredictionError, SECURITY_EVENT_SCHEMA_VERSION,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct Task1RecommendationFile {
    schema_version: u32,
    node: String,
    recommendations: Vec<Task1RecommendationRecord>,
}

#[derive(Debug, Deserialize)]
struct Task1RecommendationRecord {
    rec_id: String,
    #[serde(default)]
    alert_id: Option<String>,
    source_time_ms: u64,
    decision: String,
    score: f64,
    #[serde(default)]
    confidence: Option<f64>,
    #[serde(default)]
    model_confidence: Option<f64>,
    severity: String,
    #[serde(default)]
    evidence_features: Vec<String>,
    #[serde(default)]
    anomaly_type: Option<String>,
    #[serde(default)]
    anomaly: Option<Task1AnomalyMetadata>,
    #[serde(default)]
    port_security_context: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct Task1AnomalyMetadata {
    #[serde(default)]
    detector: Option<String>,
    #[serde(default)]
    model_version: Option<String>,
    #[serde(default)]
    model_source: Option<String>,
    #[serde(default)]
    scorer_source: Option<String>,
    #[serde(default)]
    baseline_kind: Option<String>,
    #[serde(default)]
    baseline_source: Option<String>,
    #[serde(default)]
    baseline_fallback: Option<bool>,
    #[serde(default)]
    contributors: Vec<Task1Contributor>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct Task1Contributor {
    feature: String,
    contribution: f64,
    reason: String,
}

/// Read one Task 1 recommendation artifact and convert only its already
/// classified `ANOMALY` records. The source file remains read-only.
pub fn read_task1_anomalies(
    path: impl AsRef<Path>,
) -> Result<Vec<SecurityEvent>, ThreatPredictionError> {
    let path = path.as_ref();
    let json = std::fs::read_to_string(path).map_err(|error| {
        ThreatPredictionError::Io(format!(
            "reading Task 1 recommendation JSON {}: {error}",
            path.display()
        ))
    })?;
    normalize_task1_recommendations(&json)
}

/// Convert the existing Task 1 recommendation JSON contract into canonical
/// Task 4 events. No score is recalculated and no non-anomaly record is
/// promoted to an anomaly.
pub fn normalize_task1_recommendations(
    json: &str,
) -> Result<Vec<SecurityEvent>, ThreatPredictionError> {
    let file: Task1RecommendationFile = serde_json::from_str(json).map_err(|error| {
        ThreatPredictionError::Serialization(format!("parsing Task 1 recommendation JSON: {error}"))
    })?;
    if file.schema_version != 1 {
        return Err(ThreatPredictionError::MalformedEvent(format!(
            "unsupported Task 1 recommendation schema {}",
            file.schema_version
        )));
    }

    file.recommendations
        .into_iter()
        .filter(|record| record.decision.eq_ignore_ascii_case("ANOMALY"))
        .map(|record| normalize_record(&file.node, record))
        .collect()
}

fn normalize_record(
    node_id: &str,
    record: Task1RecommendationRecord,
) -> Result<SecurityEvent, ThreatPredictionError> {
    validate_unit_interval("Task1 anomaly score", record.score, true)?;
    let confidence = record
        .model_confidence
        .or(record.confidence)
        .ok_or_else(|| {
            ThreatPredictionError::InvalidConfidence(
                "Task1 anomaly record must include model_confidence or confidence".to_string(),
            )
        })?;
    validate_unit_interval("Task1 model confidence", confidence, false)?;

    let mut attributes = BTreeMap::from([
        ("task1_rec_id".to_string(), record.rec_id.clone()),
        ("task1_anomaly_score".to_string(), record.score.to_string()),
        ("task1_decision".to_string(), record.decision),
        (
            "task1_anomaly_type".to_string(),
            record
                .anomaly_type
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
        ),
        ("task1_severity".to_string(), record.severity.clone()),
    ]);
    if let Some(alert_id) = record.alert_id {
        attributes.insert("task1_alert_id".to_string(), alert_id);
    }
    for (index, feature) in record.evidence_features.into_iter().take(3).enumerate() {
        attributes.insert(format!("task1_feature_{index}"), feature);
    }
    if let Some(metadata) = record.anomaly {
        let mut model_metadata = BTreeMap::new();
        insert_optional(&mut model_metadata, "detector", metadata.detector);
        insert_optional(&mut model_metadata, "model_version", metadata.model_version);
        insert_optional(&mut model_metadata, "model_source", metadata.model_source);
        insert_optional(&mut model_metadata, "scorer_source", metadata.scorer_source);
        insert_optional(&mut model_metadata, "baseline_kind", metadata.baseline_kind);
        insert_optional(
            &mut model_metadata,
            "baseline_source",
            metadata.baseline_source,
        );
        if let Some(baseline_fallback) = metadata.baseline_fallback {
            model_metadata.insert(
                "baseline_fallback".to_string(),
                baseline_fallback.to_string(),
            );
        }
        if !model_metadata.is_empty() {
            attributes.insert(
                "task1_model_metadata".to_string(),
                encode_source_context("Task1 model metadata", &model_metadata)?,
            );
        }
        if !metadata.contributors.is_empty() {
            attributes.insert(
                "task1_top_contributors".to_string(),
                encode_source_context(
                    "Task1 top contributors",
                    &metadata
                        .contributors
                        .into_iter()
                        .take(3)
                        .collect::<Vec<_>>(),
                )?,
            );
        }
    }
    if let Some(port_security_context) = record.port_security_context {
        if !port_security_context.is_object() {
            return Err(ThreatPredictionError::MalformedEvent(
                "Task1 port_security_context must be an object when present".to_string(),
            ));
        }
        attributes.insert(
            "task1_port_security_context".to_string(),
            encode_source_context("Task1 port/security context", &port_security_context)?,
        );
    }

    let event = SecurityEvent {
        schema_version: SECURITY_EVENT_SCHEMA_VERSION,
        event_id: format!("task4-task1:{}", record.rec_id),
        observed_at_ms: record.source_time_ms,
        source: EvidenceSource::Task1Anomaly,
        node_id: node_id.to_string(),
        peer_id: None,
        source_ip: None,
        destination_ip: None,
        source_port: None,
        destination_port: None,
        event_type: task1_event_type(record.anomaly_type.as_deref()),
        severity: task1_severity(&record.severity)?,
        confidence,
        attributes,
    };
    event.validate()?;
    Ok(event)
}

fn insert_optional(values: &mut BTreeMap<String, String>, key: &str, value: Option<String>) {
    if let Some(value) = value {
        values.insert(key.to_string(), value);
    }
}

fn encode_source_context<T: serde::Serialize>(
    label: &str,
    value: &T,
) -> Result<String, ThreatPredictionError> {
    serde_json::to_string(value).map_err(|error| {
        ThreatPredictionError::Serialization(format!("serializing {label}: {error}"))
    })
}

fn task1_event_type(anomaly_type: Option<&str>) -> SecurityEventType {
    let value = anomaly_type.unwrap_or_default().to_ascii_lowercase();
    if value.contains("ddos") || value.contains("flood") {
        SecurityEventType::TrafficFlood
    } else if value.contains("recon") || value.contains("scan") {
        SecurityEventType::Reconnaissance
    } else if value.contains("brute") || value.contains("auth") {
        SecurityEventType::AuthenticationFailure
    } else if value.contains("protocol") {
        SecurityEventType::ProtocolViolation
    } else {
        SecurityEventType::TrafficAnomaly
    }
}

fn task1_severity(value: &str) -> Result<EventSeverity, ThreatPredictionError> {
    match value.to_ascii_lowercase().as_str() {
        "info" => Ok(EventSeverity::Info),
        "low" => Ok(EventSeverity::Low),
        "medium" => Ok(EventSeverity::Medium),
        "high" => Ok(EventSeverity::High),
        "critical" => Ok(EventSeverity::Critical),
        _ => Err(ThreatPredictionError::MalformedEvent(format!(
            "unsupported Task1 severity '{value}'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_TASK1_RECOMMENDATION_FIXTURE: &str = r#"{
      "schema_version": 1,
      "node": "nodeA",
      "source": "task1-anomaly-engine",
      "recommendations": [{
        "rec_id": "urn:task1:nodeA:recommendation:63",
        "alert_id": "task1-alert-nodeA-63000",
        "source_time_ms": 63000,
        "decision": "ANOMALY",
        "score": 0.7484949431586227,
        "confidence": 0.5493281576883848,
        "model_confidence": 0.5493281576883848,
        "severity": "Medium",
        "evidence_features": ["cot_latency_avg_ms", "error_rate", "open_fds"],
        "anomaly_type": "protocol_violation",
        "anomaly": {
          "detector": "tier2_isolation_forest",
          "model_source": "real_task1_ml_engine_global_fallback",
          "scorer_source": "real_task1_ml_engine",
          "baseline_kind": "global",
          "baseline_source": "global",
          "baseline_fallback": true,
          "contributors": [{
            "feature": "cot_latency_avg_ms",
            "contribution": 0.5,
            "reason": "used in 50 of 100 Isolation Forest tree paths"
          }]
        },
        "port_security_context": {
          "target_ip": "10.0.0.25",
          "target_port": 3389,
          "nmap_finding": {"source": "nmap_inventory", "service": "rdp", "severity": "HIGH"},
          "suricata_event": {"signature": "Possible RDP port scan", "signature_id": 9100001},
          "correlated_alert_count": 1,
          "correlation_reason": "port posture correlated with Suricata alert"
        }
      }]
    }"#;

    #[test]
    fn real_task1_recommendation_fixture_converts_and_preserves_source_ids() {
        let events = normalize_task1_recommendations(REAL_TASK1_RECOMMENDATION_FIXTURE).unwrap();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.source, EvidenceSource::Task1Anomaly);
        assert_eq!(event.node_id, "nodeA");
        assert_eq!(event.observed_at_ms, 63_000);
        assert_eq!(event.event_type, SecurityEventType::ProtocolViolation);
        assert_eq!(
            event.event_id,
            "task4-task1:urn:task1:nodeA:recommendation:63"
        );
        assert_eq!(
            event.attributes.get("task1_rec_id"),
            Some(&"urn:task1:nodeA:recommendation:63".to_string())
        );
        assert_eq!(
            event.attributes.get("task1_alert_id"),
            Some(&"task1-alert-nodeA-63000".to_string())
        );
        assert_eq!(
            event.attributes.get("task1_anomaly_score"),
            Some(&"0.7484949431586227".to_string())
        );
        let contributors: Value =
            serde_json::from_str(event.attributes.get("task1_top_contributors").unwrap()).unwrap();
        assert_eq!(contributors[0]["feature"], "cot_latency_avg_ms");
        let model_metadata: Value =
            serde_json::from_str(event.attributes.get("task1_model_metadata").unwrap()).unwrap();
        assert_eq!(model_metadata["detector"], "tier2_isolation_forest");
        assert_eq!(
            model_metadata["model_source"],
            "real_task1_ml_engine_global_fallback"
        );
        let port_context: Value =
            serde_json::from_str(event.attributes.get("task1_port_security_context").unwrap())
                .unwrap();
        assert_eq!(port_context["target_port"], 3389);
        assert_eq!(port_context["nmap_finding"]["service"], "rdp");
        assert_eq!(port_context["suricata_event"]["signature_id"], 9_100_001);
        event.validate().unwrap();
    }

    #[test]
    fn bridge_is_replay_stable_and_never_infers_non_anomalies() {
        let once = normalize_task1_recommendations(REAL_TASK1_RECOMMENDATION_FIXTURE).unwrap();
        let replay = normalize_task1_recommendations(REAL_TASK1_RECOMMENDATION_FIXTURE).unwrap();
        assert_eq!(once[0].event_id, replay[0].event_id);
        assert_eq!(once[0].deduplication_key(), replay[0].deduplication_key());

        let normal = REAL_TASK1_RECOMMENDATION_FIXTURE.replace("\"ANOMALY\"", "\"NORMAL\"");
        assert!(normalize_task1_recommendations(&normal).unwrap().is_empty());
    }

    #[test]
    fn malformed_task1_input_fails_safely_without_panic() {
        assert!(matches!(
            normalize_task1_recommendations("{not valid json"),
            Err(ThreatPredictionError::Serialization(_))
        ));

        let invalid_score = REAL_TASK1_RECOMMENDATION_FIXTURE.replace("0.7484949431586227", "1.2");
        assert!(matches!(
            normalize_task1_recommendations(&invalid_score),
            Err(ThreatPredictionError::InvalidProbability(_))
        ));
    }
}
