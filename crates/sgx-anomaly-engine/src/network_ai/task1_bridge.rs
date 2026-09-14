//! Task 3 Deliverable 9: Task 1 anomaly/risk signal bridge.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Task1RouteSignal {
    pub source_path: String,
    pub run_id: Option<String>,
    pub node: String,
    pub recommendation_count: usize,
    pub recommendation_ids: Vec<String>,
    pub max_anomaly_score: Option<f64>,
    pub max_model_confidence: Option<f64>,
    pub max_advisory_confidence: Option<f64>,
    pub top_evidence_features: Vec<String>,
    pub model_metadata_traceable: bool,
}

/// Optional Task1 input is advisory context, not an availability dependency.
/// A missing or malformed file is reported for audit and safely yields no
/// Task1 feature signal; Task3 never reimplements Task1 anomaly detection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OptionalTask1RouteSignal {
    pub signal: Option<Task1RouteSignal>,
    pub status: String,
}

pub fn read_optional_task1_route_signal(path: Option<&Path>) -> OptionalTask1RouteSignal {
    let Some(path) = path else {
        return OptionalTask1RouteSignal {
            signal: None,
            status: "Task1 signal unavailable: no recommendation file was supplied".to_string(),
        };
    };
    match read_task1_route_signal(path) {
        Ok(signal) => OptionalTask1RouteSignal {
            signal: Some(signal),
            status: "Task1 recommendation signal consumed read-only".to_string(),
        },
        Err(error) => OptionalTask1RouteSignal {
            signal: None,
            status: format!("Task1 optional signal ignored safely: {error}"),
        },
    }
}

pub fn read_task1_route_signal(path: impl AsRef<Path>) -> Result<Task1RouteSignal> {
    let path = path.as_ref();
    let json = std::fs::read_to_string(path)
        .with_context(|| format!("reading Task1 recommendation JSON {}", path.display()))?;
    let value: Value = serde_json::from_str(&json).context("parsing Task1 recommendation JSON")?;
    let node = value
        .get("node")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let recommendations = value
        .get("recommendations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut max_anomaly_score: Option<f64> = None;
    let mut max_model_confidence: Option<f64> = None;
    let mut max_advisory_confidence: Option<f64> = None;
    let mut features = Vec::new();
    let mut recommendation_ids = Vec::new();
    let mut model_metadata_traceable = false;

    for rec in &recommendations {
        if let Some(id) = rec.get("rec_id").and_then(Value::as_str) {
            if recommendation_ids.len() < 10 {
                recommendation_ids.push(id.to_string());
            }
        }
        max_anomaly_score = max_f64(max_anomaly_score, rec.get("score").and_then(Value::as_f64));
        max_model_confidence = max_f64(
            max_model_confidence,
            rec.get("model_confidence").and_then(Value::as_f64),
        );
        max_advisory_confidence = max_f64(
            max_advisory_confidence,
            rec.get("advisory_confidence").and_then(Value::as_f64),
        );
        if rec.get("triggering_tier").is_some() || rec.get("tier3_shadow").is_some() {
            model_metadata_traceable = true;
        }
        if let Some(list) = rec.get("evidence_features").and_then(Value::as_array) {
            for item in list.iter().filter_map(Value::as_str).take(3) {
                if !features.iter().any(|existing| existing == item) {
                    features.push(item.to_string());
                }
            }
        }
    }

    Ok(Task1RouteSignal {
        source_path: path.display().to_string(),
        run_id: path
            .parent()
            .and_then(Path::file_name)
            .and_then(|value| value.to_str())
            .map(str::to_string),
        node,
        recommendation_count: recommendations.len(),
        recommendation_ids,
        max_anomaly_score,
        max_model_confidence,
        max_advisory_confidence,
        top_evidence_features: features,
        model_metadata_traceable,
    })
}

fn max_f64(current: Option<f64>, next: Option<f64>) -> Option<f64> {
    match (current, next) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (None, Some(b)) => Some(b),
        (Some(a), None) => Some(a),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_task1_signal_from_recommendation_json() {
        let dir = std::env::temp_dir().join(format!("task1-bridge-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("recommendations.json");
        std::fs::write(
            &path,
            r#"{
              "node": "nodeA",
              "recommendations": [{
                "score": 0.81,
                "model_confidence": 0.70,
                "advisory_confidence": 0.90,
                "triggering_tier": "Tier-2",
                "evidence_features": ["latency", "loss", "throughput"]
              }]
            }"#,
        )
        .unwrap();

        let signal = read_task1_route_signal(&path).unwrap();
        assert_eq!(signal.node, "nodeA");
        assert_eq!(signal.recommendation_count, 1);
        assert_eq!(signal.max_anomaly_score, Some(0.81));
        assert!(signal.model_metadata_traceable);
        assert_eq!(signal.top_evidence_features.len(), 3);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn malformed_or_missing_optional_signal_is_safe() {
        let dir =
            std::env::temp_dir().join(format!("task1-bridge-optional-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bad = dir.join("recommendations.json");
        std::fs::write(&bad, "not-json").unwrap();
        let malformed = read_optional_task1_route_signal(Some(&bad));
        assert!(malformed.signal.is_none());
        assert!(malformed.status.contains("ignored safely"));
        assert!(read_optional_task1_route_signal(None).signal.is_none());
        let _ = std::fs::remove_dir_all(dir);
    }
}
