//! Task 3 Deliverable 9: Task 1 anomaly/risk signal bridge.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Task1RouteSignal {
    pub source_path: String,
    pub node: String,
    pub recommendation_count: usize,
    pub max_anomaly_score: Option<f64>,
    pub max_model_confidence: Option<f64>,
    pub max_advisory_confidence: Option<f64>,
    pub top_evidence_features: Vec<String>,
    pub model_metadata_traceable: bool,
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
    let mut model_metadata_traceable = false;

    for rec in &recommendations {
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
        node,
        recommendation_count: recommendations.len(),
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
}
