//! Task 3 Deliverable 14: linked, inspectable decision audit evidence.
//!
//! This module does not make routing decisions.  It joins evidence already
//! produced by the telemetry, eligibility, prediction, degradation, reward,
//! and Task1/Task2 bridge modules into one restart-safe audit chain.

use super::{
    DegradationPrediction, EligibleRouteSet, RoutePredictionSet, RouteReward, Task1RouteSignal,
    Task2RoutingTrustSummary,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const NETWORK_AI_DECISION_AUDIT_VERSION: &str = "network-ai-decision-audit-v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionEvidenceLinks {
    pub route_history_path: String,
    pub observed_outcomes_path: String,
    pub rewards_path: String,
    pub degradation_events_path: String,
    pub task1_source_path: Option<String>,
    pub task2_trust_source_path: Option<String>,
    pub task2_trust_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RejectedCandidateAudit {
    pub route_id: String,
    pub rejection_reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionAuditRecord {
    pub schema_version: String,
    pub decision_id: String,
    pub ts_ms: u64,
    pub selected_route_id: Option<String>,
    pub selected_confidence: Option<f64>,
    pub selected_reason: String,
    pub model_version: String,
    pub feature_schema_version: String,
    pub selected_reward: Option<RouteReward>,
    /// Every observed reward considered during this decision. This is kept
    /// separately from `selected_reward` because a failed current route can
    /// be valid learning evidence even when no candidate was selected.
    #[serde(default)]
    pub observed_rewards: Vec<RouteReward>,
    pub rejected_candidates: Vec<RejectedCandidateAudit>,
    pub degradation_predictions: Vec<DegradationPrediction>,
    pub task1_signal: Option<Task1RouteSignal>,
    pub task2_summary: Option<Task2RoutingTrustSummary>,
    pub evidence: DecisionEvidenceLinks,
}

impl DecisionAuditRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn from_engine_outputs(
        decision_id: impl Into<String>,
        ts_ms: u64,
        eligible: &EligibleRouteSet,
        predictions: &RoutePredictionSet,
        rewards: &[RouteReward],
        degradation_predictions: Vec<DegradationPrediction>,
        task1_signal: Option<Task1RouteSignal>,
        task2_summary: Option<Task2RoutingTrustSummary>,
        evidence: DecisionEvidenceLinks,
    ) -> Self {
        let selected_route_id = predictions.selected_route_id.clone();
        let selected_prediction = selected_route_id.as_ref().and_then(|id| {
            predictions
                .predictions
                .iter()
                .find(|prediction| &prediction.route_id == id)
        });
        let selected_reward = selected_route_id.as_ref().and_then(|id| {
            rewards
                .iter()
                .find(|reward| &reward.route_id == id)
                .cloned()
        });
        Self {
            schema_version: NETWORK_AI_DECISION_AUDIT_VERSION.to_string(),
            decision_id: decision_id.into(),
            ts_ms,
            selected_route_id: selected_route_id.clone(),
            selected_confidence: selected_prediction.map(|prediction| prediction.confidence),
            selected_reason: selected_prediction
                .map(|prediction| prediction.reason.clone())
                .unwrap_or_else(|| "no Task2-trusted eligible route was selected".to_string()),
            model_version: predictions.model_version.clone(),
            feature_schema_version: predictions.feature_schema_version.clone(),
            selected_reward,
            observed_rewards: rewards.to_vec(),
            rejected_candidates: {
                let mut rejected_candidates = eligible
                    .rejected
                    .iter()
                    .map(|rejected| RejectedCandidateAudit {
                        route_id: rejected.route_id.clone(),
                        rejection_reason: format!("eligibility_rejected: {:?}", rejected.reason),
                    })
                    .collect::<Vec<_>>();

                // D14: persist every AI-evaluated candidate that was not
                // selected so the decision can be reconstructed/audited.
                for prediction in &predictions.predictions {
                    if selected_route_id.as_deref() == Some(prediction.route_id.as_str()) {
                        continue;
                    }

                    // Avoid duplicate audit entries if a route is already
                    // represented by an eligibility rejection.
                    if rejected_candidates
                        .iter()
                        .any(|entry| entry.route_id == prediction.route_id)
                    {
                        continue;
                    }

                    rejected_candidates.push(RejectedCandidateAudit {
                        route_id: prediction.route_id.clone(),
                        rejection_reason: format!(
                            "evaluated_not_selected: quality_score={:.2}, confidence={:.3}; {}",
                            prediction.quality_score, prediction.confidence, prediction.reason
                        ),
                    });
                }

                rejected_candidates
            },
            degradation_predictions,
            task1_signal,
            task2_summary,
            evidence,
        }
    }
}

/// Files created for one D14 audit record. `current_decision.json` is
/// replaced atomically; JSONL files are append-only history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionAuditPaths {
    pub current_decision: PathBuf,
    pub decisions_jsonl: PathBuf,
    pub rewards_jsonl: PathBuf,
    pub degradation_events_jsonl: PathBuf,
}

impl DecisionAuditPaths {
    pub fn under(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref();
        Self {
            current_decision: root.join("current_decision.json"),
            decisions_jsonl: root.join("decisions.jsonl"),
            rewards_jsonl: root.join("rewards.jsonl"),
            degradation_events_jsonl: root.join("degradation_events.jsonl"),
        }
    }
}

pub fn persist_decision_audit(
    record: &DecisionAuditRecord,
    paths: &DecisionAuditPaths,
) -> Result<()> {
    atomic_write_json(&paths.current_decision, record)?;
    append_jsonl(&paths.decisions_jsonl, record)?;
    append_jsonl(
        &paths.rewards_jsonl,
        &serde_json::json!({
            "decision_id": record.decision_id,
            "ts_ms": record.ts_ms,
            "selected_reward": record.selected_reward,
            "rewards": record.observed_rewards,
        }),
    )?;
    for degradation in &record.degradation_predictions {
        append_jsonl(
            &paths.degradation_events_jsonl,
            &serde_json::json!({
                "decision_id": record.decision_id,
                "ts_ms": record.ts_ms,
                "prediction": degradation,
            }),
        )?;
    }
    Ok(())
}

fn atomic_write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path
        .parent()
        .context("current decision path must have a parent")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("creating audit directory {}", parent.display()))?;
    let temporary = path.with_extension("json.tmp");
    fs::write(
        &temporary,
        serde_json::to_vec_pretty(value).context("serializing decision audit")?,
    )
    .with_context(|| format!("writing temporary audit {}", temporary.display()))?;
    fs::rename(&temporary, path).with_context(|| format!("activating audit {}", path.display()))?;
    Ok(())
}

fn append_jsonl(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating audit directory {}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening audit history {}", path.display()))?;
    writeln!(
        file,
        "{}",
        serde_json::to_string(value).context("serializing audit history")?
    )
    .with_context(|| format!("appending audit history {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_ai::{
        DegradationPrediction, EligibilityDecision, EligibilityReason, NetworkAiFeatureVector,
        RouteCandidateInventory, RoutePrediction, RouteQualityComponents, TrafficClass,
    };

    fn record() -> DecisionAuditRecord {
        let candidate = RouteCandidateInventory::from_relays(
            "nodeA",
            "nodeB",
            TrafficClass::Operational,
            ["nodeC"],
        )
        .candidates
        .into_iter()
        .next()
        .unwrap();
        let eligible = EligibleRouteSet {
            trust_state_version: "task2-v1".into(),
            traffic_class: TrafficClass::Operational,
            safe_fallback_active: false,
            eligible: vec![],
            rejected: vec![EligibilityDecision {
                route_id: candidate.route_id.clone(),
                eligible: false,
                reason: EligibilityReason::QuarantinedPeer,
                candidate,
            }],
        };
        let prediction = RoutePrediction {
            route_id: "direct-nodeA-nodeB".into(),
            model_version: "model-v1".into(),
            expected_latency_ms: 10.0,
            expected_loss_pct: 0.1,
            expected_throughput_mbps: 80.0,
            confidence: 0.9,
            quality_score: 90.0,
            features: NetworkAiFeatureVector {
                schema_version: "network-ai-v1".into(),
                route_id: "direct-nodeA-nodeB".into(),
                normalized_latency: 0.1,
                normalized_loss: 0.1,
                normalized_throughput: 0.8,
                normalized_utilization: 0.1,
                normalized_hops: 0.0,
                normalized_success_rate: 1.0,
                normalized_failure_rate: 0.0,
                normalized_route_age: 0.0,
                priority: 0.5,
                task1_anomaly_score: 0.7,
                missing_history: false,
                explainability: vec![],
            },
            components: RouteQualityComponents {
                latency_component: 1.0,
                throughput_component: 1.0,
                loss_penalty: 0.0,
                hop_penalty: 0.0,
                failure_penalty: 0.0,
                availability_penalty: 0.0,
                task1_anomaly_component: 0.0,
                total_score: 90.0,
            },
            reason: "best trusted route".into(),
        };
        let prediction_set = RoutePredictionSet {
            model_version: "model-v1".into(),
            feature_schema_version: "network-ai-v1".into(),
            predictions: vec![prediction.clone()],
            selected_route_id: Some(prediction.route_id.clone()),
        };
        let reward = RouteReward::from_prediction(&prediction, 0, false, false);
        let degradation = DegradationPrediction {
            model_version: "degradation-v1".into(),
            route_id: prediction.route_id.clone(),
            probability: 0.2,
            horizon_seconds: 60,
            contributors: vec!["test".into()],
            reason: "test prediction".into(),
        };
        DecisionAuditRecord::from_engine_outputs(
            "decision-1",
            100,
            &eligible,
            &prediction_set,
            &[reward],
            vec![degradation],
            None,
            None,
            DecisionEvidenceLinks {
                route_history_path: "route_history.jsonl".into(),
                observed_outcomes_path: "outcomes.jsonl".into(),
                rewards_path: "rewards.jsonl".into(),
                degradation_events_path: "degradation_events.jsonl".into(),
                task1_source_path: Some("task1.json".into()),
                task2_trust_source_path: Some("task2.json".into()),
                task2_trust_version: Some("task2-v1".into()),
            },
        )
    }

    #[test]
    fn persists_current_and_linked_append_only_audit_chain() {
        let root = std::env::temp_dir().join(format!("network-ai-d14-{}", std::process::id()));
        let paths = DecisionAuditPaths::under(&root);
        let mut record = record();
        record.evidence.rewards_path = paths.rewards_jsonl.display().to_string();
        record.evidence.degradation_events_path =
            paths.degradation_events_jsonl.display().to_string();
        persist_decision_audit(&record, &paths).unwrap();
        let mut later_record = record.clone();
        later_record.decision_id = "decision-2".to_string();
        later_record.ts_ms = 200;
        persist_decision_audit(&later_record, &paths).unwrap();
        let current: DecisionAuditRecord =
            serde_json::from_str(&fs::read_to_string(&paths.current_decision).unwrap()).unwrap();
        assert_eq!(current.decision_id, "decision-2");
        assert_eq!(
            current.rejected_candidates[0].rejection_reason,
            "eligibility_rejected: QuarantinedPeer"
        );
        assert_eq!(
            fs::read_to_string(&paths.decisions_jsonl)
                .unwrap()
                .lines()
                .count(),
            2
        );
        let linked_rewards = fs::read_to_string(&current.evidence.rewards_path).unwrap();
        assert_eq!(linked_rewards.lines().count(), 2);
        assert!(linked_rewards.lines().any(|line| {
            serde_json::from_str::<serde_json::Value>(line).unwrap()["decision_id"]
                == current.decision_id
        }));
        let linked_degradation =
            fs::read_to_string(&current.evidence.degradation_events_path).unwrap();
        assert_eq!(linked_degradation.lines().count(), 2);
        assert!(linked_degradation.lines().any(|line| {
            serde_json::from_str::<serde_json::Value>(line).unwrap()["decision_id"]
                == current.decision_id
        }));
        let _ = fs::remove_dir_all(root);
    }
}
