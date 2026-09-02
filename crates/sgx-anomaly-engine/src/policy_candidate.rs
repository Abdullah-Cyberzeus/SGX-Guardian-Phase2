//! Task 2 phase 2: convert one Task 1 recommendation record into a safe
//! pending policy candidate when (and only when) an admin template maps it.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::policy::{
    PolicyAction, PolicyCandidate, PolicyEvidence, PolicyParameters, PolicyStatus, PolicyTemplates,
};
use crate::rules::ActionDefinition;

#[derive(Debug, Deserialize)]
pub struct Task1RecommendationFile {
    pub schema_version: u32,
    pub node: String,
    pub recommendations: Vec<Task1RecommendationRecord>,
}

#[derive(Debug, Deserialize)]
pub struct Task1RecommendationRecord {
    pub display_row: usize,
    pub source_time_ms: u64,
    pub decision: String,
    pub score: f64,
    /// Confidence for the same model tier that supplied `score`.
    #[serde(default)]
    pub confidence: Option<f64>,
    pub severity: String,
    pub evidence_features: Vec<String>,
    pub recommendation: String,
    pub proposed_action: Option<ActionDefinition>,
}

pub fn read_task1_recommendations(
    path: impl AsRef<Path>,
) -> anyhow::Result<Task1RecommendationFile> {
    let contents = std::fs::read_to_string(path)?;
    let file: Task1RecommendationFile = serde_json::from_str(&contents)?;
    if file.schema_version != 1 {
        anyhow::bail!(
            "unsupported Task 1 recommendation schema {}",
            file.schema_version
        );
    }
    Ok(file)
}

/// `parameters` are supplied by the approved workflow/admin UI.  Phase 2
/// deliberately refuses to guess a target, rate, or duration from prose.
pub fn create_pending_candidate(
    source_path: impl AsRef<Path>,
    recommendation_index: usize,
    parameters: PolicyParameters,
    templates: &PolicyTemplates,
) -> anyhow::Result<PolicyCandidate> {
    let source_path = source_path.as_ref();
    let file = read_task1_recommendations(source_path)?;
    let record = file
        .recommendations
        .get(recommendation_index)
        .ok_or_else(|| {
            anyhow::anyhow!("recommendation index {recommendation_index} does not exist")
        })?;
    if record.decision != "ANOMALY" {
        anyhow::bail!("only Task 1 anomaly records can become policy candidates");
    }
    let proposed_action = record
        .proposed_action
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Task 1 record has no machine-readable proposed action"))?;
    let action = templates
        .action_for_task1_kind(&proposed_action.kind)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Task 1 action '{}' is not mapped to an admin policy template; keep it as a recommendation only",
                proposed_action.kind
            )
        })?;
    templates.validate_parameters(action, &parameters)?;

    let source_name = source_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("recommendations.json");
    Ok(PolicyCandidate {
        policy_id: format!(
            "policy-{}-{}-{}",
            file.node, record.source_time_ms, record.display_row
        ),
        source_recommendation_id: Some(format!("{source_name}:{}", recommendation_index)),
        action,
        parameters,
        reason: format!(
            "Task 1 {} anomaly (score {:.3}, severity {}): {}. Evidence: {}",
            file.node,
            record.score,
            record.severity,
            record.recommendation,
            record.evidence_features.join(", ")
        ),
        evidence: vec![evidence_from_record(record, &proposed_action.kind)],
        status: PolicyStatus::Pending,
    })
}

/// Groups repeat anomaly records by `Task 1 action + mapped policy action`.
/// This prevents one pending policy request per telemetry row while preserving
/// every source row as evidence on the one candidate.
pub fn create_grouped_pending_candidates(
    source_path: impl AsRef<Path>,
    parameters_by_action: &[(PolicyAction, PolicyParameters)],
    templates: &PolicyTemplates,
) -> anyhow::Result<Vec<PolicyCandidate>> {
    let source_path = source_path.as_ref();
    let file = read_task1_recommendations(source_path)?;
    let mut groups: Vec<(String, PolicyAction, Vec<&Task1RecommendationRecord>)> = Vec::new();

    for record in &file.recommendations {
        if record.decision != "ANOMALY" {
            continue;
        }
        let Some(proposed_action) = &record.proposed_action else {
            continue;
        };
        let Some(policy_action) = templates.action_for_task1_kind(&proposed_action.kind) else {
            continue; // recommendation-only action: never becomes a policy candidate
        };
        if let Some((_, _, records)) = groups.iter_mut().find(|(task1_kind, action, _)| {
            task1_kind == &proposed_action.kind && *action == policy_action
        }) {
            records.push(record);
        } else {
            groups.push((proposed_action.kind.clone(), policy_action, vec![record]));
        }
    }

    let source_name = source_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("recommendations.json");
    let mut candidates = Vec::new();
    for (task1_action, action, records) in groups {
        let parameters = parameters_by_action
            .iter()
            .find(|(configured_action, _)| *configured_action == action)
            .map(|(_, parameters)| parameters.clone())
            .ok_or_else(|| {
                anyhow::anyhow!("admin parameters are required for mapped action {action:?}")
            })?;
        templates.validate_parameters(action, &parameters)?;
        let first = records[0];
        let evidence: Vec<PolicyEvidence> = records
            .iter()
            .map(|record| evidence_from_record(record, &task1_action))
            .collect();
        candidates.push(PolicyCandidate {
            policy_id: format!(
                "policy-{}-{}-{}",
                file.node, first.source_time_ms, first.display_row
            ),
            source_recommendation_id: Some(format!("{source_name}:group:{task1_action}")),
            action,
            parameters,
            reason: format!(
                "Task 1 model recommendation: {} Same '{}' anomaly action appeared on {} row(s) for {} and is grouped into this one pending policy candidate.",
                first.recommendation,
                task1_action,
                evidence.len(),
                file.node,
            ),
            evidence,
            status: PolicyStatus::Pending,
        });
    }
    Ok(candidates)
}

pub fn write_candidate(
    root: impl AsRef<Path>,
    candidate: &PolicyCandidate,
) -> anyhow::Result<PathBuf> {
    let directory = root.as_ref().join(&candidate.policy_id);
    std::fs::create_dir_all(&directory)?;
    let output = directory.join("candidate.json");
    std::fs::write(&output, serde_json::to_string_pretty(candidate)?)?;
    Ok(output)
}

fn evidence_from_record(record: &Task1RecommendationRecord, task1_action: &str) -> PolicyEvidence {
    PolicyEvidence {
        display_row: record.display_row,
        source_time_ms: record.source_time_ms,
        task1_action: task1_action.to_string(),
        score: record.score,
        severity: record.severity.clone(),
        evidence_features: record.evidence_features.clone(),
        recommendation: record.recommendation.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{FirewallMode, PolicyAction};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEMP_FILE_NUMBER: AtomicUsize = AtomicUsize::new(0);

    fn templates() -> PolicyTemplates {
        PolicyTemplates::from_path("config/policy_action_templates.json").unwrap()
    }

    fn rate_limit_parameters() -> PolicyParameters {
        PolicyParameters {
            target: "10.0.0.25".into(),
            duration_seconds: Some(300),
            firewall_mode: Some(FirewallMode::RateLimit),
            rate_limit_per_second: Some(20),
            ..Default::default()
        }
    }

    fn source_json(action: &str, decision: &str) -> String {
        serde_json::json!({
            "schema_version": 1,
            "node": "nodeA",
            "recommendations": [{
                "display_row": 42,
                "source_time_ms": 42000,
                "decision": decision,
                "score": 0.95,
                "severity": "High",
                "evidence_features": ["conn_rate"],
                "recommendation": "Rate limit the peer.",
                "proposed_action": {"kind": action, "params": {}}
            }]
        })
        .to_string()
    }

    fn temporary_source(contents: &str) -> std::path::PathBuf {
        let sequence = TEMP_FILE_NUMBER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "task2_candidate_{}_{}.json",
            std::process::id(),
            sequence
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn mapped_task1_action_becomes_pending_candidate() {
        let path = temporary_source(&source_json("rate_limit_peer", "ANOMALY"));
        let candidate =
            create_pending_candidate(&path, 0, rate_limit_parameters(), &templates()).unwrap();
        assert_eq!(candidate.status, PolicyStatus::Pending);
        assert_eq!(candidate.action, PolicyAction::TightenFirewall);
        assert_eq!(candidate.evidence.len(), 1);
    }

    #[test]
    fn unmapped_task1_action_stays_recommendation_only() {
        let path = temporary_source(&source_json("inspect_node_resources", "ANOMALY"));
        assert!(create_pending_candidate(&path, 0, rate_limit_parameters(), &templates()).is_err());
    }

    #[test]
    fn normal_task1_row_cannot_become_candidate() {
        let path = temporary_source(&source_json("rate_limit_peer", "NORMAL"));
        assert!(create_pending_candidate(&path, 0, rate_limit_parameters(), &templates()).is_err());
    }

    #[test]
    fn repeat_actions_group_evidence_into_one_candidate() {
        let text = serde_json::json!({
            "schema_version": 1,
            "node": "nodeA",
            "recommendations": [
                {"display_row": 42, "source_time_ms": 42000, "decision": "ANOMALY", "score": 0.91, "severity": "High", "evidence_features": ["conn_rate"], "recommendation": "rate limit", "proposed_action": {"kind": "rate_limit_peer", "params": {}}},
                {"display_row": 43, "source_time_ms": 43000, "decision": "ANOMALY", "score": 0.92, "severity": "High", "evidence_features": ["conn_rate"], "recommendation": "rate limit", "proposed_action": {"kind": "rate_limit_peer", "params": {}}}
            ]
        })
        .to_string();
        let path = temporary_source(&text);
        let grouped = create_grouped_pending_candidates(
            &path,
            &[(PolicyAction::TightenFirewall, rate_limit_parameters())],
            &templates(),
        )
        .unwrap();
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[0].evidence.len(), 2);
    }
}
