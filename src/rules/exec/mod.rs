pub mod actions;
pub mod guards;

use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::rules::errors::RulesResult;
use crate::rules::eval::evaluate;
use crate::rules::exec::actions::{
    downgraded_report, dry_run_report, execute_action, ActionReport,
};
use crate::rules::exec::guards::{check_and_record, GuardDecision};
use crate::rules::model::{Rule, RuleEvent, RuleExecution};
use crate::rules::persistence::{write_atomic, RulesPaths};
use crate::rules::store::RULES_WRITE_LOCK;
use crate::rules::RulesConfig;
use chrono::Utc;
use std::path::Path;
use uuid::Uuid;

pub async fn process_event(config: RulesConfig, node_id: String, event: RuleEvent) {
    let registry = match crate::rules::store::load_registry(&config.paths.base, &node_id) {
        Ok(registry) => registry,
        Err(error) => {
            log_audit(
                &node_id,
                AuditCategory::Rules,
                AuditSeverity::Critical,
                AuditAction::Rejected,
                &format!("rules registry rejected: {}", error),
            );
            return;
        }
    };

    for rule in registry
        .rules
        .into_iter()
        .filter(|rule| evaluate(rule, &event))
    {
        let ctx = config.clone();
        let node = node_id.clone();
        let event = event.clone();
        tokio::spawn(async move {
            let executions_file = ctx.paths.executions_file.clone();
            let max_executions = ctx.max_executions;
            let execution = run_rule(ctx, &node, rule, event).await;
            if let Err(error) = append_execution_at(&executions_file, &execution, max_executions) {
                tracing::warn!("rules execution log append failed: {}", error);
            }
        });
    }
}

pub async fn run_rule_for_test(
    config: RulesConfig,
    node_id: &str,
    rule: Rule,
    event: RuleEvent,
) -> RuleExecution {
    run_rule(config, node_id, rule, event).await
}

pub fn dry_run_plan(rule: &Rule) -> Vec<ActionReport> {
    rule.effective_actions()
        .iter()
        .map(|action| {
            if action.destructive() && !rule.allow_destructive {
                downgraded_report(action)
            } else {
                dry_run_report(action)
            }
        })
        .collect()
}

async fn run_rule(
    config: RulesConfig,
    node_id: &str,
    rule: Rule,
    event: RuleEvent,
) -> RuleExecution {
    let actions = rule.effective_actions();
    let action_count = actions.len().max(1) as u32;
    let guard_decision = {
        let _guard = RULES_WRITE_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        check_and_record(&config.paths.state_file, &rule, &event, action_count)
    };

    match guard_decision {
        Ok(GuardDecision::Allowed) => {}
        Ok(decision) => {
            let execution = execution_from_reports(
                &rule,
                &event,
                vec![ActionReport {
                    action: "guard".to_string(),
                    outcome: decision.outcome().to_string(),
                    message: decision.message(),
                }],
            );
            log_audit(
                node_id,
                AuditCategory::Rules,
                AuditSeverity::Warning,
                AuditAction::Rejected,
                &format!(
                    "rules action suppressed rule={} reason={}",
                    rule.rule_id, execution.trigger_summary
                ),
            );
            return execution;
        }
        Err(error) => {
            return execution_from_reports(
                &rule,
                &event,
                vec![ActionReport {
                    action: "guard".to_string(),
                    outcome: "failed".to_string(),
                    message: error.to_string(),
                }],
            );
        }
    }

    let mut reports = Vec::with_capacity(actions.len());
    if config.dry_run {
        reports = dry_run_plan(&rule);
    } else {
        for action in actions {
            if action.destructive() && !rule.allow_destructive {
                let report = downgraded_report(&action);
                log_audit(
                    node_id,
                    AuditCategory::Rules,
                    AuditSeverity::Critical,
                    AuditAction::Rejected,
                    &format!(
                        "destructive rules action downgraded rule={} action={}",
                        rule.rule_id,
                        action.label()
                    ),
                );
                reports.push(report);
                reports.push(
                    execute_action(
                        &config,
                        node_id,
                        &rule,
                        &event,
                        &crate::rules::model::RuleAction::RaiseAlert {
                            severity: "critical".to_string(),
                        },
                    )
                    .await,
                );
                continue;
            }
            reports.push(execute_action(&config, node_id, &rule, &event, &action).await);
        }
    }

    let execution = execution_from_reports(&rule, &event, reports);
    let severity = match execution.outcome.as_str() {
        "failed" | "downgraded" => AuditSeverity::Critical,
        "rate-limited" => AuditSeverity::Warning,
        _ => AuditSeverity::Info,
    };
    log_audit(
        node_id,
        AuditCategory::Rules,
        severity,
        AuditAction::Succeeded,
        &format!(
            "rules execution rule={} outcome={} actions={}",
            execution.rule_id,
            execution.outcome,
            execution.actions.join(",")
        ),
    );
    execution
}

fn execution_from_reports(
    rule: &Rule,
    event: &RuleEvent,
    reports: Vec<ActionReport>,
) -> RuleExecution {
    let outcome = aggregate_outcome(&reports);
    RuleExecution {
        id: format!("urn:uuid:{}", Uuid::new_v4()),
        rule_id: rule.rule_id.clone(),
        rule_name: rule.name.clone(),
        trigger_summary: event.summary(),
        actions: reports
            .into_iter()
            .map(|report| format!("{}: {}", report.action, report.message))
            .collect(),
        outcome,
        at: Utc::now().to_rfc3339(),
    }
}

fn aggregate_outcome(reports: &[ActionReport]) -> String {
    if reports.iter().any(|report| report.outcome == "failed") {
        return "failed".to_string();
    }
    if reports
        .iter()
        .any(|report| report.outcome == "rate-limited")
    {
        return "rate-limited".to_string();
    }
    if reports.iter().any(|report| report.outcome == "downgraded") {
        return "downgraded".to_string();
    }
    if reports.iter().all(|report| report.outcome == "dry-run") {
        return "dry-run".to_string();
    }
    "executed".to_string()
}

pub fn append_execution(execution: &RuleExecution) -> RulesResult<()> {
    let paths = RulesPaths::from_env();
    append_execution_at(
        &paths.executions_file,
        execution,
        crate::rules::RulesConfig::from_env().max_executions,
    )
}

pub fn append_execution_at(path: &Path, execution: &RuleExecution, cap: usize) -> RulesResult<()> {
    let _guard = RULES_WRITE_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut executions = list_executions_at(path, Some(cap.saturating_sub(1)))?;
    executions.push(execution.clone());
    let mut bytes = Vec::new();
    for item in executions {
        serde_json::to_writer(&mut bytes, &item)?;
        bytes.push(b'\n');
    }
    write_atomic(path, &bytes)
}

pub fn list_executions(limit: Option<usize>) -> RulesResult<Vec<RuleExecution>> {
    let paths = RulesPaths::from_env();
    list_executions_at(&paths.executions_file, limit)
}

pub fn list_executions_at(path: &Path, limit: Option<usize>) -> RulesResult<Vec<RuleExecution>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        out.push(serde_json::from_str::<RuleExecution>(line)?);
    }
    if let Some(limit) = limit {
        if out.len() > limit {
            out.drain(..out.len() - limit);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::model::{Condition, RuleAction, RuleDraft};

    fn test_config(base: &std::path::Path, dry_run: bool) -> RulesConfig {
        RulesConfig {
            paths: RulesPaths::from_base(base.join("rules_base")),
            dry_run,
            max_executions: 100,
            threat_config_path: base.join("threat_config.yaml"),
            threat_state_dir: base.join("threat_state"),
            discovery_config_path: base.join("discovery.yaml"),
            transport_lock_dir: base.join("cot_lock"),
            transport_lock_interface: None,
        }
    }

    fn report(action: &str, outcome: &str) -> ActionReport {
        ActionReport {
            action: action.to_string(),
            outcome: outcome.to_string(),
            message: String::new(),
        }
    }

    #[test]
    fn aggregate_outcome_prioritizes_failed_over_everything_else() {
        assert_eq!(
            aggregate_outcome(&[report("a", "executed"), report("b", "failed")]),
            "failed"
        );
    }

    #[test]
    fn aggregate_outcome_prioritizes_rate_limited_over_downgraded() {
        assert_eq!(
            aggregate_outcome(&[report("a", "downgraded"), report("b", "rate-limited")]),
            "rate-limited"
        );
    }

    #[test]
    fn aggregate_outcome_is_dry_run_only_when_all_reports_are_dry_run() {
        assert_eq!(
            aggregate_outcome(&[report("a", "dry-run"), report("b", "dry-run")]),
            "dry-run"
        );
        assert_eq!(
            aggregate_outcome(&[report("a", "dry-run"), report("b", "executed")]),
            "executed"
        );
    }

    #[test]
    fn aggregate_outcome_defaults_to_executed_when_reports_are_mixed_non_dry_run() {
        assert_eq!(aggregate_outcome(&[report("a", "executed")]), "executed");
        assert_eq!(
            aggregate_outcome(&[report("a", "executed"), report("b", "executed")]),
            "executed"
        );
    }

    #[test]
    fn aggregate_outcome_on_empty_reports_is_vacuously_dry_run() {
        // `all()` over an empty slice is vacuously true, so an empty report
        // list takes the dry-run branch before falling through to "executed".
        assert_eq!(aggregate_outcome(&[]), "dry-run");
    }

    fn sample_execution(id: &str) -> RuleExecution {
        RuleExecution {
            id: id.to_string(),
            rule_id: "r".to_string(),
            rule_name: "r".to_string(),
            trigger_summary: "t".to_string(),
            actions: vec![],
            outcome: "executed".to_string(),
            at: Utc::now().to_rfc3339(),
        }
    }

    // ---- dry_run_plan ----------------------------------------------------------------

    #[test]
    fn dry_run_plan_downgrades_destructive_actions_without_allow_destructive() {
        let rule = Rule::from_draft(RuleDraft {
            name: Some("r".to_string()),
            condition: Some(Condition::All(Vec::new())),
            actions: Some(vec![
                RuleAction::LockTransport,
                RuleAction::Notify {
                    severity: "info".to_string(),
                },
            ]),
            allow_destructive: Some(false),
            ..RuleDraft::default()
        });
        let plan = dry_run_plan(&rule);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].outcome, "downgraded");
        assert_eq!(plan[1].outcome, "dry-run");
    }

    #[test]
    fn dry_run_plan_keeps_destructive_actions_as_dry_run_when_allowed() {
        let rule = Rule::from_draft(RuleDraft {
            actions: Some(vec![RuleAction::LockTransport]),
            allow_destructive: Some(true),
            ..RuleDraft::default()
        });
        let plan = dry_run_plan(&rule);
        assert_eq!(plan[0].outcome, "dry-run");
    }

    // ---- run_rule_for_test: guard decisions -------------------------------------------

    #[tokio::test]
    async fn run_rule_for_test_dry_run_reports_dry_run_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path(), true);
        let rule = Rule::from_draft(RuleDraft {
            name: Some("dry rule".to_string()),
            condition: Some(Condition::All(Vec::new())),
            actions: Some(vec![RuleAction::Notify {
                severity: "info".to_string(),
            }]),
            ..RuleDraft::default()
        });
        let event = RuleEvent::sample_threat("node-1");

        let execution = run_rule_for_test(config, "node-1", rule.clone(), event).await;
        assert_eq!(execution.outcome, "dry-run");
        assert_eq!(execution.rule_id, rule.rule_id);
    }

    #[tokio::test]
    async fn run_rule_for_test_reports_rate_limited_when_cooldown_active() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path(), true);
        let rule = Rule::from_draft(RuleDraft {
            name: Some("cooldown rule".to_string()),
            condition: Some(Condition::All(Vec::new())),
            cooldown_secs: Some(3600),
            actions: Some(vec![RuleAction::Notify {
                severity: "info".to_string(),
            }]),
            ..RuleDraft::default()
        });
        let event = RuleEvent::sample_threat("node-1");

        let first = run_rule_for_test(config.clone(), "node-1", rule.clone(), event.clone()).await;
        assert_eq!(first.outcome, "dry-run");

        let second = run_rule_for_test(config.clone(), "node-1", rule.clone(), event.clone()).await;
        assert_eq!(second.outcome, "rate-limited");
        assert!(second.actions[0].contains("cooldown"));
    }

    #[tokio::test]
    async fn run_rule_for_test_reports_rate_limited_when_action_cap_exceeded() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path(), true);
        let rule = Rule::from_draft(RuleDraft {
            name: Some("rate rule".to_string()),
            condition: Some(Condition::All(Vec::new())),
            cooldown_secs: Some(1),
            max_actions_per_hour: Some(1),
            actions: Some(vec![RuleAction::Notify {
                severity: "info".to_string(),
            }]),
            ..RuleDraft::default()
        });
        let event1 = RuleEvent::sample_threat("node-1");
        let mut event2 = event1.clone();
        if let RuleEvent::ThreatAlert { alert, .. } = &mut event2 {
            alert.src_ip = "203.0.113.99".to_string();
        }

        let first = run_rule_for_test(config.clone(), "node-1", rule.clone(), event1).await;
        assert_eq!(first.outcome, "dry-run");

        let second = run_rule_for_test(config.clone(), "node-1", rule.clone(), event2).await;
        assert_eq!(second.outcome, "rate-limited");
    }

    #[tokio::test]
    async fn run_rule_for_test_reports_failed_when_guard_state_is_corrupted() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path(), true);
        std::fs::create_dir_all(&config.paths.base).unwrap();
        std::fs::write(&config.paths.state_file, b"not json").unwrap();

        let rule = Rule::from_draft(RuleDraft {
            name: Some("corrupt".to_string()),
            condition: Some(Condition::All(Vec::new())),
            ..RuleDraft::default()
        });
        let event = RuleEvent::sample_threat("node-1");

        let execution = run_rule_for_test(config, "node-1", rule, event).await;
        assert_eq!(execution.outcome, "failed");
    }

    // ---- run_rule_for_test: live (non-dry-run) dispatch -------------------------------

    #[tokio::test]
    async fn run_rule_for_test_downgrades_destructive_action_when_not_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path(), false);
        let rule = Rule::from_draft(RuleDraft {
            name: Some("destructive".to_string()),
            condition: Some(Condition::All(Vec::new())),
            actions: Some(vec![RuleAction::LockTransport]),
            allow_destructive: Some(false),
            ..RuleDraft::default()
        });
        let event = RuleEvent::sample_threat("node-1");

        let execution = run_rule_for_test(config, "node-1", rule, event).await;
        assert_eq!(execution.outcome, "downgraded");
        // downgraded_report(LockTransport) + the RaiseAlert(critical) fallback report.
        assert_eq!(execution.actions.len(), 2);
    }

    #[tokio::test]
    async fn run_rule_for_test_executes_non_destructive_action_when_live() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path(), false);
        let rule = Rule::from_draft(RuleDraft {
            name: Some("live notify".to_string()),
            condition: Some(Condition::All(Vec::new())),
            actions: Some(vec![RuleAction::Notify {
                severity: "info".to_string(),
            }]),
            ..RuleDraft::default()
        });
        let event = RuleEvent::sample_threat("node-1");

        let execution = run_rule_for_test(config, "node-1", rule, event).await;
        assert_eq!(execution.outcome, "executed");
    }

    #[tokio::test]
    async fn run_rule_for_test_runs_destructive_action_directly_when_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = test_config(dir.path(), false);
        // LockTransport only ever writes a marker file under transport_lock_dir; it
        // never touches a real network interface, so this stays fully offline.
        config.transport_lock_interface = Some("eth0".to_string());
        let rule = Rule::from_draft(RuleDraft {
            name: Some("allowed destructive".to_string()),
            condition: Some(Condition::All(Vec::new())),
            actions: Some(vec![RuleAction::LockTransport]),
            allow_destructive: Some(true),
            ..RuleDraft::default()
        });
        let event = RuleEvent::sample_threat("node-1");

        let execution = run_rule_for_test(config, "node-1", rule, event).await;
        assert_eq!(execution.outcome, "executed");
    }

    // ---- process_event -----------------------------------------------------------------

    #[tokio::test]
    async fn process_event_completes_without_panicking_when_no_rules_registry_exists() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path(), true);
        let event = RuleEvent::sample_threat("node-1");
        // No rules.json present, so load_registry short-circuits to an empty default
        // registry without needing a real device key manager; the match loop has zero
        // iterations and nothing is spawned.
        process_event(config, "node-1".to_string(), event).await;
    }

    // ---- append_execution_at / list_executions_at --------------------------------------

    #[test]
    fn list_executions_at_returns_empty_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("executions.jsonl");
        let out = list_executions_at(&path, None).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn append_execution_at_appends_and_truncates_to_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("executions.jsonl");
        for i in 0..5 {
            append_execution_at(&path, &sample_execution(&format!("id-{}", i)), 3).unwrap();
        }
        let out = list_executions_at(&path, None).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].id, "id-2");
        assert_eq!(out[2].id, "id-4");
    }

    #[test]
    fn list_executions_at_limit_returns_most_recent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("executions.jsonl");
        for i in 0..5 {
            append_execution_at(&path, &sample_execution(&format!("id-{}", i)), 100).unwrap();
        }
        let limited = list_executions_at(&path, Some(2)).unwrap();
        assert_eq!(limited.len(), 2);
        assert_eq!(limited[0].id, "id-3");
        assert_eq!(limited[1].id, "id-4");
    }

    #[test]
    fn list_executions_at_surfaces_error_on_corrupted_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("executions.jsonl");
        std::fs::write(&path, "not valid json\n").unwrap();
        let result = list_executions_at(&path, None);
        assert!(result.is_err());
    }

    #[test]
    fn execution_from_reports_formats_actions_and_trigger_summary() {
        let rule = Rule::from_draft(RuleDraft {
            name: Some("My Rule".to_string()),
            condition: Some(Condition::All(Vec::new())),
            ..RuleDraft::default()
        });
        let event = RuleEvent::sample_threat("nodeA");

        let execution = execution_from_reports(
            &rule,
            &event,
            vec![report("BlockIp", "executed"), report("Notify", "failed")],
        );

        assert_eq!(execution.rule_id, rule.rule_id);
        assert_eq!(execution.rule_name, "My Rule");
        assert_eq!(execution.trigger_summary, event.summary());
        assert_eq!(
            execution.actions,
            vec!["BlockIp: ".to_string(), "Notify: ".to_string()]
        );
        assert_eq!(execution.outcome, "failed");
    }
}
