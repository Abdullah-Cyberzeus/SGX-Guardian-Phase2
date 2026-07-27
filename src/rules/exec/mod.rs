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
    use crate::rules::model::{Condition, RuleDraft};

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
