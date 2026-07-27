use sgx_guardian_client::rules::model::{RuleAction, RuleDraft};
use sgx_guardian_client::rules::{exec, Condition, Rule, RuleEvent, RulesConfig};

fn config(dir: &std::path::Path) -> RulesConfig {
    RulesConfig {
        paths: sgx_guardian_client::rules::persistence::RulesPaths::from_base(dir.join("rules")),
        dry_run: true,
        max_executions: 2000,
        threat_config_path: dir.join("threat/config.yaml"),
        threat_state_dir: dir.join("threat"),
        discovery_config_path: dir.join("discovery/nmap.yaml"),
        transport_lock_dir: dir.join("cot"),
        transport_lock_interface: None,
    }
}

#[tokio::test]
async fn dry_run_does_not_execute_actions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rule = Rule::from_draft(RuleDraft {
        name: Some("Dry run block".to_string()),
        condition: Some(Condition::All(Vec::new())),
        actions: Some(vec![RuleAction::BlockIp { ttl_secs: Some(60) }]),
        ..RuleDraft::default()
    });

    let execution = exec::run_rule_for_test(
        config(dir.path()),
        "nodeA",
        rule,
        RuleEvent::sample_threat("nodeA"),
    )
    .await;

    assert_eq!(execution.outcome, "dry-run");
    assert!(execution.actions[0].contains("would-run"));
    assert!(!dir.path().join("threat/blocked_ips.json").exists());
}

#[tokio::test]
async fn destructive_action_without_opt_in_is_downgraded_in_plan() {
    let rule = Rule::from_draft(RuleDraft {
        name: Some("No rotate".to_string()),
        actions: Some(vec![RuleAction::EmergencyKeyRotation]),
        allow_destructive: Some(false),
        ..RuleDraft::default()
    });

    let reports = exec::dry_run_plan(&rule);
    assert_eq!(reports[0].outcome, "downgraded");
}
