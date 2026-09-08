use sgx_guardian_client::automation::conflict::ConflictResolver;
use sgx_guardian_client::automation::schema::{
    AutomationRule, FailurePolicy, RuleAction, RuleTrigger,
};

fn command_rule(id: &str, priority: i32, entity: &str, command: &str) -> AutomationRule {
    AutomationRule {
        id: id.into(),
        name: id.into(),
        priority,
        enabled: true,
        trigger: RuleTrigger::StateChanged {
            entity_id: "input_boolean.trigger".into(),
            to_state: None,
        },
        conditions: vec![],
        actions: vec![RuleAction::Command {
            entity_id: entity.into(),
            domain: "test".into(),
            command: command.into(),
            service_data: None,
            on_failure: FailurePolicy::Continue,
        }],
    }
}

fn notification_rule(id: &str) -> AutomationRule {
    AutomationRule {
        actions: vec![RuleAction::Notification {
            message: "msg".into(),
            severity: "info".into(),
            on_failure: FailurePolicy::Continue,
        }],
        ..command_rule(id, 1, "light.a", "turn_on")
    }
}

fn ids(actions: Vec<(AutomationRule, RuleAction)>) -> Vec<String> {
    let mut values: Vec<_> = actions.into_iter().map(|(rule, _)| rule.id).collect();
    values.sort();
    values
}

#[test]
fn empty_rules_return_empty_actions() {
    assert!(ConflictResolver::resolve_conflicts(vec![]).is_empty());
}

#[test]
fn single_command_is_kept() {
    assert_eq!(
        ids(ConflictResolver::resolve_conflicts(vec![command_rule(
            "a", 1, "light.a", "turn_on"
        )])),
        vec!["a"]
    );
}

#[test]
fn higher_priority_command_wins_same_entity() {
    assert_eq!(
        ids(ConflictResolver::resolve_conflicts(vec![
            command_rule("low", 1, "light.a", "turn_off"),
            command_rule("high", 2, "light.a", "turn_on"),
        ])),
        vec!["high"]
    );
}

#[test]
fn negative_priority_can_lose_to_zero() {
    assert_eq!(
        ids(ConflictResolver::resolve_conflicts(vec![
            command_rule("neg", -1, "light.a", "turn_off"),
            command_rule("zero", 0, "light.a", "turn_on"),
        ])),
        vec!["zero"]
    );
}

#[test]
fn equal_priority_same_command_keeps_one_action() {
    assert_eq!(
        ConflictResolver::resolve_conflicts(vec![
            command_rule("a", 1, "light.a", "turn_on"),
            command_rule("b", 1, "light.a", "turn_on"),
        ])
        .len(),
        1
    );
}

#[test]
fn equal_priority_turn_on_turn_off_drops_both() {
    assert!(ConflictResolver::resolve_conflicts(vec![
        command_rule("a", 1, "light.a", "turn_on"),
        command_rule("b", 1, "light.a", "turn_off"),
    ])
    .is_empty());
}

#[test]
fn equal_priority_lock_unlock_drops_both() {
    assert!(ConflictResolver::resolve_conflicts(vec![
        command_rule("a", 1, "lock.front", "lock"),
        command_rule("b", 1, "lock.front", "unlock"),
    ])
    .is_empty());
}

#[test]
fn equal_priority_open_close_cover_drops_both() {
    assert!(ConflictResolver::resolve_conflicts(vec![
        command_rule("a", 1, "cover.door", "open_cover"),
        command_rule("b", 1, "cover.door", "close_cover"),
    ])
    .is_empty());
}

#[test]
fn non_contradictory_equal_priority_keeps_one() {
    assert_eq!(
        ConflictResolver::resolve_conflicts(vec![
            command_rule("a", 1, "light.a", "turn_on"),
            command_rule("b", 1, "light.a", "blink"),
        ])
        .len(),
        1
    );
}

#[test]
fn different_entities_both_commands_kept() {
    assert_eq!(
        ids(ConflictResolver::resolve_conflicts(vec![
            command_rule("a", 1, "light.a", "turn_on"),
            command_rule("b", 1, "light.b", "turn_off"),
        ])),
        vec!["a", "b"]
    );
}

#[test]
fn notification_action_is_kept() {
    assert_eq!(
        ids(ConflictResolver::resolve_conflicts(vec![
            notification_rule("n")
        ])),
        vec!["n"]
    );
}

#[test]
fn delay_action_is_kept_as_non_command() {
    let mut rule = command_rule("d", 1, "light.a", "turn_on");
    rule.actions = vec![RuleAction::Delay { delay_secs: 1 }];
    assert_eq!(
        ids(ConflictResolver::resolve_conflicts(vec![rule])),
        vec!["d"]
    );
}

#[test]
fn non_command_survives_command_conflict() {
    assert_eq!(
        ids(ConflictResolver::resolve_conflicts(vec![
            command_rule("a", 1, "light.a", "turn_on"),
            command_rule("b", 1, "light.a", "turn_off"),
            notification_rule("n"),
        ])),
        vec!["n"]
    );
}

#[test]
fn rule_with_multiple_actions_emits_each_resolved_action() {
    let mut rule = command_rule("multi", 1, "light.a", "turn_on");
    rule.actions.push(RuleAction::Notification {
        message: "m".into(),
        severity: "info".into(),
        on_failure: FailurePolicy::Continue,
    });
    assert_eq!(ConflictResolver::resolve_conflicts(vec![rule]).len(), 2);
}

#[test]
fn command_entity_grouping_uses_entity_id_only() {
    assert_eq!(
        ConflictResolver::resolve_conflicts(vec![
            command_rule("light", 1, "same.entity", "turn_on"),
            command_rule("switch", 2, "same.entity", "lock"),
        ])
        .len(),
        1
    );
}

#[test]
fn command_domain_does_not_affect_conflict_group() {
    let mut a = command_rule("a", 1, "entity.same", "turn_on");
    if let RuleAction::Command { domain, .. } = &mut a.actions[0] {
        *domain = "light".into();
    }
    let mut b = command_rule("b", 2, "entity.same", "turn_off");
    if let RuleAction::Command { domain, .. } = &mut b.actions[0] {
        *domain = "switch".into();
    }
    assert_eq!(
        ids(ConflictResolver::resolve_conflicts(vec![a, b])),
        vec!["b"]
    );
}

#[test]
fn higher_priority_wins_even_when_commands_contradict() {
    assert_eq!(
        ids(ConflictResolver::resolve_conflicts(vec![
            command_rule("high", 9, "light.a", "turn_on"),
            command_rule("low", 1, "light.a", "turn_off"),
        ])),
        vec!["high"]
    );
}

#[test]
fn max_priority_wins() {
    assert_eq!(
        ids(ConflictResolver::resolve_conflicts(vec![
            command_rule("max", i32::MAX, "light.a", "turn_on"),
            command_rule("low", i32::MIN, "light.a", "turn_off"),
        ])),
        vec!["max"]
    );
}

#[test]
fn empty_command_name_is_not_contradictory() {
    assert_eq!(
        ConflictResolver::resolve_conflicts(vec![
            command_rule("a", 1, "light.a", ""),
            command_rule("b", 1, "light.a", "turn_on"),
        ])
        .len(),
        1
    );
}

#[test]
fn contradiction_is_case_sensitive() {
    assert_eq!(
        ConflictResolver::resolve_conflicts(vec![
            command_rule("a", 1, "light.a", "Turn_On"),
            command_rule("b", 1, "light.a", "turn_off"),
        ])
        .len(),
        1
    );
}

#[test]
fn one_entity_conflict_does_not_drop_other_entity() {
    assert_eq!(
        ids(ConflictResolver::resolve_conflicts(vec![
            command_rule("a", 1, "light.a", "turn_on"),
            command_rule("b", 1, "light.a", "turn_off"),
            command_rule("c", 1, "light.c", "turn_on"),
        ])),
        vec!["c"]
    );
}

#[test]
fn result_contains_original_rule_priority() {
    let resolved =
        ConflictResolver::resolve_conflicts(vec![command_rule("a", 77, "light.a", "on")]);
    assert_eq!(resolved[0].0.priority, 77);
}

#[test]
fn result_contains_original_action_command() {
    let resolved =
        ConflictResolver::resolve_conflicts(vec![command_rule("a", 1, "light.a", "turn_on")]);
    match &resolved[0].1 {
        RuleAction::Command { command, .. } => assert_eq!(command, "turn_on"),
        _ => panic!("expected command"),
    }
}

#[test]
fn disabled_rules_are_still_processed_if_supplied() {
    let mut rule = command_rule("disabled", 1, "light.a", "turn_on");
    rule.enabled = false;
    assert_eq!(
        ids(ConflictResolver::resolve_conflicts(vec![rule])),
        vec!["disabled"]
    );
}

#[test]
fn service_data_is_preserved() {
    let mut rule = command_rule("a", 1, "light.a", "turn_on");
    if let RuleAction::Command { service_data, .. } = &mut rule.actions[0] {
        *service_data = Some(serde_json::json!({"brightness": 10}));
    }
    let resolved = ConflictResolver::resolve_conflicts(vec![rule]);
    match &resolved[0].1 {
        RuleAction::Command { service_data, .. } => {
            assert_eq!(service_data.as_ref().unwrap()["brightness"], 10)
        }
        _ => panic!("expected command"),
    }
}

#[test]
fn rule_without_actions_emits_nothing() {
    let mut rule = command_rule("empty", 1, "light.a", "turn_on");
    rule.actions.clear();
    assert!(ConflictResolver::resolve_conflicts(vec![rule]).is_empty());
}
