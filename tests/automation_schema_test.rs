use sgx_guardian_client::automation::schema::{
    AutomationRule, FailurePolicy, RuleAction, RuleCondition, RuleTrigger,
};

fn rule_json(extra: &str) -> String {
    format!(
        r#"{{
            "id":"r1",
            "name":"Rule One",
            {extra}
            "trigger":{{"type":"state_changed","entity_id":"light.kitchen","to_state":"on"}},
            "actions":[{{"type":"delay","delay_secs":5}}]
        }}"#
    )
}

#[test]
fn failure_policy_default_is_continue() {
    assert_eq!(FailurePolicy::default(), FailurePolicy::Continue);
}

#[test]
fn failure_policy_continue_serializes_lowercase() {
    assert_eq!(serde_json::to_string(&FailurePolicy::Continue).unwrap(), "\"continue\"");
}

#[test]
fn failure_policy_abort_serializes_lowercase() {
    assert_eq!(serde_json::to_string(&FailurePolicy::Abort).unwrap(), "\"abort\"");
}

#[test]
fn failure_policy_log_serializes_lowercase() {
    assert_eq!(serde_json::to_string(&FailurePolicy::Log).unwrap(), "\"log\"");
}

#[test]
fn failure_policy_retry_serializes_lowercase() {
    assert_eq!(serde_json::to_string(&FailurePolicy::Retry).unwrap(), "\"retry\"");
}

#[test]
fn failure_policy_rejects_unknown() {
    assert!(serde_json::from_str::<FailurePolicy>("\"unknown\"").is_err());
}

#[test]
fn trigger_state_changed_round_trips_with_state() {
    let trigger = RuleTrigger::StateChanged {
        entity_id: "switch.a".into(),
        to_state: Some("on".into()),
    };
    assert_eq!(serde_json::from_value::<RuleTrigger>(serde_json::to_value(&trigger).unwrap()).unwrap(), trigger);
}

#[test]
fn trigger_state_changed_round_trips_without_state() {
    let trigger = RuleTrigger::StateChanged {
        entity_id: "switch.a".into(),
        to_state: None,
    };
    assert_eq!(serde_json::from_value::<RuleTrigger>(serde_json::to_value(&trigger).unwrap()).unwrap(), trigger);
}

#[test]
fn trigger_rejects_missing_type() {
    assert!(serde_json::from_str::<RuleTrigger>(r#"{"entity_id":"x"}"#).is_err());
}

#[test]
fn trigger_rejects_unknown_type() {
    assert!(serde_json::from_str::<RuleTrigger>(r#"{"type":"time","entity_id":"x"}"#).is_err());
}

#[test]
fn condition_state_round_trips() {
    let condition = RuleCondition::State {
        entity_id: "light.a".into(),
        operator: "equals".into(),
        value: "on".into(),
    };
    assert_eq!(serde_json::from_value::<RuleCondition>(serde_json::to_value(&condition).unwrap()).unwrap(), condition);
}

#[test]
fn condition_presence_round_trips() {
    let condition = RuleCondition::Presence {
        operator: "equals".into(),
        value: "home".into(),
    };
    assert_eq!(serde_json::from_value::<RuleCondition>(serde_json::to_value(&condition).unwrap()).unwrap(), condition);
}

#[test]
fn condition_rejects_unknown_type() {
    assert!(serde_json::from_str::<RuleCondition>(r#"{"type":"bad"}"#).is_err());
}

#[test]
fn command_action_defaults_failure_policy() {
    let action: RuleAction = serde_json::from_str(
        r#"{"type":"command","entity_id":"light.a","domain":"light","command":"turn_on","service_data":null}"#,
    )
    .unwrap();
    match action {
        RuleAction::Command { on_failure, .. } => assert_eq!(on_failure, FailurePolicy::Continue),
        _ => panic!("expected command"),
    }
}

#[test]
fn command_action_preserves_service_data() {
    let action: RuleAction = serde_json::from_str(
        r#"{"type":"command","entity_id":"light.a","domain":"light","command":"turn_on","service_data":{"brightness":10}}"#,
    )
    .unwrap();
    match action {
        RuleAction::Command { service_data, .. } => assert_eq!(service_data.unwrap()["brightness"], 10),
        _ => panic!("expected command"),
    }
}

#[test]
fn notification_action_defaults_failure_policy() {
    let action: RuleAction = serde_json::from_str(
        r#"{"type":"notification","message":"m","severity":"info"}"#,
    )
    .unwrap();
    match action {
        RuleAction::Notification { on_failure, .. } => assert_eq!(on_failure, FailurePolicy::Continue),
        _ => panic!("expected notification"),
    }
}

#[test]
fn notification_action_round_trips() {
    let action = RuleAction::Notification {
        message: "m".into(),
        severity: "critical".into(),
        on_failure: FailurePolicy::Log,
    };
    assert_eq!(serde_json::from_value::<RuleAction>(serde_json::to_value(&action).unwrap()).unwrap(), action);
}

#[test]
fn delay_action_accepts_zero_boundary() {
    let action: RuleAction = serde_json::from_str(r#"{"type":"delay","delay_secs":0}"#).unwrap();
    assert_eq!(action, RuleAction::Delay { delay_secs: 0 });
}

#[test]
fn delay_action_accepts_u64_max_boundary() {
    let action = RuleAction::Delay { delay_secs: u64::MAX };
    assert_eq!(serde_json::from_value::<RuleAction>(serde_json::to_value(&action).unwrap()).unwrap(), action);
}

#[test]
fn action_rejects_unknown_type() {
    assert!(serde_json::from_str::<RuleAction>(r#"{"type":"bad"}"#).is_err());
}

#[test]
fn rule_defaults_priority_and_enabled() {
    let rule: AutomationRule = serde_json::from_str(&rule_json("")).unwrap();
    assert_eq!(rule.priority, 100);
    assert!(rule.enabled);
}

#[test]
fn rule_preserves_explicit_priority_and_enabled() {
    let rule: AutomationRule =
        serde_json::from_str(&rule_json(r#""priority":-5,"enabled":false,"#)).unwrap();
    assert_eq!(rule.priority, -5);
    assert!(!rule.enabled);
}

#[test]
fn rule_defaults_conditions_empty() {
    let rule: AutomationRule = serde_json::from_str(&rule_json("")).unwrap();
    assert!(rule.conditions.is_empty());
}

#[test]
fn rule_requires_actions() {
    assert!(serde_json::from_str::<AutomationRule>(
        r#"{"id":"r","name":"n","trigger":{"type":"state_changed","entity_id":"x","to_state":null}}"#
    )
    .is_err());
}

#[test]
fn rule_requires_id() {
    assert!(serde_json::from_str::<AutomationRule>(
        r#"{"name":"n","trigger":{"type":"state_changed","entity_id":"x","to_state":null},"actions":[]}"#
    )
    .is_err());
}

#[test]
fn rule_round_trips_complex_payload() {
    let rule: AutomationRule = serde_json::from_str(
        r#"{"id":"r","name":"n","priority":1,"enabled":true,
        "trigger":{"type":"state_changed","entity_id":"x","to_state":null},
        "conditions":[{"type":"presence","operator":"equals","value":"home"}],
        "actions":[{"type":"notification","message":"hi","severity":"info","on_failure":"retry"}]}"#,
    )
    .unwrap();
    assert_eq!(serde_json::from_value::<AutomationRule>(serde_json::to_value(&rule).unwrap()).unwrap(), rule);
}
