use serde_json::json;
use sgx_guardian_client::automation::conflict::ConflictResolver;
use sgx_guardian_client::automation::schema::{
    AutomationRule, FailurePolicy, RuleAction, RuleCondition, RuleTrigger,
};
use sgx_guardian_client::homeassistant::events::{EventBus, HaEvent};

#[tokio::test]
async fn test_event_bus_multicast_routing() {
    let bus = EventBus::new();
    let mut receiver_a = bus.subscribe();
    let mut receiver_b = bus.subscribe();

    let notification = HaEvent::NotificationCreated {
        id: "alert-motion-1".into(),
        title: "Motion Detected".into(),
        message: "Living room motion sensor active".into(),
        severity: "warning".into(),
    };

    bus.publish(notification);

    let event_a = receiver_a.recv().await.expect("receive on bus A");
    let event_b = receiver_b.recv().await.expect("receive on bus B");

    match (event_a, event_b) {
        (
            HaEvent::NotificationCreated { id: id1, title: t1, .. },
            HaEvent::NotificationCreated { id: id2, title: t2, .. },
        ) => {
            assert_eq!(id1, "alert-motion-1");
            assert_eq!(id2, "alert-motion-1");
            assert_eq!(t1, "Motion Detected");
            assert_eq!(t2, "Motion Detected");
        }
        _ => panic!("Expected NotificationCreated events"),
    }
}

#[test]
fn test_conflict_resolver_priority_and_contradiction() {
    // Rule 1: High Priority (100) -> turn_on living room light
    let rule_high = AutomationRule {
        id: "rule-motion-on".into(),
        name: "Turn On Light On Motion".into(),
        priority: 100,
        enabled: true,
        trigger: RuleTrigger::StateChanged {
            entity_id: "binary_sensor.motion".into(),
            to_state: Some("on".into()),
        },
        conditions: vec![RuleCondition::State {
            entity_id: "sun.sun".into(),
            operator: "equals".into(),
            value: "below_horizon".into(),
        }],
        actions: vec![RuleAction::Command {
            entity_id: "light.living_room".into(),
            domain: "light".into(),
            command: "turn_on".into(),
            service_data: Some(json!({ "brightness": 200 })),
            on_failure: FailurePolicy::Continue,
        }],
    };

    // Rule 2: Low Priority (50) -> turn_off living room light
    let rule_low = AutomationRule {
        id: "rule-night-off".into(),
        name: "Turn Off Light At Night".into(),
        priority: 50,
        enabled: true,
        trigger: RuleTrigger::StateChanged {
            entity_id: "time.midnight".into(),
            to_state: None,
        },
        conditions: vec![],
        actions: vec![RuleAction::Command {
            entity_id: "light.living_room".into(),
            domain: "light".into(),
            command: "turn_off".into(),
            service_data: None,
            on_failure: FailurePolicy::Log,
        }],
    };

    // ConflictResolver must select the higher priority action
    let resolved = ConflictResolver::resolve_conflicts(vec![rule_low.clone(), rule_high.clone()]);
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].0.id, "rule-motion-on");

    match &resolved[0].1 {
        RuleAction::Command { command, .. } => assert_eq!(command, "turn_on"),
        _ => panic!("Expected Command action"),
    }

    // Contradiction at equal priority (both priority 100)
    let mut rule_conflicting = rule_low.clone();
    rule_conflicting.priority = 100;

    let conflicting_resolved =
        ConflictResolver::resolve_conflicts(vec![rule_high.clone(), rule_conflicting]);

    // Contradictory commands at the same priority level are safely skipped
    assert_eq!(conflicting_resolved.len(), 0);
}

#[test]
fn test_automation_rule_serialization_roundtrip() {
    let rule = AutomationRule {
        id: "rule-away-mode".into(),
        name: "Lock Doors When Nobody Home".into(),
        priority: 80,
        enabled: true,
        trigger: RuleTrigger::StateChanged {
            entity_id: "group.family".into(),
            to_state: Some("not_home".into()),
        },
        conditions: vec![RuleCondition::Presence {
            operator: "equals".into(),
            value: "nobody_home".into(),
        }],
        actions: vec![
            RuleAction::Notification {
                message: "Securing smart home...".into(),
                severity: "info".into(),
                on_failure: FailurePolicy::Continue,
            },
            RuleAction::Delay { delay_secs: 5 },
            RuleAction::Command {
                entity_id: "lock.front_door".into(),
                domain: "lock".into(),
                command: "lock".into(),
                service_data: None,
                on_failure: FailurePolicy::Retry,
            },
        ],
    };

    let serialized = serde_json::to_string(&rule).expect("serialize rule");
    let deserialized: AutomationRule =
        serde_json::from_str(&serialized).expect("deserialize rule");

    assert_eq!(deserialized.id, "rule-away-mode");
    assert_eq!(deserialized.actions.len(), 3);
    assert_eq!(deserialized.priority, 80);
    assert!(deserialized.enabled);
}
