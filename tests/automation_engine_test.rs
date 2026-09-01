use std::sync::Arc;

use sgx_guardian_client::automation::engine::AutomationEngine;
use sgx_guardian_client::automation::presence::PresenceTracker;
use sgx_guardian_client::automation::schema::{
    AutomationRule, FailurePolicy, RuleAction, RuleCondition, RuleTrigger,
};
use sgx_guardian_client::automation::timer_store::PendingActionStore;
use sgx_guardian_client::device::manager::DeviceManager;
use sgx_guardian_client::device::registry::DeviceRegistry;
use sgx_guardian_client::homeassistant::events::EventBus;
use sgx_guardian_client::homeassistant::rest::HaRestClient;
use sgx_guardian_client::homeassistant::HomeAssistantConfig;

fn rule(id: &str) -> AutomationRule {
    AutomationRule {
        id: id.into(),
        name: format!("Rule {id}"),
        priority: 100,
        enabled: true,
        trigger: RuleTrigger::StateChanged {
            entity_id: "light.kitchen".into(),
            to_state: Some("on".into()),
        },
        conditions: vec![],
        actions: vec![RuleAction::Notification {
            message: "hello".into(),
            severity: "info".into(),
            on_failure: FailurePolicy::Continue,
        }],
    }
}

fn engine(path: &str) -> Arc<AutomationEngine> {
    let dir = tempfile::tempdir().unwrap();
    let registry_path = dir.path().join("devices.json");
    let registry = Arc::new(DeviceRegistry::new(registry_path.to_str().unwrap()));
    let rest = Arc::new(HaRestClient::new(HomeAssistantConfig {
        url: "http://127.0.0.1:9".into(),
        token: "token".into(),
    }));
    let bus = EventBus::new();
    let manager = DeviceManager::new(registry, rest, bus.clone(), None);
    let timer_file = tempfile::NamedTempFile::new().unwrap();
    AutomationEngine::new(
        path,
        manager,
        PresenceTracker::new(),
        PendingActionStore::new(timer_file.path().to_str().unwrap()),
        bus,
    )
}

#[tokio::test]
async fn missing_config_initializes_default_rule() {
    let dir = tempfile::tempdir().unwrap();
    let e = engine(dir.path().join("automations.json").to_str().unwrap());
    assert_eq!(e.get_rules().await.len(), 1);
}

#[tokio::test]
async fn empty_config_initializes_default_rule() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let e = engine(file.path().to_str().unwrap());
    assert_eq!(e.get_rules().await[0].id, "rule_sync_toggles");
}

#[tokio::test]
async fn malformed_config_initializes_default_rule() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), b"{").unwrap();
    let e = engine(file.path().to_str().unwrap());
    assert_eq!(e.get_rules().await[0].id, "rule_sync_toggles");
}

#[tokio::test]
async fn valid_config_loads_rules() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), serde_json::to_vec(&serde_json::json!({"rules":[rule("a")]})).unwrap()).unwrap();
    let e = engine(file.path().to_str().unwrap());
    assert_eq!(e.get_rules().await[0].id, "a");
}

#[tokio::test]
async fn wrong_shape_config_initializes_default_rule() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), br#"{"items":[]}"#).unwrap();
    let e = engine(file.path().to_str().unwrap());
    assert_eq!(e.get_rules().await[0].id, "rule_sync_toggles");
}

#[tokio::test]
async fn add_rule_appends_rule() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let e = engine(file.path().to_str().unwrap());
    e.add_rule(rule("a")).await.unwrap();
    assert!(e.get_rules().await.iter().any(|r| r.id == "a"));
}

#[tokio::test]
async fn add_rule_replaces_existing_id() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let e = engine(file.path().to_str().unwrap());
    e.add_rule(rule("a")).await.unwrap();
    let mut replacement = rule("a");
    replacement.name = "Replacement".into();
    e.add_rule(replacement).await.unwrap();
    assert_eq!(e.get_rules().await.iter().filter(|r| r.id == "a").count(), 1);
    assert_eq!(e.get_rules().await.iter().find(|r| r.id == "a").unwrap().name, "Replacement");
}

#[tokio::test]
async fn add_rule_persists_to_file() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let e = engine(file.path().to_str().unwrap());
    e.add_rule(rule("a")).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(file.path()).unwrap()).unwrap();
    assert!(value["rules"].as_array().unwrap().iter().any(|r| r["id"] == "a"));
}

#[tokio::test]
async fn update_rule_changes_existing_rule() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let e = engine(file.path().to_str().unwrap());
    e.add_rule(rule("a")).await.unwrap();
    let mut updated = rule("a");
    updated.priority = 5;
    e.update_rule(updated).await.unwrap();
    assert_eq!(e.get_rules().await.iter().find(|r| r.id == "a").unwrap().priority, 5);
}

#[tokio::test]
async fn update_missing_rule_returns_error() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let err = engine(file.path().to_str().unwrap()).update_rule(rule("missing")).await.unwrap_err();
    assert!(err.contains("not found"));
}

#[tokio::test]
async fn delete_rule_removes_existing_rule() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let e = engine(file.path().to_str().unwrap());
    e.add_rule(rule("a")).await.unwrap();
    e.delete_rule("a").await.unwrap();
    assert!(!e.get_rules().await.iter().any(|r| r.id == "a"));
}

#[tokio::test]
async fn delete_missing_rule_returns_error() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let err = engine(file.path().to_str().unwrap()).delete_rule("missing").await.unwrap_err();
    assert!(err.contains("missing"));
}

#[tokio::test]
async fn toggle_rule_false_disables_rule() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let e = engine(file.path().to_str().unwrap());
    e.add_rule(rule("a")).await.unwrap();
    e.toggle_rule("a", false).await.unwrap();
    assert!(!e.get_rules().await.iter().find(|r| r.id == "a").unwrap().enabled);
}

#[tokio::test]
async fn toggle_rule_true_enables_rule() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let e = engine(file.path().to_str().unwrap());
    let mut r = rule("a");
    r.enabled = false;
    e.add_rule(r).await.unwrap();
    e.toggle_rule("a", true).await.unwrap();
    assert!(e.get_rules().await.iter().find(|r| r.id == "a").unwrap().enabled);
}

#[tokio::test]
async fn toggle_missing_rule_returns_error() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let err = engine(file.path().to_str().unwrap()).toggle_rule("missing", false).await.unwrap_err();
    assert!(err.contains("missing"));
}

#[tokio::test]
async fn get_rules_returns_clone() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let e = engine(file.path().to_str().unwrap());
    let mut rules = e.get_rules().await;
    rules.clear();
    assert!(!e.get_rules().await.is_empty());
}

#[tokio::test]
async fn add_rule_with_empty_id_is_allowed() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let e = engine(file.path().to_str().unwrap());
    e.add_rule(rule("")).await.unwrap();
    assert!(e.get_rules().await.iter().any(|r| r.id.is_empty()));
}

#[tokio::test]
async fn add_rule_with_negative_priority_is_preserved() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let e = engine(file.path().to_str().unwrap());
    let mut r = rule("a");
    r.priority = -50;
    e.add_rule(r).await.unwrap();
    assert_eq!(e.get_rules().await.iter().find(|r| r.id == "a").unwrap().priority, -50);
}

#[tokio::test]
async fn add_rule_with_no_actions_is_preserved() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let e = engine(file.path().to_str().unwrap());
    let mut r = rule("a");
    r.actions.clear();
    e.add_rule(r).await.unwrap();
    assert!(e.get_rules().await.iter().find(|r| r.id == "a").unwrap().actions.is_empty());
}

#[tokio::test]
async fn add_rule_with_presence_condition_is_preserved() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let e = engine(file.path().to_str().unwrap());
    let mut r = rule("a");
    r.conditions = vec![RuleCondition::Presence {
        operator: "equals".into(),
        value: "home".into(),
    }];
    e.add_rule(r).await.unwrap();
    assert_eq!(e.get_rules().await.iter().find(|r| r.id == "a").unwrap().conditions.len(), 1);
}

#[tokio::test]
async fn add_rule_with_command_action_is_preserved() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let e = engine(file.path().to_str().unwrap());
    let mut r = rule("a");
    r.actions = vec![RuleAction::Command {
        entity_id: "switch.a".into(),
        domain: "switch".into(),
        command: "turn_off".into(),
        service_data: None,
        on_failure: FailurePolicy::Abort,
    }];
    e.add_rule(r).await.unwrap();
    assert!(matches!(e.get_rules().await.iter().find(|r| r.id == "a").unwrap().actions[0], RuleAction::Command { .. }));
}

#[tokio::test]
async fn add_rule_with_delay_action_is_preserved() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let e = engine(file.path().to_str().unwrap());
    let mut r = rule("a");
    r.actions = vec![RuleAction::Delay { delay_secs: 0 }];
    e.add_rule(r).await.unwrap();
    assert_eq!(e.get_rules().await.iter().find(|r| r.id == "a").unwrap().actions[0], RuleAction::Delay { delay_secs: 0 });
}

#[tokio::test]
async fn update_persists_across_new_engine() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let path = file.path().to_str().unwrap().to_string();
    let e = engine(&path);
    e.add_rule(rule("a")).await.unwrap();
    let mut updated = rule("a");
    updated.name = "Updated".into();
    e.update_rule(updated).await.unwrap();
    assert_eq!(engine(&path).get_rules().await.iter().find(|r| r.id == "a").unwrap().name, "Updated");
}

#[tokio::test]
async fn delete_persists_across_new_engine() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let path = file.path().to_str().unwrap().to_string();
    let e = engine(&path);
    e.add_rule(rule("a")).await.unwrap();
    e.delete_rule("a").await.unwrap();
    assert!(!engine(&path).get_rules().await.iter().any(|r| r.id == "a"));
}

#[tokio::test]
async fn toggle_persists_across_new_engine() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let path = file.path().to_str().unwrap().to_string();
    let e = engine(&path);
    e.add_rule(rule("a")).await.unwrap();
    e.toggle_rule("a", false).await.unwrap();
    assert!(!engine(&path).get_rules().await.iter().find(|r| r.id == "a").unwrap().enabled);
}

#[tokio::test]
async fn restore_pending_timers_with_empty_store_returns_quickly() {
    let file = tempfile::NamedTempFile::new().unwrap();
    engine(file.path().to_str().unwrap()).restore_pending_timers().await;
}

#[tokio::test]
async fn start_returns_after_spawning_loop() {
    let file = tempfile::NamedTempFile::new().unwrap();
    engine(file.path().to_str().unwrap()).start().await;
}
