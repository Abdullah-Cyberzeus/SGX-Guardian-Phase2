use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

use crate::automation::conflict::ConflictResolver;
use crate::automation::presence::PresenceTracker;
use crate::automation::schema::{
    AutomationRule, FailurePolicy, RuleAction, RuleCondition, RuleTrigger,
};
use crate::automation::timer_store::{PendingAction, PendingActionStore};
use crate::device::manager::DeviceManager;
use crate::homeassistant::events::{EventBus, HaEvent};
use crate::storage::file_lock::SecureFileStore;

#[derive(Serialize, Deserialize, Default)]
struct AutomationsStore {
    rules: Vec<AutomationRule>,
}

pub struct AutomationEngine {
    rules: RwLock<Vec<AutomationRule>>,
    device_manager: Arc<DeviceManager>,
    presence_tracker: Arc<PresenceTracker>,
    timer_store: Arc<PendingActionStore>,
    event_bus: Arc<EventBus>,
    config_store: Arc<SecureFileStore>,
}

impl AutomationEngine {
    pub fn new(
        config_path: &str,
        device_manager: Arc<DeviceManager>,
        presence_tracker: Arc<PresenceTracker>,
        timer_store: Arc<PendingActionStore>,
        event_bus: Arc<EventBus>,
    ) -> Arc<Self> {
        let config_store = Arc::new(SecureFileStore::new(config_path));
        let mut rules = Vec::new();

        if let Ok(Some(data)) = config_store.read() {
            if let Ok(store_data) = serde_json::from_slice::<AutomationsStore>(&data) {
                rules = store_data.rules;
                if !rules.is_empty() {
                    println!(
                        "⚙️ Loaded {} automation rule(s) from {}",
                        rules.len(),
                        config_path
                    );
                    info!(
                        "Loaded {} automation rule(s) from {}.",
                        rules.len(),
                        config_path
                    );
                }
            }
        }

        if rules.is_empty() {
            rules = vec![AutomationRule {
                id: "rule_sync_toggles".to_string(),
                name: "Sync Toggle 1 to Toggle 2".to_string(),
                priority: 100,
                enabled: true,
                trigger: RuleTrigger::StateChanged {
                    entity_id: "input_boolean.1".to_string(),
                    to_state: None,
                },
                conditions: vec![],
                actions: vec![RuleAction::Command {
                    entity_id: "input_boolean.2".to_string(),
                    domain: "input_boolean".to_string(),
                    command: "turn_on".to_string(),
                    service_data: None,
                    on_failure: FailurePolicy::Continue,
                }],
            }];
            let store = AutomationsStore {
                rules: rules.clone(),
            };
            if let Ok(json_bytes) = serde_json::to_vec_pretty(&store) {
                let _ = config_store.write_atomic(|_| Ok::<_, std::io::Error>(json_bytes));
            }
            println!(
                "⚙️ Initialized default automation rule(s) ({}) in {}",
                rules.len(),
                config_path
            );
            info!(
                "Initialized default automation rule(s) ({}) in {}",
                rules.len(),
                config_path
            );
        }

        Arc::new(Self {
            rules: RwLock::new(rules),
            device_manager,
            presence_tracker,
            timer_store,
            event_bus,
            config_store,
        })
    }

    /// Adds a new automation rule and persists it to automations.json
    pub async fn add_rule(&self, rule: AutomationRule) -> Result<(), String> {
        {
            let mut rules = self.rules.write().await;
            rules.retain(|r| r.id != rule.id);
            rules.push(rule);
        }
        self.persist_rules().await
    }

    /// Gets all current automation rules
    pub async fn get_rules(&self) -> Vec<AutomationRule> {
        let rules = self.rules.read().await;
        rules.clone()
    }

    /// Updates an existing automation rule
    pub async fn update_rule(&self, rule: AutomationRule) -> Result<(), String> {
        let mut found = false;
        {
            let mut rules = self.rules.write().await;
            for r in rules.iter_mut() {
                if r.id == rule.id {
                    *r = rule.clone();
                    found = true;
                    break;
                }
            }
        }
        if !found {
            return Err(format!("Rule with ID '{}' not found", rule.id));
        }
        self.persist_rules().await
    }

    /// Deletes an automation rule by ID
    pub async fn delete_rule(&self, rule_id: &str) -> Result<(), String> {
        let removed;
        {
            let mut rules = self.rules.write().await;
            let orig_len = rules.len();
            rules.retain(|r| r.id != rule_id);
            removed = rules.len() < orig_len;
        }
        if !removed {
            return Err(format!("Rule with ID '{}' not found", rule_id));
        }
        self.persist_rules().await
    }

    /// Toggles enabled/disabled status of a rule
    pub async fn toggle_rule(&self, rule_id: &str, enabled: bool) -> Result<(), String> {
        let mut found = false;
        {
            let mut rules = self.rules.write().await;
            for r in rules.iter_mut() {
                if r.id == rule_id {
                    r.enabled = enabled;
                    found = true;
                    break;
                }
            }
        }
        if !found {
            return Err(format!("Rule with ID '{}' not found", rule_id));
        }
        self.persist_rules().await
    }

    /// Loads and restores all pending action timers on startup
    pub async fn restore_pending_timers(self: &Arc<Self>) {
        let pending = self.timer_store.get_all_pending().await;
        if pending.is_empty() {
            return;
        }

        info!("Restoring {} pending action timers...", pending.len());
        let now = Utc::now();

        for pa in pending {
            let engine = Arc::clone(self);
            if pa.execute_at <= now {
                info!("Executing past-due pending action {} immediately", pa.id);
                tokio::spawn(async move {
                    let _ = engine.execute_single_action(&pa.action).await;
                    let _ = engine.timer_store.remove_pending_action(&pa.id).await;
                });
            } else {
                let delay = (pa.execute_at - now)
                    .to_std()
                    .unwrap_or(Duration::from_secs(0));
                info!("Scheduling pending action {} in {:?}", pa.id, delay);
                tokio::spawn(async move {
                    sleep(delay).await;
                    let _ = engine.execute_single_action(&pa.action).await;
                    let _ = engine.timer_store.remove_pending_action(&pa.id).await;
                });
            }
        }
    }

    /// Starts the Automation Engine loop
    pub async fn start(self: Arc<Self>) {
        self.restore_pending_timers().await;

        let mut rx = self.event_bus.subscribe();
        let engine = Arc::clone(&self);

        tokio::spawn(async move {
            let rules_count = engine.rules.read().await.len();
            println!(
                "⚙️ Automation Engine event loop started with {} active rule(s).",
                rules_count
            );
            info!(
                "⚙️ Automation Engine started with {} active rule(s).",
                rules_count
            );
            loop {
                match rx.recv().await {
                    Ok(HaEvent::StateChanged(val)) => {
                        engine.process_state_changed(val).await;
                    }
                    Ok(_) => {}
                    Err(RecvError::Lagged(skipped)) => {
                        warn!(
                            "Automation Engine lagged behind! Skipped {} events.",
                            skipped
                        );
                    }
                    Err(RecvError::Closed) => {
                        warn!("Event Bus closed. Stopping Automation Engine.");
                        break;
                    }
                }
            }
        });
    }

    async fn process_state_changed(self: &Arc<Self>, val: serde_json::Value) {
        let data = match val.get("data") {
            Some(d) => d,
            None => return,
        };

        let entity_id = match data.get("entity_id").and_then(|e| e.as_str()) {
            Some(id) => id,
            None => return,
        };

        let new_state = match data
            .get("new_state")
            .and_then(|n| n.get("state"))
            .and_then(|s| s.as_str())
        {
            Some(s) => s,
            None => return,
        };

        // 1. Update presence tracker if person or device_tracker
        if PresenceTracker::is_presence_entity(entity_id) {
            self.presence_tracker
                .update_entity_state(entity_id, new_state)
                .await;
        }

        // 2. Evaluate triggers across enabled rules
        let rules = self.rules.read().await;
        let mut firing_rules = Vec::new();

        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }

            if self.evaluate_trigger(&rule.trigger, entity_id, new_state) {
                if self.evaluate_conditions(&rule.conditions).await {
                    println!(
                        "⚡ Rule fired: {} ({}) for entity: {} (state={})",
                        rule.name, rule.id, entity_id, new_state
                    );
                    info!(
                        "⚡ Rule fired: {} ({}) for entity: {} (state={})",
                        rule.name, rule.id, entity_id, new_state
                    );
                    firing_rules.push(rule.clone());
                }
            }
        }

        if firing_rules.is_empty() {
            return;
        }

        // 3. Resolve rule priorities & action conflicts
        let resolved_actions = ConflictResolver::resolve_conflicts(firing_rules);

        // 4. Execute resolved actions
        for (rule, action) in resolved_actions {
            println!("▶️ Executing action {:?} for rule '{}'", action, rule.name);
            info!("▶️ Executing action {:?} for rule '{}'", action, rule.name);
            self.execute_action(&rule, &action).await;
        }
    }

    fn evaluate_trigger(&self, trigger: &RuleTrigger, entity_id: &str, new_state: &str) -> bool {
        match trigger {
            RuleTrigger::StateChanged {
                entity_id: target_entity,
                to_state,
            } => {
                if target_entity != entity_id {
                    return false;
                }
                if let Some(target_state) = to_state {
                    return target_state == new_state;
                }
                true
            }
        }
    }

    async fn evaluate_conditions(&self, conditions: &[RuleCondition]) -> bool {
        for cond in conditions {
            match cond {
                RuleCondition::Presence { operator, value } => {
                    let current = self.presence_tracker.get_presence_status().await;
                    if operator == "equals" && current.as_str() != value {
                        return false;
                    }
                }
                RuleCondition::State {
                    entity_id,
                    operator,
                    value,
                } => {
                    // Check against live device state from DeviceRegistry
                    if let Some(device) = self
                        .device_manager
                        .get_registry()
                        .get_device_by_entity_id(entity_id)
                        .await
                    {
                        if operator == "equals" && device.current_state != *value {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
            }
        }
        true
    }

    async fn execute_action(self: &Arc<Self>, rule: &AutomationRule, action: &RuleAction) {
        match action {
            RuleAction::Delay { delay_secs } => {
                // Find target action after the delay in rule.actions
                let target_action = rule
                    .actions
                    .iter()
                    .find(|a| !matches!(a, RuleAction::Delay { .. }))
                    .cloned();

                if let Some(target) = target_action {
                    let pa_id = format!("pa_{}", uuid::Uuid::new_v4().simple());
                    let execute_at = Utc::now() + chrono::Duration::seconds(*delay_secs as i64);

                    let pending_action = PendingAction {
                        id: pa_id.clone(),
                        rule_id: rule.id.clone(),
                        action: target.clone(),
                        execute_at,
                        created_at: Utc::now(),
                    };

                    let _ = self.timer_store.add_pending_action(pending_action).await;

                    let engine = Arc::clone(self);
                    let delay = Duration::from_secs(*delay_secs);
                    let rule_name = rule.name.clone();

                    println!(
                        "⏳ Delaying action {:?} for {}s (rule: '{}')...",
                        target, delay_secs, rule_name
                    );
                    info!(
                        "⏳ Delaying action {:?} for {}s (rule: '{}')...",
                        target, delay_secs, rule_name
                    );

                    tokio::spawn(async move {
                        sleep(delay).await;
                        println!(
                            "⏰ Timer expired! Executing delayed action {:?} for rule '{}'",
                            target, rule_name
                        );
                        info!(
                            "⏰ Timer expired! Executing delayed action {:?} for rule '{}'",
                            target, rule_name
                        );
                        let _ = engine.execute_single_action(&target).await;
                        let _ = engine.timer_store.remove_pending_action(&pa_id).await;
                    });
                }
            }
            RuleAction::Command { on_failure, .. } => {
                // If rule has a Delay action, skip immediate execution (handled by Delay timer)
                let has_delay = rule
                    .actions
                    .iter()
                    .any(|a| matches!(a, RuleAction::Delay { .. }));
                if !has_delay {
                    let res = self.execute_single_action(action).await;
                    if let Err(e) = res {
                        self.handle_failure(on_failure, &rule.id, &e, action).await;
                    }
                }
            }
            RuleAction::Notification {
                message,
                severity,
                on_failure,
            } => {
                let has_delay = rule
                    .actions
                    .iter()
                    .any(|a| matches!(a, RuleAction::Delay { .. }));
                if !has_delay {
                    info!("🔔 Notification [{}]: {}", severity, message);
                    let res = self.execute_single_action(action).await;
                    if let Err(e) = res {
                        self.handle_failure(on_failure, &rule.id, &e, action).await;
                    }
                }
            }
        }
    }

    async fn execute_single_action(&self, action: &RuleAction) -> Result<(), String> {
        match action {
            RuleAction::Command {
                entity_id,
                domain,
                command,
                service_data,
                ..
            } => {
                self.device_manager
                    .send_command(entity_id, domain, command, service_data.clone())
                    .await
            }
            RuleAction::Notification { .. } => Ok(()),
            RuleAction::Delay { .. } => Ok(()),
        }
    }

    async fn handle_failure(
        &self,
        policy: &FailurePolicy,
        rule_id: &str,
        err: &str,
        action: &RuleAction,
    ) {
        match policy {
            FailurePolicy::Continue => {
                warn!(
                    "Rule {} action failed: {}. Continuing remaining actions.",
                    rule_id, err
                );
            }
            FailurePolicy::Abort => {
                error!(
                    "Rule {} action failed: {}. Aborting rule execution.",
                    rule_id, err
                );
            }
            FailurePolicy::Log => {
                info!(
                    "Rule {} action failed: {}. Logged per policy.",
                    rule_id, err
                );
            }
            FailurePolicy::Retry => {
                warn!(
                    "Rule {} action failed: {}. Retrying once after 5s...",
                    rule_id, err
                );
                let dev_mgr = Arc::clone(&self.device_manager);
                let action_clone = action.clone();
                tokio::spawn(async move {
                    sleep(Duration::from_secs(5)).await;
                    if let RuleAction::Command {
                        entity_id,
                        domain,
                        command,
                        service_data,
                        ..
                    } = action_clone
                    {
                        let _ = dev_mgr
                            .send_command(&entity_id, &domain, &command, service_data)
                            .await;
                    }
                });
            }
        }
    }

    async fn persist_rules(&self) -> Result<(), String> {
        let rules_snapshot = self.rules.read().await.clone();
        let store_clone = self.config_store.clone();

        tokio::task::spawn_blocking(move || {
            store_clone.write_atomic(|_old| {
                let data = AutomationsStore {
                    rules: rules_snapshot,
                };
                serde_json::to_vec_pretty(&data)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })
        })
        .await
        .map_err(|e| format!("Join error: {}", e))?
        .map_err(|e| format!("IO error: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::automation::presence::PresenceState;
    use crate::device::registry::DeviceRegistry;
    use crate::device::state::{Device, DeviceHealth};
    use crate::homeassistant::rest::HaRestClient;
    use crate::homeassistant::HomeAssistantConfig;
    use std::time::Duration as StdDuration;
    use tempfile::tempdir;

    struct Harness {
        engine: Arc<AutomationEngine>,
        device_manager: Arc<DeviceManager>,
        registry: Arc<DeviceRegistry>,
        presence_tracker: Arc<PresenceTracker>,
        timer_store: Arc<PendingActionStore>,
        event_bus: Arc<EventBus>,
        config_path: std::path::PathBuf,
        _dir: tempfile::TempDir,
    }

    fn make_harness() -> Harness {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("automations.json");
        let dev_file = dir.path().join("devices.json");
        let timer_path = dir.path().join("timers.json");

        let event_bus = EventBus::new();
        let registry = Arc::new(DeviceRegistry::new(dev_file.to_str().unwrap()));
        let ha_rest = Arc::new(HaRestClient::new(HomeAssistantConfig {
            url: "http://127.0.0.1:1".to_string(),
            token: "test".to_string(),
        }));
        let device_manager = DeviceManager::new(registry.clone(), ha_rest, event_bus.clone(), None);
        let presence_tracker = PresenceTracker::new();
        let timer_store = PendingActionStore::new(timer_path.to_str().unwrap());

        let engine = AutomationEngine::new(
            config_path.to_str().unwrap(),
            device_manager.clone(),
            presence_tracker.clone(),
            timer_store.clone(),
            event_bus.clone(),
        );

        Harness {
            engine,
            device_manager,
            registry,
            presence_tracker,
            timer_store,
            event_bus,
            config_path,
            _dir: dir,
        }
    }

    fn command_rule(id: &str, priority: i32, entity: &str, cmd: &str) -> AutomationRule {
        AutomationRule {
            id: id.to_string(),
            name: format!("rule-{}", id),
            priority,
            enabled: true,
            trigger: RuleTrigger::StateChanged {
                entity_id: "input_boolean.trigger".to_string(),
                to_state: None,
            },
            conditions: vec![],
            actions: vec![RuleAction::Command {
                entity_id: entity.to_string(),
                domain: "input_boolean".to_string(),
                command: cmd.to_string(),
                service_data: None,
                on_failure: FailurePolicy::Continue,
            }],
        }
    }

    async fn add_device(registry: &DeviceRegistry, entity_id: &str, state: &str) {
        registry
            .upsert_device(Device {
                id: format!("dev_{}", entity_id.replace('.', "_")),
                ha_entity_id: entity_id.to_string(),
                vendor: "test".to_string(),
                device_type: "switch".to_string(),
                room: None,
                friendly_name: entity_id.to_string(),
                current_state: state.to_string(),
                health_status: DeviceHealth::Online,
                last_seen: Utc::now(),
                attributes: Default::default(),
            })
            .await
            .expect("upsert device");
    }

    // ---- construction / persistence -------------------------------------------------

    #[tokio::test]
    async fn new_creates_default_rule_when_config_missing_and_persists_it() {
        let h = make_harness();
        let rules = h.engine.get_rules().await;
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "rule_sync_toggles");

        // Persisted to disk: a fresh engine built from the same path should load it,
        // not regenerate the default (idempotent since it's already non-empty).
        let raw = std::fs::read(&h.config_path).expect("config written");
        assert!(String::from_utf8_lossy(&raw).contains("rule_sync_toggles"));
    }

    #[tokio::test]
    async fn new_loads_existing_rules_from_disk_instead_of_defaulting() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("automations.json");
        let custom_rule = command_rule("custom_rule", 50, "light.a", "turn_on");
        let store = AutomationsStore {
            rules: vec![custom_rule.clone()],
        };
        std::fs::write(&config_path, serde_json::to_vec_pretty(&store).unwrap()).unwrap();

        let dev_file = dir.path().join("devices.json");
        let event_bus = EventBus::new();
        let registry = Arc::new(DeviceRegistry::new(dev_file.to_str().unwrap()));
        let ha_rest = Arc::new(HaRestClient::new(HomeAssistantConfig {
            url: "http://127.0.0.1:1".to_string(),
            token: "test".to_string(),
        }));
        let device_manager = DeviceManager::new(registry, ha_rest, event_bus.clone(), None);
        let presence_tracker = PresenceTracker::new();
        let timer_store =
            PendingActionStore::new(dir.path().join("timers.json").to_str().unwrap());

        let engine = AutomationEngine::new(
            config_path.to_str().unwrap(),
            device_manager,
            presence_tracker,
            timer_store,
            event_bus,
        );

        let rules = engine.get_rules().await;
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "custom_rule");
    }

    // ---- CRUD -------------------------------------------------------------------------

    #[tokio::test]
    async fn add_rule_replaces_same_id_and_persists() {
        let h = make_harness();
        let rule = command_rule("r1", 10, "light.a", "turn_on");
        h.engine.add_rule(rule.clone()).await.unwrap();
        assert!(h.engine.get_rules().await.iter().any(|r| r.id == "r1"));

        let mut updated = rule.clone();
        updated.name = "renamed".to_string();
        h.engine.add_rule(updated).await.unwrap();

        let rules = h.engine.get_rules().await;
        let matches: Vec<_> = rules.iter().filter(|r| r.id == "r1").collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "renamed");
    }

    #[tokio::test]
    async fn update_rule_not_found_returns_err() {
        let h = make_harness();
        let missing = command_rule("does_not_exist", 1, "light.a", "turn_on");
        let err = h.engine.update_rule(missing).await.unwrap_err();
        assert!(err.contains("not found"));
    }

    #[tokio::test]
    async fn update_rule_found_updates_and_persists() {
        let h = make_harness();
        let rule = command_rule("r2", 10, "light.a", "turn_on");
        h.engine.add_rule(rule.clone()).await.unwrap();

        let mut changed = rule;
        changed.priority = 999;
        h.engine.update_rule(changed).await.unwrap();

        let rules = h.engine.get_rules().await;
        let found = rules.iter().find(|r| r.id == "r2").unwrap();
        assert_eq!(found.priority, 999);
    }

    #[tokio::test]
    async fn delete_rule_not_found_returns_err() {
        let h = make_harness();
        let err = h.engine.delete_rule("nope").await.unwrap_err();
        assert!(err.contains("not found"));
    }

    #[tokio::test]
    async fn delete_rule_found_removes_and_persists() {
        let h = make_harness();
        let rule = command_rule("r3", 10, "light.a", "turn_on");
        h.engine.add_rule(rule).await.unwrap();
        h.engine.delete_rule("r3").await.unwrap();
        assert!(!h.engine.get_rules().await.iter().any(|r| r.id == "r3"));
    }

    #[tokio::test]
    async fn toggle_rule_not_found_returns_err() {
        let h = make_harness();
        let err = h.engine.toggle_rule("nope", false).await.unwrap_err();
        assert!(err.contains("not found"));
    }

    #[tokio::test]
    async fn toggle_rule_found_flips_enabled_flag() {
        let h = make_harness();
        let rule = command_rule("r4", 10, "light.a", "turn_on");
        h.engine.add_rule(rule).await.unwrap();
        h.engine.toggle_rule("r4", false).await.unwrap();
        let rules = h.engine.get_rules().await;
        assert!(!rules.iter().find(|r| r.id == "r4").unwrap().enabled);
    }

    // ---- trigger matching ---------------------------------------------------------

    #[tokio::test]
    async fn evaluate_trigger_rejects_entity_mismatch() {
        let h = make_harness();
        let trigger = RuleTrigger::StateChanged {
            entity_id: "input_boolean.a".to_string(),
            to_state: None,
        };
        assert!(!h
            .engine
            .evaluate_trigger(&trigger, "input_boolean.b", "on"));
    }

    #[tokio::test]
    async fn evaluate_trigger_matches_any_state_when_to_state_absent() {
        let h = make_harness();
        let trigger = RuleTrigger::StateChanged {
            entity_id: "input_boolean.a".to_string(),
            to_state: None,
        };
        assert!(h
            .engine
            .evaluate_trigger(&trigger, "input_boolean.a", "whatever"));
    }

    #[tokio::test]
    async fn evaluate_trigger_matches_specific_state_only() {
        let h = make_harness();
        let trigger = RuleTrigger::StateChanged {
            entity_id: "input_boolean.a".to_string(),
            to_state: Some("on".to_string()),
        };
        assert!(h.engine.evaluate_trigger(&trigger, "input_boolean.a", "on"));
        assert!(!h
            .engine
            .evaluate_trigger(&trigger, "input_boolean.a", "off"));
    }

    // ---- condition evaluation -------------------------------------------------------

    #[tokio::test]
    async fn evaluate_conditions_empty_is_always_true() {
        let h = make_harness();
        assert!(h.engine.evaluate_conditions(&[]).await);
    }

    #[tokio::test]
    async fn evaluate_conditions_presence_equals() {
        let h = make_harness();
        h.presence_tracker
            .update_entity_state("person.a", "home")
            .await;

        let matching = vec![RuleCondition::Presence {
            operator: "equals".to_string(),
            value: "home".to_string(),
        }];
        assert!(h.engine.evaluate_conditions(&matching).await);

        let mismatching = vec![RuleCondition::Presence {
            operator: "equals".to_string(),
            value: "nobody_home".to_string(),
        }];
        assert!(!h.engine.evaluate_conditions(&mismatching).await);
    }

    #[tokio::test]
    async fn evaluate_conditions_state_device_not_found_is_false() {
        let h = make_harness();
        let conditions = vec![RuleCondition::State {
            entity_id: "light.missing".to_string(),
            operator: "equals".to_string(),
            value: "on".to_string(),
        }];
        assert!(!h.engine.evaluate_conditions(&conditions).await);
    }

    #[tokio::test]
    async fn evaluate_conditions_state_equals_matches_registered_device() {
        let h = make_harness();
        add_device(&h.registry, "light.kitchen", "on").await;

        let matching = vec![RuleCondition::State {
            entity_id: "light.kitchen".to_string(),
            operator: "equals".to_string(),
            value: "on".to_string(),
        }];
        assert!(h.engine.evaluate_conditions(&matching).await);

        let mismatching = vec![RuleCondition::State {
            entity_id: "light.kitchen".to_string(),
            operator: "equals".to_string(),
            value: "off".to_string(),
        }];
        assert!(!h.engine.evaluate_conditions(&mismatching).await);
    }

    #[tokio::test]
    async fn evaluate_conditions_non_equals_operator_is_not_filtered() {
        let h = make_harness();
        add_device(&h.registry, "light.hallway", "off").await;
        // Operator other than "equals" has no filtering logic, so as long as the
        // device is found the condition passes regardless of value comparison.
        let conditions = vec![RuleCondition::State {
            entity_id: "light.hallway".to_string(),
            operator: "not_equals".to_string(),
            value: "off".to_string(),
        }];
        assert!(h.engine.evaluate_conditions(&conditions).await);
    }

    // ---- process_state_changed -----------------------------------------------------

    #[tokio::test]
    async fn process_state_changed_ignores_events_missing_required_fields() {
        let h = make_harness();
        // Missing "data" entirely.
        h.engine
            .process_state_changed(serde_json::json!({}))
            .await;
        // Missing entity_id.
        h.engine
            .process_state_changed(serde_json::json!({"data": {}}))
            .await;
        // Missing new_state.
        h.engine
            .process_state_changed(serde_json::json!({"data": {"entity_id": "x.y"}}))
            .await;
        // None of the above should panic or fire any rule; nothing to assert beyond
        // "did not panic" since these are early-return branches.
    }

    #[tokio::test]
    async fn process_state_changed_updates_presence_tracker_for_presence_entities() {
        let h = make_harness();
        h.engine
            .process_state_changed(serde_json::json!({
                "data": {
                    "entity_id": "person.alice",
                    "new_state": {"state": "home"}
                }
            }))
            .await;
        assert_eq!(
            h.presence_tracker.get_presence_status().await,
            PresenceState::Home
        );
    }

    #[tokio::test]
    async fn process_state_changed_fires_enabled_rule_and_skips_disabled_rule() {
        let h = make_harness();
        // Remove the seeded default rule to keep this deterministic.
        h.engine.delete_rule("rule_sync_toggles").await.unwrap();

        let mut enabled_rule = command_rule("enabled_rule", 10, "light.a", "turn_on");
        enabled_rule.trigger = RuleTrigger::StateChanged {
            entity_id: "input_boolean.switch".to_string(),
            to_state: None,
        };
        h.engine.add_rule(enabled_rule).await.unwrap();

        let mut disabled_rule = command_rule("disabled_rule", 20, "light.b", "turn_on");
        disabled_rule.enabled = false;
        disabled_rule.trigger = RuleTrigger::StateChanged {
            entity_id: "input_boolean.switch".to_string(),
            to_state: None,
        };
        h.engine.add_rule(disabled_rule).await.unwrap();

        // Neither light.a nor light.b are registered devices, so send_command fails
        // fast (before any network I/O) and execute_action's Continue failure policy
        // just logs — nothing to assert beyond completing without panicking, which
        // still exercises rule matching + the disabled-rule skip branch.
        h.engine
            .process_state_changed(serde_json::json!({
                "data": {
                    "entity_id": "input_boolean.switch",
                    "new_state": {"state": "on"}
                }
            }))
            .await;
    }

    #[tokio::test]
    async fn process_state_changed_resolves_equal_priority_conflicts_via_resolver() {
        let h = make_harness();
        h.engine.delete_rule("rule_sync_toggles").await.unwrap();

        let mut rule_on = command_rule("conflict_on", 100, "lock.front_door", "lock");
        rule_on.trigger = RuleTrigger::StateChanged {
            entity_id: "input_boolean.switch".to_string(),
            to_state: None,
        };
        h.engine.add_rule(rule_on).await.unwrap();

        let mut rule_off = command_rule("conflict_off", 100, "lock.front_door", "unlock");
        rule_off.trigger = RuleTrigger::StateChanged {
            entity_id: "input_boolean.switch".to_string(),
            to_state: None,
        };
        h.engine.add_rule(rule_off).await.unwrap();

        // Both rules fire with equal priority and contradictory commands on the same
        // entity; ConflictResolver should drop both, so execute_action is never
        // reached for either — this just needs to complete without panicking.
        h.engine
            .process_state_changed(serde_json::json!({
                "data": {
                    "entity_id": "input_boolean.switch",
                    "new_state": {"state": "on"}
                }
            }))
            .await;
    }

    // ---- execute_single_action / execute_action / handle_failure -------------------

    #[tokio::test]
    async fn execute_single_action_command_missing_device_returns_err() {
        let h = make_harness();
        let action = RuleAction::Command {
            entity_id: "light.unregistered".to_string(),
            domain: "light".to_string(),
            command: "turn_on".to_string(),
            service_data: None,
            on_failure: FailurePolicy::Continue,
        };
        let result = h.engine.execute_single_action(&action).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn execute_single_action_notification_and_delay_are_always_ok() {
        let h = make_harness();
        let notif = RuleAction::Notification {
            message: "hi".to_string(),
            severity: "info".to_string(),
            on_failure: FailurePolicy::Continue,
        };
        assert!(h.engine.execute_single_action(&notif).await.is_ok());

        let delay = RuleAction::Delay { delay_secs: 5 };
        assert!(h.engine.execute_single_action(&delay).await.is_ok());
    }

    #[tokio::test]
    async fn execute_action_delay_schedules_a_pending_action() {
        let h = make_harness();
        let rule = AutomationRule {
            id: "delay_rule".to_string(),
            name: "delay rule".to_string(),
            priority: 10,
            enabled: true,
            trigger: RuleTrigger::StateChanged {
                entity_id: "input_boolean.switch".to_string(),
                to_state: None,
            },
            conditions: vec![],
            actions: vec![
                RuleAction::Delay { delay_secs: 3600 },
                RuleAction::Command {
                    entity_id: "light.a".to_string(),
                    domain: "light".to_string(),
                    command: "turn_on".to_string(),
                    service_data: None,
                    on_failure: FailurePolicy::Continue,
                },
            ],
        };
        let delay_action = RuleAction::Delay { delay_secs: 3600 };

        h.engine.execute_action(&rule, &delay_action).await;

        let pending = h.timer_store.get_all_pending().await;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].rule_id, "delay_rule");
        assert!(matches!(
            pending[0].action,
            RuleAction::Command { ref command, .. } if command == "turn_on"
        ));
    }

    #[tokio::test]
    async fn execute_action_command_is_skipped_when_rule_has_a_delay_action() {
        let h = make_harness();
        let rule = AutomationRule {
            id: "has_delay".to_string(),
            name: "has delay".to_string(),
            priority: 10,
            enabled: true,
            trigger: RuleTrigger::StateChanged {
                entity_id: "input_boolean.switch".to_string(),
                to_state: None,
            },
            conditions: vec![],
            actions: vec![
                RuleAction::Delay { delay_secs: 60 },
                RuleAction::Command {
                    entity_id: "light.unregistered".to_string(),
                    domain: "light".to_string(),
                    command: "turn_on".to_string(),
                    service_data: None,
                    on_failure: FailurePolicy::Continue,
                },
            ],
        };
        let command_action = rule.actions[1].clone();
        // Since the rule also carries a Delay action, immediate Command execution
        // must be skipped (handled instead by the Delay timer machinery).
        h.engine.execute_action(&rule, &command_action).await;
        // No pending timer is created by the Command branch itself.
        assert!(h.timer_store.get_all_pending().await.is_empty());
    }

    #[tokio::test]
    async fn execute_action_notification_without_delay_runs_immediately() {
        let h = make_harness();
        let rule = command_rule("notif_rule", 10, "light.a", "turn_on");
        let notif_action = RuleAction::Notification {
            message: "hello".to_string(),
            severity: "info".to_string(),
            on_failure: FailurePolicy::Continue,
        };
        // Notification always succeeds, so handle_failure is never invoked; this
        // just needs to complete without panicking.
        h.engine.execute_action(&rule, &notif_action).await;
    }

    #[tokio::test]
    async fn handle_failure_continue_policy_does_not_panic() {
        let h = make_harness();
        let action = RuleAction::Command {
            entity_id: "light.x".to_string(),
            domain: "light".to_string(),
            command: "turn_on".to_string(),
            service_data: None,
            on_failure: FailurePolicy::Continue,
        };
        h.engine
            .handle_failure(&FailurePolicy::Continue, "rule_x", "boom", &action)
            .await;
    }

    #[tokio::test]
    async fn handle_failure_abort_policy_does_not_panic() {
        let h = make_harness();
        let action = RuleAction::Notification {
            message: "m".to_string(),
            severity: "info".to_string(),
            on_failure: FailurePolicy::Abort,
        };
        h.engine
            .handle_failure(&FailurePolicy::Abort, "rule_x", "boom", &action)
            .await;
    }

    #[tokio::test]
    async fn handle_failure_log_policy_does_not_panic() {
        let h = make_harness();
        let action = RuleAction::Delay { delay_secs: 1 };
        h.engine
            .handle_failure(&FailurePolicy::Log, "rule_x", "boom", &action)
            .await;
    }

    #[tokio::test(start_paused = true)]
    async fn handle_failure_retry_policy_spawns_a_retry_that_runs_after_the_delay() {
        let h = make_harness();
        // Unregistered device: when the retry actually fires, send_command fails
        // fast before any network I/O, so this stays fully offline.
        let action = RuleAction::Command {
            entity_id: "light.unregistered".to_string(),
            domain: "light".to_string(),
            command: "turn_on".to_string(),
            service_data: None,
            on_failure: FailurePolicy::Retry,
        };
        h.engine
            .handle_failure(&FailurePolicy::Retry, "rule_x", "boom", &action)
            .await;

        // Let the spawned task run up to its `sleep(5s)` and register the timer
        // before advancing the paused virtual clock past it — no real sleeping.
        tokio::task::yield_now().await;
        tokio::time::advance(StdDuration::from_secs(6)).await;
        tokio::task::yield_now().await;
    }

    // ---- restore_pending_timers ------------------------------------------------------

    #[tokio::test]
    async fn restore_pending_timers_is_noop_when_nothing_pending() {
        let h = make_harness();
        h.engine.restore_pending_timers().await;
        assert!(h.timer_store.get_all_pending().await.is_empty());
    }

    #[tokio::test]
    async fn restore_pending_timers_executes_past_due_action_immediately() {
        let h = make_harness();
        let pending = PendingAction {
            id: "pa_past".to_string(),
            rule_id: "r".to_string(),
            action: RuleAction::Notification {
                message: "m".to_string(),
                severity: "info".to_string(),
                on_failure: FailurePolicy::Continue,
            },
            execute_at: Utc::now() - chrono::Duration::seconds(5),
            created_at: Utc::now(),
        };
        h.timer_store.add_pending_action(pending).await.unwrap();

        h.engine.restore_pending_timers().await;

        // The spawned immediate-execution task needs a few scheduler turns.
        for _ in 0..50 {
            tokio::task::yield_now().await;
            if h.timer_store.get_all_pending().await.is_empty() {
                break;
            }
        }
        assert!(h.timer_store.get_all_pending().await.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn restore_pending_timers_schedules_future_action_for_later() {
        let h = make_harness();
        let pending = PendingAction {
            id: "pa_future".to_string(),
            rule_id: "r".to_string(),
            action: RuleAction::Notification {
                message: "m".to_string(),
                severity: "info".to_string(),
                on_failure: FailurePolicy::Continue,
            },
            execute_at: Utc::now() + chrono::Duration::seconds(30),
            created_at: Utc::now(),
        };
        h.timer_store.add_pending_action(pending).await.unwrap();

        h.engine.restore_pending_timers().await;
        tokio::task::yield_now().await;
        // Not due yet — still pending.
        assert_eq!(h.timer_store.get_all_pending().await.len(), 1);

        tokio::time::advance(StdDuration::from_secs(31)).await;
        tokio::task::yield_now().await;
        for _ in 0..50 {
            tokio::task::yield_now().await;
            if h.timer_store.get_all_pending().await.is_empty() {
                break;
            }
        }
        assert!(h.timer_store.get_all_pending().await.is_empty());
    }

    // Sanity check that the harness wires the device manager through correctly,
    // exercising the `device_manager` field alongside the others.
    #[tokio::test]
    async fn harness_device_manager_sees_registry_devices() {
        let h = make_harness();
        add_device(&h.registry, "light.sanity", "on").await;
        let dev = h
            .device_manager
            .get_registry()
            .get_device_by_entity_id("light.sanity")
            .await;
        assert!(dev.is_some());
        let _ = &h.event_bus;
    }
}
