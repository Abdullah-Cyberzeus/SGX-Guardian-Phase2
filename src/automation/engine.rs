use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

use crate::automation::conflict::ConflictResolver;
use crate::automation::presence::{PresenceTracker};
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
                    println!("⚙️ Loaded {} automation rule(s) from {}", rules.len(), config_path);
                    info!("Loaded {} automation rule(s) from {}.", rules.len(), config_path);
                }
            }
        }

        if rules.is_empty() {
            rules = vec![
                AutomationRule {
                    id: "rule_sync_toggles".to_string(),
                    name: "Sync Toggle 1 to Toggle 2".to_string(),
                    priority: 100,
                    enabled: true,
                    trigger: RuleTrigger::StateChanged {
                        entity_id: "input_boolean.1".to_string(),
                        to_state: None,
                    },
                    conditions: vec![],
                    actions: vec![
                        RuleAction::Command {
                            entity_id: "input_boolean.2".to_string(),
                            domain: "input_boolean".to_string(),
                            command: "turn_on".to_string(),
                            service_data: None,
                            on_failure: FailurePolicy::Continue,
                        }
                    ],
                }
            ];
            let store = AutomationsStore { rules: rules.clone() };
            if let Ok(json_bytes) = serde_json::to_vec_pretty(&store) {
                let _ = config_store.write_atomic(|_| Ok::<_, std::io::Error>(json_bytes));
            }
            println!("⚙️ Initialized default automation rule(s) ({}) in {}", rules.len(), config_path);
            info!("Initialized default automation rule(s) ({}) in {}", rules.len(), config_path);
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
                let delay = (pa.execute_at - now).to_std().unwrap_or(Duration::from_secs(0));
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
            println!("⚙️ Automation Engine event loop started with {} active rule(s).", rules_count);
            info!("⚙️ Automation Engine started with {} active rule(s).", rules_count);
            loop {
                match rx.recv().await {
                    Ok(HaEvent::StateChanged(val)) => {
                        engine.process_state_changed(val).await;
                    }
                    Ok(_) => {}
                    Err(RecvError::Lagged(skipped)) => {
                        warn!("Automation Engine lagged behind! Skipped {} events.", skipped);
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

        let new_state = match data.get("new_state").and_then(|n| n.get("state")).and_then(|s| s.as_str()) {
            Some(s) => s,
            None => return,
        };

        // 1. Update presence tracker if person or device_tracker
        if PresenceTracker::is_presence_entity(entity_id) {
            self.presence_tracker.update_entity_state(entity_id, new_state).await;
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
                    println!("⚡ Rule fired: {} ({}) for entity: {} (state={})", rule.name, rule.id, entity_id, new_state);
                    info!("⚡ Rule fired: {} ({}) for entity: {} (state={})", rule.name, rule.id, entity_id, new_state);
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
                RuleCondition::State { entity_id, operator, value } => {
                    // Check against live device state from DeviceRegistry
                    if let Some(device) = self.device_manager.get_registry().get_device_by_entity_id(entity_id).await {
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
                let target_action = rule.actions.iter().find(|a| !matches!(a, RuleAction::Delay { .. })).cloned();

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

                    println!("⏳ Delaying action {:?} for {}s (rule: '{}')...", target, delay_secs, rule_name);
                    info!("⏳ Delaying action {:?} for {}s (rule: '{}')...", target, delay_secs, rule_name);

                    tokio::spawn(async move {
                        sleep(delay).await;
                        println!("⏰ Timer expired! Executing delayed action {:?} for rule '{}'", target, rule_name);
                        info!("⏰ Timer expired! Executing delayed action {:?} for rule '{}'", target, rule_name);
                        let _ = engine.execute_single_action(&target).await;
                        let _ = engine.timer_store.remove_pending_action(&pa_id).await;
                    });
                }
            }
            RuleAction::Command { on_failure, .. } => {
                // If rule has a Delay action, skip immediate execution (handled by Delay timer)
                let has_delay = rule.actions.iter().any(|a| matches!(a, RuleAction::Delay { .. }));
                if !has_delay {
                    let res = self.execute_single_action(action).await;
                    if let Err(e) = res {
                        self.handle_failure(on_failure, &rule.id, &e, action).await;
                    }
                }
            }
            RuleAction::Notification { message, severity, on_failure } => {
                let has_delay = rule.actions.iter().any(|a| matches!(a, RuleAction::Delay { .. }));
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
                warn!("Rule {} action failed: {}. Continuing remaining actions.", rule_id, err);
            }
            FailurePolicy::Abort => {
                error!("Rule {} action failed: {}. Aborting rule execution.", rule_id, err);
            }
            FailurePolicy::Log => {
                info!("Rule {} action failed: {}. Logged per policy.", rule_id, err);
            }
            FailurePolicy::Retry => {
                warn!("Rule {} action failed: {}. Retrying once after 5s...", rule_id, err);
                let dev_mgr = Arc::clone(&self.device_manager);
                let action_clone = action.clone();
                tokio::spawn(async move {
                    sleep(Duration::from_secs(5)).await;
                    if let RuleAction::Command { entity_id, domain, command, service_data, .. } = action_clone {
                        let _ = dev_mgr.send_command(&entity_id, &domain, &command, service_data).await;
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
                let data = AutomationsStore { rules: rules_snapshot };
                serde_json::to_vec_pretty(&data)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })
        })
        .await
        .map_err(|e| format!("Join error: {}", e))?
        .map_err(|e| format!("IO error: {}", e))
    }
}
