use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum FailurePolicy {
    #[default]
    Continue,
    Abort,
    Log,
    Retry,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleTrigger {
    StateChanged {
        entity_id: String,
        to_state: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleCondition {
    State {
        entity_id: String,
        operator: String, // "equals", "not_equals"
        value: String,
    },
    Presence {
        operator: String, // "equals"
        value: String,    // "home", "nobody_home"
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleAction {
    Command {
        entity_id: String,
        domain: String,
        command: String, // service name e.g. "turn_on", "lock"
        service_data: Option<serde_json::Value>,
        #[serde(default)]
        on_failure: FailurePolicy,
    },
    Notification {
        message: String,
        severity: String, // "info", "warning", "critical"
        #[serde(default)]
        on_failure: FailurePolicy,
    },
    Delay {
        delay_secs: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AutomationRule {
    pub id: String,
    pub name: String,
    #[serde(default = "default_priority")]
    pub priority: i32,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub trigger: RuleTrigger,
    #[serde(default)]
    pub conditions: Vec<RuleCondition>,
    pub actions: Vec<RuleAction>,
}

fn default_priority() -> i32 {
    100
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_deserialization() {
        let json_data = r#"{
            "id": "rule001",
            "name": "Auto Lock Front Door",
            "priority": 150,
            "enabled": true,
            "trigger": {
                "type": "state_changed",
                "entity_id": "input_boolean.toggle",
                "to_state": "on"
            },
            "conditions": [
                {
                    "type": "presence",
                    "operator": "equals",
                    "value": "nobody_home"
                }
            ],
            "actions": [
                {
                    "type": "command",
                    "entity_id": "input_boolean.toggle_2",
                    "domain": "input_boolean",
                    "command": "turn_on",
                    "on_failure": "continue"
                }
            ]
        }"#;

        let rule: AutomationRule = serde_json::from_str(json_data).unwrap();
        assert_eq!(rule.id, "rule001");
        assert_eq!(rule.priority, 150);
        assert_eq!(rule.actions.len(), 1);
    }
}
