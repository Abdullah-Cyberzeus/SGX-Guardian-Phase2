use crate::automation::schema::{AutomationRule, RuleAction};
use std::collections::HashMap;
use tracing::warn;

pub struct ConflictResolver;

impl ConflictResolver {
    /// Resolves rule priorities and contradictory actions for a set of firing rules.
    pub fn resolve_conflicts(
        firing_rules: Vec<AutomationRule>,
    ) -> Vec<(AutomationRule, RuleAction)> {
        if firing_rules.is_empty() {
            return Vec::new();
        }

        // Group actions by target entity_id: entity_id -> Vec<(rule_priority, rule_index, rule, action)>
        let mut entity_actions: HashMap<String, Vec<(i32, AutomationRule, RuleAction)>> =
            HashMap::new();
        let mut non_command_actions: Vec<(AutomationRule, RuleAction)> = Vec::new();

        for rule in firing_rules {
            for action in &rule.actions {
                match action {
                    RuleAction::Command { entity_id, .. } => {
                        let list = entity_actions.entry(entity_id.clone()).or_default();
                        list.push((rule.priority, rule.clone(), action.clone()));
                    }
                    _ => {
                        non_command_actions.push((rule.clone(), action.clone()));
                    }
                }
            }
        }

        let mut resolved_actions = Vec::new();

        for (entity_id, mut actions) in entity_actions {
            // Sort by priority descending
            actions.sort_by_key(|action| std::cmp::Reverse(action.0));

            if actions.len() == 1 {
                resolved_actions.push((actions[0].1.clone(), actions[0].2.clone()));
                continue;
            }

            // Check if top priority rules have contradictory commands
            let top_priority = actions[0].0;
            let top_actions: Vec<&(i32, AutomationRule, RuleAction)> =
                actions.iter().filter(|a| a.0 == top_priority).collect();

            if top_actions.len() > 1 {
                // Check if the top actions contradict each other
                let first_cmd = extract_command_name(&top_actions[0].2);
                let is_conflict = top_actions
                    .iter()
                    .any(|a| is_contradictory_command(&first_cmd, &extract_command_name(&a.2)));

                if is_conflict {
                    warn!(
                        "⚠️ Rule Priority Conflict! Multiple rules with equal priority ({}) attempted conflicting commands on {}. Dropping conflicting actions.",
                        top_priority, entity_id
                    );
                    continue; // Skip both conflicting equal-priority commands
                }
            }

            // Top priority rule wins
            resolved_actions.push((actions[0].1.clone(), actions[0].2.clone()));
        }

        resolved_actions.extend(non_command_actions);
        resolved_actions
    }
}

fn extract_command_name(action: &RuleAction) -> String {
    match action {
        RuleAction::Command { command, .. } => command.clone(),
        _ => String::new(),
    }
}

fn is_contradictory_command(cmd1: &str, cmd2: &str) -> bool {
    if cmd1 == cmd2 {
        return false;
    }
    matches!(
        (cmd1, cmd2),
        ("turn_on", "turn_off")
            | ("turn_off", "turn_on")
            | ("lock", "unlock")
            | ("unlock", "lock")
            | ("open_cover", "close_cover")
            | ("close_cover", "open_cover")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::automation::schema::RuleTrigger;

    fn make_test_rule(id: &str, priority: i32, entity: &str, cmd: &str) -> AutomationRule {
        AutomationRule {
            id: id.to_string(),
            name: id.to_string(),
            priority,
            enabled: true,
            trigger: RuleTrigger::StateChanged {
                entity_id: "input_boolean.toggle".to_string(),
                to_state: None,
            },
            conditions: vec![],
            actions: vec![RuleAction::Command {
                entity_id: entity.to_string(),
                domain: "input_boolean".to_string(),
                command: cmd.to_string(),
                service_data: None,
                on_failure: Default::default(),
            }],
        }
    }

    #[test]
    fn test_higher_priority_wins() {
        let rule_low = make_test_rule("low", 50, "light.living_room", "turn_off");
        let rule_high = make_test_rule("high", 100, "light.living_room", "turn_on");

        let resolved = ConflictResolver::resolve_conflicts(vec![rule_low, rule_high]);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].0.id, "high");
    }

    #[test]
    fn test_equal_priority_conflict_drops_both() {
        let rule1 = make_test_rule("rule1", 100, "lock.front_door", "lock");
        let rule2 = make_test_rule("rule2", 100, "lock.front_door", "unlock");

        let resolved = ConflictResolver::resolve_conflicts(vec![rule1, rule2]);
        assert_eq!(resolved.len(), 0); // Both dropped due to conflict
    }
}
