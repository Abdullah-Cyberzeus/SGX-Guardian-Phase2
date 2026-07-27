use crate::rules::errors::RulesResult;
use crate::rules::model::{Rule, RuleEvent};
use crate::rules::persistence::{read_json_if_exists, write_atomic};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RulesRuntimeState {
    #[serde(default)]
    cooldowns: HashMap<String, i64>,
    #[serde(default)]
    rates: HashMap<String, RateCounter>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RateCounter {
    window_start: i64,
    count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardDecision {
    Allowed,
    Cooldown { retry_after_secs: u64 },
    RateLimited { window_reset_secs: u64 },
}

impl GuardDecision {
    pub fn outcome(&self) -> &'static str {
        match self {
            Self::Allowed => "executed",
            Self::Cooldown { .. } | Self::RateLimited { .. } => "rate-limited",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::Allowed => "allowed".to_string(),
            Self::Cooldown { retry_after_secs } => {
                format!("cooldown active; retry after {}s", retry_after_secs)
            }
            Self::RateLimited { window_reset_secs } => {
                format!("rate cap reached; window resets in {}s", window_reset_secs)
            }
        }
    }
}

pub fn check_and_record(
    state_path: &Path,
    rule: &Rule,
    event: &RuleEvent,
    action_count: u32,
) -> RulesResult<GuardDecision> {
    let mut state = load_state(state_path)?;
    let now = Utc::now().timestamp();
    let cooldown_key = cooldown_key(rule, event);
    if let Some(last_fire) = state.cooldowns.get(&cooldown_key) {
        let elapsed = now.saturating_sub(*last_fire) as u64;
        if elapsed < rule.cooldown_secs {
            return Ok(GuardDecision::Cooldown {
                retry_after_secs: rule.cooldown_secs - elapsed,
            });
        }
    }

    let rate_key = rule.rule_id.clone();
    let rate = state.rates.entry(rate_key).or_insert(RateCounter {
        window_start: now,
        count: 0,
    });
    if now.saturating_sub(rate.window_start) >= 3600 {
        rate.window_start = now;
        rate.count = 0;
    }

    if rate.count.saturating_add(action_count) > rule.max_actions_per_hour {
        let elapsed = now.saturating_sub(rate.window_start) as u64;
        return Ok(GuardDecision::RateLimited {
            window_reset_secs: 3600_u64.saturating_sub(elapsed),
        });
    }

    rate.count = rate.count.saturating_add(action_count);
    state.cooldowns.insert(cooldown_key, now);
    save_state(state_path, &state)?;
    Ok(GuardDecision::Allowed)
}

fn cooldown_key(rule: &Rule, event: &RuleEvent) -> String {
    format!("{}:{}", rule.rule_id, event.target_key())
}

fn load_state(path: &Path) -> RulesResult<RulesRuntimeState> {
    Ok(read_json_if_exists(path)?.unwrap_or_default())
}

fn save_state(path: &Path, state: &RulesRuntimeState) -> RulesResult<()> {
    let bytes = serde_json::to_vec_pretty(state)?;
    write_atomic(path, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::model::{Condition, RuleDraft};

    fn test_rule() -> Rule {
        Rule::from_draft(RuleDraft {
            name: Some("guard".to_string()),
            condition: Some(Condition::All(Vec::new())),
            cooldown_secs: Some(60),
            max_actions_per_hour: Some(2),
            ..RuleDraft::default()
        })
    }

    #[test]
    fn cooldown_blocks_same_target_after_first_fire() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        let rule = test_rule();
        let event = RuleEvent::sample_threat("nodeA");

        assert_eq!(
            check_and_record(&path, &rule, &event, 1).expect("first"),
            GuardDecision::Allowed
        );
        assert!(matches!(
            check_and_record(&path, &rule, &event, 1).expect("second"),
            GuardDecision::Cooldown { .. }
        ));
    }

    #[test]
    fn guard_decision_outcome_and_message_are_pure() {
        assert_eq!(GuardDecision::Allowed.outcome(), "executed");
        assert_eq!(GuardDecision::Allowed.message(), "allowed");

        let cooldown = GuardDecision::Cooldown {
            retry_after_secs: 42,
        };
        assert_eq!(cooldown.outcome(), "rate-limited");
        assert_eq!(cooldown.message(), "cooldown active; retry after 42s");

        let rate_limited = GuardDecision::RateLimited {
            window_reset_secs: 7,
        };
        assert_eq!(rate_limited.outcome(), "rate-limited");
        assert_eq!(
            rate_limited.message(),
            "rate cap reached; window resets in 7s"
        );
    }

    #[test]
    fn cooldown_key_combines_rule_id_and_event_target() {
        let rule = test_rule();
        let event = RuleEvent::sample_threat("nodeA");
        assert_eq!(
            cooldown_key(&rule, &event),
            format!("{}:{}", rule.rule_id, event.target_key())
        );
    }

    #[test]
    fn rate_cap_counts_actions_per_rule() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        let mut rule = test_rule();
        rule.cooldown_secs = 1;
        let event = RuleEvent::sample_threat("nodeA");

        assert_eq!(
            check_and_record(&path, &rule, &event, 2).expect("first"),
            GuardDecision::Allowed
        );

        let mut other = event.clone();
        if let RuleEvent::ThreatAlert { alert, .. } = &mut other {
            alert.src_ip = "203.0.113.56".to_string();
        }

        assert!(matches!(
            check_and_record(&path, &rule, &other, 1).expect("limited"),
            GuardDecision::RateLimited { .. }
        ));
    }
}
