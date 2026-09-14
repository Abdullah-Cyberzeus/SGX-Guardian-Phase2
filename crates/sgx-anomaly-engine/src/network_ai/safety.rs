//! Task 3 Deliverable 10: safety guard, hysteresis, cooldown, and safe switching.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteSafetyConfig {
    pub min_improvement_pct: f64,
    pub min_route_hold_seconds: u64,
    pub switch_cooldown_seconds: u64,
    pub max_switches_per_window: u32,
    pub window_seconds: u64,
}

impl Default for RouteSafetyConfig {
    fn default() -> Self {
        Self {
            min_improvement_pct: 10.0,
            min_route_hold_seconds: 30,
            switch_cooldown_seconds: 20,
            max_switches_per_window: 6,
            window_seconds: 300,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteSwitchState {
    pub current_route_id: String,
    pub current_route_started_ms: u64,
    pub last_switch_ms: Option<u64>,
    pub switch_timestamps_ms: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SafetyVerdict {
    Allow,
    BlockSameRoute,
    BlockInsufficientImprovement,
    BlockHoldTime,
    BlockCooldown,
    BlockTooManySwitches,
    BlockNoCandidate,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteSafetyDecision {
    pub verdict: SafetyVerdict,
    pub allowed: bool,
    pub current_route_id: String,
    pub candidate_route_id: Option<String>,
    pub improvement_pct: f64,
    pub hard_failover: bool,
    pub recent_switches_in_window: u32,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteApplyResult {
    pub applied: bool,
    pub previous_route_id: String,
    pub active_route_id: String,
    pub rollback_route_id: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Default)]
pub struct RouteSafetyGuard {
    pub config: RouteSafetyConfig,
}

impl RouteSafetyGuard {
    pub fn evaluate(
        &self,
        now_ms: u64,
        state: &RouteSwitchState,
        candidate_route_id: Option<&str>,
        current_score: f64,
        candidate_score: f64,
    ) -> RouteSafetyDecision {
        self.evaluate_with_route_health(
            now_ms,
            state,
            candidate_route_id,
            current_score,
            candidate_score,
            false,
        )
    }

    pub fn evaluate_with_route_health(
        &self,
        now_ms: u64,
        state: &RouteSwitchState,
        candidate_route_id: Option<&str>,
        current_score: f64,
        candidate_score: f64,
        current_route_failed: bool,
    ) -> RouteSafetyDecision {
        let Some(candidate_route_id) = candidate_route_id else {
            return block(
                SafetyVerdict::BlockNoCandidate,
                state,
                None,
                0.0,
                false,
                recent_switches_in_window(now_ms, state, self.config.window_seconds),
                "no eligible candidate route available",
            );
        };

        if candidate_route_id == state.current_route_id {
            return block(
                SafetyVerdict::BlockSameRoute,
                state,
                Some(candidate_route_id),
                0.0,
                false,
                recent_switches_in_window(now_ms, state, self.config.window_seconds),
                "candidate is already the active route",
            );
        }

        let improvement_pct = if current_score.abs() < f64::EPSILON {
            100.0
        } else {
            ((candidate_score - current_score) / current_score.abs()) * 100.0
        };

        let recent_switches = recent_switches_in_window(now_ms, state, self.config.window_seconds);

        if current_route_failed {
            return RouteSafetyDecision {
                verdict: SafetyVerdict::Allow,
                allowed: true,
                current_route_id: state.current_route_id.clone(),
                candidate_route_id: Some(candidate_route_id.to_string()),
                improvement_pct,
                hard_failover: true,
                recent_switches_in_window: recent_switches,
                reason: "hard failure failover: current route failed, so hold/cooldown/flap guards are bypassed for this eligible candidate".to_string(),
            };
        }

        if improvement_pct < self.config.min_improvement_pct {
            return block(
                SafetyVerdict::BlockInsufficientImprovement,
                state,
                Some(candidate_route_id),
                improvement_pct,
                false,
                recent_switches,
                "candidate improvement is below configured minimum",
            );
        }

        let held_seconds = now_ms
            .saturating_sub(state.current_route_started_ms)
            .saturating_div(1000);
        if held_seconds < self.config.min_route_hold_seconds {
            return block(
                SafetyVerdict::BlockHoldTime,
                state,
                Some(candidate_route_id),
                improvement_pct,
                false,
                recent_switches,
                "current route has not satisfied minimum hold time",
            );
        }

        if let Some(last_switch_ms) = state.last_switch_ms {
            let cooldown_seconds = now_ms.saturating_sub(last_switch_ms).saturating_div(1000);
            if cooldown_seconds < self.config.switch_cooldown_seconds {
                return block(
                    SafetyVerdict::BlockCooldown,
                    state,
                    Some(candidate_route_id),
                    improvement_pct,
                    false,
                    recent_switches,
                    "switch cooldown is still active",
                );
            }
        }

        if recent_switches >= self.config.max_switches_per_window {
            return block(
                SafetyVerdict::BlockTooManySwitches,
                state,
                Some(candidate_route_id),
                improvement_pct,
                false,
                recent_switches,
                "maximum route switches reached for the current window",
            );
        }

        RouteSafetyDecision {
            verdict: SafetyVerdict::Allow,
            allowed: true,
            current_route_id: state.current_route_id.clone(),
            candidate_route_id: Some(candidate_route_id.to_string()),
            improvement_pct,
            hard_failover: false,
            recent_switches_in_window: recent_switches,
            reason: format!(
                "safety pass: improvement {:.1}% >= {:.1}%, hold/cooldown/window checks passed",
                improvement_pct, self.config.min_improvement_pct
            ),
        }
    }

    pub fn apply_safe_switch(
        &self,
        decision: &RouteSafetyDecision,
        apply_succeeds: bool,
    ) -> RouteApplyResult {
        if !decision.allowed {
            return RouteApplyResult {
                applied: false,
                previous_route_id: decision.current_route_id.clone(),
                active_route_id: decision.current_route_id.clone(),
                rollback_route_id: None,
                reason: format!("not applied: {}", decision.reason),
            };
        }

        let candidate = decision
            .candidate_route_id
            .clone()
            .unwrap_or_else(|| decision.current_route_id.clone());

        if apply_succeeds {
            RouteApplyResult {
                applied: true,
                previous_route_id: decision.current_route_id.clone(),
                active_route_id: candidate,
                rollback_route_id: Some(decision.current_route_id.clone()),
                reason: "safe route switch applied; previous route retained as rollback"
                    .to_string(),
            }
        } else {
            RouteApplyResult {
                applied: false,
                previous_route_id: decision.current_route_id.clone(),
                active_route_id: decision.current_route_id.clone(),
                rollback_route_id: Some(decision.current_route_id.clone()),
                reason: "apply failed; rollback/fallback kept previous route active".to_string(),
            }
        }
    }
}

fn block(
    verdict: SafetyVerdict,
    state: &RouteSwitchState,
    candidate_route_id: Option<&str>,
    improvement_pct: f64,
    hard_failover: bool,
    recent_switches_in_window: u32,
    reason: &str,
) -> RouteSafetyDecision {
    RouteSafetyDecision {
        verdict,
        allowed: false,
        current_route_id: state.current_route_id.clone(),
        candidate_route_id: candidate_route_id.map(str::to_string),
        improvement_pct,
        hard_failover,
        recent_switches_in_window,
        reason: reason.to_string(),
    }
}

fn recent_switches_in_window(now_ms: u64, state: &RouteSwitchState, window_seconds: u64) -> u32 {
    let window_start_ms = now_ms.saturating_sub(window_seconds.saturating_mul(1000));
    state
        .switch_timestamps_ms
        .iter()
        .filter(|ts| **ts >= window_start_ms)
        .count() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> RouteSwitchState {
        RouteSwitchState {
            current_route_id: "direct-nodeA-nodeB".to_string(),
            current_route_started_ms: 0,
            last_switch_ms: Some(10_000),
            switch_timestamps_ms: vec![10_000],
        }
    }

    #[test]
    fn allows_safe_switch_after_improvement_hold_and_cooldown() {
        let guard = RouteSafetyGuard::default();
        let decision = guard.evaluate(
            60_000,
            &state(),
            Some("relay-nodeA-via-nodeC-nodeB"),
            40.0,
            50.0,
        );

        assert!(decision.allowed);
        assert_eq!(decision.verdict, SafetyVerdict::Allow);
    }

    #[test]
    fn blocks_small_improvement_to_prevent_flapping() {
        let guard = RouteSafetyGuard::default();
        let decision = guard.evaluate(
            60_000,
            &state(),
            Some("relay-nodeA-via-nodeC-nodeB"),
            48.0,
            50.0,
        );

        assert!(!decision.allowed);
        assert_eq!(
            decision.verdict,
            SafetyVerdict::BlockInsufficientImprovement
        );
    }

    #[test]
    fn blocks_when_current_route_hold_time_not_met() {
        let guard = RouteSafetyGuard::default();
        let decision = guard.evaluate(
            25_000,
            &state(),
            Some("relay-nodeA-via-nodeC-nodeB"),
            30.0,
            50.0,
        );

        assert_eq!(decision.verdict, SafetyVerdict::BlockHoldTime);
    }

    #[test]
    fn blocks_when_switch_cooldown_is_active() {
        let guard = RouteSafetyGuard::default();
        let mut state = state();
        state.current_route_started_ms = 0;
        state.last_switch_ms = Some(25_000);
        state.switch_timestamps_ms = vec![25_000];
        let decision = guard.evaluate(
            40_000,
            &state,
            Some("relay-nodeA-via-nodeC-nodeB"),
            30.0,
            50.0,
        );

        assert!(!decision.allowed);
        assert_eq!(decision.verdict, SafetyVerdict::BlockCooldown);
        assert!(!decision.hard_failover);
        assert_eq!(decision.recent_switches_in_window, 1);
    }

    #[test]
    fn blocks_when_switch_window_limit_is_reached() {
        let guard = RouteSafetyGuard {
            config: RouteSafetyConfig {
                min_improvement_pct: 10.0,
                min_route_hold_seconds: 10,
                switch_cooldown_seconds: 5,
                max_switches_per_window: 2,
                window_seconds: 300,
            },
        };
        let state = RouteSwitchState {
            current_route_id: "direct-nodeA-nodeB".to_string(),
            current_route_started_ms: 0,
            last_switch_ms: Some(10_000),
            switch_timestamps_ms: vec![10_000, 30_000],
        };

        let decision = guard.evaluate(
            60_000,
            &state,
            Some("relay-nodeA-via-nodeC-nodeB"),
            30.0,
            50.0,
        );

        assert!(!decision.allowed);
        assert_eq!(decision.verdict, SafetyVerdict::BlockTooManySwitches);
        assert_eq!(decision.recent_switches_in_window, 2);
    }

    #[test]
    fn immediate_failover_is_allowed_only_for_hard_current_route_failure() {
        let guard = RouteSafetyGuard {
            config: RouteSafetyConfig {
                min_improvement_pct: 10.0,
                min_route_hold_seconds: 120,
                switch_cooldown_seconds: 120,
                max_switches_per_window: 1,
                window_seconds: 300,
            },
        };
        let state = RouteSwitchState {
            current_route_id: "direct-nodeA-nodeB".to_string(),
            current_route_started_ms: 55_000,
            last_switch_ms: Some(59_000),
            switch_timestamps_ms: vec![59_000],
        };

        let decision = guard.evaluate_with_route_health(
            60_000,
            &state,
            Some("relay-nodeA-via-nodeC-nodeB"),
            50.0,
            45.0,
            true,
        );

        assert!(decision.allowed);
        assert_eq!(decision.verdict, SafetyVerdict::Allow);
        assert!(decision.hard_failover);
        assert_eq!(decision.recent_switches_in_window, 1);
        assert!(decision.reason.contains("hard failure failover"));
    }

    #[test]
    fn failed_apply_keeps_previous_route_as_fallback() {
        let guard = RouteSafetyGuard::default();
        let decision = guard.evaluate(
            60_000,
            &state(),
            Some("relay-nodeA-via-nodeC-nodeB"),
            40.0,
            50.0,
        );
        let result = guard.apply_safe_switch(&decision, false);

        assert!(!result.applied);
        assert_eq!(result.active_route_id, "direct-nodeA-nodeB");
        assert_eq!(
            result.rollback_route_id.as_deref(),
            Some("direct-nodeA-nodeB")
        );
    }
}
