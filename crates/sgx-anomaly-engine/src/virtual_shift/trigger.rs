//! VS2: deterministic Virtual Shift trigger threshold, debounce and idempotency.
//!
//! This is separate from Task 1's alert threshold/cooldown. Task 1 still
//! decides whether an anomaly exists; VS2 decides whether it may begin the
//! later Virtual Shift policy-recommendation workflow.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::engine::EngineConfig;

use super::errors::VirtualShiftError;
use super::model::{AnomalyEvent, AnomalyType};

/// Admin-configurable limits for starting Virtual Shift.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VirtualShiftTriggerConfig {
    pub min_score: f64,
    pub min_confidence: f64,
    pub cooldown_ms: u64,
}

impl Default for VirtualShiftTriggerConfig {
    fn default() -> Self {
        Self {
            min_score: 0.85,
            min_confidence: 0.80,
            cooldown_ms: 300_000,
        }
    }
}

impl VirtualShiftTriggerConfig {
    /// Build the Virtual Shift admission gate from the existing Task 1
    /// engine configuration. This reuses the deployed score/confidence and
    /// cooldown settings without changing Task 1 scoring or its alert gate.
    ///
    /// A caller that has an `EngineConfig` should use this constructor rather
    /// than duplicating threshold values in another configuration file.
    pub fn from_engine_config(engine: &EngineConfig) -> Result<Self, VirtualShiftError> {
        let cooldown_ms = u64::try_from(engine.cooldown.as_millis())
            .map_err(|_| VirtualShiftError::InvalidTriggerCooldown)?;
        let config = Self {
            min_score: engine.alert_threshold,
            min_confidence: engine.min_confidence,
            cooldown_ms,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), VirtualShiftError> {
        if !self.min_score.is_finite() || !(0.0..=1.0).contains(&self.min_score) {
            return Err(VirtualShiftError::InvalidTriggerScoreThreshold);
        }
        if !self.min_confidence.is_finite() || !(0.0..=1.0).contains(&self.min_confidence) {
            return Err(VirtualShiftError::InvalidTriggerConfidenceThreshold);
        }
        if self.cooldown_ms == 0 {
            return Err(VirtualShiftError::InvalidTriggerCooldown);
        }
        Ok(())
    }
}

/// The exact result of considering one validated Task 1 anomaly event.
#[derive(Debug, Clone, PartialEq)]
pub enum TriggerDecision {
    Triggered,
    BelowThreshold { min_score: f64, min_confidence: f64 },
    DuplicateAnomalyId,
    Debounced { retry_after_ms: u64 },
}

/// VS2 in-memory trigger state. Durable workflow records are added later by
/// the plan's persistence/audit phases.
#[derive(Debug)]
pub struct VirtualShiftTriggerManager {
    config: VirtualShiftTriggerConfig,
    seen_anomaly_ids: BTreeSet<String>,
    last_trigger_by_scope: BTreeMap<TriggerScope, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TriggerScope {
    node: String,
    anomaly_type: AnomalyType,
}

impl VirtualShiftTriggerManager {
    pub fn new(config: VirtualShiftTriggerConfig) -> Result<Self, VirtualShiftError> {
        config.validate()?;
        Ok(Self {
            config,
            seen_anomaly_ids: BTreeSet::new(),
            last_trigger_by_scope: BTreeMap::new(),
        })
    }

    /// Convenience constructor for production wiring: inherit the already
    /// configured Task 1 admission values instead of maintaining a second
    /// copy of score/confidence/cooldown settings.
    pub fn from_engine_config(engine: &EngineConfig) -> Result<Self, VirtualShiftError> {
        Self::new(VirtualShiftTriggerConfig::from_engine_config(engine)?)
    }

    pub fn config(&self) -> &VirtualShiftTriggerConfig {
        &self.config
    }

    /// Evaluate a VS1-validated event exactly once.
    pub fn consider(&mut self, event: &AnomalyEvent) -> Result<TriggerDecision, VirtualShiftError> {
        event.validate()?;

        // Register before threshold checks: redelivery of the same event can
        // never later create a second workflow.
        if !self.seen_anomaly_ids.insert(event.anomaly_id.clone()) {
            return Ok(TriggerDecision::DuplicateAnomalyId);
        }

        if event.score < self.config.min_score || event.confidence < self.config.min_confidence {
            return Ok(TriggerDecision::BelowThreshold {
                min_score: self.config.min_score,
                min_confidence: self.config.min_confidence,
            });
        }

        let scope = TriggerScope {
            node: event.source_node.clone(),
            anomaly_type: event.anomaly_type.clone(),
        };
        if let Some(last_trigger_at) = self.last_trigger_by_scope.get(&scope) {
            let elapsed = event.observed_at_ms.saturating_sub(*last_trigger_at);
            if elapsed < self.config.cooldown_ms {
                return Ok(TriggerDecision::Debounced {
                    retry_after_ms: self.config.cooldown_ms - elapsed,
                });
            }
        }

        self.last_trigger_by_scope
            .insert(scope, event.observed_at_ms);
        Ok(TriggerDecision::Triggered)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::alert::Severity;
    use crate::engine::EngineConfig;
    use crate::virtual_shift::{AnomalyEvidence, AnomalyType};

    use super::*;

    fn event(id: &str, timestamp: u64, score: f64, confidence: f64) -> AnomalyEvent {
        AnomalyEvent {
            anomaly_id: id.into(),
            source_node: "nodeA".into(),
            anomaly_type: AnomalyType::ConnectionScan,
            score,
            confidence,
            severity: Severity::High,
            affected_peers: vec![],
            observed_at_ms: timestamp,
            evidence: vec![AnomalyEvidence {
                feature: "conn_rate".into(),
            }],
            reason: "test".into(),
            recommendation: "test".into(),
            proposed_action: None,
        }
    }

    fn manager() -> VirtualShiftTriggerManager {
        VirtualShiftTriggerManager::new(VirtualShiftTriggerConfig {
            min_score: 0.85,
            min_confidence: 0.80,
            cooldown_ms: 60_000,
        })
        .unwrap()
    }

    #[test]
    fn below_threshold_event_does_not_start_virtual_shift() {
        let mut trigger = manager();
        assert_eq!(
            trigger.consider(&event("low", 1000, 0.84, 0.90)).unwrap(),
            TriggerDecision::BelowThreshold {
                min_score: 0.85,
                min_confidence: 0.80,
            }
        );
    }

    #[test]
    fn threshold_crossing_starts_virtual_shift_once() {
        let mut trigger = manager();
        let high = event("high", 1000, 0.90, 0.90);
        assert_eq!(trigger.consider(&high).unwrap(), TriggerDecision::Triggered);
        assert_eq!(
            trigger.consider(&high).unwrap(),
            TriggerDecision::DuplicateAnomalyId
        );
    }

    #[test]
    fn repeated_same_node_type_is_debounced_then_allowed_after_cooldown() {
        let mut trigger = manager();
        assert_eq!(
            trigger
                .consider(&event("first", 100_000, 0.90, 0.90))
                .unwrap(),
            TriggerDecision::Triggered
        );
        assert_eq!(
            trigger
                .consider(&event("second", 130_000, 0.90, 0.90))
                .unwrap(),
            TriggerDecision::Debounced {
                retry_after_ms: 30_000
            }
        );
        assert_eq!(
            trigger
                .consider(&event("third", 160_000, 0.90, 0.90))
                .unwrap(),
            TriggerDecision::Triggered
        );
    }

    #[test]
    fn invalid_trigger_config_is_rejected() {
        assert_eq!(
            VirtualShiftTriggerManager::new(VirtualShiftTriggerConfig {
                min_score: 1.1,
                ..VirtualShiftTriggerConfig::default()
            })
            .unwrap_err(),
            VirtualShiftError::InvalidTriggerScoreThreshold
        );
    }

    #[test]
    fn trigger_config_reuses_existing_engine_admission_settings() {
        let engine = EngineConfig {
            poll_interval: Duration::from_secs(1),
            alert_threshold: 0.81,
            min_confidence: 0.62,
            cooldown: Duration::from_secs(75),
        };
        let trigger = VirtualShiftTriggerManager::from_engine_config(&engine).unwrap();
        assert_eq!(
            trigger.config(),
            &VirtualShiftTriggerConfig {
                min_score: 0.81,
                min_confidence: 0.62,
                cooldown_ms: 75_000,
            }
        );
    }
}
