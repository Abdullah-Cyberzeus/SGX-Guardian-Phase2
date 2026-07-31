use serde::{Deserialize, Serialize};

pub mod executor;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "action")]
pub enum GeofenceAction {
    RaiseAlert { severity: Option<String> },
    Notify { severity: Option<String> },
    RunScan,
    LockNetwork,
    EmergencyKeyRotation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ZoneAutomation {
    #[serde(default)]
    pub on_entry: Vec<GeofenceAction>,
    #[serde(default = "default_on_exit")]
    pub on_exit: Vec<GeofenceAction>,
    #[serde(default)]
    pub allow_destructive: bool,
    #[serde(default = "default_min_confidence")]
    pub min_confidence: f64,
}

impl Default for ZoneAutomation {
    fn default() -> Self {
        Self {
            on_entry: Vec::new(),
            on_exit: default_on_exit(),
            allow_destructive: false,
            min_confidence: default_min_confidence(),
        }
    }
}

fn default_on_exit() -> Vec<GeofenceAction> {
    vec![GeofenceAction::RaiseAlert {
        severity: Some("high".to_string()),
    }]
}

fn default_min_confidence() -> f64 {
    0.9
}

pub fn validate(automation: &ZoneAutomation) -> Result<(), String> {
    if !automation.min_confidence.is_finite() || !(0.0..=1.0).contains(&automation.min_confidence) {
        return Err("min_confidence must be between 0.0 and 1.0".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_alert_only() {
        let automation = ZoneAutomation::default();
        assert!(automation.on_entry.is_empty());
        assert_eq!(automation.on_exit.len(), 1);
        assert!(!automation.allow_destructive);
        assert_eq!(automation.min_confidence, 0.9);
    }
}
