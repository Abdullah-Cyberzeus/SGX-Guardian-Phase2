use crate::advisory::AnomalyRiskLevel;
use anyhow::{anyhow, bail, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const SCHEMA_VERSION: u32 = 1;
const SETTINGS_FILE: &str = "task1_threshold_settings.json";
const AUDIT_FILE: &str = "task1_threshold_settings_audit.jsonl";

pub const DEFAULT_DETECTION_THRESHOLD: f32 = 0.50;
pub const DEFAULT_HIGH_THRESHOLD: f32 = 0.75;
pub const DEFAULT_CRITICAL_THRESHOLD: f32 = 0.90;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct ThresholdRange {
    pub min: f32,
    pub max: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecommendedThresholdRanges {
    pub detection: ThresholdRange,
    pub high: ThresholdRange,
    pub critical: ThresholdRange,
    pub note: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct Task1ThresholdDefaults {
    pub detection_threshold: f32,
    pub high_threshold: f32,
    pub critical_threshold: f32,
}

impl Default for Task1ThresholdDefaults {
    fn default() -> Self {
        Self {
            detection_threshold: DEFAULT_DETECTION_THRESHOLD,
            high_threshold: DEFAULT_HIGH_THRESHOLD,
            critical_threshold: DEFAULT_CRITICAL_THRESHOLD,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Task1ThresholdSettings {
    pub schema_version: u32,
    pub settings_version: u64,
    pub detection_threshold: f32,
    pub high_threshold: f32,
    pub critical_threshold: f32,
    pub updated_by: String,
    pub updated_at: String,
    pub reason: String,
}

impl Task1ThresholdSettings {
    pub fn defaults() -> Task1ThresholdDefaults {
        Task1ThresholdDefaults::default()
    }

    pub fn recommended_ranges() -> RecommendedThresholdRanges {
        RecommendedThresholdRanges {
            detection: ThresholdRange {
                min: 0.45,
                max: 0.60,
            },
            high: ThresholdRange {
                min: 0.70,
                max: 0.85,
            },
            critical: ThresholdRange {
                min: 0.85,
                max: 0.95,
            },
            note: "Guidance only; validate against real telemetry before production tuning."
                .to_string(),
        }
    }

    pub fn default_settings() -> Self {
        let defaults = Self::defaults();
        Self {
            schema_version: SCHEMA_VERSION,
            settings_version: 1,
            detection_threshold: defaults.detection_threshold,
            high_threshold: defaults.high_threshold,
            critical_threshold: defaults.critical_threshold,
            updated_by: "system_default".to_string(),
            updated_at: Utc::now().to_rfc3339(),
            reason: "Default Task 1 thresholds preserved from the existing SGX runtime."
                .to_string(),
        }
    }

    pub fn risk_level(&self, normalized_score: f32) -> AnomalyRiskLevel {
        if normalized_score >= self.critical_threshold {
            AnomalyRiskLevel::Critical
        } else if normalized_score >= self.high_threshold {
            AnomalyRiskLevel::High
        } else if normalized_score >= self.detection_threshold {
            AnomalyRiskLevel::Detected
        } else {
            AnomalyRiskLevel::BelowDetection
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Task1ThresholdAuditEntry {
    pub schema_version: u32,
    pub settings_version: u64,
    pub actor: String,
    pub changed_at: String,
    pub reason: String,
    pub previous: Task1ThresholdSettings,
    pub active: Task1ThresholdSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Task1ThresholdUpdate {
    pub detection_threshold: f32,
    pub high_threshold: f32,
    pub critical_threshold: f32,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct Task1ThresholdSettingsService {
    settings_path: PathBuf,
    audit_path: PathBuf,
}

impl Task1ThresholdSettingsService {
    pub fn for_state_dir(state_dir: impl AsRef<Path>) -> Self {
        let state_dir = state_dir.as_ref();
        Self {
            settings_path: state_dir.join(SETTINGS_FILE),
            audit_path: state_dir.join(AUDIT_FILE),
        }
    }

    pub fn with_paths(settings_path: impl Into<PathBuf>, audit_path: impl Into<PathBuf>) -> Self {
        Self {
            settings_path: settings_path.into(),
            audit_path: audit_path.into(),
        }
    }

    pub fn load_or_create(&self) -> Result<Task1ThresholdSettings> {
        match fs::read_to_string(&self.settings_path) {
            Ok(text) => {
                let settings: Task1ThresholdSettings = serde_json::from_str(&text)?;
                validate(&settings)?;
                Ok(settings)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let settings = Task1ThresholdSettings::default_settings();
                self.write_settings(&settings)?;
                Ok(settings)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn load_or_default(&self) -> Task1ThresholdSettings {
        self.load_or_create()
            .unwrap_or_else(|_| Task1ThresholdSettings::default_settings())
    }

    pub fn update(
        &self,
        actor: &str,
        update: Task1ThresholdUpdate,
    ) -> Result<Task1ThresholdSettings> {
        if actor.trim().is_empty() {
            bail!("actor is required");
        }
        if update.reason.trim().is_empty() {
            bail!("reason is required");
        }

        let current = self.load_or_create()?;
        let next = Task1ThresholdSettings {
            schema_version: SCHEMA_VERSION,
            settings_version: current
                .settings_version
                .checked_add(1)
                .ok_or_else(|| anyhow!("task1 threshold settings version overflow"))?,
            detection_threshold: update.detection_threshold,
            high_threshold: update.high_threshold,
            critical_threshold: update.critical_threshold,
            updated_by: actor.trim().to_string(),
            updated_at: Utc::now().to_rfc3339(),
            reason: update.reason.trim().to_string(),
        };
        validate(&next)?;
        self.write_settings(&next)?;
        self.append_audit(&current, &next, actor.trim())?;
        Ok(next)
    }

    fn write_settings(&self, settings: &Task1ThresholdSettings) -> Result<()> {
        if let Some(parent) = self.settings_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(
            &self.settings_path,
            format!("{}\n", serde_json::to_string_pretty(settings)?),
        )?;
        Ok(())
    }

    fn append_audit(
        &self,
        previous: &Task1ThresholdSettings,
        active: &Task1ThresholdSettings,
        actor: &str,
    ) -> Result<()> {
        if let Some(parent) = self.audit_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let entry = Task1ThresholdAuditEntry {
            schema_version: SCHEMA_VERSION,
            settings_version: active.settings_version,
            actor: actor.to_string(),
            changed_at: active.updated_at.clone(),
            reason: active.reason.clone(),
            previous: previous.clone(),
            active: active.clone(),
        };
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.audit_path)?;
        writeln!(file, "{}", serde_json::to_string(&entry)?)?;
        Ok(())
    }
}

pub fn validate(settings: &Task1ThresholdSettings) -> Result<()> {
    let values = [
        settings.detection_threshold,
        settings.high_threshold,
        settings.critical_threshold,
    ];
    if values.iter().any(|value| !value.is_finite())
        || settings.detection_threshold < 0.0
        || settings.critical_threshold > 1.0
        || !(settings.detection_threshold < settings.high_threshold
            && settings.high_threshold < settings.critical_threshold)
    {
        bail!("thresholds must satisfy 0 <= detection < high < critical <= 1");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_settings_are_valid() {
        validate(&Task1ThresholdSettings::default_settings()).expect("defaults should validate");
    }

    #[test]
    fn invalid_order_is_rejected() {
        let mut settings = Task1ThresholdSettings::default_settings();
        settings.high_threshold = 0.40;
        assert!(validate(&settings).is_err());
    }

    #[test]
    fn risk_level_uses_active_threshold_bands() {
        let settings = Task1ThresholdSettings::default_settings();
        assert_eq!(settings.risk_level(0.40), AnomalyRiskLevel::BelowDetection);
        assert_eq!(settings.risk_level(0.60), AnomalyRiskLevel::Detected);
        assert_eq!(settings.risk_level(0.80), AnomalyRiskLevel::High);
        assert_eq!(settings.risk_level(0.95), AnomalyRiskLevel::Critical);
    }

    #[test]
    fn service_persists_and_audits_updates() {
        let temp = tempfile::tempdir().expect("tempdir");
        let service = Task1ThresholdSettingsService::with_paths(
            temp.path().join("settings.json"),
            temp.path().join("audit.jsonl"),
        );

        let current = service.load_or_create().expect("seed defaults");
        assert_eq!(current.settings_version, 1);

        let saved = service
            .update(
                "owner-1",
                Task1ThresholdUpdate {
                    detection_threshold: 0.55,
                    high_threshold: 0.80,
                    critical_threshold: 0.95,
                    reason: "tune for staging".to_string(),
                },
            )
            .expect("update settings");

        assert_eq!(saved.settings_version, 2);
        assert_eq!(saved.updated_by, "owner-1");
        assert!(service
            .load_or_create()
            .expect("reload settings")
            .reason
            .contains("staging"));
        assert!(std::fs::read_to_string(temp.path().join("audit.jsonl"))
            .expect("read audit")
            .contains("tune for staging"));
    }
}
