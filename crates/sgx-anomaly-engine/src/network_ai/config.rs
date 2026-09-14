//! Task 3 Deliverable 16: versioned, validated administrator settings.

use super::{NetworkAiRuntimeMode, RouteSafetyConfig};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const NETWORK_AI_CONFIG_VERSION: &str = "network-ai-config-v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkAiRewardWeights {
    pub latency_reward_weight: f64,
    pub throughput_reward_weight: f64,
    pub packet_loss_penalty_weight: f64,
    pub congestion_penalty: f64,
    pub hop_penalty_weight: f64,
    pub route_switch_penalty: f64,
    pub failure_penalty: f64,
}

impl Default for NetworkAiRewardWeights {
    fn default() -> Self {
        Self {
            latency_reward_weight: 0.35,
            throughput_reward_weight: 0.30,
            packet_loss_penalty_weight: 0.25,
            congestion_penalty: 8.0,
            hop_penalty_weight: 1.5,
            route_switch_penalty: 2.0,
            failure_penalty: 50.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkAiConfig {
    pub config_version: String,
    pub enabled: bool,
    pub mode: NetworkAiRuntimeMode,
    pub sample_interval_seconds: u64,
    pub history_window_entries: usize,
    pub safety: RouteSafetyConfig,
    pub degradation_probability_threshold: f64,
    pub rl_epsilon: f64,
    pub rl_learning_rate: f64,
    pub reward_weights: NetworkAiRewardWeights,
}

impl Default for NetworkAiConfig {
    fn default() -> Self {
        Self {
            config_version: NETWORK_AI_CONFIG_VERSION.to_string(),
            enabled: true,
            mode: NetworkAiRuntimeMode::Shadow,
            sample_interval_seconds: 10,
            history_window_entries: 20,
            safety: RouteSafetyConfig::default(),
            degradation_probability_threshold: 0.75,
            rl_epsilon: 0.05,
            rl_learning_rate: 0.25,
            reward_weights: NetworkAiRewardWeights::default(),
        }
    }
}

impl NetworkAiConfig {
    pub fn load_json(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading network AI config {}", path.display()))?;
        let config: Self = serde_json::from_str(&raw).context("parsing network AI config")?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.config_version != NETWORK_AI_CONFIG_VERSION {
            bail!(
                "unsupported network AI config_version '{}'",
                self.config_version
            );
        }
        if self.sample_interval_seconds == 0 || self.history_window_entries == 0 {
            bail!("sample interval and history window must be greater than zero");
        }
        if !(0.0..=100.0).contains(&self.safety.min_improvement_pct)
            || self.safety.min_route_hold_seconds == 0
            || self.safety.switch_cooldown_seconds == 0
            || self.safety.max_switches_per_window == 0
            || self.safety.window_seconds == 0
        {
            bail!("invalid route safety settings");
        }
        if !(0.0..=1.0).contains(&self.degradation_probability_threshold)
            || !(0.0..=1.0).contains(&self.rl_epsilon)
            || !(0.0..=1.0).contains(&self.rl_learning_rate)
            || self.rl_learning_rate == 0.0
        {
            bail!("degradation threshold and RL values must be within safe bounds");
        }
        let weights = &self.reward_weights;
        if [
            weights.latency_reward_weight,
            weights.throughput_reward_weight,
            weights.packet_loss_penalty_weight,
            weights.congestion_penalty,
            weights.hop_penalty_weight,
            weights.route_switch_penalty,
            weights.failure_penalty,
        ]
        .iter()
        .any(|value| !value.is_finite() || *value < 0.0)
        {
            bail!("reward weights must be finite non-negative values");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_safe_and_shadow_first() {
        let config = NetworkAiConfig::default();
        config.validate().unwrap();
        assert_eq!(config.mode, NetworkAiRuntimeMode::Shadow);
    }

    #[test]
    fn invalid_values_return_safe_errors() {
        let mut config = NetworkAiConfig::default();
        config.rl_epsilon = 2.0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn loads_versioned_config() {
        let path =
            std::env::temp_dir().join(format!("network-ai-config-{}.json", std::process::id()));
        fs::write(
            &path,
            serde_json::to_string(&NetworkAiConfig::default()).unwrap(),
        )
        .unwrap();
        let loaded = NetworkAiConfig::load_json(&path).unwrap();
        assert_eq!(loaded.config_version, NETWORK_AI_CONFIG_VERSION);
        let _ = fs::remove_file(path);
    }
}
