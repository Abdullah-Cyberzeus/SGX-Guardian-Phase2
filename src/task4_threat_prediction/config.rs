use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sgx_anomaly_engine::threat_prediction::ThreatPredictionConfig;
use std::path::{Path, PathBuf};
use std::time::Duration;

const DEFAULT_TASK4_CONFIG_JSON: &str =
    include_str!("../../crates/sgx-anomaly-engine/config/threat_prediction.json");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task4ThreatPredictionRuntimeConfig {
    pub node_id: String,
    pub config_path: PathBuf,
    pub state_dir: PathBuf,
    pub task1_state_dir: PathBuf,
    pub task3_runtime_dir: PathBuf,
    pub virtual_shift_root: PathBuf,
    pub queue_capacity: usize,
    pub max_events: usize,
    pub debounce: Duration,
    pub prediction: ThreatPredictionConfig,
    pub config_error: Option<String>,
}

impl Task4ThreatPredictionRuntimeConfig {
    pub fn from_env(node_id: impl Into<String>, threat_state_dir: impl AsRef<Path>) -> Self {
        let node_id = node_id.into();
        let threat_state_dir = threat_state_dir.as_ref();
        let config_path = std::env::var("SGX_TASK4_THREAT_PREDICTION_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/etc/sgx-guardian/threat-prediction/config.json"));
        let state_dir = std::env::var("SGX_TASK4_THREAT_PREDICTION_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/var/lib/sgx-guardian/threat-prediction"));
        let task3_runtime_dir = std::env::var("SGX_TASK3_NETWORK_AI_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| threat_state_dir.join("network_ai").join("runtime"));
        let queue_capacity = env_usize("SGX_TASK4_QUEUE_CAPACITY").unwrap_or(1024);
        let max_events = env_usize("SGX_TASK4_MAX_EVENTS").unwrap_or(10_000);
        let debounce_secs = env_u64("SGX_TASK4_EVENT_DEBOUNCE_SECS").unwrap_or(30);
        let (prediction, config_error) = load_or_seed_prediction_config(&config_path);

        Self {
            node_id,
            config_path,
            state_dir,
            task1_state_dir: threat_state_dir.to_path_buf(),
            task3_runtime_dir,
            virtual_shift_root: threat_state_dir.join("virtual_shift"),
            queue_capacity,
            max_events,
            debounce: Duration::from_secs(debounce_secs.max(1)),
            prediction,
            config_error,
        }
    }

    pub fn for_tests(
        node_id: impl Into<String>,
        config_path: PathBuf,
        state_dir: PathBuf,
        threat_state_dir: PathBuf,
    ) -> Self {
        let (prediction, config_error) = load_or_seed_prediction_config(&config_path);
        Self {
            node_id: node_id.into(),
            config_path,
            state_dir,
            task1_state_dir: threat_state_dir.clone(),
            task3_runtime_dir: threat_state_dir.join("network_ai").join("runtime"),
            virtual_shift_root: threat_state_dir.join("virtual_shift"),
            queue_capacity: 32,
            max_events: 512,
            debounce: Duration::from_millis(10),
            prediction,
            config_error,
        }
    }
}

fn load_or_seed_prediction_config(path: &Path) -> (ThreatPredictionConfig, Option<String>) {
    let result = if path.exists() {
        ThreatPredictionConfig::load_json(path).map_err(|error| error.to_string())
    } else {
        seed_default_config(path).and_then(|_| {
            ThreatPredictionConfig::load_json(path).map_err(|error| error.to_string())
        })
    };

    match result {
        Ok(config) => (config, None),
        Err(error) => {
            let mut disabled = ThreatPredictionConfig::default();
            disabled.enabled = false;
            (disabled, Some(error))
        }
    }
}

fn seed_default_config(path: &Path) -> std::result::Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    std::fs::write(path, DEFAULT_TASK4_CONFIG_JSON).map_err(|error| error.to_string())
}

pub fn ensure_runtime_dirs(config: &Task4ThreatPredictionRuntimeConfig) -> Result<()> {
    std::fs::create_dir_all(&config.state_dir)
        .with_context(|| format!("create Task4 state dir {}", config.state_dir.display()))?;
    std::fs::create_dir_all(config.state_dir.join("audit"))
        .with_context(|| format!("create Task4 audit dir {}", config.state_dir.display()))?;
    Ok(())
}

fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name).ok()?.parse().ok()
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok()?.parse().ok()
}
