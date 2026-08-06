pub mod context;
pub mod errors;
pub mod generate;
pub mod kb;
pub mod model;
pub mod store;

#[cfg(test)]
mod tests;

use crate::advisory::context::load_device_context_for_alert_ip;
use crate::advisory::generate::generate;
use crate::advisory::kb::RecommendationRules;
use crate::advisory::store::append_capped;
use crate::threat::threat_alert::ThreatAlert;
use std::path::{Path, PathBuf};

pub use errors::{AdvisoryError, AdvisoryResult};
pub use kb::RecommendationRules as AdvisoryRules;
pub use model::{
    AnomalyContext, CveFinding, DeviceContext, RemediationRecommendation, RemediationStep,
};

const DEFAULT_MAX_RECOMMENDATIONS: usize = 2_000;

#[derive(Debug, Clone)]
pub struct AdvisoryConfig {
    pub base_dir: PathBuf,
    pub max_recommendations: usize,
}

impl AdvisoryConfig {
    pub fn from_state_dirs(threat_state_dir: impl AsRef<Path>) -> Self {
        let base_dir = std::env::var("SGX_GUARDIAN_ADVISORY_BASE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                threat_state_dir
                    .as_ref()
                    .parent()
                    .map(|parent| parent.join("advisory"))
                    .unwrap_or_else(|| PathBuf::from("/var/lib/sgx-guardian/advisory"))
            });
        let max_recommendations = std::env::var("SGX_ADVISORY_MAX_RECS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_MAX_RECOMMENDATIONS);
        Self {
            base_dir,
            max_recommendations,
        }
    }

    pub fn recommendations_path(&self) -> PathBuf {
        self.base_dir.join("recommendations.jsonl")
    }

    pub fn rules_path(&self) -> PathBuf {
        self.base_dir.join("recommendation_rules.json")
    }
}

pub fn generate_for_alert(
    node_id: String,
    alert: ThreatAlert,
    threat_state_dir: PathBuf,
    discovery_state_dir: PathBuf,
) {
    tokio::spawn(async move {
        let config = AdvisoryConfig::from_state_dirs(threat_state_dir);
        let rules = RecommendationRules::load_or_default(&config.rules_path());
        let inventory_path = discovery_state_dir.join("inventory.json");
        let device =
            match load_device_context_for_alert_ip(&inventory_path, &alert.src_ip, &alert.dst_ip) {
                Ok(device) => device,
                Err(err) => {
                    tracing::warn!(%node_id, %err, "failed to load advisory device context");
                    None
                }
            };
        let recommendation = generate(&alert, None, device.as_ref(), &rules);
        if let Err(err) = append_capped(
            &config.recommendations_path(),
            recommendation,
            config.max_recommendations,
        )
        .await
        {
            tracing::warn!(%node_id, %err, "failed to persist advisory recommendation");
        }
    });
}
