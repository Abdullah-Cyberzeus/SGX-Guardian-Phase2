use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};

/// Rate-limits high-frequency telemetry events to max 1 sample per 60 seconds per entity.
pub struct TelemetrySampler {
    last_sampled: RwLock<HashMap<String, Instant>>,
    sample_interval: Duration,
}

impl TelemetrySampler {
    pub fn new(interval_secs: u64) -> Arc<Self> {
        Arc::new(Self {
            last_sampled: RwLock::new(HashMap::new()),
            sample_interval: Duration::from_secs(interval_secs),
        })
    }

    /// Default sampler with 60-second sampling interval
    pub fn default_60s() -> Arc<Self> {
        Self::new(60)
    }

    /// Returns `true` if the entity should be sampled (>= interval since last sample), `false` otherwise.
    pub async fn should_sample(&self, entity_id: &str) -> bool {
        let now = Instant::now();

        // Fast read check
        {
            let map = self.last_sampled.read().await;
            if let Some(last) = map.get(entity_id) {
                if now.duration_since(*last) < self.sample_interval {
                    return false; // Skip sampling
                }
            }
        }

        // Upgrade to write lock to update timestamp
        let mut map = self.last_sampled.write().await;
        map.insert(entity_id.to_string(), now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sampler_rate_limiting() {
        let sampler = TelemetrySampler::new(1); // 1s interval for test
        let entity = "sensor.temperature";

        // First attempt should be sampled
        assert!(sampler.should_sample(entity).await);

        // Immediate second attempt should be blocked
        assert!(!sampler.should_sample(entity).await);

        // Wait >1s
        tokio::time::sleep(Duration::from_millis(1100)).await;

        // Third attempt after interval should pass
        assert!(sampler.should_sample(entity).await);
    }
}
