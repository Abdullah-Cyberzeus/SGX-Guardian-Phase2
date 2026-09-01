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

    #[test]
    fn new_returns_arc_with_requested_interval_and_empty_state() {
        let sampler = TelemetrySampler::new(42);
        assert_eq!(sampler.sample_interval, Duration::from_secs(42));
        assert!(sampler.last_sampled.blocking_read().is_empty());
    }

    #[test]
    fn default_60s_uses_sixty_second_interval() {
        let sampler = TelemetrySampler::default_60s();
        assert_eq!(sampler.sample_interval, Duration::from_secs(60));
    }

    #[tokio::test]
    async fn first_sample_for_new_entity_is_allowed() {
        let sampler = TelemetrySampler::new(60);
        assert!(sampler.should_sample("entity-a").await);
    }

    #[tokio::test]
    async fn immediate_second_sample_for_same_entity_is_blocked() {
        let sampler = TelemetrySampler::new(60);
        assert!(sampler.should_sample("entity-a").await);
        assert!(!sampler.should_sample("entity-a").await);
    }

    #[tokio::test]
    async fn different_entities_are_tracked_independently() {
        let sampler = TelemetrySampler::new(60);
        assert!(sampler.should_sample("entity-a").await);
        assert!(sampler.should_sample("entity-b").await);
        assert!(!sampler.should_sample("entity-a").await);
        assert!(!sampler.should_sample("entity-b").await);
    }

    #[tokio::test]
    async fn zero_interval_allows_repeated_samples() {
        let sampler = TelemetrySampler::new(0);
        assert!(sampler.should_sample("entity-a").await);
        assert!(sampler.should_sample("entity-a").await);
        assert!(sampler.should_sample("entity-a").await);
    }

    #[tokio::test]
    async fn empty_entity_id_is_a_valid_key() {
        let sampler = TelemetrySampler::new(60);
        assert!(sampler.should_sample("").await);
        assert!(!sampler.should_sample("").await);
    }

    #[tokio::test]
    async fn whitespace_entity_id_is_not_trimmed() {
        let sampler = TelemetrySampler::new(60);
        assert!(sampler.should_sample("entity").await);
        assert!(sampler.should_sample(" entity ").await);
        assert!(!sampler.should_sample("entity").await);
        assert!(!sampler.should_sample(" entity ").await);
    }

    #[tokio::test]
    async fn case_sensitive_entity_ids_are_independent() {
        let sampler = TelemetrySampler::new(60);
        assert!(sampler.should_sample("Sensor").await);
        assert!(sampler.should_sample("sensor").await);
        assert!(!sampler.should_sample("Sensor").await);
    }

    #[tokio::test]
    async fn unicode_entity_id_round_trips_as_key() {
        let sampler = TelemetrySampler::new(60);
        assert!(sampler.should_sample("sensor-\u{2603}").await);
        assert!(!sampler.should_sample("sensor-\u{2603}").await);
    }

    #[tokio::test]
    async fn allowed_sample_updates_timestamp() {
        let sampler = TelemetrySampler::new(0);
        assert!(sampler.should_sample("entity-a").await);
        let first = *sampler
            .last_sampled
            .read()
            .await
            .get("entity-a")
            .expect("first timestamp");
        assert!(sampler.should_sample("entity-a").await);
        let second = *sampler
            .last_sampled
            .read()
            .await
            .get("entity-a")
            .expect("second timestamp");
        assert!(second >= first);
    }

    #[tokio::test]
    async fn blocked_sample_keeps_original_timestamp() {
        let sampler = TelemetrySampler::new(60);
        assert!(sampler.should_sample("entity-a").await);
        let first = *sampler
            .last_sampled
            .read()
            .await
            .get("entity-a")
            .expect("first timestamp");
        assert!(!sampler.should_sample("entity-a").await);
        let second = *sampler
            .last_sampled
            .read()
            .await
            .get("entity-a")
            .expect("second timestamp");
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn stale_existing_timestamp_allows_sample() {
        let sampler = TelemetrySampler::new(60);
        sampler
            .last_sampled
            .write()
            .await
            .insert("entity-a".into(), Instant::now() - Duration::from_secs(61));
        assert!(sampler.should_sample("entity-a").await);
    }

    #[tokio::test]
    async fn timestamp_exactly_at_interval_boundary_is_allowed() {
        let sampler = TelemetrySampler::new(60);
        sampler
            .last_sampled
            .write()
            .await
            .insert("entity-a".into(), Instant::now() - Duration::from_secs(60));
        assert!(sampler.should_sample("entity-a").await);
    }

    #[tokio::test]
    async fn timestamp_inside_interval_boundary_is_blocked() {
        let sampler = TelemetrySampler::new(60);
        sampler
            .last_sampled
            .write()
            .await
            .insert("entity-a".into(), Instant::now() - Duration::from_secs(59));
        assert!(!sampler.should_sample("entity-a").await);
    }

    #[tokio::test]
    async fn many_unique_entities_are_all_recorded() {
        let sampler = TelemetrySampler::new(60);
        for index in 0..25 {
            assert!(sampler.should_sample(&format!("entity-{index}")).await);
        }
        assert_eq!(sampler.last_sampled.read().await.len(), 25);
    }

    #[tokio::test]
    async fn concurrent_same_entity_allows_at_least_one_and_records_single_key() {
        let sampler = TelemetrySampler::new(60);
        let mut handles = Vec::new();
        for _ in 0..8 {
            let sampler = Arc::clone(&sampler);
            handles.push(tokio::spawn(async move {
                sampler.should_sample("shared-entity").await
            }));
        }

        let mut allowed = 0;
        for handle in handles {
            if handle.await.expect("task joins") {
                allowed += 1;
            }
        }
        assert!(allowed >= 1);
        assert_eq!(sampler.last_sampled.read().await.len(), 1);
    }
}
