use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::api::auth::command_auth::CommandAuthError;

#[derive(Debug)]
pub struct DeviceRateLimiter {
    history: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    max_commands_per_min: usize,
    window_duration: Duration,
}

impl Default for DeviceRateLimiter {
    fn default() -> Self {
        Self::new(10, Duration::from_secs(60))
    }
}

impl DeviceRateLimiter {
    pub fn new(max_commands_per_min: usize, window_duration: Duration) -> Self {
        Self {
            history: Arc::new(RwLock::new(HashMap::new())),
            max_commands_per_min,
            window_duration,
        }
    }

    pub async fn check_rate_limit(&self, device_id: &str) -> Result<(), CommandAuthError> {
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window_duration).unwrap_or(now);

        let mut lock = self.history.write().await;
        let entry = lock.entry(device_id.to_string()).or_default();

        // Prune timestamps older than cutoff
        entry.retain(|&ts| ts > cutoff);

        if entry.len() >= self.max_commands_per_min {
            return Err(CommandAuthError::RateLimitExceeded(format!(
                "Rate limit exceeded for device '{}'. Max {} commands per minute.",
                device_id, self.max_commands_per_min
            )));
        }

        entry.push(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_allows_under_limit() {
        let limiter = DeviceRateLimiter::new(3, Duration::from_secs(60));
        let dev = "dev_test_1";

        assert!(limiter.check_rate_limit(dev).await.is_ok());
        assert!(limiter.check_rate_limit(dev).await.is_ok());
        assert!(limiter.check_rate_limit(dev).await.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiter_blocks_over_limit() {
        let limiter = DeviceRateLimiter::new(2, Duration::from_secs(60));
        let dev = "dev_test_2";

        assert!(limiter.check_rate_limit(dev).await.is_ok());
        assert!(limiter.check_rate_limit(dev).await.is_ok());
        let third = limiter.check_rate_limit(dev).await;
        assert!(matches!(third, Err(CommandAuthError::RateLimitExceeded(_))));
    }
}
