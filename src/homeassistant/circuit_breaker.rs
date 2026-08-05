use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open { opened_at: Instant },
    HalfOpen,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CircuitBreakerError {
    CircuitOpen(String),
}

impl std::fmt::Display for CircuitBreakerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitBreakerError::CircuitOpen(msg) => write!(f, "{}", msg),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CircuitBreaker {
    failure_threshold: usize,
    reset_timeout: Duration,
    state: Arc<RwLock<CircuitState>>,
    consecutive_failures: Arc<AtomicUsize>,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(5, Duration::from_secs(30))
    }
}

impl CircuitBreaker {
    pub fn new(failure_threshold: usize, reset_timeout: Duration) -> Self {
        Self {
            failure_threshold,
            reset_timeout,
            state: Arc::new(RwLock::new(CircuitState::Closed)),
            consecutive_failures: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub async fn can_execute(&self) -> Result<(), CircuitBreakerError> {
        let mut state_lock = self.state.write().await;
        match *state_lock {
            CircuitState::Closed => Ok(()),
            CircuitState::Open { opened_at } => {
                if opened_at.elapsed() >= self.reset_timeout {
                    *state_lock = CircuitState::HalfOpen;
                    Ok(())
                } else {
                    let remaining = self.reset_timeout.saturating_sub(opened_at.elapsed());
                    Err(CircuitBreakerError::CircuitOpen(format!(
                        "Circuit breaker is OPEN. Fast failing requests for another {}s.",
                        remaining.as_secs()
                    )))
                }
            }
            CircuitState::HalfOpen => Ok(()),
        }
    }

    pub async fn on_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        let mut state_lock = self.state.write().await;
        if *state_lock != CircuitState::Closed {
            *state_lock = CircuitState::Closed;
        }
    }

    pub async fn on_failure(&self) {
        let fails = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        let mut state_lock = self.state.write().await;
        if fails >= self.failure_threshold {
            *state_lock = CircuitState::Open {
                opened_at: Instant::now(),
            };
        }
    }

    pub async fn current_state(&self) -> CircuitState {
        self.state.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_circuit_breaker_transitions() {
        let cb = CircuitBreaker::new(2, Duration::from_millis(50));

        assert_eq!(cb.current_state().await, CircuitState::Closed);
        assert!(cb.can_execute().await.is_ok());

        // 1st failure
        cb.on_failure().await;
        assert_eq!(cb.current_state().await, CircuitState::Closed);

        // 2nd failure -> opens circuit
        cb.on_failure().await;
        assert!(matches!(cb.current_state().await, CircuitState::Open { .. }));
        assert!(cb.can_execute().await.is_err());

        // Wait for reset timeout
        tokio::time::sleep(Duration::from_millis(60)).await;

        // Next execute transitions to HalfOpen
        assert!(cb.can_execute().await.is_ok());
        assert_eq!(cb.current_state().await, CircuitState::HalfOpen);

        // Success closes circuit
        cb.on_success().await;
        assert_eq!(cb.current_state().await, CircuitState::Closed);
    }
}
