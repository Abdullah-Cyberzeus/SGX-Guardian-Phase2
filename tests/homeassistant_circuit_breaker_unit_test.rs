use sgx_guardian_client::homeassistant::circuit_breaker::{
    CircuitBreaker, CircuitBreakerError, CircuitState,
};
use std::time::Duration;

#[tokio::test]
async fn default_circuit_starts_closed() {
    let breaker = CircuitBreaker::default();
    assert_eq!(breaker.current_state().await, CircuitState::Closed);
    assert!(breaker.can_execute().await.is_ok());
}

#[tokio::test]
async fn new_circuit_starts_closed() {
    let breaker = CircuitBreaker::new(3, Duration::from_secs(10));
    assert_eq!(breaker.current_state().await, CircuitState::Closed);
}

#[tokio::test]
async fn below_threshold_failures_keep_circuit_closed() {
    let breaker = CircuitBreaker::new(3, Duration::from_secs(10));
    breaker.on_failure().await;
    breaker.on_failure().await;
    assert_eq!(breaker.current_state().await, CircuitState::Closed);
}

#[tokio::test]
async fn reaching_threshold_opens_circuit() {
    let breaker = CircuitBreaker::new(2, Duration::from_secs(10));
    breaker.on_failure().await;
    breaker.on_failure().await;
    assert!(matches!(
        breaker.current_state().await,
        CircuitState::Open { .. }
    ));
}

#[tokio::test]
async fn threshold_one_opens_on_first_failure() {
    let breaker = CircuitBreaker::new(1, Duration::from_secs(10));
    breaker.on_failure().await;
    assert!(matches!(
        breaker.current_state().await,
        CircuitState::Open { .. }
    ));
}

#[tokio::test]
async fn threshold_zero_opens_on_first_failure() {
    let breaker = CircuitBreaker::new(0, Duration::from_secs(10));
    breaker.on_failure().await;
    assert!(matches!(
        breaker.current_state().await,
        CircuitState::Open { .. }
    ));
}

#[tokio::test]
async fn open_circuit_fast_fails_before_timeout() {
    let breaker = CircuitBreaker::new(1, Duration::from_secs(30));
    breaker.on_failure().await;
    let err = breaker.can_execute().await.unwrap_err();
    assert!(matches!(err, CircuitBreakerError::CircuitOpen(_)));
    assert!(err.to_string().contains("Circuit breaker is OPEN"));
}

#[tokio::test]
async fn open_circuit_moves_to_half_open_after_timeout() {
    let breaker = CircuitBreaker::new(1, Duration::from_millis(10));
    breaker.on_failure().await;
    tokio::time::sleep(Duration::from_millis(15)).await;
    assert!(breaker.can_execute().await.is_ok());
    assert_eq!(breaker.current_state().await, CircuitState::HalfOpen);
}

#[tokio::test]
async fn zero_timeout_open_circuit_immediately_moves_half_open() {
    let breaker = CircuitBreaker::new(1, Duration::ZERO);
    breaker.on_failure().await;
    assert!(breaker.can_execute().await.is_ok());
    assert_eq!(breaker.current_state().await, CircuitState::HalfOpen);
}

#[tokio::test]
async fn success_resets_closed_failure_count() {
    let breaker = CircuitBreaker::new(2, Duration::from_secs(10));
    breaker.on_failure().await;
    breaker.on_success().await;
    breaker.on_failure().await;
    assert_eq!(breaker.current_state().await, CircuitState::Closed);
}

#[tokio::test]
async fn success_closes_half_open_circuit() {
    let breaker = CircuitBreaker::new(1, Duration::ZERO);
    breaker.on_failure().await;
    breaker.can_execute().await.unwrap();
    assert_eq!(breaker.current_state().await, CircuitState::HalfOpen);
    breaker.on_success().await;
    assert_eq!(breaker.current_state().await, CircuitState::Closed);
}

#[tokio::test]
async fn success_closes_open_circuit_directly() {
    let breaker = CircuitBreaker::new(1, Duration::from_secs(10));
    breaker.on_failure().await;
    breaker.on_success().await;
    assert_eq!(breaker.current_state().await, CircuitState::Closed);
    assert!(breaker.can_execute().await.is_ok());
}

#[tokio::test]
async fn failure_in_half_open_reopens_circuit() {
    let breaker = CircuitBreaker::new(1, Duration::ZERO);
    breaker.on_failure().await;
    breaker.can_execute().await.unwrap();
    breaker.on_failure().await;
    assert!(matches!(
        breaker.current_state().await,
        CircuitState::Open { .. }
    ));
}

#[tokio::test]
async fn cloned_breakers_share_state() {
    let breaker = CircuitBreaker::new(1, Duration::from_secs(10));
    let clone = breaker.clone();
    clone.on_failure().await;
    assert!(matches!(
        breaker.current_state().await,
        CircuitState::Open { .. }
    ));
}

#[tokio::test]
async fn concurrent_failures_eventually_open_shared_circuit() {
    let breaker = CircuitBreaker::new(3, Duration::from_secs(10));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let breaker = breaker.clone();
        handles.push(tokio::spawn(async move {
            breaker.on_failure().await;
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }
    assert!(matches!(
        breaker.current_state().await,
        CircuitState::Open { .. }
    ));
}

#[test]
fn circuit_open_error_display_returns_message() {
    let err = CircuitBreakerError::CircuitOpen("blocked".into());
    assert_eq!(err.to_string(), "blocked");
}

#[test]
fn circuit_states_compare_equal_for_closed_and_half_open() {
    assert_eq!(CircuitState::Closed, CircuitState::Closed);
    assert_eq!(CircuitState::HalfOpen, CircuitState::HalfOpen);
}
