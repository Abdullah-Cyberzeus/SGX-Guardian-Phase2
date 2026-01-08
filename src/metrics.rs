use crate::logging::{log_error, log_event};
use std::time::{Duration, Instant};
/// Tracks basic runtime metrics for each SG-X node,
/// including uptime, number of connections, and error counts.
#[derive(Debug, Clone)]
pub struct Metrics {
    pub start_time: Instant,
    pub connections: u64,
    pub errors: u64,
}
/// Initializes metric counters with zeroed values and current start time.
impl Default for Metrics {
    fn default() -> Self {
        Self {
            start_time: Instant::now(),
            connections: 0,
            errors: 0,
        }
    }
}
impl Metrics {
    /// Increments the connection counter and logs the event
    /// through the global structured logging system.
    pub fn record_connection(&mut self) {
        self.connections += 1;
        log_event(
            "metrics",
            &format!("Connection event recorded. Total: {}", self.connections),
        );
    }
    /// Increments the error counter and writes an error-level log entry
    /// for monitoring and diagnostics.
    pub fn record_error(&mut self) {
        self.errors += 1;
        log_error(
            "metrics",
            &format!("Error count increased. Total: {}", self.errors),
        );
    }
    /// Returns the total runtime duration since the metrics
    /// struct was initialized (node uptime).
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }
}
