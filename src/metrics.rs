use crate::logging::{log_error, log_event};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Metrics {
    pub start_time: Instant,
    pub connections: u64,
    pub errors: u64,
}
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
    pub fn record_connection(&mut self) {
        self.connections += 1;
        log_event(
            "metrics",
            &format!("Connection event recorded. Total: {}", self.connections),
        );
    }
    pub fn record_error(&mut self) {
        self.errors += 1;
        log_error(
            "metrics",
            &format!("Error count increased. Total: {}", self.errors),
        );
    }
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }
}
