use crate::logging::{log_error, log_event};
use std::time::{Duration, Instant};
/// Tracks basic runtime metrics for each SG-X node,
/// including uptime, number of connections, and error counts.
/// Telemetry metrics for SG-X Guardian node (Prometheus-style model)
#[derive(Debug, Clone)]
pub struct Metrics {
    // Gauge
    pub start_time: Instant,

    // Counters
    pub connections_total: u64,
    pub errors_total: u64,

    // Gauges
    #[allow(dead_code)]
    pub policy_active: bool,
    #[allow(dead_code)]
    pub enforcement_failures_total: u64,
}
/// Initializes metric counters with zeroed values and current start time.
impl Default for Metrics {
    fn default() -> Self {
        Self {
            start_time: Instant::now(),
            connections_total: 0,
            errors_total: 0,
            policy_active: false,
            enforcement_failures_total: 0,
        }
    }
}
impl Metrics {
    /// Increments the connection counter and logs the event
    /// through the global structured logging system.
    /// Counter: total connection events
    pub fn record_connection(&mut self) {
        self.connections_total += 1;
        log_event(
            "metrics",
            &format!(
                "Connection event recorded. Total: {}",
                self.connections_total
            ),
        );
    }
    /// Increments the error counter and writes an error-level log entry
    /// for monitoring and diagnostics.
    /// Counter: total error events
    pub fn record_error(&mut self) {
        self.errors_total += 1;
        log_error(
            "metrics",
            &format!("Error count increased. Total: {}", self.errors_total),
        );
    }
    /// Gauge: policy active state
    #[allow(dead_code)]
    pub fn set_policy_active(&mut self, active: bool) {
        self.policy_active = active;
        log_event(
            "metrics",
            &format!("Policy active state changed: {}", active),
        );
    }

    /// Counter: enforcement failures
    #[allow(dead_code)]
    pub fn record_enforcement_failure(&mut self) {
        self.enforcement_failures_total += 1;
        log_error(
            "metrics",
            &format!(
                "Enforcement failure count: {}",
                self.enforcement_failures_total
            ),
        );
    }
    /// Returns the total runtime duration since the metrics
    /// struct was initialized (node uptime).
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }
}
impl Metrics {
    /// Create a read-only snapshot of metrics
    /// (used for Prometheus export)
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            uptime_seconds: self.uptime().as_secs(),
            connections_total: self.connections_total,
            errors_total: self.errors_total,
            enforcement_failures_total: self.enforcement_failures_total,
            policy_active: self.policy_active,
        }
    }
}

/// Immutable metrics snapshot (export-safe)
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub uptime_seconds: u64,
    pub connections_total: u64,
    pub errors_total: u64,
    pub enforcement_failures_total: u64,
    pub policy_active: bool,
}

impl MetricsSnapshot {
    /// Render snapshot in Prometheus text format
    pub fn to_prometheus(&self) -> String {
        let mut out = String::new();

        out.push_str("# HELP sgx_node_uptime_seconds Node uptime in seconds\n");
        out.push_str("# TYPE sgx_node_uptime_seconds gauge\n");
        out.push_str(&format!(
            "sgx_node_uptime_seconds {}\n",
            self.uptime_seconds
        ));

        out.push_str("# HELP sgx_connections_total Total connection events\n");
        out.push_str("# TYPE sgx_connections_total counter\n");
        out.push_str(&format!(
            "sgx_connections_total {}\n",
            self.connections_total
        ));

        out.push_str("# HELP sgx_errors_total Total error events\n");
        out.push_str("# TYPE sgx_errors_total counter\n");
        out.push_str(&format!("sgx_errors_total {}\n", self.errors_total));

        out.push_str("# HELP sgx_enforcement_failures_total Policy enforcement failures\n");
        out.push_str("# TYPE sgx_enforcement_failures_total counter\n");
        out.push_str(&format!(
            "sgx_enforcement_failures_total {}\n",
            self.enforcement_failures_total
        ));

        out.push_str("# HELP sgx_policy_active Policy active state (1=active, 0=inactive)\n");
        out.push_str("# TYPE sgx_policy_active gauge\n");
        out.push_str(&format!(
            "sgx_policy_active {}\n",
            if self.policy_active { 1 } else { 0 }
        ));

        out
    }
}
