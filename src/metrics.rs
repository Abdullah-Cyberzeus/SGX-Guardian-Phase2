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

    // Relay gauges/counters
    pub relay_active_peers: u32,
    pub relay_bytes_total: u64,
    /// Fixed-point storage: value * 100.
    pub relay_current_mbps_x100: u64,
    pub relay_limit_breaches_total: u64,
    pub relay_max_peers: u32,
    pub relay_max_bandwidth_mbps: u32,
    pub relay_alert_threshold_pct: u8,
    pub relay_direct_tunnels: u32,
    pub relay_relay_tunnels: u32,
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
            relay_active_peers: 0,
            relay_bytes_total: 0,
            relay_current_mbps_x100: 0,
            relay_limit_breaches_total: 0,
            relay_max_peers: 5,
            relay_max_bandwidth_mbps: 10,
            relay_alert_threshold_pct: 80,
            relay_direct_tunnels: 0,
            relay_relay_tunnels: 0,
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

    pub fn set_relay_limits(&mut self, max_peers: u32, max_bw: u32, alert_threshold_pct: u8) {
        self.relay_max_peers = max_peers;
        self.relay_max_bandwidth_mbps = max_bw;
        self.relay_alert_threshold_pct = alert_threshold_pct;
    }

    pub fn update_relay_stats(
        &mut self,
        active_peers: u32,
        total_bytes: u64,
        current_mbps: f64,
        direct_tunnels: u32,
        relay_tunnels: u32,
    ) {
        self.relay_active_peers = active_peers;
        self.relay_bytes_total = total_bytes;
        self.relay_current_mbps_x100 = if current_mbps.is_sign_negative() {
            0
        } else {
            (current_mbps * 100.0).round() as u64
        };
        self.relay_direct_tunnels = direct_tunnels;
        self.relay_relay_tunnels = relay_tunnels;
    }

    pub fn record_relay_limit_breach(&mut self) {
        self.relay_limit_breaches_total += 1;
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
            relay_active_peers: self.relay_active_peers,
            relay_bytes_total: self.relay_bytes_total,
            relay_current_mbps_x100: self.relay_current_mbps_x100,
            relay_limit_breaches_total: self.relay_limit_breaches_total,
            relay_max_peers: self.relay_max_peers,
            relay_max_bandwidth_mbps: self.relay_max_bandwidth_mbps,
            relay_alert_threshold_pct: self.relay_alert_threshold_pct,
            relay_direct_tunnels: self.relay_direct_tunnels,
            relay_relay_tunnels: self.relay_relay_tunnels,
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
    pub relay_active_peers: u32,
    pub relay_bytes_total: u64,
    pub relay_current_mbps_x100: u64,
    pub relay_limit_breaches_total: u64,
    pub relay_max_peers: u32,
    pub relay_max_bandwidth_mbps: u32,
    pub relay_alert_threshold_pct: u8,
    pub relay_direct_tunnels: u32,
    pub relay_relay_tunnels: u32,
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

        out.push_str("# HELP sgx_relay_active_peers Active relay peers\n");
        out.push_str("# TYPE sgx_relay_active_peers gauge\n");
        out.push_str(&format!(
            "sgx_relay_active_peers {}\n",
            self.relay_active_peers
        ));

        out.push_str("# HELP sgx_relay_bytes_total Total relayed bytes\n");
        out.push_str("# TYPE sgx_relay_bytes_total counter\n");
        out.push_str(&format!(
            "sgx_relay_bytes_total {}\n",
            self.relay_bytes_total
        ));

        out.push_str("# HELP sgx_relay_current_mbps Current relay throughput in Mbps\n");
        out.push_str("# TYPE sgx_relay_current_mbps gauge\n");
        out.push_str(&format!(
            "sgx_relay_current_mbps {:.2}\n",
            self.relay_current_mbps_x100 as f64 / 100.0
        ));

        out.push_str("# HELP sgx_relay_limit_breaches_total Relay limit threshold breaches\n");
        out.push_str("# TYPE sgx_relay_limit_breaches_total counter\n");
        out.push_str(&format!(
            "sgx_relay_limit_breaches_total {}\n",
            self.relay_limit_breaches_total
        ));

        out.push_str("# HELP sgx_relay_max_peers Configured max relay peers\n");
        out.push_str("# TYPE sgx_relay_max_peers gauge\n");
        out.push_str(&format!("sgx_relay_max_peers {}\n", self.relay_max_peers));

        out.push_str(
            "# HELP sgx_relay_max_bandwidth_mbps Configured max relay Mbps (0=unlimited)\n",
        );
        out.push_str("# TYPE sgx_relay_max_bandwidth_mbps gauge\n");
        out.push_str(&format!(
            "sgx_relay_max_bandwidth_mbps {}\n",
            self.relay_max_bandwidth_mbps
        ));

        out.push_str("# HELP sgx_relay_alert_threshold_pct Relay alert threshold percent\n");
        out.push_str("# TYPE sgx_relay_alert_threshold_pct gauge\n");
        out.push_str(&format!(
            "sgx_relay_alert_threshold_pct {}\n",
            self.relay_alert_threshold_pct
        ));

        out.push_str("# HELP sgx_relay_direct_tunnels Number of direct tunnels observed\n");
        out.push_str("# TYPE sgx_relay_direct_tunnels gauge\n");
        out.push_str(&format!(
            "sgx_relay_direct_tunnels {}\n",
            self.relay_direct_tunnels
        ));

        out.push_str("# HELP sgx_relay_tunnels Number of relay tunnels observed\n");
        out.push_str("# TYPE sgx_relay_tunnels gauge\n");
        out.push_str(&format!("sgx_relay_tunnels {}\n", self.relay_relay_tunnels));

        out
    }
}
