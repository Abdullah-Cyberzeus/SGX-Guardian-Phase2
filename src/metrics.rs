use crate::logging::{log_error, log_event};
use std::collections::BTreeMap;
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
    pub cot_transport_up: BTreeMap<(String, String), bool>,
    pub cot_transport_latency_ms: BTreeMap<String, u64>,
    pub cot_transport_bandwidth_kbps: BTreeMap<String, u64>,
    pub cot_active_transport: Option<String>,
    pub cot_switches_total: u64,
    pub cot_switch_matrix: BTreeMap<(String, String), u64>,
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
            cot_transport_up: BTreeMap::new(),
            cot_transport_latency_ms: BTreeMap::new(),
            cot_transport_bandwidth_kbps: BTreeMap::new(),
            cot_active_transport: None,
            cot_switches_total: 0,
            cot_switch_matrix: BTreeMap::new(),
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

    pub fn set_cot_transport_state(
        &mut self,
        interface: &str,
        transport: &str,
        is_up: bool,
        latency_ms: u64,
        bandwidth_kbps: u64,
    ) {
        self.cot_transport_up
            .insert((interface.to_string(), transport.to_string()), is_up);
        self.cot_transport_latency_ms
            .insert(transport.to_string(), latency_ms);
        self.cot_transport_bandwidth_kbps
            .insert(transport.to_string(), bandwidth_kbps);
    }

    pub fn set_cot_active_transport(&mut self, transport: &str) {
        self.cot_active_transport = Some(transport.to_string());
    }

    pub fn record_cot_switch(&mut self, from: &str, to: &str) {
        self.cot_switches_total += 1;
        *self
            .cot_switch_matrix
            .entry((from.to_string(), to.to_string()))
            .or_insert(0) += 1;
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
            cot_transport_up: self
                .cot_transport_up
                .iter()
                .map(|((iface, tt), up)| (iface.clone(), tt.clone(), *up))
                .collect(),
            cot_transport_latency_ms: self
                .cot_transport_latency_ms
                .iter()
                .map(|(tt, ms)| (tt.clone(), *ms))
                .collect(),
            cot_transport_bandwidth_kbps: self
                .cot_transport_bandwidth_kbps
                .iter()
                .map(|(tt, kbps)| (tt.clone(), *kbps))
                .collect(),
            cot_active_transport: self.cot_active_transport.clone(),
            cot_switches_total: self.cot_switches_total,
            cot_switch_matrix: self
                .cot_switch_matrix
                .iter()
                .map(|((from, to), count)| (from.clone(), to.clone(), *count))
                .collect(),
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
    pub cot_transport_up: Vec<(String, String, bool)>,
    pub cot_transport_latency_ms: Vec<(String, u64)>,
    pub cot_transport_bandwidth_kbps: Vec<(String, u64)>,
    pub cot_active_transport: Option<String>,
    pub cot_switches_total: u64,
    pub cot_switch_matrix: Vec<(String, String, u64)>,
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

        out.push_str(
            "# HELP sgx_cot_transport_up CoT transport health by interface (1=up, 0=down)\n",
        );
        out.push_str("# TYPE sgx_cot_transport_up gauge\n");
        for (iface, transport, up) in &self.cot_transport_up {
            out.push_str(&format!(
                "sgx_cot_transport_up{{interface=\"{}\",transport=\"{}\"}} {}\n",
                iface,
                transport.to_lowercase(),
                if *up { 1 } else { 0 }
            ));
        }

        out.push_str("# HELP sgx_cot_transport_latency_ms CoT transport latency in milliseconds\n");
        out.push_str("# TYPE sgx_cot_transport_latency_ms gauge\n");
        for (transport, latency) in &self.cot_transport_latency_ms {
            out.push_str(&format!(
                "sgx_cot_transport_latency_ms{{transport=\"{}\"}} {}\n",
                transport.to_lowercase(),
                latency
            ));
        }

        out.push_str("# HELP sgx_cot_transport_bandwidth_kbps CoT transport bandwidth in kbps\n");
        out.push_str("# TYPE sgx_cot_transport_bandwidth_kbps gauge\n");
        for (transport, bw) in &self.cot_transport_bandwidth_kbps {
            out.push_str(&format!(
                "sgx_cot_transport_bandwidth_kbps{{transport=\"{}\"}} {}\n",
                transport.to_lowercase(),
                bw
            ));
        }

        out.push_str("# HELP sgx_cot_active_transport_info Active CoT transport\n");
        out.push_str("# TYPE sgx_cot_active_transport_info gauge\n");
        if let Some(active) = &self.cot_active_transport {
            out.push_str(&format!(
                "sgx_cot_active_transport_info{{transport=\"{}\"}} 1\n",
                active.to_lowercase()
            ));
        }

        out.push_str("# HELP sgx_cot_transport_switches_total Total CoT transport switches\n");
        out.push_str("# TYPE sgx_cot_transport_switches_total counter\n");
        out.push_str(&format!(
            "sgx_cot_transport_switches_total {}\n",
            self.cot_switches_total
        ));
        for (from, to, count) in &self.cot_switch_matrix {
            out.push_str(&format!(
                "sgx_cot_transport_switches_total{{from=\"{}\",to=\"{}\"}} {}\n",
                from.to_lowercase(),
                to.to_lowercase(),
                count
            ));
        }

        out
    }
}
