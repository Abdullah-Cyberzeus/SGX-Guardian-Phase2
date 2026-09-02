use crate::attestation_service::verified_attestations_total;
use crate::dusage::counters::read_interface_counters;
use crate::metrics::Metrics;
use sgx_anomaly_engine::telemetry::{RawSample, TelemetrySource};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

#[derive(Debug, Default)]
struct CpuSample {
    total: u64,
    idle: u64,
}

/// SGX runtime telemetry adapter for the historical Task 1 full ML engine.
///
/// Sources:
/// - node Metrics: connection/error/policy/protocol/relay/CoT signals
/// - /sys/class/net: RX/TX byte + packet cumulative counters
/// - attestation service: verified-attestation cumulative counter
/// - /proc: CPU, memory, open FDs, load average
pub struct SgxTelemetrySource {
    metrics: Arc<Mutex<Metrics>>,
    sys_class_net: PathBuf,
    previous_cpu: Option<CpuSample>,
    last_sample: RawSample,
}

impl SgxTelemetrySource {
    pub fn new(metrics: Arc<Mutex<Metrics>>) -> Self {
        Self::with_sys_class_net(metrics, PathBuf::from("/sys/class/net"))
    }

    pub fn with_sys_class_net(metrics: Arc<Mutex<Metrics>>, sys_class_net: PathBuf) -> Self {
        Self {
            metrics,
            sys_class_net,
            previous_cpu: None,
            last_sample: RawSample::default(),
        }
    }

    async fn collect(&mut self) -> RawSample {
        let snapshot = {
            let guard = self.metrics.lock().await;
            guard.snapshot()
        };

        let mut sample = self.last_sample.clone();

        sample.ts_ms = now_ms();

        // ----------------------------------------------------
        // Network cumulative counters
        // ----------------------------------------------------
        match read_interface_counters(&self.sys_class_net).await {
            Ok(interfaces) => {
                sample.net_rx_bytes_total = interfaces.iter().map(|x| x.rx_bytes).sum();
                sample.net_tx_bytes_total = interfaces.iter().map(|x| x.tx_bytes).sum();
                sample.net_rx_pkts_total = interfaces.iter().map(|x| x.rx_packets).sum();
                sample.net_tx_pkts_total = interfaces.iter().map(|x| x.tx_packets).sum();
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    path = %self.sys_class_net.display(),
                    "Task1 telemetry could not read interface counters; preserving previous values"
                );
            }
        }

        // ----------------------------------------------------
        // Existing SGX cumulative counters
        // ----------------------------------------------------
        sample.conn_total = snapshot.connections_total;
        sample.error_total = snapshot.errors_total;
        sample.relay_bytes_total = snapshot.relay_bytes_total;
        sample.cot_switches_total = snapshot.cot_switches_total;
        sample.policy_event_total = snapshot.policy_events_total;
        sample.proto_violation_total = snapshot.proto_violations_total;
        sample.attest_total = verified_attestations_total();

        // ----------------------------------------------------
        // Existing SGX gauges
        // ----------------------------------------------------
        sample.nebula_mbps = snapshot.relay_current_mbps_x100 as f64 / 100.0;
        sample.active_peers = snapshot.relay_active_peers as f64;

        let total_tunnels =
            snapshot.relay_direct_tunnels as u64 + snapshot.relay_relay_tunnels as u64;

        sample.relay_ratio = if total_tunnels == 0 {
            0.0
        } else {
            snapshot.relay_relay_tunnels as f64 / total_tunnels as f64
        };

        sample.cot_latency_avg_ms = average_cot_latency(&snapshot.cot_transport_latency_ms);

        // ----------------------------------------------------
        // Linux resource telemetry
        // ----------------------------------------------------
        match read_cpu_sample("/proc/stat").await {
            Ok(current) => {
                if let Some(previous) = &self.previous_cpu {
                    sample.cpu_util_pct = cpu_utilization_pct(previous, &current);
                }
                self.previous_cpu = Some(current);
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    "Task1 telemetry could not read /proc/stat; preserving previous CPU value"
                );
            }
        }

        match read_memory_used_pct("/proc/meminfo").await {
            Ok(value) => sample.mem_used_pct = value,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "Task1 telemetry could not read /proc/meminfo; preserving previous memory value"
                );
            }
        }

        match read_open_fds("/proc/self/fd").await {
            Ok(value) => sample.open_fds = value,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "Task1 telemetry could not read /proc/self/fd; preserving previous FD value"
                );
            }
        }

        match read_load1("/proc/loadavg").await {
            Ok(value) => sample.load1 = value,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "Task1 telemetry could not read /proc/loadavg; preserving previous load value"
                );
            }
        }

        self.last_sample = sample.clone();
        sample
    }
}

#[async_trait::async_trait]
impl TelemetrySource for SgxTelemetrySource {
    async fn poll(&mut self) -> RawSample {
        self.collect().await
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn average_cot_latency(values: &[(String, u64)]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let total: u128 = values.iter().map(|(_, value)| *value as u128).sum();

    total as f64 / values.len() as f64
}

async fn read_cpu_sample(path: impl AsRef<Path>) -> std::io::Result<CpuSample> {
    let text = tokio::fs::read_to_string(path).await?;
    parse_cpu_sample(&text).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "missing aggregate cpu line",
        )
    })
}

fn parse_cpu_sample(text: &str) -> Option<CpuSample> {
    let line = text.lines().find(|line| line.starts_with("cpu "))?;
    let values: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|value| value.parse::<u64>().ok())
        .collect();

    if values.len() < 4 {
        return None;
    }

    let total = values.iter().copied().sum();
    let idle = values[3].saturating_add(values.get(4).copied().unwrap_or(0));

    Some(CpuSample { total, idle })
}

fn cpu_utilization_pct(previous: &CpuSample, current: &CpuSample) -> f64 {
    let total_delta = current.total.saturating_sub(previous.total);
    let idle_delta = current.idle.saturating_sub(previous.idle);

    if total_delta == 0 {
        return 0.0;
    }

    let busy = total_delta.saturating_sub(idle_delta);
    ((busy as f64 / total_delta as f64) * 100.0).clamp(0.0, 100.0)
}

async fn read_memory_used_pct(path: impl AsRef<Path>) -> std::io::Result<f64> {
    let text = tokio::fs::read_to_string(path).await?;
    parse_memory_used_pct(&text).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "MemTotal/MemAvailable missing",
        )
    })
}

fn parse_memory_used_pct(text: &str) -> Option<f64> {
    let mut total = None;
    let mut available = None;

    for line in text.lines() {
        let mut parts = line.split_whitespace();
        match parts.next()? {
            "MemTotal:" => {
                total = parts.next()?.parse::<f64>().ok();
            }
            "MemAvailable:" => {
                available = parts.next()?.parse::<f64>().ok();
            }
            _ => {}
        }
    }

    let total = total?;
    let available = available?;

    if total <= 0.0 {
        return Some(0.0);
    }

    Some((((total - available).max(0.0) / total) * 100.0).clamp(0.0, 100.0))
}

async fn read_open_fds(path: impl AsRef<Path>) -> std::io::Result<f64> {
    let mut entries = tokio::fs::read_dir(path).await?;
    let mut count = 0u64;

    while entries.next_entry().await?.is_some() {
        count = count.saturating_add(1);
    }

    Ok(count as f64)
}

async fn read_load1(path: impl AsRef<Path>) -> std::io::Result<f64> {
    let text = tokio::fs::read_to_string(path).await?;
    text.split_whitespace()
        .next()
        .and_then(|value| value.parse::<f64>().ok())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "load1 missing"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cpu_and_computes_utilization() {
        let previous = parse_cpu_sample("cpu  100 0 100 800 0 0 0 0 0 0\n").unwrap();
        let current = parse_cpu_sample("cpu  150 0 150 900 0 0 0 0 0 0\n").unwrap();

        let pct = cpu_utilization_pct(&previous, &current);

        assert!((pct - 50.0).abs() < 0.001);
    }

    #[test]
    fn parses_memory_used_percent() {
        let text = "\
MemTotal:       1000 kB
MemAvailable:    250 kB
";
        let pct = parse_memory_used_pct(text).unwrap();
        assert!((pct - 75.0).abs() < 0.001);
    }

    #[test]
    fn averages_cot_latency() {
        let values = vec![("wifi".to_string(), 20), ("lte".to_string(), 40)];

        assert!((average_cot_latency(&values) - 30.0).abs() < 0.001);
    }
}
