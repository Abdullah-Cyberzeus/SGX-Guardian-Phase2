// src/nebula/stats.rs
// ============================================================
// Nebula Prometheus stats reader for relay observability.
// ============================================================

use once_cell::sync::Lazy;
use std::sync::Mutex;
use std::time::Instant;

#[derive(Debug, Clone, Default)]
pub struct RelayStats {
    pub active_peers: u32,
    pub total_bytes_relayed: u64,
    pub current_mbps: f64,
    pub direct_tunnels: u32,
    pub relay_tunnels: u32,
}

static LAST_SAMPLE: Lazy<Mutex<Option<(Instant, u64)>>> = Lazy::new(|| Mutex::new(None));

pub struct NebulaStats;

impl NebulaStats {
    pub async fn fetch() -> Result<RelayStats, String> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .map_err(|e| e.to_string())?;

        let body = client
            .get("http://127.0.0.1:8625/metrics")
            .send()
            .await
            .map_err(|e| e.to_string())?
            .text()
            .await
            .map_err(|e| e.to_string())?;

        let mut stats = Self::parse_prometheus(&body)?;

        let now = Instant::now();
        if let Ok(mut guard) = LAST_SAMPLE.lock() {
            if let Some((last_ts, last_bytes)) = *guard {
                let elapsed = now.duration_since(last_ts).as_secs_f64();
                if elapsed > 0.0 && stats.total_bytes_relayed >= last_bytes {
                    let delta_bytes = stats.total_bytes_relayed - last_bytes;
                    stats.current_mbps = (delta_bytes as f64 * 8.0) / (elapsed * 1_000_000.0);
                }
            }
            *guard = Some((now, stats.total_bytes_relayed));
        }

        Ok(stats)
    }

    pub fn parse_prometheus(text: &str) -> Result<RelayStats, String> {
        let mut stats = RelayStats::default();

        let metrics = parse_metrics_map(text);

        let active_candidates = [
            "nebula_relay_active_peers",
            "nebula_tunnels_active",
            "nebula_connections_active",
        ];
        stats.active_peers = first_nonzero_u64(&metrics, &active_candidates)
            .unwrap_or(0)
            .min(u32::MAX as u64) as u32;

        let relay_bytes_candidates = [
            "nebula_relay_bytes_total",
            "nebula_relay_tx_bytes_total",
            "nebula_relay_rx_bytes_total",
            "nebula_relay_messages_total",
        ];
        let mut total = 0u64;
        for name in relay_bytes_candidates {
            if let Some(v) = metrics.get(name) {
                total = total.saturating_add(*v);
            }
        }
        stats.total_bytes_relayed = total;

        let direct_candidates = ["nebula_tunnels_direct", "nebula_handshake_direct_total"];
        stats.direct_tunnels = first_nonzero_u64(&metrics, &direct_candidates)
            .unwrap_or(0)
            .min(u32::MAX as u64) as u32;

        let relay_candidates = ["nebula_tunnels_relay", "nebula_handshake_via_relay_total"];
        stats.relay_tunnels = first_nonzero_u64(&metrics, &relay_candidates)
            .unwrap_or(0)
            .min(u32::MAX as u64) as u32;

        Ok(stats)
    }
}

fn parse_metrics_map(text: &str) -> std::collections::HashMap<String, u64> {
    let mut map = std::collections::HashMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        let Some(metric_with_labels) = parts.next() else {
            continue;
        };
        let Some(value_str) = parts.next() else {
            continue;
        };

        let metric_name = metric_with_labels
            .split('{')
            .next()
            .unwrap_or(metric_with_labels);

        let value = if let Ok(v) = value_str.parse::<u64>() {
            v
        } else if let Ok(vf) = value_str.parse::<f64>() {
            if vf.is_sign_negative() {
                0
            } else {
                vf.round() as u64
            }
        } else {
            continue;
        };

        let entry = map.entry(metric_name.to_string()).or_insert(0u64);
        *entry = (*entry).saturating_add(value);
    }
    map
}

fn first_nonzero_u64(
    metrics: &std::collections::HashMap<String, u64>,
    keys: &[&str],
) -> Option<u64> {
    for key in keys {
        if let Some(v) = metrics.get(*key) {
            return Some(*v);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_prometheus_stats() {
        let sample = r#"
# HELP nebula_relay_active_peers active relays
nebula_relay_active_peers 2
nebula_relay_tx_bytes_total 104857600
nebula_relay_rx_bytes_total 52428800
nebula_tunnels_direct 1
nebula_tunnels_relay 3
"#;

        let parsed = NebulaStats::parse_prometheus(sample).unwrap();
        assert_eq!(parsed.active_peers, 2);
        assert_eq!(parsed.total_bytes_relayed, 157286400);
        assert_eq!(parsed.direct_tunnels, 1);
        assert_eq!(parsed.relay_tunnels, 3);
    }
}
