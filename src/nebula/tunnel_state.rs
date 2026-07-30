// src/nebula/tunnel_state.rs
// ============================================================
// Direct-vs-relay observability (read-only).
// ============================================================

use crate::nebula::stats::NebulaStats;

#[derive(Debug, Clone, Default)]
pub struct PeerConnectionState {
    pub peer_overlay_ip: String,
    pub via_direct: bool,
    pub via_relay: Option<String>,
    pub last_handshake: i64,
}

pub struct TunnelState;

impl TunnelState {
    pub async fn poll_all_peers() -> Vec<PeerConnectionState> {
        let client = match reqwest::Client::builder().no_proxy().build() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        let body = match client.get("http://127.0.0.1:8625/metrics").send().await {
            Ok(resp) => match resp.text().await {
                Ok(t) => t,
                Err(_) => return Vec::new(),
            },
            Err(_) => return Vec::new(),
        };

        Self::parse_handshake_metrics(&body)
    }

    pub async fn detect_relay_usage() -> bool {
        let stats = NebulaStats::fetch().await.ok();
        stats.map(|s| s.relay_tunnels > 0).unwrap_or(false)
    }

    pub fn parse_handshake_metrics(text: &str) -> Vec<PeerConnectionState> {
        let mut direct = 0u64;
        let mut relay = 0u64;

        for line in text.lines() {
            let l = line.trim();
            if l.starts_with('#') || l.is_empty() {
                continue;
            }
            if l.starts_with("nebula_handshake_direct_total")
                || l.starts_with("nebula_tunnels_direct")
            {
                if let Some(v) = parse_metric_value(l) {
                    direct = direct.saturating_add(v);
                }
            }
            if l.starts_with("nebula_handshake_via_relay_total")
                || l.starts_with("nebula_tunnels_relay")
            {
                if let Some(v) = parse_metric_value(l) {
                    relay = relay.saturating_add(v);
                }
            }
        }

        if direct == 0 && relay == 0 {
            return Vec::new();
        }

        vec![PeerConnectionState {
            peer_overlay_ip: "aggregate".to_string(),
            via_direct: direct >= relay,
            via_relay: if relay > 0 {
                Some("unknown".to_string())
            } else {
                None
            },
            last_handshake: chrono::Utc::now().timestamp(),
        }]
    }
}

fn parse_metric_value(line: &str) -> Option<u64> {
    line.split_whitespace()
        .nth(1)
        .and_then(|v| v.parse::<u64>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_handshake_metrics_relay_detected() {
        let txt = r#"
nebula_handshake_direct_total 1
nebula_handshake_via_relay_total 2
"#;
        let peers = TunnelState::parse_handshake_metrics(txt);
        assert_eq!(peers.len(), 1);
        assert!(peers[0].via_relay.is_some());
        assert!(!peers[0].via_direct);
    }

    #[test]
    fn test_parse_handshake_metrics_direct_detected() {
        let txt = r#"
nebula_tunnels_direct 4
nebula_tunnels_relay 0
"#;
        let peers = TunnelState::parse_handshake_metrics(txt);
        assert_eq!(peers.len(), 1);
        assert!(peers[0].via_direct);
    }
}
