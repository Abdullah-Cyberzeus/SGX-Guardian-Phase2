//! UDP listener for peer node announcements.
//!
//! The socket loop is a thin shell around [`AnnouncementGate`], which holds
//! every accept/reject decision — rate limiting, self-filtering, integrity
//! verification, routability and dedup. Keeping those out of the `recv_from`
//! loop is what makes them testable without binding a real broadcast socket.

use crate::dynamic_config;
use crate::node_announcement::NodeAnnouncement;
use std::collections::HashMap;
use std::net::UdpSocket as StdUdpSocket;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

const RATE_LIMIT_PER_MINUTE: usize = 10;
const DEDUP_INTERVAL_SECS: u64 = 25;
/// Bound on the per-source tracking maps before stale entries are evicted.
/// Without it a spoofed source address could grow either map without limit.
const TRACKING_MAP_CAPACITY: usize = 500;
const RATE_WINDOW_SECS: u64 = 60;
const RATE_ENTRY_TTL_SECS: u64 = 120;
const DEDUP_ENTRY_TTL_SECS: u64 = 60;

fn listen_port() -> u16 {
    std::env::var("SGX_BROADCAST_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(9000)
}

/// What the listener decided to do with one received datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Persist the announcement to the peer's config.
    Accept(Box<NodeAnnouncement>),
    /// The source exceeded its per-minute budget.
    RateLimited,
    /// The payload was not valid UTF-8 or not a valid announcement.
    Undecodable,
    /// The announcement came from this node.
    SelfAnnouncement,
    /// The announcement's signature/integrity check failed.
    IntegrityFailed,
    /// The advertised IP is not routable.
    NonRoutable,
    /// An identical peer was accepted within the dedup interval.
    Duplicate,
}

impl Decision {
    pub fn accepted(&self) -> bool {
        matches!(self, Self::Accept(_))
    }
}

/// Per-source rate and per-peer dedup state for the announcement stream.
#[derive(Debug, Default)]
pub struct AnnouncementGate {
    local_node_id: String,
    rate: HashMap<String, (usize, Instant)>,
    dedup: HashMap<String, Instant>,
}

impl AnnouncementGate {
    pub fn new(local_node_id: impl Into<String>) -> Self {
        Self {
            local_node_id: local_node_id.into(),
            rate: HashMap::new(),
            dedup: HashMap::new(),
        }
    }

    /// Drops tracking entries that are older than their window, but only once
    /// a map has grown past [`TRACKING_MAP_CAPACITY`] — sweeping on every
    /// datagram would make the common path pay for the abuse case.
    pub fn evict_stale(&mut self, now: Instant) {
        if self.rate.len() > TRACKING_MAP_CAPACITY {
            self.rate.retain(|_, (_, seen_at)| {
                now.duration_since(*seen_at).as_secs() <= RATE_ENTRY_TTL_SECS
            });
        }
        if self.dedup.len() > TRACKING_MAP_CAPACITY {
            self.dedup.retain(|_, seen_at| {
                now.duration_since(*seen_at).as_secs() <= DEDUP_ENTRY_TTL_SECS
            });
        }
    }

    /// Whether `src_ip` is still inside its per-minute budget, counting this
    /// datagram.
    pub fn within_rate_limit(&mut self, src_ip: &str, now: Instant) -> bool {
        let entry = self.rate.entry(src_ip.to_string()).or_insert((0, now));
        if now.duration_since(entry.1).as_secs() > RATE_WINDOW_SECS {
            *entry = (1, now);
            return true;
        }
        entry.0 += 1;
        entry.0 <= RATE_LIMIT_PER_MINUTE
    }

    /// Whether this peer's announcement should be written, recording the
    /// acceptance so repeats inside the dedup interval are suppressed.
    fn admit_peer(&mut self, node_id: &str, now: Instant) -> bool {
        let should_write = match self.dedup.get(node_id) {
            Some(last) => now.duration_since(*last).as_secs() > DEDUP_INTERVAL_SECS,
            None => true,
        };
        if should_write {
            self.dedup.insert(node_id.to_string(), now);
        }
        should_write
    }

    /// Classifies one datagram received from `src_ip`.
    pub fn classify(&mut self, src_ip: &str, payload: &[u8], now: Instant) -> Decision {
        self.evict_stale(now);

        if !self.within_rate_limit(src_ip, now) {
            return Decision::RateLimited;
        }

        let Ok(text) = std::str::from_utf8(payload) else {
            return Decision::Undecodable;
        };
        let Ok(peer) = serde_json::from_str::<NodeAnnouncement>(text.trim()) else {
            return Decision::Undecodable;
        };

        if peer.node_id.trim() == self.local_node_id.trim() {
            return Decision::SelfAnnouncement;
        }
        if !peer.verify_integrity() {
            return Decision::IntegrityFailed;
        }
        if !dynamic_config::is_routable_ip(&peer.ip) {
            return Decision::NonRoutable;
        }
        if !self.admit_peer(&peer.node_id, now) {
            return Decision::Duplicate;
        }
        Decision::Accept(Box::new(peer))
    }
}

/// Writes an accepted announcement into the peer's config file.
pub fn apply_announcement(peer: &NodeAnnouncement) {
    dynamic_config::update_peer_config(
        &peer.node_id,
        &peer.hostname,
        &peer.ip,
        peer.port,
        &peer.public_key,
    );
}

/// Reports a rejected datagram on stderr, matching the operator-facing log.
fn report_rejection(decision: &Decision, src_ip: &str) {
    match decision {
        Decision::IntegrityFailed => eprintln!("Rejected {} integrity check failed", src_ip),
        Decision::NonRoutable => eprintln!("Ignoring announcement from {} non-routable IP", src_ip),
        Decision::Undecodable => eprintln!("JSON parse failed from {}", src_ip),
        _ => {}
    }
}

pub async fn start_listener(local_node_id: String) {
    let port = listen_port();
    let bind_addr = format!("0.0.0.0:{}", port);

    let std_socket = match StdUdpSocket::bind(&bind_addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Port {} bind failed: {}", port, e);
            return;
        }
    };

    std_socket
        .set_broadcast(true)
        .expect("set_broadcast failed");
    std_socket
        .set_nonblocking(true)
        .expect("set_nonblocking failed");
    let socket = UdpSocket::from_std(std_socket).expect("tokio socket conversion failed");

    println!("Listener ready on {} (SO_BROADCAST enabled)", bind_addr);

    let mut buf = [0u8; 8192];
    let mut gate = AnnouncementGate::new(local_node_id);

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((size, src)) => {
                let src_ip = src.ip().to_string();
                let decision = gate.classify(&src_ip, &buf[..size], Instant::now());
                match decision {
                    Decision::Accept(peer) => {
                        println!("Peer announcement received: {}", peer.node_id);
                        tokio::task::spawn_blocking(move || apply_announcement(&peer));
                    }
                    other => report_rejection(&other, &src_ip),
                }
            }
            Err(e) => {
                eprintln!("recv_from error: {}", e);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_port_uses_default_valid_override_and_invalid_fallback() {
        let _lock = crate::test_support::blocking_env_lock();
        const KEY: &str = "SGX_BROADCAST_PORT";
        let previous = std::env::var_os(KEY);

        std::env::remove_var(KEY);
        assert_eq!(listen_port(), 9000);
        std::env::set_var(KEY, "12345");
        assert_eq!(listen_port(), 12345);
        for value in ["", "invalid", "65536", "-1"] {
            std::env::set_var(KEY, value);
            assert_eq!(listen_port(), 9000);
        }

        if let Some(previous) = previous {
            std::env::set_var(KEY, previous);
        } else {
            std::env::remove_var(KEY);
        }
    }

    fn signed_peer(node_id: &str, ip: &str) -> NodeAnnouncement {
        NodeAnnouncement::new_signed(
            node_id.to_string(),
            format!("{node_id}.guardian"),
            ip.to_string(),
            50052,
            "peer-public-key".to_string(),
        )
    }

    fn payload(peer: &NodeAnnouncement) -> Vec<u8> {
        serde_json::to_vec(peer).expect("serialize announcement")
    }

    #[test]
    fn a_valid_peer_announcement_is_accepted() {
        let mut gate = AnnouncementGate::new("nodeA");
        let peer = signed_peer("nodeB", "192.168.1.20");

        let decision = gate.classify("192.168.1.20", &payload(&peer), Instant::now());

        assert!(decision.accepted(), "{decision:?}");
        match decision {
            Decision::Accept(accepted) => {
                assert_eq!(accepted.node_id, "nodeB");
                assert_eq!(accepted.ip, "192.168.1.20");
                assert_eq!(accepted.port, 50052);
            }
            other => panic!("expected acceptance, got {other:?}"),
        }
    }

    #[test]
    fn this_nodes_own_announcement_is_ignored() {
        let mut gate = AnnouncementGate::new("nodeA");
        let peer = signed_peer("nodeA", "192.168.1.10");

        assert_eq!(
            gate.classify("192.168.1.10", &payload(&peer), Instant::now()),
            Decision::SelfAnnouncement
        );
    }

    #[test]
    fn a_self_announcement_is_matched_after_trimming_whitespace() {
        let mut gate = AnnouncementGate::new("  nodeA  ");
        let peer = signed_peer("nodeA", "192.168.1.10");

        assert_eq!(
            gate.classify("192.168.1.10", &payload(&peer), Instant::now()),
            Decision::SelfAnnouncement
        );
    }

    #[test]
    fn a_tampered_announcement_fails_the_integrity_check() {
        let mut gate = AnnouncementGate::new("nodeA");
        let mut peer = signed_peer("nodeB", "192.168.1.20");
        // Rewrite a signed field without re-signing.
        peer.ip = "192.168.1.99".to_string();

        assert_eq!(
            gate.classify("192.168.1.20", &payload(&peer), Instant::now()),
            Decision::IntegrityFailed
        );
    }

    #[test]
    fn a_non_routable_advertised_address_is_ignored() {
        let mut gate = AnnouncementGate::new("nodeA");
        let peer = signed_peer("nodeB", "0.0.0.0");

        assert_eq!(
            gate.classify("192.168.1.20", &payload(&peer), Instant::now()),
            Decision::NonRoutable
        );
    }

    #[test]
    fn malformed_payloads_are_rejected_without_panicking() {
        let mut gate = AnnouncementGate::new("nodeA");
        let now = Instant::now();

        assert_eq!(
            gate.classify("192.168.1.20", &[0xff, 0xfe, 0xfd], now),
            Decision::Undecodable,
            "invalid UTF-8"
        );
        assert_eq!(
            gate.classify("192.168.1.21", b"{ not json", now),
            Decision::Undecodable,
            "invalid JSON"
        );
        assert_eq!(
            gate.classify("192.168.1.22", b"{\"unrelated\":true}", now),
            Decision::Undecodable,
            "JSON that is not an announcement"
        );
        assert_eq!(
            gate.classify("192.168.1.23", b"", now),
            Decision::Undecodable,
            "an empty datagram"
        );
    }

    #[test]
    fn a_source_is_rate_limited_after_its_per_minute_budget() {
        let mut gate = AnnouncementGate::new("nodeA");
        let now = Instant::now();
        let peer = signed_peer("nodeB", "192.168.1.20");
        let bytes = payload(&peer);

        // The counter starts at zero and is incremented before the check, so
        // exactly RATE_LIMIT_PER_MINUTE datagrams fit inside the window.
        for attempt in 1..=RATE_LIMIT_PER_MINUTE {
            let decision = gate.classify("192.168.1.20", &bytes, now);
            assert_ne!(
                decision,
                Decision::RateLimited,
                "datagram {attempt} should be inside the budget"
            );
        }

        assert_eq!(
            gate.classify("192.168.1.20", &bytes, now),
            Decision::RateLimited
        );
        // A different source has its own budget.
        assert_ne!(
            gate.classify("192.168.1.30", &bytes, now),
            Decision::RateLimited
        );
    }

    #[test]
    fn the_rate_window_resets_after_a_minute() {
        let mut gate = AnnouncementGate::new("nodeA");
        let start = Instant::now();

        for _ in 0..(RATE_LIMIT_PER_MINUTE + 2) {
            gate.within_rate_limit("192.168.1.20", start);
        }
        assert!(!gate.within_rate_limit("192.168.1.20", start));

        let later = start + Duration::from_secs(RATE_WINDOW_SECS + 1);
        assert!(
            gate.within_rate_limit("192.168.1.20", later),
            "the counter resets once the window elapses"
        );
    }

    #[test]
    fn a_repeat_announcement_is_deduplicated_until_the_interval_elapses() {
        let mut gate = AnnouncementGate::new("nodeA");
        let start = Instant::now();
        let peer = signed_peer("nodeB", "192.168.1.20");
        let bytes = payload(&peer);

        assert!(gate.classify("192.168.1.20", &bytes, start).accepted());
        assert_eq!(
            gate.classify("192.168.1.20", &bytes, start),
            Decision::Duplicate
        );

        let later = start + Duration::from_secs(DEDUP_INTERVAL_SECS + 1);
        assert!(
            gate.classify("192.168.1.20", &bytes, later).accepted(),
            "the peer is written again once the dedup interval passes"
        );
    }

    #[test]
    fn distinct_peers_are_not_deduplicated_against_each_other() {
        let mut gate = AnnouncementGate::new("nodeA");
        let now = Instant::now();

        assert!(gate
            .classify(
                "192.168.1.20",
                &payload(&signed_peer("nodeB", "192.168.1.20")),
                now
            )
            .accepted());
        assert!(gate
            .classify(
                "192.168.1.30",
                &payload(&signed_peer("nodeC", "192.168.1.30")),
                now
            )
            .accepted());
    }

    #[test]
    fn stale_tracking_entries_are_evicted_only_once_the_maps_grow() {
        let mut gate = AnnouncementGate::new("nodeA");
        let start = Instant::now();

        for index in 0..(TRACKING_MAP_CAPACITY + 1) {
            gate.rate
                .insert(format!("10.0.{}.{}", index / 256, index % 256), (1, start));
            gate.dedup.insert(format!("peer-{index}"), start);
        }
        let filled = gate.rate.len();

        // Below the TTL nothing is dropped even though the maps are over capacity.
        gate.evict_stale(start + Duration::from_secs(10));
        assert_eq!(gate.rate.len(), filled);

        gate.evict_stale(start + Duration::from_secs(RATE_ENTRY_TTL_SECS + 1));
        assert!(gate.rate.is_empty(), "stale rate entries are dropped");
        assert!(gate.dedup.is_empty(), "stale dedup entries are dropped");
    }

    #[test]
    fn a_small_map_is_left_alone_by_eviction() {
        let mut gate = AnnouncementGate::new("nodeA");
        let start = Instant::now();
        gate.rate.insert("10.0.0.1".to_string(), (1, start));
        gate.dedup.insert("nodeB".to_string(), start);

        gate.evict_stale(start + Duration::from_secs(RATE_ENTRY_TTL_SECS * 10));

        assert_eq!(gate.rate.len(), 1, "eviction only runs past capacity");
        assert_eq!(gate.dedup.len(), 1);
    }

    #[test]
    fn rejection_reporting_covers_every_reported_decision() {
        // Exercised for panic-freedom; these are the operator-facing lines.
        report_rejection(&Decision::IntegrityFailed, "192.168.1.20");
        report_rejection(&Decision::NonRoutable, "192.168.1.20");
        report_rejection(&Decision::Undecodable, "192.168.1.20");
        report_rejection(&Decision::RateLimited, "192.168.1.20");
        report_rejection(&Decision::Duplicate, "192.168.1.20");
        report_rejection(&Decision::SelfAnnouncement, "192.168.1.20");
    }

    #[tokio::test]
    async fn the_listener_returns_when_its_port_is_already_bound() {
        let _lock = crate::test_support::async_env_lock().await;
        const KEY: &str = "SGX_BROADCAST_PORT";
        let previous = std::env::var_os(KEY);

        // Hold the port so the listener's bind fails and it returns instead of
        // looping forever.
        let Ok(holder) = StdUdpSocket::bind("0.0.0.0:0") else {
            return;
        };
        let port = holder.local_addr().expect("bound address").port();
        std::env::set_var(KEY, port.to_string());

        // Returns rather than hanging: a timeout here means the bind-failure
        // path stopped being an early return.
        tokio::time::timeout(Duration::from_secs(5), start_listener("nodeA".to_string()))
            .await
            .expect("the listener must return when the port is taken");

        match previous {
            Some(value) => std::env::set_var(KEY, value),
            None => std::env::remove_var(KEY),
        }
    }
}
