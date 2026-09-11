// src/dynamic_config.rs — VERSION 2
// ================================================================
// CHANGES FROM V1:
//
// In V1, main.rs read peer IPs for broadcast from the config:
//   let peer_ips: Vec<String> = peers.iter().map(|p| p.ip.clone()).collect();
//   broadcast_own_config_to_peers(&my_config, &peer_ips).await;
//
// Problem: if the config contains 127.0.0.1, broadcast fails.
//
// V2 FIX:
//   - Remove or disable the startup broadcast in main.rs
//   - p2p_discovery.rs handles config sync once a real peer is discovered
//   - This file stays unchanged; only the main.rs integration is simplified
//   - If manual broadcast is needed, use broadcast_to_real_ip()
//     to send directly to a known real IP instead of a config placeholder
// ================================================================

use crate::config_loader::load_config;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};

pub const CONFIG_SYNC_PORT: u16 = 50070;

const BROADCAST_RETRIES: u32 = 3;
const RETRY_DELAY_SECS: u64 = 5;
const IP_MONITOR_INTERVAL_SECS: u64 = 60;

pub fn latest_known_ca_ip() -> Option<String> {
    let cfg = load_config("/etc/sgx-guardian/config/nodeA.yaml").ok()?;
    if cfg.ip != "0.0.0.0" && cfg.ip != "127.0.0.1" && !cfg.ip.is_empty() {
        Some(cfg.ip)
    } else {
        None
    }
}

pub async fn overlay_is_reachable() -> bool {
    reachable_lighthouse_name().await.is_some()
}

fn host_from_endpoint(endpoint: &str) -> Option<String> {
    endpoint
        .rsplit_once(':')
        .map(|(host, _)| host.to_string())
        .filter(|h| !h.is_empty())
}

async fn tcp_port_open(addr: &str) -> bool {
    tokio::time::timeout(Duration::from_millis(1500), TcpStream::connect(addr))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

async fn lighthouse_runtime_reachable(
    node_name: &str,
    overlay_ip: &str,
    physical_endpoint: &str,
    registry_port: u16,
) -> bool {
    let mut candidates = Vec::new();
    if node_name == "vps-lighthouse" {
        if let Some(host) = host_from_endpoint(physical_endpoint) {
            candidates.push(format!("{}:8080", host));
        }
        if !overlay_ip.is_empty() {
            candidates.push(format!("{}:8080", overlay_ip));
        }
    } else {
        if !overlay_ip.is_empty() {
            candidates.push(format!("{}:{}", overlay_ip, registry_port));
        }
        if let Some(host) = host_from_endpoint(physical_endpoint) {
            candidates.push(format!("{}:{}", host, registry_port));
        }
    }

    let futures: Vec<_> = candidates
        .into_iter()
        .map(|addr| async move { tcp_port_open(&addr).await })
        .collect();

    for res in futures_util::future::join_all(futures).await {
        if res {
            return true;
        }
    }
    false
}

pub async fn reachable_lighthouse_name() -> Option<String> {
    use crate::nebula::lighthouse::LighthouseRegistry;
    use crate::nebula::registry_sync::{LIGHTHOUSE_REGISTRY_PATH, REGISTRY_SYNC_PORT};

    // Runtime mode: probe all lighthouse-role entries and refresh `is_active`
    // based on live reachability, then return the best reachable candidate.
    if let Ok(mut lh_reg) = LighthouseRegistry::load(LIGHTHOUSE_REGISTRY_PATH) {
        let candidates = lh_reg
            .lighthouses
            .iter()
            .filter(|l| l.is_lighthouse)
            .cloned()
            .collect::<Vec<_>>();

        let old_primary = lh_reg.primary().map(|p| p.node_name.clone());
        let mut changed = false;

        // 1. Probe all lighthouses and update active status
        for lh in &candidates {
            let ok = lighthouse_runtime_reachable(
                &lh.node_name,
                &lh.overlay_ip,
                &lh.physical_endpoint,
                REGISTRY_SYNC_PORT,
            )
            .await;

            if let Some(entry) = lh_reg
                .lighthouses
                .iter_mut()
                .find(|entry| entry.node_name == lh.node_name && entry.is_lighthouse)
            {
                if entry.is_active != ok {
                    entry.is_active = ok;
                    changed = true;
                }
            }
        }

        // 2. Select primary with HYSTERESIS (stick to current primary if it is still active)
        let mut reachable_name: Option<String> = None;
        if let Some(ref current_name) = old_primary {
            if lh_reg
                .lighthouses
                .iter()
                .any(|l| &l.node_name == current_name && l.is_active)
            {
                reachable_name = Some(current_name.clone());
            }
        }

        // If current primary is inactive or absent, pick the first active lighthouse (nodeA preferred, then vps)
        if reachable_name.is_none() {
            reachable_name = lh_reg
                .lighthouses
                .iter()
                .filter(|l| l.is_lighthouse && l.is_active)
                .map(|l| l.node_name.clone())
                .next();
        }

        if let Some(ref reachable) = reachable_name {
            if lh_reg.set_primary_lighthouse(reachable) {
                changed = true;
                if old_primary.as_deref() != Some(reachable.as_str()) {
                    if let Some(prev) = old_primary {
                        println!(
                            "🔁 Lighthouse failover: {} -> {} (new primary)",
                            prev, reachable
                        );
                    } else {
                        println!("🔁 Lighthouse failover: {} promoted to primary", reachable);
                    }
                }
            }
        }

        if changed {
            let _ = lh_reg.save(LIGHTHOUSE_REGISTRY_PATH);
        }

        return reachable_name;
    }

    None
}

// ── Wire format ─────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfigBroadcast {
    pub node_id: String,
    pub hostname: String,
    pub ip: String,
    pub port: u16,
    pub public_key: String,
}

// ── STEP 1: IP Detection ────────────────────────────────────────
pub fn detect_local_lan_ip() -> Result<Ipv4Addr> {
    let candidates = crate::network_selector::detect_candidates()
        .map_err(|e| anyhow::anyhow!("Network scan failed: {}", e))?;

    let best = crate::network_selector::best_candidate(&candidates)
        .ok_or_else(|| anyhow::anyhow!("No LAN IP found"))?;

    // println!(
    //     "🌐 Best network selected: iface={} transport={} ip={} score={} metric={} latency~{}ms bw~{}kbps live={} stable={}/{}",
    //     best.interface_name,
    //     best.transport_type,
    //     best.ip,
    //     best.quality_score,
    //     best.route_metric
    //         .map(|m| m.to_string())
    //         .unwrap_or_else(|| "n/a".to_string()),
    //     best.observed_latency_ms,
    //     best.observed_bandwidth_kbps,
    //     best.using_live_metrics,
    //     best.consecutive_successes,
    //     best.consecutive_failures
    // );

    Ok(best.ip)
}

// ── STEP 2: Config File Update ──────────────────────────────────
pub fn update_config_ip_if_changed(
    config_path: &str,
    new_ip: &str,
) -> Result<(String, String, bool)> {
    let content = std::fs::read_to_string(config_path)
        .with_context(|| format!("Cannot read: {}", config_path))?;

    let old_ip = extract_ip_from_yaml(&content).unwrap_or_else(|| "unknown".to_string());

    if old_ip == new_ip {
        println!("✅ IP unchanged ({}) — config not modified", new_ip);
        return Ok((old_ip, new_ip.to_string(), false));
    }

    println!("🔄 Updating IP: {} → {} in {}", old_ip, new_ip, config_path);
    let updated = replace_ip_in_yaml(&content, new_ip)?;
    std::fs::write(config_path, &updated)
        .with_context(|| format!("Cannot write: {}", config_path))?;

    println!("✅ Config updated: {}", config_path);
    Ok((old_ip, new_ip.to_string(), true))
}

pub fn extract_ip_from_yaml(content: &str) -> Option<String> {
    content
        .lines()
        .find(|l| l.trim().starts_with("ip:"))
        .map(|l| {
            l.trim()
                .trim_start_matches("ip:")
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string()
        })
        .filter(|s| !s.is_empty())
}

fn replace_ip_in_yaml(content: &str, new_ip: &str) -> Result<String> {
    let mut replaced = false;
    let lines: Vec<String> = content
        .lines()
        .map(|line| {
            if line.trim().starts_with("ip:") && !replaced {
                replaced = true;
                let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
                format!("{}ip: \"{}\"", indent, new_ip)
            } else {
                line.to_string()
            }
        })
        .collect();

    if !replaced {
        return Err(anyhow::anyhow!("'ip:' field not found in YAML"));
    }

    let mut result = lines.join("\n");
    if content.ends_with('\n') {
        result.push('\n');
    }
    Ok(result)
}

pub async fn broadcast_own_config_to_peers(
    my_config: &NodeConfigBroadcast,
    peer_ips: &[String], // These should be real peer IPs, not config placeholders
) {
    // Extra safety: filter out non-routable IPs before broadcasting
    let valid_ips: Vec<&String> = peer_ips.iter().filter(|ip| is_routable_ip(ip)).collect();

    if valid_ips.is_empty() {
        println!("⚠️ No routable peer IPs to broadcast to — skipping");
        return;
    }

    let payload = match serde_json::to_vec(my_config) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("❌ Serialize failed: {:?}", e);
            return;
        }
    };

    for peer_ip in valid_ips {
        let addr = format!("{}:{}", peer_ip, CONFIG_SYNC_PORT);
        let payload_clone = payload.clone();
        let addr_clone = addr.clone();
        let source_id = my_config.node_id.clone();

        tokio::spawn(async move {
            for attempt in 1..=BROADCAST_RETRIES {
                match send_config_tcp(&addr_clone, &payload_clone).await {
                    Ok(_) => {
                        println!("✅ Config sent → {} (attempt {})", addr_clone, attempt);
                        return;
                    }
                    Err(e) => {
                        println!(
                            "⚠️ Send {}/{} → {}: {}",
                            attempt, BROADCAST_RETRIES, addr_clone, e
                        );
                        if attempt < BROADCAST_RETRIES {
                            sleep(Duration::from_secs(RETRY_DELAY_SECS * attempt as u64)).await;
                        }
                    }
                }
            }
            eprintln!(
                "❌ Failed after {} retries → {} (from {})",
                BROADCAST_RETRIES, addr_clone, source_id
            );
        });
    }
}

/// Sends config to a single peer at a real IP address.
async fn send_config_tcp(addr: &str, payload: &[u8]) -> Result<()> {
    let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr))
        .await
        .with_context(|| format!("Timeout: {}", addr))??;

    stream
        .write_all(payload)
        .await
        .with_context(|| "Write failed")?;
    let mut ack = [0u8; 3];
    let _ = tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut ack)).await;
    Ok(())
}

// ── IP validity check ─────────────────────────────────────────
pub fn is_routable_ip(ip: &str) -> bool {
    if ip.is_empty() || ip == "0.0.0.0" {
        return false;
    }
    match ip.parse::<std::net::Ipv4Addr>() {
        Ok(addr) => {
            if addr.is_loopback() {
                return false;
            }
            let o = addr.octets();
            if o[0] == 169 && o[1] == 254 {
                return false;
            }
            if o[0] == 172 && o[1] == 17 {
                return false;
            }
            true
        }
        Err(_) => false,
    }
}

// ── STEP 5: Background IP Monitor ────────────────────────────────
// NOTE: In V2, pass an empty Vec for peer_ips during startup.
// Real broadcasts are handled by p2p_discovery.
// The monitor only updates local config and prepares future mDNS re-announcement.
pub async fn start_ip_monitor(
    node_id: String,
    config_path: String,
    peer_ips: Vec<String>, // V2: empty at startup or populated with known real IPs
    initial_config: NodeConfigBroadcast,
) {
    tokio::spawn(async move {
        let mut current_ip = initial_config.ip.clone();
        let mut my_config = initial_config;

        println!(
            "🔍 IP monitor started for {} (interval: {}s)",
            node_id, IP_MONITOR_INTERVAL_SECS
        );

        loop {
            sleep(Duration::from_secs(IP_MONITOR_INTERVAL_SECS)).await;

            match detect_local_lan_ip() {
                Ok(detected) => {
                    let new_ip = detected.to_string();
                    if new_ip != current_ip {
                        println!("🔄 [{node_id}] IP: {current_ip} → {new_ip}");

                        if let Err(e) = update_config_ip_if_changed(&config_path, &new_ip) {
                            eprintln!("❌ Config update: {:?}", e);
                            continue;
                        }

                        my_config.ip = new_ip.clone();
                        current_ip = new_ip;

                        // Broadcast only to routable peer IPs
                        let routable: Vec<String> = peer_ips
                            .iter()
                            .filter(|ip| is_routable_ip(ip))
                            .cloned()
                            .collect();

                        if !routable.is_empty() {
                            broadcast_own_config_to_peers(&my_config, &routable).await;
                        }

                        println!("✅ [{node_id}] IP change handled");
                    }
                }
                Err(e) => eprintln!("⚠️ [{node_id}] IP monitor: {:?}", e),
            }
        }
    });
}

/// Directory the per-node dynamic configs live in.
pub const CONFIG_DIR: &str = "/etc/sgx-guardian/config";

/// Whether a node id is safe to interpolate into a config file path.
///
/// The id arrives from a broadcast datagram, so anything outside this set
/// could escape the config directory via `..` or a path separator.
pub fn is_safe_node_id(node_id: &str) -> bool {
    !node_id.is_empty()
        && node_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

pub fn update_peer_config(node_id: &str, hostname: &str, ip: &str, port: u16, public_key: &str) {
    update_peer_config_in(
        std::path::Path::new(CONFIG_DIR),
        node_id,
        hostname,
        ip,
        port,
        public_key,
    )
}

/// [`update_peer_config`] against an explicit config directory.
pub fn update_peer_config_in(
    config_dir: &std::path::Path,
    node_id: &str,
    hostname: &str,
    ip: &str,
    port: u16,
    public_key: &str,
) {
    if !is_safe_node_id(node_id) {
        eprintln!(
            "⚠️ update_peer_config: rejected invalid node_id '{}'",
            node_id
        );
        return;
    }
    let path = config_dir.join(format!("{}.yaml", node_id));

    if let Ok(existing) = std::fs::read_to_string(&path) {
        let mut lines: Vec<String> = existing.lines().map(|l| l.to_string()).collect();

        let updates = [
            ("node_id", node_id),
            ("hostname", hostname),
            ("ip", ip),
            ("public_key", public_key),
        ];

        for (key, value) in &updates {
            let prefix = format!("{}:", key);
            let mut found = false;
            for line in lines.iter_mut() {
                if line.trim().starts_with(&prefix) {
                    let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
                    *line = format!("{}{}: \"{}\"", indent, key, value);
                    found = true;
                    break;
                }
            }
            if !found {
                lines.push(format!("{}: \"{}\"", key, value));
            }
        }

        let mut port_found = false;
        for line in lines.iter_mut() {
            if line.trim().starts_with("port:") {
                let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
                *line = format!("{}port: {}", indent, port);
                port_found = true;
                break;
            }
        }
        if !port_found {
            lines.push(format!("port: {}", port));
        }

        let mut result = lines.join("\n");
        if existing.ends_with('\n') && !result.ends_with('\n') {
            result.push('\n');
        }
        if result == existing {
            tracing::debug!("Config unchanged (field-level): {} -> ip={}", node_id, ip);
            return;
        }

        match std::fs::write(&path, &result) {
            Ok(_) => tracing::debug!("Config updated (field-level): {} -> ip={}", node_id, ip),
            Err(e) => eprintln!("Config write failed: {} -> {}", path.display(), e),
        }
        return;
    }

    let yaml = format!(
        "node_id: \"{}\"\nhostname: \"{}\"\nip: \"{}\"\nport: {}\npublic_key: \"{}\"\n",
        node_id, hostname, ip, port, public_key,
    );
    match std::fs::write(&path, &yaml) {
        Ok(_) => println!("Config created: {} -> ip={}", node_id, ip),
        Err(e) => eprintln!("Config write failed: {} -> {}", path.display(), e),
    }
}

// ── IP Format Sanitizer ─────────────────────────────────────────
// This function checks the IP stored in the config file.
// If the format is invalid, it replaces the value with 0.0.0.0.
pub fn sanitize_config_ip_if_invalid(config_path: &str) -> Result<()> {
    let content = std::fs::read_to_string(config_path)
        .with_context(|| format!("Cannot read: {}", config_path))?;

    let current_ip = extract_ip_from_yaml(&content).unwrap_or_else(|| "0.0.0.0".to_string());

    // Leave the value unchanged when the IP format is valid.
    if current_ip.parse::<std::net::Ipv4Addr>().is_ok() {
        return Ok(());
    }

    // Invalid IP format: replace it with 0.0.0.0.
    println!(
        "⚠️ Invalid IP format '{}' in {} — resetting to 0.0.0.0",
        current_ip, config_path
    );

    let updated = replace_ip_in_yaml(&content, "0.0.0.0")?;
    std::fs::write(config_path, &updated)
        .with_context(|| format!("Cannot write: {}", config_path))?;

    println!("✅ Reset to 0.0.0.0: {}", config_path);
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routability_rejects_placeholder_loopback_link_local_and_docker_ranges() {
        assert!(is_routable_ip("192.168.1.20"));
        assert!(is_routable_ip("10.4.3.2"));
        assert!(
            is_routable_ip("172.16.0.5"),
            "only 172.17.x is the docker bridge"
        );

        assert!(!is_routable_ip(""), "empty");
        assert!(!is_routable_ip("0.0.0.0"), "the unspecified placeholder");
        assert!(!is_routable_ip("127.0.0.1"), "loopback");
        assert!(!is_routable_ip("127.9.9.9"), "the whole loopback range");
        assert!(
            !is_routable_ip("169.254.1.1"),
            "link-local autoconfiguration"
        );
        assert!(!is_routable_ip("172.17.0.2"), "the default docker bridge");
        assert!(!is_routable_ip("not-an-ip"));
        assert!(!is_routable_ip("::1"), "IPv6 is not supported here");
        assert!(!is_routable_ip("192.168.1"), "a truncated address");
    }

    #[test]
    fn a_node_id_is_only_safe_when_it_cannot_escape_the_config_directory() {
        for safe in ["nodeA", "node-b", "node_c", "edge7"] {
            assert!(is_safe_node_id(safe), "{safe}");
        }
        for unsafe_id in ["", "../etc/passwd", "node/a", "node.a", "node a", "node$"] {
            assert!(!is_safe_node_id(unsafe_id), "{unsafe_id:?}");
        }
    }

    #[test]
    fn an_endpoint_host_is_split_off_its_port() {
        assert_eq!(
            host_from_endpoint("192.168.1.20:4242").as_deref(),
            Some("192.168.1.20")
        );
        assert_eq!(
            host_from_endpoint("ca.guardian:4242").as_deref(),
            Some("ca.guardian")
        );
        assert!(host_from_endpoint(":4242").is_none(), "no host");
        assert!(host_from_endpoint("no-port").is_none());
        assert!(host_from_endpoint("").is_none());
    }

    #[test]
    fn a_peer_config_is_created_when_none_exists() {
        let temp = tempfile::tempdir().expect("create sandbox");

        update_peer_config_in(
            temp.path(),
            "nodeB",
            "nodeb.guardian",
            "192.168.1.20",
            50052,
            "pk",
        );

        let written = std::fs::read_to_string(temp.path().join("nodeB.yaml")).expect("read");
        let parsed: crate::config_loader::NodeConfig =
            serde_yaml::from_str(&written).expect("the created config must be loadable");
        assert_eq!(parsed.node_id, "nodeB");
        assert_eq!(parsed.hostname, "nodeb.guardian");
        assert_eq!(parsed.ip, "192.168.1.20");
        assert_eq!(parsed.port, 50052);
        assert_eq!(parsed.public_key, "pk");
    }

    #[test]
    fn an_existing_peer_config_is_updated_field_by_field_preserving_other_keys() {
        let temp = tempfile::tempdir().expect("create sandbox");
        let path = temp.path().join("nodeB.yaml");
        std::fs::write(
            &path,
            "node_id: \"nodeB\"\nhostname: \"old\"\nip: \"10.0.0.1\"\nport: 1\npublic_key: \"old-pk\"\noffline_mode: 0\n",
        )
        .expect("seed config");

        update_peer_config_in(
            temp.path(),
            "nodeB",
            "new.guardian",
            "192.168.1.20",
            50052,
            "new-pk",
        );

        let written = std::fs::read_to_string(&path).expect("read");
        assert!(
            written.contains("offline_mode: 0"),
            "unrelated keys must survive a field-level update: {written}"
        );
        let parsed: crate::config_loader::NodeConfig =
            serde_yaml::from_str(&written).expect("still loadable");
        assert_eq!(parsed.hostname, "new.guardian");
        assert_eq!(parsed.ip, "192.168.1.20");
        assert_eq!(parsed.port, 50052);
        assert_eq!(parsed.public_key, "new-pk");
        assert_eq!(parsed.offline_mode, 0);
    }

    #[test]
    fn missing_fields_are_appended_to_an_existing_peer_config() {
        let temp = tempfile::tempdir().expect("create sandbox");
        let path = temp.path().join("nodeB.yaml");
        std::fs::write(&path, "node_id: \"nodeB\"\n").expect("seed partial config");

        update_peer_config_in(
            temp.path(),
            "nodeB",
            "nodeb.guardian",
            "192.168.1.20",
            50052,
            "pk",
        );

        let parsed: crate::config_loader::NodeConfig =
            serde_yaml::from_str(&std::fs::read_to_string(&path).expect("read"))
                .expect("the completed config must be loadable");
        assert_eq!(parsed.hostname, "nodeb.guardian");
        assert_eq!(parsed.port, 50052);
    }

    #[test]
    fn an_unchanged_peer_config_is_not_rewritten() {
        let temp = tempfile::tempdir().expect("create sandbox");
        let path = temp.path().join("nodeB.yaml");
        update_peer_config_in(
            temp.path(),
            "nodeB",
            "nodeb.guardian",
            "192.168.1.20",
            50052,
            "pk",
        );
        let first = std::fs::read_to_string(&path).expect("read");
        let first_mtime = std::fs::metadata(&path).expect("metadata").modified().ok();

        update_peer_config_in(
            temp.path(),
            "nodeB",
            "nodeb.guardian",
            "192.168.1.20",
            50052,
            "pk",
        );

        assert_eq!(std::fs::read_to_string(&path).expect("read"), first);
        assert_eq!(
            std::fs::metadata(&path).expect("metadata").modified().ok(),
            first_mtime,
            "an identical update must not touch the file"
        );
    }

    use std::fs;
    use tokio::net::TcpListener;

    #[test]
    fn test_routable_ip() {
        assert!(is_routable_ip("192.168.0.142"));
        assert!(is_routable_ip("10.0.0.5"));
        assert!(!is_routable_ip("127.0.0.1"));
        assert!(!is_routable_ip("0.0.0.0"));
        assert!(!is_routable_ip("169.254.1.1"));
        assert!(!is_routable_ip("172.17.0.2"));
        assert!(is_routable_ip("172.18.0.2"));
        assert!(!is_routable_ip(""));
        assert!(!is_routable_ip("invalid"));
    }

    #[test]
    fn test_extract_ip_yaml() {
        assert_eq!(
            extract_ip_from_yaml("ip: \"192.168.0.142\"\n"),
            Some("192.168.0.142".to_string())
        );
        assert_eq!(
            extract_ip_from_yaml("ip: 127.0.0.1\n"),
            Some("127.0.0.1".to_string())
        );
    }

    #[test]
    fn extract_ip_from_yaml_handles_quotes_whitespace_and_first_match() {
        assert_eq!(
            extract_ip_from_yaml("node_id: n\n  ip: '10.1.2.3'\n"),
            Some("10.1.2.3".to_string())
        );
        assert_eq!(
            extract_ip_from_yaml("ip: \"192.168.4.5\"\nip: \"10.0.0.1\"\n"),
            Some("192.168.4.5".to_string())
        );
        assert_eq!(
            extract_ip_from_yaml("ip:    172.18.0.2   \n"),
            Some("172.18.0.2".to_string())
        );
        assert_eq!(extract_ip_from_yaml("ip:\n"), None);
        assert_eq!(extract_ip_from_yaml("node_id: test\nport: 50070\n"), None);
        assert_eq!(extract_ip_from_yaml("# ip: 192.168.1.1\n"), None);
    }

    #[test]
    fn replace_ip_in_yaml_updates_first_ip_preserves_indent_and_trailing_newline() {
        let content = "node_id: \"test\"\n  ip: '127.0.0.1'\npeers:\n  - ip: \"10.0.0.2\"\n";

        let updated = replace_ip_in_yaml(content, "192.168.1.20").unwrap();

        assert_eq!(
            updated,
            "node_id: \"test\"\n  ip: \"192.168.1.20\"\npeers:\n  - ip: \"10.0.0.2\"\n"
        );
    }

    #[test]
    fn replace_ip_in_yaml_handles_no_trailing_newline_and_missing_ip_error() {
        let updated = replace_ip_in_yaml("node_id: test\nip: 0.0.0.0", "10.0.0.9").unwrap();
        assert_eq!(updated, "node_id: test\nip: \"10.0.0.9\"");

        let err = replace_ip_in_yaml("node_id: test\nport: 50070\n", "10.0.0.9")
            .expect_err("missing ip field should fail");
        assert!(err.to_string().contains("'ip:' field not found"));
    }

    #[test]
    fn update_config_ip_if_changed_updates_file_and_reports_old_new_values() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap();
        fs::write(path, "node_id: test\n  ip: \"127.0.0.1\"\nport: 50070\n").unwrap();

        let (old_ip, new_ip, changed) = update_config_ip_if_changed(path, "192.168.1.100").unwrap();

        assert_eq!(old_ip, "127.0.0.1");
        assert_eq!(new_ip, "192.168.1.100");
        assert!(changed);
        assert_eq!(
            fs::read_to_string(path).unwrap(),
            "node_id: test\n  ip: \"192.168.1.100\"\nport: 50070\n"
        );
    }

    #[test]
    fn update_config_ip_if_changed_noops_when_ip_matches() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap();
        let content = "node_id: test\nip: \"10.0.0.7\"\nport: 50070\n";
        fs::write(path, content).unwrap();

        let (old_ip, new_ip, changed) = update_config_ip_if_changed(path, "10.0.0.7").unwrap();

        assert_eq!(old_ip, "10.0.0.7");
        assert_eq!(new_ip, "10.0.0.7");
        assert!(!changed);
        assert_eq!(fs::read_to_string(path).unwrap(), content);
    }

    #[test]
    fn update_config_ip_if_changed_returns_errors_for_missing_file_and_missing_ip_field() {
        let missing =
            update_config_ip_if_changed("/tmp/sgx-dynamic-config-missing.yaml", "1.2.3.4")
                .expect_err("missing file should fail");
        assert!(missing.to_string().contains("Cannot read"));

        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap();
        let content = "node_id: test\nport: 50070\n";
        fs::write(path, content).unwrap();

        let err =
            update_config_ip_if_changed(path, "1.2.3.4").expect_err("missing ip field should fail");
        assert!(err.to_string().contains("'ip:' field not found"));
        assert_eq!(fs::read_to_string(path).unwrap(), content);
    }

    #[test]
    fn sanitize_config_ip_if_invalid_preserves_valid_ips_and_resets_invalid_ips() {
        let valid = tempfile::NamedTempFile::new().unwrap();
        let valid_path = valid.path().to_str().unwrap();
        let valid_content = "node_id: test\nip: \"192.168.1.77\"\n";
        fs::write(valid_path, valid_content).unwrap();

        sanitize_config_ip_if_invalid(valid_path).unwrap();
        assert_eq!(fs::read_to_string(valid_path).unwrap(), valid_content);

        let invalid = tempfile::NamedTempFile::new().unwrap();
        let invalid_path = invalid.path().to_str().unwrap();
        fs::write(invalid_path, "node_id: test\n  ip: \"not-an-ip\"\n").unwrap();

        sanitize_config_ip_if_invalid(invalid_path).unwrap();
        assert_eq!(
            fs::read_to_string(invalid_path).unwrap(),
            "node_id: test\n  ip: \"0.0.0.0\"\n"
        );
    }

    #[test]
    fn sanitize_config_ip_if_invalid_handles_missing_ip_as_valid_default() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap();
        let content = "node_id: test\nport: 50070\n";
        fs::write(path, content).unwrap();

        sanitize_config_ip_if_invalid(path).unwrap();

        assert_eq!(fs::read_to_string(path).unwrap(), content);
    }

    #[test]
    fn sanitize_config_ip_if_invalid_errors_when_invalid_ip_cannot_be_replaced() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap();
        fs::write(path, "node_id: test\n").unwrap();

        sanitize_config_ip_if_invalid(path).unwrap();

        fs::write(path, "node_id: test\nip: \"300.1.1.1\"\n").unwrap();
        sanitize_config_ip_if_invalid(path).unwrap();
        assert!(fs::read_to_string(path)
            .unwrap()
            .contains("ip: \"0.0.0.0\""));
    }

    #[test]
    fn is_routable_ip_covers_ipv4_boundaries_and_invalid_formats() {
        assert!(is_routable_ip("1.1.1.1"));
        assert!(is_routable_ip("172.16.255.255"));
        assert!(!is_routable_ip("172.17.0.1"));
        assert!(!is_routable_ip("172.17.255.255"));
        assert!(is_routable_ip("172.18.0.1"));
        assert!(!is_routable_ip("127.255.255.255"));
        assert!(!is_routable_ip("169.254.0.0"));
        assert!(!is_routable_ip("169.254.255.255"));
        assert!(!is_routable_ip("256.1.1.1"));
        assert!(!is_routable_ip("192.168.1"));
        assert!(!is_routable_ip("::1"));
        assert!(!is_routable_ip(" 192.168.1.1 "));
    }

    #[test]
    fn host_from_endpoint_extracts_host_using_last_colon() {
        assert_eq!(
            host_from_endpoint("example.com:50070"),
            Some("example.com".to_string())
        );
        assert_eq!(
            host_from_endpoint("10.0.0.5:4242"),
            Some("10.0.0.5".to_string())
        );
        assert_eq!(host_from_endpoint("[::1]:50070"), Some("[::1]".to_string()));
        assert_eq!(
            host_from_endpoint("host:with:colons:123"),
            Some("host:with:colons".to_string())
        );
        assert_eq!(host_from_endpoint(":50070"), None);
        assert_eq!(host_from_endpoint("missing-port"), None);
    }

    #[test]
    fn node_config_broadcast_serializes_round_trips_and_clones() {
        let config = NodeConfigBroadcast {
            node_id: "node-A_1".to_string(),
            hostname: "node-a.local".to_string(),
            ip: "192.168.1.50".to_string(),
            port: CONFIG_SYNC_PORT,
            public_key: "public-key".to_string(),
        };

        let cloned = config.clone();
        let json = serde_json::to_string(&cloned).unwrap();
        let decoded: NodeConfigBroadcast = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.node_id, "node-A_1");
        assert_eq!(decoded.hostname, "node-a.local");
        assert_eq!(decoded.ip, "192.168.1.50");
        assert_eq!(decoded.port, CONFIG_SYNC_PORT);
        assert_eq!(decoded.public_key, "public-key");
        assert!(format!("{:?}", decoded).contains("node-A_1"));
    }

    #[tokio::test]
    async fn tcp_port_open_reports_open_and_closed_loopback_ports() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        assert!(tcp_port_open(&addr.to_string()).await);
        accept_task.await.unwrap();

        let closed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_addr = closed_listener.local_addr().unwrap();
        drop(closed_listener);

        assert!(!tcp_port_open(&closed_addr.to_string()).await);
    }

    #[tokio::test]
    async fn send_config_tcp_writes_payload_and_accepts_ack() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let payload = b"{\"node_id\":\"node-a\"}".to_vec();
        let expected = payload.clone();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut received = vec![0; expected.len()];
            socket.read_exact(&mut received).await.unwrap();
            socket.write_all(b"ack").await.unwrap();
            received
        });

        send_config_tcp(&addr.to_string(), &payload).await.unwrap();

        assert_eq!(server.await.unwrap(), payload);
    }

    #[tokio::test]
    async fn send_config_tcp_returns_error_for_unreachable_loopback_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let err = send_config_tcp(&addr.to_string(), b"payload")
            .await
            .expect_err("closed listener should refuse connection");

        assert!(!err.to_string().is_empty());
    }

    #[tokio::test]
    async fn lighthouse_runtime_reachable_tries_overlay_then_endpoint_host() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        assert!(lighthouse_runtime_reachable("", "", &format!("127.0.0.1:{}", port), port).await);
        server.await.unwrap();

        let closed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_port = closed_listener.local_addr().unwrap().port();
        drop(closed_listener);

        assert!(
            !lighthouse_runtime_reachable(
                "",
                "",
                &format!("127.0.0.1:{}", closed_port),
                closed_port,
            )
            .await
        );
    }

    #[test]
    fn latest_known_ca_ip_returns_none_when_the_system_config_is_absent() {
        // `/etc/sgx-guardian/config/nodeA.yaml` is a hardcoded path (no env
        // override) that genuinely doesn't exist in this sandbox, so this
        // deterministically exercises the load-failure branch.
        assert!(!std::path::Path::new("/etc/sgx-guardian/config/nodeA.yaml").exists());
        assert_eq!(latest_known_ca_ip(), None);
    }

    #[tokio::test]
    async fn overlay_is_reachable_and_reachable_lighthouse_name_return_none_without_a_registry() {
        // `LIGHTHOUSE_REGISTRY_PATH` is likewise a hardcoded, non-overridable
        // path that is genuinely absent in this sandbox.
        assert!(
            !std::path::Path::new("/var/lib/sgx-guardian/nebula/lighthouse_registry.json").exists()
        );
        assert_eq!(reachable_lighthouse_name().await, None);
        assert!(!overlay_is_reachable().await);
    }

    #[test]
    fn detect_local_lan_ip_runs_the_real_network_scan_without_panicking() {
        // Whichever branch this sandbox's real interfaces produce, the call
        // itself must complete without panicking.
        let _ = detect_local_lan_ip();
    }

    #[test]
    fn update_peer_config_rejects_an_invalid_node_id_without_touching_disk() {
        // An invalid node_id must be rejected before any path is built or
        // file I/O attempted, regardless of whether `/etc/sgx-guardian` is
        // writable in this environment.
        update_peer_config("../escape", "host", "10.0.0.1", 50070, "key");
        update_peer_config("", "host", "10.0.0.1", 50070, "key");
        assert!(!std::path::Path::new("/etc/sgx-guardian/config/../escape.yaml").exists());
    }

    #[tokio::test]
    async fn overlay_and_broadcast_empty_paths_do_not_require_network_or_config() {
        let config = NodeConfigBroadcast {
            node_id: "node-a".to_string(),
            hostname: "node-a.local".to_string(),
            ip: "192.168.1.50".to_string(),
            port: CONFIG_SYNC_PORT,
            public_key: "public-key".to_string(),
        };

        broadcast_own_config_to_peers(
            &config,
            &[
                "127.0.0.1".to_string(),
                "0.0.0.0".to_string(),
                "169.254.1.1".to_string(),
                "172.17.0.2".to_string(),
                "invalid".to_string(),
            ],
        )
        .await;
    }
}
