// src/dynamic_config.rs — VERSION 2
// ================================================================
// CHANGES FROM V1:
//
// V1 mein main.rs broadcast ke liye peer IPs config se leta tha:
//   let peer_ips: Vec<String> = peers.iter().map(|p| p.ip.clone()).collect();
//   broadcast_own_config_to_peers(&my_config, &peer_ips).await;
//
// Problem: Agar config mein 127.0.0.1 hai to broadcast fail hoga.
//
// V2 FIX:
//   - main.rs se startup broadcast HATA DO (ya disabled rakho)
//   - p2p_discovery.rs hi config sync karta hai jab real peer milta hai
//   - is file mein koi change nahi — sirf main.rs integration simplify hua
//   - Agar manual broadcast karna ho to: broadcast_to_real_ip() use karo
//     jo seedha ek known real IP par bhejta hai (config se nahi)
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

pub async fn reachable_lighthouse_name() -> Option<String> {
    use crate::nebula::lighthouse::LighthouseRegistry;
    use crate::nebula::overlay_registry::OverlayRegistry;
    use crate::nebula::registry_sync::{
        LIGHTHOUSE_REGISTRY_PATH, REGISTRY_PATH, REGISTRY_SYNC_PORT,
    };

    let local_node_id = std::env::args().nth(1).unwrap_or_else(|| "nodeA".into());
    let local_is_lh = local_node_id == "nodeA"
        || std::path::Path::new("/var/lib/sgx-guardian/nebula/am_lighthouse").exists();

    // First preference: active Lighthouse from lighthouse_registry.json,
    // with deterministic ordering: primary first, then secondaries.
    if let Ok(lh_reg) = LighthouseRegistry::load(LIGHTHOUSE_REGISTRY_PATH) {
        let mut candidates = lh_reg.active().into_iter().cloned().collect::<Vec<_>>();
        candidates.sort_by(|a, b| {
            b.is_primary
                .cmp(&a.is_primary)
                .then_with(|| a.node_name.cmp(&b.node_name))
        });

        for lh in candidates {
            let addr = format!("{}:{}", lh.overlay_ip, REGISTRY_SYNC_PORT);
            let ok = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(&addr))
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false);
            if ok {
                return Some(lh.node_name);
            }
        }
    }

    // Fallback: nodeA from overlay registry.
    let reg = match OverlayRegistry::load(REGISTRY_PATH) {
        Ok(r) => r,
        Err(_) => return None,
    };
    let ca_overlay = reg.get_ip("nodeA")?;
    let addr = format!("{}:{}", ca_overlay, REGISTRY_SYNC_PORT);
    let ok = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(&addr))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);
    if ok {
        Some("nodeA".to_string())
    } else if local_is_lh {
        // Secondary LH fallback: if we are promoted, we can act as control plane
        // even when nodeA is down.
        Some(local_node_id)
    } else {
        None
    }
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
    use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};

    let interfaces =
        NetworkInterface::show().map_err(|e| anyhow::anyhow!("Network scan failed: {}", e))?;

    let mut candidates: Vec<(u8, String, Ipv4Addr)> = Vec::new();

    for iface in interfaces {
        if iface.name.starts_with("lo")
            || is_virtual_interface(&iface.name)
            || iface.name.starts_with("nebula")
            || iface.name.starts_with("docker")
            || iface.name.starts_with("defined")
            || iface.name.starts_with("armia")
        {
            continue;
        }

        for addr in iface.addr {
            if let Addr::V4(v4) = addr {
                let ip = v4.ip;
                if !is_routable_ip(&ip.to_string()) {
                    continue;
                }

                // NODE IDENTITY priority — how other nodes find us.
                // WiFi/Ethernet FIRST because peers on the LAN can reach us directly.
                // Cellular LAST because it's behind carrier NAT — peers on our
                // WiFi LAN cannot connect to our cellular IP.
                //
                // NOTE: This does NOT affect CoT transport priority (types.rs).
                // CoT can still prefer cellular for data once the overlay is up.
                let priority = if iface.name.starts_with("eth") || iface.name.starts_with("ens") {
                    0 // Wired Ethernet — most stable
                } else if iface.name == "wlan0" {
                    1 // Primary WiFi — the LAN peers use
                } else if iface.name.starts_with("wlan") {
                    2 // Secondary WiFi
                } else if iface.name.starts_with("wwan") || iface.name.starts_with("rmnet") {
                    100 // Cellular — behind carrier NAT, NOT reachable by LAN peers
                } else {
                    50 // Unknown
                };

                candidates.push((priority, iface.name.clone(), ip));
            }
        }
    }

    candidates.sort_by(|(pa, na, _), (pb, nb, _)| pa.cmp(pb).then_with(|| na.cmp(nb)));
    candidates
        .into_iter()
        .next()
        .map(|(_, _, ip)| ip)
        .ok_or_else(|| anyhow::anyhow!("No LAN IP found"))
}

fn is_virtual_interface(name: &str) -> bool {
    let n = name.to_lowercase();
    n.starts_with("docker")
        || n.starts_with("veth")
        || n.starts_with("br-")
        || n.starts_with("virbr")
        || n.starts_with("vnet")
        || n.starts_with("flannel")
        || n.starts_with("cni")
        || n.starts_with("cali")
        || n == "docker0"
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
    peer_ips: &[String], // ← ye IPs REAL honi chahiye, config se nahi
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

/// Single peer ko ek real IP par config bhejta hai
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
// NOTE: V2 mein peer_ips parameter empty Vec pass karo startup par.
// Real broadcasts p2p_discovery handle karta hai.
// Monitor sirf apni config update karta hai + future mDNS re-announce.
pub async fn start_ip_monitor(
    node_id: String,
    config_path: String,
    peer_ips: Vec<String>, // V2: startup par empty ya known real IPs
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

                        // Sirf routable peer IPs ko broadcast karo
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

pub fn update_peer_config(node_id: &str, hostname: &str, ip: &str, port: u16, public_key: &str) {
    // SECURITY: Sanitize node_id before using as filename — peers are untrusted.
    // Reject anything that isn't alphanumeric / dash / underscore.
    if node_id.is_empty()
        || !node_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        eprintln!(
            "⚠️ update_peer_config: rejected invalid node_id '{}' (path traversal protection)",
            node_id
        );
        return;
    }

    let path = format!("/etc/sgx-guardian/config/{}.yaml", node_id);

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
            println!("Config unchanged (field-level): {} -> ip={}", node_id, ip);
            return;
        }

        match std::fs::write(&path, &result) {
            Ok(_) => println!("Config updated (field-level): {} -> ip={}", node_id, ip),
            Err(e) => eprintln!("Config write failed: {} -> {}", path, e),
        }
        return;
    }

    let yaml = format!(
        "node_id: \"{}\"\nhostname: \"{}\"\nip: \"{}\"\nport: {}\npublic_key: \"{}\"\n",
        node_id, hostname, ip, port, public_key,
    );
    match std::fs::write(&path, &yaml) {
        Ok(_) => println!("Config created: {} -> ip={}", node_id, ip),
        Err(e) => eprintln!("Config write failed: {} -> {}", path, e),
    }
}

// ── IP Format Sanitizer ─────────────────────────────────────────
// Ye function config file mein IP check karta hai
// Agar format invalid hai to 0.0.0.0 se replace karta hai
pub fn sanitize_config_ip_if_invalid(config_path: &str) -> Result<()> {
    let content = std::fs::read_to_string(config_path)
        .with_context(|| format!("Cannot read: {}", config_path))?;

    let current_ip = extract_ip_from_yaml(&content).unwrap_or_else(|| "0.0.0.0".to_string());

    // Agar IP valid format hai — kuch mat karo
    if current_ip.parse::<std::net::Ipv4Addr>().is_ok() {
        return Ok(());
    }

    // Invalid format hai — 0.0.0.0 se replace karo
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
}
