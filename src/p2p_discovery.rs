use crate::config_loader::{load_config, NodeConfig};
use crate::logging::log_event;
use anyhow::Result;
use libmdns::Responder;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

/// Provides peer discovery for SGX nodes using mDNS broadcasting,
/// UDP-based listener scanning, and simulated fallback discovery for testing.
pub struct P2PDiscovery;

fn sim_mode_enabled() -> bool {
    match std::env::var("SGX_SIM_MODE") {
        Ok(v) => matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => false,
    }
}

fn load_known_node_configs(node_id: &str) -> Vec<NodeConfig> {
    let config_paths_abs = [
        "/etc/sgx-guardian/config/nodeA.yaml",
        "/etc/sgx-guardian/config/nodeB.yaml",
        "/etc/sgx-guardian/config/nodeC.yaml",
    ];
    let config_paths_rel = [
        "config/nodeA.yaml",
        "config/nodeB.yaml",
        "config/nodeC.yaml",
    ];

    let mut configs = Vec::new();
    for (abs_path, rel_path) in config_paths_abs.iter().zip(config_paths_rel.iter()) {
        // Try absolute first (boards), then relative (laptop dev)
        match load_config(abs_path) {
            Ok(cfg) => {
                if cfg.node_id != node_id {
                    configs.push(cfg);
                }
            }
            Err(_) => {
                if let Ok(cfg) = load_config(rel_path) {
                    if cfg.node_id != node_id {
                        configs.push(cfg);
                    }
                }
            }
        }
    }

    configs
}

async fn peer_is_reachable(ip: &str, port: u16) -> bool {
    let addr = format!("{}:{}", ip, port);
    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false)
}

impl P2PDiscovery {
    /// Starts the P2P discovery workflow for an SG-X node.  
    /// Registers an mDNS service, listens for incoming peer advertisements,
    /// emits discovered peers to the attestation channel, and performs
    /// simulated discovery for local multi-node testing.
    pub async fn run(
        tx: Sender<String>,
        node_id: String,
        _logger: Arc<Mutex<String>>,
    ) -> Result<()> {
        log_event(&node_id, "Starting mDNS discovery");

        let responder = match Responder::new() {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!(
                    "⚠️ mDNS responder unavailable (continuing without mDNS): {}",
                    e
                );
                None
            }
        };
        let _svc = responder.as_ref().map(|r| {
            r.register(
                "_sgx-guardian._tcp".to_string(),
                node_id.clone(),
                8443,
                &["node=sgx-guardian"],
            )
        });
        if _svc.is_some() {
            println!("✅ mDNS service registered for {}", node_id);
        } else {
            println!("⚠️ mDNS service disabled; using broadcast/config discovery only");
        }
        let node_id_clone = node_id.clone();
        let node_id_sim = node_id.clone();
        // ✅ Create clone for simulation path
        let tx_clone_sim = tx.clone(); // for simulation below

        tokio::spawn(async move {
            let mut socket_opt = None;
            for port in 5353..5360 {
                match UdpSocket::bind(format!("0.0.0.0:{}", port)).await {
                    Ok(s) => {
                        log_event(&node_id_clone, &format!("Bound UDP port {}", port));
                        socket_opt = Some(s);
                        break;
                    }
                    Err(_) => continue,
                }
            }
            let Some(socket) = socket_opt else {
                eprintln!("❌ No free UDP port available for mDNS listener");
                return;
            };
            println!("Peer discovery listener active (UDP mDNS — observability only)");
            let mut buf = [0u8; 1024];
            loop {
                if let Ok((len, _addr)) = socket.recv_from(&mut buf).await {
                    let msg = String::from_utf8_lossy(&buf[..len]);
                    if msg.contains("_sgx-guardian._tcp") && !msg.contains(&node_id_clone) {
                        // Observability only — config-scan path is source of truth for queueing.
                        log_event(&node_id_clone, "mDNS peer advertisement observed");
                    }
                }
            }
        });

        // Static simulation is opt-in for laptop/local demos only.
        if sim_mode_enabled() {
            println!("💡 [Simulation Mode] Using static peer list for discovery testing.");
            for conf in load_known_node_configs(&node_id) {
                if !crate::dynamic_config::is_routable_ip(&conf.ip) {
                    continue;
                }
                let peer_ip = conf.ip.clone();
                let peer_port = conf.port;
                log_event(
                    &node_id,
                    &format!("Simulated discovery event: {}:{}", peer_ip, peer_port),
                );
                tokio::time::sleep(Duration::from_secs(1)).await; // prevent race
                let full_addr = format!("{}:{}", peer_ip, peer_port);
                let queue_entry = format!("{}|{}", conf.node_id, full_addr);
                tx_clone_sim.send(queue_entry).await.ok();
                tracing::debug!(
                    "🔐 Queued discovered peer for attestation (sim-mode): {}",
                    conf.node_id
                );
            }
        } else {
            println!("🔎 Simulation mode disabled (set SGX_SIM_MODE=true to enable)");
        }

        // Periodically scan dynamic node configs (updated by broadcasts) and
        // enqueue routable peers for attestation.
        let tx_clone_cfg = tx.clone();
        let node_id_cfg = node_id.clone();
        tokio::spawn(async move {
            let mut last_sent: HashMap<String, std::time::Instant> = HashMap::new();

            loop {
                if node_id_cfg != "nodeA" && !crate::dynamic_config::overlay_is_reachable().await {
                    // Don't skip entirely — still enqueue LAN peers for bootstrap
                    // Only skip overlay-specific peers
                    eprintln!(
                        "⏳ [{}] Overlay not yet reachable — LAN discovery continues",
                        node_id_cfg
                    );
                }

                for conf in load_known_node_configs(&node_id_cfg) {
                    if !crate::dynamic_config::is_routable_ip(&conf.ip) {
                        continue;
                    }

                    // Queue only live peers. Prevents stale "discovered" logs for stopped nodes.
                    if !peer_is_reachable(&conf.ip, conf.port).await {
                        continue;
                    }

                    let full_addr = format!("{}:{}", conf.ip, conf.port);
                    let now = std::time::Instant::now();
                    let should_send = match last_sent.get(&full_addr) {
                        Some(last) => now.duration_since(*last).as_secs() >= 30,
                        None => true,
                    };
                    if !should_send {
                        continue;
                    }

                    last_sent.insert(full_addr.clone(), now);
                    let queue_entry = format!("{}|{}", conf.node_id, full_addr);
                    if let Err(e) = tx_clone_cfg.send(queue_entry).await {
                        eprintln!("⚠️ Failed to queue peer for attestation: {:?}", e);
                        return;
                    }
                    tracing::debug!(
                        "🔐 Queued discovered peer for attestation: {}",
                        conf.node_id
                    );
                }

                // 2. Scan overlay registry allocations (for mesh peers)
                let mut overlay_candidates: Vec<(String, String)> = Vec::new();
                if let Ok(reg) = crate::nebula::overlay_registry::OverlayRegistry::load(
                    crate::nebula::registry_sync::REGISTRY_PATH,
                ) {
                    for (peer_node, ip_rec) in reg.allocations {
                        overlay_candidates.push((peer_node, ip_rec.overlay_ip));
                    }
                }
                if node_id_cfg != "nodeA" && !overlay_candidates.iter().any(|(n, _)| n == "nodeA") {
                    overlay_candidates.push(("nodeA".to_string(), "192.168.100.1".to_string()));
                }

                for (peer_node, overlay_ip) in overlay_candidates {
                    if peer_node == node_id_cfg {
                        continue;
                    }
                    let base_port = match peer_node.as_str() {
                        "nodeA" => 50051,
                        "nodeB" => 50052,
                        "nodeC" => 50053,
                        _ => 50051,
                    };
                    let attest_port =
                        crate::attestation_service::attestation_listener_port_for_base(base_port);

                    // Check if peer is reachable over overlay (either on gRPC base port or attestation port)
                    if !peer_is_reachable(&overlay_ip, attest_port).await
                        && !peer_is_reachable(&overlay_ip, base_port).await
                    {
                        continue;
                    }

                    let full_addr = format!("{}:{}", overlay_ip, base_port);
                    let now = std::time::Instant::now();
                    let should_send = match last_sent.get(&full_addr) {
                        Some(last) => now.duration_since(*last).as_secs() >= 30,
                        None => true,
                    };
                    if !should_send {
                        continue;
                    }

                    last_sent.insert(full_addr.clone(), now);
                    let queue_entry = format!("{}|{}", peer_node, full_addr);
                    if let Err(e) = tx_clone_cfg.send(queue_entry).await {
                        eprintln!("⚠️ Failed to queue overlay peer for attestation: {:?}", e);
                        return;
                    }
                    tracing::debug!(
                        "🔐 Queued discovered overlay peer for attestation: {} ({})",
                        peer_node,
                        full_addr
                    );
                }

                // 3. Scan SGX_LIGHTHOUSE_IP for nodeA if this node is not nodeA
                if node_id_cfg != "nodeA" {
                    if let Ok(lh_ip) = std::env::var("SGX_LIGHTHOUSE_IP") {
                        if crate::dynamic_config::is_routable_ip(&lh_ip) {
                            if peer_is_reachable(&lh_ip, 50151).await
                                || peer_is_reachable(&lh_ip, 50051).await
                            {
                                let full_addr = format!("{}:50051", lh_ip);
                                let now = std::time::Instant::now();
                                let should_send = match last_sent.get(&full_addr) {
                                    Some(last) => now.duration_since(*last).as_secs() >= 30,
                                    None => true,
                                };
                                if should_send {
                                    last_sent.insert(full_addr.clone(), now);
                                    let queue_entry = format!("nodeA|{}", full_addr);
                                    let _ = tx_clone_cfg.send(queue_entry).await;
                                }
                            }
                        }
                    }
                }

                sleep(Duration::from_secs(15)).await;
            }
        });

        // Continue advertisement loop as before
        loop {
            let adv = json!({
                "event": "ADVERTISE",
                "node": node_id_sim.clone(),
                "service": "_sgx-guardian._tcp"
            });
            log_event(&node_id_sim, &adv.to_string());
            sleep(Duration::from_secs(10)).await;
        }
    }
}
