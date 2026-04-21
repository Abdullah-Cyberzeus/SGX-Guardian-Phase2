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
            Err(_) => match load_config(rel_path) {
                Ok(cfg) => {
                    if cfg.node_id != node_id {
                        configs.push(cfg);
                    }
                }
                Err(_) => {}
            },
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
                println!(
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
                    sleep(Duration::from_secs(15)).await;
                    continue;
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
                    println!(
                        "🔐 Queued discovered peer for attestation: {}",
                        conf.node_id
                    );
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
