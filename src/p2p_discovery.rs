use crate::attestation_service::AttestationService;
use crate::config_loader::load_config;
use crate::key_manager::KeyManager;
use crate::logging::log_event;
use anyhow::Result;
use libmdns::Responder;
use serde_json::json;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

/// Provides peer discovery for SGX nodes using mDNS broadcasting,
/// UDP-based listener scanning, and simulated fallback discovery for testing.
pub struct P2PDiscovery;

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

        let responder = Responder::new()?;
        let _svc = responder.register(
            "_sgx-guardian._tcp".to_string(),
            node_id.clone(),
            8443,
            &["node=sgx-guardian"],
        );
        println!("✅ mDNS service registered for {}", node_id);
        let km = Arc::new(KeyManager::load_or_generate(None)?);
        let _km_clone = km.clone();
        let node_id_clone = node_id.clone();
        let node_id_sim = node_id.clone();
        // ✅ Create two independent clones
        let tx_clone_bg = tx.clone(); // for background task
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
            println!("Peer discovery listener active (UDP mDNS)");
            let mut buf = [0u8; 1024];
            loop {
                if let Ok((len, addr)) = socket.recv_from(&mut buf).await {
                    let msg = String::from_utf8_lossy(&buf[..len]);
                    if msg.contains("_sgx-guardian._tcp") && !msg.contains(&node_id_clone) {
                        log_event(
                            &node_id_clone,
                            &format!("Discovered peer via mDNS: {}", addr),
                        );
                        log_event(&node_id_clone, &format!("Discovered peer: {}", addr));

                        // FIXED: send full address instead of only IP
                        let full_addr = format!("{}:{}", addr.ip(), 50051); // default base port

                        if let Err(e) = tx_clone_bg.send(full_addr).await {
                            eprintln!("⚠️ Failed to send discovered peer to channel: {:?}", e);
                        }
                    }
                }
            }
        });

        // ✅ Use tx_clone_sim safely for simulation peers later
        println!("💡 [Simulation Mode] Using static peer list for discovery testing.");

        let config_paths = [
            "config/nodeA.yaml",
            "config/nodeB.yaml",
            "config/nodeC.yaml",
        ];

        let mut configs = Vec::new();

        for path in config_paths {
            match load_config(path) {
                Ok(cfg) => configs.push(cfg),
                Err(e) => {
                    log_event(&node_id, &format!("⚠️ Failed to load {}: {}", path, e));
                }
            }
        }

        for conf in configs {
            if conf.node_id != node_id {
                let peer_ip = conf.ip.clone();
                let peer_port = conf.port;
                log_event(
                    &node_id,
                    &format!("Simulated discovery event: {}:{}", peer_ip, peer_port),
                );
                tokio::time::sleep(Duration::from_secs(1)).await; // prevent race
                let full_addr = format!("{}:{}", peer_ip, peer_port);
                tx_clone_sim.send(full_addr.clone()).await.ok();
                println!("🔐 Attesting discovered peer (sim-mode): {}", full_addr);
                let km_ref = Arc::new(KeyManager::load_or_generate(None)?);
                println!("🔐 Attesting discovered peer: {}:{}", peer_ip, peer_port);

                // 👇 use peer_port + 100 for attestation listener (5015x range)
                if let Ok(true) =
                    AttestationService::mutual_attest(peer_ip.clone(), peer_port + 100, &km_ref)
                        .await
                {
                    log_event(
                        &node_id,
                        &format!(
                            "✅ Mutual attestation succeeded with {}:{}",
                            peer_ip,
                            peer_port + 100
                        ),
                    );
                } else {
                    log_event(
                        &node_id,
                        &format!(
                            "❌ Mutual attestation failed with {}:{}",
                            peer_ip,
                            peer_port + 100
                        ),
                    );
                }
            }
        }

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
