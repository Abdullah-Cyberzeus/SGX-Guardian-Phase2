mod config_loader;
mod policy;
pub mod proto {
    pub mod sgx {
        include!(concat!(env!("OUT_DIR"), "/sgx.rs"));
    }
}
mod attestation_service;
mod client;
mod key_manager;
mod logging;
mod metrics;
mod p2p_discovery;
mod server;

use base64::{engine::general_purpose, Engine as _};
use client::send_ping;
use config_loader::load_config;
use key_manager::KeyManager;
#[allow(unused_imports)]
use logging::{init_logger, log_error, log_event};
use metrics::Metrics;
use server::start_server;
use std::env;
use std::fs;
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
#[allow(unused_imports)]
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::{signal, task};

#[cfg(windows)]
use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!(" SGX Guardian Client Starting...");
    #[cfg(windows)]
    {
        static CTRL_C_PRESSED: AtomicBool = AtomicBool::new(false);
        unsafe extern "system" fn ctrl_handler(_: u32) -> i32 {
            CTRL_C_PRESSED.store(true, Ordering::SeqCst);
            println!("\n SGX Guardian Client shut down cleanly.");
            1
        }
        unsafe {
            SetConsoleCtrlHandler(Some(ctrl_handler), 1);
        }
    }

    // Initialize or load persistent identity keypair
    let km = KeyManager::load_or_generate(None)?;
    let pubkey_b64 = general_purpose::STANDARD.encode(km.pubkey_der());
    println!(
        "Node Identity Initialized | Public Key Prefix: {}...",
        &pubkey_b64[..20]
    );

    // Generate and log attestation evidence for this node
    use crate::attestation_service::AttestationService;
    let sample_policy = fs::read_to_string("schemas/uep_policy_v1.yaml")
        .expect("Failed to read policy file for attestation test");
    let evidence = AttestationService::create_signed_evidence(&km, &sample_policy)?;
    println!(
        "Created local attestation evidence (nonce={}..)",
        &evidence.nonce[..8]
    );
    let verified =
        AttestationService::verify_signed_evidence(&evidence, &km.pubkey_der(), &sample_policy)?;
    if verified {
        println!("✅ Local attestation evidence verified successfully.");
    } else {
        eprintln!("❌ Local attestation verification failed!");
    }
    println!("\n Loading node configurations...");
    let node_a = load_config("config/nodeA.yaml").expect("Failed to load nodeA config");
    let node_b = load_config("config/nodeB.yaml").expect("Failed to load nodeB config");
    let node_c = load_config("config/nodeC.yaml").expect("Failed to load nodeC config");

    println!(
        "✅ Loaded Node A: {} ({}) at {}:{} | key: {}",
        node_a.node_id, node_a.hostname, node_a.ip, node_a.port, node_a.public_key
    );
    println!(
        "✅ Loaded Node B: {} ({}) at {}:{} | key: {}",
        node_b.node_id, node_b.hostname, node_b.ip, node_b.port, node_b.public_key
    );
    println!(
        "✅ Loaded Node C: {} ({}) at {}:{} | key: {}",
        node_c.node_id, node_c.hostname, node_c.ip, node_c.port, node_c.public_key
    );

    // Read the UEP policy YAML file
    let yaml_content =
        fs::read_to_string("schemas/uep_policy_v1.yaml").expect("Cannot read policy file");

    // Validate and parse the YAML policy
    match policy::validate_policy(&yaml_content) {
        Ok(parsed) => {
            println!(
                "Policy Loaded: ID = {}, Version = {}",
                parsed.policy_id, parsed.version
            );
            for rule in parsed.rules {
                println!(
                    " - Rule {}: {} {} -> {} (protocol: {}{})",
                    rule.id,
                    rule.action,
                    rule.src,
                    rule.dst,
                    rule.protocol,
                    rule.port
                        .map(|p| format!(", port: {}", p))
                        .unwrap_or_else(|| "".to_string())
                );
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to parse policy: {}", e);
        }
    }
    println!("\n Starting inter-node mock communication...");
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run -- <node_id>");
        std::process::exit(1);
    }
    let node_id = args[1].clone();

    // Initialize structured JSON logger
    init_logger(&node_id);
    log_event(&node_id, "Logger initialized for node");
    log_event(&node_id, "Node configuration loading complete");

    let metrics = Arc::new(Mutex::new(Metrics::default()));
    {
        let mut m = metrics.lock().await;
        m.record_connection();
    }
    // === SGX Sprint 2: Integrate Discovery + Attestation Services ===
    println!("🛰️ Initializing P2P Discovery and Attestation Services...");

    // Create async channel between discovery ↔ attestation
    let (disc_tx, disc_rx) = mpsc::channel(64);

    // Prepare shared auditor context (used by discovery + logs)
    let node_id_clone = node_id.clone();
    let auditor_arc = Arc::new(Mutex::new(node_id_clone.clone()));

    // Spawn Discovery service
    tokio::spawn({
        let tx = disc_tx.clone();
        let node_id_clone = node_id.clone();
        let auditor_arc_clone = auditor_arc.clone();
        async move {
            if let Err(e) = p2p_discovery::P2PDiscovery::run(
                tx,
                node_id_clone.clone(),
                auditor_arc_clone.clone(),
            )
            .await
            {
                eprintln!("Discovery service error: {:?}", e);
                log_error(&node_id_clone, &format!("Discovery service error: {:?}", e));
            }
        }
    });

    // Spawn Attestation service
    tokio::spawn({
        let node_id_clone = node_id.clone();
        async move {
            if let Err(e) = attestation_service::run(disc_rx).await {
                eprintln!("Attestation service error: {:?}", e);
                log_error(
                    &node_id_clone,
                    &format!("Attestation service error: {:?}", e),
                );
            }
        }
    });

    println!("✅ P2P Discovery and Attestation background services started.");

    let (this_node, peers) = match node_id.as_str() {
        "nodeA" => (node_a.clone(), vec![node_b, node_c]),
        "nodeB" => (node_b.clone(), vec![node_a, node_c]),
        "nodeC" => (node_c.clone(), vec![node_a, node_b]),
        _ => {
            eprintln!("❌ Unknown node ID: {}", node_id);
            log_error(&node_id, "Unknown node ID provided");
            std::process::exit(1);
        }
    };
    let this_addr = format!("{}:{}", this_node.ip, this_node.port);
    log_event(&node_id, &format!("Starting server at {}", this_addr));
    let server_task = task::spawn(async move {
        start_server(this_addr.clone()).await.unwrap();
    });

    // Wait for servers to initialize
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Only nodeA sends pings to others
    if node_id == "nodeA" {
        for peer in peers {
            let target = format!("{}:{}", peer.ip, peer.port);
            log_event(&node_id, &format!("Sending ping to {}", target));
            if let Err(e) = send_ping(target, node_id.clone()).await {
                log_error(&node_id, &format!("Ping failed: {}", e));
                let mut m = metrics.lock().await;
                m.record_error();
            }
        }
    }

    // background uptime tracker
    let node_id_clone = node_id.clone();
    let metrics_clone = metrics.clone();
    tokio::spawn(async move {
        loop {
            {
                let m = metrics_clone.lock().await;
                let uptime = m.uptime().as_secs();
                log_event(&node_id_clone, &format!("Uptime: {} seconds", uptime));
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
    use tokio::select;
    select! {
        _ = signal::ctrl_c() => {
            println!("\n Ctrl+C detected — shutting down gracefully...");
            log_event(&node_id, "Ctrl+C detected — graceful shutdown initiated");
        },
        res = server_task => {
            if let Err(e) = res {
                log_error(&node_id, &format!("Server task error: {:?}", e));
            }
        }
    }
    println!("🛑 Node {} shutting down gracefully.", node_id);
    log_event(&node_id, "Node shutting down gracefully");
    if cfg!(windows) {
        std::process::exit(0);
    } else {
        Ok(())
    }
}
