//! SG-X Guardian Client entrypoint.
//! Initializes node identity, loads configuration, starts discovery,
//! attestation, metrics tracking, and the gRPC server runtime.
mod audit;
mod config_loader;
mod dynamic_config;
mod nebula;
mod policy;
pub mod proto {
    pub mod sgx {
        include!(concat!(env!("OUT_DIR"), "/sgx.rs"));
    }
}
mod attestation_service;
mod cert_client;
mod cert_service;
mod client;
mod cloud;
mod key_manager;
mod logging;
mod metrics;
mod metrics_server;
mod node_announcement;
mod node_broadcast;
mod node_listener;
mod p2p_discovery;
mod server;
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::{init_audit_logger, log_audit};
use crate::audit::verifier::AuditVerifier;
use crate::config_loader::CloudConfig;
use base64::{engine::general_purpose, Engine as _};
use client::send_ping;
use config_loader::load_config;
use key_manager::KeyManager;
#[allow(unused_imports)]
use logging::{init_logger, log_error, log_event};
use metrics::Metrics;
use nebula::install::NebulaInstall;

use server::start_server;
use std::env;
use std::fs;
use std::path::PathBuf;
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

async fn wait_for_valid_node_ip(node_id: &str, path: &str) -> String {
    loop {
        let cfg = crate::config_loader::load_config(path).expect("Failed to reload config");

        if cfg.ip != "0.0.0.0" && cfg.ip != "127.0.0.1" {
            println!("✅ {} discovered at {}", node_id, cfg.ip);
            return cfg.ip;
        }

        println!("⏳ Waiting for {} discovery...", node_id);
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}
/// Entry point for the SG-X Guardian Client.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!(" SGX Guardian Client Starting...");

    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: cargo run -- <node_id>");
        std::process::exit(1);
    }

    let node_id = args[1].clone();

    // Start node announcement listener
    let node_id_clone = node_id.clone();

    tokio::spawn(async move {
        node_listener::start_listener(node_id_clone).await;
    });
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
    // Parse command-line arguments for node ID
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run -- <node_id>");
        std::process::exit(1);
    }
    let node_id = args[1].clone();
    // Generate node-specific identity key path
    let node_key_path = format!("/var/lib/sgx-guardian/sgx-agent/device_{}.key", node_id);
    // Initialize or load persistent identity keypair
    let km = KeyManager::load_or_generate(&node_key_path)?;

    let pubkey_b64 = general_purpose::STANDARD.encode(km.pubkey_der());
    println!(
        "Node Identity Initialized | Public Key Prefix: {}...",
        &pubkey_b64[..20]
    );

    // Generate and log attestation evidence for this node
    use crate::attestation_service::AttestationService;

    let sample_policy_path = "/etc/sgx-guardian/schemas/uep_policy_v1.yaml";

    let sample_policy = fs::read_to_string(sample_policy_path).expect(
        "Failed to read policy file for attestation test (check /etc/sgx-guardian/schemas)",
    );

    let evidence = AttestationService::create_signed_evidence(&km, &sample_policy)?;
    println!(
        "Created local attestation evidence (nonce={}..)",
        &evidence.nonce[..8]
    );
    let verified = AttestationService::verify_signed_evidence(&evidence, &sample_policy)?;
    if verified {
        println!("✅ Local attestation evidence verified successfully.");
        log_audit(
            &node_id,
            AuditCategory::Attestation,
            AuditSeverity::Info,
            AuditAction::Succeeded,
            "Local attestation evidence verified",
        );
    } else {
        eprintln!("❌ Local attestation verification failed!");
        log_audit(
            &node_id,
            AuditCategory::Attestation,
            AuditSeverity::Critical,
            AuditAction::Failed,
            "Local attestation evidence verification failed",
        );
    }
    // === DYNAMIC IP DETECTION + CONFIG AUTO-UPDATE ===
    println!("\n🔍 Detecting local LAN IP address...");

    let detected_ip = match dynamic_config::detect_local_lan_ip() {
        Ok(ip) => {
            println!("🌐 Detected LAN IP: {}", ip);
            log_event(&node_id, &format!("Detected LAN IP: {}", ip));
            ip.to_string()
        }
        Err(e) => {
            eprintln!("❌ IP detection failed: {:?}", e);
            log_error(&node_id, &format!("IP detection failed: {:?}", e));
            String::new()
        }
    };
    // ✅ NEW — sanitize + update only own config
    println!("\n🔧 Sanitizing configs before load...");

    // Step 1: fix invalid IPs in all configs
    for yaml_file in &[
        "/etc/sgx-guardian/config/nodeA.yaml",
        "/etc/sgx-guardian/config/nodeB.yaml",
        "/etc/sgx-guardian/config/nodeC.yaml",
    ] {
        if let Err(e) = dynamic_config::sanitize_config_ip_if_invalid(yaml_file) {
            eprintln!("⚠️ Sanitize failed for {}: {:?}", yaml_file, e);
        }
    }

    // Step 2: update ONLY current node config
    if !detected_ip.is_empty() {
        let my_config_path = format!("/etc/sgx-guardian/config/{}.yaml", node_id);

        let _ = dynamic_config::update_config_ip_if_changed(&my_config_path, &detected_ip);
    }
    // === Load configs AFTER update ===
    println!("\n📦 Loading node configurations...");

    let node_a =
        load_config("/etc/sgx-guardian/config/nodeA.yaml").expect("Failed to load nodeA config");
    let node_b =
        load_config("/etc/sgx-guardian/config/nodeB.yaml").expect("Failed to load nodeB config");
    let node_c =
        load_config("/etc/sgx-guardian/config/nodeC.yaml").expect("Failed to load nodeC config");

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
    let _yaml_content = fs::read_to_string("/etc/sgx-guardian/schemas/uep_policy_v1.yaml")
        .expect("Cannot read policy file (/etc/sgx-guardian/schemas)");
    // Validate and parse the YAML policy
    fn print_policy_from_yaml(yaml: &str, label: &str) {
        match policy::validate_policy(yaml) {
            Ok(parsed) => {
                println!(
                    "Policy Loaded ({}): ID = {}, Version = {}",
                    label, parsed.policy_id, parsed.version
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
                eprintln!("❌ Failed to parse {} policy: {}", label, e);
            }
        }
    }
    println!("\n Starting inter-node mock communication...");

    // Initialize structured JSON logger
    init_logger(&node_id);
    log_event(&node_id, "Logger initialized for node");
    log_event(&node_id, "Node configuration loading complete");
    // === VERIFY EXISTING AUDIT LOG (tamper detection) ===
    let prod_log_dir = "/var/log/sgx-guardian";
    let dev_log_dir = "logs";

    std::fs::create_dir_all(prod_log_dir).ok();
    std::fs::create_dir_all(dev_log_dir).ok();

    let audit_log_path_prod = format!("{}/audit.log", prod_log_dir);
    let audit_log_path_dev = "logs/audit.log";
    let audit_check_path = if std::path::Path::new(&audit_log_path_prod).exists() {
        &audit_log_path_prod
    } else {
        audit_log_path_dev
    };

    if std::path::Path::new(audit_check_path).exists() {
        if let Err(e) = AuditVerifier::verify(audit_check_path) {
            log_error(
                &node_id,
                &format!("Audit log integrity warning (non-fatal): {}", e),
            );
        }
    }

    // === Initialize Audit Logger (tamper-evident) ===
    let audit_path_prod = PathBuf::from(format!("{}/audit-{}.log", prod_log_dir, node_id));

    // Initialize PROD logger first
    init_audit_logger(audit_path_prod);
    log_audit(
        &node_id,
        AuditCategory::Node,
        AuditSeverity::Info,
        AuditAction::Started,
        "Node started successfully",
    );
    log_audit(
        &node_id,
        AuditCategory::Identity,
        AuditSeverity::Info,
        AuditAction::Succeeded,
        "Node identity key loaded or generated",
    );

    // === OPTIONAL: Run local mock cloud server (DEV ONLY) ===
    if std::env::var("SGX_RUN_MOCK_CLOUD")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
    {
        tokio::spawn(async {
            cloud::mock_server::run_mock_cloud(([127, 0, 0, 1], 9443)).await;
        });

        log_audit(
            &node_id,
            AuditCategory::Cloud,
            AuditSeverity::Info,
            AuditAction::Started,
            "Local mock cloud server started (DEV mode)",
        );
    }

    let metrics = Arc::new(Mutex::new(Metrics::default()));

    // === Cloud uplink (outbound-only mock) ===
    let cloud_cfg = CloudConfig::from_env();

    if cloud_cfg.enabled {
        let node_id_clone = node_id.clone();
        let endpoint = cloud_cfg.endpoint.clone();

        log_audit(
            &node_id,
            AuditCategory::Cloud,
            AuditSeverity::Info,
            AuditAction::Started,
            "Cloud uplink enabled (mock)",
        );

        tokio::spawn(async move {
            if let Err(e) = cloud::client::send_heartbeat(&node_id_clone, &endpoint).await {
                log_error(
                    &node_id_clone,
                    &format!("Cloud uplink heartbeat failed: {}", e),
                );
            }
        });
    }

    {
        let mut m = metrics.lock().await;
        m.record_connection();
    }

    // === Nebula Installation Verification (Deliverable 1) ===
    println!("\n🔎 Verifying Nebula Installation...");

    // === Generate CA + Node Certificates for Nebula (if not exist) ===
    use nebula::ca::NebulaCA;
    use nebula::daemon::NebulaDaemon;
    use nebula::models::CircleMembership;

    let nebula_base_dir =
        std::env::var("SGX_NEBULA_DIR").unwrap_or("/var/lib/sgx-guardian/nebula".to_string());

    match NebulaInstall::check_binary() {
        Ok(_) => println!("✅ Nebula binary found"),
        Err(e) => {
            eprintln!("❌ Nebula binary missing: {}", e);
            log_error(&node_id, &format!("Nebula binary missing: {}", e));
            std::process::exit(1);
        }
    }

    match NebulaInstall::check_version() {
        Ok(v) => println!("✅ Nebula version: {}", v.trim()),
        Err(e) => {
            eprintln!("❌ Nebula version check failed: {}", e);
            log_error(&node_id, &format!("Nebula version check failed: {}", e));
            std::process::exit(1);
        }
    }

    match NebulaInstall::test_daemon_start() {
        Ok(_) => println!("✅ Nebula daemon responding"),
        Err(e) => {
            eprintln!("❌ Nebula daemon test failed: {}", e);
            log_error(&node_id, &format!("Nebula daemon test failed: {}", e));
            std::process::exit(1);
        }
    }

    // Generate CA if not exists
    if let Err(e) = NebulaCA::generate_ca(&nebula_base_dir) {
        eprintln!("❌ Failed to generate CA: {:?}", e);
        std::process::exit(1);
    }

    log_audit(
        &node_id,
        AuditCategory::Network,
        AuditSeverity::Info,
        AuditAction::Created,
        "Nebula CA verified or generated",
    );

    // Issue cert for this node
    let nebula_ip = match node_id.as_str() {
        "nodeA" => "192.168.100.1/24",
        "nodeB" => "192.168.100.2/24",
        "nodeC" => "192.168.100.3/24",
        _ => {
            eprintln!("❌ Unknown node ID for Nebula IP mapping");
            std::process::exit(1);
        }
    };

    let membership = CircleMembership {
        node_name: node_id.clone(),
        circle_id: "guardian-circle-alpha".to_string(),
        vc_hash: "mock-vc-proof-123".to_string(),
        is_valid: true,
    };

    if node_id == "nodeA" {
        // CA node: auto-issue its own certificate (self-bootstrap)
        if let Err(e) = NebulaCA::issue_node_cert(&nebula_base_dir, &membership, nebula_ip) {
            eprintln!("❌ Failed to issue CA node certificate: {:?}", e);
            std::process::exit(1);
        }
        log_audit(
            &node_id,
            AuditCategory::Network,
            AuditSeverity::Info,
            AuditAction::Created,
            "Nebula CA certificate verified or issued for nodeA",
        );
    } else {
        // Member node: check if cert already exists
        let member_cert_path = format!("{}/nodes/{}.crt", nebula_base_dir, node_id);
        let member_key_path = format!("{}/nodes/{}.key", nebula_base_dir, node_id);

        if std::path::Path::new(&member_cert_path).exists()
            && std::path::Path::new(&member_key_path).exists()
        {
            println!("✅ Nebula certificate already exists for {}", node_id);
            log_audit(
                &node_id,
                AuditCategory::Network,
                AuditSeverity::Info,
                AuditAction::Succeeded,
                &format!("Existing Nebula certificate found for {}", node_id),
            );
        } else {
            println!(
                "🔐 No Nebula certificate for {} — requesting from CA immediately",
                node_id
            );

            let cert_node_id = node_id.clone();
            let cert_overlay_ip = nebula_ip.to_string();
            let cert_pubkey = pubkey_b64.clone();
            let node_a_ip =
                wait_for_valid_node_ip("nodeA", "/etc/sgx-guardian/config/nodeA.yaml").await;

            let ca_address = format!("{}:50061", node_a_ip);

            println!("🚀 Sending cert request to CA at {}", ca_address);

            cert_client::request_certificate_from_ca(
                cert_node_id,
                ca_address,
                cert_overlay_ip,
                cert_pubkey,
            )
            .await;

            println!("✅ Certificate bootstrap completed for {}", node_id);
        }
    }
    //configuration directory for nebula
    use nebula::config::NebulaConfig;
    let config_directory = nebula_base_dir.clone();
    let is_lighthouse = node_id == "nodeA";

    if let Err(e) =
        NebulaConfig::generate_config(&node_id, nebula_ip, is_lighthouse, &config_directory)
    {
        eprintln!("❌ Failed to generate Nebula config: {:?}", e);
        std::process::exit(1);
    }

    println!("🚀 Nebula Installation Verified Successfully\n");

    // === Start Nebula ===
    let nebula_config_path = format!("{}/nebula.yaml", nebula_base_dir);
    if let Err(e) = NebulaDaemon::start(&nebula_config_path) {
        eprintln!("❌ Failed to start Nebula daemon: {:?}", e);
        std::process::exit(1);
    }
    println!("🌐 Nebula mesh daemon started successfully.");

    log_audit(
        &node_id,
        AuditCategory::Network,
        AuditSeverity::Info,
        AuditAction::Started,
        "Nebula mesh daemon started successfully",
    );

    // === Nebula Health Check ===
    use nebula::health::NebulaHealth;

    println!("🩺 Performing Nebula health check...");

    let health_report = NebulaHealth::check(&nebula_base_dir, &node_id);

    println!("--- Nebula Health Report ---");
    println!("{}", health_report.summary());
    println!("-----------------------------");

    // === Start Expiry Monitor ===
    use nebula::cert_lifecycle::ExpiryMonitor;
    ExpiryMonitor::start(nebula_base_dir.clone(), node_id.clone());

    // === CoT Deliverable Integration Start ===
    println!("🔗 Initializing Circle of Trust (CoT) transport-agnostic layer...");

    use sgx_guardian_client::cot::identity::DeviceIdentity;
    use sgx_guardian_client::cot::interface_detector::InterfaceDetector;
    use sgx_guardian_client::cot::membership::CircleMembership as CotCircleMembership;
    use sgx_guardian_client::cot::router::CotRouter;
    use sgx_guardian_client::cot::session_manager::SessionManager;
    use sgx_guardian_client::cot::transport_registry::TransportRegistry;
    use sgx_guardian_client::cot::transports;
    use sgx_guardian_client::cot::trust_engine::TrustEngine;

    // Step 1: Create device identity from existing KeyManager public key
    let cot_identity = DeviceIdentity::from_public_key_with_name(&km.pubkey_der(), &node_id)
        .expect("Failed to create CoT device identity");
    println!(
        "🔑 CoT Identity: {} ({})",
        cot_identity,
        cot_identity.device_id()
    );

    log_audit(
        &node_id,
        AuditCategory::Identity,
        AuditSeverity::Info,
        AuditAction::Succeeded,
        &format!("CoT identity established: {}", cot_identity.short_id()),
    );

    // Step 2: Detect available network interfaces
    let detected_interfaces = InterfaceDetector::detect_all().unwrap_or_else(|e| {
        eprintln!("⚠️ Interface detection failed: {}", e);
        Vec::new()
    });

    println!(
        "📡 Detected {} network interfaces:",
        detected_interfaces.len()
    );
    for iface in &detected_interfaces {
        println!(
            "   {} → {} [{}] {:?}",
            iface.name,
            iface.transport_type,
            iface.status,
            iface
                .ip_addr
                .map(|ip| ip.to_string())
                .unwrap_or("no-ip".into())
        );
    }

    // Step 3: Create and populate transport registry
    let cot_registry = std::sync::Arc::new(TransportRegistry::new());
    {
        let usable = transports::auto_create_transports().unwrap_or_else(|_| Vec::new());
        for transport in usable {
            cot_registry.register(transport).await;
        }
    }
    println!("🚛 Transport Registry: {}", cot_registry.summary().await);

    // Step 4: Create session manager
    let cot_sessions = std::sync::Arc::new(SessionManager::new());

    // Step 5: Create circle membership
    let cot_circle = std::sync::Arc::new(CotCircleMembership::new(
        "guardian-circle-alpha".into(),
        cot_identity.device_id().to_string(),
        km.pubkey_der().to_vec(),
    ));

    // Step 6: Create trust engine
    let cot_trust = std::sync::Arc::new(TrustEngine::new(cot_identity.clone(), cot_circle.clone()));

    // Step 7: Create router
    let cot_router = std::sync::Arc::new(CotRouter::new(
        cot_identity.clone(),
        cot_registry.clone(),
        cot_sessions.clone(),
        cot_circle.clone(),
        cot_trust.clone(),
    ));
    println!("✅ CoT layer initialized successfully.");
    println!("{}", cot_router.status_summary().await);

    log_audit(
        &node_id,
        AuditCategory::Network,
        AuditSeverity::Info,
        AuditAction::Succeeded,
        "CoT transport-agnostic layer initialized",
    );

    // Step 8: Periodic interface refresh (every 30s)
    {
        let reg = cot_registry.clone();
        let nid = node_id.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                if let Ok(new) = transports::auto_create_transports() {
                    for t in new {
                        reg.register(t).await;
                    }
                }
                let health = reg.health_check_all().await;
                for (tt, h) in &health {
                    if !h.is_healthy {
                        log_error(&nid, &format!("CoT {} unhealthy: {}", tt, h.status_message));
                    }
                }
            }
        });
    }

    // Step 9: Periodic session cleanup (every 60s)
    {
        let sess = cot_sessions.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                let cleaned = sess.cleanup_expired().await;
                if cleaned > 0 {
                    println!("🧹 Cleaned {} expired CoT sessions", cleaned);
                }
            }
        });
    }

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

    use crate::node_announcement::NodeAnnouncement;

    let announcement = NodeAnnouncement {
        node_id: this_node.node_id.clone(),
        hostname: this_node.hostname.clone(),
        ip: detected_ip.clone(),
        port: this_node.port,
        public_key: this_node.public_key.clone(),
    };
    node_broadcast::broadcast_node(&announcement);
    dynamic_config::start_ip_monitor(
        node_id.clone(),
        format!("/etc/sgx-guardian/config/{}.yaml", node_id),
        vec![],
        dynamic_config::NodeConfigBroadcast {
            node_id: this_node.node_id.clone(),
            hostname: this_node.hostname.clone(),
            ip: detected_ip.clone(),
            port: this_node.port,
            public_key: this_node.public_key.clone(),
        },
    )
    .await;

    println!("✅ Config auto-update system active\n");
    // === END DYNAMIC CONFIG SYNC ===

    println!("🛰️ Initializing P2P Discovery and Attestation Services...");

    let (disc_tx, disc_rx) = mpsc::channel(64);

    let node_id_clone = node_id.clone();
    let auditor_arc = Arc::new(Mutex::new(node_id_clone.clone()));

    tokio::spawn({
        let tx = disc_tx.clone();
        let node_id_clone = node_id.clone();
        let auditor_arc_clone = auditor_arc.clone();
        async move {
            if let Err(e) =
                p2p_discovery::P2PDiscovery::run(tx, node_id_clone.clone(), auditor_arc_clone).await
            {
                eprintln!("Discovery service error: {:?}", e);
            }
        }
    });

    tokio::spawn({
        // let node_id_clone = node_id.clone();
        async move {
            if let Err(e) = attestation_service::run(disc_rx).await {
                eprintln!("Attestation service error: {:?}", e);
            }
        }
    });

    println!("✅ P2P Discovery and Attestation background services started.");
    // Periodic node broadcast (every 30 seconds)
    let node_id_bc = node_id.clone();
    let hostname_bc = this_node.hostname.clone();
    let pubkey_bc = pubkey_b64.clone();
    let port_bc = this_node.port;

    tokio::spawn(async move {
        loop {
            // Fresh IP har baar detect karo
            let current_ip = match dynamic_config::detect_local_lan_ip() {
                Ok(ip) => ip.to_string(),
                Err(_) => {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    continue;
                }
            };

            let announcement = NodeAnnouncement {
                node_id: node_id_bc.clone(),
                hostname: hostname_bc.clone(),
                ip: current_ip,
                port: port_bc,
                public_key: pubkey_bc.clone(),
            };

            node_broadcast::broadcast_node(&announcement);
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
    // === Metrics server enable/disable (node-specific, YAML-driven)
    if let Some(metrics_cfg) = &this_node.metrics {
        if metrics_cfg.enabled {
            let metrics_clone = metrics.clone();

            let bind_ip: [u8; 4] = metrics_cfg
                .bind
                .parse::<std::net::Ipv4Addr>()
                .expect("Invalid metrics.bind IP")
                .octets();

            let port = metrics_cfg.port;

            tokio::spawn(async move {
                metrics_server::start_metrics_server(metrics_clone, (bind_ip, port)).await;
            });
        }
    }

    log_audit(
        &node_id,
        AuditCategory::Node,
        AuditSeverity::Info,
        AuditAction::Applied,
        match this_node.metrics.as_ref() {
            Some(cfg) if cfg.enabled => "Metrics server enabled (YAML)",
            _ => "Metrics server disabled (YAML)",
        },
    );
    // Always bind to all interfaces (avoid stale IP issues)
    let this_addr = format!("0.0.0.0:{}", this_node.port);
    log_event(&node_id, &format!("Starting server at {}", this_addr));
    use sgx_guardian_client::policy::load_policy_runtime;
    use sgx_guardian_client::policy_manager::load_and_activate_policy;

    let signed_policy_path = "/etc/sgx-guardian/policies/policy.sig";

    if std::path::Path::new(signed_policy_path).exists() {
        match load_and_activate_policy(signed_policy_path) {
            Ok(verified) => {
                println!("📜 Verified policy loaded (digest={})", verified.digest_hex);
                print_policy_from_yaml(&verified.policy_yaml, "NEW");
                if let Err(e) = load_policy_runtime(&verified.policy_yaml) {
                    eprintln!("❌ Policy runtime load failed: {}", e);
                    log_error(&node_id, &format!("Policy runtime load failed: {}", e));
                    std::process::exit(1);
                }

                println!("✅ Policy is now ACTIVE at runtime");
                log_event(&node_id, "Runtime policy activated successfully");
                log_audit(
                    &node_id,
                    AuditCategory::Policy,
                    AuditSeverity::Info,
                    AuditAction::Applied,
                    "Signed policy verified and activated",
                );
                {
                    let mut m = metrics.lock().await;
                    m.set_policy_active(true);
                }
            }
            Err(e) => {
                eprintln!(
                    "❌ Signed policy rejected: {} — continuing with last active policy",
                    e
                );
                log_error(
                    &node_id,
                    &format!(
                        "Signed policy rejected, continuing with last active policy: {}",
                        e
                    ),
                );
                log_audit(
                    &node_id,
                    AuditCategory::Policy,
                    AuditSeverity::Critical,
                    AuditAction::Rejected,
                    "Signed policy rejected during verification",
                );
                {
                    let mut m = metrics.lock().await;
                    m.set_policy_active(false);
                    m.record_error();
                }
                // 🔁 PRINT BACKUP / LAST-ACTIVE POLICY
                if let Ok(backup_yaml) =
                    fs::read_to_string("/etc/sgx-guardian/policies/backup_policy.yaml")
                {
                    print_policy_from_yaml(&backup_yaml, "BACKUP / LAST-ACTIVE");
                } else {
                    eprintln!("⚠️ No backup_policy.yaml found to display");
                }
                // IMPORTANT: do NOT exit — continue runtime
            }
        }
    } else {
        println!("⚠️ No signed policy found — running with last active policy");
        log_event(&node_id, "No signed policy found at startup");
    }
    // TLS Certificate Setup
    use sgx_guardian_client::tls;
    let key_path = format!("/var/lib/sgx-guardian/sgx-agent/device_{}.key", node_id);
    let cert_path = format!(
        "/var/lib/sgx-guardian/sgx-agent/device_{}_cert.der",
        node_id
    );
    // Use real detected IP in certificate
    let san = [this_node.hostname.as_str(), detected_ip.as_str()];
    // Ensure certificate exists
    match tls::ensure_node_certificate_or_generate(&key_path, &cert_path, &san) {
        Ok(_) => {
            println!("🔐 TLS certificate ready at {}", cert_path);
            log_event(
                &node_id,
                &format!("TLS certificate loaded/generated at {}", cert_path),
            );
        }
        Err(err) => {
            eprintln!("❌ Failed to prepare TLS certificate: {:?}", err);
            log_error(&node_id, &format!("TLS certificate error: {:?}", err));
            std::process::exit(1);
        }
    }
    // === DER → PEM conversion (required by tonic TLS) ===
    use sgx_guardian_client::tls::der_to_pem;
    use tonic::transport::{Certificate as TonicCertificate, Identity};
    // load DER cert
    let cert_der = std::fs::read(cert_path).expect("read cert der");
    let cert_pem = der_to_pem(&cert_der);
    // load DER private key and wrap as PEM (pem 3.x compatible)
    let key_der = std::fs::read(key_path).expect("read key der");
    let key_pem = {
        let pem = pem::Pem::new("PRIVATE KEY", key_der);
        pem::encode(&pem)
    };
    // Build tonic Identity + CA root
    let identity = Identity::from_pem(cert_pem.clone(), key_pem.clone());
    let ca_cert = TonicCertificate::from_pem(cert_pem.clone());
    // spawn gRPC server using tonic Identity + CA (mTLS)
    let server_task = task::spawn({
        let identity = identity.clone();
        let ca_cert = ca_cert.clone();
        let this_addr = this_addr.clone();
        async move {
            if let Err(e) = start_server(this_addr.clone(), identity, ca_cert).await {
                eprintln!("Server failed at {}: {:?}", this_addr, e);
            }
        }
    });
    // === CERT BOOTSTRAP SERVER (nodeA only, plaintext port 50061) ===
    if node_id == "nodeA" {
        tokio::spawn(async move {
            if let Err(e) = server::start_cert_bootstrap_server("0.0.0.0:50061".to_string()).await {
                eprintln!("Cert bootstrap server failed: {:?}", e);
            }
        });
    }
    // === APPLY POLICY ENFORCEMENT AFTER NODE IS STEADY ===
    use sgx_guardian_client::enforcement;
    use sgx_guardian_client::policy::get_active_policy;

    if let Some(active_policy) = get_active_policy() {
        println!("🛡️ Applying policy enforcement (nftables)");

        log_audit(
            &node_id,
            AuditCategory::Enforcement,
            AuditSeverity::Info,
            AuditAction::Started,
            "Policy enforcement started",
        );

        match enforcement::enforce_policy(&active_policy) {
            Ok(_) => {
                println!("✅ Policy enforcement applied successfully");

                log_audit(
                    &node_id,
                    AuditCategory::Enforcement,
                    AuditSeverity::Info,
                    AuditAction::Applied,
                    "Policy enforcement applied successfully",
                );
            }
            Err(e) => {
                eprintln!("❌ Policy enforcement failed: {:?}", e);

                log_audit(
                    &node_id,
                    AuditCategory::Enforcement,
                    AuditSeverity::Critical,
                    AuditAction::Failed,
                    "Policy enforcement failed",
                );

                let mut m = metrics.lock().await;
                m.record_enforcement_failure();
            }
        }
    }
    // === END POLICY ENFORCEMENT ===

    // Only nodeA sends pings to others
    if node_id == "nodeA" {
        for peer in peers {
            let target = format!("{}:{}", peer.ip, peer.port);
            log_event(&node_id, &format!("Sending ping to {}", target));
            if let Err(e) =
                send_ping(target, node_id.clone(), identity.clone(), ca_cert.clone()).await
            {
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
            println!("\n shutting down gracefully...");
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
    log_audit(
        &node_id,
        AuditCategory::Node,
        AuditSeverity::Info,
        AuditAction::Succeeded,
        "Node shutting down gracefully",
    );
    if cfg!(windows) {
        std::process::exit(0);
    } else {
        Ok(())
    }
}
