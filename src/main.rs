//! SG-X Guardian Client entrypoint.
//! Initializes node identity, loads configuration, starts discovery,
//! attestation, metrics tracking, and the gRPC server runtime.
mod audit;
mod config_loader;
mod nebula;
mod policy;
pub mod proto {
    pub mod sgx {
        include!(concat!(env!("OUT_DIR"), "/sgx.rs"));
    }
}
mod attestation_service;
mod client;
mod cloud;
mod key_manager;
mod logging;
mod metrics;
mod metrics_server;
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
/// Entry point for the SG-X Guardian Client.
/// Initializes identity keys, loads node configurations, starts P2P discovery,
/// attestation services, metrics tracking, structured logging, and the gRPC server.
/// This function orchestrates the full runtime lifecycle for each SG-X node.
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
    println!("\n Loading node configurations...");
    let node_a = load_config("/etc/sgx-guardian/nodeA.yaml").expect("Failed to load nodeA config");

    let node_b = load_config("/etc/sgx-guardian/nodeB.yaml").expect("Failed to load nodeB config");

    let node_c = load_config("/etc/sgx-guardian/nodeC.yaml").expect("Failed to load nodeC config");

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
    use nebula::models::CircleMembership;
    use nebula::daemon::NebulaDaemon;

    let nebula_base_dir = std::env::var("SGX_NEBULA_DIR")
    .unwrap_or("/var/lib/sgx-guardian/nebula".to_string());

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

    if let Err(e) = NebulaCA::issue_node_cert(&nebula_base_dir, &membership, nebula_ip) {
        eprintln!("❌ Failed to issue node certificate: {:?}", e);
        std::process::exit(1);
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

    // === Nebula Health Check ===
    use nebula::health::NebulaHealth;

    println!("🩺 Performing Nebula health check...");

    let health_report = NebulaHealth::check(&nebula_base_dir, &node_id);

    println!("--- Nebula Health Report ---");
    println!("{}", health_report.summary());
    println!("-----------------------------");

    // === Integrate Discovery + Attestation Services ===
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

    let this_addr = format!("{}:{}", this_node.ip, this_node.port);
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
    // SAN = hostname and IP of node
    let san = [this_node.hostname.as_str(), "127.0.0.1"];
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
    // Wait for servers to initialize
    tokio::time::sleep(Duration::from_secs(20)).await;

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