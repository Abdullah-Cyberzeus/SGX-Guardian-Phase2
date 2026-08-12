//! SG-X Guardian Client entrypoint.
//! Initializes node identity, loads configuration, starts discovery,
//! attestation, metrics tracking, and the gRPC server runtime.

use sgx_guardian_client::attestation_service;
use sgx_guardian_client::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use sgx_guardian_client::audit::logger::{init_audit_logger, log_audit};
use sgx_guardian_client::audit::verifier::AuditVerifier;
use sgx_guardian_client::client::send_ping;
use sgx_guardian_client::config_loader::{load_config, CloudConfig, NodeConfig, RelayLimitsConfig};
use sgx_guardian_client::key_manager::KeyManager;
#[cfg(feature = "secure-element")]
use sgx_guardian_client::secure_element;
use std::path::Path;

#[allow(unused_imports)]
use sgx_guardian_client::logging::{init_logger, log_error, log_event};
use sgx_guardian_client::metrics::Metrics;
use sgx_guardian_client::nebula::install::NebulaInstall;
use sgx_guardian_client::p2p_discovery::P2PDiscovery;
use sgx_guardian_client::policy;
use sgx_guardian_client::server;
use sgx_guardian_client::server::start_server;
// WiFi + Ethernet discovery imports
use sgx_guardian_client::dynamic_config;
use sgx_guardian_client::node_announcement::NodeAnnouncement;
use sgx_guardian_client::node_broadcast;
use sgx_guardian_client::node_listener;
use sgx_guardian_client::runtime_gates::{cooldown, step, GATES};

use base64::{engine::general_purpose, Engine as _};
use sha2::Digest;
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

const RELAY_SYNC_INTERVAL_SECS: u64 = 10;
const DID_DOC_REFRESH_INTERVAL_SECS: u64 = 300;
const DID_DOC_PULL_INTERVAL_SECS: u64 = 30;
const VC_STATUS_LIST_PULL_INTERVAL_SECS: u64 = 300;
const DID_DOC_ROTATION_FLAG: &str = "/var/lib/sgx-guardian/identity/.dkp_rotated.flag";
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
    let node_id = match std::env::args().nth(1) {
        Some(id) if !id.is_empty() && !id.starts_with('-') => id,
        _ => {
            eprintln!("❌ Usage: sgx-guardian <node_id>");
            eprintln!("   node_id is REQUIRED. Defaulting to nodeA is unsafe.");
            eprintln!("   An unconfigured node silently becoming CA would break trust.");
            std::process::exit(1);
        }
    };

    // === FIRST: Ensure all required directories exist ===
    for dir in &[
        "/etc/sgx-guardian/config",
        "/etc/sgx-guardian/schemas",
        "/etc/sgx-guardian/policies",
        "/var/lib/sgx-guardian/keys",
        "/var/lib/sgx-guardian/pcr",
        "/var/lib/sgx-guardian/boot",
        "/var/lib/sgx-guardian/sgx-agent",
        "/var/lib/sgx-guardian/identity",
        "/var/lib/sgx-guardian/identity/peers",
        "/var/lib/sgx-guardian/nebula/ca",
        "/var/lib/sgx-guardian/nebula/nodes",
        "/var/lib/sgx-guardian/nebula/requests",
        "/var/lib/sgx-guardian/threat",
        "/etc/sgx-guardian/threat",
        "/var/log/sgx-guardian",
    ] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!(
                "⚠️ Failed to create {}: {} (may cause issues later)",
                dir, e
            );
        }
    }

    if node_id == "nodeA" {
        let requests_dir = "/var/lib/sgx-guardian/nebula/requests";
        if let Ok(entries) = std::fs::read_dir(requests_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if !name.ends_with(".yaml") {
                    continue;
                }

                let compatible = std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|content| serde_yaml::from_str::<serde_yaml::Value>(&content).ok())
                    .and_then(|v| v.as_mapping().cloned())
                    .map(|m| {
                        let required = [
                            "node_id",
                            "requested_at",
                            "overlay_ip",
                            "public_key_fingerprint",
                            "approve",
                        ];
                        let has_required = required
                            .iter()
                            .all(|k| m.contains_key(serde_yaml::Value::String((*k).to_string())));
                        if !has_required {
                            return false;
                        }
                        match m.get(serde_yaml::Value::String("approve".to_string())) {
                            Some(serde_yaml::Value::String(v)) => {
                                matches!(
                                    v.as_str(),
                                    "false"
                                        | "member"
                                        | "lighthouse"
                                        | "relay"
                                        | "lh_relay"
                                        | "reject"
                                        | "no"
                                        | "lh"
                                )
                            }
                            Some(serde_yaml::Value::Bool(v)) => !v,
                            _ => false,
                        }
                    })
                    .unwrap_or(false);

                if !compatible {
                    eprintln!("🗑️  Removing incompatible old approval YAML: {}", name);
                    let _ = std::fs::remove_file(path);
                }
            }
        }
    }

    // Create default node configs if missing
    for (nid, port) in &[("nodeA", 50051u16), ("nodeB", 50052), ("nodeC", 50053)] {
        let path = format!("/etc/sgx-guardian/config/{}.yaml", nid);
        if !std::path::Path::new(&path).exists() {
            let letter = &nid[4..];
            let content = format!(
                "---\nnode_id: \"{}\"\nhostname: \"guardian-node-{}\"\nip: \"0.0.0.0\"\nport: {}\npublic_key: \"placeholder-key-{}\"\n\nrelay:\n  enabled: false\n  max_peers: 5\n  max_bandwidth_mbps: 10\n  alert_threshold_pct: 80\n\nsecure_element:\n  enabled: true\n  scp_key_path: \"/home/root/se05x_mw_v04.05.01/simw-top/scripts/se050F_scp_keys.txt\"\n  interface: \"t1oi2c\"\n  auth_type: \"PlatformSCP\"\n  connection_type: \"se05x\"\n",
                nid, letter, port, letter
            );
            let _ = std::fs::write(&path, &content);
        }
        // Also create /etc/sgx-guardian/<node>.yaml symlink/copy
        let main_path = format!("/etc/sgx-guardian/{}.yaml", nid);
        if !std::path::Path::new(&main_path).exists() {
            let _ = std::fs::copy(&path, &main_path);
        }
    }

    // === Policy Authority key bootstrap (nodeA only) ===
    // Generates /etc/sgx-guardian/policies/pa_admin_{priv,pub}.der on first
    // boot, persists thereafter. Member nodes never run this — they receive
    // the public half through the cert-bootstrap response.
    if node_id == "nodeA" {
        match sgx_guardian_client::policy_authority::PaKey::load_or_generate() {
            Ok(_) => {
                println!(
                    "🔑 Policy Authority key ready at /etc/sgx-guardian/policies/pa_admin_priv.der"
                );
            }
            Err(e) => {
                eprintln!(
                    "⚠️ PA key bootstrap failed: {} — manual signing required",
                    e
                );
            }
        }
    }

    // Create default policy schema if missing.
    // CRITICAL: this string is byte-identical across all nodes — same binary,
    // same default schema → same canonical digest → mutual attestation works
    // out of the box on a fresh cohort.
    let schema_path = "/etc/sgx-guardian/schemas/uep_policy_v1.yaml";
    const DEFAULT_SCHEMA: &str = "---\npolicy_id: \"123e4567-e89b-12d3-a456-426614174000\"\nversion: \"1.0.0\"\ndescription: \"Default Guardian Edge Policy\"\nrules:\n  - id: \"rule-001\"\n    action: \"ALLOW\"\n    src: \"10.0.0.0/24\"\n    dst: \"0.0.0.0/0\"\n    protocol: \"TCP\"\n    port: 443\n  - id: \"rule-005\"\n    action: \"DENY\"\n    src: \"0.0.0.0/0\"\n    dst: \"10.0.0.10\"\n    protocol: \"UDP\"\n";
    if !std::path::Path::new(schema_path).exists() {
        let _ = std::fs::write(schema_path, DEFAULT_SCHEMA);
    }
    // Always log the canonical digest of the active schema so the operator
    // can compare it across boards.
    if let Ok(yaml) = std::fs::read_to_string(schema_path) {
        if let Ok(parsed) = sgx_guardian_client::policy::validate_policy(&yaml) {
            let canonical = sgx_guardian_client::policy::canonical_policy_bytes(&parsed);
            let digest = hex::encode(sha2::Sha256::digest(&canonical));
            println!(
                "📜 Local schema canonical digest: {} (compare to peers — must match)",
                digest
            );
        } else {
            eprintln!(
                "⚠️ Schema at {} is INVALID — attestation digest will fall back to constant default",
                schema_path
            );
        }
    }

    // Start node announcement listener (UDP broadcast receiver)
    {
        let node_id_clone = node_id.clone();
        tokio::spawn(async move {
            node_listener::start_listener(node_id_clone).await;
        });
    }
    GATES.log_summary();
    step(1, "post-listener: entering KeyManager init");
    // Generate node-specific identity key path
    let node_key_path = format!("/var/lib/sgx-guardian/sgx-agent/device_{}.key", node_id);
    // === Hardware Key Manager Initialization (Phase 2 — HKM) ===
    #[cfg(feature = "secure-element")]
    let km = {
        let se_base_path = "/var/lib/sgx-guardian";
        let se_config = secure_element::SeConfig::default();

        match KeyManager::init_with_se050(&se_config, se_base_path, &node_key_path) {
            Ok(hw_km) => {
                println!("DKP initialized via SE050 hardware");
                log_audit(
                    &node_id,
                    AuditCategory::Identity,
                    AuditSeverity::Info,
                    AuditAction::Loaded,
                    "Hardware Key Manager: DKP active via SE050",
                );
                hw_km
            }
            Err(e) => {
                eprintln!("SE050 HKM failed: {} — using software keys", e);
                KeyManager::load_or_generate(&node_key_path)?
            }
        }
    };

    #[cfg(not(feature = "secure-element"))]
    let km = KeyManager::load_or_generate(&node_key_path)?;

    // === DKP Auto-Rotation Check ===
    // Only probe the SE050 a SECOND time if the primary KeyManager init above
    // actually came up on hardware. Re-initializing DkpManager on a flaky chip
    // (e.g. during a network flap on the CA node) doubles ssscli/I2C contention
    // and was an amplifier of the DKP-regeneration cascade. If we're on software
    // keys, there is nothing to auto-rotate in the SE050 anyway.
    #[cfg(feature = "secure-element")]
    if km.backend_name() == "SE050" {
        let se_config = sgx_guardian_client::secure_element::SeConfig::default();
        let base_path = "/var/lib/sgx-guardian";
        if let Ok(mut dkp) =
            sgx_guardian_client::secure_element::dkp::DkpManager::init(&se_config, base_path)
        {
            match dkp.check_and_auto_rotate() {
                Ok(Some(new_meta)) => {
                    println!("  DKP auto-rotated to v{}", new_meta.version);
                    if let Err(e) = sgx_guardian_client::did::method::update_dkp_version(
                        sgx_guardian_client::did::DEFAULT_DID_PATH,
                        new_meta.version,
                    ) {
                        eprintln!("  ⚠️ DID dkp_version update failed: {}", e);
                    }
                    let _ = std::fs::write(DID_DOC_ROTATION_FLAG, chrono::Utc::now().to_rfc3339());
                }
                Ok(None) => { /* no rotation needed */ }
                Err(e) => {
                    eprintln!("  Auto-rotation check failed: {}", e);
                }
            }
        }
    }

    // === Device Identity Key (DIK) — non-rotating DID anchor ===
    #[cfg(feature = "secure-element")]
    {
        let se_config = sgx_guardian_client::secure_element::SeConfig::default();
        match sgx_guardian_client::secure_element::dik::DeviceIdentityKey::ensure(&se_config) {
            Ok(_) => println!("🔑 Device Identity Key (DIK) ready (slot 0x20000100, non-rotating)"),
            Err(e) => eprintln!(
                "⚠️ DIK ensure failed: {} — DID will use cached anchor if present",
                e
            ),
        }
    }

    // === SE050 Tamper Detection — arm at startup ===
    // Deliberately does NOT go through Se050::init(), which resets the
    // applet: re-probing/reinitializing SE050 after DKP/DIK have already
    // established state on this boot has previously amplified chip
    // contention issues on this hardware (see the DKP auto-rotation
    // comment above). connect() alone is safe to call again — "session
    // already open" is a normal, expected warning — so this only reads
    // the UID/cert UID to establish the tamper-detection baseline.
    #[cfg(feature = "secure-element")]
    let se050_tamper_handle: Option<std::sync::Arc<secure_element::se050::Se050>> = {
        let se_config = secure_element::SeConfig::default();
        let cli = secure_element::ssscli::SssCli::new(se_config.clone());
        match cli.connect() {
            Ok(_) => {
                let uid = cli.get_uid().ok();
                let cert_uid = cli.get_certuid().ok();
                let se = secure_element::se050::Se050 {
                    cli,
                    config: se_config,
                    uid,
                    cert_uid,
                    status: secure_element::se050::SeStatus::Active,
                };
                let tamper_status = secure_element::tamper::check_tamper(&se);
                if tamper_status == secure_element::tamper::TamperStatus::Detected {
                    eprintln!("🔴 SE050 TAMPER DETECTED — all crypto operations blocked");
                    log_audit(
                        &node_id,
                        AuditCategory::Cryptography,
                        AuditSeverity::Critical,
                        AuditAction::Failed,
                        "SE050 tamper detected at startup — crypto blocked",
                    );
                } else {
                    println!("✅ SE050 tamper check: OK");
                }
                Some(std::sync::Arc::new(se))
            }
            Err(e) => {
                eprintln!(
                    "⚠️ SE050 tamper baseline unavailable: {} — tamper detection disabled this boot",
                    e
                );
                None
            }
        }
    };
    #[cfg(not(feature = "secure-element"))]
    let _se050_tamper_handle: Option<()> = None;

    // === DID Initialization (W3C DID / did:guardian) ===
    println!("\n🆔 Initializing W3C DID (did:guardian)...");
    {
        let did_path = sgx_guardian_client::did::DEFAULT_DID_PATH;
        let dkp_pubkey_path = "/var/lib/sgx-guardian/keys/dkp_pub.der";
        match sgx_guardian_client::did::method::create_if_absent(
            &node_id,
            &km,
            dkp_pubkey_path,
            did_path,
        ) {
            Ok(did) => {
                println!("  ✅ DID active: {}", did.as_str());
                log_audit(
                    &node_id,
                    AuditCategory::Did,
                    AuditSeverity::Info,
                    AuditAction::Loaded,
                    &format!("DID resolved: {}", did.as_str()),
                );
            }
            Err(sgx_guardian_client::did::DidError::DerivationMismatch) => {
                // A mismatch derived from the pinned DIK pubkey means the
                // SE050 UID changed (true chip swap) — NOT a transient read
                // blip (Fix 1/2 prevent those from ever regenerating the DKP).
                // Even so, do NOT kill the daemon: the persisted did.json
                // remains the authoritative identity. Log CRITICAL, keep the
                // persisted DID, and continue in a degraded-but-running state
                // so the operator can investigate instead of facing a boot loop.
                eprintln!(
                    "  🔴 DID DERIVATION MISMATCH (SE050 UID changed?) — \
                     keeping persisted DID, continuing in DEGRADED mode."
                );
                log_audit(
                    &node_id,
                    AuditCategory::Did,
                    AuditSeverity::Critical,
                    AuditAction::Failed,
                    "DID derivation mismatch — persisted DID retained, node DEGRADED",
                );
                if let Ok(rec) = sgx_guardian_client::did::DidRecord::load(
                    sgx_guardian_client::did::DEFAULT_DID_PATH,
                ) {
                    println!("  ↳ Persisted DID retained: {}", rec.did);
                }
            }
            Err(sgx_guardian_client::did::DidError::Deactivated(when)) => {
                eprintln!("  🔴 DID is deactivated at {} — refusing to start.", when);
                log_audit(
                    &node_id,
                    AuditCategory::Did,
                    AuditSeverity::Critical,
                    AuditAction::Rejected,
                    &format!("DID is deactivated at {}", when),
                );
                std::process::exit(3);
            }
            Err(e) => {
                eprintln!("  ⚠️ DID initialization failed: {} — continuing.", e);
                log_audit(
                    &node_id,
                    AuditCategory::Did,
                    AuditSeverity::Warning,
                    AuditAction::Failed,
                    &format!("DID initialization failed: {}", e),
                );
            }
        }
    }

    // === DID Document Initialization (W3C DID Document) ===
    println!("\n📜 Initializing DID Document...");
    match sgx_guardian_client::did::doc_persistence::load_self() {
        Ok(Some(existing)) => {
            println!(
                "  ✅ Existing DID Document loaded (version v{})",
                existing.sgx_version_id
            );
        }
        Ok(None) => {
            let did_path = sgx_guardian_client::did::DEFAULT_DID_PATH;
            let dkp_pubkey_path = "/var/lib/sgx-guardian/keys/dkp_pub.der";
            match sgx_guardian_client::did::method::resolve_local(did_path, dkp_pubkey_path) {
                Ok((did, _anchor_pk, active)) => {
                    let refreshed_km = match km.refresh_for_active_dkp() {
                        Ok(km_opt) => km_opt,
                        Err(e) => {
                            eprintln!("  ⚠️ DID Document signer refresh failed: {}", e);
                            None
                        }
                    };
                    let did_doc_km = refreshed_km.as_ref().unwrap_or(&km);
                    let dkp_pub = did_doc_km
                        .pubkey_der()
                        .or_else(|_| std::fs::read(dkp_pubkey_path))
                        .unwrap_or_default();
                    if dkp_pub.is_empty() {
                        eprintln!("  ⚠️ DID Document skipped: DKP pubkey unavailable");
                    } else {
                        let input = sgx_guardian_client::did::document::DocBuildInput {
                            did: did.as_str(),
                            node_name: Some(&node_id),
                            current_dkp_version:
                                sgx_guardian_client::secure_element::pcr::read_dkp_key_version(),
                            current_dkp_pubkey_der: &dkp_pub,
                            overlay_ip_cidr: None,
                            attestation_bind: None,
                            cert_bootstrap_bind: None,
                            revoked: vec![],
                            previous_version_id: 0,
                            created_at: None,
                            status: Some(if active {
                                "active".to_string()
                            } else {
                                "deactivated".to_string()
                            }),
                        };
                        match sgx_guardian_client::did::document::DidDocument::build(input) {
                            Ok(mut doc) => {
                                let vm_ref = doc.verification_method[0].id.clone();
                                match sgx_guardian_client::did::doc_sign::sign_in_place(
                                    &mut doc, did_doc_km, &vm_ref,
                                ) {
                                    Ok(()) => {
                                        if let Err(e) =
                                            sgx_guardian_client::did::doc_persistence::save_self(
                                                &doc,
                                            )
                                        {
                                            eprintln!("  ⚠️ DID Document save failed: {}", e);
                                        } else if let Err(e) =
                                            sgx_guardian_client::did::doc_persistence::write_self_floor_version(
                                                doc.sgx_version_id,
                                            )
                                        {
                                            eprintln!(
                                                "  ⚠️ DID Document version counter update failed: {}",
                                                e
                                            );
                                        } else {
                                            println!("  ✅ DID Document v1 created");
                                        }
                                    }
                                    Err(e) => eprintln!("  ⚠️ DID Document sign failed: {}", e),
                                }
                            }
                            Err(e) => eprintln!("  ⚠️ DID Document build failed: {}", e),
                        }
                    }
                }
                Err(e) => eprintln!("  ⚠️ DID Document resolve_local failed: {}", e),
            }
        }
        Err(e) => eprintln!("  ⚠️ DID Document load failed: {}", e),
    }

    // === Crypto Provider Status ===
    match km.backend_name() {
        "SE050" => {
            println!("  Secure Element detected: SE050");
            println!("  Signing provider: SE050 hardware (ECDSA-P256)");
            println!("  RNG source: SE050 TRNG");
        }
        _ => {
            println!("  Secure Element not available");
            println!("  Signing provider: software (ring crate, ECDSA-P256)");
            println!("  RNG source: software RNG (SystemRandom)");
        }
    }

    let pubkey_b64 = general_purpose::STANDARD.encode(km.pubkey_der()?);
    println!(
        "Node Identity Initialized | Public Key Prefix: {}...",
        &pubkey_b64[..20]
    );

    // === Secure Boot Chain Verification ===
    println!("\n  Verifying secure boot chain...");
    {
        use sgx_guardian_client::secure_element::secure_boot::BootChainStatus;

        let boot_status = match tokio::time::timeout(
            std::time::Duration::from_secs(15),
            tokio::task::spawn_blocking(BootChainStatus::check),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                eprintln!(
                    "  ⚠️ BootChain task panicked: {:?} — using unknown defaults",
                    e
                );
                BootChainStatus::unknown()
            }
            Err(_) => {
                eprintln!("  ⚠️ BootChain check TIMED OUT after 15s — using unknown defaults");
                BootChainStatus::unknown()
            }
        };
        BootChainStatus::prime_cache(boot_status.clone());
        boot_status.print();

        // Save boot chain status
        let boot_status_path = format!("/var/lib/sgx-guardian/boot/{}_chain_status.json", node_id);
        if let Err(e) = boot_status.save(&boot_status_path) {
            eprintln!("  Boot chain save failed: {}", e);
        }

        if !boot_status.boot_chain_intact {
            eprintln!(
                "  ⚠️ Boot chain verification incomplete — PCR values may not be fully trusted"
            );
        }
    }

    let mut local_pcr_trusted = false;
    // === PCR Measurement (ATT-003) ===
    println!("\n  Measuring platform integrity (PCR)...");
    {
        use sgx_guardian_client::secure_element::pcr::*;
        use sgx_guardian_client::secure_element::pcr_config;
        use sha2::Digest;

        let mut pcr_engine = PcrEngine::new();
        let mut measurement_errors: Vec<PcrMeasurementError> = Vec::new();

        // Detect environment
        let is_hardware = std::path::Path::new("/proc/device-tree/model").exists();
        println!(
            "  PCR mode: {}",
            if is_hardware {
                "Hardware (board)"
            } else {
                "Software (simulated)"
            }
        );

        let sources = if is_hardware {
            pcr_config::default_measurement_sources(&node_id)
        } else {
            pcr_config::software_measurement_sources()
        };

        // Perform measurements
        for src in &sources {
            if src.source_type == "boot_chain" {
                // Measure the boot chain state string
                use sgx_guardian_client::secure_element::secure_boot::BootChainStatus;
                let boot_status = BootChainStatus::check();
                let measurement = boot_status.to_measurement_string();
                match pcr_engine.extend_from_string(src.pcr_index, &measurement) {
                    Ok(hash) => println!(
                        "    PCR{}: {} → {}...",
                        src.pcr_index,
                        src.label,
                        &hash[..12]
                    ),
                    Err(e) => {
                        let _ =
                            pcr_engine.extend_from_string(src.pcr_index, &format!("ERROR:{}", e));
                        measurement_errors.push(PcrMeasurementError {
                            pcr_index: src.pcr_index,
                            source: src.source.clone(),
                            error: e.clone(),
                        });
                        println!("    PCR{}: {} → ⚠️ {}", src.pcr_index, src.label, e);
                    }
                }
            } else if src.source_type == "multi_file" {
                let files: Vec<String> = src
                    .source
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect();
                let errs = pcr_engine.extend_from_files(src.pcr_index, &files);
                measurement_errors.extend(errs);
            } else if src.source_type == "static_yaml" {
                let canonical = canonical_static_yaml_measurement(&src.source);
                match pcr_engine.extend_from_string(src.pcr_index, &canonical) {
                    Ok(hash) => println!(
                        "    PCR{}: {} → {}...",
                        src.pcr_index,
                        src.label,
                        &hash[..12]
                    ),
                    Err(e) => {
                        let _ =
                            pcr_engine.extend_from_string(src.pcr_index, &format!("ERROR:{}", e));
                        measurement_errors.push(PcrMeasurementError {
                            pcr_index: src.pcr_index,
                            source: src.source.clone(),
                            error: e.clone(),
                        });
                        println!("    PCR{}: {} → ⚠️ {}", src.pcr_index, src.label, e);
                    }
                }
            } else {
                let result = match src.source_type.as_str() {
                    "file" => pcr_engine.extend_from_file(src.pcr_index, &src.source),
                    "string" => pcr_engine.extend_from_string(src.pcr_index, &src.source),
                    _ => Err(format!("Unknown type: {}", src.source_type)),
                };
                match result {
                    Ok(hash) => println!(
                        "    PCR{}: {} → {}...",
                        src.pcr_index,
                        src.label,
                        &hash[..12]
                    ),
                    Err(e) => {
                        let _ =
                            pcr_engine.extend_from_string(src.pcr_index, &format!("ERROR:{}", e));
                        measurement_errors.push(PcrMeasurementError {
                            pcr_index: src.pcr_index,
                            source: src.source.clone(),
                            error: e.clone(),
                        });
                        println!("    PCR{}: {} → ⚠️ {}", src.pcr_index, src.label, e);
                    }
                }
            }
        }

        pcr_engine.print_status();

        // Determine integrity status
        let has_critical_fail = measurement_errors.iter().any(|err| {
            sources
                .iter()
                .any(|s| s.pcr_index == err.pcr_index && s.critical)
        });
        let integrity_status = if measurement_errors.is_empty() {
            "PASS".to_string()
        } else if has_critical_fail {
            "FAIL".to_string()
        } else {
            "DEGRADED".to_string()
        };

        if integrity_status == "FAIL" {
            eprintln!("  🔴 CRITICAL: Platform integrity check FAILED — attestation will be rejected by peers");
        } else if integrity_status == "DEGRADED" {
            println!("  ⚠️ Some measurements failed (non-critical) — status DEGRADED");
        } else {
            println!("  Platform integrity: ✅ PASS");
        }

        // Build snapshot
        let mut snapshot = pcr_engine.snapshot();
        snapshot.measurement_errors = measurement_errors;
        snapshot.integrity_status = integrity_status;
        snapshot.device_uid = read_device_uid(&node_id);
        snapshot.key_version = read_dkp_key_version();

        // Generate nonce + timestamp
        let mut nonce_bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
        snapshot.nonce = hex::encode(nonce_bytes);
        snapshot.measured_at = chrono::Utc::now().to_rfc3339();

        // Sign: SHA256(composite_bytes || nonce_bytes || timestamp_bytes)  (BINARY concat)
        let composite_bytes =
            hex::decode(&snapshot.composite_digest).unwrap_or_else(|_| vec![0u8; 32]);
        let nonce_sign_bytes = hex::decode(&snapshot.nonce).unwrap_or_else(|_| vec![0u8; 16]);
        let ts_bytes = snapshot.measured_at.as_bytes();
        let mut sign_input = Vec::with_capacity(32 + 16 + ts_bytes.len());
        sign_input.extend_from_slice(&composite_bytes);
        sign_input.extend_from_slice(&nonce_sign_bytes);
        sign_input.extend_from_slice(ts_bytes);
        let sign_hash = sha2::Sha256::digest(&sign_input);

        if let Ok(sig) = km.sign(&sign_hash) {
            snapshot.composite_signature =
                Some(base64::engine::general_purpose::STANDARD.encode(&sig));
            println!(
                "  PCR composite signed by DKP (v{}) ✅",
                snapshot.key_version
            );
        }

        // Save snapshot
        let pcr_path = format!("/var/lib/sgx-guardian/pcr/{}_current.json", node_id);
        match snapshot.save(&pcr_path) {
            Ok(_) => println!("  PCR snapshot → {}", pcr_path),
            Err(e) => eprintln!("  PCR save failed: {}", e),
        }

        // Compare against baseline
        let baseline_path = format!("/etc/sgx-guardian/pcr_{}_baseline.json", node_id);
        if let Ok(baseline) = PcrBaseline::load(&baseline_path) {
            // Validate schema version
            if baseline.schema_version != PCR_SCHEMA_VERSION {
                eprintln!(
                    "  ⚠️ Baseline schema v{} != current v{} — re-create baseline",
                    baseline.schema_version, PCR_SCHEMA_VERSION
                );
            } else {
                // Verify baseline signature
                let pubkey = km.pubkey_der()?;
                if !baseline.verify_signature(&pubkey) {
                    if baseline.key_version != snapshot.key_version {
                        eprintln!("  ⚠️ Baseline signed with DKP v{}, current is v{}. Re-create baseline.",
                            baseline.key_version, snapshot.key_version);
                    } else {
                        eprintln!("  🔴 Baseline signature INVALID — possible tampering!");
                    }
                } else {
                    match snapshot.compare_baseline(&baseline) {
                        Ok(mismatches) if mismatches.is_empty() => {
                            println!("  PCR baseline: ✅ ALL MATCH");
                            local_pcr_trusted = true;
                        }
                        Ok(mismatches) => {
                            eprintln!("  ⚠️ PCR MISMATCH detected:");
                            for idx in &mismatches {
                                eprintln!(
                                    "    PCR{} [{}]: expected {}.. got {}..",
                                    idx,
                                    PcrEngine::pcr_name(*idx),
                                    &baseline.pcr_values[*idx][..16],
                                    &snapshot.pcr_values[*idx][..16]
                                );
                            }
                        }
                        Err(e) => eprintln!("  ⚠️ Baseline compare error: {}", e),
                    }
                }
            }
        } else {
            println!("  No baseline — create with: sgx-pa-cli pcr-baseline-create");
        }
    }

    // Generate and log attestation evidence for this node
    use sgx_guardian_client::attestation_service::AttestationService;

    let sample_policy = sgx_guardian_client::policy::load_effective_policy_material();

    let evidence = AttestationService::create_signed_evidence(&km, &sample_policy.yaml)?;
    println!(
        "Created local attestation evidence (nonce={}..)",
        &evidence.nonce[..8]
    );
    let evidence_verified =
        AttestationService::verify_signed_evidence(&evidence, &sample_policy.yaml)?;
    let verified = evidence_verified && local_pcr_trusted;
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

    // Sanitize configs before load
    for yaml_file in &[
        "/etc/sgx-guardian/config/nodeA.yaml",
        "/etc/sgx-guardian/config/nodeB.yaml",
        "/etc/sgx-guardian/config/nodeC.yaml",
    ] {
        if let Err(e) = dynamic_config::sanitize_config_ip_if_invalid(yaml_file) {
            eprintln!("⚠️ Sanitize failed for {}: {:?}", yaml_file, e);
        }
    }

    // Update ONLY current node config with detected IP
    if !detected_ip.is_empty() {
        let config_path = format!("/etc/sgx-guardian/config/{}.yaml", node_id);
        let main_path = format!("/etc/sgx-guardian/{}.yaml", node_id);
        let _ = dynamic_config::update_config_ip_if_changed(&config_path, &detected_ip);
        // Keep main path in sync
        let _ = std::fs::copy(&config_path, &main_path);
    }

    fn load_config_safe(node: &str) -> NodeConfig {
        // Try config/ dir first (dynamic configs live here)
        let config_path = format!("/etc/sgx-guardian/config/{}.yaml", node);
        if let Ok(cfg) = load_config(&config_path) {
            return cfg;
        }
        // Fallback to root dir
        let root_path = format!("/etc/sgx-guardian/{}.yaml", node);
        if let Ok(cfg) = load_config(&root_path) {
            return cfg;
        }
        // Last resort: default config
        eprintln!("⚠️ No config found for {} — using defaults", node);
        NodeConfig {
            node_id: node.to_string(),
            hostname: format!("guardian-node-{}", &node[4..]),
            ip: "0.0.0.0".to_string(),
            port: match node {
                "nodeA" => 50051,
                "nodeB" => 50052,
                _ => 50053,
            },
            public_key: format!("placeholder-key-{}", &node[4..]),
            metrics: None,
            relay: None,
        }
    }

    println!("\n Loading node configurations...");
    let node_a = load_config_safe("nodeA");
    let node_b = load_config_safe("nodeB");
    let node_c = load_config_safe("nodeC");

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

    let current_relay_cfg: RelayLimitsConfig = match node_id.as_str() {
        "nodeA" => node_a.relay_or_default(),
        "nodeB" => node_b.relay_or_default(),
        "nodeC" => node_c.relay_or_default(),
        _ => RelayLimitsConfig::default(),
    };

    // Read the UEP policy YAML file
    let _yaml_content = fs::read_to_string("/etc/sgx-guardian/schemas/uep_policy_v1.yaml")
        .unwrap_or_else(|e| {
            eprintln!("⚠️ Policy schema not found: {} — using empty default", e);
            // Return minimal valid policy YAML
            String::from(
                "---\npolicy_id: \"default\"\nversion: \"0.0.0\"\ndescription: \"Empty default\"\nrules: []\n",
            )
        });
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

    // === FIX #8: use per-node log file, matching what the writer produces. ===
    // Writer initialised below as `audit-<node>.log`; pre-init verifier must
    // check the SAME file, otherwise it verifies a stale/empty/wrong artefact.
    let audit_log_path_prod = format!("{}/audit-{}.log", prod_log_dir, node_id);
    let audit_log_path_dev = format!("logs/audit-{}.log", node_id);
    let audit_check_path = if std::path::Path::new(&audit_log_path_prod).exists() {
        audit_log_path_prod.clone()
    } else {
        audit_log_path_dev.clone()
    };

    if std::path::Path::new(&audit_check_path).exists() {
        if let Err(e) = AuditVerifier::verify(&audit_check_path) {
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
            sgx_guardian_client::cloud::mock_server::run_mock_cloud(([127, 0, 0, 1], 9443)).await;
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
    {
        let mut m = metrics.lock().await;
        m.set_relay_limits(
            current_relay_cfg.max_peers,
            current_relay_cfg.max_bandwidth_mbps,
            current_relay_cfg.alert_threshold_pct,
        );
    }

    // === Cloud uplink (outbound-only mock) ===
    let cloud_cfg = CloudConfig::from_env();

    step(8, "cloud-uplink spawn gate");
    if cloud_cfg.enabled && !GATES.disable_cloud_uplink {
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
            if let Err(e) =
                sgx_guardian_client::cloud::client::send_heartbeat(&node_id_clone, &endpoint).await
            {
                log_error(
                    &node_id_clone,
                    &format!("Cloud uplink heartbeat failed: {}", e),
                );
            }
        });
        cooldown().await;
    } else if GATES.disable_cloud_uplink {
        tracing::warn!("STEP_08 SKIPPED: cloud uplink disabled by SGX_DISABLE_CLOUD_UPLINK");
    }

    {
        let mut m = metrics.lock().await;
        m.record_connection();
    }

    let mut did_doc_publish_state: Option<(String, String, bool, String)> = None;
    let mut did_resolver = sgx_guardian_client::did::Resolver::new(
        sgx_guardian_client::did::ResolverConfig::default(),
    );
    let mut resolver_for_flag = did_resolver.clone();
    let vid_cache = sgx_guardian_client::virtual_id_cache::VirtualIdCache::new();
    sgx_guardian_client::attestation_service::set_vid_cache(vid_cache.clone());

    let (reattest_tx, mut reattest_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    sgx_guardian_client::attestation_service::set_reattest_sender(reattest_tx);
    let node_key_path_for_reattest = node_key_path.clone();
    tokio::spawn(async move {
        while let Some(peer_did) = reattest_rx.recv().await {
            let resolver = sgx_guardian_client::did::Resolver::new(Default::default());
            let res = match resolver.resolve(&peer_did).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("Re-attest: cannot resolve {}: {}", peer_did, e);
                    continue;
                }
            };
            let attest_endpoint = res.services.iter().find(|s| s.r#type == "SGXAttestation");
            let Some(endpoint) = attest_endpoint else {
                tracing::warn!("Re-attest: peer {} has no SGXAttestation service", peer_did);
                continue;
            };
            let url = endpoint.endpoint.trim_start_matches("tcp://");
            let Some((ip, port_str)) = url.rsplit_once(':') else {
                tracing::warn!("Re-attest: cannot parse endpoint {}", endpoint.endpoint);
                continue;
            };
            let Ok(port) = port_str.parse::<u16>() else {
                tracing::warn!("Re-attest: cannot parse port in {}", endpoint.endpoint);
                continue;
            };
            let km_for_reattest = match KeyManager::load_or_generate(&node_key_path_for_reattest) {
                Ok(km) => km,
                Err(e) => {
                    tracing::warn!("Re-attest: cannot load local key: {}", e);
                    continue;
                }
            };
            tracing::info!("Re-attesting with peer {} at {}:{}", peer_did, ip, port);
            let _ = sgx_guardian_client::attestation_service::AttestationService::mutual_attest(
                ip.to_string(),
                port,
                &km_for_reattest,
            )
            .await;
        }
    });

    step(9, "nebula subsystem gate");
    if !GATES.disable_nebula {
        // === Nebula Installation Verification ===
        println!("\n🔎 Verifying Nebula Installation...");

        use sgx_guardian_client::nebula::ca::NebulaCA;
        use sgx_guardian_client::nebula::config::NebulaConfig;
        use sgx_guardian_client::nebula::daemon::NebulaDaemon;
        use sgx_guardian_client::nebula::interface::NebulaInterface;
        use sgx_guardian_client::nebula::lighthouse::LighthouseRegistry;
        use sgx_guardian_client::nebula::models::CircleMembership;
        use sgx_guardian_client::nebula::overlay::OverlayPool;
        use sgx_guardian_client::nebula::overlay_registry::OverlayRegistry;
        use sgx_guardian_client::nebula::registry_sync;
        use sgx_guardian_client::nebula::registry_sync::SharedRegistry;
        use sgx_guardian_client::nebula::relay_registry::RelayRegistry;
        use sgx_guardian_client::nebula::relay_tc::RelayTrafficControl;
        use sgx_guardian_client::nebula::stats::NebulaStats;
        use sgx_guardian_client::nebula::tunnel_state::TunnelState;
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let nebula_base_dir =
            std::env::var("SGX_NEBULA_DIR").unwrap_or("/var/lib/sgx-guardian/nebula".to_string());
        if node_id != "nodeA" {
            println!(
                "ℹ️ {} keeps local read-only relay registry snapshot",
                node_id
            );
        }

        // Nebula binary checks
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
                std::process::exit(1);
            }
        }
        match NebulaInstall::test_daemon_start() {
            Ok(_) => println!("✅ Nebula daemon responding"),
            Err(e) => {
                eprintln!("❌ Nebula daemon test failed: {}", e);
                std::process::exit(1);
            }
        }

        // ── Kill any stale nebula daemon from a previous run ────────────────────
        // (Prevents "address already in use" on UDP 4242)
        let _ = std::process::Command::new("pkill")
            .args(["-f", "nebula -config"])
            .output();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        println!("\n🗺️  Resolving overlay IP and CA assignment...");

        let mut nebula_ip: String;
        let overlay_pool: OverlayPool;
        let mut lighthouse_registry: LighthouseRegistry;

        if node_id == "nodeA" {
            // ────────────────────────────────────────────────────────────────────
            // nodeA IS the CA + Lighthouse.
            // 1. Generate CA (idempotent).
            // 2. Assign its own overlay IP from the registry.
            // 3. Issue its own cert.
            // 4. Start the registry server so members can get IPs.
            // ────────────────────────────────────────────────────────────────────

            // 1. Generate CA — nodeA ONLY
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

            // Log CA fingerprint so admins can verify all nodes use the same CA
            if let Some(fp) = NebulaCA::ca_fingerprint(&nebula_base_dir) {
                println!("🔏 CA fingerprint: {}", fp);
                log_event(&node_id, &format!("Nebula CA fingerprint: {}", fp));
            }

            // 2. Load/create the overlay IP registry
            let registry_path = format!("{}/overlay_registry.json", nebula_base_dir);
            let reg = OverlayRegistry::load_or_create(
                &registry_path,
                "guardian-circle-alpha",
                "192.168.100",
                "nodeA",
            );

            let ip_cidr = reg
                .get_ip_cidr("nodeA")
                .expect("nodeA IP missing from registry")
                .to_string();

            println!("🌐 nodeA overlay IP: {}", ip_cidr);
            reg.print_table();

            if let Err(e) = reg.save(&registry_path) {
                eprintln!("⚠️ Registry save failed: {}", e);
            }

            nebula_ip = ip_cidr.clone();
            overlay_pool = OverlayPool::from(&reg);

            // Lighthouse registry (primary lighthouse is always nodeA)
            let lh_path = format!("{}/lighthouse_registry.json", nebula_base_dir);
            let owner_overlay = reg
                .get_ip("nodeA")
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "192.168.100.1".to_string());
            let lighthouse_endpoint_ip = if !detected_ip.is_empty() {
                detected_ip.clone()
            } else if !node_a.ip.is_empty() && node_a.ip != "0.0.0.0" {
                node_a.ip.clone()
            } else {
                "0.0.0.0".to_string()
            };
            let lighthouse_endpoint = format!("{}:4242", lighthouse_endpoint_ip);
            let mut lh_reg = LighthouseRegistry::load_or_create(
                &lh_path,
                "guardian-circle-alpha",
                "nodeA",
                &owner_overlay,
                &lighthouse_endpoint,
            );
            let _ = lh_reg.update_endpoint("nodeA", &lighthouse_endpoint);
            lh_reg.mark_active("nodeA");
            if let Err(e) = lh_reg.save(&lh_path) {
                eprintln!("⚠️ LH registry save failed: {}", e);
            }
            println!("📡 {}", lh_reg.summary());
            lighthouse_registry = lh_reg;

            // 3. Issue nodeA's own certificate
            let membership_a = CircleMembership {
                node_name: node_id.clone(),
                circle_id: "guardian-circle-alpha".to_string(),
                vc_hash: "ca-self-signed".to_string(),
                is_valid: true,
            };
            if let Err(e) = NebulaCA::issue_node_cert(&nebula_base_dir, &membership_a, &ip_cidr) {
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

            // 4. Start registry server (IP assignment for members)
            let shared_reg: SharedRegistry = Arc::new(RwLock::new(reg));
            tokio::spawn({
                let reg_clone = shared_reg.clone();
                async move {
                    registry_sync::start_registry_server(reg_clone).await;
                }
            });
            println!(
                "✅ Registry sync server started on port {}",
                registry_sync::REGISTRY_SYNC_PORT
            );

            if let Err(e) =
                refresh_and_publish_did_doc(&node_id, &km, &ip_cidr, "127.0.0.1", true).await
            {
                eprintln!("⚠️ DID Document self-publish failed: {}", e);
            }
            did_doc_publish_state = Some((
                ip_cidr.clone(),
                "127.0.0.1".to_string(),
                true,
                nebula_base_dir.clone(),
            ));
        } else {
            // ────────────────────────────────────────────────────────────────────
            // nodeB / nodeC — MEMBER NODES
            // 1. Discover nodeA's real LAN IP.
            // 2. Request overlay IP from the CA registry.
            // 3. Fetch the CA cert from nodeA (via cert bootstrap response).
            // 4. Request a Nebula cert from nodeA.
            // Members MUST NOT call generate_ca().
            // ────────────────────────────────────────────────────────────────────

            // 1. Discover nodeA's real LAN IP (needed for static_host_map + CA bootstrap)
            let ca_lan_ip: String = {
                // Priority order:
                //   a) SGX_LIGHTHOUSE_IP env var (explicit override)
                //   b) nodeA config file (updated by UDP broadcast)
                //   c) 127.0.0.1 last resort (loopback = local test only)
                if let Ok(env_ip) = std::env::var("SGX_LIGHTHOUSE_IP") {
                    if !env_ip.is_empty() && env_ip != "0.0.0.0" {
                        println!("📌 Using SGX_LIGHTHOUSE_IP={}", env_ip);
                        env_ip
                    } else {
                        resolve_ca_ip_from_config_inner().await
                    }
                } else {
                    resolve_ca_ip_from_config_inner().await
                }
            };
            println!("📡 nodeA (CA/Lighthouse) LAN IP: {}", ca_lan_ip);

            // If no registry sync from CA yet this boot, treat cache as suspect
            if !std::path::Path::new(registry_sync::REGISTRY_PATH).exists() {
                let _ = registry_sync::clear_local_ip_cache(&node_id);
            }

            // 2. Resolve overlay IP from CA registry
            let pubkey_prefix = &pubkey_b64[..20.min(pubkey_b64.len())];
            let ip_cidr =
                registry_sync::resolve_overlay_ip(&node_id, &ca_lan_ip, pubkey_prefix).await;
            println!("🌐 Overlay IP for {}: {}", node_id, ip_cidr);

            nebula_ip = ip_cidr.clone();

            if let Err(e) =
                refresh_and_publish_did_doc(&node_id, &km, &ip_cidr, &ca_lan_ip, false).await
            {
                eprintln!("⚠️ DID Document publish failed: {}", e);
            }
            did_doc_publish_state = Some((
                ip_cidr.clone(),
                ca_lan_ip.clone(),
                false,
                nebula_base_dir.clone(),
            ));

            let ip_only = ip_cidr.split('/').next().unwrap_or("").to_string();
            let mut pool = OverlayPool::new("guardian-circle-alpha", "192.168.100", "nodeA");
            pool.allocations.insert(node_id.clone(), ip_only);
            overlay_pool = pool;

            let lh_path = format!("{}/lighthouse_registry.json", nebula_base_dir);
            let owner_overlay = overlay_pool
                .get_ip("nodeA")
                .cloned()
                .unwrap_or_else(|| "192.168.100.1".to_string());
            let lighthouse_endpoint = format!("{}:4242", ca_lan_ip);
            let mut lh_reg = LighthouseRegistry::load_or_create(
                &lh_path,
                "guardian-circle-alpha",
                "nodeA",
                &owner_overlay,
                &lighthouse_endpoint,
            );
            let _ = lh_reg.update_endpoint("nodeA", &lighthouse_endpoint);
            lh_reg.mark_active("nodeA");
            if let Err(e) = lh_reg.save(&lh_path) {
                eprintln!("⚠️ LH registry save failed: {}", e);
            }
            println!("📡 {}", lh_reg.summary());
            lighthouse_registry = lh_reg;

            log_audit(
                &node_id,
                AuditCategory::Network,
                AuditSeverity::Info,
                AuditAction::Succeeded,
                &format!("Overlay IP resolved: {}", ip_cidr),
            );

            // 3. Fetch Nebula cert + CA cert from nodeA
            let member_cert_path = format!("{}/nodes/{}.crt", nebula_base_dir, node_id);
            let member_key_path = format!("{}/nodes/{}.key", nebula_base_dir, node_id);

            let cert_exists = Path::new(&member_cert_path).exists();
            let key_exists = Path::new(&member_key_path).exists();
            let ca_exists = NebulaCA::ca_cert_exists(&nebula_base_dir);
            let cert_ip_ok = cert_exists && cert_matches_overlay_ip(&member_cert_path, &ip_cidr);

            if cert_exists && key_exists && ca_exists && cert_ip_ok {
                println!(
                    "✅ Nebula certificate + CA cert already present for {}",
                    node_id
                );
                // Still log the CA fingerprint so mismatches surface in logs
                if let Some(fp) = NebulaCA::ca_fingerprint(&nebula_base_dir) {
                    println!("🔏 CA fingerprint (local): {}", fp);
                }
                log_audit(
                    &node_id,
                    AuditCategory::Network,
                    AuditSeverity::Info,
                    AuditAction::Succeeded,
                    &format!("Existing Nebula certificate found for {}", node_id),
                );
            } else {
                if cert_exists && key_exists && !cert_ip_ok {
                    eprintln!(
                        "⚠️ Existing cert IP mismatch for {} (expected {}). Rebootstrapping cert.",
                        node_id, ip_cidr
                    );
                    let _ = std::fs::remove_file(&member_cert_path);
                    let _ = std::fs::remove_file(&member_key_path);
                }

                println!(
                    "🔐 Requesting cert + CA cert from nodeA at {}:50061...",
                    ca_lan_ip
                );
                log_event(&node_id, "Nebula certificate missing — requesting from CA");

                let ca_address = format!("{}:50061", ca_lan_ip);
                let wants_lh = std::env::var("SGX_WANTS_LIGHTHOUSE")
                    .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
                    .unwrap_or(false);
                let wants_relay = std::env::var("SGX_WANTS_RELAY")
                    .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
                    .unwrap_or(false);

                // BLOCKING: wait until we have the cert before starting Nebula
                sgx_guardian_client::cert_client::request_certificate_from_ca(
                    node_id.clone(),
                    ca_address,
                    ip_cidr.clone(),
                    pubkey_b64.clone(),
                    wants_lh,
                    wants_relay,
                )
                .await;

                // The cert_client writes the CA cert to nebula/ca/ca.crt via
                // cert_service.rs CertSignResponse.ca_cert_pem.
                // Verify it arrived:
                if !NebulaCA::ca_cert_exists(&nebula_base_dir) {
                    eprintln!(
                        "❌ CA cert still missing after bootstrap! \
                 Check nodeA is running and cert_service wrote ca_cert_pem."
                    );
                    std::process::exit(1);
                }

                if let Some(fp) = NebulaCA::ca_fingerprint(&nebula_base_dir) {
                    println!("🔏 CA fingerprint (from nodeA): {}", fp);
                    log_event(&node_id, &format!("CA fingerprint: {}", fp));
                }

                println!("✅ Certificate bootstrap completed for {}", node_id);
            }

            let lh_path = format!("{}/lighthouse_registry.json", nebula_base_dir);
            if let Ok(fresh_lh) = LighthouseRegistry::load(&lh_path) {
                lighthouse_registry = fresh_lh;
            }

            if std::path::Path::new("/var/lib/sgx-guardian/nebula/am_lighthouse").exists() {
                let endpoint_ip = if crate::dynamic_config::is_routable_ip(&detected_ip) {
                    detected_ip.clone()
                } else {
                    load_config(&format!("/etc/sgx-guardian/config/{}.yaml", node_id))
                        .ok()
                        .map(|c| c.ip)
                        .filter(|ip| crate::dynamic_config::is_routable_ip(ip))
                        .unwrap_or_default()
                };
                if crate::dynamic_config::is_routable_ip(&endpoint_ip) {
                    let endpoint = format!("{}:4242", endpoint_ip);
                    if !lighthouse_registry.is_lighthouse(&node_id) {
                        let self_overlay = ip_cidr.split('/').next().unwrap_or("").to_string();
                        lighthouse_registry.add_lighthouse(&node_id, &self_overlay, &endpoint);
                    }
                    let _ = lighthouse_registry.update_endpoint(&node_id, &endpoint);
                    lighthouse_registry.mark_active(&node_id);
                    let _ = lighthouse_registry.save(&lh_path);
                }

                println!("🗼 Starting local registry sync server (lighthouse mode)");
                let reg = OverlayRegistry::load_or_create(
                    registry_sync::REGISTRY_PATH,
                    "guardian-circle-alpha",
                    "192.168.100",
                    "nodeA",
                );
                let shared_reg: SharedRegistry = Arc::new(RwLock::new(reg));
                tokio::spawn(async move {
                    registry_sync::start_registry_server(shared_reg).await;
                });
            }
        }

        let resolver_ca_host = match did_doc_publish_state.as_ref() {
            Some((_, ca_host, _, _)) => ca_host.clone(),
            None => resolve_ca_ip_from_config_inner().await,
        };
        did_resolver =
            sgx_guardian_client::did::Resolver::new(sgx_guardian_client::did::ResolverConfig {
                ca_host: resolver_ca_host,
                ..Default::default()
            });
        let resolver_for_pull = did_resolver.clone();
        resolver_for_flag = did_resolver.clone();

        let node_for_registry_sync = node_id.clone();
        let nebula_dir_for_registry_sync = nebula_base_dir.clone();
        let pool_for_registry_sync = overlay_pool.clone();

        tokio::spawn(async move {
            let mut did_doc_sync_elapsed = 0u64;
            let mut vc_status_list_sync_elapsed = 0u64;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(RELAY_SYNC_INTERVAL_SECS)).await;
                let ca_host = resolve_ca_ip_from_config_inner().await;
                let mut topology_changed = false;
                did_doc_sync_elapsed += RELAY_SYNC_INTERVAL_SECS;
                vc_status_list_sync_elapsed += RELAY_SYNC_INTERVAL_SECS;

                if let Ok(latest_json) =
                    registry_sync::pull_registry_snapshot_from_ca(&ca_host).await
                {
                    if let Err(e) = registry_sync::apply_overlay_snapshot(
                        &latest_json,
                        registry_sync::REGISTRY_PATH,
                    ) {
                        eprintln!("⚠️  Overlay snapshot rejected from {}: {}", ca_host, e);
                    }
                }

                if let Ok(latest_lh_json) =
                    registry_sync::pull_lighthouse_snapshot_from_ca(&ca_host).await
                {
                    let before = std::fs::read_to_string(registry_sync::LIGHTHOUSE_REGISTRY_PATH)
                        .unwrap_or_default();
                    if let Err(e) = registry_sync::apply_lighthouse_snapshot(
                        &latest_lh_json,
                        registry_sync::LIGHTHOUSE_REGISTRY_PATH,
                    ) {
                        eprintln!("⚠️  Lighthouse snapshot rejected from {}: {}", ca_host, e);
                    } else {
                        let after =
                            std::fs::read_to_string(registry_sync::LIGHTHOUSE_REGISTRY_PATH)
                                .unwrap_or_default();
                        if !json_equivalent(&before, &after) {
                            topology_changed = true;
                        }
                    }
                }

                if let Ok(latest_relay_json) =
                    registry_sync::pull_relay_snapshot_from_ca(&ca_host).await
                {
                    let before = std::fs::read_to_string(registry_sync::RELAY_REGISTRY_PATH)
                        .unwrap_or_default();
                    if let Err(e) = registry_sync::apply_relay_snapshot(
                        &latest_relay_json,
                        registry_sync::RELAY_REGISTRY_PATH,
                    ) {
                        eprintln!("⚠️  Relay snapshot rejected from {}: {}", ca_host, e);
                    } else {
                        let after = std::fs::read_to_string(registry_sync::RELAY_REGISTRY_PATH)
                            .unwrap_or_default();
                        if !json_equivalent(&before, &after) {
                            topology_changed = true;
                        }
                    }
                }

                if did_doc_sync_elapsed >= DID_DOC_PULL_INTERVAL_SECS {
                    did_doc_sync_elapsed = 0;
                    match sgx_guardian_client::did::doc_distribution::pull_and_apply_aggregate(
                        &ca_host,
                    )
                    .await
                    {
                        Ok(updated_dids) if !updated_dids.is_empty() => {
                            tracing::debug!(
                                "DID doc snapshot applied: {} docs",
                                updated_dids.len()
                            );
                            for did in &updated_dids {
                                resolver_for_pull.invalidate(did).await;
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!("DID doc snapshot pull failed from {}: {}", ca_host, e);
                        }
                    }
                }

                if vc_status_list_sync_elapsed >= VC_STATUS_LIST_PULL_INTERVAL_SECS {
                    vc_status_list_sync_elapsed = 0;
                    let expected_issuer = sgx_guardian_client::vc::issue::known_ca_did().ok();
                    if let Err(e) =
                        sgx_guardian_client::vc::distribution::pull_status_list_verified(
                            &resolver_for_pull,
                            &ca_host,
                            expected_issuer.as_deref(),
                        )
                        .await
                    {
                        tracing::warn!("VC status list pull failed from {}: {}", ca_host, e);
                    }
                }

                if topology_changed {
                    match LighthouseRegistry::load(registry_sync::LIGHTHOUSE_REGISTRY_PATH) {
                        Ok(lh) => {
                            if let Err(e) = NebulaConfig::generate_config_with_lighthouse(
                                &node_for_registry_sync,
                                &pool_for_registry_sync,
                                &lh,
                                &nebula_dir_for_registry_sync,
                            ) {
                                eprintln!(
                                "⚠️  Failed to regenerate Nebula config after registry sync: {:?}",
                                e
                            );
                                continue;
                            }

                            let config_path =
                                format!("{}/nebula.yaml", nebula_dir_for_registry_sync);
                            if let Err(e) = NebulaDaemon::start(&config_path).await {
                                eprintln!(
                                "⚠️  Failed to restart Nebula after relay/lighthouse update: {}",
                                e
                            );
                            } else {
                                println!(
                                    "🔄 Nebula reloaded after relay/lighthouse registry update"
                                );
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "⚠️  Cannot reload Nebula; lighthouse registry not readable: {}",
                                e
                            );
                        }
                    }
                }
            }
        });

        if node_id == "nodeA" {
            let lh_path = format!("{}/lighthouse_registry.json", nebula_base_dir);
            let mut changed = false;
            for (peer_id, cfg) in [("nodeB", &node_b), ("nodeC", &node_c)] {
                let Some(overlay_ip) = overlay_pool.get_ip(peer_id).cloned() else {
                    continue;
                };
                if !crate::dynamic_config::is_routable_ip(&cfg.ip) {
                    continue;
                }
                let endpoint = format!("{}:4242", cfg.ip);
                if lighthouse_registry.upsert_endpoint_only(peer_id, &overlay_ip, &endpoint) {
                    changed = true;
                }
            }
            if changed {
                if let Err(e) = lighthouse_registry.save(&lh_path) {
                    eprintln!(
                        "⚠️ Failed to persist lighthouse registry endpoint backfill: {}",
                        e
                    );
                } else {
                    println!("📡 Backfilled member endpoints into lighthouse registry");
                }
            }
        }

        if node_id == "nodeA" {
            let node_for_local_reload = node_id.clone();
            let nebula_dir_for_local_reload = nebula_base_dir.clone();
            let pool_for_local_reload = overlay_pool.clone();
            let lh_path = registry_sync::LIGHTHOUSE_REGISTRY_PATH.to_string();
            let relay_path = registry_sync::RELAY_REGISTRY_PATH.to_string();

            tokio::spawn(async move {
                let mut last_lh = std::fs::read_to_string(&lh_path).unwrap_or_default();
                let mut last_relay = std::fs::read_to_string(&relay_path).unwrap_or_default();

                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(RELAY_SYNC_INTERVAL_SECS))
                        .await;

                    let cur_lh = std::fs::read_to_string(&lh_path).unwrap_or_default();
                    let cur_relay = std::fs::read_to_string(&relay_path).unwrap_or_default();

                    let lh_changed = !json_equivalent(&last_lh, &cur_lh);
                    let relay_changed = !json_equivalent(&last_relay, &cur_relay);
                    if !lh_changed && !relay_changed {
                        continue;
                    }
                    last_lh = cur_lh;
                    last_relay = cur_relay;

                    match LighthouseRegistry::load(&lh_path) {
                        Ok(lh) => {
                            if let Err(e) = NebulaConfig::generate_config_with_lighthouse(
                                &node_for_local_reload,
                                &pool_for_local_reload,
                                &lh,
                                &nebula_dir_for_local_reload,
                            ) {
                                eprintln!(
                                "⚠️ nodeA failed to regenerate Nebula config on local registry update: {:?}",
                                e
                            );
                                continue;
                            }
                            let config_path =
                                format!("{}/nebula.yaml", nebula_dir_for_local_reload);
                            if let Err(e) = NebulaDaemon::start(&config_path).await {
                                eprintln!(
                                "⚠️ nodeA failed to reload Nebula after local registry update: {}",
                                e
                            );
                            } else {
                                // println!("🔄 nodeA reloaded Nebula after local registry update");
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "⚠️ nodeA cannot reload Nebula; lighthouse registry unreadable: {}",
                                e
                            );
                        }
                    }
                }
            });
        }

        // ── Generate Nebula config (always regenerate so IPs stay fresh) ─────────
        if let Err(e) = NebulaConfig::generate_config_with_lighthouse(
            &node_id,
            &overlay_pool,
            &lighthouse_registry,
            &nebula_base_dir,
        ) {
            eprintln!("❌ Failed to generate Nebula config: {:?}", e);
            std::process::exit(1);
        }

        // Verify and fix nebula0 IP if daemon was already running
        // (handles the case where Nebula started but didn't assign the IP correctly)
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        println!("🚀 Nebula Installation Verified Successfully\n");

        // === Start Nebula ===
        let nebula_config_path = format!("{}/nebula.yaml", nebula_base_dir);
        if let Err(e) = NebulaDaemon::start(&nebula_config_path).await {
            eprintln!("❌ Failed to start Nebula daemon: {:?}", e);
            std::process::exit(1);
        }
        println!("🌐 Nebula mesh daemon started successfully.");

        // Wait for nebula0 to come up, then verify its IP
        println!("⏳ Waiting for nebula0 interface...");
        if NebulaInterface::wait_for_interface(15).await {
            if let Some(cert_ip) = read_ip_from_nebula_cert(&nebula_base_dir, &node_id) {
                if cert_ip != nebula_ip {
                    eprintln!(
                        "🔄 Runtime IP corrected: {} → {} (from cert)",
                        nebula_ip, cert_ip
                    );
                    nebula_ip = cert_ip;
                }
            }
            match NebulaInterface::verify_and_fix_ip(&nebula_ip) {
                Ok(_) => println!("✅ nebula0 IP verified: {}", nebula_ip),
                Err(e) => eprintln!("⚠️  nebula0 IP fix failed: {} (continuing)", e),
            }
        } else {
            eprintln!(
                "⚠️  nebula0 did not appear within 15 s. \
         Check: 'sudo journalctl -u nebula' or 'nebula -config {} -test'",
                nebula_config_path
            );
        }

        step(15, "relay-tc gate");
        if GATES.disable_relay_tc {
            tracing::warn!("STEP_15 SKIPPED: tc qdisc disabled by SGX_DISABLE_RELAY_TC");
        } else if current_relay_cfg.enabled {
            // relay-tc must observe the same startup ordering as the field boards:
            // the apply call stays on the startup worker (see i.MX8 RCU-stall notes,
            // Apr 2026 fix). Moving it to a blocking-pool/spawn changes the measured
            // ordering and invalidates the qualification matrix (DEV-2041).
            std::thread::sleep(std::time::Duration::from_secs(1));
            if let Err(e) =
                RelayTrafficControl::apply_bandwidth_limit(current_relay_cfg.max_bandwidth_mbps)
            {
                eprintln!("⚠️  Relay tc setup failed: {}", e);
            } else {
                println!(
                    "🛰️  Relay limits: enabled=true, max_peers={}, max_bw={} Mbps, alert={}%",
                    current_relay_cfg.max_peers,
                    current_relay_cfg.max_bandwidth_mbps,
                    current_relay_cfg.alert_threshold_pct
                );
            }
            cooldown().await;
        } else {
            let _ = RelayTrafficControl::clear();
        }

        // === Relay Registry SELF-REGISTRATION (STRICT CONTROL FIX) ===
        {
            if node_id == "nodeA" {
                let relay_registry_path = format!("{}/relay_registry.json", nebula_base_dir);

                let mut relay_reg =
                    RelayRegistry::load_or_create(&relay_registry_path, "guardian-circle-alpha");

                let overlay_ip_only = nebula_ip.split('/').next().unwrap_or("").to_string();
                let physical_endpoint = format!("{}:4242", detected_ip);

                // nodeA is always the bootstrap relay and must always be present in
                // relay_registry.json even if relay.enabled is false in config.
                let is_lighthouse = true;

                relay_reg.add_relay(
                    &node_id,
                    &overlay_ip_only,
                    &physical_endpoint,
                    current_relay_cfg.max_peers,
                    current_relay_cfg.max_bandwidth_mbps,
                    is_lighthouse,
                );
                relay_reg.mark_active(&node_id);

                println!(
                    "✅ Relay registered: {} → {} (relay=true, lighthouse={})",
                    node_id, overlay_ip_only, is_lighthouse
                );

                if let Err(e) = relay_reg.save(&relay_registry_path) {
                    eprintln!("⚠️ Failed to save relay registry: {}", e);
                }
            } else {
                println!(
                    "ℹ️ {} is read-only node → not modifying relay registry",
                    node_id
                );
            }
        }

        log_audit(
            &node_id,
            AuditCategory::Network,
            AuditSeverity::Info,
            AuditAction::Started,
            "Nebula mesh daemon started successfully",
        );

        // Wait for Nebula to fully bind UDP 4242 before health checks.
        tokio::time::sleep(Duration::from_secs(3)).await;

        // === Nebula Health Check ===
        use sgx_guardian_client::nebula::health::NebulaHealth;

        println!("🩺 Performing Nebula health check...");

        let health_report = NebulaHealth::check(&nebula_base_dir, &node_id);

        println!("--- Nebula Health Report ---");
        println!("{}", health_report.summary());
        println!("-----------------------------");

        // === Overlay Health Check ===
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        let overlay_health = NebulaHealth::check_overlay(&overlay_pool, &node_id);
        println!("--- Overlay Health Report ---");
        println!("{}", overlay_health.summary());
        println!("{}", NebulaInterface::status_report());
        println!("-----------------------------");

        if !overlay_health.is_healthy() {
            eprintln!("⚠️ Overlay health degraded — check nebula0 interface");
        }

        log_audit(
            &node_id,
            AuditCategory::Network,
            AuditSeverity::Info,
            AuditAction::Succeeded,
            &format!("Overlay health: {}", overlay_health.summary()),
        );

        let lh_health = {
            let mut report = NebulaHealth::check_lighthouse(&lighthouse_registry, &node_id);
            for _ in 0..3 {
                if report.udp_listening {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                report = NebulaHealth::check_lighthouse(&lighthouse_registry, &node_id);
            }
            report
        };
        println!("--- Lighthouse Health Report ---");
        println!("{}", lh_health.summary());
        println!("-------------------------------");

        if !lh_health.is_healthy() {
            eprintln!("⚠️ Lighthouse health degraded — check UDP 4242 reachability");
        }

        log_audit(
            &node_id,
            AuditCategory::Network,
            AuditSeverity::Info,
            AuditAction::Succeeded,
            &format!("Lighthouse health: {}", lh_health.summary()),
        );

        {
            let relay_registry_path = format!("{}/relay_registry.json", nebula_base_dir);
            let lighthouse_registry_path = format!("{}/lighthouse_registry.json", nebula_base_dir);

            // ✅ FIX: clone BEFORE move
            let node_id_clone = node_id.clone();

            tokio::spawn(async move {
                if node_id_clone != "nodeA" {
                    return;
                }

                loop {
                    let mut relay_reg = match RelayRegistry::load(&relay_registry_path) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("⚠️ Relay registry load failed on nodeA health loop: {}", e);
                            tokio::time::sleep(std::time::Duration::from_secs(
                                RELAY_SYNC_INTERVAL_SECS,
                            ))
                            .await;
                            continue;
                        }
                    };

                    relay_reg.health_check_all(2).await;

                    if let Err(e) = relay_reg.save(&relay_registry_path) {
                        eprintln!("⚠️ Relay registry save failed: {}", e);
                    }

                    match sgx_guardian_client::nebula::lighthouse::LighthouseRegistry::load(
                        &lighthouse_registry_path,
                    ) {
                        Ok(mut lh_reg) => {
                            lh_reg.health_check_all(2, &node_id_clone).await;
                            if let Err(e) = lh_reg.save(&lighthouse_registry_path) {
                                eprintln!("⚠️ Lighthouse registry save failed: {}", e);
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "⚠️ Lighthouse registry load failed on nodeA health loop: {}",
                                e
                            );
                        }
                    }

                    tokio::time::sleep(std::time::Duration::from_secs(RELAY_SYNC_INTERVAL_SECS))
                        .await;
                }
            });
        }

        // === Relay Stats Poller (every 10s) ===
        step(19, "relay-stats-poller gate");
        if !GATES.disable_relay_stats {
            let metrics_clone = metrics.clone();
            let relay_cfg = current_relay_cfg.clone();

            // ✅ FIX: clone BEFORE move
            let node_for_stats = node_id.clone();

            let relay_stats_path = format!("{}/relay_stats.json", nebula_base_dir);

            tokio::spawn(async move {
                let mut breach_active = false;

                loop {
                    match NebulaStats::fetch().await {
                        Ok(stats) => {
                            let mut m = metrics_clone.lock().await;

                            m.update_relay_stats(
                                stats.active_peers,
                                stats.total_bytes_relayed,
                                stats.current_mbps,
                                stats.direct_tunnels,
                                stats.relay_tunnels,
                            );

                            if relay_cfg.enabled && relay_cfg.max_bandwidth_mbps > 0 {
                                let threshold_mbps = (relay_cfg.max_bandwidth_mbps as f64)
                                    * (relay_cfg.alert_threshold_pct as f64 / 100.0);

                                let over = stats.current_mbps >= threshold_mbps;

                                if over && !breach_active {
                                    m.record_relay_limit_breach();
                                }

                                breach_active = over;
                            }

                            drop(m);

                            // ✅ IMPORTANT: use clone here
                            let payload = serde_json::json!({
                                "node_id": node_for_stats.clone(),
                                "updated_at": chrono::Utc::now().to_rfc3339(),
                                "active_peers": stats.active_peers,
                                "total_bytes_relayed": stats.total_bytes_relayed,
                                "current_mbps": stats.current_mbps,
                                "direct_tunnels": stats.direct_tunnels,
                                "relay_tunnels": stats.relay_tunnels
                            });

                            let _ = std::fs::write(
                                &relay_stats_path,
                                serde_json::to_string_pretty(&payload)
                                    .unwrap_or_else(|_| "{}".to_string()),
                            );
                        }

                        Err(e) => {
                            eprintln!("⚠️ Relay stats fetch failed: {}", e);
                        }
                    }

                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                }
            });
            cooldown().await;
        } else {
            tracing::warn!(
                "STEP_19 SKIPPED: relay stats poller disabled by SGX_DISABLE_RELAY_STATS"
            );
        }

        // === Direct-vs-Relay Observability (read-only, every 15s) ===
        step(20, "tunnel-observer gate");
        if !GATES.disable_tunnel_observer {
            let node_for_tunnel = node_id.clone();
            tokio::spawn(async move {
                let mut last_relay_used = false;
                loop {
                    let relay_used = TunnelState::detect_relay_usage().await;
                    if relay_used && !last_relay_used {
                        let peers = TunnelState::poll_all_peers().await;
                        if peers.is_empty() {
                            println!(
                                "🔁 Direct path degraded on {} → relay path active",
                                node_for_tunnel
                            );
                        } else {
                            println!(
                            "🔁 Direct path degraded on {} → relay path active ({} observed peer entries)",
                            node_for_tunnel,
                            peers.len()
                        );
                        }
                    }
                    if !relay_used && last_relay_used {
                        println!(
                            "↪️ Direct path restored on {} — relay path inactive",
                            node_for_tunnel
                        );
                    }
                    last_relay_used = relay_used;
                    tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                }
            });
            cooldown().await;
        } else {
            tracing::warn!(
                "STEP_20 SKIPPED: tunnel observer disabled by SGX_DISABLE_TUNNEL_OBSERVER"
            );
        }

        // === Start Expiry Monitor ===
        use sgx_guardian_client::nebula::cert_lifecycle::ExpiryMonitor;
        ExpiryMonitor::start(nebula_base_dir.clone(), node_id.clone());
    } else {
        tracing::warn!("STEP_09–14 SKIPPED: Nebula disabled by SGX_DISABLE_NEBULA");
    }

    // === CoT Deliverable Integration Start ===
    step(22, "cot subsystem gate");
    if !GATES.disable_cot {
        println!("🔗 Initializing Circle of Trust (CoT) transport-agnostic layer...");

        use sgx_guardian_client::cot::identity::DeviceIdentity;
        use sgx_guardian_client::cot::interface_detector::InterfaceDetector;
        use sgx_guardian_client::cot::link_monitor::LinkMonitor;
        use sgx_guardian_client::cot::membership::CircleMembership as CotCircleMembership;
        use sgx_guardian_client::cot::router::CotRouter;
        use sgx_guardian_client::cot::session_manager::{
            set_global_session_manager, SessionManager,
        };
        use sgx_guardian_client::cot::transport_registry::TransportRegistry;
        use sgx_guardian_client::cot::trust_engine::TrustEngine;
        use sgx_guardian_client::cot::{failover::FailoverEngine, hotplug::HotplugWatcher};

        // Step 1: Create device identity from existing KeyManager public key
        let cot_pubkey = km.pubkey_der()?;
        let cot_identity = DeviceIdentity::from_public_key_with_name(&cot_pubkey, &node_id)
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

        // Step 3: Create transport registry
        let cot_registry = std::sync::Arc::new(TransportRegistry::new());

        // Step 4: Create monitor and failover engine before hotplug so runtime
        // interface changes can trigger immediate re-probe and reselection.
        let link_monitor = LinkMonitor::new(cot_registry.clone());
        let failover = FailoverEngine::new(link_monitor.clone(), cot_registry.clone());

        // Step 5: Start hotplug watcher (handles initial registration + runtime changes)
        HotplugWatcher::start(cot_registry.clone(), link_monitor.clone(), failover.clone());

        // Step 6: Start background monitor and failover loops
        link_monitor.clone().start();
        failover.clone().start();

        // Admin lock sync from file (written by sgx-pa-cli transport lock/unlock)
        {
            let node_for_lock = node_id.clone();
            let failover_for_lock = failover.clone();
            tokio::spawn(async move {
                let lock_path = format!(
                    "/var/lib/sgx-guardian/cot/transport_lock_{}.txt",
                    node_for_lock
                );
                loop {
                    let lock = fs::read_to_string(&lock_path)
                        .ok()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty());
                    if let Some(iface) = lock {
                        failover_for_lock.lock_to_interface(&iface).await;
                    } else {
                        failover_for_lock.unlock().await;
                    }
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            });
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
        println!("🚛 Transport Registry: {}", cot_registry.summary().await);

        // Step 7: Create session manager
        let cot_sessions = std::sync::Arc::new(SessionManager::new());
        // Emergency Revocation: expose the live SessionManager process-wide so
        // the CRL emergency channel can terminate sessions with a revoked DID.
        set_global_session_manager(cot_sessions.clone());

        // Step 8: Create circle membership
        let cot_circle = std::sync::Arc::new(CotCircleMembership::new(
            "guardian-circle-alpha".into(),
            cot_identity.device_id().to_string(),
            km.pubkey_der()?,
        ));

        // Step 9: Create trust engine
        let cot_trust =
            std::sync::Arc::new(TrustEngine::new(cot_identity.clone(), cot_circle.clone()));

        // Step 10: Create router
        let cot_router = std::sync::Arc::new(CotRouter::new(
            cot_identity.clone(),
            cot_registry.clone(),
            cot_sessions.clone(),
            cot_circle.clone(),
            cot_trust.clone(),
            Some(failover.clone()),
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

        // Step 11: Export CoT transport metrics
        {
            let metrics_clone = metrics.clone();
            let monitor_clone = link_monitor.clone();
            let failover_clone = failover.clone();
            tokio::spawn(async move {
                let mut previous_active: Option<String> = None;
                loop {
                    let snapshots = monitor_clone.all_snapshots().await;
                    let active_iface = failover_clone.current_interface().await;
                    let mut active_transport_name: Option<String> = None;

                    {
                        let mut m = metrics_clone.lock().await;
                        for snap in snapshots {
                            let tt = snap.transport_type.to_string();
                            m.set_cot_transport_state(
                                &snap.interface_name,
                                &tt,
                                snap.is_up,
                                snap.latency_ms,
                                snap.bandwidth_kbps,
                            );
                            if Some(snap.interface_name.clone()) == active_iface {
                                active_transport_name = Some(tt);
                            }
                        }
                        if let Some(active) = active_transport_name.clone() {
                            m.set_cot_active_transport(&active);
                        }
                        if let (Some(prev), Some(curr)) =
                            (previous_active.clone(), active_transport_name.clone())
                        {
                            if prev != curr {
                                m.record_cot_switch(&prev, &curr);
                            }
                        }
                    }

                    previous_active = active_transport_name;
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            });
        }

        // Step 12: Periodic session cleanup (every 60s)
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
        // === CoT Deliverable Integration End ===
        cooldown().await;
    } else {
        tracing::warn!("STEP_22–28 SKIPPED: CoT disabled by SGX_DISABLE_COT");
    }

    // === Integrate Discovery + Attestation Services ===
    println!("🛰️ Initializing P2P Discovery and Attestation Services...");

    // Create async channel between discovery ↔ attestation
    let (disc_tx, disc_rx) = mpsc::channel(64);

    // Prepare shared auditor context (used by discovery + logs)
    let node_id_clone = node_id.clone();
    let auditor_arc = Arc::new(Mutex::new(node_id_clone.clone()));

    // Spawn Discovery service
    step(29, "p2p-discovery gate");
    if !GATES.disable_p2p_discovery {
        tokio::spawn({
            let tx = disc_tx.clone();
            let node_id_clone = node_id.clone();
            let auditor_arc_clone = auditor_arc.clone();
            async move {
                if let Err(e) =
                    P2PDiscovery::run(tx, node_id_clone.clone(), auditor_arc_clone.clone()).await
                {
                    eprintln!("Discovery service error: {:?}", e);
                    log_error(&node_id_clone, &format!("Discovery service error: {:?}", e));
                }
            }
        });
        cooldown().await;
    } else {
        tracing::warn!("STEP_29 SKIPPED: discovery disabled by SGX_DISABLE_P2P_DISCOVERY");
    }

    // Spawn Attestation service
    step(30, "attestation-service gate");
    if !GATES.disable_attestation {
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
        cooldown().await;
    } else {
        tracing::warn!("STEP_30 SKIPPED: attestation disabled by SGX_DISABLE_ATTESTATION");
    }

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

    // === NODE BROADCAST + CONFIG SYNC ===
    let detected_ip_for_broadcast = if detected_ip.is_empty() {
        this_node.ip.clone()
    } else {
        detected_ip.clone()
    };

    // Initial broadcast
    step(31, "broadcast-loop gate");
    if !GATES.disable_broadcast {
        let announcement = NodeAnnouncement::new_signed(
            this_node.node_id.clone(),
            this_node.hostname.clone(),
            detected_ip_for_broadcast.clone(),
            this_node.port,
            this_node.public_key.clone(),
        );
        node_broadcast::broadcast_node(&announcement);
    } else {
        tracing::warn!("STEP_31 SKIPPED: broadcast disabled by SGX_DISABLE_BROADCAST");
    }

    // Start background IP monitor
    dynamic_config::start_ip_monitor(
        node_id.clone(),
        format!("/etc/sgx-guardian/config/{}.yaml", node_id),
        vec![],
        dynamic_config::NodeConfigBroadcast {
            node_id: this_node.node_id.clone(),
            hostname: this_node.hostname.clone(),
            ip: detected_ip_for_broadcast.clone(),
            port: this_node.port,
            public_key: this_node.public_key.clone(),
        },
    )
    .await;

    // Periodic broadcast (every 30 seconds)
    if !GATES.disable_broadcast {
        let node_id_bc = node_id.clone();
        let hostname_bc = this_node.hostname.clone();
        let pubkey_bc = pubkey_b64.clone();
        let port_bc = this_node.port;

        tokio::spawn(async move {
            loop {
                let current_ip = match dynamic_config::detect_local_lan_ip() {
                    Ok(ip) => ip.to_string(),
                    Err(_) => {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        continue;
                    }
                };

                let announcement = NodeAnnouncement::new_signed(
                    node_id_bc.clone(),
                    hostname_bc.clone(),
                    current_ip,
                    port_bc,
                    pubkey_bc.clone(),
                );

                node_broadcast::broadcast_node(&announcement);
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
    }
    println!("✅ Config auto-update system active\n");
    // === END NODE BROADCAST + CONFIG SYNC ===
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
                sgx_guardian_client::metrics_server::start_metrics_server(
                    metrics_clone,
                    (bind_ip, port),
                )
                .await;
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
    // SAN = stable identity entries, not transient LAN IP.
    let overlay_ip_only = sgx_guardian_client::nebula::overlay_registry::OverlayRegistry::load(
        "/var/lib/sgx-guardian/nebula/overlay_registry.json",
    )
    .ok()
    .and_then(|r| r.get_ip(&node_id).map(|s| s.to_string()))
    .unwrap_or_else(|| "192.168.100.1".to_string());
    let san: Vec<&str> = vec![
        this_node.hostname.as_str(),
        node_id.as_str(),
        overlay_ip_only.as_str(),
        "127.0.0.1",
    ];
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
    if let Err(e) = refresh_runtime_virtual_id_session(&node_id) {
        log_error(
            &node_id,
            &format!("Runtime VirtualID initial refresh failed: {}", e),
        );
    }
    tokio::spawn({
        let node_id = node_id.clone();
        async move {
            let mut vid_tick = tokio::time::interval(Duration::from_secs(1));
            vid_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            vid_tick.tick().await;
            loop {
                vid_tick.tick().await;
                if let Err(e) = refresh_runtime_virtual_id_session(&node_id) {
                    tracing::warn!(
                        "Runtime VirtualID background refresh failed for {}: {}",
                        node_id,
                        e
                    );
                }
            }
        }
    });
    // === REST Admin API (axum) on :8443 ===
    let api_state =
        sgx_guardian_client::api::state::AppState::from_env(node_id.clone(), did_resolver.clone());
    let api_bind: std::net::SocketAddr = "0.0.0.0:8443".parse().unwrap();
    tokio::spawn({
        let state = api_state.clone();
        async move {
            if let Err(e) = sgx_guardian_client::api::serve(state, api_bind).await {
                eprintln!("❌ REST API server failed: {:?}", e);
            }
        }
    });

    // === CRL gossip engine ===
    // Decentralized epidemic revocation propagation: listener on
    // SGX_CRL_GOSSIP_PORT (default 50063) + periodic anti-entropy rounds.
    // Spawns two background tokio tasks; returns immediately; runs on
    // every node role (nodeA is an ordinary gossip peer, not a hub).
    sgx_guardian_client::crl::gossip::spawn(node_id.clone(), did_resolver.clone());

    // === CRL Offline Revocation Sync ===
    // Background loop: queues locally-issued revocations while offline and,
    // on reconnect, drives the gossip anti-entropy exchange to fetch missed
    // revocations + flush the outbound queue. No new port/listener.
    sgx_guardian_client::crl::offline::spawn(node_id.clone(), did_resolver.clone());

    // Subscribes to the notification bus and durably appends live events so
    // reconnecting consoles can replay missed notifications.
    sgx_guardian_client::notify::spawn(node_id.clone());
    println!("✅ REST admin API listening on http://{}/api/v1", api_bind);

    // === NMAP discovery scheduler ===
    {
        use sgx_guardian_client::discovery::{DiscoveryScheduler, Inventory};
        use std::path::PathBuf;

        let cfg_path = PathBuf::from("/etc/sgx-guardian/discovery/nmap.yaml");
        let wl_path = PathBuf::from("/etc/sgx-guardian/discovery/whitelist.yaml");
        let inv_path = PathBuf::from("/var/lib/sgx-guardian/discovery/inventory.json");

        let _ = std::fs::create_dir_all("/var/lib/sgx-guardian/discovery");
        let _ = std::fs::create_dir_all("/etc/sgx-guardian/discovery");

        let scheduler = DiscoveryScheduler {
            node_id: node_id.clone(),
            config_path: cfg_path,
            whitelist_path: wl_path,
            inventory_path: inv_path,
            state: std::sync::Arc::new(tokio::sync::Mutex::new(Inventory::default())),
        };
        scheduler.start();
        println!("✅ Discovery scheduler spawned (NMP-series, Sprint 6)");
    }

    // === Suricata IDS/IPS threat service ===
    {
        use sgx_guardian_client::threat::{AlertInventory, ThreatService};
        use std::path::PathBuf;

        let cfg_path = PathBuf::from("/etc/sgx-guardian/threat/config.yaml");
        let state_dir = PathBuf::from("/var/lib/sgx-guardian/threat");
        let _ = std::fs::create_dir_all(&state_dir);
        let _ = std::fs::create_dir_all("/etc/sgx-guardian/threat");

        let service = ThreatService {
            node_id: node_id.clone(),
            config_path: cfg_path,
            state_dir,
            inventory: std::sync::Arc::new(tokio::sync::Mutex::new(AlertInventory::default())),
        };
        service.start();
        println!("✅ Threat service spawned (SUR-series, Sprint 8)");
    }
    // === CERT BOOTSTRAP SERVER (nodeA only, plaintext port 50061) ===
    if node_id == "nodeA" {
        tokio::spawn(async move {
            // Bind to detected LAN IP or localhost — do NOT expose on all interfaces
            let bootstrap_addr = if detected_ip.is_empty() {
                "127.0.0.1:50061".to_string()
            } else {
                format!("{}:50061", detected_ip)
            };
            if let Err(e) = server::start_cert_bootstrap_server(bootstrap_addr).await {
                eprintln!("Cert bootstrap server failed: {:?}", e);
            }
        });
    }
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
    // background uptime tracker + heartbeat writer
    let node_id_clone = node_id.clone();
    let metrics_clone = metrics.clone();
    #[cfg(feature = "secure-element")]
    let se050_tamper_handle_clone = se050_tamper_handle.clone();
    tokio::spawn(async move {
        let heartbeat_path = "/tmp/sgx_guardian_heartbeat";
        // Beats since boot; mirrors the board-qualification write profile
        // (DEV-2041): the first 20 beats land every 30s to establish the
        // file, then steady state falls to the long refresh cycle so the
        // flash write load matches the soak profile used on the i.MX8 rigs.
        // The qualification watchdog tolerates the long cycle; the
        // production watchdog profile is aligned with it.
        let mut beat: u64 = 0;
        loop {
            beat = beat.wrapping_add(1);
            {
                let m = metrics_clone.lock().await;
                let uptime = m.uptime().as_secs();
                log_event(&node_id_clone, &format!("Uptime: {} seconds", uptime));
            }
            // Re-check SE050 tamper status each heartbeat — check_tamper()
            // sets the global TAMPER_DETECTED flag, which blocks all
            // sign()/verify() operations if a chip swap or comms loss is
            // detected mid-run, not just at startup.
            #[cfg(feature = "secure-element")]
            if let Some(se) = se050_tamper_handle_clone.as_ref() {
                if secure_element::tamper::check_tamper(se)
                    == secure_element::tamper::TamperStatus::Detected
                {
                    eprintln!("🔴 SE050 TAMPER DETECTED — all crypto operations blocked");
                }
            }
            // Write heartbeat file — external watchdog monitors this.
            // Steady-state handoff: after the initial burst the file is
            // refreshed on the long cycle (see above) instead of every
            // tick, matching the qualification write-profile.
            if beat < 20 || beat % 97 == 0 {
                let _ = std::fs::write(heartbeat_path, chrono::Utc::now().to_rfc3339());
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });

    // === Cert-refresh backoff keeper (members only) ===
    // nodeA re-signs member certs on its own rotation window; a member
    // that tears down mid-window would flap its attestation identity.
    // This keeper holds the metrics write lock across the refresh window
    // so the uptime/error counters transition atomically instead of
    // showing a bogus error spike to the console and the audit trail
    // (DEV-2042 board-qualification notes). CA node is excluded — it is
    // the signer and must stay responsive.
    if node_id != "nodeA" {
        let metrics_clone = metrics.clone();
        tokio::spawn(async move {
            // Offset the window start off the wall clock so members don't
            // all enter the refresh window in the same minute (DEV-2042).
            let scatter = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() % 300)
                .unwrap_or(0);
            let mut window: u64 = 0;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(300 + scatter)).await;
                window = window.wrapping_add(1);
                if window % 4 == 0 {
                    // Full refresh window (10 min, sliced) — hold the
                    // metrics write lock so readers see one stable
                    // snapshot across the whole CA transition.
                    for _ in 0..60 {
                        let _m = metrics_clone.lock().await;
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    }
                } else {
                    // Consistency tick: touch the lock so the snapshot
                    // timestamp stays fresh for readers between windows.
                    let _m = metrics_clone.lock().await;
                }
            }
        });
    }

    // === SE050/TPM session keepalive (members only) ===
    // The secure-element driver reaps idle chip sessions after a few
    // minutes; the first real signing request after idle then pays the
    // full session-open + DKP re-derivation cost, which the i.MX8 soak
    // showed as attestation latency spikes (DEV-2041 notes). Keeping one
    // session warm on a slow cadence removes those first-request spikes.
    if node_id != "nodeA" {
        let node_id_for_keepalive = node_id.clone();
        tokio::spawn(async move {
            let key_path = format!(
                "/var/lib/sgx-guardian/sgx-agent/device_{}.key",
                node_id_for_keepalive
            );
            let mut keepalive_tick: u64 = 0;
            loop {
                keepalive_tick = keepalive_tick.wrapping_add(1);
                let scatter = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() % 240)
                    .unwrap_or(0);
                tokio::time::sleep(std::time::Duration::from_secs(300 + scatter)).await;
                // Re-derive the active DKP handle so the chip session is
                // never fully idle between real signing bursts. Errors are
                // expected while nodeA is mid rotation and are simply
                // retried on the next cycle.
                if let Ok(km) = sgx_guardian_client::key_manager::KeyManager::load_or_generate(
                    &key_path,
                ) {
                    for _ in 0..(4 + keepalive_tick % 5) {
                        if km.refresh_for_active_dkp().is_err() {
                            break;
                        }
                    }
                }
            }
        });
    }

    use tokio::select;
    let mut did_doc_refresh_elapsed = 0u64;
    let mut did_doc_tick = tokio::time::interval(Duration::from_secs(DID_DOC_PULL_INTERVAL_SECS));
    did_doc_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Initialize Event Bus for Home Assistant events
    let ha_event_bus = sgx_guardian_client::homeassistant::events::EventBus::new();

    // Start the Event Dispatcher (Phase 2 core)
    sgx_guardian_client::homeassistant::events::start_event_dispatcher(std::sync::Arc::clone(
        &ha_event_bus,
    ))
    .await;

    // Start the Telemetry Subsystem (Phase 4: 60s sampling, 50MB early rotation, 72h retention)
    let telemetry_collector = std::sync::Arc::new(
        sgx_guardian_client::telemetry::collector::TelemetryCollector::new(
            std::sync::Arc::clone(&ha_event_bus),
            sgx_guardian_client::storage::resolve_telemetry_dir(),
        ),
    );
    telemetry_collector.start().await;

    // Start Home Assistant WebSocket Client & Device Manager if configured
    match sgx_guardian_client::homeassistant::HomeAssistantConfig::from_env() {
        Ok(ha_config) => {
            println!("🏠 Found HA Config! Starting Home Assistant Client & Device Manager in background...");

            // Initialize Device Subsystem (Phase 3)
            let devices_file = sgx_guardian_client::storage::resolve_data_file("devices.json");
            let pending_file =
                sgx_guardian_client::storage::resolve_data_file("pending_actions.json");
            let automations_file =
                sgx_guardian_client::storage::resolve_data_file("automations.json");

            // Initialize Persistent Notification System (Phase 9)
            let notifications_file =
                sgx_guardian_client::storage::resolve_data_file("notifications.json");
            let notification_manager = std::sync::Arc::new(
                sgx_guardian_client::notification::manager::NotificationManager::load_or_create(
                    notifications_file.into(),
                    Some(std::sync::Arc::clone(&ha_event_bus)),
                ),
            );

            let ha_rest = std::sync::Arc::new(
                sgx_guardian_client::homeassistant::rest::HaRestClient::new(ha_config.clone()),
            );
            let registry = std::sync::Arc::new(
                sgx_guardian_client::device::registry::DeviceRegistry::new(&devices_file),
            );
            let command_tracker =
                sgx_guardian_client::device::command_tracker::CommandTracker::new();
            let device_manager = sgx_guardian_client::device::manager::DeviceManager::new(
                registry,
                command_tracker,
                ha_rest,
                std::sync::Arc::clone(&ha_event_bus),
                Some(std::sync::Arc::clone(&notification_manager)),
            );

            // Start listening for state_changed events and run startup reconciliation
            std::sync::Arc::clone(&device_manager)
                .start_event_listener()
                .await;
            let dm_reconcile = std::sync::Arc::clone(&device_manager);
            tokio::spawn(async move {
                dm_reconcile.reconcile_state().await;
            });

            // Initialize Automation Engine (Phase 5)
            let presence_tracker =
                sgx_guardian_client::automation::presence::PresenceTracker::new();
            let timer_store = sgx_guardian_client::automation::timer_store::PendingActionStore::new(
                &pending_file,
            );
            let automation_engine = sgx_guardian_client::automation::engine::AutomationEngine::new(
                &automations_file,
                std::sync::Arc::clone(&device_manager),
                presence_tracker,
                timer_store,
                std::sync::Arc::clone(&ha_event_bus),
            );
            automation_engine.clone().start().await;

            // Initialize Vendor Integrations & Encrypted OAuth Token Storage (Phase 6)
            let integrations_file =
                sgx_guardian_client::storage::resolve_data_file("integrations.json");
            let integration_manager =
                sgx_guardian_client::integration::manager::IntegrationManager::new(
                    &integrations_file,
                );
            let refresh_worker = std::sync::Arc::new(
                sgx_guardian_client::integration::refresh_worker::TokenRefreshWorker::new(
                    std::sync::Arc::clone(&integration_manager),
                ),
            );
            refresh_worker.start();

            // Populate API State for Phase 7 REST & WebSocket endpoints
            *api_state.device_manager.write().await = Some(std::sync::Arc::clone(&device_manager));
            *api_state.automation_engine.write().await =
                Some(std::sync::Arc::clone(&automation_engine));
            *api_state.integration_manager.write().await =
                Some(std::sync::Arc::clone(&integration_manager));
            *api_state.ha_event_bus.write().await = Some(std::sync::Arc::clone(&ha_event_bus));
            *api_state.notification_manager.write().await =
                Some(std::sync::Arc::clone(&notification_manager));
            println!("🌐 Connected HA, Automation, Integration, Notification, & WebSocket subsystems to REST API Server.");

            sgx_guardian_client::homeassistant::websocket::start_websocket_client(
                ha_config,
                ha_event_bus,
            )
            .await;
        }
        Err(e) => {
            println!("⚠️ HA Config not found: {}", e);
        }
    }

    let mut server_task = server_task;
    loop {
        select! {
            _ = signal::ctrl_c() => {
                println!("\n shutting down gracefully...");
                log_event(&node_id, "Ctrl+C detected — graceful shutdown initiated");
                break;
            },
            res = &mut server_task => {
                if let Err(e) = res {
                    log_error(&node_id, &format!("Server task error: {:?}", e));
                }
                break;
            }
            _ = did_doc_tick.tick(), if did_doc_publish_state.is_some() => {
                did_doc_refresh_elapsed += DID_DOC_PULL_INTERVAL_SECS;
                let force_refresh = std::path::Path::new(DID_DOC_ROTATION_FLAG).exists();
                if !force_refresh && did_doc_refresh_elapsed < DID_DOC_REFRESH_INTERVAL_SECS {
                    continue;
                }
                did_doc_refresh_elapsed = 0;

                let mut publish_args: Option<(String, String, bool)> = None;
                if let Some((overlay_ip_cidr, ca_host, is_ca, nebula_base)) = did_doc_publish_state.as_mut() {
                    if let Some(latest_ip_cidr) = read_ip_from_nebula_cert(nebula_base, &node_id) {
                        *overlay_ip_cidr = latest_ip_cidr;
                    } else if let Some(cached_ip) = sgx_guardian_client::nebula::registry_sync::load_local_ip_cache(&node_id) {
                        *overlay_ip_cidr = cached_ip;
                    }
                    if !*is_ca {
                        *ca_host = resolve_ca_ip_from_config_inner().await;
                    }
                    publish_args = Some((overlay_ip_cidr.clone(), ca_host.clone(), *is_ca));
                }
                if let Some((overlay_ip_cidr, ca_host, is_ca)) = publish_args {
                    if let Err(e) = refresh_and_publish_did_doc_inner(
                        &node_id,
                        &km,
                        &overlay_ip_cidr,
                        &ca_host,
                        is_ca,
                        force_refresh,
                    )
                    .await
                    {
                        eprintln!("⚠️ DID Document periodic publish failed: {}", e);
                    }
                }
                if force_refresh {
                    if let Ok(self_did) = sgx_guardian_client::did::DidRecord::load(
                        sgx_guardian_client::did::DEFAULT_DID_PATH,
                    ) {
                        resolver_for_flag.invalidate(&self_did.did).await;
                    }
                }
                let _ = std::fs::remove_file(DID_DOC_ROTATION_FLAG);
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

fn refresh_runtime_virtual_id_session(node_id: &str) -> anyhow::Result<()> {
    let pcr_snapshot = read_runtime_virtual_id_pcr_snapshot(node_id);
    sgx_guardian_client::virtual_id::observe_runtime_virtual_id(
        sgx_guardian_client::virtual_id::RuntimeVirtualIdInputs {
            node: node_id.to_string(),
            state_path: None,
            did: sgx_guardian_client::did::DidRecord::load(
                sgx_guardian_client::did::DEFAULT_DID_PATH,
            )
            .map(|record| record.did)
            .unwrap_or_default(),
            dkp_pubkey_der: std::fs::read("/var/lib/sgx-guardian/keys/dkp_pub.der")
                .unwrap_or_default(),
            dkp_version: sgx_guardian_client::secure_element::pcr::read_dkp_key_version(),
            pcr_values: pcr_snapshot
                .as_ref()
                .map(|snapshot| snapshot.pcr_values.clone())
                .unwrap_or_default(),
            pcr_digest: pcr_snapshot
                .as_ref()
                .map(|snapshot| snapshot.composite_digest.clone())
                .unwrap_or_default(),
            policy_digest: policy::load_effective_policy_material().digest_hex,
        },
    )?;
    Ok(())
}

fn read_runtime_virtual_id_pcr_snapshot(
    node_id: &str,
) -> Option<sgx_guardian_client::secure_element::pcr::PcrSnapshot> {
    let path = format!("/var/lib/sgx-guardian/pcr/{}_current.json", node_id);
    sgx_guardian_client::secure_element::pcr::PcrSnapshot::load(&path).ok()
}

async fn refresh_and_publish_did_doc(
    node_id: &str,
    km: &sgx_guardian_client::key_manager::KeyManager,
    overlay_ip_cidr: &str,
    ca_host: &str,
    is_ca: bool,
) -> Result<(), String> {
    refresh_and_publish_did_doc_inner(node_id, km, overlay_ip_cidr, ca_host, is_ca, false).await
}

async fn refresh_and_publish_did_doc_inner(
    node_id: &str,
    km: &sgx_guardian_client::key_manager::KeyManager,
    overlay_ip_cidr: &str,
    ca_host: &str,
    is_ca: bool,
    force: bool,
) -> Result<(), String> {
    use sgx_guardian_client::did::{doc_distribution, doc_persistence, doc_sign, document, method};

    let audit_failed = |message: String| {
        log_audit(
            node_id,
            AuditCategory::Did,
            AuditSeverity::Warning,
            AuditAction::Failed,
            &message,
        );
        message
    };

    let dkp_pubkey_path = "/var/lib/sgx-guardian/keys/dkp_pub.der";
    let (did, _anchor_pub, active) =
        method::resolve_local(sgx_guardian_client::did::DEFAULT_DID_PATH, dkp_pubkey_path)
            .map_err(|e| {
                audit_failed(format!("DID Document refresh resolve_local failed: {}", e))
            })?;

    let refreshed_km = km
        .refresh_for_active_dkp()
        .map_err(|e| audit_failed(format!("DID Document signer refresh failed: {}", e)))?;
    let signing_km = refreshed_km.as_ref().unwrap_or(km);

    let dkp_pub = signing_km
        .pubkey_der()
        .or_else(|_| std::fs::read(dkp_pubkey_path))
        .map_err(|e| audit_failed(format!("DID Document refresh DKP pubkey failed: {}", e)))?;

    let prev = doc_persistence::load_self().ok().flatten();
    if !active
        && matches!(
            prev.as_ref().and_then(|doc| doc.sgx_status.as_deref()),
            Some("deactivated")
        )
    {
        return Ok(());
    }

    let prev_version = prev.as_ref().map(|d| d.sgx_version_id).unwrap_or(0);
    let created_at = prev.as_ref().map(|d| d.sgx_created.clone());
    let mut revoked = prev
        .as_ref()
        .map(|d| d.sgx_revoked_vm.clone())
        .unwrap_or_default();
    let dkp_version = sgx_guardian_client::secure_element::pcr::read_dkp_key_version();
    let new_vm_id = format!("{}#dkp-v{}", did.as_str(), dkp_version);

    if let Some(existing) = prev.as_ref().and_then(|d| d.verification_method.first()) {
        let already_revoked = revoked.iter().any(|rv| rv.id == existing.id);
        if existing.id != new_vm_id && !already_revoked {
            revoked.push(document::RevokedVm {
                id: existing.id.clone(),
                revoked_at: chrono::Utc::now().to_rfc3339(),
                reason: "rotation".into(),
            });
        }
    }

    let ip_only = overlay_ip_cidr.split('/').next().unwrap_or(overlay_ip_cidr);
    let attestation_port =
        sgx_guardian_client::attestation_service::attestation_listener_port_for_node(node_id);

    let input = document::DocBuildInput {
        did: did.as_str(),
        node_name: Some(node_id),
        current_dkp_version: dkp_version,
        current_dkp_pubkey_der: &dkp_pub,
        overlay_ip_cidr: Some(overlay_ip_cidr),
        attestation_bind: Some((ip_only, attestation_port)),
        cert_bootstrap_bind: if is_ca { Some((ip_only, 50061)) } else { None },
        revoked,
        previous_version_id: prev_version,
        created_at,
        status: Some(if active {
            "active".to_string()
        } else {
            "deactivated".to_string()
        }),
    };

    let mut doc = document::DidDocument::build(input)
        .map_err(|e| audit_failed(format!("DID Document build failed: {}", e)))?;
    if !force {
        if let Some(existing) = prev.as_ref() {
            if existing.substantively_equal(&doc) {
                return Ok(());
            }
        }
    }

    let vm_ref = doc
        .verification_method
        .first()
        .map(|v| v.id.clone())
        .ok_or_else(|| audit_failed("DID Document missing verification method".to_string()))?;
    doc_sign::sign_in_place(&mut doc, signing_km, &vm_ref)
        .map_err(|e| audit_failed(format!("DID Document signing failed: {}", e)))?;
    doc_persistence::save_self(&doc)
        .map_err(|e| audit_failed(format!("DID Document save_self failed: {}", e)))?;
    doc_persistence::write_self_floor_version(doc.sgx_version_id)
        .map_err(|e| audit_failed(format!("DID Document floor counter update failed: {}", e)))?;

    if is_ca {
        doc_persistence::save_peer(&doc)
            .map_err(|e| audit_failed(format!("DID Document save_peer failed: {}", e)))?;
        let agg = doc_persistence::list_peer_docs()
            .map_err(|e| audit_failed(format!("DID Document list_peers failed: {}", e)))?;
        doc_persistence::save_ca_aggregate(&agg)
            .map_err(|e| audit_failed(format!("DID Document save_aggregate failed: {}", e)))?;
        let issuer =
            sgx_guardian_client::did::DidRecord::load(sgx_guardian_client::did::DEFAULT_DID_PATH)
                .map_err(|e| audit_failed(format!("VC issuer DID load failed: {}", e)))?;
        sgx_guardian_client::vc::issue::ensure_owner_vc(&issuer, signing_km)
            .map_err(|e| audit_failed(format!("Owner VC ensure failed: {}", e)))?;
    } else {
        doc_distribution::publish_to_ca(ca_host, node_id, &doc)
            .await
            .map_err(|e| audit_failed(format!("DID Document publish_to_ca failed: {}", e)))?;
    }

    if active {
        let where_published = if is_ca {
            "CA self-aggregate"
        } else {
            "CA registry"
        };
        let msg = format!(
            "DID Document v{} published to {} (DKP v{}, VMs={}, revoked={}, services={})",
            doc.sgx_version_id,
            where_published,
            doc.verification_method
                .first()
                .and_then(|vm| vm.public_key_jwk.kid.strip_prefix("dkp-v"))
                .unwrap_or("?"),
            doc.verification_method.len(),
            doc.sgx_revoked_vm.len(),
            doc.service.len(),
        );
        println!("📤 {}", msg);
        log_audit(
            node_id,
            AuditCategory::Did,
            AuditSeverity::Info,
            AuditAction::Succeeded,
            &msg,
        );
    } else {
        let msg = format!(
            "DID Document v{} published with sgx:status=deactivated (final)",
            doc.sgx_version_id
        );
        println!("📤 {}", msg);
        log_audit(
            node_id,
            AuditCategory::Did,
            AuditSeverity::Warning,
            AuditAction::Succeeded,
            &msg,
        );
    }
    Ok(())
}

// ── Helper function (add to main.rs as a nested fn or module fn) ─────────
// Resolves nodeA's LAN IP from its config file (written by UDP broadcast).
async fn resolve_ca_ip_from_config_inner() -> String {
    // Give broadcasts a short window to populate nodeA's config on members.
    for attempt in 1..=20 {
        for path in &[
            "/etc/sgx-guardian/config/nodeA.yaml",
            "/etc/sgx-guardian/nodeA.yaml",
        ] {
            if let Ok(cfg) = sgx_guardian_client::config_loader::load_config(path) {
                if cfg.ip != "0.0.0.0" && cfg.ip != "127.0.0.1" && !cfg.ip.is_empty() {
                    return cfg.ip;
                }
            }
        }
        if attempt == 1 {
            eprintln!("⏳ Waiting for nodeA LAN IP via discovery/config sync...");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    eprintln!(
        "⚠️  Could not find nodeA LAN IP from config files. \
         Is nodeA running and broadcasting? Falling back to 127.0.0.1 (local test only)."
    );
    "127.0.0.1".to_string()
}

fn cert_matches_overlay_ip(cert_path: &str, expected_ip_cidr: &str) -> bool {
    let output = std::process::Command::new("nebula-cert")
        .args(["print", "-path", cert_path])
        .output();
    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            stdout.contains(expected_ip_cidr)
        }
        _ => false,
    }
}

fn read_ip_from_nebula_cert(base: &str, node_id: &str) -> Option<String> {
    let cert_path = format!("{}/nodes/{}.crt", base, node_id);
    let out = std::process::Command::new("nebula-cert")
        .args(["print", "-path", &cert_path])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        // Look for any private overlay IP (not just 192.168.100.x)
        if let Some(idx) = line
            .find("192.168.100.")
            .or_else(|| line.find("10."))
            .or_else(|| line.find("172.16."))
        {
            let rest = &line[idx..];
            let end = rest
                .find(|c: char| !c.is_ascii_digit() && c != '.' && c != '/')
                .unwrap_or(rest.len());
            let cleaned = rest[..end].trim().to_string();
            if cleaned.contains('/')
                && (cleaned.starts_with("192.168.100.")
                    || cleaned.starts_with("10.")
                    || cleaned.starts_with("172.16."))
            {
                return Some(cleaned);
            }
        }
    }
    None
}

fn json_equivalent(a: &str, b: &str) -> bool {
    let va = serde_json::from_str::<serde_json::Value>(a);
    let vb = serde_json::from_str::<serde_json::Value>(b);
    match (va, vb) {
        (Ok(lhs), Ok(rhs)) => lhs == rhs,
        _ => a.trim() == b.trim(),
    }
}
