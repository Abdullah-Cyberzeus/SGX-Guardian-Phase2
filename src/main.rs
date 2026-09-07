//! SG-X Guardian Client entrypoint.
//! Initializes node identity, loads configuration, starts discovery,
//! attestation, metrics tracking, and the gRPC server runtime.

use sgx_guardian_client::attestation_service;
use sgx_guardian_client::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use sgx_guardian_client::audit::logger::{init_audit_logger, log_audit};
use sgx_guardian_client::audit::verifier::AuditVerifier;
use sgx_guardian_client::client::send_ping;
use sgx_guardian_client::config_loader::{CloudConfig, RelayLimitsConfig};
use sgx_guardian_client::key_manager::KeyManager;
#[cfg(feature = "secure-element")]
use sgx_guardian_client::secure_element;
use std::path::Path;

#[allow(unused_imports)]
use sgx_guardian_client::logging::{init_logger, log_error, log_event};
use sgx_guardian_client::metrics::Metrics;
use sgx_guardian_client::nebula::install::NebulaInstall;
use sgx_guardian_client::p2p_discovery::P2PDiscovery;
use sgx_guardian_client::server;
use sgx_guardian_client::server::start_server;
// WiFi + Ethernet discovery imports
use sgx_guardian_client::dynamic_config;
use sgx_guardian_client::node_announcement::NodeAnnouncement;
use sgx_guardian_client::node_broadcast;
use sgx_guardian_client::node_listener;
use sgx_guardian_client::runtime_gates::{cooldown, step, GATES};
use sgx_guardian_client::startup::config as startup_config;
use sgx_guardian_client::startup::json_equivalent;
use sgx_guardian_client::startup::nebula_cert::{
    cert_matches_overlay_ip, read_ip_from_nebula_cert,
};
use sgx_guardian_client::startup::{
    admin_tls, audit_paths, bootstrap, ca_discovery, did_boot, identity, pcr_status, GuardianPaths,
};

use base64::{engine::general_purpose, Engine as _};
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
    let lan_hostname = sgx_guardian_client::lan_name::host_label(&node_id);
    let lan_fqdn = sgx_guardian_client::lan_name::fqdn(&node_id);
    // Networking components are initialized through several independent
    // managers. Export one canonical identity so DHCP and hotspot DNS always
    // advertise the same name as the HTTPS certificate.
    std::env::set_var("SGX_LAN_HOSTNAME", &lan_hostname);
    std::env::set_var("SGX_LAN_FQDN", &lan_fqdn);

    // === FIRST-BOOT FILESYSTEM BOOTSTRAP ===
    // Directory creation, default node configs, the shipped policy schema and
    // pruning of approval requests written by an incompatible binary all live
    // in `startup::bootstrap` so each branch is testable against a tempdir.
    let paths = GuardianPaths::production();
    let report = bootstrap::bootstrap_filesystem(&paths, node_id == "nodeA");
    for dir in &report.directory_failures {
        eprintln!(
            "⚠️ Failed to create {} (may cause issues later)",
            dir.display()
        );
    }
    for name in &report.pruned_approvals {
        eprintln!("🗑️  Removed incompatible old approval YAML: {}", name);
    }
    match &report.schema_digest {
        Some(digest) => println!(
            "📜 Local schema canonical digest: {} (compare to peers — must match)",
            digest
        ),
        None => eprintln!(
            "⚠️ Schema at {} is INVALID or missing — attestation digest will fall back to constant default",
            paths.policy_schema().display()
        ),
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
    let km = identity::initialize_key_manager(&node_id, &node_key_path)?;

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

    // Share the active signing identity with the API, pairing, and calling
    // runtimes instead of reloading independent key-manager instances.
    let km = Arc::new(km);

    // === Crypto Provider Status ===
    match km.backend_name() {
        "SE050" => {
            println!("  Secure Element detected: SE050");
            println!("  Signing provider: SE050 hardware (ECDSA-P256)");
            println!("  RNG source: SE050 TRNG");
        }
        "TPM2" => {
            println!("  TPM detected: TPM 2.0");
            println!("  Signing provider: TPM 2.0 hardware (ECDSA-P256)");
            println!("  RNG source: TPM-backed key operations");
        }
        _ => {
            println!("  Hardware key backend not available");
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

        let boot_status = if GATES.disable_secure_boot_check {
            println!("  Secure boot check disabled by SGX_DISABLE_SECURE_BOOT_CHECK");
            BootChainStatus::unknown()
        } else {
            match tokio::time::timeout(
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
            }
        };
        BootChainStatus::prime_cache(boot_status.clone());
        boot_status.print();

        // Save boot chain status
        let boot_status_path = paths.boot_chain_status(&node_id);
        if let Err(e) = boot_status.save(&boot_status_path.to_string_lossy()) {
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

        let mut pcr_engine = PcrEngine::new();

        // Detect environment
        let is_hardware = pcr_status::running_on_hardware();
        println!(
            "  PCR mode: {}",
            if is_hardware {
                "Hardware (board)"
            } else {
                "Software (simulated)"
            }
        );

        let sources = pcr_status::measurement_sources(&node_id, is_hardware);
        let run = pcr_status::measure_sources(&mut pcr_engine, &sources);
        pcr_status::print_measurement_lines(&run.lines);
        let measurement_errors = run.errors;

        pcr_engine.print_status();

        // Determine integrity status
        let integrity_status = pcr_status::integrity_status(&measurement_errors, &sources);
        match integrity_status {
            pcr_status::IntegrityStatus::Fail => eprintln!(
                "  🔴 CRITICAL: Platform integrity check FAILED — attestation will be rejected by peers"
            ),
            pcr_status::IntegrityStatus::Degraded => {
                println!("  ⚠️ Some measurements failed (non-critical) — status DEGRADED")
            }
            pcr_status::IntegrityStatus::Pass => println!("  Platform integrity: ✅ PASS"),
        }

        // Build snapshot
        let mut snapshot = pcr_engine.snapshot();
        snapshot.measurement_errors = measurement_errors;
        snapshot.integrity_status = integrity_status.as_str().to_string();
        #[cfg(feature = "secure-element")]
        let se_node_uid = if km.backend_name() == "SE050" {
            let se_config = sgx_guardian_client::secure_element::config::SeConfig::default();
            Some(node_device_uid(
                &se_config,
                "/var/lib/sgx-guardian/keys/dkp_pub.der",
                &node_id,
            ))
        } else {
            None
        };
        #[cfg(not(feature = "secure-element"))]
        let se_node_uid: Option<String> = None;

        snapshot.device_uid = se_node_uid
            .unwrap_or_else(|| sgx_guardian_client::key_manager::runtime_device_uid(&node_id));
        snapshot.key_version = read_dkp_key_version();

        // Generate nonce + timestamp
        let mut nonce_bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
        snapshot.nonce = hex::encode(nonce_bytes);
        snapshot.measured_at = chrono::Utc::now().to_rfc3339();

        // Sign: SHA256(composite_bytes || nonce_bytes || timestamp_bytes)  (BINARY concat)
        let sign_hash = pcr_status::composite_sign_hash(
            &snapshot.composite_digest,
            &snapshot.nonce,
            &snapshot.measured_at,
        );

        if let Ok(sig) = km.sign(&sign_hash) {
            snapshot.composite_signature =
                Some(base64::engine::general_purpose::STANDARD.encode(&sig));
            println!(
                "  PCR composite signed by DKP (v{}) ✅",
                snapshot.key_version
            );
        }

        // Save snapshot
        let pcr_path = paths.pcr_snapshot(&node_id).to_string_lossy().into_owned();
        match snapshot.save(&pcr_path) {
            Ok(_) => println!("  PCR snapshot → {}", pcr_path),
            Err(e) => eprintln!("  PCR save failed: {}", e),
        }

        // Compare against baseline
        let baseline_path = paths.pcr_baseline(&node_id);
        if let Ok(baseline) = PcrBaseline::load(&baseline_path.to_string_lossy()) {
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
    for (node, _) in bootstrap::DEFAULT_NODE_PORTS {
        let yaml_file = paths.node_config(node);
        if let Err(e) = dynamic_config::sanitize_config_ip_if_invalid(&yaml_file.to_string_lossy())
        {
            eprintln!("⚠️ Sanitize failed for {}: {:?}", yaml_file.display(), e);
        }
    }

    // Update ONLY current node config with detected IP
    if !detected_ip.is_empty() {
        let config_path = paths.node_config(&node_id);
        let _ = dynamic_config::update_config_ip_if_changed(
            &config_path.to_string_lossy(),
            &detected_ip,
        );
        // Keep main path in sync
        let _ = std::fs::copy(&config_path, paths.node_config_mirror(&node_id));
    }

    println!("\n Loading node configurations...");
    let cohort = startup_config::Cohort::load(&paths);
    for node in [&cohort.node_a, &cohort.node_b, &cohort.node_c] {
        println!(
            "✅ Loaded {}: {} ({}) at {}:{} | key: {}",
            node.node_id, node.node_id, node.hostname, node.ip, node.port, node.public_key
        );
    }

    let current_relay_cfg: RelayLimitsConfig = cohort.relay_limits_for(&node_id);

    // Read the UEP policy YAML file (falls back to a minimal valid document)
    let _yaml_content = startup_config::read_policy_schema_or_fallback(&paths);
    println!("\n Starting inter-node mock communication...");

    // Initialize structured JSON logger
    init_logger(&node_id);
    log_event(&node_id, "Logger initialized for node");
    log_event(&node_id, "Node configuration loading complete");
    // === VERIFY EXISTING AUDIT LOG (tamper detection) ===
    // The pre-init verifier and the writer must agree on one path; that
    // selection lives in `startup::audit_paths` (see FIX #8 there).
    std::fs::create_dir_all(&paths.log_root).ok();
    std::fs::create_dir_all(audit_paths::DEV_LOG_DIR).ok();
    let audit_log = audit_paths::AuditLogPaths::for_node(&paths, &node_id);
    let audit_check_path = audit_log.verification_target();

    if audit_check_path.exists() {
        if let Err(e) = AuditVerifier::verify(&audit_check_path.to_string_lossy()) {
            log_error(
                &node_id,
                &format!("Audit log integrity warning (non-fatal): {}", e),
            );
        }
    }

    // === Initialize Audit Logger (tamper-evident) ===
    init_audit_logger(audit_log.writer_target());
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

    step(9, "Guardian Mesh subsystem gate");
    if !GATES.disable_nebula {
        // === Nebula Installation Verification ===
        println!("\n🔎 Verifying Guardian Mesh Installation...");

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
            Ok(_) => println!("✅ Guardian Mesh binary found"),
            Err(e) => {
                eprintln!("❌ Guardian Mesh binary missing: {}", e);
                log_error(&node_id, &format!("Guardian Mesh binary missing: {}", e));
                std::process::exit(1);
            }
        }
        match NebulaInstall::check_version() {
            Ok(v) => println!("✅ Guardian Mesh version: {}", v.trim()),
            Err(e) => {
                eprintln!("❌ Guardian Mesh version check failed: {}", e);
                std::process::exit(1);
            }
        }
        match NebulaInstall::test_daemon_start() {
            Ok(_) => println!("✅ Guardian Mesh daemon responding"),
            Err(e) => {
                eprintln!("❌ Guardian Mesh daemon test failed: {}", e);
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
                "Guardian Mesh CA verified or generated",
            );

            // Log CA fingerprint so admins can verify all nodes use the same CA
            if let Some(fp) = NebulaCA::ca_fingerprint(&nebula_base_dir) {
                println!("🔏 CA fingerprint: {}", fp);
                log_event(&node_id, &format!("Guardian Mesh CA fingerprint: {}", fp));
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
            } else if !cohort.node_a.ip.is_empty() && cohort.node_a.ip != "0.0.0.0" {
                cohort.node_a.ip.clone()
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
                "Guardian Mesh CA certificate verified or issued for nodeA",
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
                did_boot::refresh_and_publish_did_doc(&node_id, &km, &ip_cidr, "127.0.0.1", true)
                    .await
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
                        ca_discovery::resolve_ca_ip_from_config().await
                    }
                } else {
                    ca_discovery::resolve_ca_ip_from_config().await
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
                did_boot::refresh_and_publish_did_doc(&node_id, &km, &ip_cidr, &ca_lan_ip, false)
                    .await
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
                    "✅ Guardian Mesh certificate + CA cert already present for {}",
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
                    &format!("Existing Guardian Mesh certificate found for {}", node_id),
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
                log_event(
                    &node_id,
                    "Guardian Mesh certificate missing — requesting from CA",
                );

                let ca_address = format!("{}:50061", ca_lan_ip);
                let wants_lh = std::env::var("SGX_WANTS_LIGHTHOUSE")
                    .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
                    .unwrap_or(false);
                let wants_relay = std::env::var("SGX_WANTS_RELAY")
                    .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
                    .unwrap_or(false);
                let pairing_proof = match std::env::var("SGX_GUARDIAN_PAIRING_CODE") {
                    Ok(code) if !code.trim().is_empty() => {
                        let device_did = sgx_guardian_client::did::DidRecord::load(
                            sgx_guardian_client::did::DEFAULT_DID_PATH,
                        )
                        .map(|record| record.did)
                        .map_err(|e| {
                            eprintln!("⚠️ Failed to load DID for pairing bootstrap proof: {}", e);
                            e
                        })
                        .ok();
                        let device_pubkey = km.pubkey_der().map_err(|e| {
                            eprintln!(
                                "⚠️ Failed to load device pubkey for pairing bootstrap proof: {}",
                                e
                            );
                            e
                        });
                        match (device_did, device_pubkey) {
                            (Some(device_did), Ok(device_pubkey)) => {
                                match sgx_guardian_client::api::auth::pairing::build_pairing_proof(
                                    &code,
                                    &node_id,
                                    &device_did,
                                    &device_pubkey,
                                    km.clone(),
                                )
                                .await
                                {
                                    Ok(proof) => Some(proof),
                                    Err(e) => {
                                        eprintln!(
                                            "⚠️ Failed to build pairing bootstrap proof: {}",
                                            e
                                        );
                                        None
                                    }
                                }
                            }
                            _ => None,
                        }
                    }
                    _ => None,
                };

                // BLOCKING: wait until we have the cert before starting Nebula
                sgx_guardian_client::cert_client::request_certificate_from_ca(
                    node_id.clone(),
                    ca_address,
                    ip_cidr.clone(),
                    pubkey_b64.clone(),
                    wants_lh,
                    wants_relay,
                    pairing_proof,
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
                    sgx_guardian_client::config_loader::load_config(&format!(
                        "/etc/sgx-guardian/config/{}.yaml",
                        node_id
                    ))
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
            None => ca_discovery::resolve_ca_ip_from_config().await,
        };
        did_resolver =
            sgx_guardian_client::did::Resolver::new(sgx_guardian_client::did::ResolverConfig {
                ca_host: resolver_ca_host,
                ..Default::default()
            });
        let resolver_for_pull = did_resolver.clone();
        resolver_for_flag = did_resolver.clone();
        let resolver_for_reattest = did_resolver.clone();
        tokio::spawn(async move {
            while let Some(peer_did) = reattest_rx.recv().await {
                let res = match resolver_for_reattest.resolve(&peer_did).await {
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
                let km_for_reattest =
                    match KeyManager::load_or_generate(&node_key_path_for_reattest) {
                        Ok(km) => km,
                        Err(e) => {
                            tracing::warn!("Re-attest: cannot load local key: {}", e);
                            continue;
                        }
                    };
                tracing::info!("Re-attesting with peer {} at {}:{}", peer_did, ip, port);
                let _ =
                    sgx_guardian_client::attestation_service::AttestationService::mutual_attest(
                        ip.to_string(),
                        port,
                        &km_for_reattest,
                    )
                    .await;
            }
        });

        let node_for_registry_sync = node_id.clone();
        let nebula_dir_for_registry_sync = nebula_base_dir.clone();
        let pool_for_registry_sync = overlay_pool.clone();

        tokio::spawn(async move {
            let mut did_doc_sync_elapsed = 0u64;
            let mut vc_status_list_sync_elapsed = 0u64;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(RELAY_SYNC_INTERVAL_SECS)).await;
                let ca_host = ca_discovery::resolve_ca_ip_from_config().await;
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
                                "⚠️  Failed to regenerate Guardian Mesh config after registry sync: {:?}",
                                e
                            );
                                continue;
                            }

                            let config_path =
                                format!("{}/nebula.yaml", nebula_dir_for_registry_sync);
                            if let Err(e) = NebulaDaemon::start(&config_path).await {
                                eprintln!(
                                "⚠️  Failed to restart Guardian Mesh after relay/lighthouse update: {}",
                                e
                            );
                            } else {
                                println!(
                                    "🔄 Guardian Mesh reloaded after relay/lighthouse registry update"
                                );
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "⚠️  Cannot reload Guardian Mesh; lighthouse registry not readable: {}",
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
            for (peer_id, cfg) in [("nodeB", &cohort.node_b), ("nodeC", &cohort.node_c)] {
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
                                "⚠️ nodeA failed to regenerate Guardian Mesh config on local registry update: {:?}",
                                e
                            );
                                continue;
                            }
                            let config_path =
                                format!("{}/nebula.yaml", nebula_dir_for_local_reload);
                            if let Err(e) = NebulaDaemon::start(&config_path).await {
                                eprintln!(
                                "⚠️ nodeA failed to reload Guardian Mesh after local registry update: {}",
                                e
                            );
                            } else {
                                // println!("🔄 nodeA reloaded Nebula after local registry update");
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "⚠️ nodeA cannot reload Guardian Mesh; lighthouse registry unreadable: {}",
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
            eprintln!("❌ Failed to generate Guardian Mesh config: {:?}", e);
            std::process::exit(1);
        }

        // Verify and fix nebula0 IP if daemon was already running
        // (handles the case where Nebula started but didn't assign the IP correctly)
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        println!("🚀 Guardian Mesh Installation Verified Successfully\n");

        // === Start Nebula ===
        let nebula_config_path = format!("{}/nebula.yaml", nebula_base_dir);
        if let Err(e) = NebulaDaemon::start(&nebula_config_path).await {
            eprintln!("❌ Failed to start Guardian Mesh daemon: {:?}", e);
            std::process::exit(1);
        }
        println!("🌐 Guardian Mesh daemon started successfully.");

        // Wait for nebula0 to come up, then verify its IP
        println!("⏳ Waiting for Guardian Mesh interface...");
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
                Ok(_) => println!("✅ Guardian Mesh interface IP verified: {}", nebula_ip),
                Err(e) => eprintln!(
                    "⚠️  Guardian Mesh interface IP fix failed: {} (continuing)",
                    e
                ),
            }
        } else {
            eprintln!(
                "⚠️  Guardian Mesh interface did not appear within 15 s. \
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
            "Guardian Mesh daemon started successfully",
        );

        // Wait for Nebula to fully bind UDP 4242 before health checks.
        tokio::time::sleep(Duration::from_secs(3)).await;

        // === Nebula Health Check ===
        use sgx_guardian_client::nebula::health::NebulaHealth;

        println!("🩺 Performing Guardian Mesh health check...");

        let health_report = NebulaHealth::check(&nebula_base_dir, &node_id);

        println!("--- Guardian Mesh Health Report ---");
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
            eprintln!("⚠️ Overlay health degraded — check Guardian Mesh interface");
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
        tracing::warn!("STEP_09–14 SKIPPED: Guardian Mesh disabled by SGX_DISABLE_NEBULA");
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

    let Some((this_node, peers)) = cohort.split(&node_id) else {
        eprintln!("❌ Unknown node ID: {}", node_id);
        log_error(&node_id, "Unknown node ID provided");
        std::process::exit(1);
    };

    // === NODE BROADCAST + CONFIG SYNC ===
    let detected_ip_for_broadcast = startup_config::broadcast_ip(&detected_ip, &this_node.ip);

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
                startup_config::print_policy_from_yaml(&verified.policy_yaml, "NEW");
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
                    startup_config::print_policy_from_yaml(&backup_yaml, "BACKUP / LAST-ACTIVE");
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
    let san_entries =
        admin_tls::certificate_san(&lan_fqdn, &this_node.hostname, &node_id, &overlay_ip_only);
    let san: Vec<&str> = san_entries.iter().map(String::as_str).collect();
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
    // Start the network runtime and mount its Wi-Fi routes into the same API
    // listener as the embedded frontend.
    let (wifi_router, runtime_manager) = sgx_guardian_client::runtime::start_daemon().await;
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
    if let Err(e) = identity::refresh_runtime_virtual_id_session(&node_id) {
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
                if let Err(e) = identity::refresh_runtime_virtual_id_session(&node_id) {
                    tracing::warn!(
                        "Runtime VirtualID background refresh failed for {}: {}",
                        node_id,
                        e
                    );
                }
            }
        }
    });
    // === REST API (axum) on :8443 ===
    let admin_stores =
        sgx_guardian_client::api::auth::store::AdminStores::new("/var/lib/sgx-guardian/admin");
    sgx_guardian_client::api::auth::store::install_global_admin_stores(admin_stores.clone());
    let device_did =
        sgx_guardian_client::did::DidRecord::load(sgx_guardian_client::did::DEFAULT_DID_PATH)
            .map(|record| record.did)
            .unwrap_or_else(|e| {
                eprintln!("⚠️ Failed to load persisted DID for auth issuer: {}", e);
                sgx_guardian_client::did::Did::from_id_bytes(&[0u8; 32]).to_string()
            });
    let device_pubkey_point = km.pubkey_der().unwrap_or_else(|e| {
        eprintln!("⚠️ Failed to load auth verification key: {}", e);
        Vec::new()
    });
    let api_state = sgx_guardian_client::api::state::AppState::from_env(
        node_id.clone(),
        did_resolver.clone(),
        km.clone(),
        admin_stores,
        device_did,
        device_pubkey_point,
    );
    let chat_grpc_port = startup_config::chat_grpc_port(&node_id);
    tokio::spawn({
        let state = api_state.clone();
        let chat_addr = format!("0.0.0.0:{}", chat_grpc_port);
        async move {
            if let Err(e) = server::start_chat_plaintext_server(chat_addr.clone(), state).await {
                eprintln!(
                    "Chat plaintext gRPC server failed at {}: {:?}",
                    chat_addr, e
                );
            }
        }
    });
    let api_bind: std::net::SocketAddr = "0.0.0.0:8443".parse().unwrap();
    let tls_plan = admin_tls::resolve_admin_tls_from_env(this_node.api_or_default().tls, &node_id);
    if tls_plan.misconfigured {
        eprintln!("❌ REST API TLS misconfigured: require_https=true but tls.enabled=false");
        log_error(
            &node_id,
            "REST API TLS misconfigured: require_https=true but tls.enabled=false",
        );
    } else {
        let tls = tls_plan
            .enabled
            .then(|| sgx_guardian_client::api::AdminTls {
                cert_path: tls_plan.cert_path.clone(),
                key_path: tls_plan.key_path.clone(),
            });
        let require_https = tls_plan.require_https;
        tokio::spawn({
            let state = api_state.clone();
            async move {
                if let Err(e) =
                    sgx_guardian_client::api::serve(state, api_bind, tls, wifi_router).await
                {
                    eprintln!("❌ REST API server failed: {:?}", e);
                    if require_https {
                        eprintln!("TLS required; REST API not started (fail-closed).");
                    }
                }
            }
        });
        if tls_plan.enabled {
            if let Some(alias_port) = admin_tls::alias_port_from_env(api_bind.port()) {
                let alias_bind = std::net::SocketAddr::from(([0, 0, 0, 0], alias_port));
                let alias_upstream = std::net::SocketAddr::from(([127, 0, 0, 1], api_bind.port()));
                tokio::spawn(async move {
                    if let Err(error) =
                        admin_tls::serve_admin_tls_alias(alias_bind, alias_upstream).await
                    {
                        tracing::warn!(%error, %alias_bind, "Guardian HTTPS name endpoint unavailable");
                    }
                });
            }
        }
        println!(
            "✅ REST API ({}) starting on {}://{}/api/v1",
            node_id,
            tls_plan.scheme(),
            api_bind
        );
    }

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

    // === Comms Circle member snapshot sync ===
    // Pulls latest owner-signed Comms Circle membership state after boot and
    // periodically after reconnect, matching the live Mesh/CRL sync posture.
    sgx_guardian_client::circle::snapshot::spawn(node_id.clone(), did_resolver.clone());

    // Secure XFER must listen on every Guardian before another peer can
    // connect to it. The REST send endpoint only queues the outbound job; the
    // engine owns both the TCP listener and the background sender tasks.
    sgx_guardian_client::xfer::spawn(node_id.clone(), did_resolver.clone());
    // Subscribes to the notification bus and durably appends live events so
    // reconnecting consoles can replay missed notifications.
    sgx_guardian_client::notify::spawn(node_id.clone());
    // === NMAP discovery scheduler ===
    {
        use sgx_guardian_client::discovery::{DiscoveryScheduler, Inventory};

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

        match enforcement::apply_policy(&active_policy) {
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
        loop {
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
            // Write heartbeat file — external watchdog monitors this
            let _ = std::fs::write(heartbeat_path, chrono::Utc::now().to_rfc3339());
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
                if let Ok(km) =
                    sgx_guardian_client::key_manager::KeyManager::load_or_generate(&key_path)
                {
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

    // Start the Vault expiry reaper (Phase 7: automatic expiry cleanup)
    sgx_guardian_client::vault::VaultExpiryReaper::new(
        sgx_guardian_client::vault::VaultConfig::from_env(),
    )
    .start_background();

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
            // HA emits a state_changed event on every attribute tick, so device updates are
            // written on a short debounce instead of fsyncing the registry per event.
            registry.start_flusher(std::time::Duration::from_secs(2));
            let device_manager = sgx_guardian_client::device::manager::DeviceManager::new(
                std::sync::Arc::clone(&registry),
                ha_rest,
                std::sync::Arc::clone(&ha_event_bus),
                Some(std::sync::Arc::clone(&notification_manager)),
            );

            // Start listening for state_changed events. Reconciliation is kicked off further
            // below, once the integration manager is wired in, so vendor tagging is correct.
            std::sync::Arc::clone(&device_manager)
                .start_event_listener()
                .await;

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

            // Lets the device manager tell a Nest thermostat from any other `climate.*`
            // entity, so unbranded thermostats are not blanket-tagged as Google Nest.
            device_manager
                .set_integration_manager(std::sync::Arc::clone(&integration_manager))
                .await;

            // Startup reconciliation: reads HA's unit system and every entity's attributes.
            let dm_reconcile = std::sync::Arc::clone(&device_manager);
            tokio::spawn(async move {
                dm_reconcile.reconcile_state().await;
            });

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
                println!("🛑 Tearing down networking stacks...");
                let _ = runtime_manager
                    .handle_transition(sgx_guardian_client::runtime::models::RuntimeMode::Off)
                    .await;
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
                        *ca_host = ca_discovery::resolve_ca_ip_from_config().await;
                    }
                    publish_args = Some((overlay_ip_cidr.clone(), ca_host.clone(), *is_ca));
                }
                if let Some((overlay_ip_cidr, ca_host, is_ca)) = publish_args {
                    if let Err(e) = did_boot::publish_did_doc(
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
