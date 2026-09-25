//! SG-X Guardian Client entrypoint.
//! Initializes node identity, loads configuration, starts discovery,
//! attestation, metrics tracking, and the gRPC server runtime.

use sgx_guardian_client::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use sgx_guardian_client::audit::logger::{init_audit_logger, log_audit};
use sgx_guardian_client::audit::verifier::AuditVerifier;
use sgx_guardian_client::client::send_ping;
use sgx_guardian_client::config_loader::{CloudConfig, RelayLimitsConfig};
#[cfg(feature = "secure-element")]
use sgx_guardian_client::secure_element;

#[allow(unused_imports)]
use sgx_guardian_client::logging::{init_logger, log_error, log_event};
use sgx_guardian_client::metrics::Metrics;
use sgx_guardian_client::server;
use sgx_guardian_client::server::start_server;
// WiFi + Ethernet discovery imports
use sgx_guardian_client::dynamic_config;
use sgx_guardian_client::node_listener;
use sgx_guardian_client::runtime_gates::{cooldown, step, GATES};
use sgx_guardian_client::startup::config as startup_config;
use sgx_guardian_client::startup::nebula_cert::read_ip_from_nebula_cert;
use sgx_guardian_client::startup::{
    admin_tls, audit_paths, bootstrap, ca_discovery, did_boot, identity, pcr_status, GuardianPaths,
};

use base64::{engine::general_purpose, Engine as _};
use std::fs;
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
#[allow(unused_imports)]
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::{signal, task};

#[cfg(windows)]
use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;

// RELAY_SYNC_INTERVAL_SECS and VC_STATUS_LIST_PULL_INTERVAL_SECS moved to
// src/mesh/activation.rs along with their only remaining use sites (P1.2 step 3).
const DID_DOC_REFRESH_INTERVAL_SECS: u64 = 300;
const DID_DOC_PULL_INTERVAL_SECS: u64 = 30;
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
    // P1.9: the argument is now optional for a genuinely fresh unit — it still
    // must never *default* to a fixed name like "nodeA" (an unconfigured
    // Guardian silently becoming a specific, possibly-trusted identity would
    // break trust), so an absent argument gets a freshly generated, persisted
    // id instead. Existing deployments and systemd units keep passing the
    // argument explicitly and are unaffected.
    let node_id = match std::env::args().nth(1) {
        Some(id) if !id.is_empty() && !id.starts_with('-') => id,
        _ => {
            let generated = sgx_guardian_client::mesh::fresh_guardian_id();
            println!(
                "ℹ️ No node_id argument given — generated '{}'. Rename it in the setup UI \
                 before enrolling this Guardian into a circle.",
                generated
            );
            generated
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

    // === MESH PROFILE (P0.4/P0.5) ===
    // Must run before anything asks `is_ca()`. On a pre-Phase-0 install this
    // synthesises a profile from the Nebula material already on disk — holding
    // `ca/ca.key` is what made a Guardian the CA, so the role survives the
    // upgrade without anyone re-enrolling. It is idempotent and never
    // destructive, and a fresh Guardian simply has no profile (UNENROLLED),
    // which `is_ca()` reports as `false`.
    let mesh_profile = match sgx_guardian_client::mesh::legacy::migrate_and_initialize(&paths, &node_id) {
        Ok(Some(profile)) => {
            println!(
                "🔗 Mesh profile: guardian={} role={:?} circle={} ({})",
                profile.guardian_id, profile.role, profile.circle_id, profile.circle_name
            );
            Some(profile)
        }
        Ok(None) => {
            println!("🔗 No mesh profile — this Guardian is not enrolled in a circle yet");
            None
        }
        Err(e) => {
            // P1.3: a corrupt profile must not be silently treated as
            // "unenrolled" (that would let the daemon overwrite it, and on a
            // CA come up believing it has no circle) — but it also must not
            // kill the process before the API has even bound. `is_ca()` and
            // the other `mesh::` accessors already fail closed to their
            // legacy/absent defaults when no profile is cached, which is
            // exactly the safe state to continue booting in: the operator
            // sees ERROR with the reason over the lifecycle API and fixes or
            // resets it, rather than finding a dead process under systemd.
            let reason = format!(
                "Mesh profile could not be loaded: {e}. Fix or remove \
                 /var/lib/sgx-guardian/mesh/profile.json and restart, or use the \
                 lifecycle reset API."
            );
            eprintln!("❌ {reason}");
            sgx_guardian_client::mesh::lifecycle::fail(reason);
            None
        }
    };
    // P1.1/P1.2 step 6: resolve where the lifecycle state machine starts —
    // straight to CIRCLE_MEMBER for an already-enrolled Guardian, resuming a
    // persisted in-progress/failed attempt, or UNENROLLED for a fresh one.
    // `mesh_gate` (P1.5) and the setup UI (P1.7/P1.8) both read this from here
    // on; nothing before this point needs it; the `Err` case above already
    // recorded `ERROR` on the profile-load path, so this does not overwrite
    // that with a fresh `Initializing → Unenrolled` walk.
    if !matches!(
        sgx_guardian_client::mesh::lifecycle::current().state,
        sgx_guardian_client::mesh::lifecycle::LifecycleState::Error
    ) {
        if let Err(e) =
            sgx_guardian_client::mesh::lifecycle::resolve_boot_state(&paths, mesh_profile.as_deref())
        {
            eprintln!("⚠️ Lifecycle boot-state resolution failed: {e}");
        }
    }
    // P2.2: a process that died mid-`create_circle` leaves an abandoned
    // `mesh/staging/create-<ts>/` directory — never a half-written `nebula/`
    // (nothing commits there except the final atomic rename), but the
    // staging leftovers themselves are still worth sweeping on every boot.
    sgx_guardian_client::mesh::ca::cleanup_stale_staging(&paths);
    // P4.6: "B restarts while PENDING and resumes" — a no-op unless a join
    // was actually left mid-flight before the last restart.
    {
        let paths_for_resume = paths.clone();
        let node_id_for_resume = node_id.clone();
        tokio::spawn(async move {
            sgx_guardian_client::mesh::enroll::resume_pending_join_if_any(
                &paths_for_resume,
                &node_id_for_resume,
            )
            .await;
        });
    }

    let report = bootstrap::bootstrap_filesystem(&paths, sgx_guardian_client::mesh::is_ca());
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

    // === Policy Authority key bootstrap (CA only) ===
    // Generates /etc/sgx-guardian/policies/pa_admin_{priv,pub}.der on first
    // boot, persists thereafter. Member nodes never run this — they receive
    // the public half through the cert-bootstrap response.
    if sgx_guardian_client::mesh::is_ca() {
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
    for (node, _) in bootstrap::default_node_ports() {
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

    // P1.2 step 1: hoisted from its previous position deep inside the
    // Nebula/mesh block (immediately before "=== NODE BROADCAST ==="). Pure
    // function of `cohort` (just loaded above) and `node_id` (available since
    // the top of `main()`) — nothing it depends on requires enrollment or
    // mesh activation to have happened, so there was no reason for it to run
    // that late. Moving it here is what lets `this_node` — needed by the TLS
    // cert SAN entries and the REST API's TLS config, both destined to move
    // early too — actually be available early.
    // `Cohort` only ever represents the fixed legacy three-name set
    // (config/node{A,B,C}.yaml) — it was never meant to answer "is this a
    // known Guardian" in general, only "which of the three legacy peers am
    // I". A Guardian outside that set (any name from P0.6/P0.7's
    // de-hardcoding onward) is the normal, expected, successful case now, not
    // an error: falling back to a config built from this Guardian's own
    // node_id (the same helper first-boot config generation already uses)
    // gives it sensible TLS SAN / API-port defaults, and an empty peer list
    // is correct too — a non-cohort Guardian's peers come from the overlay
    // registry and DID documents elsewhere, never from this static list.
    //
    // Before P1.2 this was `std::process::exit(1)`, positioned deep inside
    // Stage B, after enrollment had already run — so a nodeD/edge-7-style
    // Guardian got as far as obtaining a certificate before the process
    // eventually died here. Hoisting the split earlier (P1.2 step 1) moved
    // that death earlier too, before the API ever bound — exactly the
    // failure mode P1.2/P1.3 exist to remove, so this is fixed now rather
    // than carried forward.
    let (this_node, peers) = match cohort.split(&node_id) {
        Some(pair) => pair,
        None => {
            log_event(
                &node_id,
                "Not part of the legacy nodeA/B/C cohort — using this Guardian's own \
                 configuration and no legacy peers.",
            );
            (startup_config::default_node_config(&node_id), Vec::new())
        }
    };

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

    // P1.2 step 6: `Arc<Mutex<_>>`, not a plain local — `activate_mesh` is
    // spawned below, not awaited inline, so a `&mut` reference to a
    // stack-local can no longer cross into it. See
    // `mesh::activation::DidDocPublishState`.
    let did_doc_publish_state: sgx_guardian_client::mesh::activation::DidDocPublishState =
        std::sync::Arc::new(tokio::sync::Mutex::new(None));
    let did_resolver = sgx_guardian_client::did::Resolver::new(
        sgx_guardian_client::did::ResolverConfig::default(),
    );
    let resolver_for_flag = did_resolver.clone();
    let vid_cache = sgx_guardian_client::virtual_id_cache::VirtualIdCache::new();
    sgx_guardian_client::attestation_service::set_vid_cache(vid_cache.clone());

    let (reattest_tx, reattest_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    sgx_guardian_client::attestation_service::set_reattest_sender(reattest_tx);
    let node_key_path_for_reattest = node_key_path.clone();

    // === REST API + TLS identity, moved early (P1.2 step 2) ===
    // Was positioned after the entire Nebula/CoT/discovery/broadcast block
    // (~1650 lines below), which is the literal B2 blocker: the frontend
    // could not be reached until enrollment-dependent code had already run.
    // Nothing in this block needs enrollment to have happened — the overlay
    // IP lookup below already degrades gracefully pre-enrollment (see its own
    // comment), and `did_resolver` is late-bindable (P1.4) so its CA host is
    // filled in later without reconstructing the resolver AppState already
    // holds a clone of.
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
                // P1.2/P1.3: this sits before the REST API bind further down
                // this same block — a `std::process::exit(1)` here used to
                // kill the process (and take the not-yet-bound API with it)
                // over a policy runtime error, which is exactly the failure
                // mode this phase removes. Falls through to whatever policy
                // was already active, matching the sibling `Err` arm below
                // (a rejected signature), including that arm's precedent of
                // not touching mesh lifecycle state — a local policy-engine
                // issue is not a circle-enrollment one, so it stays out of
                // the ERROR state the setup UI reads.
                if let Err(e) = load_policy_runtime(&verified.policy_yaml) {
                    let reason = format!("Policy runtime load failed: {}", e);
                    eprintln!("❌ {reason} — continuing with previously active policy");
                    log_error(&node_id, &reason);
                    log_audit(
                        &node_id,
                        AuditCategory::Policy,
                        AuditSeverity::Critical,
                        AuditAction::Failed,
                        &reason,
                    );
                    let mut m = metrics.lock().await;
                    m.set_policy_active(false);
                    m.record_error();
                } else {
                    println!("✅ Policy is now ACTIVE at runtime");
                    log_event(&node_id, "Runtime policy activated successfully");
                    log_audit(
                        &node_id,
                        AuditCategory::Policy,
                        AuditSeverity::Info,
                        AuditAction::Applied,
                        "Signed policy verified and activated",
                    );
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
    .unwrap_or_else(|| sgx_guardian_client::mesh::overlay_host(1));
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
            // Unlike the cohort-split and policy-runtime cases above, this one
            // is left as a hard stop rather than reworked to let the API bind
            // regardless: this device identity is what the peer mTLS server
            // signs with, and generating it is a local keypair/self-signed-
            // cert operation that essentially only fails on a disk-full or
            // permission-denied host — not, like an unrecognised node_id, an
            // expected outcome of normal use. `lifecycle::fail` at least
            // leaves a persisted, API-readable reason behind before the
            // process ends, rather than the previous bare `exit(1)` leaving
            // none.
            let reason = format!("Failed to prepare TLS certificate: {:?}", err);
            eprintln!("❌ {reason}");
            log_error(&node_id, &reason);
            sgx_guardian_client::mesh::lifecycle::fail(reason.clone());
            return Err(reason.into());
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


    step(9, "Guardian Mesh subsystem gate");
    // P1.2 step 3: the body used to be inline here — see
    // src/mesh/activation.rs for why and what changed. Its own first
    // statement is `if !GATES.disable_nebula { ... }` (part of the original,
    // verbatim body), so the gate is not repeated here.
    //
    // P1.2 step 6: spawned, not awaited — this is the change that actually
    // delivers Phase 1's goal. Before this, a failure anywhere in Stage B
    // (`lifecycle::fail` + `Err` — P1.3) propagated via `?` out of `main()`
    // itself, ending the whole process, API included. Spawned, the same
    // failure now only ends this one task: the REST API bound above (P1.2
    // step 2) keeps serving, `mesh_gate` (P1.5) reports `ERROR` with the
    // reason on `MeshRequired` routes, and the setup UI (P1.7/P1.8) shows
    // Retry instead of the operator finding a dead process under systemd.
    let did_doc_publish_state_for_activation = did_doc_publish_state.clone();
    // Cloned *before* the spawn, not inside it: `node_id`/`metrics`/`km` are
    // all still used later in this function (the tail loop, the CA-ping
    // loop). An `async move` closure captures whichever outer binding a
    // `.clone()` call inside it references, by move — so calling
    // `node_id.clone()` from inside the closure would move the *outer*
    // `node_id` into the task, not just borrow it, leaving nothing for the
    // code after this spawn to use.
    let node_id_for_activation = node_id.clone();
    let metrics_for_activation = metrics.clone();
    let km_for_activation = km.clone();
    tokio::spawn(async move {
        if let Err(e) = sgx_guardian_client::mesh::activation::activate_mesh(
            node_id_for_activation,
            paths,
            km_for_activation,
            metrics_for_activation,
            did_resolver.clone(),
            cohort,
            this_node.clone(),
            current_relay_cfg.clone(),
            detected_ip.clone(),
            did_doc_publish_state_for_activation,
            node_key_path_for_reattest.clone(),
            pubkey_b64.clone(),
            reattest_rx,
        )
        .await
        {
            // `activate_mesh` already called `lifecycle::fail(reason)` and
            // logged specifics on every path that produces this — this is
            // the last-resort backstop for anything it did not (e.g. a
            // dependency panicking mid-await, surfaced as this `Err` via
            // `?`'s conversion rather than an explicit `fail` call).
            eprintln!("❌ Mesh activation failed: {e}");
            let _ = sgx_guardian_client::mesh::lifecycle::transition_to(
                sgx_guardian_client::mesh::lifecycle::LifecycleState::Error,
                Some(e.to_string()),
            );
        }
    });
    // === END POLICY ENFORCEMENT ===

    // Only the CA sends pings to others
    if sgx_guardian_client::mesh::is_ca() {
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
            // P1.2 step 6: was `if did_doc_publish_state.is_some()` — a
            // `select!` branch guard cannot `.await`, and locking a shared
            // `Arc<Mutex<_>>` needs to. The tick interval already bounds how
            // often this fires; firing unconditionally and checking `is_some`
            // just inside the branch (see below) costs one uncontended lock
            // per tick when this Guardian has nothing to publish yet.
            _ = did_doc_tick.tick() => {
                did_doc_refresh_elapsed += DID_DOC_PULL_INTERVAL_SECS;
                let force_refresh = std::path::Path::new(DID_DOC_ROTATION_FLAG).exists();
                if !force_refresh && did_doc_refresh_elapsed < DID_DOC_REFRESH_INTERVAL_SECS {
                    continue;
                }
                did_doc_refresh_elapsed = 0;

                let mut publish_args: Option<(String, String, bool)> = None;
                {
                    // `tokio::sync::Mutex`'s guard is safely held across an
                    // `.await` (unlike `std::sync::Mutex`'s), which the CA-IP
                    // resolution call below does briefly — this tick runs at
                    // most every 30s, so holding the lock that long is not a
                    // contention concern. Scoped so the guard still drops
                    // before the DID publish/invalidate `.await`s further
                    // down, which do not need it at all.
                    let mut guard = did_doc_publish_state.lock().await;
                    if let Some((overlay_ip_cidr, ca_host, is_ca, nebula_base)) = guard.as_mut() {
                        if let Some(latest_ip_cidr) = read_ip_from_nebula_cert(nebula_base, &node_id) {
                            *overlay_ip_cidr = latest_ip_cidr;
                        } else if let Some(cached_ip) = sgx_guardian_client::nebula::registry_sync::load_local_ip_cache(&node_id) {
                            *overlay_ip_cidr = cached_ip;
                        }
                        if !*is_ca {
                            *ca_host = ca_discovery::resolve_ca_ip_for_runtime().await;
                        }
                        publish_args = Some((overlay_ip_cidr.clone(), ca_host.clone(), *is_ca));
                    }
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

