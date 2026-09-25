//! `mesh::activation::activate_mesh` — the Nebula/CA/member-enrollment half of
//! boot (P1.2 step 3).
//!
//! Extracted verbatim from `main()` (was `main.rs:1108-3036`, the whole
//! `step(9, "Guardian Mesh subsystem gate")` block through
//! `// === END POLICY ENFORCEMENT ===`). Not yet spawned as a background task
//! — still called inline, awaited, from `main()` — so this step changes
//! *where the code lives*, not *when it runs*. Splitting it out is what makes
//! the later "spawn it, make exit(1) non-fatal" step (P1.2 step 6 / P1.3)
//! possible without touching this body again.
//!
//! Parameters were derived mechanically: the body was pasted here with an
//! empty signature and every `cannot find value` the compiler reported became
//! a parameter, so this list is exactly what Stage A must have ready before
//! calling this — nothing assumed, nothing guessed.

use crate::attestation_service;
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
#[allow(unused_imports)]
use crate::logging::{log_error, log_event};
use crate::config_loader::RelayLimitsConfig;
use crate::dynamic_config;
use crate::key_manager::KeyManager;
use crate::metrics::Metrics;
use crate::nebula::install::NebulaInstall;
use crate::node_announcement::NodeAnnouncement;
use crate::node_broadcast;
use crate::p2p_discovery::P2PDiscovery;
use crate::runtime_gates::{cooldown, step, GATES};
use crate::server;
use crate::startup::config as startup_config;
use crate::startup::config::Cohort;
use crate::startup::json_equivalent;
use crate::startup::nebula_cert::read_ip_from_nebula_cert;
use crate::startup::{ca_discovery, did_boot};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};

const RELAY_SYNC_INTERVAL_SECS: u64 = 60;
const DID_DOC_PULL_INTERVAL_SECS: u64 = 30;
const VC_STATUS_LIST_PULL_INTERVAL_SECS: u64 = 300;

/// The overlay IP / CA host / is-CA / nebula-base-dir tuple the DID
/// re-publish tick (in `main()`'s tail loop) needs, shared with — and
/// mutated by — this function.
///
/// A `&mut` reference cannot cross a `tokio::spawn` boundary (P1.2 step 6:
/// this function is spawned, not awaited inline, so its lifetime is no longer
/// tied to `main()`'s stack frame). `Arc<Mutex<_>>` is the direct replacement:
/// `main()` creates one, clones it in here, and the tail loop reads the same
/// one back after spawning.
pub type DidDocPublishState = Arc<Mutex<Option<(String, String, bool, String)>>>;

/// Everything Stage B does: Nebula install checks, overlay/lighthouse
/// registries, CA/member cert enrollment, DID publish, mTLS peer server,
/// CoT/discovery/attestation integration, node broadcast, and policy
/// enforcement application.
///
/// Not yet spawned — still `.await`ed inline from `main()` at the same point
/// this body used to run (P1.2 step 3 is "move the code", not "change when it
/// runs"; that is step 6). The parameter list is exactly what the extraction
/// needed, discovered by the compiler rather than guessed — see the module
/// doc comment.
#[allow(unused, clippy::too_many_arguments)]
pub async fn activate_mesh(
    node_id: String,
    paths: crate::startup::GuardianPaths,
    km: Arc<KeyManager>,
    metrics: Arc<Mutex<Metrics>>,
    did_resolver: crate::did::Resolver,
    cohort: Cohort,
    this_node: crate::config_loader::NodeConfig,
    current_relay_cfg: RelayLimitsConfig,
    detected_ip: String,
    did_doc_publish_state: DidDocPublishState,
    node_key_path_for_reattest: String,
    pubkey_b64: String,
    mut reattest_rx: mpsc::UnboundedReceiver<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    step(9, "Guardian Mesh subsystem gate");
    if !GATES.disable_nebula {
        // === Nebula Installation Verification ===
        println!("\n🔎 Verifying Guardian Mesh Installation...");

        use crate::nebula::ca::NebulaCA;
        use crate::nebula::config::NebulaConfig;
        use crate::nebula::daemon::NebulaDaemon;
        use crate::nebula::interface::NebulaInterface;
        use crate::nebula::lighthouse::LighthouseRegistry;
        use crate::nebula::models::CircleMembership;
        use crate::nebula::overlay::OverlayPool;
        use crate::nebula::overlay_registry::OverlayRegistry;
        use crate::nebula::registry_sync;
        use crate::nebula::registry_sync::SharedRegistry;
        use crate::nebula::relay_registry::RelayRegistry;
        use crate::nebula::relay_tc::RelayTrafficControl;
        use crate::nebula::stats::NebulaStats;
        use crate::nebula::tunnel_state::TunnelState;
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let nebula_base_dir =
            std::env::var("SGX_NEBULA_DIR").unwrap_or("/var/lib/sgx-guardian/nebula".to_string());
        if !crate::mesh::is_ca() {
            println!(
                "ℹ️ {} keeps local read-only relay registry snapshot",
                node_id
            );
        }

        // Nebula binary checks
        match NebulaInstall::check_binary() {
            Ok(_) => println!("✅ Guardian Mesh binary found"),
            Err(e) => {
                let reason = format!("Guardian Mesh binary missing: {}", e);
                eprintln!("❌ {reason}");
                log_error(&node_id, &reason);
                crate::mesh::lifecycle::fail(reason.clone());
                return Err(reason.into());
            }
        }
        match NebulaInstall::check_version() {
            Ok(v) => println!("✅ Guardian Mesh version: {}", v.trim()),
            Err(e) => {
                let reason = format!("Guardian Mesh version check failed: {}", e);
                eprintln!("❌ {reason}");
                crate::mesh::lifecycle::fail(reason.clone());
                return Err(reason.into());
            }
        }
        match NebulaInstall::test_daemon_start() {
            Ok(_) => println!("✅ Guardian Mesh daemon responding"),
            Err(e) => {
                let reason = format!("Guardian Mesh daemon test failed: {}", e);
                eprintln!("❌ {reason}");
                crate::mesh::lifecycle::fail(reason.clone());
                return Err(reason.into());
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

        if crate::mesh::is_ca() {
            // ────────────────────────────────────────────────────────────────────
            // nodeA IS the CA + Lighthouse.
            // 1. Generate CA (idempotent).
            // 2. Assign its own overlay IP from the registry.
            // 3. Issue its own cert.
            // 4. Start the registry server so members can get IPs.
            // ────────────────────────────────────────────────────────────────────

            // 1. Generate CA — nodeA ONLY
            if let Err(e) = NebulaCA::generate_ca(&nebula_base_dir) {
                let reason = format!("Failed to generate CA: {:?}", e);
                eprintln!("❌ {reason}");
                crate::mesh::lifecycle::fail(reason.clone());
                return Err(reason.into());
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
                &crate::mesh::circle_id(),
                &crate::mesh::overlay_prefix(),
                &crate::mesh::ca_guardian_id(),
            );

            let ip_cidr = reg
                .get_ip_cidr(&crate::mesh::ca_guardian_id())
                .expect("the CA's own overlay IP is missing from the registry")
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
                .get_ip(&crate::mesh::ca_guardian_id())
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| crate::mesh::overlay_host(1));
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
                &crate::mesh::circle_id(),
                &crate::mesh::ca_guardian_id(),
                &owner_overlay,
                &lighthouse_endpoint,
            );
            let _ = lh_reg.update_endpoint(&crate::mesh::ca_guardian_id(), &lighthouse_endpoint);
            lh_reg.mark_active(&crate::mesh::ca_guardian_id());

            let vps_cfg = crate::config_loader::resolve_vps_config(&node_id);
            if let Some(vps_pub_ip) = vps_cfg.vps_public_ip {
                if !vps_pub_ip.trim().is_empty() {
                    let vps_ovl_ip = vps_cfg
                        .vps_overlay_ip
                        .unwrap_or_else(|| crate::mesh::overlay_host(10));
                    let vps_endpoint = format!("{}:4242", vps_pub_ip.trim());
                    lh_reg.upsert_node("vps-lighthouse", &vps_ovl_ip, &vps_endpoint, true, true);
                    lh_reg.mark_active("vps-lighthouse");
                    println!(
                        "🗼 Registered VPS Cloud Lighthouse on Node A: {} -> {}",
                        vps_ovl_ip, vps_endpoint
                    );
                }
            }

            if let Err(e) = lh_reg.save(&lh_path) {
                eprintln!("⚠️ LH registry save failed: {}", e);
            }
            println!("📡 {}", lh_reg.summary());
            lighthouse_registry = lh_reg;

            // 3. Issue the CA's own certificate
            let membership_a = CircleMembership {
                node_name: node_id.clone(),
                circle_id: crate::mesh::circle_id(),
                vc_hash: "ca-self-signed".to_string(),
                is_valid: true,
            };
            if let Err(e) = NebulaCA::issue_node_cert(&nebula_base_dir, &membership_a, &ip_cidr) {
                let reason = format!("Failed to issue CA node certificate: {:?}", e);
                eprintln!("❌ {reason}");
                crate::mesh::lifecycle::fail(reason.clone());
                return Err(reason.into());
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

            // 5. Start VPS CA broker worker (if configured)
            if let Some(vps_url) = vps_cfg.broker_url {
                if !vps_url.is_empty() {
                    let circle_id = crate::mesh::circle_id();
                    let auth_token = vps_cfg.broker_token.unwrap_or_default();
                    tokio::spawn(async move {
                        crate::cloud::ca_broker::start_ca_broker_worker(
                            vps_url, circle_id, auth_token,
                        )
                        .await;
                    });
                    println!("☁️  VPS CA broker worker started");
                }
            }

            if let Err(e) =
                did_boot::refresh_and_publish_did_doc(&node_id, &km, &ip_cidr, "127.0.0.1", true)
                    .await
            {
                eprintln!("⚠️ DID Document self-publish failed: {}", e);
            }
            *did_doc_publish_state.lock().await = Some((
                ip_cidr.clone(),
                "127.0.0.1".to_string(),
                true,
                nebula_base_dir.clone(),
            ));
        } else {
            // ────────────────────────────────────────────────────────────────────
            // MEMBER NODES (e.g. nodeB, nodeC)
            // ────────────────────────────────────────────────────────────────────
            let member_cert_path = format!("{}/nodes/{}.crt", nebula_base_dir, node_id);
            let member_key_path = format!("{}/nodes/{}.key", nebula_base_dir, node_id);
            let ca_exists = NebulaCA::ca_cert_exists(&nebula_base_dir);
            let mesh_credentials_exist = Path::new(&member_cert_path).exists()
                && Path::new(&member_key_path).exists()
                && ca_exists;
            let cot_trust_exists =
                crate::cert_client::broker_trust_material_available();
            let cert_exists = mesh_credentials_exist && cot_trust_exists;

            if mesh_credentials_exist && !cot_trust_exists {
                println!(
                    "⚠️ Guardian Mesh certificate exists, but CoT membership trust material is missing or stale — refreshing bootstrap"
                );
            }

            if cert_exists {
                // ── Fast-Path: Existing valid certificate on disk ────────────────
                let ip_cidr = read_ip_from_nebula_cert(&nebula_base_dir, &node_id)
                    .unwrap_or_else(|| crate::mesh::overlay_host_cidr(2));
                println!(
                    "✅ Guardian Mesh certificate + CA cert already present for {} (IP: {})",
                    node_id, ip_cidr
                );
                if let Some(fp) = NebulaCA::ca_fingerprint(&nebula_base_dir) {
                    println!("🔏 CA fingerprint (local): {}", fp);
                }
                nebula_ip = ip_cidr.clone();

                let ip_only = ip_cidr.split('/').next().unwrap_or("").to_string();
                let mut pool = OverlayPool::new(
                        &crate::mesh::circle_id(),
                        &crate::mesh::overlay_prefix(),
                        &crate::mesh::ca_guardian_id(),
                    );
                pool.allocations.insert(node_id.clone(), ip_only);
                overlay_pool = pool;

                let lh_path = format!("{}/lighthouse_registry.json", nebula_base_dir);
                let vps_cfg = crate::config_loader::resolve_vps_config(&node_id);
                let vps_public_ip = vps_cfg
                    .vps_public_ip
                    .clone()
                    .unwrap_or_else(|| "159.203.186.55".to_string());
                let vps_overlay_ip = vps_cfg
                    .vps_overlay_ip
                    .clone()
                    .unwrap_or_else(|| crate::mesh::overlay_host(10));
                let vps_endpoint = format!("{}:4242", vps_public_ip);
                let owner_overlay = overlay_pool
                    .get_ip(&crate::mesh::ca_guardian_id())
                    .cloned()
                    .unwrap_or_else(|| crate::mesh::overlay_host(1));
                let mut lh_reg = LighthouseRegistry::load_or_create(
                    &lh_path,
                    &crate::mesh::circle_id(),
                    &crate::mesh::ca_guardian_id(),
                    &owner_overlay,
                    "",
                );
                lh_reg.upsert_node("vps-lighthouse", &vps_overlay_ip, &vps_endpoint, true, true);
                lh_reg.mark_active("vps-lighthouse");
                let _ = lh_reg.save(&lh_path);
                lighthouse_registry = lh_reg;

                *did_doc_publish_state.lock().await = Some((
                    ip_cidr.clone(),
                    owner_overlay.clone(),
                    false,
                    nebula_base_dir.clone(),
                ));

                log_audit(
                    &node_id,
                    AuditCategory::Network,
                    AuditSeverity::Info,
                    AuditAction::Succeeded,
                    &format!("Existing Guardian Mesh certificate found for {}", node_id),
                );
            } else {
                // ── Bootstrap Required: LAN First with Automatic VPS Fallback ────
                let lan_ca_ip =
                    crate::mesh::legacy::discover_lan_node_a(3, std::time::Duration::from_secs(30))
                        .await;

                if let Some(ca_lan_ip) = lan_ca_ip {
                    // ── Case A: Local Node A Found on LAN ────────────────────────
                    println!(
                        "🌐 Local Node A discovered at {} — proceeding with LAN enrollment",
                        ca_lan_ip
                    );

                    if !std::path::Path::new(registry_sync::REGISTRY_PATH).exists() {
                        let _ = registry_sync::clear_local_ip_cache(&node_id);
                    }

                    let pubkey_prefix = &pubkey_b64[..20.min(pubkey_b64.len())];
                    let ip_cidr =
                        registry_sync::resolve_overlay_ip(&node_id, &ca_lan_ip, pubkey_prefix)
                            .await;
                    println!("🌐 Overlay IP for {}: {}", node_id, ip_cidr);
                    nebula_ip = ip_cidr.clone();

                    if let Err(e) =
                        refresh_and_publish_did_doc(&node_id, &km, &ip_cidr, &ca_lan_ip, false)
                            .await
                    {
                        eprintln!("⚠️ DID Document publish failed: {}", e);
                    }
                    *did_doc_publish_state.lock().await = Some((
                        ip_cidr.clone(),
                        ca_lan_ip.clone(),
                        false,
                        nebula_base_dir.clone(),
                    ));

                    let ip_only = ip_cidr.split('/').next().unwrap_or("").to_string();
                    let mut pool =
                        OverlayPool::new(
                        &crate::mesh::circle_id(),
                        &crate::mesh::overlay_prefix(),
                        &crate::mesh::ca_guardian_id(),
                    );
                    pool.allocations.insert(node_id.clone(), ip_only);
                    overlay_pool = pool;

                    let lh_path = format!("{}/lighthouse_registry.json", nebula_base_dir);
                    let owner_overlay = overlay_pool
                        .get_ip(&crate::mesh::ca_guardian_id())
                        .cloned()
                        .unwrap_or_else(|| crate::mesh::overlay_host(1));
                    let lighthouse_endpoint = format!("{}:4242", ca_lan_ip);
                    let mut lh_reg = LighthouseRegistry::load_or_create(
                        &lh_path,
                        &crate::mesh::circle_id(),
                        &crate::mesh::ca_guardian_id(),
                        &owner_overlay,
                        &lighthouse_endpoint,
                    );
                    let _ = lh_reg.update_endpoint(&crate::mesh::ca_guardian_id(), &lighthouse_endpoint);
                    lh_reg.mark_active(&crate::mesh::ca_guardian_id());
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

                    let ca_address = format!("{}:50061", ca_lan_ip);
                    let wants_lh = std::env::var("SGX_WANTS_LIGHTHOUSE")
                        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
                        .unwrap_or(false);
                    let wants_relay = std::env::var("SGX_WANTS_RELAY")
                        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
                        .unwrap_or(false);
                    let pairing_proof = match std::env::var("SGX_GUARDIAN_PAIRING_CODE") {
                        Ok(code) if !code.trim().is_empty() => {
                            let device_did = crate::did::DidRecord::load(
                                crate::did::DEFAULT_DID_PATH,
                            )
                            .map(|record| record.did)
                            .map_err(|e| {
                                eprintln!(
                                    "⚠️ Failed to load DID for pairing bootstrap proof: {}",
                                    e
                                );
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
                                    match crate::api::auth::pairing::build_pairing_proof(
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

                    println!(
                        "🔐 Requesting cert + CA cert from nodeA at {}:50061...",
                        ca_lan_ip
                    );
                    log_event(
                        &node_id,
                        "Guardian Mesh certificate missing — requesting from CA via LAN",
                    );

                    crate::cert_client::request_certificate_from_ca(
                        node_id.clone(),
                        ca_address,
                        ip_cidr.clone(),
                        pubkey_b64.clone(),
                        wants_lh,
                        wants_relay,
                        pairing_proof,
                    )
                    .await;

                    if !NebulaCA::ca_cert_exists(&nebula_base_dir) {
                        let reason = "CA cert still missing after bootstrap! Check the CA is \
                             running and cert_service wrote ca_cert_pem."
                            .to_string();
                        eprintln!("❌ {reason}");
                        crate::mesh::lifecycle::fail(reason.clone());
                        return Err(reason.into());
                    }

                    if let Some(fp) = NebulaCA::ca_fingerprint(&nebula_base_dir) {
                        println!("🔏 CA fingerprint (from nodeA): {}", fp);
                        log_event(&node_id, &format!("CA fingerprint: {}", fp));
                    }

                    println!("✅ Certificate bootstrap completed for {}", node_id);
                } else {
                    // ── Case B: Remote Fallback to Cloud VPS Broker ──────────────
                    let vps_cfg = crate::config_loader::resolve_vps_config(&node_id);
                    let broker_url = match vps_cfg.broker_url {
                        Some(ref u) if !u.trim().is_empty() => u.clone(),
                        _ => {
                            let reason = "Node A not found on LAN and no VPS broker configured \
                                 in /etc/sgx-guardian/config.yaml"
                                .to_string();
                            eprintln!("❌ {reason}");
                            crate::mesh::lifecycle::fail(reason.clone());
                            return Err(reason.into());
                        }
                    };

                    println!();
                    println!("☁️  Node A not found on local network after 3 attempts (90s).");
                    println!(
                        "☁️  Falling back to VPS Cloud Broker enrollment at {}",
                        broker_url
                    );
                    println!();
                    log_event(
                        &node_id,
                        &format!(
                            "Remote fallback: requesting certificate via VPS Cloud Broker at {}",
                            broker_url
                        ),
                    );

                    crate::cert_client::request_certificate_via_broker(
                        node_id.clone(),
                        broker_url,
                        pubkey_b64.clone(),
                    )
                    .await;

                    if !NebulaCA::ca_cert_exists(&nebula_base_dir) {
                        let reason =
                            "CA cert missing after broker bootstrap! Check broker and CA connection."
                                .to_string();
                        eprintln!("❌ {reason}");
                        crate::mesh::lifecycle::fail(reason.clone());
                        return Err(reason.into());
                    }

                    if let Some(fp) = NebulaCA::ca_fingerprint(&nebula_base_dir) {
                        println!("🔏 CA fingerprint (from broker): {}", fp);
                        log_event(&node_id, &format!("CA fingerprint: {}", fp));
                    }

                    let ip_cidr = read_ip_from_nebula_cert(&nebula_base_dir, &node_id)
                        .unwrap_or_else(|| crate::mesh::overlay_host_cidr(2));
                    println!("🌐 Overlay IP for {}: {}", node_id, ip_cidr);
                    nebula_ip = ip_cidr.clone();

                    let ip_only = ip_cidr.split('/').next().unwrap_or("").to_string();
                    let mut pool =
                        OverlayPool::new(
                        &crate::mesh::circle_id(),
                        &crate::mesh::overlay_prefix(),
                        &crate::mesh::ca_guardian_id(),
                    );
                    pool.allocations.insert(node_id.clone(), ip_only);
                    overlay_pool = pool;

                    let lh_path = format!("{}/lighthouse_registry.json", nebula_base_dir);
                    let owner_overlay = overlay_pool
                        .get_ip(&crate::mesh::ca_guardian_id())
                        .cloned()
                        .unwrap_or_else(|| crate::mesh::overlay_host(1));
                    let vps_public_ip = vps_cfg
                        .vps_public_ip
                        .unwrap_or_else(|| "159.203.186.55".to_string());
                    let vps_overlay_ip = vps_cfg
                        .vps_overlay_ip
                        .unwrap_or_else(|| crate::mesh::overlay_host(10));
                    let vps_endpoint = format!("{}:4242", vps_public_ip);
                    let mut lh_reg = LighthouseRegistry::load_or_create(
                        &lh_path,
                        &crate::mesh::circle_id(),
                        &crate::mesh::ca_guardian_id(),
                        &owner_overlay,
                        "",
                    );
                    lh_reg.upsert_node(
                        "vps-lighthouse",
                        &vps_overlay_ip,
                        &vps_endpoint,
                        true,
                        true,
                    );
                    lh_reg.mark_active("vps-lighthouse");
                    let _ = lh_reg.save(&lh_path);
                    lighthouse_registry = lh_reg;
                    *did_doc_publish_state.lock().await = Some((
                        ip_cidr.clone(),
                        owner_overlay.clone(),
                        false,
                        nebula_base_dir.clone(),
                    ));

                    // The overlay IP above isn't reachable until the Nebula
                    // tunnel to the VPS lighthouse finishes establishing
                    // (NAT punch-through / lighthouse failover), which can
                    // take anywhere from seconds to a couple of minutes. The
                    // normal periodic publish only fires every
                    // DID_DOC_REFRESH_INTERVAL_SECS (5 min), so left to that
                    // alone, a node can sit unpublished — and CRL-GOSSIP/
                    // CRL-OFFLINE skipped — for multiple missed cycles. Poll
                    // fast here just for the bootstrap window so the publish
                    // fires within ~10s of the tunnel actually coming up;
                    // the periodic tick remains the permanent fallback if
                    // this window isn't enough.
                    {
                        let node_id = node_id.clone();
                        let km = km.clone();
                        let ip_cidr = ip_cidr.clone();
                        let owner_overlay = owner_overlay.clone();
                        tokio::spawn(async move {
                            const FAST_RETRY_INTERVAL: std::time::Duration =
                                std::time::Duration::from_secs(10);
                            const FAST_RETRY_WINDOW: std::time::Duration =
                                std::time::Duration::from_secs(180);
                            let start = std::time::Instant::now();
                            loop {
                                match refresh_and_publish_did_doc(
                                    &node_id,
                                    &km,
                                    &ip_cidr,
                                    &owner_overlay,
                                    false,
                                )
                                .await
                                {
                                    Ok(()) => {
                                        println!(
                                            "📤 DID Document published over Nebula tunnel after broker enrollment"
                                        );
                                        break;
                                    }
                                    Err(e) => {
                                        if start.elapsed() >= FAST_RETRY_WINDOW {
                                            eprintln!(
                                                "⚠️  DID doc still unpublished after {}s of fast retries ({}); \
                                                 falling back to the periodic publish cycle",
                                                FAST_RETRY_WINDOW.as_secs(),
                                                e
                                            );
                                            break;
                                        }
                                        tokio::time::sleep(FAST_RETRY_INTERVAL).await;
                                    }
                                }
                            }
                        });
                    }

                    log_audit(
                        &node_id,
                        AuditCategory::Network,
                        AuditSeverity::Info,
                        AuditAction::Succeeded,
                        &format!("Remote overlay bootstrap complete for {}", node_id),
                    );
                    println!(
                        "✅ Certificate bootstrap completed via broker for {}",
                        node_id
                    );
                }
            }

            let lh_path = format!("{}/lighthouse_registry.json", nebula_base_dir);
            if let Ok(mut fresh_lh) = LighthouseRegistry::load(&lh_path) {
                let vps_cfg = crate::config_loader::resolve_vps_config(&node_id);
                if let Some(ref vps_pub) = vps_cfg.vps_public_ip {
                    if !vps_pub.trim().is_empty() {
                        let vps_ovl = vps_cfg
                            .vps_overlay_ip
                            .clone()
                            .unwrap_or_else(|| crate::mesh::overlay_host(10));
                        let vps_end = format!("{}:4242", vps_pub.trim());
                        fresh_lh.upsert_node("vps-lighthouse", &vps_ovl, &vps_end, true, true);
                        fresh_lh.mark_active("vps-lighthouse");
                    }
                }
                let _ = fresh_lh.save(&lh_path);
                lighthouse_registry = fresh_lh;
            }

            if std::path::Path::new("/var/lib/sgx-guardian/nebula/am_lighthouse").exists() {
                let endpoint_ip = if crate::dynamic_config::is_routable_ip(&detected_ip) {
                    detected_ip.clone()
                } else {
                    crate::config_loader::load_config(&format!(
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
                        let self_overlay = nebula_ip.split('/').next().unwrap_or("").to_string();
                        lighthouse_registry.add_lighthouse(&node_id, &self_overlay, &endpoint);
                    }
                    let _ = lighthouse_registry.update_endpoint(&node_id, &endpoint);
                    lighthouse_registry.mark_active(&node_id);
                    let _ = lighthouse_registry.save(&lh_path);
                }

                println!("🗼 Starting local registry sync server (lighthouse mode)");
                let reg = OverlayRegistry::load_or_create(
                    registry_sync::REGISTRY_PATH,
                    &crate::mesh::circle_id(),
                    &crate::mesh::overlay_prefix(),
                    &crate::mesh::ca_guardian_id(),
                );
                let shared_reg: SharedRegistry = Arc::new(RwLock::new(reg));
                tokio::spawn(async move {
                    registry_sync::start_registry_server(shared_reg).await;
                });
            }
        }

        let snapshot = did_doc_publish_state.lock().await.clone();
        let resolver_ca_host = match snapshot.as_ref() {
            Some((_, ca_host, _, _)) => ca_host.clone(),
            None => ca_discovery::resolve_ca_ip_for_runtime().await,
        };
        // P1.2/P1.4: was `did_resolver = Resolver::new(...)`, which built a
        // brand-new resolver with its own fresh `Arc<RwLock<_>>` — harmless
        // while AppState was always constructed *after* this point (a clone
        // taken later just saw the new instance), but silently wrong once
        // AppState is built earlier (see the moved REST API block above):
        // AppState would keep holding a clone of the *old* resolver, and this
        // reassignment would never reach it. `set_ca_host` mutates the shared
        // config in place, so every existing clone — AppState's included —
        // sees the update immediately.
        did_resolver.set_ca_host(resolver_ca_host);
        let resolver_for_pull = did_resolver.clone();
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
                    crate::attestation_service::AttestationService::mutual_attest(
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
                let ca_host = ca_discovery::resolve_ca_ip_for_runtime().await;
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
                    match crate::did::doc_distribution::pull_and_apply_aggregate(
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
                    let expected_issuer = crate::vc::issue::known_ca_did().ok();
                    if let Err(e) =
                        crate::vc::distribution::pull_status_list_verified(
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
                            let config_path =
                                format!("{}/nebula.yaml", nebula_dir_for_registry_sync);
                            // Read the current nebula.yaml BEFORE regenerating
                            let config_before =
                                std::fs::read_to_string(&config_path).unwrap_or_default();

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

                            // Only restart Nebula if the actual YAML content changed
                            let config_after =
                                std::fs::read_to_string(&config_path).unwrap_or_default();
                            if config_before == config_after {
                                tracing::debug!(
                                    "Registry changed but nebula.yaml unchanged — skipping restart"
                                );
                            } else if let Err(e) = NebulaDaemon::reload(&config_path).await {
                                eprintln!(
                                "⚠️  Failed to reload Guardian Mesh after relay/lighthouse update: {}",
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

        if crate::mesh::is_ca() {
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

        if crate::mesh::is_ca() {
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
                        Ok(mut lh) => {
                            let vps_cfg = crate::config_loader::resolve_vps_config(
                                &node_for_local_reload,
                            );
                            if let Some(vps_pub_ip) = vps_cfg.vps_public_ip {
                                if !vps_pub_ip.trim().is_empty() {
                                    let vps_ovl_ip = vps_cfg
                                        .vps_overlay_ip
                                        .unwrap_or_else(|| crate::mesh::overlay_host(10));
                                    let vps_endpoint = format!("{}:4242", vps_pub_ip.trim());
                                    lh.upsert_node(
                                        "vps-lighthouse",
                                        &vps_ovl_ip,
                                        &vps_endpoint,
                                        true,
                                        true,
                                    );
                                    lh.mark_active("vps-lighthouse");
                                }
                            }

                            match NebulaConfig::generate_config_with_lighthouse(
                                &node_for_local_reload,
                                &pool_for_local_reload,
                                &lh,
                                &nebula_dir_for_local_reload,
                            ) {
                                Ok(changed) => {
                                    if !changed {
                                        tracing::debug!(
                                            "Local registry updated but nebula.yaml unchanged — skipping reload"
                                        );
                                        continue;
                                    }
                                    let config_path =
                                        format!("{}/nebula.yaml", nebula_dir_for_local_reload);
                                    if let Err(e) = NebulaDaemon::reload(&config_path).await {
                                        eprintln!(
                                            "⚠️ nodeA failed to reload Guardian Mesh after local registry update: {}",
                                            e
                                        );
                                    } else {
                                        println!(
                                            "🔄 Guardian Mesh reloaded after local registry update"
                                        );
                                    }
                                }
                                Err(e) => {
                                    eprintln!(
                                        "⚠️ nodeA failed to regenerate Guardian Mesh config on local registry update: {:?}",
                                        e
                                    );
                                    continue;
                                }
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

        // ── Generate Nebula config (always regenerate so IPs and lighthouse mappings stay fresh) ─────────
        if let Err(e) = NebulaConfig::generate_config_with_lighthouse(
            &node_id,
            &overlay_pool,
            &lighthouse_registry,
            &nebula_base_dir,
        ) {
            let reason = format!("Failed to generate Guardian Mesh config: {:?}", e);
            eprintln!("❌ {reason}");
            crate::mesh::lifecycle::fail(reason.clone());
            return Err(reason.into());
        }

        // Verify and fix nebula0 IP if daemon was already running
        // (handles the case where Nebula started but didn't assign the IP correctly)
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        println!("🚀 Guardian Mesh Installation Verified Successfully\n");

        // === Start Nebula ===
        let nebula_config_path = format!("{}/nebula.yaml", nebula_base_dir);
        if let Err(e) = NebulaDaemon::start(&nebula_config_path).await {
            let reason = format!("Failed to start Guardian Mesh daemon: {:?}", e);
            eprintln!("❌ {reason}");
            crate::mesh::lifecycle::fail(reason.clone());
            return Err(reason.into());
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

            if !crate::mesh::is_ca() {
                let node_for_init_pub = node_id.clone();
                let nebula_ip_for_init_pub = nebula_ip.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    // Honour the same explicit CA override and resolution order used
                    // by periodic DID synchronization.  The old boot-only resolver
                    // ignored SGX_CA_HOST and could therefore publish to a stale
                    // discovery/lighthouse address.
                    let ca_host = ca_discovery::resolve_ca_ip_for_runtime().await;
                    // Use the same runtime (SE050/TPM) signer as Circle, VC and
                    // periodic DID refresh. `KeyManager::load_or_generate` always
                    // returns the software attestation key, so the boot publish
                    // used to build a DID document around that software key: the
                    // CA rejected it as a key change, while the local copy
                    // (already saved) broke Circle-registry verification with
                    // DerivSignatureInvalid until the next periodic refresh.
                    if let Ok(km_init) =
                        crate::vc::issue::load_runtime_key_manager(&node_for_init_pub)
                    {
                        for attempt in 1..=5 {
                            if let Err(e) = crate::did::doc_distribution::pull_and_apply_aggregate(&ca_host).await {
                                tracing::warn!(
                                    "Boot DID doc pre-publish CA sync failed (attempt {}): {} — CA may be unreachable, publishing from local cache",
                                    attempt,
                                    e
                                );
                            }
                            if let Err(e) = refresh_and_publish_did_doc_inner(
                                &node_for_init_pub,
                                &km_init,
                                &nebula_ip_for_init_pub,
                                &ca_host,
                                false,
                                false,
                            )
                            .await
                            {
                                tracing::warn!(
                                    "Boot DID doc publish attempt {} failed: {}",
                                    attempt,
                                    e
                                );
                                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                            } else {
                                tracing::info!(
                                    "Boot DID doc published successfully to CA at {}",
                                    ca_host
                                );
                                let _ = crate::did::doc_distribution::pull_and_apply_aggregate(&ca_host).await;
                                break;
                            }
                        }
                    }
                });
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
            if crate::mesh::is_ca() {
                let relay_registry_path = format!("{}/relay_registry.json", nebula_base_dir);

                let mut relay_reg =
                    RelayRegistry::load_or_create(
                        &relay_registry_path,
                        &crate::mesh::circle_id(),
                    );

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
        use crate::nebula::health::NebulaHealth;

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
                if !crate::mesh::is_ca() {
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

                    match crate::nebula::lighthouse::LighthouseRegistry::load(
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
        use crate::nebula::cert_lifecycle::ExpiryMonitor;
        ExpiryMonitor::start(nebula_base_dir.clone(), node_id.clone());
    } else {
        tracing::warn!("STEP_09–14 SKIPPED: Guardian Mesh disabled by SGX_DISABLE_NEBULA");
    }

    // === CoT Deliverable Integration Start ===
    step(22, "cot subsystem gate");
    if !GATES.disable_cot {
        println!("🔗 Initializing Circle of Trust (CoT) transport-agnostic layer...");

        use crate::cot::identity::DeviceIdentity;
        use crate::cot::interface_detector::InterfaceDetector;
        use crate::cot::link_monitor::LinkMonitor;
        use crate::cot::membership::CircleMembership as CotCircleMembership;
        use crate::cot::router::CotRouter;
        use crate::cot::session_manager::{
            set_global_session_manager, SessionManager,
        };
        use crate::cot::transport_registry::TransportRegistry;
        use crate::cot::trust_engine::TrustEngine;
        use crate::cot::{failover::FailoverEngine, hotplug::HotplugWatcher};

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
            crate::mesh::circle_id(),
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

    // === NODE BROADCAST + CONFIG SYNC ===
    let detected_ip_for_broadcast = startup_config::broadcast_ip(&detected_ip, &this_node.ip);
    // Cloned this early because `detected_ip` itself is moved into a
    // `tokio::spawn` a little further down (the legacy cert-bootstrap
    // server) — P3.2's LAN advertiser, wired in near the end of this
    // function, needs its own copy that survives that move.
    let detected_ip_for_discovery = detected_ip.clone();

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
                crate::metrics_server::start_metrics_server(
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

    // === CRL gossip engine ===
    // Decentralized epidemic revocation propagation: listener on
    // SGX_CRL_GOSSIP_PORT (default 50063) + periodic anti-entropy rounds.
    // Spawns two background tokio tasks; returns immediately; runs on
    // every node role (nodeA is an ordinary gossip peer, not a hub).
    crate::crl::gossip::spawn(node_id.clone(), did_resolver.clone());

    // === CRL Offline Revocation Sync ===
    // Background loop: queues locally-issued revocations while offline and,
    // on reconnect, drives the gossip anti-entropy exchange to fetch missed
    // revocations + flush the outbound queue. No new port/listener.
    crate::crl::offline::spawn(node_id.clone(), did_resolver.clone());

    // === Comms Circle member snapshot sync ===
    // Pulls latest owner-signed Comms Circle membership state after boot and
    // periodically after reconnect, matching the live Mesh/CRL sync posture.
    crate::circle::snapshot::spawn(node_id.clone(), did_resolver.clone());

    // Secure XFER must listen on every Guardian before another peer can
    // connect to it. The REST send endpoint only queues the outbound job; the
    // engine owns both the TCP listener and the background sender tasks.
    crate::xfer::spawn(node_id.clone(), did_resolver.clone());
    // Subscribes to the notification bus and durably appends live events so
    // reconnecting consoles can replay missed notifications.
    crate::notify::spawn(node_id.clone());
    // === NMAP discovery scheduler ===
    {
        use crate::discovery::{DiscoveryScheduler, Inventory};

        let discovery_config_dir = std::env::var("SGX_GUARDIAN_DISCOVERY_CONFIG_DIR")
            .unwrap_or_else(|_| "/etc/sgx-guardian/discovery".into());
        let discovery_state_dir = std::env::var("SGX_GUARDIAN_DISCOVERY_STATE_DIR")
            .unwrap_or_else(|_| "/var/lib/sgx-guardian/discovery".into());
        let cfg_path = PathBuf::from(&discovery_config_dir).join("nmap.yaml");
        let wl_path = PathBuf::from(&discovery_config_dir).join("whitelist.yaml");
        let inv_path = PathBuf::from(&discovery_state_dir).join("inventory.json");

        let _ = std::fs::create_dir_all(&discovery_state_dir);
        let _ = std::fs::create_dir_all(&discovery_config_dir);

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
        use crate::threat::{AlertInventory, ThreatService};

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
    // === CERT BOOTSTRAP SERVER (CA only, plaintext port 50061) ===
    if crate::mesh::is_ca() {
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
    use crate::enforcement;
    use crate::policy::get_active_policy;

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

    // P1.1/P1.2 step 6: every path above that could have failed already
    // returned `Err` (and called `lifecycle::fail`) before reaching here, so
    // arriving at this point means Stage B genuinely finished — the mesh
    // subsystem is up. `mesh_gate` (P1.5) starts admitting `MeshRequired`
    // routes the instant ONLINE lands.
    //
    // Goes through CIRCLE_MEMBER explicitly rather than assuming it: an
    // already-enrolled Guardian is there already (self-transition, a no-op),
    // but a fresh or previously-failed one is still at UNENROLLED/ERROR at
    // this point, since Phases 2-7's states are not wired up yet — this
    // function's own success is what proves membership until they are (see
    // the transition table's comment on `(Unenrolled, CircleMember)`).
    if let Err(e) = crate::mesh::lifecycle::transition_to(
        crate::mesh::lifecycle::LifecycleState::CircleMember,
        None,
    ) {
        eprintln!("⚠️ Could not record CIRCLE_MEMBER lifecycle state: {e}");
    }
    if let Err(e) = crate::mesh::lifecycle::transition_to(
        crate::mesh::lifecycle::LifecycleState::Online,
        None,
    ) {
        eprintln!("⚠️ Could not record ONLINE lifecycle state: {e}");
    }

    // P3.2: make this circle discoverable on the LAN, but only if this
    // Guardian is its CA — a `Member` has nothing to advertise.
    // `discovery::advertise::run` itself also checks the role and returns
    // immediately for a `Member`, so this check is belt-and-suspenders, not
    // load-bearing; kept anyway so a `Member` boot never even spawns the
    // task.
    if let Some(profile) = crate::mesh::profile::current() {
        if matches!(profile.role, crate::mesh::profile::MeshRole::Ca) {
            let advertise_ip = detected_ip_for_discovery;
            tokio::spawn(async move {
                crate::mesh::discovery::advertise::run(profile, advertise_ip).await;
            });
        }
    }

    Ok(())
}

// Moved from src/main.rs verbatim — these had no remaining callers there
// once the body above moved here; kept private since nothing outside this
// module uses them.
async fn refresh_and_publish_did_doc(
    node_id: &str,
    km: &crate::key_manager::KeyManager,
    overlay_ip_cidr: &str,
    ca_host: &str,
    is_ca: bool,
) -> Result<(), String> {
    refresh_and_publish_did_doc_inner(node_id, km, overlay_ip_cidr, ca_host, is_ca, false).await
}

async fn refresh_and_publish_did_doc_inner(
    node_id: &str,
    km: &crate::key_manager::KeyManager,
    overlay_ip_cidr: &str,
    ca_host: &str,
    is_ca: bool,
    force: bool,
) -> Result<(), String> {
    use crate::did::{doc_distribution, doc_persistence, doc_sign, document, method};

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
        method::resolve_local(crate::did::DEFAULT_DID_PATH, dkp_pubkey_path)
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
    let dkp_version = crate::secure_element::pcr::read_dkp_key_version();
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
        crate::attestation_service::attestation_listener_port_for_node(node_id);

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
                if !is_ca {
                    // Surface CA rejection: ignoring it made a retry after a
                    // rejected publish report "published successfully".
                    doc_distribution::publish_to_ca(ca_host, node_id, existing)
                        .await
                        .map_err(|e| {
                            audit_failed(format!("DID Document publish_to_ca failed: {}", e))
                        })?;
                }
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
    // Members persist the new document only after the CA accepts it, so a
    // rejected document never replaces the local copy that Circle-registry
    // and peer verification rely on.
    if !is_ca {
        doc_distribution::publish_to_ca(ca_host, node_id, &doc)
            .await
            .map_err(|e| audit_failed(format!("DID Document publish_to_ca failed: {}", e)))?;
    }
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
            crate::did::DidRecord::load(crate::did::DEFAULT_DID_PATH)
                .map_err(|e| audit_failed(format!("VC issuer DID load failed: {}", e)))?;
        crate::vc::issue::ensure_owner_vc(&issuer, signing_km)
            .map_err(|e| audit_failed(format!("Owner VC ensure failed: {}", e)))?;
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

// `is_lan_ca_reachable`/`discover_lan_node_a` moved to `mesh::legacy` (P3.5) —
// this is the pre-Phase-3 self-bootstrap path, kept only for the hardcoded
// legacy nodeA/B/C cohort. See `mesh::legacy::discover_lan_node_a`'s doc
// comment. A Phase-2-created circle's members discover CAs through
// `mesh::discovery` instead.
