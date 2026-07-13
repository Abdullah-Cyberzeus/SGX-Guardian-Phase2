//! Certificate Service (CA-side) — runs on nodeA ONLY.
//!
//! YAML-based manual approval + NebulaCA signing.

use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::config_loader::load_config;
use crate::logging::log_event;
use crate::nebula::ca::NebulaCA;
use crate::nebula::models::CircleMembership;
use crate::nebula::relay_registry::RelayRegistry;
use crate::proto::sgx::cert_service_server::CertService;
use crate::proto::sgx::{CertSignRequest, CertSignResponse};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Mutex as AsyncMutex;
use tonic::{Request, Response, Status};

/// Base directory — the ONLY path we use.
const NEBULA_BASE_DIR: &str = "/var/lib/sgx-guardian/nebula";
const RELAY_REGISTRY_PATH: &str = "/var/lib/sgx-guardian/nebula/relay_registry.json";
const PA_PUB_PATH: &str = "/etc/sgx-guardian/policies/pa_admin_pub.der";

/// Poll interval for YAML approval check (seconds).
const APPROVAL_POLL_SECS: u64 = 2;

/// Maximum wait before timeout (seconds). 1 hour.
const APPROVAL_TIMEOUT_SECS: u64 = 3600;

/// YAML structure written to nebula/requests/<node>.yaml
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ApprovalDecision {
    #[serde(alias = "false", alias = "reject", alias = "no")]
    False,
    #[serde(alias = "member")]
    Member,
    #[serde(alias = "lighthouse", alias = "lh")]
    Lighthouse,
    #[serde(alias = "relay")]
    Relay,
    #[serde(rename = "lh_relay", alias = "lhrelay", alias = "relay_lh")]
    LhRelay,
}

#[derive(Debug, Serialize, Deserialize)]
struct CertRequestYaml {
    node_id: String,
    requested_at: String,
    overlay_ip: String,
    public_key_fingerprint: String,
    requested_role: String,
    approve: ApprovalDecision,
}

/// gRPC CertService implementation — registered on nodeA only.
pub struct MyCertService;

/// Serializes concurrent certificate requests for the same node_id.
///
/// nodeB's bootstrap client (cert_client.rs) retries on any transient error
/// with no request coalescing and no gRPC deadline. Without this lock, a
/// retried request can race an in-flight one on the shared
/// requests/<node>.yaml file: the retry can misidentify the first request's
/// still-active "approved" YAML as a stale leftover and delete it out from
/// under it, silently stalling both requests. Holding this lock for the
/// whole handler serializes same-node requests; a retry that arrives while
/// the first is still being processed simply waits, then hits the
/// idempotency fast-path once the first request finishes signing.
static NODE_LOCKS: Lazy<StdMutex<HashMap<String, Arc<AsyncMutex<()>>>>> =
    Lazy::new(|| StdMutex::new(HashMap::new()));

fn node_lock(node_id: &str) -> Arc<AsyncMutex<()>> {
    let mut locks = NODE_LOCKS.lock().unwrap();
    locks
        .entry(node_id.to_string())
        .or_insert_with(|| Arc::new(AsyncMutex::new(())))
        .clone()
}

async fn read_pa_pubkey_or_warn() -> Vec<u8> {
    match tokio::fs::read(PA_PUB_PATH).await {
        Ok(b) if !b.is_empty() => b,
        _ => {
            eprintln!(
                "⚠️ PA signing public key missing at {} — member node will not receive a separate trust anchor. Run `sgx-pa-cli policy-sign-and-deploy` on nodeA to generate it.",
                PA_PUB_PATH
            );
            Vec::new()
        }
    }
}

fn issue_member_vc(node_id: &str) -> Result<crate::vc::credential::VerifiableCredential, Status> {
    let issuer = crate::did::DidRecord::load(crate::did::DEFAULT_DID_PATH)
        .map_err(|e| Status::internal(format!("CA DID load: {}", e)))?;
    let km = crate::vc::issue::load_runtime_key_manager("nodeA")
        .map_err(|e| Status::internal(format!("VC key manager: {}", e)))?;
    let subject_did = if node_id == "nodeA" {
        issuer.did.clone()
    } else {
        crate::vc::issue::subject_did_for_node(node_id)
            .map_err(|e| Status::internal(format!("VC subject DID: {}", e)))?
    };

    match crate::vc::issue::issue_membership_vc_with_outcome(
        &issuer,
        &km,
        crate::vc::issue::IssueRequest {
            subject_did: &subject_did,
            role: if node_id == "nodeA" {
                crate::vc::credential::CredentialRole::Owner
            } else {
                crate::vc::credential::CredentialRole::Member
            },
            permissions: crate::vc::issue::default_permissions_for_role(if node_id == "nodeA" {
                crate::vc::credential::CredentialRole::Owner
            } else {
                crate::vc::credential::CredentialRole::Member
            }),
            circle_id: crate::vc::issue::DEFAULT_CIRCLE_ID,
            node_hint: Some(node_id.to_string()),
            duration_days: None,
        },
    ) {
        Ok(crate::vc::issue::IssueMembershipOutcome::ReusedExisting { vc }) => {
            log_event(
                "nodeA",
                &format!(
                    "VC already exists for subject DID — reused existing credential ({})",
                    vc.id
                ),
            );
            Ok(vc)
        }
        Ok(crate::vc::issue::IssueMembershipOutcome::IssuedNew { vc, .. }) => Ok(vc),
        Err(e) => Err(Status::internal(format!("VC issue: {}", e))),
    }
}

fn cert_contains_overlay_ip(cert_path: &str, expected_ip_cidr: &str) -> bool {
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

fn resolve_member_lighthouse_endpoint(node_id: &str) -> String {
    let candidates = [
        format!("/etc/sgx-guardian/config/{}.yaml", node_id),
        format!("/etc/sgx-guardian/{}.yaml", node_id),
        format!("config/{}.yaml", node_id),
    ];

    for path in candidates {
        if let Ok(cfg) = crate::config_loader::load_config(&path) {
            if crate::dynamic_config::is_routable_ip(&cfg.ip) {
                return format!("{}:4242", cfg.ip);
            }
        }
    }

    "0.0.0.0:4242".to_string()
}

fn relay_limits_for_node(node_id: &str) -> (u32, u32) {
    let cfg_paths = [
        format!("/etc/sgx-guardian/config/{}.yaml", node_id),
        format!("/etc/sgx-guardian/{}.yaml", node_id),
    ];

    for p in cfg_paths {
        if let Ok(cfg) = load_config(&p) {
            let relay = cfg.relay_or_default();
            return (relay.max_peers, relay.max_bandwidth_mbps);
        }
    }

    // Defaults if node config not available yet
    (5, 10)
}

fn validate_node_id(node_id: &str) -> Result<(), Status> {
    if node_id.is_empty()
        || !node_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(Status::invalid_argument("invalid node_id"));
    }
    Ok(())
}
fn ensure_nodea_relay_entries(
    lh_reg: &mut crate::nebula::lighthouse::LighthouseRegistry,
    relay_reg: &mut RelayRegistry,
    overlay_ip: &str,
) {
    let node_a_endpoint = resolve_member_lighthouse_endpoint("nodeA");
    let (node_a_max_peers, node_a_max_bw) = relay_limits_for_node("nodeA");

    lh_reg.upsert_node("nodeA", overlay_ip, &node_a_endpoint, true, true);
    let _ = lh_reg.set_lighthouse_role("nodeA", true);
    let _ = lh_reg.set_relay_role("nodeA", true);
    lh_reg.mark_active("nodeA");

    relay_reg.add_relay(
        "nodeA",
        overlay_ip,
        &node_a_endpoint,
        node_a_max_peers,
        node_a_max_bw,
        true,
    );
    relay_reg.mark_active("nodeA");
}

#[tonic::async_trait]
impl CertService for MyCertService {
    async fn request_certificate(
        &self,
        request: Request<CertSignRequest>,
    ) -> Result<Response<CertSignResponse>, Status> {
        let req = request.into_inner();
        let node_id = req.node_id.clone();
        validate_node_id(&node_id)?;

        // Serialize concurrent/retried requests for this node_id — see NODE_LOCKS docs.
        let lock = node_lock(&node_id);
        let _node_guard = lock.lock().await;

        let public_key_pem = req.public_key_pem.clone();
        let wants_lighthouse = req.wants_lighthouse;
        let wants_relay = req.wants_relay;
        let requested_role = match (wants_lighthouse, wants_relay) {
            (true, true) => "lh_relay",
            (true, false) => "lighthouse",
            (false, true) => "relay",
            (false, false) => "member",
        };

        // ── 1. Log receipt ──────────────────────────────────────────
        println!("Certificate request received from {}", node_id);
        println!("  Node requested role: {}", requested_role);
        log_event(
            "nodeA",
            &format!("Certificate request received from {}", node_id),
        );
        log_audit(
            "nodeA",
            AuditCategory::Network,
            AuditSeverity::Info,
            AuditAction::Started,
            &format!("Certificate request received from {}", node_id),
        );

        // ── 2. Idempotency: cert already exists? ────────────────────
        let cert_path = format!("{}/nodes/{}.crt", NEBULA_BASE_DIR, node_id);
        let key_path = format!("{}/nodes/{}.key", NEBULA_BASE_DIR, node_id);

        if Path::new(&cert_path).exists() && Path::new(&key_path).exists() {
            // Idempotency with safety:
            // if existing cert IP doesn't match requested overlay IP, regenerate.
            let requested_overlay_ip = req.overlay_ip.clone();
            let ip_matches = requested_overlay_ip.is_empty()
                || cert_contains_overlay_ip(&cert_path, &requested_overlay_ip);

            if ip_matches {
                println!(
                    "Certificate already exists for {} — returning existing",
                    node_id
                );

                let signed_cert = tokio::fs::read_to_string(&cert_path)
                    .await
                    .unwrap_or_default();
                let node_key = tokio::fs::read_to_string(&key_path)
                    .await
                    .unwrap_or_default();
                let ca_cert_pem =
                    tokio::fs::read_to_string(format!("{}/ca/ca.crt", NEBULA_BASE_DIR))
                        .await
                        .unwrap_or_default();
                let lighthouse_registry_json = tokio::fs::read_to_string(format!(
                    "{}/lighthouse_registry.json",
                    NEBULA_BASE_DIR
                ))
                .await
                .unwrap_or_default();
                let overlay_registry_json =
                    tokio::fs::read_to_string(format!("{}/overlay_registry.json", NEBULA_BASE_DIR))
                        .await
                        .unwrap_or_default();
                let relay_registry_json = tokio::fs::read_to_string(RELAY_REGISTRY_PATH)
                    .await
                    .unwrap_or_default();
                let assigned_relay = RelayRegistry::load(RELAY_REGISTRY_PATH)
                    .map(|r| r.is_relay(&node_id))
                    .unwrap_or(false);
                let assigned_lighthouse = crate::nebula::lighthouse::LighthouseRegistry::load(
                    &format!("{}/lighthouse_registry.json", NEBULA_BASE_DIR),
                )
                .map(|r| r.is_lighthouse(&node_id))
                .unwrap_or(false);
                let signed_policy_bytes = tokio::fs::read("/etc/sgx-guardian/policies/policy.sig")
                    .await
                    .unwrap_or_default();
                let signing_pubkey_der = read_pa_pubkey_or_warn().await;
                let member_vc_json = issue_member_vc(&node_id)
                    .ok()
                    .and_then(|vc| serde_json::to_string(&vc).ok())
                    .unwrap_or_default();

                return Ok(Response::new(CertSignResponse {
                    status: "approved".into(),
                    signed_cert_pem: signed_cert,
                    node_key_pem: node_key,
                    ca_cert_pem,
                    message: format!("Certificate already exists for {}", node_id),
                    assigned_lighthouse,
                    lighthouse_registry_json,
                    overlay_registry_json,
                    signed_policy_bytes,
                    assigned_relay,
                    relay_registry_json,
                    signing_pubkey_der,
                    member_vc_json,
                }));
            } else {
                eprintln!(
                    "⚠️ Existing cert IP mismatch for {} (expected {}). Regenerating cert.",
                    node_id, requested_overlay_ip
                );
                let _ = tokio::fs::remove_file(&cert_path).await;
                let _ = tokio::fs::remove_file(&key_path).await;
            }
        }

        // ── 3. Create requests/ dir ─────────────────────────────────
        let requests_dir = format!("{}/requests", NEBULA_BASE_DIR);
        if let Err(e) = tokio::fs::create_dir_all(&requests_dir).await {
            eprintln!("Failed to create requests directory: {}", e);
            return Err(Status::internal("Failed to create requests directory"));
        }

        let yaml_path = format!("{}/{}.yaml", requests_dir, node_id);

        // ═══════════════════════════════════════════════════════════
        // IMPROVEMENT #1: Only create YAML if it does NOT already exist.
        // Repeated requests from same node skip YAML creation and
        // go straight to polling. Admin edits are never lost.
        //
        // A YAML left over from an already-approved-and-consumed request is
        // stale and gets deleted — but a *fresh* one must be written in its
        // place (needs_new_yaml), otherwise this request silently polls a
        // file that no longer exists until the 1-hour timeout, and the
        // admin never sees a new approval prompt.
        // ═══════════════════════════════════════════════════════════
        let mut needs_new_yaml = true;

        if Path::new(&yaml_path).exists() {
            needs_new_yaml = false;
            // Read existing YAML
            if let Ok(content) = tokio::fs::read_to_string(&yaml_path).await {
                if let Ok(parsed) = serde_yaml::from_str::<CertRequestYaml>(&content) {
                    if matches!(
                        parsed.approve,
                        ApprovalDecision::Member
                            | ApprovalDecision::Lighthouse
                            | ApprovalDecision::Relay
                            | ApprovalDecision::LhRelay
                    ) {
                        // Old approved YAML is stale → delete it and re-request approval
                        println!(
                            "⚠️ Stale approved YAML detected for {} — deleting old request",
                            node_id
                        );

                        log_event(
                            "nodeA",
                            &format!(
                                "Deleting stale approved YAML for {} before new request",
                                node_id
                            ),
                        );

                        let _ = tokio::fs::remove_file(&yaml_path).await;
                        needs_new_yaml = true;
                    } else {
                        // Pending request still valid
                        println!(
                            "YAML already exists for {} — request still pending, resuming poll",
                            node_id
                        );

                        log_event(
                            "nodeA",
                            &format!("Existing pending YAML for {} — polling continues", node_id),
                        );
                    }
                }
            }
        }

        if needs_new_yaml {
            // Fingerprint from public key (first 16 hex chars of SHA-256)
            let fingerprint = {
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(public_key_pem.as_bytes());
                hex::encode(&hash[..8])
            };

            let yaml_data = CertRequestYaml {
                node_id: node_id.clone(),
                requested_at: chrono::Utc::now().to_rfc3339(),
                overlay_ip: req.overlay_ip.clone(),
                public_key_fingerprint: fingerprint,
                requested_role: requested_role.to_string(),
                approve: ApprovalDecision::False,
            };

            let yaml_string = serde_yaml::to_string(&yaml_data)
                .map_err(|e| Status::internal(format!("YAML serialization failed: {}", e)))?;

            if let Err(e) = tokio::fs::write(&yaml_path, &yaml_string).await {
                eprintln!("Failed to write approval YAML: {}", e);
                return Err(Status::internal("Failed to create approval YAML"));
            }

            // Terminal instructions for admin
            println!();
            println!("Approval file created: {}", yaml_path);
            println!();
            println!("Edit the file and set 'approve' to ONE of:");
            println!("  approve: false        (reject the request)");
            println!("  approve: member       (accept as standard member)");
            println!("  approve: lighthouse   (accept as lighthouse only)");
            println!("  approve: relay        (accept as relay only)");
            println!("  approve: lh_relay     (accept as lighthouse + relay)");
            println!();
            println!("Save the file to trigger approval.");
        }

        // ── 4. Async-poll YAML for approve: true ────────────────────
        let start = tokio::time::Instant::now();
        let timeout = std::time::Duration::from_secs(APPROVAL_TIMEOUT_SECS);
        let poll_interval = std::time::Duration::from_secs(APPROVAL_POLL_SECS);
        let (assigned_lh, assigned_relay) = loop {
            if start.elapsed() > timeout {
                println!(
                    "Approval timeout for {} after {} seconds",
                    node_id, APPROVAL_TIMEOUT_SECS
                );
                log_audit(
                    "nodeA",
                    AuditCategory::Network,
                    AuditSeverity::Warning,
                    AuditAction::Failed,
                    &format!("Certificate approval timeout for {}", node_id),
                );
                return Ok(Response::new(CertSignResponse {
                    status: "pending".into(),
                    signed_cert_pem: String::new(),
                    node_key_pem: String::new(),
                    ca_cert_pem: String::new(),
                    message: format!(
                        "Approval timeout after {} seconds. Request still pending.",
                        APPROVAL_TIMEOUT_SECS
                    ),
                    assigned_lighthouse: false,
                    lighthouse_registry_json: String::new(),
                    overlay_registry_json: String::new(),
                    signed_policy_bytes: Vec::new(),
                    assigned_relay: false,
                    relay_registry_json: String::new(),
                    signing_pubkey_der: Vec::new(),
                    member_vc_json: String::new(),
                }));
            }

            // Read and parse YAML
            if let Ok(content) = tokio::fs::read_to_string(&yaml_path).await {
                if let Ok(parsed) = serde_yaml::from_str::<CertRequestYaml>(&content) {
                    match parsed.approve {
                        ApprovalDecision::False => {}
                        ApprovalDecision::Member => {
                            println!("Approval detected for {} (role: member)", node_id);
                            log_event(
                                "nodeA",
                                &format!("Certificate approval detected for {}", node_id),
                            );
                            break (false, false);
                        }
                        ApprovalDecision::Lighthouse => {
                            println!("Approval detected for {} (role: lighthouse)", node_id);
                            log_event(
                                "nodeA",
                                &format!("Certificate approval detected for {}", node_id),
                            );
                            break (true, false);
                        }
                        ApprovalDecision::Relay => {
                            println!("Approval detected for {} (role: relay)", node_id);
                            log_event(
                                "nodeA",
                                &format!("Certificate approval detected for {}", node_id),
                            );
                            break (false, true);
                        }
                        ApprovalDecision::LhRelay => {
                            println!("Approval detected for {} (role: lh_relay)", node_id);
                            log_event(
                                "nodeA",
                                &format!("Certificate approval detected for {}", node_id),
                            );
                            break (true, true);
                        }
                    }
                }
            }

            tokio::time::sleep(poll_interval).await;
        };

        // ── 5. Sign using NebulaCA (sync — run in blocking task) ────
        println!("Signing certificate...");

        use crate::nebula::overlay_registry::OverlayRegistry;
        use crate::nebula::registry_sync::REGISTRY_PATH;

        // IMPORTANT:
        // Use the same OverlayRegistry that registry_sync uses.
        // This keeps cert IP assignment consistent with previously assigned
        // member IPs and prevents nodeB/nodeC swap during approval races.
        let mut reg = OverlayRegistry::load_or_create(
            REGISTRY_PATH,
            "guardian-circle-alpha",
            "192.168.100",
            "nodeA",
        );

        let overlay_ip = if let Some(existing) = reg.get_ip_cidr(&node_id) {
            existing.to_string()
        } else if !req.overlay_ip.is_empty() && req.overlay_ip.starts_with("192.168.100.") {
            reg.set_ip(&node_id, &req.overlay_ip)
                .map_err(|e| Status::internal(format!("Registry set failed: {}", e)))?;
            req.overlay_ip.clone()
        } else {
            reg.assign_ip(&node_id)
                .map_err(|e| Status::internal(format!("Registry IP allocation failed: {}", e)))?
        };

        reg.save(REGISTRY_PATH)
            .map_err(|e| Status::internal(format!("Registry save failed: {}", e)))?;

        println!("📋 CA assigned overlay IP: {} → {}", node_id, overlay_ip);

        // Best-effort member VC issuance. A failure here (e.g. the member's DID
        // document is not yet resolvable on the CA) must NOT abort signing the
        // Nebula certificate — the cert is what the member actually needs to
        // join the overlay. Previously a `?` hard-failed the whole request, so
        // the cert was never persisted, nodeA never hit its idempotency
        // fast-path, and every retry re-created the approval YAML (an endless
        // re-approval loop). This mirrors the idempotency path above, which
        // already treats the VC as best-effort. The error is logged loudly so
        // the real cause (e.g. a missing/duplicate member DID) stays visible.
        let (member_vc_json, vc_hash) = match issue_member_vc(&node_id) {
            Ok(vc) => (
                serde_json::to_string(&vc).unwrap_or_default(),
                vc.id.clone(),
            ),
            Err(e) => {
                eprintln!(
                    "⚠️ Member VC not issued for {} (continuing to sign Nebula cert): {}",
                    node_id, e
                );
                log_event(
                    "nodeA",
                    &format!("Member VC issuance failed for {}: {}", node_id, e),
                );
                // Non-empty placeholder so validate_circle_membership() still
                // permits signing the Nebula cert.
                (String::new(), format!("bootstrap-{}", node_id))
            }
        };

        let membership = CircleMembership {
            node_name: node_id.clone(),
            circle_id: "guardian-circle-alpha".to_string(),
            vc_hash,
            is_valid: true,
        };

        let nebula_base = NEBULA_BASE_DIR.to_string();
        let ip_clone = overlay_ip.clone();

        let sign_result = tokio::task::spawn_blocking(move || {
            NebulaCA::issue_node_cert(&nebula_base, &membership, &ip_clone)
        })
        .await
        .map_err(|e| Status::internal(format!("Task join error: {}", e)))?;

        if let Err(e) = sign_result {
            eprintln!("Certificate signing failed for {}: {}", node_id, e);
            log_audit(
                "nodeA",
                AuditCategory::Network,
                AuditSeverity::Critical,
                AuditAction::Failed,
                &format!("Certificate signing failed for {}: {}", node_id, e),
            );
            return Err(Status::internal(format!("NebulaCA signing failed: {}", e)));
        }

        use crate::nebula::lighthouse::LighthouseRegistry;
        let lh_path = format!("{}/lighthouse_registry.json", NEBULA_BASE_DIR);
        let mut lh_reg = LighthouseRegistry::load_or_create(
            &lh_path,
            "guardian-circle-alpha",
            "nodeA",
            "192.168.100.1",
            "0.0.0.0:4242",
        );
        let member_overlay = overlay_ip.split('/').next().unwrap_or("").to_string();
        let node_a_overlay = reg
            .get_ip("nodeA")
            .map(|s| s.to_string())
            .unwrap_or_else(|| "192.168.100.1".to_string());
        let member_endpoint = resolve_member_lighthouse_endpoint(&node_id);

        // Always keep nodeA anchored as lighthouse+relay, even when additional relay
        // nodes are approved later.
        let mut relay_reg =
            RelayRegistry::load_or_create(RELAY_REGISTRY_PATH, "guardian-circle-alpha");
        ensure_nodea_relay_entries(&mut lh_reg, &mut relay_reg, &node_a_overlay);

        // Always keep an endpoint record for approved nodes (member/lighthouse/relay).
        // This lets static_host_map include reachable endpoints for relay forwarding paths.
        lh_reg.upsert_node(
            &node_id,
            &member_overlay,
            &member_endpoint,
            assigned_lh,
            assigned_relay,
        );
        // Keep role flags explicitly consistent in lighthouse registry snapshots.
        let _ = lh_reg.set_relay_role(&node_id, assigned_relay);
        let _ = lh_reg.set_lighthouse_role(&node_id, assigned_lh);

        if assigned_lh {
            println!("🗼 Node {} promoted to Lighthouse role", node_id);
        }
        if assigned_relay {
            println!("🛰️ Node {} promoted to Relay role", node_id);
        }
        let _ = lh_reg.update_endpoint(&node_id, &member_endpoint);
        lh_reg.mark_active(&node_id);
        if let Err(e) = lh_reg.save(&lh_path) {
            eprintln!("⚠️ Failed to save lighthouse registry: {}", e);
        }

        if assigned_relay {
            let (max_peers, max_bw) = relay_limits_for_node(&node_id);
            relay_reg.add_relay(
                &node_id,
                &member_overlay,
                &member_endpoint,
                max_peers,
                max_bw,
                assigned_lh,
            );
            relay_reg.mark_active(&node_id);
        } else {
            relay_reg.remove_relay(&node_id);
        }
        if let Err(e) = relay_reg.save(RELAY_REGISTRY_PATH) {
            eprintln!("⚠️ Failed to save relay registry: {}", e);
        }

        // ── 6. Read generated cert/key ──────────────────────────────
        let signed_cert = tokio::fs::read_to_string(&cert_path)
            .await
            .map_err(|e| Status::internal(format!("Failed to read signed cert: {}", e)))?;

        let node_key = tokio::fs::read_to_string(&key_path)
            .await
            .map_err(|e| Status::internal(format!("Failed to read node key: {}", e)))?;

        let ca_cert_pem = tokio::fs::read_to_string(format!("{}/ca/ca.crt", NEBULA_BASE_DIR))
            .await
            .unwrap_or_default();
        let lighthouse_registry_json =
            tokio::fs::read_to_string(format!("{}/lighthouse_registry.json", NEBULA_BASE_DIR))
                .await
                .unwrap_or_default();
        let overlay_registry_json =
            tokio::fs::read_to_string(format!("{}/overlay_registry.json", NEBULA_BASE_DIR))
                .await
                .unwrap_or_default();
        let relay_registry_json = tokio::fs::read_to_string(RELAY_REGISTRY_PATH)
            .await
            .unwrap_or_default();
        let signed_policy_bytes = tokio::fs::read("/etc/sgx-guardian/policies/policy.sig")
            .await
            .unwrap_or_default();
        let signing_pubkey_der = read_pa_pubkey_or_warn().await;

        println!("Certificate approved and signed for {}", node_id);
        // Remove YAML after successful signing
        let _ = tokio::fs::remove_file(&yaml_path).await;
        println!("Approval YAML removed for {}", node_id);
        log_audit(
            "nodeA",
            AuditCategory::Network,
            AuditSeverity::Info,
            AuditAction::Succeeded,
            &format!("Certificate signed for {} via NebulaCA", node_id),
        );

        Ok(Response::new(CertSignResponse {
            status: "approved".into(),
            signed_cert_pem: signed_cert,
            node_key_pem: node_key,
            ca_cert_pem,
            message: format!("Certificate approved and signed for {}", node_id),
            assigned_lighthouse: assigned_lh,
            lighthouse_registry_json,
            overlay_registry_json,
            signed_policy_bytes,
            assigned_relay,
            relay_registry_json,
            signing_pubkey_der,
            member_vc_json,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::{ensure_nodea_relay_entries, ApprovalDecision};
    use crate::nebula::lighthouse::LighthouseRegistry;
    use crate::nebula::relay_registry::RelayRegistry;

    #[test]
    fn test_approval_decision_parses_relay() {
        let relay: ApprovalDecision = serde_yaml::from_str("relay").unwrap();
        let lh_relay: ApprovalDecision = serde_yaml::from_str("lh_relay").unwrap();
        let lighthouse: ApprovalDecision = serde_yaml::from_str("lighthouse").unwrap();
        let member: ApprovalDecision = serde_yaml::from_str("member").unwrap();
        let reject: ApprovalDecision = serde_yaml::from_str("false").unwrap();

        assert!(matches!(relay, ApprovalDecision::Relay));
        assert!(matches!(lh_relay, ApprovalDecision::LhRelay));
        assert!(matches!(lighthouse, ApprovalDecision::Lighthouse));
        assert!(matches!(member, ApprovalDecision::Member));
        assert!(matches!(reject, ApprovalDecision::False));
    }

    #[test]
    fn test_ensure_nodea_relay_entries_preserves_owner_relay_registration() {
        let mut lh_reg =
            LighthouseRegistry::new("alpha", "nodeA", "192.168.100.1", "10.0.0.1:4242");
        let mut relay_reg = RelayRegistry::new("alpha");

        ensure_nodea_relay_entries(&mut lh_reg, &mut relay_reg, "192.168.100.1");

        let node_a_lh = lh_reg
            .lighthouses
            .iter()
            .find(|entry| entry.node_name == "nodeA")
            .expect("nodeA lighthouse entry should exist");
        assert!(node_a_lh.is_lighthouse);
        assert!(node_a_lh.am_relay);
        assert!(relay_reg.is_relay("nodeA"));
        assert!(
            relay_reg
                .relays
                .get("nodeA")
                .expect("nodeA relay entry should exist")
                .is_lighthouse
        );
    }
}
