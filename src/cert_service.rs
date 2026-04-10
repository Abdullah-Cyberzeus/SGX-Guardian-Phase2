//! Certificate Service (CA-side) — runs on nodeA ONLY.
//!
//! YAML-based manual approval + NebulaCA signing.

use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::logging::log_event;
use crate::nebula::ca::NebulaCA;
use crate::nebula::models::CircleMembership;
use crate::proto::sgx::cert_service_server::CertService;
use crate::proto::sgx::{CertSignRequest, CertSignResponse};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tonic::{Request, Response, Status};

/// Base directory — the ONLY path we use.
const NEBULA_BASE_DIR: &str = "/var/lib/sgx-guardian/nebula";

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
}

#[derive(Debug, Serialize, Deserialize)]
struct CertRequestYaml {
    node_id: String,
    requested_at: String,
    overlay_ip: String,
    public_key_fingerprint: String,
    approve: ApprovalDecision,
}

/// gRPC CertService implementation — registered on nodeA only.
pub struct MyCertService;

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

#[tonic::async_trait]
impl CertService for MyCertService {
    async fn request_certificate(
        &self,
        request: Request<CertSignRequest>,
    ) -> Result<Response<CertSignResponse>, Status> {
        let req = request.into_inner();
        let node_id = req.node_id.clone();
        let public_key_pem = req.public_key_pem.clone();
        let wants_lighthouse = req.wants_lighthouse;

        // ── 1. Log receipt ──────────────────────────────────────────
        println!("Certificate request received from {}", node_id);
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
                let signed_policy_bytes = tokio::fs::read("/etc/sgx-guardian/policies/policy.sig")
                    .await
                    .unwrap_or_default();

                return Ok(Response::new(CertSignResponse {
                    status: "approved".into(),
                    signed_cert_pem: signed_cert,
                    node_key_pem: node_key,
                    ca_cert_pem,
                    message: format!("Certificate already exists for {}", node_id),
                    assigned_lighthouse: false,
                    lighthouse_registry_json,
                    overlay_registry_json,
                    signed_policy_bytes,
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
        // ═══════════════════════════════════════════════════════════
        if Path::new(&yaml_path).exists() {
            // Read existing YAML
            if let Ok(content) = tokio::fs::read_to_string(&yaml_path).await {
                if let Ok(parsed) = serde_yaml::from_str::<CertRequestYaml>(&content) {
                    if matches!(
                        parsed.approve,
                        ApprovalDecision::Member | ApprovalDecision::Lighthouse
                    ) {
                        // Old approved YAML is stale → delete it
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
        } else {
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
                approve: ApprovalDecision::False,
            };

            let yaml_string = serde_yaml::to_string(&yaml_data)
                .map_err(|e| Status::internal(format!("YAML serialization failed: {}", e)))?;

            if let Err(e) = tokio::fs::write(&yaml_path, &yaml_string).await {
                eprintln!("Failed to write approval YAML: {}", e);
                return Err(Status::internal("Failed to create approval YAML"));
            }

            // Terminal instructions for admin
            println!("Certificate request received from {}", node_id);
            println!("  Node requested lighthouse role: {}", wants_lighthouse);
            println!();
            println!("Approval file created: {}", yaml_path);
            println!();
            println!("Edit the file and set 'approve' to ONE of:");
            println!("  approve: false        (reject the request)");
            println!("  approve: member       (accept as standard member)");
            println!("  approve: lighthouse   (accept and also make this node a Lighthouse)");
            println!();
            println!("Save the file to trigger approval.");
        }

        // ── 4. Async-poll YAML for approve: true ────────────────────
        let start = tokio::time::Instant::now();
        let timeout = std::time::Duration::from_secs(APPROVAL_TIMEOUT_SECS);
        let poll_interval = std::time::Duration::from_secs(APPROVAL_POLL_SECS);
        let assigned_lh = loop {
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
                            break false;
                        }
                        ApprovalDecision::Lighthouse => {
                            println!("Approval detected for {} (role: lighthouse)", node_id);
                            log_event(
                                "nodeA",
                                &format!("Certificate approval detected for {}", node_id),
                            );
                            break true;
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

        let membership = CircleMembership {
            node_name: node_id.clone(),
            circle_id: "guardian-circle-alpha".to_string(),
            vc_hash: "manual-approval-verified".to_string(),
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

        if assigned_lh {
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
            let member_endpoint = resolve_member_lighthouse_endpoint(&node_id);
            lh_reg.add_lighthouse(&node_id, &member_overlay, &member_endpoint);
            if let Some(entry) = lh_reg
                .lighthouses
                .iter_mut()
                .find(|l| l.node_name == node_id)
            {
                entry.overlay_ip = member_overlay.clone();
                entry.physical_endpoint = member_endpoint.clone();
                entry.is_primary = false;
                entry.is_active = true;
            }
            let _ = lh_reg.update_endpoint(&node_id, &member_endpoint);
            lh_reg.mark_active(&node_id);
            let _ = lh_reg.save(&lh_path);
            println!("🗼 Node {} promoted to Lighthouse role", node_id);
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
        let signed_policy_bytes = tokio::fs::read("/etc/sgx-guardian/policies/policy.sig")
            .await
            .unwrap_or_default();

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
        }))
    }
}
