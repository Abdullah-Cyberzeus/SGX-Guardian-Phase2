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
struct CertRequestYaml {
    node_id: String,
    requested_at: String,
    overlay_ip: String,
    public_key_fingerprint: String,
    approve: bool,
    approved_at: Option<String>,
}

/// gRPC CertService implementation — registered on nodeA only.
pub struct MyCertService;

#[tonic::async_trait]
impl CertService for MyCertService {
    async fn request_certificate(
        &self,
        request: Request<CertSignRequest>,
    ) -> Result<Response<CertSignResponse>, Status> {
        let req = request.into_inner();
        let node_id = req.node_id.clone();
        let public_key_pem = req.public_key_pem.clone();

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
            let ca_cert_pem = tokio::fs::read_to_string(format!("{}/ca/ca.crt", NEBULA_BASE_DIR))
                .await
                .unwrap_or_default();

            return Ok(Response::new(CertSignResponse {
                status: "approved".into(),
                signed_cert_pem: signed_cert,
                node_key_pem: node_key,
                ca_cert_pem,
                message: format!("Certificate already exists for {}", node_id),
            }));
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
                    if parsed.approve {
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
                overlay_ip: "pending".to_string(),
                public_key_fingerprint: fingerprint,
                approve: false,
                approved_at: None,
            };

            let yaml_string = serde_yaml::to_string(&yaml_data)
                .map_err(|e| Status::internal(format!("YAML serialization failed: {}", e)))?;

            if let Err(e) = tokio::fs::write(&yaml_path, &yaml_string).await {
                eprintln!("Failed to write approval YAML: {}", e);
                return Err(Status::internal("Failed to create approval YAML"));
            }

            // Terminal instructions for admin
            println!("Approval file created:");
            println!("{}", yaml_path);
            println!();
            println!("Open this file and set:");
            println!("  approve: true");
            println!("Then save the file to approve.");
        }

        // ── 4. Async-poll YAML for approve: true ────────────────────
        let start = tokio::time::Instant::now();
        let timeout = std::time::Duration::from_secs(APPROVAL_TIMEOUT_SECS);
        let poll_interval = std::time::Duration::from_secs(APPROVAL_POLL_SECS);

        loop {
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
                }));
            }

            // Read and parse YAML
            if let Ok(content) = tokio::fs::read_to_string(&yaml_path).await {
                if let Ok(parsed) = serde_yaml::from_str::<CertRequestYaml>(&content) {
                    if parsed.approve {
                        println!("Approval detected for {}", node_id);
                        log_event(
                            "nodeA",
                            &format!("Certificate approval detected for {}", node_id),
                        );
                        break;
                    }
                }
            }

            tokio::time::sleep(poll_interval).await;
        }

        // ── 5. Sign using NebulaCA (sync — run in blocking task) ────
        println!("Signing certificate...");

        use crate::nebula::overlay::OverlayPool;

        // Load pool
        let pool_path = format!("{}/overlay_pool.json", NEBULA_BASE_DIR);

        let mut pool = OverlayPool::load_or_create(
            &pool_path,
            "guardian-circle-alpha",
            "192.168.100",
            "nodeA",
        );

        // Allocate IP
        let assigned_ip = pool
            .allocate(&node_id)
            .map(|ip| format!("{}/24", ip))
            .map_err(|e| Status::internal(format!("IP allocation failed: {}", e)))?;

        // Save updated pool
        pool.save(&pool_path)
            .map_err(|e| Status::internal(format!("Pool save failed: {}", e)))?;

        // Use CA-assigned IP
        let overlay_ip = assigned_ip;

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

        // ── 7. Update YAML with approved_at ─────────────────────────
        if let Ok(content) = tokio::fs::read_to_string(&yaml_path).await {
            if let Ok(mut parsed) = serde_yaml::from_str::<CertRequestYaml>(&content) {
                parsed.approve = true;
                parsed.approved_at = Some(chrono::Utc::now().to_rfc3339());
                if let Ok(s) = serde_yaml::to_string(&parsed) {
                    let _ = tokio::fs::write(&yaml_path, &s).await;
                }
            }
        }

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
        }))
    }
}
