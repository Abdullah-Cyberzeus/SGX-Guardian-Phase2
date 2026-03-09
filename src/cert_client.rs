//! Certificate Client (Member-side) — runs on nodeB, nodeC.

use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::logging::{log_error, log_event};
use crate::proto::sgx::cert_service_client::CertServiceClient;
use crate::proto::sgx::CertSignRequest;
use std::path::Path;
use tonic::transport::Channel;

/// Base directory — the ONLY path we use.
const NEBULA_BASE_DIR: &str = "/var/lib/sgx-guardian/nebula";

/// Retry interval (seconds).
const RETRY_INTERVAL_SECS: u64 = 5;

/// Requests a CA-signed Nebula certificate from nodeA.
///
/// Called on startup by non-CA nodes when their cert is missing.
/// Connects via PLAINTEXT to the bootstrap port (no TLS required).
/// Returns only after certificate is received. NEVER crashes or exits.
pub async fn request_certificate_from_ca(
    node_id: String,
    ca_addr: String,
    overlay_ip: String,
    public_key_pem: String,
) {
    let cert_path = format!("{}/nodes/{}.crt", NEBULA_BASE_DIR, node_id);
    let key_path = format!("{}/nodes/{}.key", NEBULA_BASE_DIR, node_id);

    // ── Idempotency: skip if cert already exists ────────────────
    if Path::new(&cert_path).exists() && Path::new(&key_path).exists() {
        return; // silent — cert already present
    }

    println!(
        "No CA-signed certificate found for {} -- requesting from CA at {}",
        node_id, ca_addr
    );
    println!("Waiting for CA approval...");

    log_event(
        &node_id,
        &format!("Starting certificate request to CA at {}", ca_addr),
    );
    log_audit(
        &node_id,
        AuditCategory::Network,
        AuditSeverity::Info,
        AuditAction::Started,
        &format!("Certificate request initiated to CA at {}", ca_addr),
    );

    let mut attempt: u32 = 0;

    loop {
        attempt += 1;

        // Re-check: cert may have appeared on local filesystem
        if Path::new(&cert_path).exists() && Path::new(&key_path).exists() {
            println!("CA-signed certificate received for {}", node_id);
            log_event(&node_id, "CA-signed certificate detected on filesystem");
            log_audit(
                &node_id,
                AuditCategory::Network,
                AuditSeverity::Info,
                AuditAction::Succeeded,
                "CA-signed certificate received (local detection)",
            );
            return;
        }

        if attempt > 1 {
            println!(
                "Certificate request attempt #{} for {} -> CA at {}",
                attempt, node_id, ca_addr
            );
        }

        match try_request(&node_id, &ca_addr, &overlay_ip, &public_key_pem).await {
            Ok(resp) => match resp.status.as_str() {
                "approved" => {
                    // Save cert if not already written by CA on same machine
                    if !Path::new(&cert_path).exists() {
                        if let Err(e) = write_file(&cert_path, &resp.signed_cert_pem).await {
                            eprintln!("Failed to save cert: {} -- will retry", e);
                            log_error(&node_id, &format!("Failed to save cert: {}", e));
                            tokio::time::sleep(std::time::Duration::from_secs(RETRY_INTERVAL_SECS))
                                .await;
                            continue;
                        }
                    }
                    if !Path::new(&key_path).exists() && !resp.node_key_pem.is_empty() {
                        if let Err(e) = write_file(&key_path, &resp.node_key_pem).await {
                            eprintln!("Failed to save key: {} -- will retry", e);
                            log_error(&node_id, &format!("Failed to save key: {}", e));
                            tokio::time::sleep(std::time::Duration::from_secs(RETRY_INTERVAL_SECS))
                                .await;
                            continue;
                        }
                    }

                    // Save CA cert if provided and missing
                    if !resp.ca_cert_pem.is_empty() {
                        let ca_path = format!("{}/ca/ca.crt", NEBULA_BASE_DIR);
                        if !Path::new(&ca_path).exists() {
                            let _ = write_file(&ca_path, &resp.ca_cert_pem).await;
                        }
                    }

                    println!("CA-signed certificate received for {}", node_id);
                    log_event(&node_id, "CA-signed certificate received and saved");
                    log_audit(
                        &node_id,
                        AuditCategory::Network,
                        AuditSeverity::Info,
                        AuditAction::Succeeded,
                        "CA-signed certificate received via gRPC",
                    );
                    return;
                }
                "pending" => {
                    if attempt == 1 {
                        println!("Certificate request pending -- waiting for admin approval on CA");
                    }
                }
                "rejected" => {
                    eprintln!(
                        "Certificate request rejected for {}: {}",
                        node_id, resp.message
                    );
                    log_audit(
                        &node_id,
                        AuditCategory::Network,
                        AuditSeverity::Warning,
                        AuditAction::Rejected,
                        &format!("Certificate request rejected: {}", resp.message),
                    );
                }
                other => {
                    eprintln!("Unknown cert response status '{}' for {}", other, node_id);
                }
            },
            Err(e) => {
                if attempt <= 3 {
                    eprintln!(
                        "Certificate request failed (attempt #{}) for {}: {} -- retrying in {}s",
                        attempt, node_id, e, RETRY_INTERVAL_SECS
                    );
                }
                log_event(
                    &node_id,
                    &format!("Certificate request attempt #{} failed: {}", attempt, e),
                );
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(RETRY_INTERVAL_SECS)).await;
    }
}

/// Single gRPC request to CA node via PLAINTEXT (bootstrap — no TLS).
async fn try_request(
    node_id: &str,
    ca_addr: &str,
    overlay_ip: &str,
    public_key_pem: &str,
) -> Result<crate::proto::sgx::CertSignResponse, String> {
    // PLAINTEXT connection — no TLS needed for bootstrap
    let endpoint = Channel::from_shared(format!("http://{}", ca_addr))
        .map_err(|e| format!("Invalid CA address: {}", e))?;

    let channel = endpoint
        .connect()
        .await
        .map_err(|e| format!("Connection to CA failed: {}", e))?;

    let mut client = CertServiceClient::new(channel);

    let request = tonic::Request::new(CertSignRequest {
        node_id: node_id.to_string(),
        public_key_pem: public_key_pem.to_string(),
        overlay_ip: overlay_ip.to_string(),
    });

    let response = client
        .request_certificate(request)
        .await
        .map_err(|e| format!("gRPC cert request failed: {}", e))?;

    Ok(response.into_inner())
}

/// Write content to file, creating parent dirs.
async fn write_file(path: &str, content: &str) -> Result<(), String> {
    if let Some(parent) = Path::new(path).parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| format!("mkdir failed: {}", e))?;
    }
    tokio::fs::write(path, content)
        .await
        .map_err(|e| format!("write failed for {}: {}", path, e))
}
