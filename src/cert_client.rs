// src/cert_client.rs  — FULL REPLACEMENT
//
// KEY FIX: When nodeA returns ca_cert_pem in the CertSignResponse,
// we now save it to <nebula_base_dir>/ca/ca.crt so that nodeB/nodeC
// share the SAME CA as nodeA.  Previously this was silently discarded
// if the file already existed, which masked the CA mismatch bug.

use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::config_loader::load_config;
use crate::logging::{log_error, log_event};
use crate::nebula::ca::NebulaCA;
use crate::proto::sgx::cert_service_client::CertServiceClient;
use crate::proto::sgx::CertSignRequest;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tonic::transport::Channel;

const NEBULA_BASE_DIR: &str = "/var/lib/sgx-guardian/nebula";
const RETRY_INTERVAL_SECS: u64 = 5;

fn valid_lan_ip(ip: &str) -> bool {
    !ip.is_empty() && ip != "0.0.0.0" && ip != "127.0.0.1"
}

fn resolve_nodea_ip_for_bootstrap() -> Option<String> {
    if let Ok(env_ip) = std::env::var("SGX_LIGHTHOUSE_IP") {
        if valid_lan_ip(&env_ip) {
            return Some(env_ip);
        }
    }

    for path in [
        "/etc/sgx-guardian/config/nodeA.yaml",
        "/etc/sgx-guardian/nodeA.yaml",
    ] {
        if let Ok(cfg) = load_config(path) {
            if valid_lan_ip(&cfg.ip) {
                return Some(cfg.ip);
            }
        }
    }
    None
}

fn split_host_port(addr: &str) -> (String, u16) {
    if let Some((host, port_s)) = addr.rsplit_once(':') {
        if let Ok(port) = port_s.parse::<u16>() {
            return (host.to_string(), port);
        }
    }
    (addr.to_string(), 50061)
}

/// Request a CA-signed Nebula certificate from nodeA.
///
/// Blocks until the cert is received.  On success:
/// - Writes <NEBULA_BASE_DIR>/nodes/<node_id>.crt
/// - Writes <NEBULA_BASE_DIR>/nodes/<node_id>.key
/// - Saves   <NEBULA_BASE_DIR>/ca/ca.crt  (CRITICAL — shared CA)
pub async fn request_certificate_from_ca(
    node_id: String,
    ca_addr: String,
    overlay_ip: String,
    public_key_pem: String,
) {
    let (_, ca_port) = split_host_port(&ca_addr);
    let mut current_ca_addr = ca_addr.clone();
    if let Some(ip) = resolve_nodea_ip_for_bootstrap() {
        current_ca_addr = format!("{}:{}", ip, ca_port);
    }

    let cert_path = format!("{}/nodes/{}.crt", NEBULA_BASE_DIR, node_id);
    let key_path = format!("{}/nodes/{}.key", NEBULA_BASE_DIR, node_id);

    // Idempotent: cert AND CA cert both present
    if Path::new(&cert_path).exists()
        && Path::new(&key_path).exists()
        && NebulaCA::ca_cert_exists(NEBULA_BASE_DIR)
    {
        println!(
            "ℹ️  Cert + CA cert already present for {} — skipping bootstrap.",
            node_id
        );
        return;
    }

    println!(
        "📡 Requesting certificate from CA at {} (overlay: {})",
        current_ca_addr, overlay_ip
    );
    log_event(
        &node_id,
        &format!("Starting certificate request to CA at {}", current_ca_addr),
    );
    log_audit(
        &node_id,
        AuditCategory::Network,
        AuditSeverity::Info,
        AuditAction::Started,
        &format!("Certificate request initiated to CA at {}", current_ca_addr),
    );

    let mut attempt: u32 = 0;

    loop {
        attempt += 1;

        if let Some(ip) = resolve_nodea_ip_for_bootstrap() {
            let refreshed = format!("{}:{}", ip, ca_port);
            if refreshed != current_ca_addr {
                println!(
                    "🔄 CA address updated from {} to {} (using latest nodeA config)",
                    current_ca_addr, refreshed
                );
                current_ca_addr = refreshed;
            }
        }

        // Re-check in case another code path wrote the files
        if Path::new(&cert_path).exists()
            && Path::new(&key_path).exists()
            && NebulaCA::ca_cert_exists(NEBULA_BASE_DIR)
        {
            println!("✅ Cert + CA cert detected on filesystem — done.");
            log_event(&node_id, "Cert + CA cert detected on filesystem");
            return;
        }

        if attempt > 1 {
            println!(
                "📡 Cert request attempt #{} → CA at {}",
                attempt, current_ca_addr
            );
        }

        match try_request(&node_id, &current_ca_addr, &overlay_ip, &public_key_pem).await {
            Ok(resp) => match resp.status.as_str() {
                "approved" => {
                    // ── Save node cert ────────────────────────────────
                    if !Path::new(&cert_path).exists() && !resp.signed_cert_pem.is_empty() {
                        if let Err(e) = write_file(&cert_path, &resp.signed_cert_pem).await {
                            eprintln!("❌ Save cert failed: {} — retrying", e);
                            log_error(&node_id, &format!("Save cert: {}", e));
                            tokio::time::sleep(std::time::Duration::from_secs(RETRY_INTERVAL_SECS))
                                .await;
                            continue;
                        }
                    }

                    // ── Save node key ─────────────────────────────────
                    if !Path::new(&key_path).exists() && !resp.node_key_pem.is_empty() {
                        if let Err(e) = write_file(&key_path, &resp.node_key_pem).await {
                            eprintln!("❌ Save key failed: {} — retrying", e);
                            log_error(&node_id, &format!("Save key: {}", e));
                            tokio::time::sleep(std::time::Duration::from_secs(RETRY_INTERVAL_SECS))
                                .await;
                            continue;
                        }
                    }

                    // ── Save CA cert (CRITICAL FIX) ───────────────────
                    // We always save the CA cert from nodeA to ensure all nodes
                    // share the same CA.  NebulaCA::save_ca_cert() handles the
                    // fingerprint comparison and warns on mismatch.
                    if !resp.ca_cert_pem.is_empty() {
                        match NebulaCA::save_ca_cert(NEBULA_BASE_DIR, &resp.ca_cert_pem) {
                            Ok(_) => {
                                if let Some(fp) = NebulaCA::ca_fingerprint(NEBULA_BASE_DIR) {
                                    println!("🔏 CA fingerprint (nodeA): {}", fp);
                                    log_event(
                                        &node_id,
                                        &format!("CA cert saved, fingerprint: {}", fp),
                                    );
                                }
                            }
                            Err(e) => {
                                eprintln!(
                                    "❌ Failed to save CA cert: {} — this will break the overlay!",
                                    e
                                );
                                log_error(&node_id, &format!("CA cert save failed: {}", e));
                                // Don't retry forever — surface the error and continue.
                            }
                        }
                    } else {
                        eprintln!(
                            "⚠️  CertSignResponse.ca_cert_pem is empty! \
                             Check cert_service.rs on nodeA is populating this field."
                        );
                    }

                    println!("✅ CA-signed certificate received from nodeA");
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
                        println!(
                            "⏳ Certificate request pending — waiting for admin approval on nodeA.\n\
                             Run on nodeA: edit {}/requests/{}.yaml → set approve: true",
                            NEBULA_BASE_DIR, node_id
                        );
                    }
                }

                "rejected" => {
                    eprintln!("❌ Certificate request rejected: {}", resp.message);
                    eprintln!("   Manual intervention required — not retrying.");
                    log_audit(
                        &node_id,
                        AuditCategory::Network,
                        AuditSeverity::Warning,
                        AuditAction::Rejected,
                        &format!("Certificate rejected: {}", resp.message),
                    );
                    return;
                }

                other => eprintln!("⚠️  Unknown cert response status: '{}'", other),
            },

            Err(e) => {
                if attempt <= 3 {
                    eprintln!(
                        "⚠️  Cert request attempt #{} failed: {} — retrying in {}s",
                        attempt, e, RETRY_INTERVAL_SECS
                    );
                }
                log_event(
                    &node_id,
                    &format!("Cert request attempt #{} failed: {}", attempt, e),
                );
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(RETRY_INTERVAL_SECS)).await;
    }
}

/// Single gRPC attempt to the CA (PLAINTEXT — bootstrap phase, no TLS yet).
async fn try_request(
    node_id: &str,
    ca_addr: &str,
    overlay_ip: &str,
    public_key_pem: &str,
) -> Result<crate::proto::sgx::CertSignResponse, String> {
    let endpoint = Channel::from_shared(format!("http://{}", ca_addr))
        .map_err(|e| format!("Invalid CA address: {}", e))?;

    let channel = endpoint
        .connect()
        .await
        .map_err(|e| format!("Connection to CA at {} failed: {}", ca_addr, e))?;

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

/// Write content to a file, creating parent dirs.
async fn write_file(path: &str, content: &str) -> Result<(), String> {
    if let Some(parent) = Path::new(path).parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| format!("mkdir {}: {}", parent.display(), e))?;
    }

    // Write atomically via temp file
    let tmp = format!("{}.tmp", path);
    tokio::fs::write(&tmp, content)
        .await
        .map_err(|e| format!("write {}: {}", tmp, e))?;
    tokio::fs::rename(&tmp, path)
        .await
        .map_err(|e| format!("rename {} → {}: {}", tmp, path, e))?;

    #[cfg(unix)]
    if path.ends_with(".key") {
        let perms = std::fs::Permissions::from_mode(0o600);
        tokio::fs::set_permissions(path, perms)
            .await
            .map_err(|e| format!("chmod {}: {}", path, e))?;
    }

    Ok(())
}
