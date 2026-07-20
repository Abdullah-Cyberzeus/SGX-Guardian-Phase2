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
use crate::nebula::registry_sync;
use crate::proto::sgx::cert_service_client::CertServiceClient;
use crate::proto::sgx::CertSignRequest;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tonic::transport::Channel;

const NEBULA_BASE_DIR: &str = "/var/lib/sgx-guardian/nebula";
const RETRY_INTERVAL_SECS: u64 = 5;

fn sync_role_marker(path: &str, enabled: bool) {
    if enabled {
        if let Err(e) = std::fs::write(path, "true") {
            eprintln!("⚠️  Failed to write marker {}: {}", path, e);
        }
        return;
    }

    if Path::new(path).exists() {
        if let Err(e) = std::fs::remove_file(path) {
            eprintln!("⚠️  Failed to remove marker {}: {}", path, e);
        }
    }
}

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
    wants_lh: bool,
    wants_relay: bool,
    pairing_proof: Option<String>,
) {
    if node_id.is_empty()
        || !node_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        eprintln!("❌ Invalid node_id for certificate bootstrap");
        return;
    }

    let (_, ca_port) = split_host_port(&ca_addr);
    let mut current_ca_addr = ca_addr.clone();
    if let Some(ip) = resolve_nodea_ip_for_bootstrap() {
        current_ca_addr = format!("{}:{}", ip, ca_port);
    }

    let cert_path = format!("{}/nodes/{}.crt", NEBULA_BASE_DIR, node_id);
    let key_path = format!("{}/nodes/{}.key", NEBULA_BASE_DIR, node_id);
    let has_vc = crate::vc::persistence::load_own_any()
        .ok()
        .flatten()
        .is_some();
    let has_status_list = crate::vc::persistence::status_list_path().exists();

    // Idempotent: cert AND CA cert both present
    if Path::new(&cert_path).exists()
        && Path::new(&key_path).exists()
        && NebulaCA::ca_cert_exists(NEBULA_BASE_DIR)
        && has_vc
        && has_status_list
    {
        println!(
            "ℹ️  Cert + CA cert + VC already present for {} — skipping bootstrap.",
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
            && crate::vc::persistence::load_own_any()
                .ok()
                .flatten()
                .is_some()
            && crate::vc::persistence::status_list_path().exists()
        {
            println!("✅ Cert + CA cert + VC detected on filesystem — done.");
            log_event(&node_id, "Cert + CA cert + VC detected on filesystem");
            return;
        }

        if attempt > 1 {
            println!(
                "📡 Cert request attempt #{} → CA at {}",
                attempt, current_ca_addr
            );
        }

        match try_request(
            &node_id,
            &current_ca_addr,
            &overlay_ip,
            &public_key_pem,
            wants_lh,
            wants_relay,
            pairing_proof.as_deref(),
        )
        .await
        {
            Ok(resp) => match resp.status.as_str() {
                "approved" => {
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
                                    "❌ Failed to save CA cert: {} — bootstrap cannot continue!",
                                    e
                                );
                                log_error(&node_id, &format!("CA cert save FATAL: {}", e));
                                log_audit(
                                    &node_id,
                                    AuditCategory::Network,
                                    AuditSeverity::Critical,
                                    AuditAction::Failed,
                                    &format!("CA cert save failed — bootstrap aborted: {}", e),
                                );
                                return; // Abort — node is half-bootstrapped, operator must fix
                            }
                        }
                    } else {
                        eprintln!(
                            "⚠️  CertSignResponse.ca_cert_pem is empty! \
                             Check cert_service.rs on nodeA is populating this field."
                        );
                    }

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

                    if !resp.overlay_registry_json.is_empty() {
                        let path = "/var/lib/sgx-guardian/nebula/overlay_registry.json";
                        match registry_sync::apply_overlay_snapshot(
                            &resp.overlay_registry_json,
                            path,
                        ) {
                            Ok(_) => println!("📋 Overlay registry synced from CA"),
                            Err(e) => eprintln!("⚠️  Overlay registry snapshot rejected: {}", e),
                        }
                    }

                    if !resp.lighthouse_registry_json.is_empty() {
                        let path = "/var/lib/sgx-guardian/nebula/lighthouse_registry.json";
                        match registry_sync::apply_lighthouse_snapshot(
                            &resp.lighthouse_registry_json,
                            path,
                        ) {
                            Ok(_) => println!("📋 Lighthouse registry synced from CA"),
                            Err(e) => eprintln!("⚠️  Lighthouse registry snapshot rejected: {}", e),
                        }
                    }

                    if resp.assigned_lighthouse {
                        println!("🗼 This node is now a LIGHTHOUSE in guardian-circle-alpha");
                    }
                    sync_role_marker(
                        "/var/lib/sgx-guardian/nebula/am_lighthouse",
                        resp.assigned_lighthouse,
                    );

                    if !resp.relay_registry_json.is_empty() {
                        let path = "/var/lib/sgx-guardian/nebula/relay_registry.json";
                        match registry_sync::apply_relay_snapshot(&resp.relay_registry_json, path) {
                            Ok(_) => println!("📋 Relay registry synced from CA"),
                            Err(e) => eprintln!("⚠️  Relay registry snapshot rejected: {}", e),
                        }
                    }

                    if resp.assigned_relay {
                        println!("🛰️ This node is now a RELAY in guardian-circle-alpha");
                        if let Err(e) = set_relay_enabled_in_node_config(&node_id) {
                            eprintln!("⚠️  Failed to enable relay in node config: {}", e);
                        }
                    }
                    sync_role_marker("/var/lib/sgx-guardian/nebula/am_relay", resp.assigned_relay);

                    // ── Save signed policy (if present) ──────────────
                    if !resp.signed_policy_bytes.is_empty() {
                        let policy_path = "/etc/sgx-guardian/policies/policy.sig";
                        if let Some(parent) = Path::new(policy_path).parent() {
                            let _ = tokio::fs::create_dir_all(parent).await;
                        }
                        if let Err(e) =
                            tokio::fs::write(policy_path, &resp.signed_policy_bytes).await
                        {
                            eprintln!("⚠️  Save signed policy failed: {}", e);
                        } else {
                            println!("📜 Signed policy saved to {}", policy_path);
                        }
                    }

                    // ── Save Policy Authority signing public key ─────
                    if !resp.signing_pubkey_der.is_empty() {
                        let pubkey_path = "/etc/sgx-guardian/policies/pa_admin_pub.der";
                        if let Some(parent) = Path::new(pubkey_path).parent() {
                            let _ = tokio::fs::create_dir_all(parent).await;
                        }
                        match tokio::fs::write(pubkey_path, &resp.signing_pubkey_der).await {
                            Ok(_) => {
                                use sha2::{Digest, Sha256};
                                let fp =
                                    hex::encode(&Sha256::digest(&resp.signing_pubkey_der)[..8]);
                                println!(
                                    "🔑 PA signing public key saved to {} (fp={})",
                                    pubkey_path, fp
                                );
                                log_event(
                                    &node_id,
                                    &format!("PA signing public key saved, fingerprint: {}", fp),
                                );
                            }
                            Err(e) => {
                                eprintln!("⚠️  Save PA pubkey failed: {}", e);
                                log_error(&node_id, &format!("PA pubkey save: {}", e));
                            }
                        }
                    }

                    if !resp.member_vc_json.is_empty() {
                        match serde_json::from_str::<crate::vc::credential::VerifiableCredential>(
                            &resp.member_vc_json,
                        ) {
                            Ok(vc) => {
                                if let Err(e) = crate::vc::persistence::save_own(&vc) {
                                    log_error(&node_id, &format!("VC save failed: {}", e));
                                } else {
                                    log_audit(
                                        &node_id,
                                        AuditCategory::Vc,
                                        AuditSeverity::Info,
                                        AuditAction::Succeeded,
                                        &format!("VC received and stored: {}", vc.id),
                                    );
                                }
                            }
                            Err(e) => log_error(&node_id, &format!("VC parse failed: {}", e)),
                        }
                    }

                    let (ca_host, _) = split_host_port(&current_ca_addr);
                    match crate::vc::distribution::pull_status_list(&ca_host).await {
                        Ok(true) => {
                            println!("📋 VC status list pulled from CA");
                            log_event(&node_id, "VC status list pulled from CA");
                        }
                        Ok(false) => {}
                        Err(e) => {
                            eprintln!("⚠️  VC status list pull failed: {}", e);
                            log_error(&node_id, &format!("VC status list pull: {}", e));
                        }
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
                             Run on nodeA: edit {}/requests/{}.yaml → set approve: member|lighthouse|relay|lh_relay",
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
    wants_lh: bool,
    wants_relay: bool,
    pairing_proof: Option<&str>,
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
        wants_lighthouse: wants_lh,
        wants_relay,
        pairing_proof: pairing_proof.unwrap_or_default().to_string(),
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

fn set_relay_enabled_in_node_config(node_id: &str) -> Result<(), String> {
    let cfg_path = format!("/etc/sgx-guardian/config/{}.yaml", node_id);
    let content =
        std::fs::read_to_string(&cfg_path).map_err(|e| format!("read {}: {}", cfg_path, e))?;
    let mut doc: serde_yaml::Value =
        serde_yaml::from_str(&content).map_err(|e| format!("yaml parse: {}", e))?;

    if !doc.is_mapping() {
        return Err("node config root is not a YAML mapping".to_string());
    }

    let map = doc.as_mapping_mut().ok_or("invalid YAML mapping")?;
    let relay_key = serde_yaml::Value::String("relay".to_string());

    let relay_mapping = map
        .entry(relay_key)
        .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));

    if !relay_mapping.is_mapping() {
        *relay_mapping = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    }

    if let Some(relay_map) = relay_mapping.as_mapping_mut() {
        relay_map.insert(
            serde_yaml::Value::String("enabled".to_string()),
            serde_yaml::Value::Bool(true),
        );
        relay_map
            .entry(serde_yaml::Value::String("max_peers".to_string()))
            .or_insert_with(|| serde_yaml::Value::Number(serde_yaml::Number::from(5)));
        relay_map
            .entry(serde_yaml::Value::String("max_bandwidth_mbps".to_string()))
            .or_insert_with(|| serde_yaml::Value::Number(serde_yaml::Number::from(10)));
        relay_map
            .entry(serde_yaml::Value::String("alert_threshold_pct".to_string()))
            .or_insert_with(|| serde_yaml::Value::Number(serde_yaml::Number::from(80)));
    }

    let updated = serde_yaml::to_string(&doc).map_err(|e| format!("yaml serialize: {}", e))?;
    std::fs::write(&cfg_path, updated).map_err(|e| format!("write {}: {}", cfg_path, e))?;
    Ok(())
}
