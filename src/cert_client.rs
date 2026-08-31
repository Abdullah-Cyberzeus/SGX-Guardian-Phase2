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

fn local_membership_vc_available() -> bool {
    crate::vc::persistence::load_own_any()
        .ok()
        .flatten()
        .is_some()
}

fn ensure_local_membership_vc(member_vc_json: &str) -> Result<Option<String>, String> {
    if member_vc_json.trim().is_empty() {
        return if local_membership_vc_available() {
            Ok(None)
        } else {
            Err("membership VC missing from CA response and no local VC is stored".to_string())
        };
    }

    let vc = serde_json::from_str::<crate::vc::credential::VerifiableCredential>(member_vc_json)
        .map_err(|e| format!("VC parse failed: {}", e))?;
    crate::vc::persistence::save_own(&vc).map_err(|e| format!("VC save failed: {}", e))?;

    match crate::vc::persistence::load_own_any() {
        Ok(Some(saved)) if saved.id == vc.id => Ok(Some(vc.id)),
        Ok(Some(saved)) => Err(format!(
            "VC saved as {} but load_own_any returned {}",
            vc.id, saved.id
        )),
        Ok(None) => Err(format!(
            "VC saved as {} but load_own_any returned no local VC",
            vc.id
        )),
        Err(e) => Err(format!("VC post-save load failed: {}", e)),
    }
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
    let has_vc = local_membership_vc_available();
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
            && local_membership_vc_available()
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

                    match ensure_local_membership_vc(&resp.member_vc_json) {
                        Ok(Some(vc_id)) => {
                            log_audit(
                                &node_id,
                                AuditCategory::Vc,
                                AuditSeverity::Info,
                                AuditAction::Succeeded,
                                &format!("VC received and stored: {}", vc_id),
                            );
                        }
                        Ok(None) => {}
                        Err(e) => {
                            let msg = format!(
                                "{}; certificate bootstrap is not complete yet, retrying",
                                e
                            );
                            eprintln!("⚠️  {}", msg);
                            log_error(&node_id, &msg);
                            tokio::time::sleep(std::time::Duration::from_secs(RETRY_INTERVAL_SECS))
                                .await;
                            continue;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::document::Proof;
    use crate::vc::credential::{
        CredentialRole, CredentialStatus, CredentialSubject, MembershipStatus,
        VerifiableCredential, TYPE_CIRCLE_MEMBERSHIP, TYPE_VC, VC_CONTEXT_CORE,
    };
    use crate::proto::sgx::cert_service_server::{CertService, CertServiceServer};
    use crate::proto::sgx::CertSignResponse;
    use once_cell::sync::Lazy;
    use std::sync::Mutex;
    use tempfile::TempDir;
    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;

    static TEST_ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    /// gRPC CertService double that always returns a canned response.
    struct MockCertService {
        response: CertSignResponse,
    }

    #[tonic::async_trait]
    impl CertService for MockCertService {
        async fn request_certificate(
            &self,
            _request: tonic::Request<CertSignRequest>,
        ) -> Result<tonic::Response<CertSignResponse>, tonic::Status> {
            Ok(tonic::Response::new(self.response.clone()))
        }
    }

    /// gRPC CertService double that always fails, to exercise the client's
    /// gRPC-status error mapping without a real CA process.
    struct MockCertErrorService;

    #[tonic::async_trait]
    impl CertService for MockCertErrorService {
        async fn request_certificate(
            &self,
            _request: tonic::Request<CertSignRequest>,
        ) -> Result<tonic::Response<CertSignResponse>, tonic::Status> {
            Err(tonic::Status::unavailable("mock CA unavailable"))
        }
    }

    /// Spins up an in-process gRPC CertService on an ephemeral loopback port
    /// so client logic (request construction, response parsing, status
    /// handling) can be exercised without any real network or CA process.
    async fn spawn_mock_cert_service<S>(service: S) -> (String, tokio::task::JoinHandle<()>)
    where
        S: CertService,
    {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock cert service");
        let addr = listener.local_addr().expect("local addr").to_string();
        let incoming = TcpListenerStream::new(listener);
        let handle = tokio::spawn(async move {
            let _ = Server::builder()
                .add_service(CertServiceServer::new(service))
                .serve_with_incoming(incoming)
                .await;
        });
        // Give the acceptor loop a moment to start before the client connects.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        (addr, handle)
    }

    #[test]
    fn ensure_local_membership_vc_saves_and_surfaces_saved_vc() {
        let _guard = TEST_ENV_LOCK.lock().expect("test env lock");
        let temp = TempDir::new().expect("tempdir");
        let previous = std::env::var_os(crate::vc::persistence::VC_BASE_ENV);
        std::env::set_var(crate::vc::persistence::VC_BASE_ENV, temp.path());

        let vc = VerifiableCredential {
            context: vec![VC_CONTEXT_CORE.to_string()],
            id: "urn:uuid:test-member-vc".to_string(),
            vc_type: vec![TYPE_VC.to_string(), TYPE_CIRCLE_MEMBERSHIP.to_string()],
            issuer: "did:guardian:issuer".to_string(),
            issuance_date: "2026-07-16T00:00:00Z".to_string(),
            expiration_date: "2027-07-16T00:00:00Z".to_string(),
            credential_subject: CredentialSubject::new(
                "did:guardian:member".to_string(),
                CredentialRole::Member,
                vec!["READ".to_string()],
                "2026-07-16T00:00:00Z".to_string(),
                "guardian-circle-alpha".to_string(),
                Some("nodeB".to_string()),
                MembershipStatus::Active,
            ),
            credential_status: CredentialStatus {
                id: "did:guardian:issuer/status-list#0".to_string(),
                status_type: "StatusList2021Entry".to_string(),
                status_purpose: "revocation".to_string(),
                status_list_index: "0".to_string(),
                status_list_credential: "did:guardian:issuer/status-list".to_string(),
            },
            proof: Proof::default(),
        };

        let result =
            ensure_local_membership_vc(&serde_json::to_string(&vc).expect("serialize test vc"))
                .expect("persist own vc");
        let loaded = crate::vc::persistence::load_own_any()
            .expect("load own any")
            .expect("saved vc");

        assert_eq!(result.as_deref(), Some(vc.id.as_str()));
        assert_eq!(loaded.id, vc.id);

        if let Some(previous) = previous {
            std::env::set_var(crate::vc::persistence::VC_BASE_ENV, previous);
        } else {
            std::env::remove_var(crate::vc::persistence::VC_BASE_ENV);
        }
    }

    #[test]
    fn lan_ip_and_host_port_parsers_cover_defaults_and_boundaries() {
        assert!(!valid_lan_ip(""));
        assert!(!valid_lan_ip("0.0.0.0"));
        assert!(!valid_lan_ip("127.0.0.1"));
        assert!(valid_lan_ip("192.168.1.20"));

        assert_eq!(split_host_port("node-a.example:50070"), ("node-a.example".into(), 50070));
        assert_eq!(split_host_port("node-a.example"), ("node-a.example".into(), 50061));
        assert_eq!(split_host_port("node-a.example:invalid"), ("node-a.example:invalid".into(), 50061));
        assert_eq!(split_host_port("10.0.0.1:0"), ("10.0.0.1".into(), 0));
    }

    #[test]
    fn role_marker_create_remove_and_missing_remove_are_idempotent() {
        let temp = TempDir::new().expect("tempdir");
        let marker = temp.path().join("roles").join("relay.enabled");
        std::fs::create_dir_all(marker.parent().expect("marker parent")).expect("create parent");
        let marker = marker.to_str().expect("utf-8 marker path");

        sync_role_marker(marker, true);
        assert_eq!(std::fs::read_to_string(marker).expect("read marker"), "true");
        sync_role_marker(marker, false);
        assert!(!Path::new(marker).exists());
        sync_role_marker(marker, false);
        assert!(!Path::new(marker).exists());
    }

    #[tokio::test]
    async fn write_file_creates_parents_replaces_content_and_secures_keys() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("nested").join("node.key");
        let path = path.to_str().expect("utf-8 path");

        write_file(path, "first").await.expect("initial write");
        write_file(path, "second").await.expect("replacement write");
        assert_eq!(tokio::fs::read_to_string(path).await.expect("read key"), "second");
        assert!(!Path::new(&format!("{path}.tmp")).exists());

        #[cfg(unix)]
        {
            let mode = std::fs::metadata(path).expect("key metadata").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn membership_vc_rejects_empty_or_malformed_payload_without_local_state() {
        let _guard = TEST_ENV_LOCK.lock().expect("test env lock");
        let temp = TempDir::new().expect("tempdir");
        let previous = std::env::var_os(crate::vc::persistence::VC_BASE_ENV);
        std::env::set_var(crate::vc::persistence::VC_BASE_ENV, temp.path());

        let empty = ensure_local_membership_vc("").expect_err("missing VC must fail");
        assert!(empty.contains("membership VC missing"));
        let malformed = ensure_local_membership_vc("not-json").expect_err("malformed VC must fail");
        assert!(malformed.contains("VC parse failed"));

        if let Some(previous) = previous {
            std::env::set_var(crate::vc::persistence::VC_BASE_ENV, previous);
        } else {
            std::env::remove_var(crate::vc::persistence::VC_BASE_ENV);
        }
    }

    #[tokio::test]
    async fn try_request_rejects_an_invalid_ca_uri_before_network_io() {
        let error = try_request("nodeB", "[invalid", "10.0.0.2", "public-key", false, false, None)
            .await
            .expect_err("invalid URI must fail");
        assert!(error.contains("Invalid CA address"));
    }

    #[tokio::test]
    async fn try_request_round_trips_status_through_a_live_grpc_server() {
        let response = CertSignResponse {
            status: "pending".to_string(),
            message: "awaiting admin approval".to_string(),
            ..Default::default()
        };
        let (addr, handle) = spawn_mock_cert_service(MockCertService { response }).await;

        let result = try_request("nodeB", &addr, "10.0.0.5", "public-key", false, false, None)
            .await
            .expect("mock cert service call should succeed");

        assert_eq!(result.status, "pending");
        assert_eq!(result.message, "awaiting admin approval");
        handle.abort();
    }

    #[tokio::test]
    async fn try_request_surfaces_grpc_status_errors_from_the_server() {
        let (addr, handle) = spawn_mock_cert_service(MockCertErrorService).await;

        let error = try_request("nodeB", &addr, "10.0.0.10", "public-key", false, false, None)
            .await
            .expect_err("server-side gRPC status must surface as an error");

        assert!(error.contains("gRPC cert request failed"));
        handle.abort();
    }

    #[tokio::test]
    async fn request_certificate_from_ca_rejects_empty_node_id_without_any_io() {
        // Must short-circuit before touching the filesystem or network —
        // otherwise this call would never return, since the retry loop only
        // exits on approval, rejection, or an invalid node_id.
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            request_certificate_from_ca(
                String::new(),
                "127.0.0.1:1".to_string(),
                "10.0.0.9".to_string(),
                "public-key".to_string(),
                false,
                false,
                None,
            ),
        )
        .await;

        assert!(outcome.is_ok(), "empty node_id must short-circuit immediately");
    }

    #[tokio::test]
    async fn request_certificate_from_ca_rejects_node_id_with_invalid_characters() {
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            request_certificate_from_ca(
                "not an id!".to_string(),
                "127.0.0.1:1".to_string(),
                "10.0.0.9".to_string(),
                "public-key".to_string(),
                false,
                false,
                None,
            ),
        )
        .await;

        assert!(
            outcome.is_ok(),
            "node_id with invalid characters must short-circuit immediately"
        );
    }

    #[tokio::test]
    async fn request_certificate_from_ca_returns_promptly_on_rejection() {
        let response = CertSignResponse {
            status: "rejected".to_string(),
            message: "not authorized".to_string(),
            ..Default::default()
        };
        let (addr, handle) = spawn_mock_cert_service(MockCertService { response }).await;

        let node_id = format!("test-reject-{}", std::process::id());
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            request_certificate_from_ca(
                node_id,
                addr,
                "10.0.0.6".to_string(),
                "public-key".to_string(),
                false,
                false,
                None,
            ),
        )
        .await;

        assert!(
            outcome.is_ok(),
            "a rejected response must return promptly rather than retry forever"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn request_certificate_from_ca_completes_approved_flow_without_privileged_writes() {
        let _guard = TEST_ENV_LOCK.lock().expect("test env lock");
        let temp = TempDir::new().expect("tempdir");
        let previous = std::env::var_os(crate::vc::persistence::VC_BASE_ENV);
        std::env::set_var(crate::vc::persistence::VC_BASE_ENV, temp.path());

        // Pre-seed a local membership VC so the mock CA's empty
        // member_vc_json resolves via the "already have one locally" branch
        // instead of requiring a fresh VC payload.
        let vc = VerifiableCredential {
            context: vec![VC_CONTEXT_CORE.to_string()],
            id: "urn:uuid:already-local-member-vc".to_string(),
            vc_type: vec![TYPE_VC.to_string(), TYPE_CIRCLE_MEMBERSHIP.to_string()],
            issuer: "did:guardian:issuer".to_string(),
            issuance_date: "2026-07-16T00:00:00Z".to_string(),
            expiration_date: "2027-07-16T00:00:00Z".to_string(),
            credential_subject: CredentialSubject::new(
                "did:guardian:member".to_string(),
                CredentialRole::Member,
                vec!["READ".to_string()],
                "2026-07-16T00:00:00Z".to_string(),
                "guardian-circle-alpha".to_string(),
                Some("nodeB".to_string()),
                MembershipStatus::Active,
            ),
            credential_status: CredentialStatus {
                id: "did:guardian:issuer/status-list#0".to_string(),
                status_type: "StatusList2021Entry".to_string(),
                status_purpose: "revocation".to_string(),
                status_list_index: "0".to_string(),
                status_list_credential: "did:guardian:issuer/status-list".to_string(),
            },
            proof: Proof::default(),
        };
        crate::vc::persistence::save_own(&vc).expect("seed local vc");

        // Every payload field that would require writing to a hardcoded,
        // root-owned system path (/var/lib/sgx-guardian/..., /etc/sgx-guardian/...)
        // is left empty/false so the CA-response handler exercises its
        // branch logic without attempting privileged filesystem writes —
        // those write bodies are not unit-testable in this sandbox (no root).
        let response = CertSignResponse {
            status: "approved".to_string(),
            ..Default::default()
        };
        let (addr, handle) = spawn_mock_cert_service(MockCertService { response }).await;

        let node_id = format!("test-approve-{}", std::process::id());
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            request_certificate_from_ca(
                node_id,
                addr,
                "10.0.0.7".to_string(),
                "public-key".to_string(),
                false,
                false,
                None,
            ),
        )
        .await;

        assert!(
            outcome.is_ok(),
            "an approved response with no privileged payload fields must return promptly"
        );

        handle.abort();
        if let Some(previous) = previous {
            std::env::set_var(crate::vc::persistence::VC_BASE_ENV, previous);
        } else {
            std::env::remove_var(crate::vc::persistence::VC_BASE_ENV);
        }
    }

    #[test]
    fn resolve_nodea_ip_for_bootstrap_prefers_env_var_over_config_files() {
        let _guard = TEST_ENV_LOCK.lock().expect("test env lock");

        // The config-file fallback reads hardcoded, unoverridable system
        // paths. Only assert the fallback-to-None behavior when those paths
        // are genuinely absent, so this test stays honest instead of
        // depending on real system state.
        let config_paths_absent = !Path::new("/etc/sgx-guardian/config/nodeA.yaml").exists()
            && !Path::new("/etc/sgx-guardian/nodeA.yaml").exists();

        let previous = std::env::var_os("SGX_LIGHTHOUSE_IP");

        std::env::set_var("SGX_LIGHTHOUSE_IP", "192.168.50.9");
        assert_eq!(
            resolve_nodea_ip_for_bootstrap(),
            Some("192.168.50.9".to_string())
        );

        if config_paths_absent {
            std::env::set_var("SGX_LIGHTHOUSE_IP", "127.0.0.1");
            assert_eq!(
                resolve_nodea_ip_for_bootstrap(),
                None,
                "invalid LAN ip in env var with no nodeA config files must resolve to None"
            );

            std::env::remove_var("SGX_LIGHTHOUSE_IP");
            assert_eq!(resolve_nodea_ip_for_bootstrap(), None);
        }

        if let Some(previous) = previous {
            std::env::set_var("SGX_LIGHTHOUSE_IP", previous);
        } else {
            std::env::remove_var("SGX_LIGHTHOUSE_IP");
        }
    }

    #[test]
    fn ensure_local_membership_vc_returns_none_when_payload_empty_but_local_vc_present() {
        let _guard = TEST_ENV_LOCK.lock().expect("test env lock");
        let temp = TempDir::new().expect("tempdir");
        let previous = std::env::var_os(crate::vc::persistence::VC_BASE_ENV);
        std::env::set_var(crate::vc::persistence::VC_BASE_ENV, temp.path());

        let vc = VerifiableCredential {
            context: vec![VC_CONTEXT_CORE.to_string()],
            id: "urn:uuid:preexisting-local-vc".to_string(),
            vc_type: vec![TYPE_VC.to_string(), TYPE_CIRCLE_MEMBERSHIP.to_string()],
            issuer: "did:guardian:issuer".to_string(),
            issuance_date: "2026-07-16T00:00:00Z".to_string(),
            expiration_date: "2027-07-16T00:00:00Z".to_string(),
            credential_subject: CredentialSubject::new(
                "did:guardian:member".to_string(),
                CredentialRole::Member,
                vec!["READ".to_string()],
                "2026-07-16T00:00:00Z".to_string(),
                "guardian-circle-alpha".to_string(),
                Some("nodeB".to_string()),
                MembershipStatus::Active,
            ),
            credential_status: CredentialStatus {
                id: "did:guardian:issuer/status-list#0".to_string(),
                status_type: "StatusList2021Entry".to_string(),
                status_purpose: "revocation".to_string(),
                status_list_index: "0".to_string(),
                status_list_credential: "did:guardian:issuer/status-list".to_string(),
            },
            proof: Proof::default(),
        };
        crate::vc::persistence::save_own(&vc).expect("seed local vc");

        let result = ensure_local_membership_vc("")
            .expect("empty payload with a local vc already present must succeed");
        assert_eq!(result, None);

        if let Some(previous) = previous {
            std::env::set_var(crate::vc::persistence::VC_BASE_ENV, previous);
        } else {
            std::env::remove_var(crate::vc::persistence::VC_BASE_ENV);
        }
    }

    #[test]
    fn set_relay_enabled_in_node_config_surfaces_read_error_for_missing_config() {
        // The target path is a hardcoded system path with no env override
        // (/etc/sgx-guardian/config/<node>.yaml), and this sandbox has no
        // write access to /etc/sgx-guardian, so only the "config file
        // missing" failure branch is exercised here — the happy-path write
        // requires root/real system state and is intentionally left uncovered.
        let node_id = format!("no-such-node-{}", std::process::id());
        let err = set_relay_enabled_in_node_config(&node_id)
            .expect_err("missing node config file must produce a read error");
        assert!(err.contains("read"));
    }
}
