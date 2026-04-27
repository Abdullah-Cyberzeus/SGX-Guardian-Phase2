//! Core attestation orchestration logic for exchanging and verifying
//! evidence between SGX Guardian nodes.
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::config_loader::{load_config, NodeConfig};
use crate::key_manager::KeyManager;
use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use chrono::DateTime;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;
use tokio::sync::mpsc::Receiver;
use tokio::time::Duration;

// ---- Attestation identity key base path (single source of truth) ----
const ATTESTATION_KEY_DIR: &str = "/var/lib/sgx-guardian/sgx-agent";
const CONNECT_RETRY_ATTEMPTS: u8 = 5;
const CONNECT_RETRY_DELAY_MS: u64 = 1000;
const MAX_TRUSTED_PEER_AGE_HOURS: i64 = 24;
const ATTEST_ATTEMPT_THROTTLE_SECS: u64 = 30;
const MAX_ATTEST_EVIDENCE_BYTES: u32 = 256 * 1024;
static LIGHTHOUSE_WARNING_PRINTED: AtomicBool = AtomicBool::new(false);
static OVERLAY_WAIT_LOGGED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
const DEFAULT_ATTEST_POLICY_YAML: &str = r#"---
policy_id: "123e4567-e89b-12d3-a456-426614174000"
version: "1.0.0"
description: "Default Guardian Edge Policy"
rules:
  - id: "rule-001"
    action: "ALLOW"
    src: "10.0.0.0/24"
    dst: "0.0.0.0/0"
    protocol: "TCP"
    port: 443
  - id: "rule-005"
    action: "DENY"
    src: "0.0.0.0/0"
    dst: "10.0.0.10"
    protocol: "UDP"
"#;

// Trusted Peer JSON Logging Helpers ===
use chrono::Utc;
use std::fs;
/// Represents a peer that successfully passed attestation
/// and is stored in the per-node trusted peers file.
#[derive(Serialize, Deserialize)]
struct TrustedPeer {
    peer_id: String,
    ip: String,
    status: String,
    timestamp: String,
}
/// Stores the most recent attestation result for a peer,
/// including digest, result (success/fail), and timestamp.
#[derive(Serialize, Deserialize)]
struct LastAttestation {
    peer_id: String,
    policy_digest: String,
    result: String,
    timestamp: String,
}
/// Writes or updates trusted peer info into the per-node JSON file
/// and then merges all peer files into a global combined view.
fn write_trusted_peer(peer_id: &str, ip: &str) {
    // Identify node name (nodeA / nodeB / nodeC)
    let node = std::env::args().nth(1).unwrap_or("nodeX".into());
    let prod_file = format!("/var/log/sgx-guardian/trusted_peers_{}.json", node);
    let dev_file = format!(
        "{}/logs/trusted_peers_{}.json",
        std::env::var("SGX_GUARDIAN_HOME").unwrap_or_else(|_| "/var/lib/sgx-guardian".into()),
        node
    );
    let entry = TrustedPeer {
        peer_id: peer_id.to_string(),
        ip: ip.to_string(),
        status: "verified".to_string(),
        timestamp: Utc::now().to_rfc3339(),
    };

    // Load existing per-node file (NOT global file)
    let mut data = Vec::<TrustedPeer>::new();
    let existing = fs::read_to_string(&prod_file).or_else(|_| fs::read_to_string(&dev_file));

    if let Ok(existing) = existing {
        if let Ok(parsed) = serde_json::from_str::<Vec<TrustedPeer>>(&existing) {
            data = parsed;
        }
    }

    // Update or insert
    let mut updated = false;
    for p in data.iter_mut() {
        if p.peer_id == peer_id {
            p.timestamp = entry.timestamp.clone();
            p.status = "verified".to_string();
            updated = true;
            break;
        }
    }
    if !updated {
        data.push(entry);
    }

    // Save back to per-node file
    if let Ok(json) = serde_json::to_string_pretty(&data) {
        let _ = fs::write(&prod_file, &json);
        let _ = fs::create_dir_all("logs");
        let _ = fs::write(&dev_file, &json);
    } else {
        eprintln!(
            "⚠️ Failed to serialize trusted peer list for trusted_peers_{}.json",
            node
        );
    }
    merge_parent_peer_file();
}
/// Saves the latest attestation result for a peer into
/// `/var/log/sgx-guardian/last_attestation.json` for debugging & audit visibility.
fn write_last_attestation(peer_id: &str, policy_digest: &str, result: &str) {
    let record = LastAttestation {
        peer_id: peer_id.to_string(),
        policy_digest: policy_digest.to_string(),
        result: result.to_string(),
        timestamp: Utc::now().to_rfc3339(),
    };

    if let Ok(json) = serde_json::to_string_pretty(&record) {
        let _ = fs::write("/var/log/sgx-guardian/last_attestation.json", &json);
        let _ = fs::create_dir_all("logs");
        let _ = fs::write("logs/last_attestation.json", &json);
    } else {
        eprintln!("⚠️ Failed to write last_attestation.json");
    }
}
/// Merges all `trusted_peers_nodeX.json` files into a single
/// `trusted_peers.json` by removing duplicates and combining entries.
fn merge_parent_peer_file() {
    use serde_json::Value;
    use std::fs;

    let mut merged: Vec<Value> = vec![];

    // Read all per-node files
    let entries = std::fs::read_dir("/var/log/sgx-guardian").or_else(|_| std::fs::read_dir("logs"));

    let entries = match entries {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();

        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with("trusted_peers_node") && name.ends_with(".json") {
                if let Ok(text) = fs::read_to_string(&path) {
                    if let Ok(arr) = serde_json::from_str::<Vec<Value>>(&text) {
                        merged.extend(arr);
                    }
                }
            }
        }
    }

    // remove duplicates by peer_id
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    merged.retain(|v| {
        if let Some(id) = v.get("peer_id").and_then(|x| x.as_str()) {
            if seen.contains(id) {
                false
            } else {
                seen.insert(id.to_string());
                true
            }
        } else {
            false
        }
    });

    // write parent file
    if let Ok(json) = serde_json::to_string_pretty(&merged) {
        let _ = fs::write("/var/log/sgx-guardian/trusted_peers.json", &json);
        let _ = fs::create_dir_all("logs");
        let _ = fs::write("logs/trusted_peers.json", &json);
    } else {
        eprintln!("⚠️ Failed to merge trusted peer JSON");
    }
}

fn load_node_config_for_attestation(node_id: &str) -> Result<NodeConfig> {
    let candidates = [
        format!("/etc/sgx-guardian/config/{}.yaml", node_id),
        format!("/etc/sgx-guardian/{}.yaml", node_id),
        format!("config/{}.yaml", node_id),
    ];

    for path in candidates {
        if let Ok(conf) = load_config(&path) {
            return Ok(conf);
        }
    }

    anyhow::bail!(
        "Failed to load node config for {} from /etc/sgx-guardian/config, /etc/sgx-guardian, or local config/",
        node_id
    )
}

fn allowed_attestation_targets(local_node_id: &str) -> HashSet<String> {
    let mut targets = HashSet::new();
    for node in ["nodeA", "nodeB", "nodeC"] {
        if node == local_node_id {
            continue;
        }
        if let Ok(conf) = load_node_config_for_attestation(node) {
            if crate::dynamic_config::is_routable_ip(&conf.ip) {
                targets.insert(format!("{}:{}", conf.ip, conf.port + 100));
            }
            if let Some(overlay_ip) = overlay_ip_from_local_registry(node) {
                targets.insert(format!("{}:{}", overlay_ip, conf.port + 100));
            }
        }
    }
    targets
}

fn parse_peer_addr(peer_id: &str) -> Option<(String, u16)> {
    let (ip, port_s) = peer_id.split_once(':')?;
    let port = port_s.parse::<u16>().ok()?;
    Some((ip.to_string(), port))
}

fn parse_bool_env(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => default,
    }
}

#[derive(Debug, Clone)]
struct AttestationPolicyMaterial {
    yaml: String,
    digest: String,
    source: &'static str,
}

fn is_hex_digest_64(input: &str) -> bool {
    input.len() == 64 && input.bytes().all(|b| b.is_ascii_hexdigit())
}

fn load_attestation_policy_material() -> AttestationPolicyMaterial {
    // Strict precedence — DETERMINISTIC across all nodes in a Circle.
    //
    // 1. If a signed policy was activated at startup, use it (canonical bytes).
    // 2. Otherwise, ALL nodes must use the same shared schema file at the
    //    well-known path. The file is canonicalised before hashing.
    // 3. If the file is missing OR fails canonical parsing, we DO NOT fall
    //    back to a different YAML — that would silently produce a different
    //    digest and break mutual attestation. Instead, we use a constant
    //    canonical-form digest derived from DEFAULT_ATTEST_POLICY_YAML so
    //    every node hits the same hash. We also log a critical warning.

    if let Some(active) = crate::policy::get_active_policy() {
        let canonical = crate::policy::canonical_policy_bytes(&active);
        let yaml = String::from_utf8_lossy(&canonical).to_string();
        let digest = hex::encode(Sha256::digest(yaml.as_bytes()));
        return AttestationPolicyMaterial {
            yaml,
            digest,
            source: "runtime-active-policy",
        };
    }

    // Try to load the shared schema file. ALWAYS canonicalise before hashing.
    let schema_path = "/etc/sgx-guardian/schemas/uep_policy_v1.yaml";
    if let Ok(file_yaml) = fs::read_to_string(schema_path) {
        match crate::policy::validate_policy(&file_yaml) {
            Ok(parsed) => {
                let canonical = crate::policy::canonical_policy_bytes(&parsed);
                let yaml = String::from_utf8_lossy(&canonical).to_string();
                let digest = hex::encode(Sha256::digest(yaml.as_bytes()));
                return AttestationPolicyMaterial {
                    yaml,
                    digest,
                    source: "schema-canonical",
                };
            }
            Err(e) => {
                tracing::error!(
                    "Policy schema {} failed validation: {} — \
                     falling back to constant default. Mutual attestation may \
                     fail with peers that have a valid schema. Fix the schema \
                     file on this node ASAP.",
                    schema_path,
                    e
                );
            }
        }
    } else {
        tracing::error!(
            "Policy schema {} missing. Mutual attestation may fail with peers \
             that have the schema. Restore /etc/sgx-guardian/schemas/uep_policy_v1.yaml.",
            schema_path
        );
    }

    // Last-resort: deterministic constant across all builds of this binary.
    let parsed =
        crate::policy::validate_policy(DEFAULT_ATTEST_POLICY_YAML).expect("default policy valid");
    let canonical = crate::policy::canonical_policy_bytes(&parsed);
    let yaml = String::from_utf8_lossy(&canonical).to_string();
    let digest = hex::encode(Sha256::digest(yaml.as_bytes()));
    AttestationPolicyMaterial {
        yaml,
        digest,
        source: "constant-default",
    }
}

fn infer_node_id_from_base_port(base_port: u16) -> Option<&'static str> {
    match base_port {
        50051 => Some("nodeA"),
        50052 => Some("nodeB"),
        50053 => Some("nodeC"),
        _ => None,
    }
}

fn infer_node_id_from_peer(peer_ip: &str, base_port: u16) -> Option<String> {
    if let Some(node_id) = infer_node_id_from_base_port(base_port) {
        return Some(node_id.to_string());
    }

    for node in ["nodeA", "nodeB", "nodeC"] {
        if let Ok(conf) = load_node_config_for_attestation(node) {
            if conf.port == base_port && conf.ip == peer_ip {
                return Some(node.to_string());
            }
        }
    }
    None
}

fn overlay_ip_from_local_registry(node_id: &str) -> Option<String> {
    let reg = crate::nebula::overlay_registry::OverlayRegistry::load(
        crate::nebula::registry_sync::REGISTRY_PATH,
    )
    .ok()?;
    reg.get_ip(node_id).map(|s| s.to_string())
}

async fn resolve_overlay_ip_for_node(node_id: &str) -> Option<String> {
    if let Some(ip) = overlay_ip_from_local_registry(node_id) {
        return Some(ip);
    }

    // On member nodes, ask nodeA's registry service for authoritative mapping.
    let ca_cfg = load_node_config_for_attestation("nodeA").ok()?;
    if !crate::dynamic_config::is_routable_ip(&ca_cfg.ip) {
        return None;
    }

    match crate::nebula::registry_sync::query_ip_from_ca(node_id, &ca_cfg.ip).await {
        Ok((_, ip)) if crate::dynamic_config::is_routable_ip(&ip) => Some(ip),
        _ => None,
    }
}

async fn resolve_attestation_target(
    peer_ip: &str,
    base_port: u16,
    overlay_only: bool,
) -> Option<(String, u16, String)> {
    let peer_node_id =
        infer_node_id_from_peer(peer_ip, base_port).unwrap_or_else(|| "unknown".into());
    let attest_port = base_port.saturating_add(100);

    if let Some(overlay_ip) = resolve_overlay_ip_for_node(&peer_node_id).await {
        return Some((overlay_ip, attest_port, peer_node_id));
    }

    if overlay_only {
        let seen = OVERLAY_WAIT_LOGGED.get_or_init(|| Mutex::new(HashSet::new()));
        if let Ok(mut seen_nodes) = seen.lock() {
            if seen_nodes.insert(peer_node_id.clone()) {
                eprintln!(
                    "⚠️ Overlay-only: waiting for registry sync before attesting {}",
                    peer_node_id
                );
            }
        }
        return None;
    }

    if crate::dynamic_config::is_routable_ip(peer_ip) {
        Some((peer_ip.to_string(), attest_port, peer_node_id))
    } else {
        None
    }
}

async fn target_is_reachable(ip: &str, port: u16, timeout_secs: u64) -> bool {
    let addr = format!("{}:{}", ip, port);
    tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false)
}

async fn write_evidence_framed(
    stream: &mut tokio::net::TcpStream,
    ev: &AttestationEvidence,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let payload = serde_json::to_vec(ev)?;
    let len = payload.len() as u32;
    if len > MAX_ATTEST_EVIDENCE_BYTES {
        anyhow::bail!("Attestation payload too large: {} bytes", len);
    }

    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_evidence_framed(stream: &mut tokio::net::TcpStream) -> Result<AttestationEvidence> {
    use tokio::io::AsyncReadExt;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len == 0 || len > MAX_ATTEST_EVIDENCE_BYTES {
        anyhow::bail!("Invalid attestation payload length: {}", len);
    }

    let mut payload = vec![0u8; len as usize];
    stream.read_exact(&mut payload).await?;
    let ev: AttestationEvidence = serde_json::from_slice(&payload)?;
    Ok(ev)
}

fn trusted_peer_is_recent(ts: &str) -> bool {
    match DateTime::parse_from_rfc3339(ts) {
        Ok(dt) => {
            let age = Utc::now().signed_duration_since(dt.with_timezone(&Utc));
            age.num_hours() <= MAX_TRUSTED_PEER_AGE_HOURS
        }
        Err(_) => false,
    }
}

fn should_attempt_persisted_peer(
    peer: &TrustedPeer,
    local_ip: &str,
    local_attest_port: u16,
    allowed_targets: &HashSet<String>,
) -> Option<(String, u16)> {
    let (ip, port) = parse_peer_addr(&peer.peer_id)?;
    if !crate::dynamic_config::is_routable_ip(&ip) {
        return None;
    }
    if ip == local_ip && port == local_attest_port {
        return None;
    }
    if !trusted_peer_is_recent(&peer.timestamp) {
        return None;
    }
    if !allowed_targets.is_empty() && !allowed_targets.contains(&peer.peer_id) {
        return None;
    }
    Some((ip, port))
}

/// Main service responsible for generating, verifying,
/// and coordinating SG-X attestation workflows.
pub struct AttestationService;
/// Contains the nonce, policy digest, and cryptographic signature
/// exchanged during the attestation handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEvidence {
    pub nonce: String,
    pub policy_digest: String,
    pub signature: String,
    pub pubkey_der_b64: String,
    /// PCR snapshot (when available)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pcr_values: Option<crate::secure_element::pcr::PcrSnapshot>,
    /// DKP key version used for signing
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub key_version: Option<u32>,
}

// ════════════════════════════════════════════════════════════════
// Hardware Attestation Protocol — Challenge-Response Structures
// ════════════════════════════════════════════════════════════════

/// Boot chain summary embedded in attestation quotes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootChainSummary {
    pub hab_enabled: bool,
    pub device_closed: bool,
    pub hab_events_found: bool,
    pub boot_chain_intact: bool,
}

/// Cryptographic proof of device integrity state.
/// Contains PCR values, boot chain status, device metadata.
/// Signed by SE050 DKP key (ECDSA-P256).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationQuote {
    /// Protocol version
    pub version: u32,
    /// Verifier's nonce (32 bytes hex) — proves freshness
    pub challenge_nonce: String,
    /// Device-generated nonce (16 bytes hex)
    pub device_nonce: String,
    /// ISO 8601 timestamp
    pub timestamp: String,
    /// Node identifier
    pub node_id: String,
    /// SE050 Certificate UID (hardware identity)
    pub device_uid: String,
    /// DKP key version used for signing
    pub key_version: u32,
    /// Public key (Base64-encoded)
    pub pubkey_b64: String,
    /// Current PCR values (5 registers)
    pub pcr_values: Vec<String>,
    /// PCR composite digest (SHA-256)
    pub composite_digest: String,
    /// PCR integrity status
    pub integrity_status: String,
    /// Boot chain status
    pub boot_chain: BootChainSummary,
    /// Firmware version
    pub firmware_version: String,
    /// Active policy digest
    pub active_policy_digest: String,
}

/// Signed attestation quote with cryptographic binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedQuote {
    /// The attestation quote (JSON-serialized)
    pub quote_json: String,
    /// ECDSA-P256 signature over SHA-256(quote_json) — Base64
    pub signature_b64: String,
    /// Signing backend ("SE050" or "Software")
    pub signing_backend: String,
}

/// Challenge sent by verifier to prover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRequest {
    pub verifier_node_id: String,
    pub nonce: String, // 32 bytes hex
    pub timestamp: String,
}

/// Response from prover containing signed quote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub prover_node_id: String,
    pub signed_quote: SignedQuote,
    /// Optional counter-challenge for mutual attestation
    pub counter_challenge_nonce: Option<String>,
}

/// Result of verifying a signed quote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteVerificationResult {
    pub verified: bool,
    pub nonce_valid: bool,
    pub signature_valid: bool,
    pub pcr_match: bool,
    pub boot_chain_ok: bool,
    pub freshness_ok: bool,
    pub reason: String,
    pub timestamp: String,
}

impl AttestationQuote {
    /// Generate a fresh attestation quote from current platform state.
    pub fn generate(challenge_nonce: &str, node_id: &str, km: &KeyManager) -> Result<Self> {
        use crate::secure_element::pcr::{read_dkp_key_version, PcrEngine, PcrSnapshot};
        use crate::secure_element::secure_boot::BootChainStatus;

        // Load current PCR snapshot
        let pcr_path = format!("/var/lib/sgx-guardian/pcr/{}_current.json", node_id);
        let snapshot = PcrSnapshot::load(&pcr_path).unwrap_or_else(|_| PcrEngine::new().snapshot());

        // Load boot chain status
        let boot = BootChainStatus::check();

        // Generate device nonce
        let mut dev_nonce = [0u8; 16];
        let rng = SystemRandom::new();
        rng.fill(&mut dev_nonce)
            .map_err(|_| anyhow::anyhow!("RNG failed"))?;

        // Read device UID
        let device_uid = crate::secure_element::pcr::read_device_uid(node_id);

        // Get active policy digest
        let policy_mat = load_attestation_policy_material();

        let pubkey_b64 = general_purpose::STANDARD.encode(km.pubkey_der()?);

        Ok(Self {
            version: 1,
            challenge_nonce: challenge_nonce.to_string(),
            device_nonce: hex::encode(dev_nonce),
            timestamp: chrono::Utc::now().to_rfc3339(),
            node_id: node_id.to_string(),
            device_uid,
            key_version: read_dkp_key_version(),
            pubkey_b64,
            pcr_values: snapshot.pcr_values.clone(),
            composite_digest: snapshot.composite_digest.clone(),
            integrity_status: snapshot.integrity_status.clone(),
            boot_chain: BootChainSummary {
                hab_enabled: boot.hab_enabled,
                device_closed: boot.device_closed,
                hab_events_found: boot.hab_events_found,
                boot_chain_intact: boot.boot_chain_intact,
            },
            firmware_version: boot.kernel_version,
            active_policy_digest: policy_mat.digest,
        })
    }

    /// Sign the quote using the KeyManager (SE050 or software).
    pub fn sign(&self, km: &KeyManager) -> Result<SignedQuote> {
        let quote_json =
            serde_json::to_string(self).map_err(|e| anyhow::anyhow!("Quote serialize: {}", e))?;
        let hash = Sha256::digest(quote_json.as_bytes());
        let sig = km.sign(&hash)?;
        Ok(SignedQuote {
            quote_json,
            signature_b64: general_purpose::STANDARD.encode(&sig),
            signing_backend: km.backend_name().to_string(),
        })
    }
}

impl SignedQuote {
    /// Verify a signed quote against a known public key and optional baseline.
    pub fn verify(
        &self,
        peer_pubkey_der: &[u8],
        expected_nonce: &str,
        baseline: Option<&crate::secure_element::pcr::PcrBaseline>,
        max_age_secs: u64,
    ) -> QuoteVerificationResult {
        let now = chrono::Utc::now().to_rfc3339();
        let mut result = QuoteVerificationResult {
            verified: false,
            nonce_valid: false,
            signature_valid: false,
            pcr_match: false,
            boot_chain_ok: false,
            freshness_ok: false,
            reason: String::new(),
            timestamp: now,
        };

        // 1. Verify signature
        let hash = Sha256::digest(self.quote_json.as_bytes());
        let sig_bytes = match general_purpose::STANDARD.decode(&self.signature_b64) {
            Ok(b) => b,
            Err(_) => {
                result.reason = "Invalid signature base64".into();
                return result;
            }
        };

        let peer_pubkey = if peer_pubkey_der.len() == 91 {
            peer_pubkey_der[26..].to_vec()
        } else {
            peer_pubkey_der.to_vec()
        };

        let algo: &dyn signature::VerificationAlgorithm = match sig_bytes.len() {
            64 => &signature::ECDSA_P256_SHA256_FIXED,
            _ if sig_bytes.first() == Some(&0x30) => &signature::ECDSA_P256_SHA256_ASN1,
            _ => {
                result.reason = format!("Unknown sig format (len={})", sig_bytes.len());
                return result;
            }
        };

        let key = signature::UnparsedPublicKey::new(algo, &peer_pubkey);
        if key.verify(&hash, &sig_bytes).is_err() {
            result.reason = "Signature verification failed".into();
            return result;
        }
        result.signature_valid = true;

        // 2. Deserialize quote
        let quote: AttestationQuote = match serde_json::from_str(&self.quote_json) {
            Ok(q) => q,
            Err(e) => {
                result.reason = format!("Quote parse: {}", e);
                return result;
            }
        };

        // 3. Check nonce
        result.nonce_valid = quote.challenge_nonce == expected_nonce;
        if !result.nonce_valid {
            result.reason = "Nonce mismatch (possible replay)".into();
            return result;
        }

        // 4. Check freshness
        if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&quote.timestamp) {
            let age = chrono::Utc::now().signed_duration_since(ts.with_timezone(&chrono::Utc));
            result.freshness_ok = age.num_seconds().unsigned_abs() <= max_age_secs;
        }
        if !result.freshness_ok {
            result.reason = format!("Quote too old (max {}s)", max_age_secs);
            return result;
        }

        // 5. Check boot chain
        result.boot_chain_ok =
            !quote.boot_chain.hab_events_found && quote.integrity_status != "FAIL";

        // 6. Compare PCRs against baseline (if provided)
        if let Some(bl) = baseline {
            if bl.pcr_values.len() == quote.pcr_values.len() {
                result.pcr_match = bl
                    .pcr_values
                    .iter()
                    .zip(quote.pcr_values.iter())
                    .all(|(a, b)| a == b);
            }
            if !result.pcr_match {
                result.reason = "PCR mismatch against baseline".into();
                // Still set verified=false but don't return — let caller decide severity
            }
        } else {
            result.pcr_match = true; // No baseline = skip comparison
        }

        result.verified = result.signature_valid
            && result.nonce_valid
            && result.freshness_ok
            && result.boot_chain_ok
            && result.pcr_match;

        if result.verified {
            result.reason = "All checks passed".into();
        } else if result.reason.is_empty() {
            result.reason = "Boot chain or integrity check failed".into();
        }

        result
    }

    /// Save the signed quote to a JSON file.
    pub fn save(&self, path: &str) -> Result<()> {
        let json =
            serde_json::to_string_pretty(self).map_err(|e| anyhow::anyhow!("Serialize: {}", e))?;
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(path, json).map_err(|e| anyhow::anyhow!("Write: {}", e))
    }

    /// Load a signed quote from a JSON file.
    pub fn load(path: &str) -> Result<Self> {
        let json =
            std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("Read {}: {}", path, e))?;
        serde_json::from_str(&json).map_err(|e| anyhow::anyhow!("Parse: {}", e))
    }
}

/// Save a QuoteVerificationResult to the attestation results log.
pub fn save_verification_result(result: &QuoteVerificationResult, peer_node: &str) {
    #[derive(Serialize, Deserialize)]
    struct ResultEntry {
        peer: String,
        #[serde(flatten)]
        result: QuoteVerificationResult,
    }

    let entry = ResultEntry {
        peer: peer_node.to_string(),
        result: result.clone(),
    };

    let path = "/var/log/sgx-guardian/attestation_results.json";
    let mut entries: Vec<serde_json::Value> = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    if let Ok(val) = serde_json::to_value(&entry) {
        entries.push(val);
        // Keep last 100 results
        if entries.len() > 100 {
            entries.drain(0..entries.len() - 100);
        }
        if let Ok(json) = serde_json::to_string_pretty(&entries) {
            let _ = std::fs::write(path, json);
        }
    }
}

impl AttestationService {
    /// Creates signed attestation evidence by hashing the policy file,
    /// generating a random nonce, and signing the combined message.
    pub fn create_signed_evidence(
        km: &KeyManager,
        policy_yaml: &str,
    ) -> Result<AttestationEvidence> {
        let mut nonce_bytes = [0u8; 16];
        let rng = SystemRandom::new();
        rng.fill(&mut nonce_bytes)
            .map_err(|_| anyhow::anyhow!("Failed to generate attestation nonce"))?;
        let nonce = hex::encode(nonce_bytes);
        let policy_digest = hex::encode(Sha256::digest(policy_yaml.as_bytes()));
        let msg = format!("{}{}", nonce, policy_digest);
        let sig_bytes = km.sign(msg.as_bytes())?;
        let signature_b64 = general_purpose::STANDARD.encode(sig_bytes);
        let pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(km.pubkey_der()?);
        // Load PCR snapshot if available
        let node_id_pcr = std::env::args().nth(1).unwrap_or_else(|| "nodeA".into());
        let pcr_load_path = format!("/var/lib/sgx-guardian/pcr/{}_current.json", node_id_pcr);
        let pcr_values = crate::secure_element::pcr::PcrSnapshot::load(&pcr_load_path).ok();
        let key_version = Some(crate::secure_element::pcr::read_dkp_key_version());
        Ok(AttestationEvidence {
            nonce,
            policy_digest,
            signature: signature_b64,
            pubkey_der_b64: pubkey_b64,
            pcr_values,
            key_version,
        })
    }
    /// Verifies incoming attestation evidence by recomputing the policy digest,
    /// reconstructing the signed message, and validating the signature using
    /// the peer’s public key.
    pub fn verify_signed_evidence(ev: &AttestationEvidence, policy_yaml: &str) -> Result<bool> {
        if !is_hex_digest_64(&ev.policy_digest) {
            eprintln!(
                "⚠️ Attestation rejected: malformed policy digest '{}' (len={})",
                ev.policy_digest,
                ev.policy_digest.len()
            );
            return Ok(false);
        }

        // Step 1: Recompute policy digest
        let expected_digest = hex::encode(Sha256::digest(policy_yaml.as_bytes()));
        // Step 3: Ensure digest matches
        if ev.policy_digest != expected_digest {
            println!(
                "❌ Policy digest mismatch (expected={}, got={})",
                expected_digest, ev.policy_digest
            );
            return Ok(false);
        }
        // Verify PCR snapshot freshness (if present)
        if let Some(ref pcr) = ev.pcr_values {
            if pcr.schema_version != crate::secure_element::pcr::PCR_SCHEMA_VERSION {
                println!(
                    "⚠️ PCR schema version mismatch (got {}, expected {})",
                    pcr.schema_version,
                    crate::secure_element::pcr::PCR_SCHEMA_VERSION
                );
            }
            if !pcr.is_fresh() {
                println!(
                    "⚠️ PCR snapshot is stale (older than {} seconds)",
                    crate::secure_element::pcr::MAX_PCR_SNAPSHOT_AGE_SECS
                );
            }
            if pcr.integrity_status == "FAIL" {
                println!("🔴 Peer PCR integrity FAILED — rejecting attestation");
                return Ok(false);
            }
        }
        // Step 4: Build same message bytes as during signing
        let mut msg = Vec::new();
        msg.extend_from_slice(ev.nonce.as_bytes());
        msg.extend_from_slice(ev.policy_digest.as_bytes());
        // Step 5: Decode Base64 safely
        let sig_bytes = match general_purpose::STANDARD.decode(&ev.signature) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("⚠️ Attestation rejected: invalid signature base64: {}", e);
                return Ok(false);
            }
        };
        // Step 6: Prepare verification key
        let peer_pubkey_raw =
            match base64::engine::general_purpose::STANDARD.decode(&ev.pubkey_der_b64) {
                Ok(bytes) => bytes,
                Err(e) => {
                    eprintln!("⚠️ Attestation rejected: invalid pubkey base64: {}", e);
                    return Ok(false);
                }
            };

        // Handle both raw EC point (65 bytes from software/hardware)
        // and full SubjectPublicKeyInfo DER (91 bytes legacy)
        let peer_pubkey = if peer_pubkey_raw.len() == 91 {
            // Extract raw 65-byte EC point from DER wrapper
            peer_pubkey_raw[26..].to_vec()
        } else {
            peer_pubkey_raw
        };

        // Auto-detect signature format:
        // ring/software → FIXED (exactly 64 bytes, r||s concatenated)
        // SE050/hardware → ASN.1 DER (starts with 0x30, typically 70-72 bytes)
        let verification_algo: &dyn signature::VerificationAlgorithm = match sig_bytes.len() {
            64 => &signature::ECDSA_P256_SHA256_FIXED,
            _ if sig_bytes.first() == Some(&0x30) => &signature::ECDSA_P256_SHA256_ASN1,
            _ => {
                eprintln!(
                    "⚠️ Attestation rejected: unrecognized signature format (len={})",
                    sig_bytes.len()
                );
                return Ok(false);
            }
        };

        let peer_key = signature::UnparsedPublicKey::new(verification_algo, &peer_pubkey);
        // Step 7: Verify signature
        match peer_key.verify(&msg, &sig_bytes) {
            Ok(_) => {
                println!("✅ Attestation verified successfully.");
                Ok(true)
            }
            Err(e) => {
                println!("❌ Signature verification failed: {:?}", e);
                Ok(false)
            }
        }
    }
    /// Generate a signed attestation quote in response to a challenge nonce.
    /// The quote contains current PCR values, boot chain status, and device metadata.
    /// Signed by SE050 DKP (or software key if SE050 unavailable).
    pub fn generate_quote(challenge_nonce: &str, km: &KeyManager) -> Result<SignedQuote> {
        let node_id = std::env::args().nth(1).unwrap_or_else(|| "nodeA".into());
        let quote = AttestationQuote::generate(challenge_nonce, &node_id, km)?;
        quote.sign(km)
    }

    /// Handle an incoming challenge request: generate quote and return response.
    pub fn handle_challenge(req: &ChallengeRequest, km: &KeyManager) -> Result<ChallengeResponse> {
        let node_id = std::env::args().nth(1).unwrap_or_else(|| "nodeA".into());
        let signed_quote = Self::generate_quote(&req.nonce, km)?;

        // Optional: generate counter-challenge for mutual attestation
        let mut counter_nonce_bytes = [0u8; 32];
        let rng = SystemRandom::new();
        let counter_nonce = if rng.fill(&mut counter_nonce_bytes).is_ok() {
            Some(hex::encode(counter_nonce_bytes))
        } else {
            None
        };

        Ok(ChallengeResponse {
            prover_node_id: node_id,
            signed_quote,
            counter_challenge_nonce: counter_nonce,
        })
    }

    /// Verify a signed quote from a peer.
    /// Returns a detailed verification result.
    pub fn verify_quote(
        signed_quote: &SignedQuote,
        expected_nonce: &str,
        peer_pubkey_der: &[u8],
        baseline: Option<&crate::secure_element::pcr::PcrBaseline>,
    ) -> QuoteVerificationResult {
        signed_quote.verify(peer_pubkey_der, expected_nonce, baseline, 300)
    }

    /// Performs the full mutual attestation handshake: connects to peer,
    /// exchanges signed evidence, verifies policy digest & signature,
    /// and updates trusted peer state on success.
    pub async fn mutual_attest(peer_ip: String, peer_port: u16, km: &KeyManager) -> Result<bool> {
        use tokio::net::TcpStream;
        let addr = format!("{}:{}", peer_ip, peer_port);
        println!("Attempting mutual attestation with overlay {}", addr);
        let node_id = std::env::args().nth(1).unwrap_or("unknown-node".into());

        log_audit(
            &node_id,
            AuditCategory::Attestation,
            AuditSeverity::Info,
            AuditAction::Started,
            &format!("Started mutual attestation with {}", addr),
        );
        // Step 1: try connect with retry loop to tolerate startup races
        let mut attempt = 0;
        let mut stream_opt = None;

        while attempt < CONNECT_RETRY_ATTEMPTS {
            match TcpStream::connect(addr.clone()).await {
                Ok(s) => {
                    stream_opt = Some(s);
                    break;
                }
                Err(_) => {
                    attempt += 1;
                    println!(
                        "⏳ Waiting for peer {} (attempt {}/{})...",
                        addr, attempt, CONNECT_RETRY_ATTEMPTS
                    );
                    tokio::time::sleep(Duration::from_millis(CONNECT_RETRY_DELAY_MS)).await;
                }
            }
        }

        let mut stream = match stream_opt {
            Some(s) => s,
            None => {
                let node_id = std::env::args().nth(1).unwrap_or("unknown-node".into());

                log_audit(
                    &node_id,
                    AuditCategory::Attestation,
                    AuditSeverity::Warning,
                    AuditAction::Failed,
                    &format!("Failed to connect to peer {}", addr),
                );

                eprintln!(
        "⚠️ [NetworkError] Failed to connect to peer {} – will retry on next timer cycle",
        addr
    );
                return Ok(false);
            }
        };

        // Step 2: send our attestation evidence
        let policy = load_attestation_policy_material();
        let evidence = Self::create_signed_evidence(km, &policy.yaml)?;
        if let Err(e) = write_evidence_framed(&mut stream, &evidence).await {
            eprintln!(
                "❌ Failed to send attestation evidence to {}: {:?}",
                addr, e
            );
            return Ok(false);
        }
        // Step 3: receive peer evidence
        let peer_ev = match read_evidence_framed(&mut stream).await {
            Ok(ev) => ev,
            Err(e) => {
                println!("⚠️ No valid attestation reply from peer {}: {:?}", addr, e);
                return Ok(false);
            }
        };
        // Step 4: verify peer evidence (using peer's embedded public key)
        let verified = Self::verify_signed_evidence(&peer_ev, &policy.yaml)?;
        if !verified {
            let node_id = std::env::args().nth(1).unwrap_or("unknown-node".into());

            log_audit(
                &node_id,
                AuditCategory::Attestation,
                AuditSeverity::Critical,
                AuditAction::Rejected,
                &format!("Attestation verification failed for peer {}", addr),
            );

            write_last_attestation(&addr, &peer_ev.policy_digest, "failed");
            println!("❌ Peer attestation verification failed for {}", addr);
            return Ok(false);
        }

        // Step 5: on success → add to trusted_peers.json
        let node_id = std::env::args().nth(1).unwrap_or("unknown-node".into());

        log_audit(
            &node_id,
            AuditCategory::Attestation,
            AuditSeverity::Info,
            AuditAction::Succeeded,
            &format!("Peer {} successfully attested and trusted", addr),
        );

        println!("Peer {} successfully attested and trusted", addr);
        write_trusted_peer(&addr, &peer_ip);
        write_last_attestation(&addr, &peer_ev.policy_digest, "success");
        Ok(true)
    }
}
/// Background task that processes discovered peers, re-attests persisted peers,
/// spawns the attestation listener, and runs periodic re-attestation every 60 seconds.
pub async fn run(mut rx: Receiver<String>) -> Result<()> {
    println!("🛰️ Attestation Service background task started (listening for new peers)");
    let node_id_env = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "nodeA".to_string());
    let node_conf = load_node_config_for_attestation(&node_id_env)?;
    let listen_port: u16 = node_conf.port + 100;
    let local_ip = node_conf.ip.clone();
    let overlay_only = parse_bool_env("SGX_ATTEST_OVERLAY_ONLY", true);
    if overlay_only {
        println!("🔒 Attestation target mode: overlay-only");
    } else {
        println!("🔓 Attestation target mode: overlay-preferred (LAN fallback enabled)");
    }
    let policy_info = load_attestation_policy_material();
    println!(
        "🛡️ Attestation policy digest: {} (source: {})",
        policy_info.digest, policy_info.source
    );

    // === Spawn background TCP listener for incoming attestations ===
    println!("🛰️ Spawning attestation listener on port {}", listen_port);
    let bind_ip = "0.0.0.0".to_string();
    tokio::spawn(async move {
        if let Err(e) = start_attestation_listener(bind_ip, listen_port).await {
            eprintln!("⚠️ Attestation listener error: {:?}", e);
        }
    });

    // Delay initial startup re-attestation to reduce race on cold boot.
    tokio::time::sleep(Duration::from_secs(3)).await;

    // === Auto Re-Attest on Startup ===
    let contents = fs::read_to_string("/var/log/sgx-guardian/trusted_peers.json")
        .or_else(|_| fs::read_to_string("logs/trusted_peers.json"));

    if let Ok(contents) = contents {
        let allowed_targets = allowed_attestation_targets(&node_id_env);
        // Parse JSON safely
        let parsed: Result<Vec<TrustedPeer>, serde_json::Error> = serde_json::from_str(&contents);
        if let Ok(peers_list) = parsed {
            for peer in peers_list {
                let Some((ip, port)) =
                    should_attempt_persisted_peer(&peer, &local_ip, listen_port, &allowed_targets)
                else {
                    continue;
                };
                let peer_target = format!("{}:{}", ip, port);
                println!("Verifying persisted peer {} on startup...", peer_target);
                let node_id = std::env::args().nth(1).unwrap_or("nodeA".into());
                let key_path = format!("{}/device_{}.key", ATTESTATION_KEY_DIR, node_id);
                match KeyManager::load_or_generate(&key_path) {
                    Ok(km) => {
                        let base_port = if port >= 100 { port - 100 } else { port };
                        let Some((target_ip, target_port, peer_node)) =
                            resolve_attestation_target(&ip, base_port, overlay_only).await
                        else {
                            continue;
                        };

                        if node_id != "nodeA"
                            && peer_node == "nodeA"
                            && !target_is_reachable(&target_ip, target_port, 2).await
                        {
                            continue;
                        }

                        if let Ok(true) =
                            AttestationService::mutual_attest(target_ip, target_port, &km).await
                        {
                            println!("✅ Persisted peer {} re-verified.", peer_target);
                        }
                    }
                    Err(e) => eprintln!("⚠️ Failed KeyManager load for {}: {:?}", peer_target, e),
                }
            }
        }
    }

    // === Sprint 2 Day 9 – Periodic Re-Attestation Timer (every 60 seconds) ===
    tokio::spawn(async move {
        let node_id = std::env::args().nth(1).unwrap_or("nodeA".into());
        let local_conf = match load_node_config_for_attestation(&node_id) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "⚠️ Re-attestation disabled: failed to load node config: {:?}",
                    e
                );
                return;
            }
        };
        let local_ip = local_conf.ip;
        let local_attest_port = local_conf.port + 100;
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let allowed_targets = allowed_attestation_targets(&node_id);
            let contents = fs::read_to_string("/var/log/sgx-guardian/trusted_peers.json")
                .or_else(|_| fs::read_to_string("logs/trusted_peers.json"));

            if let Ok(contents) = contents {
                let parsed: Result<Vec<TrustedPeer>, serde_json::Error> =
                    serde_json::from_str(&contents);
                if let Ok(peers_list) = parsed {
                    for peer in peers_list {
                        let Some((ip, port)) = should_attempt_persisted_peer(
                            &peer,
                            &local_ip,
                            local_attest_port,
                            &allowed_targets,
                        ) else {
                            continue;
                        };
                        let peer_target = format!("{}:{}", ip, port);
                        println!("🔁 Re-attesting trusted peer: {}", peer_target);
                        let node_id = std::env::args().nth(1).unwrap_or("nodeA".into());
                        let key_path = format!("{}/device_{}.key", ATTESTATION_KEY_DIR, node_id);
                        match KeyManager::load_or_generate(&key_path) {
                            Ok(km) => {
                                let base_port = if port >= 100 { port - 100 } else { port };
                                let Some((target_ip, target_port, peer_node)) =
                                    resolve_attestation_target(&ip, base_port, overlay_only).await
                                else {
                                    continue;
                                };

                                if node_id != "nodeA"
                                    && peer_node == "nodeA"
                                    && !target_is_reachable(&target_ip, target_port, 2).await
                                {
                                    continue;
                                }

                                if let Ok(true) = AttestationService::mutual_attest(
                                    target_ip.clone(),
                                    target_port,
                                    &km,
                                )
                                .await
                                {
                                    println!("✅ Peer {} re-attested successfully.", peer_target);
                                } else {
                                    eprintln!("⚠️ Re-attestation failed for {}", peer_target);
                                }
                            }
                            Err(e) => eprintln!("⚠️ KeyManager load failed: {:?}", e),
                        }
                    }
                }
            }
        }
    });

    let local_node_id = node_id_env.clone();

    if local_node_id != "nodeA" {
        tokio::spawn(async move {
            let mut last_lh: Option<String> = None;
            loop {
                let current_lh = crate::dynamic_config::reachable_lighthouse_name().await;
                if current_lh != last_lh {
                    match (&last_lh, &current_lh) {
                        (Some(prev), Some(curr)) => {
                            println!(
                                "🛑 Lighthouse {} closed; Lighthouse {} is active now",
                                prev, curr
                            );
                        }
                        (Some(prev), None) => {
                            println!(
                                "🛑 Lighthouse {} closed; no reachable lighthouse right now",
                                prev
                            );
                        }
                        (None, Some(curr)) => {
                            println!("🗼 Lighthouse {} is active", curr);
                        }
                        (None, None) => {}
                    }
                    last_lh = current_lh;
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });
    }

    let mut last_attempts: HashMap<String, Instant> = HashMap::new();
    let local_overlay_ip = overlay_ip_from_local_registry(&local_node_id);

    while let Some(peer) = rx.recv().await {
        // Parse preferred queue format "node_id|ip:port" with legacy fallback to "ip:port".
        let (queued_node_id, peer_addr) = if let Some((nid, addr)) = peer.split_once('|') {
            (Some(nid.to_string()), addr.to_string())
        } else {
            (None, peer.clone())
        };

        let (peer_ip, base_port) = if let Some((ip, port)) = peer_addr.split_once(':') {
            (ip.to_string(), port.parse::<u16>().unwrap_or(50051))
        } else {
            (peer_addr.clone(), 50051)
        };

        let discovered_node = queued_node_id
            .clone()
            .or_else(|| infer_node_id_from_peer(&peer_ip, base_port))
            .unwrap_or_else(|| "unknown".to_string());

        if discovered_node == local_node_id {
            continue;
        }

        if local_node_id != "nodeA" {
            let reachable_lh = crate::dynamic_config::reachable_lighthouse_name().await;
            if let Some(lh_name) = reachable_lh {
                if LIGHTHOUSE_WARNING_PRINTED.swap(false, Ordering::SeqCst) {
                    println!(
                        "✅ New lighthouse reachable: {} — resuming attestation",
                        lh_name
                    );
                }
            } else {
                if !LIGHTHOUSE_WARNING_PRINTED.swap(true, Ordering::SeqCst) {
                    println!("⚠️ No lighthouse reachable — pausing attestation until one returns");
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        }

        let Some((target_ip, attest_port, peer_node_id)) =
            resolve_attestation_target(&peer_ip, base_port, overlay_only).await
        else {
            continue;
        };

        // Self-attestation guard (by node identity and by resolved overlay IP).
        if peer_node_id == local_node_id {
            continue;
        }
        if let Some(ref local_ovl) = local_overlay_ip {
            if &target_ip == local_ovl {
                continue;
            }
        }

        let target_key = format!("{}:{}", target_ip, attest_port);
        if let Some(last) = last_attempts.get(&target_key) {
            if last.elapsed().as_secs() < ATTEST_ATTEMPT_THROTTLE_SECS {
                continue;
            }
        }
        last_attempts.insert(target_key.clone(), Instant::now());

        if local_node_id != "nodeA"
            && peer_node_id == "nodeA"
            && !target_is_reachable(&target_ip, attest_port, 2).await
        {
            continue;
        }

        println!("🔐 Attesting discovered peer over overlay: {}", target_key);

        let node_id = std::env::args().nth(1).unwrap_or("nodeA".into());
        let key_path = format!("{}/device_{}.key", ATTESTATION_KEY_DIR, node_id);
        match crate::key_manager::KeyManager::load_or_generate(&key_path) {
            Ok(km) => {
                match AttestationService::mutual_attest(target_ip.clone(), attest_port, &km).await {
                    Ok(true) => println!("✅ Peer {} attested successfully.", target_key),
                    Ok(false) => println!("❌ Peer {} attestation failed.", target_key),
                    Err(e) => eprintln!("⚠️ Attestation error with {}: {:?}", target_key, e),
                }
            }
            Err(e) => eprintln!("⚠️ Failed to load key manager: {:?}", e),
        }
    }

    println!("Attestation Service receiver loop exiting.");
    Ok(())
}
/// Starts a TCP listener to receive attestation evidence from peers,
/// verify it, and respond with locally signed evidence.
pub async fn start_attestation_listener(bind_ip: String, listen_port: u16) -> Result<()> {
    use tokio::net::TcpListener;

    let addr = format!("{}:{}", bind_ip, listen_port);
    let listener = TcpListener::bind(&addr).await?;
    println!("🔒 Attestation listener started on {}", addr);

    loop {
        match listener.accept().await {
            Ok((mut socket, remote)) => {
                // NOTE: Self-attestation guard removed from listener side.
                // The SENDER side already guards against self-attestation
                // (by node_id check and overlay IP check in the discovery loop).
                // The listener should accept ALL valid connections and let
                // cryptographic verification handle trust decisions.
                // The old IP-based guard was causing "Broken pipe" errors
                // when peers shared the same nebula0 interface (same-machine tests)
                // or when overlay IPs hadn't synced yet.
                println!("📩 Received attestation request from {}", remote.ip());
                let node_id = std::env::args().nth(1).unwrap_or("unknown-node".into());

                log_audit(
                    &node_id,
                    AuditCategory::Attestation,
                    AuditSeverity::Info,
                    AuditAction::Started,
                    &format!("Received attestation request from {}", remote),
                );
                let incoming = match read_evidence_framed(&mut socket).await {
                    Ok(ev) => ev,
                    Err(e) => {
                        if e.downcast_ref::<std::io::Error>()
                            .map(|ioe| ioe.kind() == ErrorKind::UnexpectedEof)
                            .unwrap_or(false)
                        {
                            continue;
                        }
                        eprintln!("❌ Failed to read incoming attestation: {:?}", e);
                        continue;
                    }
                };

                // Verify peer evidence
                let node_id = std::env::args().nth(1).unwrap_or("nodeA".into());
                let key_path = format!("{}/device_{}.key", ATTESTATION_KEY_DIR, node_id);
                let km = KeyManager::load_or_generate(&key_path)?;
                let policy = load_attestation_policy_material();
                let verified = AttestationService::verify_signed_evidence(&incoming, &policy.yaml)?;

                if verified {
                    println!("✅ Verified attestation from peer");
                    let node_id = std::env::args().nth(1).unwrap_or("unknown-node".into());

                    log_audit(
                        &node_id,
                        AuditCategory::Attestation,
                        AuditSeverity::Info,
                        AuditAction::Succeeded,
                        &format!("Incoming attestation verified from {}", remote),
                    );

                    // Send our own evidence back
                    let reply = AttestationService::create_signed_evidence(&km, &policy.yaml)?;
                    if let Err(e) = write_evidence_framed(&mut socket, &reply).await {
                        eprintln!(
                            "⚠️ Failed to send attestation reply to {} : {:?}",
                            remote, e
                        );
                    } else {
                        println!("📤 Sent attestation reply to peer");
                    }
                } else {
                    eprintln!("❌ Attestation verification failed for peer");
                    let node_id = std::env::args().nth(1).unwrap_or("unknown-node".into());

                    log_audit(
                        &node_id,
                        AuditCategory::Attestation,
                        AuditSeverity::Critical,
                        AuditAction::Rejected,
                        &format!("Incoming attestation rejected from {}", remote),
                    );
                }
            }
            Err(e) => {
                eprintln!("⚠️ Error accepting attestation connection: {:?}", e);
                // small backoff to avoid busy loop on accept errors
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use p256::SecretKey;

    fn make_test_evidence(policy: &str, nonce: &str) -> AttestationEvidence {
        let secret = SecretKey::from_slice(&[42u8; 32]).expect("valid deterministic secret key");
        let signing_key = SigningKey::from(secret);
        let verify_key = signing_key.verifying_key();
        let raw_pubkey = verify_key.to_encoded_point(false).as_bytes().to_vec();

        // Build SE050-style SPKI DER wrapper (26-byte prefix + 65-byte raw point).
        let mut spki = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06,
            0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        spki.extend_from_slice(&raw_pubkey);

        let policy_digest = hex::encode(Sha256::digest(policy.as_bytes()));
        let msg = format!("{}{}", nonce, policy_digest);

        let signature: Signature = signing_key.sign(msg.as_bytes());
        let sig_der = signature.to_der();

        AttestationEvidence {
            nonce: nonce.to_string(),
            policy_digest,
            signature: general_purpose::STANDARD.encode(sig_der.as_bytes()),
            pubkey_der_b64: general_purpose::STANDARD.encode(spki),
            pcr_values: None,
            key_version: None,
        }
    }

    #[test]
    fn test_attestation_create_and_verify() {
        let policy = "allow: all";
        let ev = make_test_evidence(policy, "00112233445566778899aabbccddeeff");
        assert!(AttestationService::verify_signed_evidence(&ev, policy).unwrap());
    }

    #[test]
    fn test_signed_quote_serialization_roundtrip() {
        let quote = SignedQuote {
            quote_json: r#"{"version":1,"challenge_nonce":"aabb"}"#.to_string(),
            signature_b64: "dGVzdA==".to_string(),
            signing_backend: "Software".to_string(),
        };
        let json = serde_json::to_string(&quote).unwrap();
        let parsed: SignedQuote = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.signing_backend, "Software");
        assert_eq!(parsed.quote_json, quote.quote_json);
    }

    #[test]
    fn test_boot_chain_summary_serialization() {
        let summary = BootChainSummary {
            hab_enabled: true,
            device_closed: true,
            hab_events_found: false,
            boot_chain_intact: true,
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"hab_enabled\":true"));
        assert!(json.contains("\"boot_chain_intact\":true"));
    }

    #[test]
    fn test_challenge_request_serialization() {
        let req = ChallengeRequest {
            verifier_node_id: "nodeA".to_string(),
            nonce: "ff".repeat(32),
            timestamp: "2026-04-17T12:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: ChallengeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.verifier_node_id, "nodeA");
        assert_eq!(parsed.nonce.len(), 64);
    }

    #[test]
    fn test_verification_result_defaults() {
        let result = QuoteVerificationResult {
            verified: false,
            nonce_valid: false,
            signature_valid: false,
            pcr_match: false,
            boot_chain_ok: false,
            freshness_ok: false,
            reason: "test".into(),
            timestamp: "2026-04-17T12:00:00Z".into(),
        };
        assert!(!result.verified);
        assert_eq!(result.reason, "test");
    }
}
