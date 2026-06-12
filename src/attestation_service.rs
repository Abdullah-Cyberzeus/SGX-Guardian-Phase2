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
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;
use tokio::sync::mpsc::{self, Receiver};
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
static LAST_ATTEST_REQUEST_LOGGED: OnceLock<Mutex<Option<String>>> = OnceLock::new();
pub static VID_CACHE: once_cell::sync::OnceCell<crate::virtual_id_cache::VirtualIdCache> =
    once_cell::sync::OnceCell::new();
pub static REATTEST_TX: once_cell::sync::OnceCell<mpsc::UnboundedSender<String>> =
    once_cell::sync::OnceCell::new();
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

pub fn set_vid_cache(c: crate::virtual_id_cache::VirtualIdCache) {
    let _ = VID_CACHE.set(c);
}

pub fn set_reattest_sender(tx: mpsc::UnboundedSender<String>) {
    let _ = REATTEST_TX.set(tx);
}

pub fn trigger_reattestation_for(peer_did: &str) {
    if let Some(tx) = REATTEST_TX.get() {
        let _ = tx.send(peer_did.to_string());
    }
}

pub fn attestation_listener_port_for_base(base_port: u16) -> u16 {
    base_port.saturating_add(100)
}

pub fn attestation_listener_port_for_node(node_id: &str) -> u16 {
    match node_id {
        "nodeA" => attestation_listener_port_for_base(50051),
        "nodeB" => attestation_listener_port_for_base(50052),
        "nodeC" => attestation_listener_port_for_base(50053),
        _ => attestation_listener_port_for_base(50051),
    }
}

// Trusted Peer JSON Logging Helpers ===
use chrono::Utc;
use std::fs;
/// Represents a peer that successfully passed attestation
/// and is stored in the per-node trusted peers file.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrustedPeer {
    peer_id: String,
    ip: String,
    status: String,
    /// Legacy field. Equal to `last_attested_at` after Fix 3. Retained for
    /// pre-Fix-3 readers (ops dashboard, merge logic).
    timestamp: String,
    // Fix 3: identity + state metadata captured at the moment of last
    // successful attestation. All optional with serde defaults so files
    // written before this fix continue to parse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    virtual_id: Option<String>,
    /// RFC3339 of last successful attestation (mirrors `timestamp` for
    /// new writes; lets future tooling phase `timestamp` out cleanly).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_attested_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dkp_pubkey_sha256_b16: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pcr_composite_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rotation_reason: Option<String>,
}
/// Stores the most recent attestation result for a peer with full identity +
/// state evidence so post-mortems can reconstruct WHAT was verified.
#[derive(Serialize, Deserialize)]
struct LastAttestation {
    peer_id: String,
    policy_digest: String,
    result: String,
    timestamp: String,
    // Fix 2: peer identity at the moment of attestation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    peer_did: Option<String>,
    // Session-scoped VID actually verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    virtual_id: Option<String>,
    // SHA-256 fingerprint of peer's DKP pubkey (12-byte hex prefix for
    // human readability; the cache still stores the full digest).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dkp_pubkey_sha256_b16: Option<String>,
    // PCR composite digest at time of attestation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pcr_composite_digest: Option<String>,
    // Initiator nonce used (already covered by the signed evidence; kept
    // here for ops correlation with peer logs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct StableDkpState {
    verification_method_id: String,
    kid: String,
    pubkey_sha256_b16: String,
}

fn log_dir_primary() -> PathBuf {
    PathBuf::from("/var/log/sgx-guardian")
}

fn log_dir_fallback() -> PathBuf {
    std::env::var("SGX_GUARDIAN_HOME")
        .map(PathBuf::from)
        .map(|base| base.join("logs"))
        .unwrap_or_else(|_| PathBuf::from("logs"))
}

fn current_log_dirs() -> (PathBuf, PathBuf) {
    (log_dir_primary(), log_dir_fallback())
}

fn current_node_name(default: &str) -> String {
    std::env::var("SGX_GUARDIAN_NODE_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            std::env::args()
                .nth(1)
                .unwrap_or_else(|| default.to_string())
        })
}

fn trusted_peer_node_paths(
    node: &str,
    primary_dir: &Path,
    fallback_dir: &Path,
) -> (PathBuf, PathBuf) {
    (
        primary_dir.join(format!("trusted_peers_{}.json", node)),
        fallback_dir.join(format!("trusted_peers_{}.json", node)),
    )
}

fn trusted_peer_global_paths(primary_dir: &Path, fallback_dir: &Path) -> (PathBuf, PathBuf) {
    (
        primary_dir.join("trusted_peers.json"),
        fallback_dir.join("trusted_peers.json"),
    )
}

fn last_attestation_paths(primary_dir: &Path, fallback_dir: &Path) -> (PathBuf, PathBuf) {
    (
        primary_dir.join("last_attestation.json"),
        fallback_dir.join("last_attestation.json"),
    )
}

fn write_string(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(path, contents);
}

fn read_to_string_first(paths: [&Path; 2]) -> std::io::Result<String> {
    fs::read_to_string(paths[0]).or_else(|_| fs::read_to_string(paths[1]))
}

fn decode_dkp_pubkey_fingerprint(pubkey_der_b64: &str) -> Option<String> {
    general_purpose::STANDARD
        .decode(pubkey_der_b64)
        .ok()
        .map(|bytes| hex::encode(Sha256::digest(&bytes)))
}

fn find_peer_did_document(peer_did: &str) -> Option<crate::did::document::DidDocument> {
    let did = crate::did::Did::parse(peer_did).ok()?;
    if let Ok(Some(doc)) = crate::did::doc_persistence::load_peer(&did) {
        return Some(doc);
    }
    if let Ok(docs) = crate::did::doc_persistence::load_ca_aggregate() {
        if let Some(doc) = docs.into_iter().find(|doc| doc.id == peer_did) {
            return Some(doc);
        }
    }
    if let Ok(Some(doc)) = crate::did::doc_persistence::load_self() {
        if doc.id == peer_did {
            return Some(doc);
        }
    }
    None
}

fn verification_method_pubkey_sha256(
    vm: &crate::did::document::VerificationMethod,
) -> Option<String> {
    let x = general_purpose::URL_SAFE_NO_PAD
        .decode(&vm.public_key_jwk.x)
        .ok()?;
    let y = general_purpose::URL_SAFE_NO_PAD
        .decode(&vm.public_key_jwk.y)
        .ok()?;
    if x.len() != 32 || y.len() != 32 {
        return None;
    }

    let mut der = hex::decode("3059301306072a8648ce3d020106082a8648ce3d030107034200").ok()?;
    der.push(0x04);
    der.extend_from_slice(&x);
    der.extend_from_slice(&y);
    Some(hex::encode(Sha256::digest(&der)))
}

fn stable_dkp_state_for_attestation(ev: &AttestationEvidence) -> StableDkpState {
    if let Some(doc) = find_peer_did_document(&ev.subject_did) {
        if let Some(active_vm) = doc.verification_method.first() {
            let mut state = StableDkpState {
                verification_method_id: active_vm.id.clone(),
                kid: active_vm.public_key_jwk.kid.clone(),
                pubkey_sha256_b16: verification_method_pubkey_sha256(active_vm).unwrap_or_default(),
            };
            if state.pubkey_sha256_b16.is_empty() {
                state.pubkey_sha256_b16 =
                    decode_dkp_pubkey_fingerprint(&ev.pubkey_der_b64).unwrap_or_default();
            }
            return state;
        }
    }

    let key_version = ev.key_version.unwrap_or_default();
    StableDkpState {
        verification_method_id: if !ev.subject_did.is_empty() && key_version > 0 {
            format!("{}#dkp-v{}", ev.subject_did, key_version)
        } else {
            String::new()
        },
        kid: if key_version > 0 {
            format!("dkp-v{}", key_version)
        } else {
            String::new()
        },
        pubkey_sha256_b16: decode_dkp_pubkey_fingerprint(&ev.pubkey_der_b64).unwrap_or_default(),
    }
}

fn current_rotation_reason_for_peer(peer_did: &str) -> Option<String> {
    VID_CACHE
        .get()
        .and_then(|cache| cache.current_for_sync(peer_did))
        .and_then(|cached| cached.last_rotation_reason)
        .map(|reason| reason.as_str().to_string())
}
/// Writes or updates trusted peer info into the per-node JSON file
/// and then merges all peer files into a global combined view.
fn write_trusted_peer(
    peer_id: &str,
    ip: &str,
    ev: &AttestationEvidence,
    rotation_reason: Option<String>,
) {
    let node = current_node_name("nodeX");
    let (primary_dir, fallback_dir) = current_log_dirs();
    write_trusted_peer_with_dirs(
        &node,
        &primary_dir,
        &fallback_dir,
        peer_id,
        ip,
        ev,
        rotation_reason,
    );
}

fn write_trusted_peer_with_dirs(
    node: &str,
    primary_dir: &Path,
    fallback_dir: &Path,
    peer_id: &str,
    ip: &str,
    ev: &AttestationEvidence,
    rotation_reason: Option<String>,
) {
    let (primary_file, fallback_file) = trusted_peer_node_paths(node, primary_dir, fallback_dir);
    let now = Utc::now().to_rfc3339();
    let dkp_state = stable_dkp_state_for_attestation(ev);
    let pcr_digest = ev
        .baseline_status
        .as_ref()
        .map(|b| b.composite_digest.clone())
        .filter(|digest| !digest.is_empty());

    let entry = TrustedPeer {
        peer_id: peer_id.to_string(),
        ip: ip.to_string(),
        status: "verified".to_string(),
        timestamp: now.clone(),
        did: Some(ev.subject_did.clone()).filter(|s| !s.is_empty()),
        virtual_id: Some(ev.virtual_id.clone()).filter(|s| !s.is_empty()),
        last_attested_at: Some(now.clone()),
        dkp_pubkey_sha256_b16: Some(dkp_state.pubkey_sha256_b16).filter(|s| !s.is_empty()),
        pcr_composite_digest: pcr_digest,
        policy_digest: Some(ev.policy_digest.clone()).filter(|s| !s.is_empty()),
        rotation_reason,
    };

    // Load existing per-node file (NOT global file)
    let mut data = Vec::<TrustedPeer>::new();
    let existing = read_to_string_first([primary_file.as_path(), fallback_file.as_path()]);

    if let Ok(existing) = existing {
        if let Ok(parsed) = serde_json::from_str::<Vec<TrustedPeer>>(&existing) {
            data = parsed;
        }
    }

    // Update or insert by peer_id. Update path now also refreshes ALL
    // identity/state fields, not just timestamp+status — so a peer's
    // record stays current as their VID/DKP/PCR/policy evolve.
    let mut updated = false;
    for p in data.iter_mut() {
        if p.peer_id == peer_id {
            p.timestamp = entry.timestamp.clone();
            p.status = "verified".into();
            if entry.did.is_some() {
                p.did = entry.did.clone();
            }
            if entry.virtual_id.is_some() {
                p.virtual_id = entry.virtual_id.clone();
            }
            if entry.last_attested_at.is_some() {
                p.last_attested_at = entry.last_attested_at.clone();
            }
            if entry.dkp_pubkey_sha256_b16.is_some() {
                p.dkp_pubkey_sha256_b16 = entry.dkp_pubkey_sha256_b16.clone();
            }
            if entry.pcr_composite_digest.is_some() {
                p.pcr_composite_digest = entry.pcr_composite_digest.clone();
            }
            if entry.policy_digest.is_some() {
                p.policy_digest = entry.policy_digest.clone();
            }
            if entry.rotation_reason.is_some() {
                p.rotation_reason = entry.rotation_reason.clone();
            }
            updated = true;
            break;
        }
    }
    if !updated {
        data.push(entry);
    }

    // Save back to per-node file
    if let Ok(json) = serde_json::to_string_pretty(&data) {
        write_string(&primary_file, &json);
        write_string(&fallback_file, &json);
    } else {
        eprintln!(
            "⚠️ Failed to serialize trusted peer list for trusted_peers_{}.json",
            node
        );
    }
    merge_parent_peer_file_with_dirs(primary_dir, fallback_dir);
}

fn remove_trusted_peer(peer_id: &str) {
    let node = current_node_name("nodeX");
    let (primary_dir, fallback_dir) = current_log_dirs();
    let (primary_file, fallback_file) = trusted_peer_node_paths(&node, &primary_dir, &fallback_dir);

    let mut data = Vec::<TrustedPeer>::new();
    let existing = read_to_string_first([primary_file.as_path(), fallback_file.as_path()]);
    if let Ok(existing) = existing {
        if let Ok(parsed) = serde_json::from_str::<Vec<TrustedPeer>>(&existing) {
            data = parsed;
        }
    }

    let before = data.len();
    data.retain(|p| p.peer_id != peer_id);
    let removed = before.saturating_sub(data.len());

    if removed > 0 {
        if let Ok(json) = serde_json::to_string_pretty(&data) {
            write_string(&primary_file, &json);
            write_string(&fallback_file, &json);
            println!(
                "🗑️  Removed {} from trusted_peers (attestation failed)",
                peer_id
            );
        }
    }
    merge_parent_peer_file_with_dirs(&primary_dir, &fallback_dir);
}
/// Writes the most recent attestation outcome for a peer.
/// `ev` is the *peer's* evidence (so DID/VID/DKP/PCR reflect THEM, not us).
/// Pass `None` only when we couldn't decode the evidence (e.g. connect
/// failed); in that case only the (peer_id, result, timestamp) shape survives.
fn write_last_attestation(
    peer_id: &str,
    policy_digest: &str,
    result: &str,
    ev: Option<&AttestationEvidence>,
) {
    let (peer_did, virtual_id, dkp_fp, pcr_digest, nonce) = match ev {
        None => (None, None, None, None, None),
        Some(ev) => {
            let dkp_fp = general_purpose::STANDARD
                .decode(&ev.pubkey_der_b64)
                .ok()
                .map(|b| hex::encode(Sha256::digest(&b)));
            let pcr_digest = ev
                .baseline_status
                .as_ref()
                .map(|b| b.composite_digest.clone());
            (
                Some(ev.subject_did.clone()).filter(|s| !s.is_empty()),
                Some(ev.virtual_id.clone()).filter(|s| !s.is_empty()),
                dkp_fp,
                pcr_digest,
                Some(ev.nonce.clone()).filter(|s| !s.is_empty()),
            )
        }
    };

    let record = LastAttestation {
        peer_id: peer_id.to_string(),
        policy_digest: policy_digest.to_string(),
        result: result.to_string(),
        timestamp: Utc::now().to_rfc3339(),
        peer_did,
        virtual_id,
        dkp_pubkey_sha256_b16: dkp_fp,
        pcr_composite_digest: pcr_digest,
        nonce,
    };

    if let Ok(json) = serde_json::to_string_pretty(&record) {
        let (primary_dir, fallback_dir) = current_log_dirs();
        let (primary_file, fallback_file) = last_attestation_paths(&primary_dir, &fallback_dir);
        write_string(&primary_file, &json);
        write_string(&fallback_file, &json);
    } else {
        eprintln!("⚠️ Failed to write last_attestation.json");
    }
}
fn merge_parent_peer_file_with_dirs(primary_dir: &Path, fallback_dir: &Path) {
    let mut merged: HashMap<String, TrustedPeer> = HashMap::new();

    for dir in [primary_dir, fallback_dir] {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !(name.starts_with("trusted_peers_node") && name.ends_with(".json")) {
                continue;
            }
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            let Ok(peers) = serde_json::from_str::<Vec<TrustedPeer>>(&text) else {
                continue;
            };
            for peer in peers {
                if peer.peer_id.is_empty() {
                    continue;
                }
                match merged.get_mut(&peer.peer_id) {
                    Some(existing) => merge_trusted_peer(existing, peer),
                    None => {
                        merged.insert(peer.peer_id.clone(), peer);
                    }
                }
            }
        }
    }

    let mut peers: Vec<TrustedPeer> = merged.into_values().collect();
    peers.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));

    if let Ok(json) = serde_json::to_string_pretty(&peers) {
        let (primary_file, fallback_file) = trusted_peer_global_paths(primary_dir, fallback_dir);
        write_string(&primary_file, &json);
        write_string(&fallback_file, &json);
    } else {
        eprintln!("⚠️ Failed to merge trusted peer JSON");
    }
}

fn trusted_peer_seen_at(peer: &TrustedPeer) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    peer.last_attested_at
        .as_deref()
        .unwrap_or(&peer.timestamp)
        .parse()
        .ok()
}

fn merge_trusted_peer(existing: &mut TrustedPeer, candidate: TrustedPeer) {
    let candidate_is_newer = match (
        trusted_peer_seen_at(existing),
        trusted_peer_seen_at(&candidate),
    ) {
        (Some(existing_ts), Some(candidate_ts)) => candidate_ts >= existing_ts,
        (None, Some(_)) => true,
        _ => false,
    };

    if candidate_is_newer {
        existing.ip = candidate.ip.clone();
        existing.status = candidate.status.clone();
        existing.timestamp = candidate.timestamp.clone();
        if candidate.last_attested_at.is_some() {
            existing.last_attested_at = candidate.last_attested_at.clone();
        }
    }
    if candidate.did.is_some() {
        existing.did = candidate.did.clone();
    }
    if candidate.virtual_id.is_some() {
        existing.virtual_id = candidate.virtual_id.clone();
    }
    if candidate.dkp_pubkey_sha256_b16.is_some() {
        existing.dkp_pubkey_sha256_b16 = candidate.dkp_pubkey_sha256_b16.clone();
    }
    if candidate.pcr_composite_digest.is_some() {
        existing.pcr_composite_digest = candidate.pcr_composite_digest.clone();
    }
    if candidate.policy_digest.is_some() {
        existing.policy_digest = candidate.policy_digest.clone();
    }
    if candidate.rotation_reason.is_some() {
        existing.rotation_reason = candidate.rotation_reason.clone();
    }
}

fn load_trusted_peers_from_global() -> Vec<TrustedPeer> {
    let (primary_dir, fallback_dir) = current_log_dirs();
    let (primary_file, fallback_file) = trusted_peer_global_paths(&primary_dir, &fallback_dir);
    read_to_string_first([primary_file.as_path(), fallback_file.as_path()])
        .ok()
        .and_then(|text| serde_json::from_str::<Vec<TrustedPeer>>(&text).ok())
        .unwrap_or_default()
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
                targets.insert(format!(
                    "{}:{}",
                    conf.ip,
                    attestation_listener_port_for_base(conf.port)
                ));
            }
            if let Some(overlay_ip) = overlay_ip_from_local_registry(node) {
                targets.insert(format!(
                    "{}:{}",
                    overlay_ip,
                    attestation_listener_port_for_base(conf.port)
                ));
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
    let attest_port = attestation_listener_port_for_base(base_port);

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

fn build_evidence_signing_message(
    nonce: &str,
    policy_digest: &str,
    baseline_status: Option<&BaselineStatus>,
    virtual_id_hex: &str,
) -> Vec<u8> {
    let mut msg = Vec::new();
    write_lp(&mut msg, nonce.as_bytes());
    write_lp(&mut msg, policy_digest.as_bytes());
    if let Some(bs) = baseline_status {
        if let Ok(json) = serde_json::to_string(bs) {
            write_lp(&mut msg, json.as_bytes());
        } else {
            write_lp(&mut msg, b"");
        }
    } else {
        write_lp(&mut msg, b"");
    }
    write_lp(&mut msg, virtual_id_hex.as_bytes());
    msg
}

fn write_lp(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(&(b.len() as u32).to_be_bytes());
    buf.extend_from_slice(b);
}

fn normalize_p256_pubkey(mut key: Vec<u8>) -> Option<Vec<u8>> {
    if key.len() == 91 {
        key = key[26..].to_vec();
    }
    if key.len() == 65 {
        Some(key)
    } else {
        None
    }
}

fn local_dkp_pubkey_candidates(km: &KeyManager) -> Vec<Vec<u8>> {
    let mut out = Vec::new();

    if let Ok(k) = km.pubkey_der() {
        if let Some(raw) = normalize_p256_pubkey(k) {
            out.push(raw);
        }
    }

    if let Ok(der) = std::fs::read("/var/lib/sgx-guardian/keys/dkp_pub.der") {
        if let Some(raw) = normalize_p256_pubkey(der) {
            out.push(raw);
        }
    }

    out.sort();
    out.dedup();
    out
}

fn resolve_ca_host_for_vc() -> String {
    if let Ok(host) = std::env::var("SGX_CA_HOST") {
        if !host.trim().is_empty() && host != "0.0.0.0" {
            return host;
        }
    }
    if let Some(host) = crate::dynamic_config::latest_known_ca_ip() {
        if crate::dynamic_config::is_routable_ip(&host) {
            return host;
        }
    }
    load_node_config_for_attestation("nodeA")
        .ok()
        .map(|cfg| cfg.ip)
        .filter(|ip| crate::dynamic_config::is_routable_ip(ip))
        .unwrap_or_default()
}

fn vc_required() -> bool {
    std::env::var("SGX_REQUIRE_VC").as_deref() != Ok("0")
}

fn jwk_raw_pubkey(doc: &crate::did::document::DidDocument) -> Option<Vec<u8>> {
    let vm = doc.verification_method.first()?;
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&vm.public_key_jwk.x)
        .ok()?;
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&vm.public_key_jwk.y)
        .ok()?;
    if x.len() != 32 || y.len() != 32 {
        return None;
    }
    let mut raw = Vec::with_capacity(65);
    raw.push(0x04);
    raw.extend_from_slice(&x);
    raw.extend_from_slice(&y);
    Some(raw)
}

fn subject_did_from_attestation_pubkey(pubkey_der_b64: &str) -> Option<String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(pubkey_der_b64)
        .ok()
        .and_then(normalize_p256_pubkey)?;

    if let Ok(Some(doc)) = crate::did::doc_persistence::load_self() {
        if jwk_raw_pubkey(&doc).as_deref() == Some(raw.as_slice()) {
            return Some(doc.id);
        }
    }

    if let Ok(docs) = crate::did::doc_persistence::list_peer_docs() {
        for doc in docs {
            if jwk_raw_pubkey(&doc).as_deref() == Some(raw.as_slice()) {
                return Some(doc.id);
            }
        }
    }

    if let Ok(docs) = crate::did::doc_persistence::load_ca_aggregate() {
        for doc in docs {
            if jwk_raw_pubkey(&doc).as_deref() == Some(raw.as_slice()) {
                return Some(doc.id);
            }
        }
    }

    None
}

fn observe_verified_virtual_id(ev: &AttestationEvidence) {
    let Some(cache) = VID_CACHE.get() else {
        return;
    };

    // Build the ObservationContext from the evidence we just verified.
    // Every input is already in scope — no extra computation cost.
    let dkp_state = stable_dkp_state_for_attestation(ev);
    let pcr_digest = ev
        .baseline_status
        .as_ref()
        .map(|b| b.composite_digest.clone())
        .unwrap_or_default();
    let policy_digest = ev.policy_digest.clone();

    // Recompute the classifier's stable security-state component the same
    // way the cache will: DID + active DKP VM/kid/fingerprint + PCR + policy.
    let stable_hex = crate::virtual_id_cache::compute_stable_security_state_hex(
        &ev.subject_did,
        &dkp_state.verification_method_id,
        &dkp_state.kid,
        &dkp_state.pubkey_sha256_b16,
        &pcr_digest,
        &policy_digest,
    );

    let ctx = crate::virtual_id_cache::ObservationContext {
        peer_did: &ev.subject_did,
        new_vid_hex: &ev.virtual_id,
        new_stable_hex: &stable_hex,
        new_dkp_verification_method_id: &dkp_state.verification_method_id,
        new_dkp_kid: &dkp_state.kid,
        new_dkp_fp: &dkp_state.pubkey_sha256_b16,
        new_pcr_digest: &pcr_digest,
        new_policy_digest: &policy_digest,
    };

    let node_id = std::env::args().nth(1).unwrap_or_else(|| "unknown".into());
    match cache.observe_rich(&ctx) {
        crate::virtual_id_cache::VidObservation::FirstSeen => {
            log_audit(
                &node_id,
                AuditCategory::Attestation,
                AuditSeverity::Info,
                AuditAction::Started,
                &format!("First VID seen for {}: {}", ev.subject_did, ev.virtual_id),
            );
        }
        crate::virtual_id_cache::VidObservation::Unchanged => {}
        crate::virtual_id_cache::VidObservation::Rotated {
            previous,
            reason,
            cooldown_allows_reattest,
        } => {
            if !reason.is_security_event() {
                log_audit(
                    &node_id,
                    AuditCategory::Attestation,
                    AuditSeverity::Info,
                    AuditAction::Started,
                    &format!(
                        "VID session refresh for {} (reason={}): {} -> {}",
                        ev.subject_did,
                        reason.as_str(),
                        previous,
                        ev.virtual_id
                    ),
                );
                return;
            }

            let severity = AuditSeverity::Warning;
            log_audit(
                &node_id,
                AuditCategory::Attestation,
                severity,
                AuditAction::Started,
                &format!(
                    "VID rotation for {} (reason={}): {} -> {}",
                    ev.subject_did,
                    reason.as_str(),
                    previous,
                    ev.virtual_id
                ),
            );

            if cooldown_allows_reattest {
                trigger_reattestation_for(&ev.subject_did);
            } else {
                log_audit(
                    &node_id,
                    AuditCategory::Attestation,
                    AuditSeverity::Info,
                    AuditAction::Started,
                    &format!(
                        "Re-attest suppressed by cooldown for {} (reason={})",
                        ev.subject_did,
                        reason.as_str()
                    ),
                );
            }
        }
    }
}

async fn verify_peer_vc_for_attestation(
    peer_ev: &AttestationEvidence,
    peer_label: &str,
) -> Result<Option<String>> {
    let expected_subject_did = subject_did_from_attestation_pubkey(&peer_ev.pubkey_der_b64);
    let Some(vc_json) = peer_ev.presented_vc_json.as_deref() else {
        if vc_required() {
            anyhow::bail!("Peer {} presented no VC", peer_label);
        }
        return Ok(expected_subject_did);
    };

    let expected_subject_did = expected_subject_did
        .or_else(|| (!peer_ev.subject_did.is_empty()).then(|| peer_ev.subject_did.clone()))
        .ok_or_else(|| anyhow::anyhow!("subject DID unavailable for {}", peer_label))?;

    let vc: crate::vc::credential::VerifiableCredential =
        serde_json::from_str(vc_json).map_err(|e| anyhow::anyhow!("VC parse: {}", e))?;
    let ca_did =
        crate::vc::issue::known_ca_did().map_err(|e| anyhow::anyhow!("known CA DID: {}", e))?;
    let resolver = crate::did::Resolver::new(crate::did::ResolverConfig {
        ca_host: resolve_ca_host_for_vc(),
        ..Default::default()
    });
    let status_list_credential = crate::vc::persistence::load_status_list_credential()
        .map_err(|e| anyhow::anyhow!("status list load: {}", e))?;
    let status_list = crate::vc::status_list::verify_status_list_credential(
        &status_list_credential,
        &resolver,
        Some(&ca_did),
    )
    .await
    .map_err(|e| anyhow::anyhow!("status list verify: {}", e))?;

    crate::vc::verify::verify_vc(
        &vc,
        &resolver,
        crate::vc::verify::VerifyOptions {
            expected_subject_did: Some(&expected_subject_did),
            expected_circle_id: Some(crate::vc::issue::DEFAULT_CIRCLE_ID),
            expected_issuer_did: Some(&ca_did),
            check_status_list: true,
            status_list: Some(&status_list),
        },
    )
    .await
    .map_err(|e| anyhow::anyhow!("VC verify: {}", e))?;

    let _ = crate::vc::persistence::save_peer(&expected_subject_did, &vc);
    Ok(Some(expected_subject_did))
}

/// Main service responsible for generating, verifying,
/// and coordinating SG-X attestation workflows.
pub struct AttestationService;
/// Contains the nonce, policy digest, and cryptographic signature
/// exchanged during the attestation handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEvidence {
    pub node_id: String,
    #[serde(default)]
    pub subject_did: String,
    pub nonce: String,
    pub policy_digest: String,
    /// VirtualID computed at evidence-creation time. Hex-encoded 32 bytes.
    /// Verifier recomputes and compares; signature covers this field.
    #[serde(default)]
    pub virtual_id: String,
    pub signature: String,
    pub pubkey_der_b64: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub presented_vc_json: Option<String>,
    /// PCR snapshot (when available)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pcr_values: Option<crate::secure_element::pcr::PcrSnapshot>,
    /// DKP key version used for signing
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub key_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub baseline_status: Option<BaselineStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineStatus {
    /// "ALL_MATCH" | "MISMATCH" | "ABSENT" | "BAD_SIGNATURE"
    pub state: String,
    /// Indices of PCRs that mismatched (empty when state == "ALL_MATCH")
    pub mismatched_pcrs: Vec<usize>,
    /// Hex of the local composite digest at evidence-creation time
    pub composite_digest: String,
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

fn compute_local_baseline_status(node_id: &str, km: &KeyManager) -> BaselineStatus {
    use crate::secure_element::pcr::{PcrBaseline, PcrSnapshot};

    let snap_path = format!("/var/lib/sgx-guardian/pcr/{}_current.json", node_id);
    let bl_path = format!("/etc/sgx-guardian/pcr_{}_baseline.json", node_id);

    let snap = match PcrSnapshot::load(&snap_path) {
        Ok(s) => s,
        Err(_) => {
            return BaselineStatus {
                state: "ABSENT".into(),
                mismatched_pcrs: vec![],
                composite_digest: String::new(),
            };
        }
    };

    let baseline = match PcrBaseline::load(&bl_path) {
        Ok(b) => b,
        Err(_) => {
            return BaselineStatus {
                state: "ABSENT".into(),
                mismatched_pcrs: vec![],
                composite_digest: snap.composite_digest.clone(),
            };
        }
    };

    let pubkeys = local_dkp_pubkey_candidates(km);
    let sig_ok = pubkeys.iter().any(|pk| baseline.verify_signature(pk));
    if !sig_ok {
        return BaselineStatus {
            state: "BAD_SIGNATURE".into(),
            mismatched_pcrs: vec![],
            composite_digest: snap.composite_digest.clone(),
        };
    }

    let mismatched = snap.compare_baseline(&baseline).unwrap_or_default();
    let state = if mismatched.is_empty() {
        "ALL_MATCH"
    } else {
        "MISMATCH"
    };
    BaselineStatus {
        state: state.into(),
        mismatched_pcrs: mismatched,
        composite_digest: snap.composite_digest.clone(),
    }
}

impl AttestationService {
    /// Creates signed attestation evidence by hashing the policy file,
    /// generating a random nonce, and signing the combined message.
    pub fn create_signed_evidence(
        km: &KeyManager,
        policy_yaml: &str,
    ) -> Result<AttestationEvidence> {
        let node_id = std::env::args().nth(1).unwrap_or_else(|| "nodeA".into());
        let mut nonce_bytes = [0u8; 16];
        let rng = SystemRandom::new();
        rng.fill(&mut nonce_bytes)
            .map_err(|_| anyhow::anyhow!("Failed to generate attestation nonce"))?;
        let nonce = hex::encode(nonce_bytes);
        let policy_digest = hex::encode(Sha256::digest(policy_yaml.as_bytes()));
        let baseline_status = Some(compute_local_baseline_status(&node_id, km));
        let dkp_pub = km.pubkey_der()?;
        let pcr_digest_bytes = baseline_status
            .as_ref()
            .and_then(|b| hex::decode(&b.composite_digest).ok())
            .unwrap_or_default();
        let policy_digest_bytes = hex::decode(&policy_digest).unwrap_or_default();
        let nonce_i_bytes = hex::decode(&nonce).unwrap_or_default();
        let nonce_r_bytes: Vec<u8> = Vec::new();
        let subject_did = crate::did::DidRecord::load(crate::did::DEFAULT_DID_PATH)
            .map(|record| record.did)
            .unwrap_or_default();
        let vid = crate::virtual_id::VirtualIdInputs {
            did: &subject_did,
            dkp_pubkey_der: &dkp_pub,
            pcr_composite_digest: &pcr_digest_bytes,
            policy_digest: &policy_digest_bytes,
            nonce_i: &nonce_i_bytes,
            nonce_r: &nonce_r_bytes,
        }
        .compute();
        let virtual_id_hex = hex::encode(vid);

        let msg = build_evidence_signing_message(
            &nonce,
            &policy_digest,
            baseline_status.as_ref(),
            &virtual_id_hex,
        );
        let sig_bytes = km.sign(&msg)?;
        let signature_b64 = general_purpose::STANDARD.encode(sig_bytes);
        let pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(dkp_pub);
        // Load PCR snapshot if available
        let pcr_load_path = format!("/var/lib/sgx-guardian/pcr/{}_current.json", node_id);
        let pcr_values = crate::secure_element::pcr::PcrSnapshot::load(&pcr_load_path).ok();
        let key_version = Some(crate::secure_element::pcr::read_dkp_key_version());
        Ok(AttestationEvidence {
            node_id,
            subject_did,
            nonce,
            policy_digest,
            virtual_id: virtual_id_hex,
            signature: signature_b64,
            pubkey_der_b64: pubkey_b64,
            presented_vc_json: None,
            pcr_values,
            key_version,
            baseline_status,
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
        let pcr_dig_bytes = ev
            .baseline_status
            .as_ref()
            .and_then(|b| hex::decode(&b.composite_digest).ok())
            .unwrap_or_default();
        let policy_dig_bytes = hex::decode(&ev.policy_digest).unwrap_or_default();
        let nonce_i_bytes = hex::decode(&ev.nonce).unwrap_or_default();
        let peer_dkp_bytes = match general_purpose::STANDARD.decode(&ev.pubkey_der_b64) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("⚠️ Attestation rejected: invalid pubkey base64: {}", e);
                return Ok(false);
            }
        };
        let recomputed_vid = crate::virtual_id::VirtualIdInputs {
            did: &ev.subject_did,
            dkp_pubkey_der: &peer_dkp_bytes,
            pcr_composite_digest: &pcr_dig_bytes,
            policy_digest: &policy_dig_bytes,
            nonce_i: &nonce_i_bytes,
            nonce_r: &[],
        }
        .compute();
        let recomputed_hex = hex::encode(recomputed_vid);
        if recomputed_hex != ev.virtual_id {
            let hint = if ev.virtual_id.is_empty() {
                " (peer is likely on the pre-VID protocol)"
            } else {
                ""
            };
            log_audit(
                &std::env::args().nth(1).unwrap_or_else(|| "unknown".into()),
                AuditCategory::Attestation,
                AuditSeverity::Critical,
                AuditAction::Rejected,
                &format!(
                    "VirtualID mismatch: claimed {} but recomputed {} for DID {}{}",
                    ev.virtual_id, recomputed_hex, ev.subject_did, hint
                ),
            );
            return Ok(false);
        }

        // Step 4: Build same message bytes as during signing
        let msg = build_evidence_signing_message(
            &ev.nonce,
            &ev.policy_digest,
            ev.baseline_status.as_ref(),
            &ev.virtual_id,
        );
        // Step 5: Decode Base64 safely
        let sig_bytes = match general_purpose::STANDARD.decode(&ev.signature) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("⚠️ Attestation rejected: invalid signature base64: {}", e);
                return Ok(false);
            }
        };
        // Step 6: Prepare verification key
        let peer_pubkey_raw = peer_dkp_bytes;

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
                // Step 8: enforce prover's self-baseline check
                if let Some(bs) = &ev.baseline_status {
                    match bs.state.as_str() {
                        "ALL_MATCH" => {}
                        "MISMATCH" => {
                            eprintln!(
                                "❌ Attestation rejected: prover {} reports PCR mismatch on PCRs {:?}",
                                ev.node_id, bs.mismatched_pcrs
                            );
                            return Ok(false);
                        }
                        "BAD_SIGNATURE" => {
                            eprintln!(
                                "❌ Attestation rejected: prover {} baseline has bad signature",
                                ev.node_id
                            );
                            return Ok(false);
                        }
                        "ABSENT" => {
                            eprintln!(
                                "⚠️ Prover {} has no signed baseline; treating as untrusted",
                                ev.node_id
                            );
                            return Ok(false);
                        }
                        other => {
                            eprintln!(
                                "❌ Attestation rejected: prover {} unknown baseline state '{}'",
                                ev.node_id, other
                            );
                            return Ok(false);
                        }
                    }
                } else {
                    eprintln!(
                        "⚠️ Prover did not include baseline_status (older binary); \
                         accepting only because legacy compatibility is still on. \
                         Upgrade all peers to enforce."
                    );
                }
                observe_verified_virtual_id(ev);
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
        // println!("Attempting mutual attestation with overlay {}", addr);
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
        let mut evidence = Self::create_signed_evidence(km, &policy.yaml)?;
        if let Ok(Some(vc)) = crate::vc::persistence::load_own_any() {
            evidence.presented_vc_json = serde_json::to_string(&vc).ok();
        }
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

            write_last_attestation(&addr, &peer_ev.policy_digest, "failed", Some(&peer_ev));
            remove_trusted_peer(&addr);
            println!("❌ Peer attestation verification failed for {}", addr);
            return Ok(false);
        }

        match verify_peer_vc_for_attestation(&peer_ev, &addr).await {
            Ok(Some(subject_did)) => {
                log_audit(
                    &node_id,
                    AuditCategory::Vc,
                    AuditSeverity::Info,
                    AuditAction::Succeeded,
                    &format!("Peer {} VC verified for {}", addr, subject_did),
                );
            }
            Ok(None) => {}
            Err(e) => {
                log_audit(
                    &node_id,
                    AuditCategory::Vc,
                    AuditSeverity::Critical,
                    AuditAction::Rejected,
                    &format!("Peer {} VC rejected: {}", addr, e),
                );
                write_last_attestation(&addr, &peer_ev.policy_digest, "failed", Some(&peer_ev));
                remove_trusted_peer(&addr);
                return Ok(false);
            }
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
        write_trusted_peer(
            &addr,
            &peer_ip,
            &peer_ev,
            current_rotation_reason_for_peer(&peer_ev.subject_did),
        );
        write_last_attestation(&addr, &peer_ev.policy_digest, "success", Some(&peer_ev));
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
    let listen_port: u16 = attestation_listener_port_for_base(node_conf.port);
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
    let peers_list = load_trusted_peers_from_global();
    if !peers_list.is_empty() {
        let allowed_targets = allowed_attestation_targets(&node_id_env);
        for peer in peers_list {
            let Some((ip, port)) =
                should_attempt_persisted_peer(&peer, &local_ip, listen_port, &allowed_targets)
            else {
                continue;
            };
            let peer_target = format!("{}:{}", ip, port);
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

                    match AttestationService::mutual_attest(target_ip.clone(), target_port, &km)
                        .await
                    {
                        Ok(true) => println!("✅ Persisted peer {} re-verified.", peer_target),
                        Ok(false) => {
                            eprintln!(
                                "❌ Persisted peer {} FAILED re-verification — removing from trust",
                                peer_target
                            );
                            remove_trusted_peer(&peer_target);
                        }
                        Err(e) => {
                            eprintln!(
                                "⚠️ Persisted peer {} re-verification error (transient): {:?}",
                                peer_target, e
                            );
                        }
                    }
                }
                Err(e) => eprintln!("⚠️ Failed KeyManager load for {}: {:?}", peer_target, e),
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
        let local_attest_port = attestation_listener_port_for_base(local_conf.port);
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let allowed_targets = allowed_attestation_targets(&node_id);
            let peers_list = load_trusted_peers_from_global();
            if !peers_list.is_empty() {
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

                            match AttestationService::mutual_attest(
                                target_ip.clone(),
                                target_port,
                                &km,
                            )
                            .await
                            {
                                Ok(true) => {
                                    println!("✅ Peer {} re-attested successfully.", peer_target);
                                }
                                Ok(false) => {
                                    eprintln!(
                                        "❌ Persisted peer {} FAILED re-verification — removing from trust",
                                        peer_target
                                    );
                                    remove_trusted_peer(&peer_target);
                                }
                                Err(e) => {
                                    eprintln!(
                                        "⚠️ Persisted peer {} re-verification error (transient): {:?}",
                                        peer_target, e
                                    );
                                }
                            }
                        }
                        Err(e) => eprintln!("⚠️ KeyManager load failed: {:?}", e),
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
                let remote_ip = remote.ip().to_string();
                let should_print_request = LAST_ATTEST_REQUEST_LOGGED
                    .get_or_init(|| Mutex::new(None))
                    .lock()
                    .map(|mut last| {
                        if last.as_deref() == Some(remote_ip.as_str()) {
                            false
                        } else {
                            *last = Some(remote_ip.clone());
                            true
                        }
                    })
                    .unwrap_or(true);
                if should_print_request {
                    println!("📩 Received attestation request from {}", remote.ip());
                }
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
                match AttestationService::verify_signed_evidence(&incoming, &policy.yaml) {
                    Ok(true) => {
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
                        match verify_peer_vc_for_attestation(&incoming, &remote.to_string()).await {
                            Ok(Some(subject_did)) => {
                                log_audit(
                                    &node_id,
                                    AuditCategory::Vc,
                                    AuditSeverity::Info,
                                    AuditAction::Succeeded,
                                    &format!("Incoming peer VC verified for {}", subject_did),
                                );
                            }
                            Ok(None) => {}
                            Err(e) => {
                                log_audit(
                                    &node_id,
                                    AuditCategory::Vc,
                                    AuditSeverity::Critical,
                                    AuditAction::Rejected,
                                    &format!("Incoming peer VC rejected from {}: {}", remote, e),
                                );
                                remove_trusted_peer(&incoming.node_id);
                                continue;
                            }
                        }

                        let mut reply =
                            AttestationService::create_signed_evidence(&km, &policy.yaml)?;
                        if let Ok(Some(vc)) = crate::vc::persistence::load_own_any() {
                            reply.presented_vc_json = serde_json::to_string(&vc).ok();
                        }
                        if let Err(e) = write_evidence_framed(&mut socket, &reply).await {
                            eprintln!(
                                "⚠️ Failed to send attestation reply to {} : {:?}",
                                remote, e
                            );
                        } else {
                            println!("📤 Sent attestation reply to peer");
                        }
                    }
                    Ok(false) | Err(_) => {
                        let peer_addr = incoming.node_id.clone();
                        eprintln!(
                            "❌ Listener: rejecting incoming attestation from {} (PCR/signature failure)",
                            peer_addr
                        );
                        remove_trusted_peer(&peer_addr);
                        let node_id = std::env::args().nth(1).unwrap_or("unknown-node".into());
                        log_audit(
                            &node_id,
                            AuditCategory::Attestation,
                            AuditSeverity::Critical,
                            AuditAction::Rejected,
                            &format!("Incoming attestation rejected from {}", remote),
                        );
                        continue;
                    }
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
    use crate::virtual_id_cache::RotationReason;
    use base64::engine::general_purpose;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use p256::SecretKey;
    use std::fs;
    use std::path::PathBuf;

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
        let baseline_status = BaselineStatus {
            state: "ALL_MATCH".into(),
            mismatched_pcrs: vec![],
            composite_digest: String::new(),
        };
        let policy_digest_bytes = hex::decode(&policy_digest).unwrap();
        let nonce_i_bytes = hex::decode(nonce).unwrap();
        let virtual_id = hex::encode(
            crate::virtual_id::VirtualIdInputs {
                did: "did:guardian:test-subject",
                dkp_pubkey_der: &spki,
                pcr_composite_digest: &[],
                policy_digest: &policy_digest_bytes,
                nonce_i: &nonce_i_bytes,
                nonce_r: &[],
            }
            .compute(),
        );
        let msg = build_evidence_signing_message(
            nonce,
            &policy_digest,
            Some(&baseline_status),
            &virtual_id,
        );

        let signature: Signature = signing_key.sign(&msg);
        let sig_der = signature.to_der();

        AttestationEvidence {
            node_id: "nodeA".to_string(),
            subject_did: "did:guardian:test-subject".to_string(),
            nonce: nonce.to_string(),
            policy_digest,
            virtual_id,
            signature: general_purpose::STANDARD.encode(sig_der.as_bytes()),
            pubkey_der_b64: general_purpose::STANDARD.encode(spki),
            presented_vc_json: None,
            pcr_values: None,
            key_version: None,
            baseline_status: Some(baseline_status),
        }
    }

    fn temp_test_dir(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "sgx-guardian-attestation-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    #[test]
    fn test_attestation_create_and_verify() {
        let policy = "allow: all";
        let nonce = {
            let hash = Sha256::digest(b"sgx-guardian-test-nonce::inline_create_verify");
            hex::encode(&hash[..16])
        };
        let ev = make_test_evidence(policy, &nonce);
        assert!(AttestationService::verify_signed_evidence(&ev, policy).unwrap());
    }

    #[test]
    fn trusted_peer_legacy_json_deserializes() {
        let legacy = r#"
        [
          {
            "peer_id": "10.0.0.2:50152",
            "ip": "10.0.0.2",
            "status": "verified",
            "timestamp": "2026-06-10T00:00:00Z"
          }
        ]
        "#;

        let peers: Vec<TrustedPeer> =
            serde_json::from_str(legacy).expect("parse legacy trusted peers");
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].peer_id, "10.0.0.2:50152");
        assert!(peers[0].did.is_none());
        assert!(peers[0].rotation_reason.is_none());
    }

    #[test]
    fn trusted_peer_new_json_writes_enriched_metadata() {
        let base = temp_test_dir("trusted-peer");
        let primary_dir = base.join("primary");
        let fallback_dir = base.join("logs");
        fs::create_dir_all(&primary_dir).expect("create primary dir");
        fs::create_dir_all(&fallback_dir).expect("create fallback dir");

        let legacy = serde_json::json!([
            {
                "peer_id": "10.0.0.2:50152",
                "ip": "10.0.0.2",
                "status": "verified",
                "timestamp": "2026-06-10T00:00:00Z"
            }
        ]);
        fs::write(
            primary_dir.join("trusted_peers_nodeB.json"),
            serde_json::to_string_pretty(&legacy).expect("serialize legacy"),
        )
        .expect("write legacy trusted peers");

        let policy = "allow: all";
        let nonce = {
            let hash = Sha256::digest(b"sgx-guardian-test-nonce::trusted-peer-enriched");
            hex::encode(&hash[..16])
        };
        let mut ev = make_test_evidence(policy, &nonce);
        ev.node_id = "nodeB".into();
        ev.subject_did = "did:guardian:peer-b".into();
        ev.key_version = Some(2);
        if let Some(status) = ev.baseline_status.as_mut() {
            status.composite_digest = "a1".repeat(32);
        }

        write_trusted_peer_with_dirs(
            "nodeA",
            &primary_dir,
            &fallback_dir,
            "10.0.0.2:50152",
            "10.0.0.2",
            &ev,
            Some(RotationReason::DkpRotated.as_str().to_string()),
        );

        let merged = fs::read_to_string(fallback_dir.join("trusted_peers.json"))
            .expect("read merged trusted peers");
        let peers: Vec<TrustedPeer> =
            serde_json::from_str(&merged).expect("parse merged trusted peers");
        assert_eq!(peers.len(), 1);
        let peer = &peers[0];
        assert_eq!(peer.peer_id, "10.0.0.2:50152");
        assert_eq!(peer.did.as_deref(), Some("did:guardian:peer-b"));
        assert_eq!(peer.virtual_id.as_deref(), Some(ev.virtual_id.as_str()));
        assert_eq!(
            peer.rotation_reason.as_deref(),
            Some(RotationReason::DkpRotated.as_str())
        );
        assert!(peer.last_attested_at.is_some());
        assert_eq!(
            peer.policy_digest.as_deref(),
            Some(ev.policy_digest.as_str())
        );
        assert_eq!(
            peer.pcr_composite_digest.as_deref(),
            Some("a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1")
        );
        assert!(peer.dkp_pubkey_sha256_b16.is_some());

        fs::remove_dir_all(base).expect("cleanup temp dir");
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

    #[test]
    fn test_attestation_listener_ports_are_not_grpc_ports() {
        assert_eq!(attestation_listener_port_for_node("nodeA"), 50151);
        assert_eq!(attestation_listener_port_for_node("nodeB"), 50152);
        assert_eq!(attestation_listener_port_for_node("nodeC"), 50153);
        assert_ne!(attestation_listener_port_for_node("nodeA"), 50051);
        assert_ne!(attestation_listener_port_for_node("nodeB"), 50052);
        assert_ne!(attestation_listener_port_for_node("nodeC"), 50053);
    }

    #[tokio::test]
    async fn test_framed_reader_rejects_grpc_preface_length_cleanly() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket
                .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let err = read_evidence_framed(&mut client).await.unwrap_err();
        assert!(err
            .to_string()
            .contains("Invalid attestation payload length"));
        server.await.unwrap();
    }
}
