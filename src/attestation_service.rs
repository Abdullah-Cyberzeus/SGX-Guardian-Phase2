//! Core attestation orchestration logic for exchanging and verifying
//! evidence between SGX Guardian nodes.
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::key_manager::KeyManager;
use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use rand::{thread_rng, RngCore};
use ring::signature;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc::Receiver;
use tokio::time::Duration;

// ---- Attestation identity key base path (single source of truth) ----
const ATTESTATION_KEY_DIR: &str = "/var/lib/sgx-guardian/sgx-agent";

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
impl AttestationService {
    /// Creates signed attestation evidence by hashing the policy file,
    /// generating a random nonce, and signing the combined message.
    pub fn create_signed_evidence(
        km: &KeyManager,
        policy_yaml: &str,
    ) -> Result<AttestationEvidence> {
        let mut nonce_bytes = [0u8; 16];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);
        let clean_policy = policy_yaml
            .replace("\r", "")
            .replace("\n", "")
            .trim()
            .to_string();
        let digest = Sha256::digest(clean_policy.as_bytes());
        let policy_digest = hex::encode(digest);
        let msg = format!("{}{}", nonce, policy_digest);
        let sig_bytes = km.sign(msg.as_bytes())?;
        let signature_b64 = general_purpose::STANDARD.encode(sig_bytes);
        let pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(km.pubkey_der());
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
        // Step 1: Normalize policy content
        let clean_policy = policy_yaml
            .replace("\r", "")
            .replace("\n", "")
            .trim()
            .to_string();
        // Step 2: Recompute policy digest
        let digest = Sha256::digest(clean_policy.as_bytes());
        let expected_digest = hex::encode(digest);
        // Step 3: Ensure digest matches
        if ev.policy_digest != expected_digest {
            println!("❌ Policy digest mismatch");
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
    /// Performs the full mutual attestation handshake: connects to peer,
    /// exchanges signed evidence, verifies policy digest & signature,
    /// and updates trusted peer state on success.
    pub async fn mutual_attest(peer_ip: String, peer_port: u16, km: &KeyManager) -> Result<bool> {
        use std::fs;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;
        let addr = format!("{}:{}", peer_ip, peer_port);
        println!("Attempting mutual attestation with {}", addr);
        let node_id = std::env::args().nth(1).unwrap_or("unknown-node".into());

        log_audit(
            &node_id,
            AuditCategory::Attestation,
            AuditSeverity::Info,
            AuditAction::Started,
            &format!("Started mutual attestation with {}", addr),
        );
        // Step 1: try connect with small retry loop
        let mut attempt = 0;
        let mut stream_opt = None;

        while attempt < 3 {
            match TcpStream::connect(addr.clone()).await {
                Ok(s) => {
                    stream_opt = Some(s);
                    break;
                }
                Err(_) => {
                    attempt += 1;
                    println!("⏳ Waiting for peer {} (attempt {}/3)...", addr, attempt);
                    tokio::time::sleep(Duration::from_millis(300)).await;
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
        let policy_data = fs::read_to_string("/etc/sgx-guardian/schemas/uep_policy_v1.yaml")?;
        let evidence = Self::create_signed_evidence(km, &policy_data)?;
        let payload = serde_json::to_vec(&evidence)?;
        stream.write_all(&payload).await?;
        // Step 3: receive peer evidence
        let mut buffer = vec![0u8; 4096];
        let n = stream.read(&mut buffer).await?;
        if n == 0 {
            println!("⚠️ No data received from peer {}", addr);
            return Ok(false);
        }
        let peer_ev: AttestationEvidence = match serde_json::from_slice(&buffer[..n]) {
            Ok(e) => e,
            Err(e) => {
                println!("❌ Failed to parse peer evidence: {:?}", e);
                return Ok(false);
            }
        };
        // Step 4: verify peer evidence (using peer's embedded public key)
        let verified = Self::verify_signed_evidence(&peer_ev, &policy_data)?;
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
    // === Auto Re-Attest on Startup ===
    let contents = fs::read_to_string("/var/log/sgx-guardian/trusted_peers.json")
        .or_else(|_| fs::read_to_string("logs/trusted_peers.json"));

    if let Ok(contents) = contents {
        // Parse JSON safely
        let parsed: Result<Vec<TrustedPeer>, serde_json::Error> = serde_json::from_str(&contents);
        if let Ok(peers_list) = parsed {
            for peer in peers_list {
                println!("Verifying persisted peer {} on startup...", peer.peer_id);
                let node_id = std::env::args().nth(1).unwrap_or("nodeA".into());
                let key_path = format!("{}/device_{}.key", ATTESTATION_KEY_DIR, node_id);
                match KeyManager::load_or_generate(&key_path) {
                    Ok(km) => {
                        let parts: Vec<&str> = peer.peer_id.split(':').collect();
                        if parts.len() == 2 {
                            let ip = parts[0].to_string();
                            let port = parts[1].parse::<u16>().unwrap_or(50151);
                            if let Ok(true) =
                                AttestationService::mutual_attest(ip.clone(), port, &km).await
                            {
                                println!("✅ Persisted peer {} re-verified.", peer.peer_id);
                            }
                        }
                    }
                    Err(e) => eprintln!("⚠️ Failed KeyManager load for {}: {:?}", peer.peer_id, e),
                }
            }
        }
    }

    // === Spawn background TCP listener for incoming attestations ===
    use crate::config_loader::load_config;

    let node_id_env = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "nodeA".to_string());
    let node_conf = load_config(&format!("/etc/sgx-guardian/{}.yaml", node_id_env))
        .expect("Failed to load node config in attestation service");
    let listen_port: u16 = node_conf.port + 100;

    println!("🛰️ Spawning attestation listener on port {}", listen_port);

    let bind_ip = "0.0.0.0".to_string();
    tokio::spawn(async move {
        if let Err(e) = start_attestation_listener(bind_ip, listen_port).await {
            eprintln!("⚠️ Attestation listener error: {:?}", e);
        }
    });

    // === Sprint 2 Day 9 – Periodic Re-Attestation Timer (every 60 seconds) ===
    tokio::spawn(async {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let contents = fs::read_to_string("/var/log/sgx-guardian/trusted_peers.json")
                .or_else(|_| fs::read_to_string("logs/trusted_peers.json"));

            if let Ok(contents) = contents {
                let parsed: Result<Vec<TrustedPeer>, serde_json::Error> =
                    serde_json::from_str(&contents);
                if let Ok(peers_list) = parsed {
                    for peer in peers_list {
                        println!("🔁 Re-attesting trusted peer: {}", peer.peer_id);
                        let node_id = std::env::args().nth(1).unwrap_or("nodeA".into());
                        let key_path = format!("{}/device_{}.key", ATTESTATION_KEY_DIR, node_id);
                        match KeyManager::load_or_generate(&key_path) {
                            Ok(km) => {
                                let addr_parts: Vec<&str> = peer.peer_id.split(':').collect();
                                if addr_parts.len() == 2 {
                                    let ip = addr_parts[0].to_string();
                                    let port = addr_parts[1].parse::<u16>().unwrap_or(50151);
                                    if let Ok(true) =
                                        AttestationService::mutual_attest(ip.clone(), port, &km)
                                            .await
                                    {
                                        println!(
                                            "✅ Peer {} re-attested successfully.",
                                            peer.peer_id
                                        );
                                    } else {
                                        eprintln!("⚠️ Re-attestation failed for {}", peer.peer_id);
                                    }
                                }
                            }
                            Err(e) => eprintln!("⚠️ KeyManager load failed: {:?}", e),
                        }
                    }
                }
            }
        }
    });

    while let Some(peer) = rx.recv().await {
        println!("🔐 Attesting discovered peer: {}", peer);

        // Parse peer address: expect "ip:port"
        let (peer_ip, base_port) = if let Some((ip, port)) = peer.split_once(':') {
            (ip.to_string(), port.parse::<u16>().unwrap_or(50051))
        } else {
            (peer.clone(), 50051)
        };

        // Derive attestation port (+100 offset)
        let attest_port = base_port + 100;
        let node_id = std::env::args().nth(1).unwrap_or("nodeA".into());
        let key_path = format!("{}/device_{}.key", ATTESTATION_KEY_DIR, node_id);
        match crate::key_manager::KeyManager::load_or_generate(&key_path) {
            Ok(km) => {
                match AttestationService::mutual_attest(peer_ip.clone(), attest_port, &km).await {
                    Ok(true) => println!("✅ Peer {} attested successfully.", peer_ip),
                    Ok(false) => println!("❌ Peer {} attestation failed.", peer_ip),
                    Err(e) => eprintln!("⚠️ Attestation error with {}: {:?}", peer_ip, e),
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
    use std::fs;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let addr = format!("{}:{}", bind_ip, listen_port);
    let listener = TcpListener::bind(&addr).await?;
    println!("🔒 Attestation listener started on {}", addr);

    loop {
        match listener.accept().await {
            Ok((mut socket, remote)) => {
                println!("📩 Received attestation request from {}", remote);
                let node_id = std::env::args().nth(1).unwrap_or("unknown-node".into());

                log_audit(
                    &node_id,
                    AuditCategory::Attestation,
                    AuditSeverity::Info,
                    AuditAction::Started,
                    &format!("Received attestation request from {}", remote),
                );
                let mut buffer = vec![0u8; 4096];
                match socket.read(&mut buffer).await {
                    Ok(n) if n > 0 => {
                        // Deserialize peer evidence
                        let incoming: AttestationEvidence =
                            match serde_json::from_slice(&buffer[..n]) {
                                Ok(ev) => ev,
                                Err(e) => {
                                    eprintln!("❌ Failed to parse incoming evidence: {:?}", e);
                                    continue;
                                }
                            };

                        // Verify peer evidence
                        let node_id = std::env::args().nth(1).unwrap_or("nodeA".into());
                        let key_path = format!("{}/device_{}.key", ATTESTATION_KEY_DIR, node_id);
                        let km = KeyManager::load_or_generate(&key_path)?;
                        let policy =
                            fs::read_to_string("/etc/sgx-guardian/schemas/uep_policy_v1.yaml")?;
                        let verified =
                            AttestationService::verify_signed_evidence(&incoming, &policy)?;

                        if verified {
                            println!("✅ Verified attestation from {}", remote);
                            let node_id = std::env::args().nth(1).unwrap_or("unknown-node".into());

                            log_audit(
                                &node_id,
                                AuditCategory::Attestation,
                                AuditSeverity::Info,
                                AuditAction::Succeeded,
                                &format!("Incoming attestation verified from {}", remote),
                            );

                            // Send our own evidence back
                            let reply = AttestationService::create_signed_evidence(&km, &policy)?;
                            let payload = serde_json::to_vec(&reply)?;
                            if let Err(e) = socket.write_all(&payload).await {
                                eprintln!(
                                    "⚠️ Failed to send attestation reply to {} : {:?}",
                                    remote, e
                                );
                            } else {
                                println!("📤 Sent attestation reply to {}", remote);
                            }
                        } else {
                            eprintln!("❌ Attestation verification failed for {}", remote);
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
                    Ok(_) => {
                        eprintln!("⚠️ Empty attestation request from {}", remote);
                    }
                    Err(e) => {
                        eprintln!(
                            "⚠️ Error reading attestation request from {} : {:?}",
                            remote, e
                        );
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
    use base64::engine::general_purpose;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use p256::SecretKey;
    use sha2::{Digest, Sha256};

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

        let clean_policy = policy
            .replace("\r", "")
            .replace("\n", "")
            .trim()
            .to_string();
        let digest = Sha256::digest(clean_policy.as_bytes());
        let policy_digest = hex::encode(digest);
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
}
