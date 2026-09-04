//! Gossip engine: inbound listener + periodic outbound rounds.

use super::protocol::{
    self, SyncAck, SyncPush, SyncRequest, SyncResponse, KIND_ACK, KIND_PUSH, KIND_REQUEST,
    KIND_RESPONSE,
};
use super::store;
use super::GossipConfig;
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::crl::entry::{CrlEntry, Severity, UnrevokeTombstone};
use crate::did::{DidRecord, Resolver};
use crate::key_manager::KeyManager;
use once_cell::sync::Lazy;
use rand::seq::SliceRandom;
use rand::Rng;
use serde::Serialize;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Duration;
use tokio::io::BufReader;
use tokio::net::{TcpListener, TcpStream};

// Runtime observability (read by GET /api/v1/crl/gossip/status)

static ROUNDS_INITIATED: AtomicU64 = AtomicU64::new(0);
static ROUNDS_SERVED: AtomicU64 = AtomicU64::new(0);
static ENTRIES_MERGED: AtomicU64 = AtomicU64::new(0);
static LAST_ROUND: Lazy<RwLock<Option<LastRound>>> = Lazy::new(|| RwLock::new(None));

#[derive(Debug, Clone, Serialize)]
pub struct LastRound {
    pub direction: String,
    pub peer_did: String,
    pub peer_node: String,
    pub merged: usize,
    pub sent: usize,
    pub merkle_root: String,
    pub at: String,
}

pub fn rounds_initiated() -> u64 {
    ROUNDS_INITIATED.load(Ordering::Relaxed)
}
pub fn rounds_served() -> u64 {
    ROUNDS_SERVED.load(Ordering::Relaxed)
}
pub fn entries_merged_total() -> u64 {
    ENTRIES_MERGED.load(Ordering::Relaxed)
}
pub fn last_round() -> Option<LastRound> {
    LAST_ROUND.read().ok().and_then(|guard| guard.clone())
}

fn record_last_round(round: LastRound) {
    if let Ok(mut guard) = LAST_ROUND.write() {
        *guard = Some(round);
    }
}

// Identity / peer directory

pub fn did_record_path() -> String {
    std::env::var("SGX_GUARDIAN_DID_PATH")
        .unwrap_or_else(|_| crate::did::DEFAULT_DID_PATH.to_string())
}

fn load_identity(node_id: &str) -> Result<(DidRecord, std::sync::Arc<KeyManager>, String), String> {
    let record =
        DidRecord::load(&did_record_path()).map_err(|error| format!("did record: {}", error))?;
    let km = crate::vc::issue::load_runtime_key_manager(node_id)
        .map_err(|error| format!("key manager: {}", error))?;
    let circle_id = crate::crl::issue::current_circle_id()
        .unwrap_or_else(|_| crate::crl::issue::DEFAULT_CIRCLE_ID.to_string());
    Ok((record, km, circle_id))
}

#[derive(Debug, Clone)]
pub struct GossipPeer {
    pub did: String,
    pub node_name: String,
    pub overlay_ip: String,
}

/// `"nebula://192.168.100.7/24"` -> `Some("192.168.100.7")`
pub fn parse_nebula_endpoint(endpoint: &str) -> Option<String> {
    endpoint
        .strip_prefix("nebula://")
        .and_then(|cidr| cidr.split('/').next())
        .filter(|ip| !ip.is_empty())
        .map(|ip| ip.to_string())
}

/// Gossip candidates = cached peer DID Documents that are (a) not self,
/// (b) status "active", (c) not currently revoked, (d) advertising an
/// `SGXNebulaMesh` overlay endpoint. Revoked peers are excluded in BOTH
/// directions (never dialed here; inbound rejected in `handle_inbound`).
pub fn active_gossip_peers(self_did: &str) -> Vec<GossipPeer> {
    let docs = match crate::did::doc_persistence::list_peer_docs() {
        Ok(docs) => docs,
        Err(_) => return Vec::new(),
    };
    let mut peers = Vec::new();
    for doc in docs {
        if doc.id == self_did {
            continue;
        }
        if doc.sgx_status.as_deref() != Some("active") {
            continue;
        }
        if crate::crl::is_revoked(&doc.id) {
            continue;
        }
        let Some(overlay_ip) = doc
            .service
            .iter()
            .find(|service| service.svc_type == "SGXNebulaMesh")
            .and_then(|service| parse_nebula_endpoint(&service.service_endpoint))
        else {
            continue;
        };
        peers.push(GossipPeer {
            did: doc.id.clone(),
            node_name: doc.sgx_node_name.clone().unwrap_or_default(),
            overlay_ip,
        });
    }
    peers
}

/// `ceil(threshold_pct% x other_members)`, floored at 1.
/// 3-node cohort -> other_members = 2 -> ceil(1.6) = 2 acks flip `propagated`.
pub fn threshold_count(other_members: usize, threshold_pct: u8) -> usize {
    if other_members == 0 {
        return 1;
    }
    let raw = (other_members as f64) * (threshold_pct as f64) / 100.0;
    (raw.ceil() as usize).max(1)
}

#[derive(Debug, Clone, Serialize)]
pub struct RoundReport {
    pub peer_did: String,
    pub peer_node: String,
    pub merged: usize,
    pub replaced: usize,
    pub pushed: usize,
    pub peer_merged: usize,
    pub merkle_root: String,
    pub sequence: u64,
    pub newly_propagated: Vec<String>,
}

// Periodic round loop

pub async fn round_task(node_id: String, resolver: Resolver, config: GossipConfig) {
    let mut tick = tokio::time::interval(Duration::from_secs(config.interval_secs));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tick.tick().await;
    loop {
        tick.tick().await;
        // +/-20 % jitter desynchronizes cohort rounds (probabilistic flooding).
        let jitter_ms = {
            let mut rng = rand::thread_rng();
            rng.gen_range(0..=config.interval_secs.saturating_mul(200))
        };
        tokio::time::sleep(Duration::from_millis(jitter_ms)).await;
        match run_round_once(&node_id, &resolver, &config).await {
            Ok(report) => {
                println!(
                    "🗣️ CRL-GOSSIP round ok peer={} node={} merged={} pushed={} root={}",
                    report.peer_did,
                    report.peer_node,
                    report.merged + report.replaced,
                    report.pushed,
                    report.merkle_root
                );
            }
            Err(reason) => {
                tracing::warn!("CRL-GOSSIP round skipped: {}", reason);
            }
        }
    }
}

/// One full initiator-side exchange with ONE random active peer. Also
/// invoked by `POST /api/v1/crl/gossip/trigger` for deterministic board
/// testing. Stateless per call - all durable state lives in `crl.json`.
pub async fn run_round_once(
    node_id: &str,
    resolver: &Resolver,
    config: &GossipConfig,
) -> Result<RoundReport, String> {
    let (record, km, circle_id) = load_identity(node_id)?;
    let peers = active_gossip_peers(&record.did);
    if peers.is_empty() {
        return Err("no active gossip peers yet (peer DID documents not synced)".into());
    }
    let other_members = peers.len();
    let peer = {
        let mut rng = rand::thread_rng();
        peers
            .choose(&mut rng)
            .cloned()
            .expect("peer list verified non-empty")
    };
    exchange_with_peer(
        node_id,
        &record,
        &km,
        &circle_id,
        resolver,
        config,
        &peer,
        other_members,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn exchange_with_peer(
    node_id: &str,
    record: &DidRecord,
    km: &KeyManager,
    circle_id: &str,
    resolver: &Resolver,
    config: &GossipConfig,
    peer: &GossipPeer,
    other_members: usize,
) -> Result<RoundReport, String> {
    let addr = format!("{}:{}", peer.overlay_ip, config.port);
    let stream = tokio::time::timeout(
        Duration::from_secs(protocol::IO_TIMEOUT_SECS),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| format!("timeout connecting {}", addr))?
    .map_err(|error| format!("connect {}: {}", addr, error))?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // 1) advertise local snapshot
    let (sequence, merkle_root, fingerprints) = {
        let _guard = store::CRL_WRITE_LOCK.lock().await;
        store::snapshot().map_err(|error| error.to_string())?
    };
    let local_set: HashSet<String> = fingerprints.iter().cloned().collect();
    let request = SyncRequest {
        kind: KIND_REQUEST.to_string(),
        circle_id: circle_id.to_string(),
        sender_did: record.did.clone(),
        sequence,
        merkle_root,
        fingerprints,
    };
    protocol::write_json_line(&mut write_half, &request)
        .await
        .map_err(|error| error.to_string())?;

    // 2) receive the peer's diff
    let line = protocol::read_json_line(&mut reader)
        .await
        .map_err(|error| error.to_string())?;
    let response: SyncResponse = serde_json::from_str(line.trim())
        .map_err(|error| format!("bad sync response: {}", error))?;
    if let Some(error) = response.error.as_deref() {
        return Err(format!("peer {} rejected exchange: {}", peer.did, error));
    }
    if response.kind != KIND_RESPONSE {
        return Err(format!("unexpected message kind '{}'", response.kind));
    }
    if response.circle_id != circle_id {
        return Err(format!(
            "circle mismatch: local={} peer={}",
            circle_id, response.circle_id
        ));
    }
    if response.sender_did != peer.did {
        return Err(format!(
            "peer identity mismatch: directory={} announced={}",
            peer.did, response.sender_did
        ));
    }

    // 3) verify + merge what the peer had that we lacked
    let (verified_entries, verified_tombstones) = verify_batch(
        node_id,
        &response.entries,
        &response.tombstones,
        resolver,
        circle_id,
    )
    .await;
    let merge = {
        let _guard = store::CRL_WRITE_LOCK.lock().await;
        store::merge_verified_records(
            record,
            km,
            circle_id,
            &verified_entries,
            &verified_tombstones,
        )
        .map_err(|error| error.to_string())?
    };
    audit_merged_entries(node_id, &merge.merged_entries, &peer.did);
    audit_merged_tombstones(node_id, &merge.merged_tombstones, &peer.did);

    // 4) push what the peer asked for. `want` is filtered against OUR
    //    pre-merge set, so entries just received from this peer are never
    //    echoed back.
    let want: HashSet<String> = response
        .want
        .iter()
        .filter(|fingerprint| local_set.contains(*fingerprint))
        .cloned()
        .collect();
    let (push_entries, push_tombstones) = {
        let _guard = store::CRL_WRITE_LOCK.lock().await;
        store::entries_matching(&want).map_err(|error| error.to_string())?
    };
    let pushed = push_entries.len() + push_tombstones.len();
    let push = SyncPush {
        kind: KIND_PUSH.to_string(),
        entries: push_entries,
        tombstones: push_tombstones,
    };
    protocol::write_json_line(&mut write_half, &push)
        .await
        .map_err(|error| error.to_string())?;

    // 5) ack
    let ack_line = protocol::read_json_line(&mut reader)
        .await
        .map_err(|error| error.to_string())?;
    let ack: SyncAck = serde_json::from_str(ack_line.trim())
        .map_err(|error| format!("bad sync ack: {}", error))?;
    if let Some(error) = ack.error.as_deref() {
        return Err(format!("peer {} failed to merge push: {}", peer.did, error));
    }

    // 6) record the ack + propagation threshold on our side
    let threshold = threshold_count(other_members, config.threshold_pct);
    let noted = {
        let _guard = store::CRL_WRITE_LOCK.lock().await;
        store::mark_peer_notified(record, km, circle_id, &peer.did, threshold)
            .map_err(|error| error.to_string())?
    };
    audit_propagated(node_id, &noted.newly_propagated, threshold);

    ROUNDS_INITIATED.fetch_add(1, Ordering::Relaxed);
    ENTRIES_MERGED.fetch_add((merge.added + merge.replaced) as u64, Ordering::Relaxed);
    record_last_round(LastRound {
        direction: "initiated".into(),
        peer_did: peer.did.clone(),
        peer_node: peer.node_name.clone(),
        merged: merge.added + merge.replaced,
        sent: pushed,
        merkle_root: noted.merkle_root.clone(),
        at: chrono::Utc::now().to_rfc3339(),
    });
    log_audit(
        node_id,
        AuditCategory::Crl,
        AuditSeverity::Info,
        AuditAction::Succeeded,
        &format!(
            "CRL gossip round peer={} node={} merged={} pushed={} peer_merged={} root={}",
            peer.did,
            peer.node_name,
            merge.added + merge.replaced,
            pushed,
            ack.merged,
            noted.merkle_root
        ),
    );

    Ok(RoundReport {
        peer_did: peer.did.clone(),
        peer_node: peer.node_name.clone(),
        merged: merge.added,
        replaced: merge.replaced,
        pushed,
        peer_merged: ack.merged,
        merkle_root: noted.merkle_root,
        sequence: noted.sequence,
        newly_propagated: noted.newly_propagated,
    })
}

// Inbound listener (runs on every node)

pub async fn listener_task(node_id: String, resolver: Resolver, config: GossipConfig) {
    let addr = format!("0.0.0.0:{}", config.port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(listener) => {
            println!("🗣️ CRL-GOSSIP listener on {}", addr);
            listener
        }
        Err(error) => {
            eprintln!("❌ CRL-GOSSIP bind failed on {}: {}", addr, error);
            log_audit(
                &node_id,
                AuditCategory::Crl,
                AuditSeverity::Critical,
                AuditAction::Failed,
                &format!("CRL gossip listener bind failed on {}: {}", addr, error),
            );
            return;
        }
    };
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let node_id = node_id.clone();
                let resolver = resolver.clone();
                let config = config.clone();
                tokio::spawn(async move {
                    if let Err(reason) = handle_inbound(stream, &node_id, &resolver, &config).await
                    {
                        tracing::warn!("CRL-GOSSIP inbound from {} failed: {}", peer_addr, reason);
                    }
                });
            }
            Err(error) => eprintln!("CRL-GOSSIP accept error: {}", error),
        }
    }
}

async fn handle_inbound(
    stream: TcpStream,
    node_id: &str,
    resolver: &Resolver,
    config: &GossipConfig,
) -> Result<(), String> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let line = protocol::read_json_line(&mut reader)
        .await
        .map_err(|error| error.to_string())?;
    let request: SyncRequest = serde_json::from_str(line.trim())
        .map_err(|error| format!("bad sync request: {}", error))?;

    let (record, km, circle_id) = match load_identity(node_id) {
        Ok(identity) => identity,
        Err(reason) => {
            reject(&mut write_half, node_id, &request.circle_id, &reason).await;
            return Err(reason);
        }
    };

    // Zero-trust inbound validation
    if request.kind != KIND_REQUEST {
        let reason = format!("unexpected message kind '{}'", request.kind);
        reject(&mut write_half, &record.did, &circle_id, &reason).await;
        return Err(reason);
    }
    if request.circle_id != circle_id {
        let reason = format!(
            "circle mismatch: local={} peer={}",
            circle_id, request.circle_id
        );
        reject(&mut write_half, &record.did, &circle_id, &reason).await;
        return Err(reason);
    }
    if request.sender_did == record.did {
        let reason = "sender_did equals local DID".to_string();
        reject(&mut write_half, &record.did, &circle_id, &reason).await;
        return Err(reason);
    }
    if crate::crl::is_revoked(&request.sender_did) {
        let reason = format!("sender is revoked: {}", request.sender_did);
        audit_reject(node_id, &request.sender_did, &reason);
        reject(&mut write_half, &record.did, &circle_id, &reason).await;
        return Err(reason);
    }
    let peers = active_gossip_peers(&record.did);
    let Some(sender) = peers
        .iter()
        .find(|peer| peer.did == request.sender_did)
        .cloned()
    else {
        let reason = format!("sender not in local peer directory: {}", request.sender_did);
        audit_reject(node_id, &request.sender_did, &reason);
        reject(&mut write_half, &record.did, &circle_id, &reason).await;
        return Err(reason);
    };
    let other_members = peers.len();

    // Diff: what they lack / what we lack
    let their_set: HashSet<String> = request.fingerprints.iter().cloned().collect();
    let (sequence, merkle_root, local_fps, records_for_them) = {
        let _guard = store::CRL_WRITE_LOCK.lock().await;
        let (sequence, merkle_root, local_fps) =
            store::snapshot().map_err(|error| error.to_string())?;
        let records_for_them =
            store::entries_not_in(&their_set).map_err(|error| error.to_string())?;
        (sequence, merkle_root, local_fps, records_for_them)
    };
    let (entries_for_them, tombstones_for_them) = records_for_them;
    let local_set: HashSet<String> = local_fps.into_iter().collect();
    let want: Vec<String> = request
        .fingerprints
        .iter()
        .filter(|fingerprint| !local_set.contains(*fingerprint))
        .cloned()
        .collect();
    let sent = entries_for_them.len() + tombstones_for_them.len();

    let response = SyncResponse {
        kind: KIND_RESPONSE.to_string(),
        circle_id: circle_id.clone(),
        sender_did: record.did.clone(),
        sequence,
        merkle_root,
        entries: entries_for_them,
        tombstones: tombstones_for_them,
        want,
        error: None,
    };
    protocol::write_json_line(&mut write_half, &response)
        .await
        .map_err(|error| error.to_string())?;

    // Receive + verify + merge their push
    let push_line = protocol::read_json_line(&mut reader)
        .await
        .map_err(|error| error.to_string())?;
    let push: SyncPush = serde_json::from_str(push_line.trim())
        .map_err(|error| format!("bad sync push: {}", error))?;
    if push.kind != KIND_PUSH {
        return Err(format!("unexpected message kind '{}'", push.kind));
    }
    let (verified_entries, verified_tombstones) = verify_batch(
        node_id,
        &push.entries,
        &push.tombstones,
        resolver,
        &circle_id,
    )
    .await;
    let merge_result = {
        let _guard = store::CRL_WRITE_LOCK.lock().await;
        store::merge_verified_records(
            &record,
            &km,
            &circle_id,
            &verified_entries,
            &verified_tombstones,
        )
    };
    let outcome = match merge_result {
        Ok(outcome) => outcome,
        Err(error) => {
            let message = error.to_string();
            let ack = SyncAck {
                kind: KIND_ACK.to_string(),
                merged: 0,
                merkle_root: String::new(),
                error: Some(message.clone()),
            };
            protocol::write_json_line(&mut write_half, &ack)
                .await
                .map_err(|error| error.to_string())?;
            return Err(message);
        }
    };
    audit_merged_entries(node_id, &outcome.merged_entries, &sender.did);
    audit_merged_tombstones(node_id, &outcome.merged_tombstones, &sender.did);
    let merged_count = outcome.added + outcome.replaced;
    let ack = SyncAck {
        kind: KIND_ACK.to_string(),
        merged: merged_count,
        merkle_root: outcome.merkle_root.clone(),
        error: None,
    };
    protocol::write_json_line(&mut write_half, &ack)
        .await
        .map_err(|error| error.to_string())?;

    // Record the ack + propagation threshold on our side
    let threshold = threshold_count(other_members, config.threshold_pct);
    let noted = {
        let _guard = store::CRL_WRITE_LOCK.lock().await;
        store::mark_peer_notified(&record, &km, &circle_id, &sender.did, threshold)
            .map_err(|error| error.to_string())?
    };
    audit_propagated(node_id, &noted.newly_propagated, threshold);

    ROUNDS_SERVED.fetch_add(1, Ordering::Relaxed);
    ENTRIES_MERGED.fetch_add(merged_count as u64, Ordering::Relaxed);
    record_last_round(LastRound {
        direction: "served".into(),
        peer_did: sender.did.clone(),
        peer_node: sender.node_name.clone(),
        merged: merged_count,
        sent,
        merkle_root: noted.merkle_root.clone(),
        at: chrono::Utc::now().to_rfc3339(),
    });
    log_audit(
        node_id,
        AuditCategory::Crl,
        AuditSeverity::Info,
        AuditAction::Succeeded,
        &format!(
            "CRL gossip served peer={} node={} sent={} merged={} root={}",
            sender.did, sender.node_name, sent, merged_count, noted.merkle_root
        ),
    );
    Ok(())
}

// Shared helpers

async fn reject(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    local_identity: &str,
    circle_id: &str,
    reason: &str,
) {
    let response = SyncResponse {
        kind: KIND_RESPONSE.to_string(),
        circle_id: circle_id.to_string(),
        sender_did: local_identity.to_string(),
        sequence: 0,
        merkle_root: String::new(),
        entries: Vec::new(),
        tombstones: Vec::new(),
        want: Vec::new(),
        error: Some(reason.to_string()),
    };
    let _ = protocol::write_json_line(writer, &response).await;
}

/// Verify each received entry against the issuer's resolved DID Document.
/// Invalid entries are skipped (and audited) - one bad entry must never
/// poison a whole exchange.
async fn verify_batch(
    node_id: &str,
    entries: &[CrlEntry],
    tombstones: &[UnrevokeTombstone],
    resolver: &Resolver,
    circle_id: &str,
) -> (Vec<CrlEntry>, Vec<UnrevokeTombstone>) {
    let mut verified_entries = Vec::new();
    let mut processed_entries = 0usize;
    for entry in entries.iter().take(protocol::MAX_ENTRIES_PER_MESSAGE) {
        processed_entries += 1;
        match crate::crl::verify::verify_entry(entry, resolver, circle_id).await {
            Ok(()) => verified_entries.push(entry.clone()),
            Err(error) => {
                tracing::warn!("CRL-GOSSIP rejected entry {}: {}", entry.id, error);
                log_audit(
                    node_id,
                    AuditCategory::Crl,
                    AuditSeverity::Warning,
                    AuditAction::Failed,
                    &format!("CRL gossip rejected entry {}: {}", entry.id, error),
                );
            }
        }
    }
    let remaining = protocol::MAX_ENTRIES_PER_MESSAGE.saturating_sub(processed_entries);
    let mut verified_tombstones = Vec::new();
    for tombstone in tombstones.iter().take(remaining) {
        match crate::crl::verify::verify_tombstone(tombstone, resolver).await {
            Ok(()) => verified_tombstones.push(tombstone.clone()),
            Err(error) => {
                tracing::warn!("CRL-GOSSIP rejected tombstone {}: {}", tombstone.id, error);
                log_audit(
                    node_id,
                    AuditCategory::Crl,
                    AuditSeverity::Warning,
                    AuditAction::Failed,
                    &format!("CRL gossip rejected tombstone {}: {}", tombstone.id, error),
                );
            }
        }
    }
    (verified_entries, verified_tombstones)
}

fn audit_merged_entries(node_id: &str, merged: &[CrlEntry], peer_did: &str) {
    for entry in merged {
        let severity = match entry.severity {
            Severity::Critical => AuditSeverity::Critical,
            Severity::High => AuditSeverity::Warning,
            Severity::Medium | Severity::Low => AuditSeverity::Info,
        };
        log_audit(
            node_id,
            AuditCategory::Crl,
            severity,
            AuditAction::Succeeded,
            &format!(
                "CRL gossip merged revocation revoked_did={} reason={} severity={} via_peer={}",
                entry.revoked_did,
                entry.reason.as_str(),
                entry.severity.as_str(),
                peer_did
            ),
        );
        println!(
            "🗣️ CRL-GOSSIP merged revocation revoked_did={} severity={} via_peer={}",
            entry.revoked_did,
            entry.severity.as_str(),
            peer_did
        );
    }
}

fn audit_merged_tombstones(node_id: &str, merged: &[UnrevokeTombstone], peer_did: &str) {
    for tombstone in merged {
        log_audit(
            node_id,
            AuditCategory::Crl,
            AuditSeverity::Info,
            AuditAction::Succeeded,
            &format!(
                "CRL gossip merged unrevoke tombstone revoked_did={} original_entry_id={} via_peer={}",
                tombstone.revoked_did, tombstone.original_entry_id, peer_did
            ),
        );
        println!(
            "🗣️ CRL-GOSSIP merged tombstone revoked_did={} via_peer={}",
            tombstone.revoked_did, peer_did
        );
    }
}

fn audit_propagated(node_id: &str, newly_propagated: &[String], threshold: usize) {
    for entry_id in newly_propagated {
        log_audit(
            node_id,
            AuditCategory::Crl,
            AuditSeverity::Info,
            AuditAction::Updated,
            &format!(
                "CRL entry propagated id={} threshold={}",
                entry_id, threshold
            ),
        );
        println!(
            "🗣️ CRL-GOSSIP entry propagated id={} threshold={}",
            entry_id, threshold
        );
    }
}

fn audit_reject(node_id: &str, sender_did: &str, reason: &str) {
    log_audit(
        node_id,
        AuditCategory::Crl,
        AuditSeverity::Warning,
        AuditAction::Failed,
        &format!("CRL gossip rejected sender={}: {}", sender_did, reason),
    );
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::crl::entry::{RevocationReason, RevokerRole, CRL_CONTEXT_CORE, CRL_CONTEXT_SGX};
    use crate::crl::list::CertificateRevocationList;
    use crate::crl::persistence;
    use crate::did::doc_persistence;
    use crate::did::document::{DidDocument, Proof, ServiceEndpoint};
    use crate::did::ResolverConfig;
    use tempfile::TempDir;

    #[test]
    fn parse_nebula_endpoint_extracts_ip_from_cidr() {
        assert_eq!(
            parse_nebula_endpoint("nebula://192.168.100.7/24"),
            Some("192.168.100.7".to_string())
        );
    }

    #[test]
    fn parse_nebula_endpoint_extracts_ip_without_cidr_suffix() {
        assert_eq!(
            parse_nebula_endpoint("nebula://10.0.0.5"),
            Some("10.0.0.5".to_string())
        );
    }

    #[test]
    fn parse_nebula_endpoint_rejects_wrong_scheme_or_empty_ip() {
        assert_eq!(parse_nebula_endpoint("tcp://192.168.100.7:9000"), None);
        assert_eq!(parse_nebula_endpoint("nebula:///24"), None);
        assert_eq!(parse_nebula_endpoint(""), None);
    }

    #[test]
    fn threshold_count_ceils_percentage_of_other_members() {
        // 3-node cohort -> other_members = 2 -> ceil(1.6) = 2.
        assert_eq!(threshold_count(2, 80), 2);
        assert_eq!(threshold_count(10, 50), 5);
        assert_eq!(threshold_count(10, 51), 6);
    }

    #[test]
    fn threshold_count_floors_at_one() {
        assert_eq!(threshold_count(0, 80), 1);
        assert_eq!(threshold_count(1, 1), 1);
    }

    #[test]
    fn threshold_count_full_percentage_equals_member_count() {
        assert_eq!(threshold_count(5, 100), 5);
        assert_eq!(threshold_count(1, 100), 1);
    }

    // --- test env helpers ---------------------------------------------------

    /// Restores whatever value (if any) preceded an `env::set_var` call on
    /// `key`, even if the test body panics. Mirrors the `CrlBaseGuard`
    /// pattern already used in `crl::offline::sync` and `crl::gossip::store`.
    struct EnvGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(previous) => std::env::set_var(self.key, previous),
                None => std::env::remove_var(self.key),
            }
        }
    }

    fn sample_crl_entry(id: &str, revoked_did: &str, timestamp: &str) -> CrlEntry {
        CrlEntry {
            context: vec![CRL_CONTEXT_CORE.into(), CRL_CONTEXT_SGX.into()],
            id: id.to_string(),
            r#type: vec!["VerifiableCredential".into(), "RevocationCredential".into()],
            revoked_did: revoked_did.to_string(),
            device_id: None,
            user_id: None,
            circle_id: "circle-1".to_string(),
            reason: RevocationReason::Compromised,
            severity: Severity::High,
            timestamp: timestamp.to_string(),
            revoker_did: "did:guardian:owner".to_string(),
            revoker_role: RevokerRole::Owner,
            evidence: None,
            proof: Proof::default(),
            peers_notified: vec![],
            propagated: false,
        }
    }

    fn sample_tombstone(id: &str, revoked_did: &str) -> UnrevokeTombstone {
        UnrevokeTombstone {
            context: vec![CRL_CONTEXT_CORE.into(), CRL_CONTEXT_SGX.into()],
            id: id.to_string(),
            r#type: vec!["VerifiableCredential".into(), "UnrevokeTombstone".into()],
            revoked_did: revoked_did.to_string(),
            original_entry_id: "urn:uuid:orig-1".into(),
            owner_did: "did:guardian:owner".into(),
            sequence: 1,
            timestamp: "2026-01-01T00:00:00Z".into(),
            proof: Proof::default(),
            peers_notified: vec![],
            propagated: false,
        }
    }

    fn sample_peer_doc(
        did: &str,
        status: Option<&str>,
        nebula_ip_cidr: Option<&str>,
        node_name: &str,
    ) -> DidDocument {
        let mut service = Vec::new();
        if let Some(cidr) = nebula_ip_cidr {
            service.push(ServiceEndpoint {
                id: format!("{did}#sgx-mesh"),
                svc_type: "SGXNebulaMesh".into(),
                service_endpoint: format!("nebula://{cidr}"),
            });
        }
        DidDocument {
            context: vec![],
            id: did.to_string(),
            controller: did.to_string(),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            service,
            sgx_node_name: Some(node_name.to_string()),
            sgx_created: "2026-01-01T00:00:00Z".into(),
            sgx_updated: "2026-01-01T00:00:00Z".into(),
            sgx_version_id: 1,
            sgx_method_spec_version: "1.0".into(),
            sgx_status: status.map(|s| s.to_string()),
            sgx_revoked_vm: vec![],
            proof: None,
        }
    }

    fn write_peer_doc(dir: &std::path::Path, name: &str, doc: &DidDocument) {
        std::fs::write(
            dir.join(format!("did_doc_{name}.json")),
            serde_json::to_vec(doc).expect("serialize peer doc"),
        )
        .expect("write peer doc");
    }

    // --- did_record_path -----------------------------------------------

    #[test]
    fn did_record_path_defaults_when_env_unset() {
        let _lock = crate::test_support::blocking_env_lock();
        std::env::remove_var("SGX_GUARDIAN_DID_PATH");
        assert_eq!(did_record_path(), crate::did::DEFAULT_DID_PATH);
    }

    #[test]
    fn did_record_path_honors_env_override() {
        let _lock = crate::test_support::blocking_env_lock();
        let _guard = EnvGuard::set("SGX_GUARDIAN_DID_PATH", "/tmp/custom-did-path.json");
        assert_eq!(did_record_path(), "/tmp/custom-did-path.json");
    }

    // --- active_gossip_peers ---------------------------------------------

    #[test]
    fn active_gossip_peers_filters_self_inactive_revoked_and_missing_endpoint() {
        let _lock = crate::test_support::blocking_env_lock();
        let peers_dir = TempDir::new().expect("peers tempdir");
        let crl_dir = TempDir::new().expect("crl tempdir");
        let _peers_guard =
            EnvGuard::set(doc_persistence::PEERS_DOC_DIR_ENV, peers_dir.path());
        let _crl_guard = EnvGuard::set(persistence::CRL_BASE_ENV, crl_dir.path());

        let self_did = "did:guardian:self0000";
        let revoked_did = "did:guardian:revoked0000";

        write_peer_doc(
            peers_dir.path(),
            "self",
            &sample_peer_doc(self_did, Some("active"), Some("10.0.0.1/24"), "self-node"),
        );
        write_peer_doc(
            peers_dir.path(),
            "inactive",
            &sample_peer_doc(
                "did:guardian:inactive0000",
                Some("pending"),
                Some("10.0.0.2/24"),
                "inactive-node",
            ),
        );
        write_peer_doc(
            peers_dir.path(),
            "noendpoint",
            &sample_peer_doc(
                "did:guardian:noendpoint0000",
                Some("active"),
                None,
                "no-endpoint-node",
            ),
        );
        write_peer_doc(
            peers_dir.path(),
            "revoked",
            &sample_peer_doc(
                revoked_did,
                Some("active"),
                Some("10.0.0.3/24"),
                "revoked-node",
            ),
        );
        write_peer_doc(
            peers_dir.path(),
            "valid",
            &sample_peer_doc(
                "did:guardian:valid0000",
                Some("active"),
                Some("10.0.0.4/24"),
                "valid-node",
            ),
        );

        let mut crl = CertificateRevocationList::new(self_did, "circle-1");
        crl.entries.push(sample_crl_entry(
            "urn:uuid:r1",
            revoked_did,
            "2026-01-01T00:00:00Z",
        ));
        persistence::save_crl(&crl).expect("save crl");

        let peers = active_gossip_peers(self_did);

        assert_eq!(peers.len(), 1, "peers: {peers:?}");
        assert_eq!(peers[0].did, "did:guardian:valid0000");
        assert_eq!(peers[0].overlay_ip, "10.0.0.4");
        assert_eq!(peers[0].node_name, "valid-node");
    }

    #[test]
    fn active_gossip_peers_returns_empty_when_peer_dir_missing() {
        let _lock = crate::test_support::blocking_env_lock();
        let peers_dir = TempDir::new().expect("peers tempdir");
        let missing = peers_dir.path().join("does-not-exist");
        let _peers_guard = EnvGuard::set(doc_persistence::PEERS_DOC_DIR_ENV, &missing);
        let peers = active_gossip_peers("did:guardian:self0000");
        assert!(peers.is_empty());
    }

    // --- counters and last round ------------------------------------------

    static ROUND_STATE_TEST_LOCK: Lazy<std::sync::Mutex<()>> =
        Lazy::new(|| std::sync::Mutex::new(()));

    #[test]
    fn round_counters_reflect_recorded_increments() {
        let _guard = ROUND_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let before_initiated = rounds_initiated();
        let before_served = rounds_served();
        let before_merged = entries_merged_total();

        ROUNDS_INITIATED.fetch_add(1, Ordering::Relaxed);
        ROUNDS_SERVED.fetch_add(2, Ordering::Relaxed);
        ENTRIES_MERGED.fetch_add(3, Ordering::Relaxed);

        assert_eq!(rounds_initiated(), before_initiated + 1);
        assert_eq!(rounds_served(), before_served + 2);
        assert_eq!(entries_merged_total(), before_merged + 3);
    }

    #[test]
    fn record_last_round_and_last_round_roundtrip() {
        let _guard = ROUND_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let round = LastRound {
            direction: "initiated".into(),
            peer_did: "did:guardian:peer".into(),
            peer_node: "node-a".into(),
            merged: 2,
            sent: 1,
            merkle_root: "root123".into(),
            at: "2026-01-01T00:00:00Z".into(),
        };
        record_last_round(round.clone());
        let got = last_round().expect("last round recorded");
        assert_eq!(got.direction, "initiated");
        assert_eq!(got.peer_did, "did:guardian:peer");
        assert_eq!(got.merkle_root, "root123");
        assert_eq!(got.merged, 2);
        assert_eq!(got.sent, 1);
    }

    // --- audit_* helpers ----------------------------------------------------

    #[test]
    fn audit_merged_entries_handles_empty_and_typical_input_without_panicking() {
        audit_merged_entries("node-x", &[], "did:guardian:peer");
        let mut entry = sample_crl_entry(
            "urn:uuid:audit1",
            "did:guardian:target",
            "2026-01-01T00:00:00Z",
        );
        entry.severity = Severity::Critical;
        audit_merged_entries("node-x", std::slice::from_ref(&entry), "did:guardian:peer");
        entry.severity = Severity::Low;
        audit_merged_entries("node-x", std::slice::from_ref(&entry), "did:guardian:peer");
    }

    #[test]
    fn audit_merged_tombstones_handles_empty_and_typical_input_without_panicking() {
        audit_merged_tombstones("node-x", &[], "did:guardian:peer");
        let tombstone = sample_tombstone("urn:uuid:ts1", "did:guardian:target");
        audit_merged_tombstones(
            "node-x",
            std::slice::from_ref(&tombstone),
            "did:guardian:peer",
        );
    }

    #[test]
    fn audit_propagated_handles_empty_and_typical_input_without_panicking() {
        audit_propagated("node-x", &[], 2);
        audit_propagated("node-x", &["urn:uuid:e1".to_string()], 2);
    }

    #[test]
    fn audit_reject_does_not_panic() {
        audit_reject("node-x", "did:guardian:bad", "some reason");
    }

    // --- verify_batch ---------------------------------------------------

    #[tokio::test]
    async fn verify_batch_returns_empty_for_empty_input() {
        let resolver = Resolver::new(ResolverConfig::default());
        let (entries, tombstones) = verify_batch("node-x", &[], &[], &resolver, "circle-1").await;
        assert!(entries.is_empty());
        assert!(tombstones.is_empty());
    }

    #[tokio::test]
    async fn verify_batch_rejects_entry_with_circle_mismatch() {
        let resolver = Resolver::new(ResolverConfig::default());
        let entry = sample_crl_entry(
            "urn:uuid:mismatch1",
            "did:guardian:target",
            "2026-01-01T00:00:00Z",
        );
        let (entries, _) = verify_batch(
            "node-x",
            std::slice::from_ref(&entry),
            &[],
            &resolver,
            "other-circle",
        )
        .await;
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn verify_batch_rejects_tombstone_with_missing_required_fields() {
        let resolver = Resolver::new(ResolverConfig::default());
        let tombstone = sample_tombstone("urn:uuid:badts", "");
        let (_, tombstones) = verify_batch(
            "node-x",
            &[],
            std::slice::from_ref(&tombstone),
            &resolver,
            "circle-1",
        )
        .await;
        assert!(tombstones.is_empty());
    }

    // --- reject -----------------------------------------------------------

    #[tokio::test]
    async fn reject_writes_error_sync_response_to_peer() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (_read_half, mut write_half) = stream.into_split();
            reject(&mut write_half, "did:guardian:me", "circle-1", "test rejection").await;
        });

        let client = TcpStream::connect(addr).await.expect("connect loopback");
        let (read_half, _write_half) = client.into_split();
        let mut reader = BufReader::new(read_half);
        let line = protocol::read_json_line(&mut reader)
            .await
            .expect("read line");
        server.await.expect("server task");

        let response: SyncResponse = serde_json::from_str(line.trim()).expect("parse response");
        assert_eq!(response.kind, KIND_RESPONSE);
        assert_eq!(response.sender_did, "did:guardian:me");
        assert_eq!(response.circle_id, "circle-1");
        assert_eq!(response.error.as_deref(), Some("test rejection"));
        assert!(response.entries.is_empty());
        assert!(response.want.is_empty());
    }

    // --- shared identity fixture for load_identity / run_round_once /
    // exchange_with_peer / handle_inbound below -----------------------------

    /// Guards + backing tempdirs for one fully-isolated node identity
    /// (DID record + software key manager + empty peer directory + empty
    /// CRL store). Kept alive for the lifetime of the test that owns it so
    /// `Drop` restores whatever env vars preceded it.
    struct IdentityFixture {
        _tmp: TempDir,
        _did_guard: EnvGuard,
        _keys_guard: EnvGuard,
        _force_guard: EnvGuard,
        _peers_guard: EnvGuard,
        _crl_guard: EnvGuard,
        peers_dir: std::path::PathBuf,
        record: DidRecord,
        km: std::sync::Arc<KeyManager>,
        circle_id: String,
    }

    fn make_did_record(did: &str) -> DidRecord {
        DidRecord {
            did: did.to_string(),
            method: "guardian".to_string(),
            method_version: "1.0".to_string(),
            did_id_b58: format!("b58-{}", did.replace(':', "_")),
            did_id_hex: hex::encode(did.as_bytes()),
            created_at: chrono::Utc::now().to_rfc3339(),
            deactivated_at: None,
            derivation: crate::did::persistence::DerivationProof {
                se050_uid: "se050-test-uid".to_string(),
                se050_uid_source: "test".to_string(),
                dkp_v1_pubkey_sha256_b16: "00".repeat(32),
                dkp_v1_pubkey_path: "device.key".to_string(),
                dkp_v1_pubkey_der_b64: None,
                dik_pubkey_sha256_b16: "11".repeat(32),
                dik_pubkey_der_b64: None,
            },
            current_dkp_version: 1,
            deriv_signature_b64: "signature".to_string(),
        }
    }

    /// Builds one isolated identity (own tempdir for DID record, software
    /// keys, peer directory and CRL store) and eagerly runs `load_identity`
    /// so callers get back the exact `(record, km, circle_id)` the
    /// module-under-test will also resolve (same env vars, same node_id).
    fn setup_identity_fixture(node_id: &str, local_did: &str) -> IdentityFixture {
        let tmp = TempDir::new().expect("tempdir");
        let did_path = tmp.path().join("did.json");
        let key_dir = tmp.path().join("keys");
        let peers_dir = tmp.path().join("peers");
        let crl_dir = tmp.path().join("crl");
        std::fs::create_dir_all(&peers_dir).expect("peers dir");
        std::fs::create_dir_all(&crl_dir).expect("crl dir");

        let did_record = make_did_record(local_did);
        did_record
            .save(did_path.to_str().expect("utf8 did path"))
            .expect("save did record");

        let did_guard = EnvGuard::set("SGX_GUARDIAN_DID_PATH", &did_path);
        let keys_guard = EnvGuard::set(crate::vc::issue::DEVICE_KEY_DIR_ENV, &key_dir);
        let force_guard = EnvGuard::set("SGX_FORCE_SOFTWARE_KEYS", "1");
        let peers_guard = EnvGuard::set(doc_persistence::PEERS_DOC_DIR_ENV, &peers_dir);
        let crl_guard = EnvGuard::set(persistence::CRL_BASE_ENV, &crl_dir);

        let (record, km, circle_id) = load_identity(node_id).expect("identity must load");

        IdentityFixture {
            _tmp: tmp,
            _did_guard: did_guard,
            _keys_guard: keys_guard,
            _force_guard: force_guard,
            _peers_guard: peers_guard,
            _crl_guard: crl_guard,
            peers_dir,
            record,
            km,
            circle_id,
        }
    }

    fn sample_gossip_config(port: u16, threshold_pct: u8) -> GossipConfig {
        GossipConfig {
            enabled: true,
            port,
            interval_secs: 60,
            threshold_pct,
            emergency_enabled: false,
            emergency_port: 0,
            emergency_ttl: 1,
        }
    }

    fn sample_sync_request(circle_id: &str, sender_did: &str) -> SyncRequest {
        SyncRequest {
            kind: KIND_REQUEST.to_string(),
            circle_id: circle_id.to_string(),
            sender_did: sender_did.to_string(),
            sequence: 0,
            merkle_root: String::new(),
            fingerprints: Vec::new(),
        }
    }

    fn base_sync_response(circle_id: &str, sender_did: &str) -> SyncResponse {
        SyncResponse {
            kind: KIND_RESPONSE.to_string(),
            circle_id: circle_id.to_string(),
            sender_did: sender_did.to_string(),
            sequence: 0,
            merkle_root: String::new(),
            entries: Vec::new(),
            tombstones: Vec::new(),
            want: Vec::new(),
            error: None,
        }
    }

    // --- load_identity ------------------------------------------------------

    #[test]
    fn load_identity_succeeds_with_fixture_record_and_software_keys() {
        let _lock = crate::test_support::blocking_env_lock();
        let tmp = TempDir::new().expect("tempdir");
        let did_path = tmp.path().join("did.json");
        let key_dir = tmp.path().join("keys");

        let record = make_did_record("did:guardian:engineload0000");
        record
            .save(did_path.to_str().expect("utf8 path"))
            .expect("save did record");

        let _did_guard = EnvGuard::set("SGX_GUARDIAN_DID_PATH", &did_path);
        let _keys_guard = EnvGuard::set(crate::vc::issue::DEVICE_KEY_DIR_ENV, &key_dir);
        let _force_guard = EnvGuard::set("SGX_FORCE_SOFTWARE_KEYS", "1");

        let result = load_identity("engine-load-identity-ok");
        assert!(result.is_ok(), "expected Ok, got {:?}", result.err());
        let (loaded, _km, circle_id) = result.expect("identity loaded");
        assert_eq!(loaded.did, "did:guardian:engineload0000");
        assert!(!circle_id.is_empty());
    }

    #[test]
    fn load_identity_fails_when_did_record_missing() {
        let _lock = crate::test_support::blocking_env_lock();
        let tmp = TempDir::new().expect("tempdir");
        let missing_path = tmp.path().join("does-not-exist.json");
        let _did_guard = EnvGuard::set("SGX_GUARDIAN_DID_PATH", &missing_path);

        let result = load_identity("engine-load-identity-missing");
        match result {
            Ok(_) => panic!("missing did record must fail"),
            Err(error) => assert!(error.contains("did record"), "unexpected error: {error}"),
        }
    }

    // --- active_gossip_peers (error branch) ---------------------------------

    #[test]
    fn active_gossip_peers_returns_empty_when_peer_dir_is_not_a_directory() {
        let _lock = crate::test_support::blocking_env_lock();
        let tmp = TempDir::new().expect("tempdir");
        let not_a_dir = tmp.path().join("peers-is-a-file");
        std::fs::write(&not_a_dir, b"not a directory").expect("write file");
        let _peers_guard = EnvGuard::set(doc_persistence::PEERS_DOC_DIR_ENV, &not_a_dir);

        let peers = active_gossip_peers("did:guardian:self0000");
        assert!(peers.is_empty());
    }

    // --- run_round_once -------------------------------------------------

    #[tokio::test]
    async fn run_round_once_fails_when_identity_missing() {
        let _lock = crate::test_support::async_env_lock().await;
        let tmp = TempDir::new().expect("tempdir");
        let missing_path = tmp.path().join("no-did.json");
        let _did_guard = EnvGuard::set("SGX_GUARDIAN_DID_PATH", &missing_path);
        let resolver = Resolver::new(ResolverConfig::default());
        let config = sample_gossip_config(0, 80);

        let result = run_round_once("engine-round-missing-identity", &resolver, &config).await;
        match result {
            Ok(_) => panic!("expected error"),
            Err(error) => assert!(error.contains("did record"), "unexpected error: {error}"),
        }
    }

    #[tokio::test]
    async fn run_round_once_fails_when_no_active_peers() {
        let _lock = crate::test_support::async_env_lock().await;
        let _fx = setup_identity_fixture(
            "engine-round-nopeers",
            "did:guardian:round-local-nopeers0000",
        );
        let resolver = Resolver::new(ResolverConfig::default());
        let config = sample_gossip_config(0, 80);

        let result = run_round_once("engine-round-nopeers", &resolver, &config).await;
        match result {
            Ok(_) => panic!("expected error"),
            Err(error) => assert!(
                error.contains("no active gossip peers"),
                "unexpected error: {error}"
            ),
        }
    }

    #[tokio::test]
    async fn run_round_once_fails_when_chosen_peer_is_unreachable() {
        let _lock = crate::test_support::async_env_lock().await;
        let fx = setup_identity_fixture(
            "engine-round-unreachable",
            "did:guardian:round-local-unreachable0000",
        );
        // Bind then immediately drop: reserves a free loopback port that
        // nothing is listening on, so the connect below fails fast instead
        // of relying on an arbitrary hard-coded port.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);

        write_peer_doc(
            &fx.peers_dir,
            "peer",
            &sample_peer_doc(
                "did:guardian:round-peer-unreachable0000",
                Some("active"),
                Some(&format!("{}/24", addr.ip())),
                "peer-node",
            ),
        );

        let resolver = Resolver::new(ResolverConfig::default());
        let config = sample_gossip_config(addr.port(), 80);

        let result = run_round_once("engine-round-unreachable", &resolver, &config).await;
        match result {
            Ok(_) => panic!("expected error"),
            Err(error) => assert!(
                error.contains("connect") || error.contains("timeout"),
                "unexpected error: {error}"
            ),
        }
    }

    // --- exchange_with_peer (client side, scripted loopback peer) ----------

    #[tokio::test]
    async fn exchange_with_peer_fails_when_peer_unreachable() {
        let _lock = crate::test_support::async_env_lock().await;
        let fx = setup_identity_fixture(
            "engine-exchange-unreachable",
            "did:guardian:exchange-local-unreachable0000",
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);

        let resolver = Resolver::new(ResolverConfig::default());
        let config = sample_gossip_config(addr.port(), 80);
        let peer = GossipPeer {
            did: "did:guardian:peer-unreachable0000".to_string(),
            node_name: "peer-node".to_string(),
            overlay_ip: addr.ip().to_string(),
        };

        let result = exchange_with_peer(
            "engine-exchange-unreachable",
            &fx.record,
            fx.km.as_ref(),
            &fx.circle_id,
            &resolver,
            &config,
            &peer,
            1,
        )
        .await;
        match result {
            Ok(_) => panic!("expected error"),
            Err(error) => assert!(error.contains("connect"), "unexpected error: {error}"),
        }
    }

    #[tokio::test]
    async fn exchange_with_peer_fails_when_peer_response_has_error() {
        let _lock = crate::test_support::async_env_lock().await;
        let fx = setup_identity_fixture(
            "engine-exchange-resperr",
            "did:guardian:exchange-local-resperr0000",
        );
        let resolver = Resolver::new(ResolverConfig::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let config = sample_gossip_config(addr.port(), 80);

        let peer_did = "did:guardian:peer-resperr0000".to_string();
        let peer_did_for_server = peer_did.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            let _request_line = protocol::read_json_line(&mut reader)
                .await
                .expect("read request");
            let mut response = base_sync_response("circle-irrelevant", &peer_did_for_server);
            response.error = Some("peer says no".to_string());
            protocol::write_json_line(&mut write_half, &response)
                .await
                .expect("write response");
        });

        let peer = GossipPeer {
            did: peer_did,
            node_name: "peer-node".to_string(),
            overlay_ip: addr.ip().to_string(),
        };
        let result = exchange_with_peer(
            "engine-exchange-resperr",
            &fx.record,
            fx.km.as_ref(),
            &fx.circle_id,
            &resolver,
            &config,
            &peer,
            1,
        )
        .await;
        server.await.expect("server task joined");
        match result {
            Ok(_) => panic!("expected error"),
            Err(error) => assert!(
                error.contains("rejected exchange"),
                "unexpected error: {error}"
            ),
        }
    }

    #[tokio::test]
    async fn exchange_with_peer_fails_on_unexpected_response_kind() {
        let _lock = crate::test_support::async_env_lock().await;
        let fx = setup_identity_fixture(
            "engine-exchange-badkind",
            "did:guardian:exchange-local-badkind0000",
        );
        let resolver = Resolver::new(ResolverConfig::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let config = sample_gossip_config(addr.port(), 80);

        let peer_did = "did:guardian:peer-badkind0000".to_string();
        let peer_did_for_server = peer_did.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            let _request_line = protocol::read_json_line(&mut reader)
                .await
                .expect("read request");
            let mut response = base_sync_response("circle-irrelevant", &peer_did_for_server);
            response.kind = "bogus-kind".to_string();
            protocol::write_json_line(&mut write_half, &response)
                .await
                .expect("write response");
        });

        let peer = GossipPeer {
            did: peer_did,
            node_name: "peer-node".to_string(),
            overlay_ip: addr.ip().to_string(),
        };
        let result = exchange_with_peer(
            "engine-exchange-badkind",
            &fx.record,
            fx.km.as_ref(),
            &fx.circle_id,
            &resolver,
            &config,
            &peer,
            1,
        )
        .await;
        server.await.expect("server task joined");
        match result {
            Ok(_) => panic!("expected error"),
            Err(error) => assert!(
                error.contains("unexpected message kind"),
                "unexpected error: {error}"
            ),
        }
    }

    #[tokio::test]
    async fn exchange_with_peer_fails_on_circle_mismatch() {
        let _lock = crate::test_support::async_env_lock().await;
        let fx = setup_identity_fixture(
            "engine-exchange-circle",
            "did:guardian:exchange-local-circle0000",
        );
        let resolver = Resolver::new(ResolverConfig::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let config = sample_gossip_config(addr.port(), 80);

        let peer_did = "did:guardian:peer-circle0000".to_string();
        let peer_did_for_server = peer_did.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            let _request_line = protocol::read_json_line(&mut reader)
                .await
                .expect("read request");
            let response = base_sync_response("a-different-circle", &peer_did_for_server);
            protocol::write_json_line(&mut write_half, &response)
                .await
                .expect("write response");
        });

        let peer = GossipPeer {
            did: peer_did,
            node_name: "peer-node".to_string(),
            overlay_ip: addr.ip().to_string(),
        };
        let result = exchange_with_peer(
            "engine-exchange-circle",
            &fx.record,
            fx.km.as_ref(),
            &fx.circle_id,
            &resolver,
            &config,
            &peer,
            1,
        )
        .await;
        server.await.expect("server task joined");
        match result {
            Ok(_) => panic!("expected error"),
            Err(error) => assert!(
                error.contains("circle mismatch"),
                "unexpected error: {error}"
            ),
        }
    }

    #[tokio::test]
    async fn exchange_with_peer_fails_on_sender_identity_mismatch() {
        let _lock = crate::test_support::async_env_lock().await;
        let fx = setup_identity_fixture(
            "engine-exchange-identity",
            "did:guardian:exchange-local-identity0000",
        );
        let resolver = Resolver::new(ResolverConfig::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let config = sample_gossip_config(addr.port(), 80);

        let peer_did = "did:guardian:peer-identity0000".to_string();
        let circle_id_for_server = fx.circle_id.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            let _request_line = protocol::read_json_line(&mut reader)
                .await
                .expect("read request");
            // Announces a different DID than the directory entry for this peer.
            let response =
                base_sync_response(&circle_id_for_server, "did:guardian:someone-else0000");
            protocol::write_json_line(&mut write_half, &response)
                .await
                .expect("write response");
        });

        let peer = GossipPeer {
            did: peer_did,
            node_name: "peer-node".to_string(),
            overlay_ip: addr.ip().to_string(),
        };
        let result = exchange_with_peer(
            "engine-exchange-identity",
            &fx.record,
            fx.km.as_ref(),
            &fx.circle_id,
            &resolver,
            &config,
            &peer,
            1,
        )
        .await;
        server.await.expect("server task joined");
        match result {
            Ok(_) => panic!("expected error"),
            Err(error) => assert!(
                error.contains("peer identity mismatch"),
                "unexpected error: {error}"
            ),
        }
    }

    #[tokio::test]
    async fn exchange_with_peer_fails_when_ack_has_error() {
        let _lock = crate::test_support::async_env_lock().await;
        let fx = setup_identity_fixture(
            "engine-exchange-ackerr",
            "did:guardian:exchange-local-ackerr0000",
        );
        let resolver = Resolver::new(ResolverConfig::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let config = sample_gossip_config(addr.port(), 80);

        let peer_did = "did:guardian:peer-ackerr0000".to_string();
        let peer_did_for_server = peer_did.clone();
        let circle_id_for_server = fx.circle_id.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            let _request_line = protocol::read_json_line(&mut reader)
                .await
                .expect("read request");
            let response = base_sync_response(&circle_id_for_server, &peer_did_for_server);
            protocol::write_json_line(&mut write_half, &response)
                .await
                .expect("write response");

            let _push_line = protocol::read_json_line(&mut reader)
                .await
                .expect("read push");
            let ack = SyncAck {
                kind: KIND_ACK.to_string(),
                merged: 0,
                merkle_root: String::new(),
                error: Some("peer failed to merge".to_string()),
            };
            protocol::write_json_line(&mut write_half, &ack)
                .await
                .expect("write ack");
        });

        let peer = GossipPeer {
            did: peer_did,
            node_name: "peer-node".to_string(),
            overlay_ip: addr.ip().to_string(),
        };
        let result = exchange_with_peer(
            "engine-exchange-ackerr",
            &fx.record,
            fx.km.as_ref(),
            &fx.circle_id,
            &resolver,
            &config,
            &peer,
            1,
        )
        .await;
        server.await.expect("server task joined");
        match result {
            Ok(_) => panic!("expected error"),
            Err(error) => assert!(
                error.contains("failed to merge push"),
                "unexpected error: {error}"
            ),
        }
    }

    #[tokio::test]
    async fn exchange_with_peer_succeeds_full_round_trip() {
        let _lock = crate::test_support::async_env_lock().await;
        let fx = setup_identity_fixture(
            "engine-exchange-happy",
            "did:guardian:exchange-local-happy0000",
        );
        let resolver = Resolver::new(ResolverConfig::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let config = sample_gossip_config(addr.port(), 80);

        let peer_did = "did:guardian:peer-happy0000".to_string();
        let peer_did_for_server = peer_did.clone();
        let circle_id_for_server = fx.circle_id.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            let request_line = protocol::read_json_line(&mut reader)
                .await
                .expect("read request");
            let request: SyncRequest =
                serde_json::from_str(request_line.trim()).expect("parse request");
            assert_eq!(request.kind, KIND_REQUEST);

            let response = base_sync_response(&circle_id_for_server, &peer_did_for_server);
            protocol::write_json_line(&mut write_half, &response)
                .await
                .expect("write response");

            let push_line = protocol::read_json_line(&mut reader)
                .await
                .expect("read push");
            let push: SyncPush = serde_json::from_str(push_line.trim()).expect("parse push");
            assert_eq!(push.kind, KIND_PUSH);
            assert!(push.entries.is_empty());
            assert!(push.tombstones.is_empty());

            let ack = SyncAck {
                kind: KIND_ACK.to_string(),
                merged: 0,
                merkle_root: "peer-root".to_string(),
                error: None,
            };
            protocol::write_json_line(&mut write_half, &ack)
                .await
                .expect("write ack");
        });

        let peer = GossipPeer {
            did: peer_did.clone(),
            node_name: "peer-happy-node".to_string(),
            overlay_ip: addr.ip().to_string(),
        };
        let result = exchange_with_peer(
            "engine-exchange-happy",
            &fx.record,
            fx.km.as_ref(),
            &fx.circle_id,
            &resolver,
            &config,
            &peer,
            1,
        )
        .await;
        server.await.expect("server task joined");

        let report = result.expect("exchange should succeed");
        assert_eq!(report.peer_did, peer_did);
        assert_eq!(report.peer_node, "peer-happy-node");
        assert_eq!(report.merged, 0);
        assert_eq!(report.replaced, 0);
        assert_eq!(report.pushed, 0);
        assert_eq!(report.peer_merged, 0);
        assert!(report.newly_propagated.is_empty());
    }

    // --- handle_inbound (server side, raw loopback client) ------------------

    #[tokio::test]
    async fn handle_inbound_rejects_wrong_message_kind() {
        let _lock = crate::test_support::async_env_lock().await;
        let fx = setup_identity_fixture(
            "engine-inbound-kind",
            "did:guardian:inbound-local-kind0000",
        );
        let resolver = Resolver::new(ResolverConfig::default());
        let config = sample_gossip_config(0, 80);

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let node_id = "engine-inbound-kind".to_string();
        let resolver_s = resolver.clone();
        let config_s = config.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            handle_inbound(stream, &node_id, &resolver_s, &config_s).await
        });

        let client = TcpStream::connect(addr).await.expect("connect");
        let (read_half, mut write_half) = client.into_split();
        let mut reader = BufReader::new(read_half);

        let mut request = sample_sync_request(&fx.circle_id, "did:guardian:whoever0000");
        request.kind = "bogus-kind".to_string();
        protocol::write_json_line(&mut write_half, &request)
            .await
            .expect("write request");

        let line = protocol::read_json_line(&mut reader)
            .await
            .expect("read response");
        let response: SyncResponse = serde_json::from_str(line.trim()).expect("parse response");
        assert!(response
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("unexpected message kind"));

        let result = server.await.expect("server task joined");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handle_inbound_rejects_circle_mismatch() {
        let _lock = crate::test_support::async_env_lock().await;
        let fx = setup_identity_fixture(
            "engine-inbound-circle",
            "did:guardian:inbound-local-circle0000",
        );
        let resolver = Resolver::new(ResolverConfig::default());
        let config = sample_gossip_config(0, 80);

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let node_id = "engine-inbound-circle".to_string();
        let resolver_s = resolver.clone();
        let config_s = config.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            handle_inbound(stream, &node_id, &resolver_s, &config_s).await
        });

        let client = TcpStream::connect(addr).await.expect("connect");
        let (read_half, mut write_half) = client.into_split();
        let mut reader = BufReader::new(read_half);

        let request = sample_sync_request("a-different-circle", "did:guardian:whoever0000");
        protocol::write_json_line(&mut write_half, &request)
            .await
            .expect("write request");

        let line = protocol::read_json_line(&mut reader)
            .await
            .expect("read response");
        let response: SyncResponse = serde_json::from_str(line.trim()).expect("parse response");
        assert!(response
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("circle mismatch"));

        let result = server.await.expect("server task joined");
        assert!(result.is_err());
        let _ = fx;
    }

    #[tokio::test]
    async fn handle_inbound_rejects_sender_equal_to_local_did() {
        let _lock = crate::test_support::async_env_lock().await;
        let fx = setup_identity_fixture(
            "engine-inbound-self",
            "did:guardian:inbound-local-self0000",
        );
        let resolver = Resolver::new(ResolverConfig::default());
        let config = sample_gossip_config(0, 80);

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let node_id = "engine-inbound-self".to_string();
        let resolver_s = resolver.clone();
        let config_s = config.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            handle_inbound(stream, &node_id, &resolver_s, &config_s).await
        });

        let client = TcpStream::connect(addr).await.expect("connect");
        let (read_half, mut write_half) = client.into_split();
        let mut reader = BufReader::new(read_half);

        let request = sample_sync_request(&fx.circle_id, &fx.record.did);
        protocol::write_json_line(&mut write_half, &request)
            .await
            .expect("write request");

        let line = protocol::read_json_line(&mut reader)
            .await
            .expect("read response");
        let response: SyncResponse = serde_json::from_str(line.trim()).expect("parse response");
        assert!(response
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("sender_did equals local DID"));

        let result = server.await.expect("server task joined");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handle_inbound_rejects_revoked_sender() {
        let _lock = crate::test_support::async_env_lock().await;
        let fx = setup_identity_fixture(
            "engine-inbound-revoked",
            "did:guardian:inbound-local-revoked0000",
        );
        let sender_did = "did:guardian:inbound-sender-revoked0000";
        let mut crl = CertificateRevocationList::new(&fx.record.did, &fx.circle_id);
        crl.entries.push(sample_crl_entry(
            "urn:uuid:inbound-revoked-sender",
            sender_did,
            "2026-01-01T00:00:00Z",
        ));
        persistence::save_crl(&crl).expect("save crl");

        let resolver = Resolver::new(ResolverConfig::default());
        let config = sample_gossip_config(0, 80);

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let node_id = "engine-inbound-revoked".to_string();
        let resolver_s = resolver.clone();
        let config_s = config.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            handle_inbound(stream, &node_id, &resolver_s, &config_s).await
        });

        let client = TcpStream::connect(addr).await.expect("connect");
        let (read_half, mut write_half) = client.into_split();
        let mut reader = BufReader::new(read_half);

        let request = sample_sync_request(&fx.circle_id, sender_did);
        protocol::write_json_line(&mut write_half, &request)
            .await
            .expect("write request");

        let line = protocol::read_json_line(&mut reader)
            .await
            .expect("read response");
        let response: SyncResponse = serde_json::from_str(line.trim()).expect("parse response");
        assert!(response
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("sender is revoked"));

        let result = server.await.expect("server task joined");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handle_inbound_rejects_sender_not_in_peer_directory() {
        let _lock = crate::test_support::async_env_lock().await;
        let fx = setup_identity_fixture(
            "engine-inbound-unknown",
            "did:guardian:inbound-local-unknown0000",
        );
        let resolver = Resolver::new(ResolverConfig::default());
        let config = sample_gossip_config(0, 80);

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let node_id = "engine-inbound-unknown".to_string();
        let resolver_s = resolver.clone();
        let config_s = config.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            handle_inbound(stream, &node_id, &resolver_s, &config_s).await
        });

        let client = TcpStream::connect(addr).await.expect("connect");
        let (read_half, mut write_half) = client.into_split();
        let mut reader = BufReader::new(read_half);

        let request = sample_sync_request(&fx.circle_id, "did:guardian:inbound-sender-unknown0000");
        protocol::write_json_line(&mut write_half, &request)
            .await
            .expect("write request");

        let line = protocol::read_json_line(&mut reader)
            .await
            .expect("read response");
        let response: SyncResponse = serde_json::from_str(line.trim()).expect("parse response");
        assert!(response
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("sender not in local peer directory"));

        let result = server.await.expect("server task joined");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handle_inbound_rejects_push_with_wrong_kind() {
        let _lock = crate::test_support::async_env_lock().await;
        let fx = setup_identity_fixture(
            "engine-inbound-pushkind",
            "did:guardian:inbound-local-pushkind0000",
        );
        let sender_did = "did:guardian:inbound-sender-pushkind0000";
        write_peer_doc(
            &fx.peers_dir,
            "sender",
            &sample_peer_doc(sender_did, Some("active"), Some("10.0.0.51/24"), "sender-node"),
        );

        let resolver = Resolver::new(ResolverConfig::default());
        let config = sample_gossip_config(0, 80);

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let node_id = "engine-inbound-pushkind".to_string();
        let resolver_s = resolver.clone();
        let config_s = config.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            handle_inbound(stream, &node_id, &resolver_s, &config_s).await
        });

        let client = TcpStream::connect(addr).await.expect("connect");
        let (read_half, mut write_half) = client.into_split();
        let mut reader = BufReader::new(read_half);

        let request = sample_sync_request(&fx.circle_id, sender_did);
        protocol::write_json_line(&mut write_half, &request)
            .await
            .expect("write request");
        let line = protocol::read_json_line(&mut reader)
            .await
            .expect("read response");
        let response: SyncResponse = serde_json::from_str(line.trim()).expect("parse response");
        assert!(response.error.is_none());

        let push = SyncPush {
            kind: "bogus-push-kind".to_string(),
            entries: Vec::new(),
            tombstones: Vec::new(),
        };
        protocol::write_json_line(&mut write_half, &push)
            .await
            .expect("write push");

        let result = server.await.expect("server task joined");
        match result {
            Ok(_) => panic!("expected error"),
            Err(error) => assert!(
                error.contains("unexpected message kind"),
                "unexpected error: {error}"
            ),
        }
    }

    #[tokio::test]
    async fn handle_inbound_succeeds_full_round_trip() {
        let _lock = crate::test_support::async_env_lock().await;
        let fx = setup_identity_fixture(
            "engine-inbound-happy",
            "did:guardian:inbound-local-happy0000",
        );
        let sender_did = "did:guardian:inbound-sender-happy0000";
        write_peer_doc(
            &fx.peers_dir,
            "sender",
            &sample_peer_doc(sender_did, Some("active"), Some("10.0.0.52/24"), "sender-node"),
        );

        let resolver = Resolver::new(ResolverConfig::default());
        let config = sample_gossip_config(0, 80);

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let node_id = "engine-inbound-happy".to_string();
        let resolver_s = resolver.clone();
        let config_s = config.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            handle_inbound(stream, &node_id, &resolver_s, &config_s).await
        });

        let client = TcpStream::connect(addr).await.expect("connect");
        let (read_half, mut write_half) = client.into_split();
        let mut reader = BufReader::new(read_half);

        let request = sample_sync_request(&fx.circle_id, sender_did);
        protocol::write_json_line(&mut write_half, &request)
            .await
            .expect("write request");

        let line = protocol::read_json_line(&mut reader)
            .await
            .expect("read response");
        let response: SyncResponse = serde_json::from_str(line.trim()).expect("parse response");
        assert_eq!(response.kind, KIND_RESPONSE);
        assert!(response.error.is_none());
        assert!(response.entries.is_empty());
        assert!(response.want.is_empty());

        let push = SyncPush {
            kind: KIND_PUSH.to_string(),
            entries: Vec::new(),
            tombstones: Vec::new(),
        };
        protocol::write_json_line(&mut write_half, &push)
            .await
            .expect("write push");

        let ack_line = protocol::read_json_line(&mut reader)
            .await
            .expect("read ack");
        let ack: SyncAck = serde_json::from_str(ack_line.trim()).expect("parse ack");
        assert_eq!(ack.kind, KIND_ACK);
        assert!(ack.error.is_none());
        assert_eq!(ack.merged, 0);

        let result = server.await.expect("server task joined");
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[tokio::test]
    async fn listener_task_logs_and_returns_when_the_bind_port_is_already_taken() {
        // Occupy a real ephemeral TCP port first so the listener's own bind
        // to that exact port fails deterministically (EADDRINUSE).
        let holder = TcpListener::bind("127.0.0.1:0").await.expect("bind holder");
        let port = holder.local_addr().expect("addr").port();
        let config = sample_gossip_config(port, 80);
        let resolver = Resolver::new(ResolverConfig::default());

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            listener_task("listener-bind-fail".to_string(), resolver, config),
        )
        .await;
        assert!(
            result.is_ok(),
            "listener_task must return promptly on a bind failure, not hang"
        );
        drop(holder);
    }
}
