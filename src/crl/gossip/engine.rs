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
