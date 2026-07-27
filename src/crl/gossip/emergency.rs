//! Priority emergency broadcast channel for CRITICAL revocations
//! (Sprint 7 — "Emergency Revocation", CRL-series).
//!
//! Routine gossip (`50063`, pull, one random peer per interval) is the
//! eventual-consistency backstop. THIS module is the fast path: the moment
//! a `severity: critical` revocation is issued locally, we push a signed
//! `REVOCATION_NOTICE` datagram to EVERY active peer at once over UDP `50064`,
//! bypassing gossip intervals. Receivers re-verify + merge through the SAME
//! locked CRL path as gossip, terminate sessions with the revoked DID,
//! record a user-facing notification, then re-broadcast once (bounded TTL
//! flood) before their own routine gossip. UDP loss is self-healed by the
//! routine anti-entropy layer, so no ACK machinery is needed for
//! correctness — only speed.

use super::store;
use super::GossipConfig;
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::crl::entry::{CrlEntry, Severity};
use crate::did::{DidRecord, Resolver};
use crate::key_manager::KeyManager;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::net::UdpSocket;

/// Hard cap on a single emergency datagram (abuse guard). A signed `CrlEntry`
/// is ~1–2 KB; 16 KB leaves generous headroom while bounding memory.
pub const MAX_DATAGRAM_BYTES: usize = 16_384;
/// Bounded dedup memory: remember the last N notice fingerprints seen.
pub const SEEN_CAPACITY: usize = 4096;
pub const IO_TIMEOUT_SECS: u64 = 5;
pub const KIND_NOTICE: &str = "crl_revocation_notice";

// Runtime observability (read by GET /crl/emergency/status)
static NOTICES_SENT: AtomicU64 = AtomicU64::new(0);
static NOTICES_RECEIVED: AtomicU64 = AtomicU64::new(0);
static NOTICES_MERGED: AtomicU64 = AtomicU64::new(0);
static NOTICES_REBROADCAST: AtomicU64 = AtomicU64::new(0);
static SESSIONS_TERMINATED: AtomicU64 = AtomicU64::new(0);
static LAST_NOTICE: Lazy<RwLock<Option<LastNotice>>> = Lazy::new(|| RwLock::new(None));

#[derive(Debug, Clone, Serialize)]
pub struct LastNotice {
    pub direction: String,
    pub revoked_did: String,
    pub origin_did: String,
    pub peers: usize,
    pub merged: bool,
    pub at: String,
}

pub fn notices_sent() -> u64 {
    NOTICES_SENT.load(Ordering::Relaxed)
}

pub fn notices_received() -> u64 {
    NOTICES_RECEIVED.load(Ordering::Relaxed)
}

pub fn notices_merged() -> u64 {
    NOTICES_MERGED.load(Ordering::Relaxed)
}

pub fn notices_rebroadcast() -> u64 {
    NOTICES_REBROADCAST.load(Ordering::Relaxed)
}

pub fn sessions_terminated_total() -> u64 {
    SESSIONS_TERMINATED.load(Ordering::Relaxed)
}

pub fn last_notice() -> Option<LastNotice> {
    LAST_NOTICE.read().ok().and_then(|guard| guard.clone())
}

fn record_last(notice: LastNotice) {
    if let Ok(mut guard) = LAST_NOTICE.write() {
        *guard = Some(notice);
    }
}

// Bounded dedup seen-set (fingerprint of already-processed notices)
static SEEN: Lazy<Mutex<SeenSet>> = Lazy::new(|| Mutex::new(SeenSet::default()));

#[derive(Default)]
struct SeenSet {
    set: HashSet<String>,
    order: VecDeque<String>,
}

impl SeenSet {
    /// Returns true if `fingerprint` is new (and records it); false if already seen.
    fn insert_new(&mut self, fingerprint: &str) -> bool {
        if self.set.contains(fingerprint) {
            return false;
        }
        if self.order.len() >= SEEN_CAPACITY {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        self.set.insert(fingerprint.to_string());
        self.order.push_back(fingerprint.to_string());
        true
    }
}

fn seen_is_new(fingerprint: &str) -> bool {
    SEEN.lock()
        .map(|mut seen| seen.insert_new(fingerprint))
        .unwrap_or(true)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationNotice {
    pub kind: String,
    pub circle_id: String,
    /// The node that first broadcast this notice (advisory; entry proof is
    /// the real trust anchor).
    pub origin_did: String,
    pub notice_id: String,
    /// Re-broadcast hops remaining. 0 = do not relay further.
    pub ttl: u8,
    pub sent_at: String,
    /// Full signed CRL entry — re-verified on receipt.
    pub entry: CrlEntry,
}

fn load_identity(node_id: &str) -> Result<(DidRecord, Arc<KeyManager>, String), String> {
    let record = DidRecord::load(&super::engine::did_record_path())
        .map_err(|error| format!("did record: {error}"))?;
    let km = crate::vc::issue::load_runtime_key_manager(node_id)
        .map_err(|error| format!("key manager: {error}"))?;
    let circle_id = crate::crl::issue::current_circle_id()
        .unwrap_or_else(|_| crate::crl::issue::DEFAULT_CIRCLE_ID.to_string());
    Ok((record, km, circle_id))
}

/// Fire-and-forget: broadcast a signed `REVOCATION_NOTICE` for `entry` to every
/// active peer over UDP `port`. Only meaningful for critical entries; callers
/// gate on severity, but we double-check here for safety. Never blocks the
/// caller (spawns), never panics.
pub fn broadcast_for_entry(node_id: String, entry: CrlEntry) {
    let config = GossipConfig::from_env();
    if !config.emergency_enabled {
        return;
    }
    if !matches!(entry.severity, Severity::Critical) {
        return;
    }
    tokio::spawn(async move {
        if let Err(reason) = broadcast_once(&node_id, &entry, &config).await {
            tracing::warn!("emergency broadcast failed: {}", reason);
        }
    });
}

async fn broadcast_once(
    node_id: &str,
    entry: &CrlEntry,
    config: &GossipConfig,
) -> Result<(), String> {
    let (record, _km, circle_id) = load_identity(node_id)?;
    let peers = super::engine::active_gossip_peers(&record.did);
    if peers.is_empty() {
        return Err("no active peers to emergency-broadcast to".into());
    }
    let notice = RevocationNotice {
        kind: KIND_NOTICE.to_string(),
        circle_id,
        origin_did: record.did.clone(),
        notice_id: uuid::Uuid::new_v4().to_string(),
        ttl: config.emergency_ttl,
        sent_at: chrono::Utc::now().to_rfc3339(),
        entry: entry.clone(),
    };
    // Mark our own notice as seen so an inbound echo is a no-op.
    seen_is_new(&entry.fingerprint());
    let bytes = serde_json::to_vec(&notice).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_DATAGRAM_BYTES {
        let notice_len = bytes.len();
        return Err(format!("notice {notice_len} bytes exceeds cap"));
    }
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|error| format!("bind ephemeral: {error}"))?;
    let mut sent = 0usize;
    for peer in &peers {
        let addr = format!("{}:{}", peer.overlay_ip, config.emergency_port);
        match tokio::time::timeout(
            Duration::from_secs(IO_TIMEOUT_SECS),
            socket.send_to(&bytes, &addr),
        )
        .await
        {
            Ok(Ok(_)) => sent += 1,
            Ok(Err(error)) => tracing::warn!("emergency send to {} failed: {}", addr, error),
            Err(_) => tracing::warn!("emergency send to {} timed out", addr),
        }
    }
    NOTICES_SENT.fetch_add(1, Ordering::Relaxed);
    record_last(LastNotice {
        direction: "sent".into(),
        revoked_did: entry.revoked_did.clone(),
        origin_did: record.did.clone(),
        peers: sent,
        merged: true,
        at: chrono::Utc::now().to_rfc3339(),
    });
    log_audit(
        node_id,
        AuditCategory::Crl,
        AuditSeverity::Critical,
        AuditAction::Started,
        &format!(
            "EMERGENCY revocation broadcast revoked_did={} peers={} notice_id={}",
            entry.revoked_did, sent, notice.notice_id
        ),
    );
    println!(
        "🚨 EMERGENCY broadcast revoked_did={} → {} peers",
        entry.revoked_did, sent
    );
    Ok(())
}

pub async fn listener_task(node_id: String, resolver: Resolver, config: GossipConfig) {
    let addr = format!("0.0.0.0:{}", config.emergency_port);
    let socket = match UdpSocket::bind(&addr).await {
        Ok(socket) => {
            println!("🚨 CRL-EMERGENCY listener on {addr}");
            socket
        }
        Err(error) => {
            eprintln!("❌ CRL-EMERGENCY bind failed on {addr}: {error}");
            log_audit(
                &node_id,
                AuditCategory::Crl,
                AuditSeverity::Critical,
                AuditAction::Failed,
                &format!("CRL emergency listener bind failed on {addr}: {error}"),
            );
            return;
        }
    };
    let mut buf = vec![0u8; MAX_DATAGRAM_BYTES];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, src)) => {
                let datagram = buf[..len].to_vec();
                let node_id = node_id.clone();
                let resolver = resolver.clone();
                let config = config.clone();
                tokio::spawn(async move {
                    if let Err(reason) =
                        handle_notice(&datagram, &node_id, &resolver, &config).await
                    {
                        tracing::warn!("CRL-EMERGENCY notice from {} dropped: {}", src, reason);
                    }
                });
            }
            Err(error) => eprintln!("CRL-EMERGENCY recv error: {error}"),
        }
    }
}

async fn handle_notice(
    datagram: &[u8],
    node_id: &str,
    resolver: &Resolver,
    config: &GossipConfig,
) -> Result<(), String> {
    let notice: RevocationNotice =
        serde_json::from_slice(datagram).map_err(|error| format!("bad notice: {error}"))?;
    if notice.kind != KIND_NOTICE {
        return Err(format!("unexpected kind '{kind}'", kind = notice.kind));
    }
    NOTICES_RECEIVED.fetch_add(1, Ordering::Relaxed);

    let (record, km, circle_id) = load_identity(node_id)?;
    if notice.circle_id != circle_id {
        return Err(format!(
            "circle mismatch: local={} notice={}",
            circle_id, notice.circle_id
        ));
    }
    let fingerprint = notice.entry.fingerprint();
    // Dedup: if we've already processed this exact revocation notice, stop
    // (prevents infinite re-broadcast echo).
    if !seen_is_new(&fingerprint) {
        return Ok(());
    }

    // Zero-trust: re-verify the signed entry against the issuer DID Document.
    if let Err(error) = crate::crl::verify::verify_entry(&notice.entry, resolver, &circle_id).await
    {
        log_audit(
            node_id,
            AuditCategory::Crl,
            AuditSeverity::Warning,
            AuditAction::Failed,
            &format!(
                "EMERGENCY notice rejected revoked_did={}: {}",
                notice.entry.revoked_did, error
            ),
        );
        return Err(format!("verify failed: {error}"));
    }

    // Merge via the SAME locked path routine gossip uses → roots converge.
    let merge = {
        let _guard = store::CRL_WRITE_LOCK.lock().await;
        store::merge_verified_entries(
            &record,
            &km,
            &circle_id,
            std::slice::from_ref(&notice.entry),
        )
        .map_err(|error| error.to_string())?
    };
    let newly_merged = merge.added + merge.replaced > 0;
    if newly_merged {
        NOTICES_MERGED.fetch_add(1, Ordering::Relaxed);
        // Record origin as a notified peer (reuse routine threshold logic).
        let other_members = super::engine::active_gossip_peers(&record.did).len();
        let threshold = super::engine::threshold_count(other_members, config.threshold_pct);
        let _ = {
            let _guard = store::CRL_WRITE_LOCK.lock().await;
            store::mark_peer_notified(&record, &km, &circle_id, &notice.origin_did, threshold)
        };
    }

    // Critical-only side effects: terminate sessions + user notification.
    if matches!(notice.entry.severity, Severity::Critical) && newly_merged {
        let terminated = terminate_sessions_for_did(&notice.entry.revoked_did).await;
        if terminated > 0 {
            SESSIONS_TERMINATED.fetch_add(terminated as u64, Ordering::Relaxed);
        }
        super::notifications::record(node_id, &notice.entry, &notice.origin_did, terminated);
        log_audit(
            node_id,
            AuditCategory::Crl,
            AuditSeverity::Critical,
            AuditAction::Succeeded,
            &format!(
                "EMERGENCY revocation applied revoked_did={} sessions_terminated={} via_origin={}",
                notice.entry.revoked_did, terminated, notice.origin_did
            ),
        );
        println!(
            "🚨 EMERGENCY applied revoked_did={} sessions_terminated={}",
            notice.entry.revoked_did, terminated
        );
    }

    record_last(LastNotice {
        direction: "received".into(),
        revoked_did: notice.entry.revoked_did.clone(),
        origin_did: notice.origin_did.clone(),
        peers: 0,
        merged: newly_merged,
        at: chrono::Utc::now().to_rfc3339(),
    });

    // Bounded re-broadcast: forward ONCE to our own active peers before we
    // fall back to routine gossip. TTL decrement prevents unbounded flood;
    // the seen-set prevents echo loops.
    if notice.ttl > 0 && newly_merged {
        rebroadcast(node_id, &record, &notice, config).await;
    }
    Ok(())
}

async fn rebroadcast(
    node_id: &str,
    record: &DidRecord,
    notice: &RevocationNotice,
    config: &GossipConfig,
) {
    let peers = super::engine::active_gossip_peers(&record.did);
    if peers.is_empty() {
        return;
    }
    let forwarded = RevocationNotice {
        kind: KIND_NOTICE.to_string(),
        circle_id: notice.circle_id.clone(),
        origin_did: notice.origin_did.clone(),
        notice_id: notice.notice_id.clone(),
        ttl: notice.ttl.saturating_sub(1),
        sent_at: chrono::Utc::now().to_rfc3339(),
        entry: notice.entry.clone(),
    };
    let Ok(bytes) = serde_json::to_vec(&forwarded) else {
        return;
    };
    if bytes.len() > MAX_DATAGRAM_BYTES {
        return;
    }
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await else {
        return;
    };
    let mut fanned = 0usize;
    for peer in &peers {
        // Don't bounce straight back to the origin.
        if peer.did == notice.origin_did {
            continue;
        }
        let addr = format!("{}:{}", peer.overlay_ip, config.emergency_port);
        match tokio::time::timeout(
            Duration::from_secs(IO_TIMEOUT_SECS),
            socket.send_to(&bytes, &addr),
        )
        .await
        {
            Ok(Ok(_)) => fanned += 1,
            Ok(Err(error)) => tracing::warn!("emergency relay to {} failed: {}", addr, error),
            Err(_) => tracing::warn!("emergency relay to {} timed out", addr),
        }
    }
    if fanned > 0 {
        NOTICES_REBROADCAST.fetch_add(1, Ordering::Relaxed);
        log_audit(
            node_id,
            AuditCategory::Crl,
            AuditSeverity::Info,
            AuditAction::Updated,
            &format!(
                "EMERGENCY notice re-broadcast revoked_did={} peers={} ttl={}",
                forwarded.entry.revoked_did, fanned, forwarded.ttl
            ),
        );
    }
}

/// Map a revoked `did:guardian:...` to its `CoT` `device_id` via the cached peer
/// `DID Document`, then terminate all matching sessions in the global
/// `SessionManager`. Returns the number of sessions dropped (0 if the DID has
/// no live session or no cached doc — both benign).
async fn terminate_sessions_for_did(revoked_did: &str) -> usize {
    let Some(handle) = crate::cot::session_manager::global_session_manager() else {
        return 0;
    };
    let Some(device_id) = did_to_device_id(revoked_did) else {
        return 0;
    };
    handle.terminate_peer(&device_id).await
}

/// Resolve `device_id` from the revoked DID's cached `DID Document`. The `CoT`
/// `device_id` is derived from the node public key; peer docs carry the key.
fn did_to_device_id(revoked_did: &str) -> Option<String> {
    let docs = crate::did::doc_persistence::list_peer_docs().ok()?;
    let doc = docs.into_iter().find(|doc| doc.id == revoked_did)?;
    let pubkey = doc.primary_public_key_bytes()?;
    crate::cot::identity::DeviceIdentity::from_public_key(&pubkey)
        .ok()
        .map(|identity| identity.device_id().to_string())
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn seen_set_insert_new_dedups_fingerprints() {
        let mut seen = SeenSet::default();
        assert!(seen.insert_new("fp-1"));
        assert!(!seen.insert_new("fp-1"));
        assert!(seen.insert_new("fp-2"));
    }

    #[test]
    fn seen_set_evicts_oldest_once_capacity_is_reached() {
        let mut seen = SeenSet::default();
        for i in 0..SEEN_CAPACITY {
            assert!(seen.insert_new(&format!("fp-{}", i)));
        }
        // Capacity reached: inserting one more must evict "fp-0".
        assert!(seen.insert_new("fp-overflow"));
        assert!(seen.insert_new("fp-0"));
        // The set never grows past its capacity.
        assert_eq!(seen.set.len(), SEEN_CAPACITY);
        assert_eq!(seen.order.len(), SEEN_CAPACITY);
    }
}
