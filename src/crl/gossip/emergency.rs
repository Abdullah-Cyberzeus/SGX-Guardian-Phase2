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
        store::merge_verified_records(
            &record,
            &km,
            &circle_id,
            std::slice::from_ref(&notice.entry),
            &[],
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

    // Gated on severity alone, NOT `newly_merged` — the fingerprint dedup
    // above already caps this block to one run per entry. Routine gossip
    // racing this notice and winning the CRL-merge lock must not skip
    // session termination, since gossip itself never terminates sessions.
    if matches!(notice.entry.severity, Severity::Critical) {
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
    use crate::did::doc_persistence;
    use crate::did::document::{DidDocument, DocBuildInput};
    use crate::did::persistence::DerivationProof;
    use crate::crl::entry::{RevocationReason, RevokerRole, CRL_CONTEXT_CORE, CRL_CONTEXT_SGX};
    use crate::did::document::Proof;
    use tempfile::TempDir;

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

    /// A syntactically valid (but not curve-checked) uncompressed P-256
    /// public key, matching the fixture already used by
    /// `did::document::unit_tests`. `primary_public_key_bytes` only decodes
    /// coordinates; it does not validate the point is on-curve.
    const SAMPLE_PUBKEY: [u8; 65] = {
        let mut bytes = [0u8; 65];
        bytes[0] = 0x04;
        let mut i = 1;
        while i < 65 {
            bytes[i] = i as u8;
            i += 1;
        }
        bytes
    };

    fn sample_entry(sev: Severity) -> CrlEntry {
        CrlEntry {
            context: vec![CRL_CONTEXT_CORE.into(), CRL_CONTEXT_SGX.into()],
            id: "urn:uuid:emergunit".to_string(),
            r#type: vec!["VerifiableCredential".into(), "RevocationCredential".into()],
            revoked_did: "did:guardian:target".to_string(),
            device_id: None,
            user_id: None,
            circle_id: "guardian-circle-alpha".to_string(),
            reason: RevocationReason::Compromised,
            severity: sev,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            revoker_did: "did:guardian:owner".to_string(),
            revoker_role: RevokerRole::Owner,
            evidence: None,
            proof: Proof::default(),
            peers_notified: Vec::new(),
            propagated: false,
        }
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
            derivation: DerivationProof {
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

    // --- seen_is_new (global dedup wrapper) --------------------------------

    #[test]
    fn seen_is_new_dedups_across_calls_via_global_seen_set() {
        let fp_a = format!("emergency-unit-test-fp-a-{}", uuid::Uuid::new_v4());
        let fp_b = format!("emergency-unit-test-fp-b-{}", uuid::Uuid::new_v4());
        assert!(seen_is_new(&fp_a));
        assert!(!seen_is_new(&fp_a));
        assert!(seen_is_new(&fp_b));
        assert!(!seen_is_new(&fp_b));
        // Unrelated fingerprints remain independent.
        assert!(seen_is_new(&format!("{fp_a}-suffix")));
    }

    // --- did_to_device_id ----------------------------------------------

    #[test]
    fn did_to_device_id_resolves_via_cached_peer_doc() {
        let _lock = crate::test_support::blocking_env_lock();
        let peers_dir = TempDir::new().expect("peers tempdir");
        let _peers_guard = EnvGuard::set(doc_persistence::PEERS_DOC_DIR_ENV, peers_dir.path());

        let target_did = "did:guardian:target-device0000";
        let doc = DidDocument::build(DocBuildInput {
            did: target_did,
            node_name: Some("node-target"),
            current_dkp_version: 1,
            current_dkp_pubkey_der: &SAMPLE_PUBKEY,
            overlay_ip_cidr: None,
            attestation_bind: None,
            cert_bootstrap_bind: None,
            revoked: vec![],
            previous_version_id: 0,
            created_at: None,
            status: None,
        })
        .expect("build doc");

        std::fs::write(
            peers_dir.path().join("did_doc_target.json"),
            serde_json::to_vec(&doc).expect("serialize doc"),
        )
        .expect("write doc");

        let device_id = did_to_device_id(target_did);
        assert!(device_id.is_some());

        let expected = crate::cot::identity::DeviceIdentity::from_public_key(&SAMPLE_PUBKEY)
            .expect("device identity")
            .device_id()
            .to_string();
        assert_eq!(device_id.unwrap(), expected);
    }

    #[test]
    fn did_to_device_id_returns_none_when_doc_missing() {
        let _lock = crate::test_support::blocking_env_lock();
        let peers_dir = TempDir::new().expect("peers tempdir");
        let _peers_guard = EnvGuard::set(doc_persistence::PEERS_DOC_DIR_ENV, peers_dir.path());
        assert!(did_to_device_id("did:guardian:does-not-exist0000").is_none());
    }

    #[test]
    fn did_to_device_id_returns_none_when_peer_dir_missing() {
        let _lock = crate::test_support::blocking_env_lock();
        let peers_dir = TempDir::new().expect("peers tempdir");
        let missing = peers_dir.path().join("nope");
        let _peers_guard = EnvGuard::set(doc_persistence::PEERS_DOC_DIR_ENV, &missing);
        assert!(did_to_device_id("did:guardian:whoever").is_none());
    }

    // --- load_identity ----------------------------------------------------

    #[test]
    fn load_identity_succeeds_with_fixture_record_and_software_keys() {
        let _lock = crate::test_support::blocking_env_lock();
        let tmp = TempDir::new().expect("tempdir");
        let did_path = tmp.path().join("did.json");
        let key_dir = tmp.path().join("keys");

        let record = make_did_record("did:guardian:loadtest0000");
        record
            .save(did_path.to_str().expect("utf8 path"))
            .expect("save did record");

        let _did_guard = EnvGuard::set("SGX_GUARDIAN_DID_PATH", &did_path);
        let _keys_guard = EnvGuard::set(crate::vc::issue::DEVICE_KEY_DIR_ENV, &key_dir);
        let _force_guard = EnvGuard::set("SGX_FORCE_SOFTWARE_KEYS", "1");

        let result = load_identity("emergency-load-identity-ok");
        assert!(result.is_ok(), "expected Ok, got {:?}", result.err());
        let (loaded_record, _km, circle_id) = result.expect("identity loaded");
        assert_eq!(loaded_record.did, "did:guardian:loadtest0000");
        assert!(!circle_id.is_empty());
    }

    #[test]
    fn load_identity_fails_when_did_record_missing() {
        let _lock = crate::test_support::blocking_env_lock();
        let tmp = TempDir::new().expect("tempdir");
        let missing_path = tmp.path().join("does-not-exist.json");
        let _did_guard = EnvGuard::set("SGX_GUARDIAN_DID_PATH", &missing_path);

        let result = load_identity("emergency-load-identity-missing");
        match result {
            Ok(_) => panic!("missing did record must fail"),
            Err(error) => assert!(error.contains("did record"), "unexpected error: {error}"),
        }
    }

    // --- counters and last notice ------------------------------------------

    static EMERGENCY_STATE_TEST_LOCK: Lazy<std::sync::Mutex<()>> =
        Lazy::new(|| std::sync::Mutex::new(()));

    #[test]
    fn notice_counters_reflect_recorded_increments() {
        let _guard = EMERGENCY_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let before_sent = notices_sent();
        let before_received = notices_received();
        let before_merged = notices_merged();
        let before_rebroadcast = notices_rebroadcast();
        let before_terminated = sessions_terminated_total();

        NOTICES_SENT.fetch_add(1, Ordering::Relaxed);
        NOTICES_RECEIVED.fetch_add(2, Ordering::Relaxed);
        NOTICES_MERGED.fetch_add(3, Ordering::Relaxed);
        NOTICES_REBROADCAST.fetch_add(4, Ordering::Relaxed);
        SESSIONS_TERMINATED.fetch_add(5, Ordering::Relaxed);

        assert_eq!(notices_sent(), before_sent + 1);
        assert_eq!(notices_received(), before_received + 2);
        assert_eq!(notices_merged(), before_merged + 3);
        assert_eq!(notices_rebroadcast(), before_rebroadcast + 4);
        assert_eq!(sessions_terminated_total(), before_terminated + 5);
    }

    #[test]
    fn record_last_and_last_notice_roundtrip() {
        let _guard = EMERGENCY_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let notice = LastNotice {
            direction: "sent".into(),
            revoked_did: "did:guardian:target".into(),
            origin_did: "did:guardian:origin".into(),
            peers: 3,
            merged: true,
            at: "2026-01-01T00:00:00Z".into(),
        };
        record_last(notice.clone());
        let got = last_notice().expect("last notice recorded");
        assert_eq!(got.direction, "sent");
        assert_eq!(got.revoked_did, "did:guardian:target");
        assert_eq!(got.origin_did, "did:guardian:origin");
        assert_eq!(got.peers, 3);
        assert!(got.merged);
    }

    // --- broadcast_for_entry (pure gate branches only; the network path is
    // out of scope — no live UDP peers in a unit test) ----------------------

    #[test]
    fn broadcast_for_entry_returns_before_spawning_when_emergency_disabled() {
        let _lock = crate::test_support::blocking_env_lock();
        let _guard = EnvGuard::set("SGX_CRL_EMERGENCY_ENABLED", "0");
        let entry = sample_entry(Severity::Critical);
        // If this reached `tokio::spawn` it would panic ("no reactor
        // running") since this is a plain `#[test]`, not `#[tokio::test]`.
        // Reaching the end of the function without panicking proves the
        // `!config.emergency_enabled` early return fired.
        broadcast_for_entry("node-x".to_string(), entry);
    }

    #[test]
    fn broadcast_for_entry_returns_before_spawning_when_entry_not_critical() {
        let _lock = crate::test_support::blocking_env_lock();
        let _guard = EnvGuard::set("SGX_CRL_EMERGENCY_ENABLED", "1");
        let entry = sample_entry(Severity::Low);
        broadcast_for_entry("node-x".to_string(), entry);
    }
}
