//! Connectivity detection + reconnect-driven fetch/flush via the existing
//! gossip anti-entropy exchange. Maintains a per-peer version-vector view.

use super::{queue, OfflineConfig};
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::crl::gossip::engine::{
    active_gossip_peers, did_record_path, run_round_once, GossipPeer,
};
use crate::crl::gossip::GossipConfig;
use crate::crl::persistence;
use crate::did::{DidRecord, Resolver};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Duration;
use tokio::net::TcpStream;

// Observability
static SYNC_CYCLES: AtomicU64 = AtomicU64::new(0);
static RECONNECTS: AtomicU64 = AtomicU64::new(0);
static ENTRIES_DELIVERED: AtomicU64 = AtomicU64::new(0);
static ENTRIES_FETCHED: AtomicU64 = AtomicU64::new(0);
static WAS_ONLINE: AtomicBool = AtomicBool::new(false);

pub fn sync_cycles() -> u64 {
    SYNC_CYCLES.load(Ordering::Relaxed)
}

pub fn reconnects() -> u64 {
    RECONNECTS.load(Ordering::Relaxed)
}

pub fn entries_delivered() -> u64 {
    ENTRIES_DELIVERED.load(Ordering::Relaxed)
}

pub fn entries_fetched() -> u64 {
    ENTRIES_FETCHED.load(Ordering::Relaxed)
}

pub fn is_online() -> bool {
    WAS_ONLINE.load(Ordering::Relaxed)
}

/// Per-peer CRL version-vector view, persisted for observability.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerSyncState {
    pub last_seen_merkle_root: String,
    pub last_seen_sequence: u64,
    pub last_sync_at: String,
}

static SYNC_STATE: Lazy<RwLock<HashMap<String, PeerSyncState>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

pub fn sync_state_snapshot() -> HashMap<String, PeerSyncState> {
    SYNC_STATE
        .read()
        .map(|guard| guard.clone())
        .unwrap_or_default()
}

fn sync_state_path() -> std::path::PathBuf {
    persistence::pending_dir()
        .parent()
        .map(|base| base.join("sync_state.json"))
        .unwrap_or_else(|| {
            std::path::PathBuf::from("/var/lib/sgx-guardian/identity/crl/sync_state.json")
        })
}

fn load_sync_state() {
    let path = sync_state_path();
    let Ok(bytes) = std::fs::read(path) else {
        return;
    };
    let Ok(snapshot) = serde_json::from_slice::<HashMap<String, PeerSyncState>>(&bytes) else {
        return;
    };
    if let Ok(mut guard) = SYNC_STATE.write() {
        *guard = snapshot;
    }
}

fn persist_sync_state() {
    if let Ok(guard) = SYNC_STATE.read() {
        if let Ok(bytes) = serde_json::to_vec_pretty(&*guard) {
            let path = sync_state_path();
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let tmp = path.with_extension("tmp");
            if std::fs::write(&tmp, &bytes).is_ok() {
                let _ = std::fs::rename(&tmp, &path);
            }
        }
    }
}

fn record_local_vector_for(peer_did: &str) {
    let (sequence, merkle_root) = match persistence::load_crl() {
        Ok(Some(crl)) => (crl.sequence, crl.merkle_root),
        _ => (0, String::new()),
    };
    if let Ok(mut guard) = SYNC_STATE.write() {
        guard.insert(
            peer_did.to_string(),
            PeerSyncState {
                last_seen_merkle_root: merkle_root,
                last_seen_sequence: sequence,
                last_sync_at: chrono::Utc::now().to_rfc3339(),
            },
        );
    }
}

async fn reachable_peers(self_did: &str, config: &OfflineConfig) -> Vec<GossipPeer> {
    let gossip_port = GossipConfig::from_env().port;
    let candidates = active_gossip_peers(self_did);
    let mut reachable = Vec::new();
    for peer in candidates {
        let addr = format!("{}:{}", peer.overlay_ip, gossip_port);
        let ok = tokio::time::timeout(
            Duration::from_millis(config.probe_timeout_ms),
            TcpStream::connect(&addr),
        )
        .await
        .map(|result| result.is_ok())
        .unwrap_or(false);
        if ok {
            reachable.push(peer);
        }
    }
    reachable
}

pub async fn sync_loop(node_id: String, resolver: Resolver, config: OfflineConfig) {
    load_sync_state();
    tokio::time::sleep(Duration::from_secs(config.sync_interval_secs)).await;
    loop {
        if let Err(reason) = run_cycle(&node_id, &resolver, &config).await {
            tracing::warn!("CRL-OFFLINE cycle error: {}", reason);
        }
        tokio::time::sleep(Duration::from_secs(config.sync_interval_secs)).await;
    }
}

/// One sync cycle. Also invoked by POST /crl/offline/sync for deterministic
/// board testing. Returns a short human summary.
pub async fn run_cycle(
    node_id: &str,
    resolver: &Resolver,
    config: &OfflineConfig,
) -> Result<CycleReport, String> {
    SYNC_CYCLES.fetch_add(1, Ordering::Relaxed);

    let record = DidRecord::load(&did_record_path()).map_err(|error| error.to_string())?;
    let self_did = record.did.clone();

    let reachable = reachable_peers(&self_did, config).await;
    let online = !reachable.is_empty();

    let was_online = WAS_ONLINE.swap(online, Ordering::Relaxed);
    if online && !was_online {
        RECONNECTS.fetch_add(1, Ordering::Relaxed);
        log_audit(
            node_id,
            AuditCategory::Crl,
            AuditSeverity::Info,
            AuditAction::Succeeded,
            &format!(
                "CRL offline: connectivity restored - {} peer(s) reachable, syncing",
                reachable.len()
            ),
        );
        println!(
            "CRL-OFFLINE connectivity restored: {} peer(s) reachable",
            reachable.len()
        );
    } else if !online && was_online {
        log_audit(
            node_id,
            AuditCategory::Crl,
            AuditSeverity::Warning,
            AuditAction::Failed,
            "CRL offline: connectivity lost - no reachable gossip peers",
        );
        println!("CRL-OFFLINE connectivity lost: no reachable gossip peers");
    }

    let reconciled = queue::reconcile_from_local(&self_did).map_err(|error| error.to_string())?;

    if !online {
        return Ok(CycleReport {
            online: false,
            reachable_peers: 0,
            reconciled,
            fetched: 0,
            delivered: 0,
            pending_remaining: queue::count(),
        });
    }

    let before = pending_fingerprints();
    let mut fetched = 0usize;
    for _ in 0..config.flush_rounds {
        match run_round_once(node_id, resolver, &GossipConfig::from_env()).await {
            Ok(report) => {
                fetched += report.merged + report.replaced;
                record_local_vector_for(&report.peer_did);
            }
            Err(reason) => {
                tracing::info!("CRL-OFFLINE round skipped: {}", reason);
            }
        }
    }
    persist_sync_state();
    ENTRIES_FETCHED.fetch_add(fetched as u64, Ordering::Relaxed);

    let delivered = settle_pending(node_id, config, &before)?;
    ENTRIES_DELIVERED.fetch_add(delivered as u64, Ordering::Relaxed);

    println!(
        "CRL-OFFLINE cycle complete peers={} reconciled={} fetched={} delivered={} pending={}",
        reachable.len(),
        reconciled,
        fetched,
        delivered,
        queue::count()
    );

    Ok(CycleReport {
        online: true,
        reachable_peers: reachable.len(),
        reconciled,
        fetched,
        delivered,
        pending_remaining: queue::count(),
    })
}

fn pending_fingerprints() -> Vec<String> {
    queue::list()
        .map(|items| items.iter().map(|p| p.entry.fingerprint()).collect())
        .unwrap_or_default()
}

/// For each pending entry: bump the attempt counter; if the entry is now
/// `propagated` in local crl.json, dequeue it (delivered). Returns the number
/// dequeued this cycle.
fn settle_pending(
    node_id: &str,
    config: &OfflineConfig,
    _before: &[String],
) -> Result<usize, String> {
    let crl = persistence::load_crl().map_err(|error| error.to_string())?;
    let propagated_ids: HashSet<String> = crl
        .map(|crl| {
            crl.entries
                .into_iter()
                .filter(|entry| entry.propagated)
                .map(|entry| entry.id)
                .collect()
        })
        .unwrap_or_default();

    let pending = queue::list().map_err(|error| error.to_string())?;
    let mut delivered = 0usize;
    for item in pending {
        if propagated_ids.contains(&item.entry.id) {
            queue::dequeue(&item.entry.id).map_err(|error| error.to_string())?;
            delivered += 1;
            log_audit(
                node_id,
                AuditCategory::Crl,
                AuditSeverity::Info,
                AuditAction::Succeeded,
                &format!(
                    "CRL offline delivered revoked_did={} id={} (propagated)",
                    item.entry.revoked_did, item.entry.id
                ),
            );
            println!(
                "CRL-OFFLINE delivered revoked_did={} id={}",
                item.entry.revoked_did, item.entry.id
            );
            continue;
        }

        if item.parked {
            continue;
        }

        let next_attempt = item.attempts.saturating_add(1);
        queue::record_attempt(&item.entry.id, None, config.max_retries)
            .map_err(|error| error.to_string())?;
        println!(
            "CRL-OFFLINE flush attempt id={} attempt={}",
            item.entry.id, next_attempt
        );
        if config.max_retries > 0 && next_attempt >= config.max_retries {
            log_audit(
                node_id,
                AuditCategory::Crl,
                AuditSeverity::Warning,
                AuditAction::Failed,
                &format!(
                    "CRL offline parked revoked_did={} id={} attempts={}",
                    item.entry.revoked_did, item.entry.id, next_attempt
                ),
            );
            println!(
                "CRL-OFFLINE parked revoked_did={} id={} attempts={}",
                item.entry.revoked_did, item.entry.id, next_attempt
            );
        }
    }
    Ok(delivered)
}

#[derive(Debug, Clone, Serialize)]
pub struct CycleReport {
    pub online: bool,
    pub reachable_peers: usize,
    pub reconciled: usize,
    pub fetched: usize,
    pub delivered: usize,
    pub pending_remaining: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crl::entry::{
        CrlEntry, RevocationReason, RevokerRole, Severity, CRL_CONTEXT_CORE, CRL_CONTEXT_SGX,
    };
    use crate::crl::list::CertificateRevocationList;
    use crate::did::document::{DidDocument, Proof, ServiceEndpoint};
    use crate::did::{persistence::DerivationProof, ResolverConfig};
    use tempfile::TempDir;
    use tokio::net::TcpListener;

    struct CrlBaseGuard(Option<std::ffi::OsString>);

    impl CrlBaseGuard {
        fn set(path: &std::path::Path) -> Self {
            let previous = std::env::var_os(persistence::CRL_BASE_ENV);
            std::env::set_var(persistence::CRL_BASE_ENV, path);
            Self(previous)
        }
    }

    impl Drop for CrlBaseGuard {
        fn drop(&mut self) {
            if let Some(previous) = self.0.take() {
                std::env::set_var(persistence::CRL_BASE_ENV, previous);
            } else {
                std::env::remove_var(persistence::CRL_BASE_ENV);
            }
        }
    }

    /// Generic env-var guard (mirrors `CrlBaseGuard`) for the identity/peer
    /// directory env vars `run_cycle`/`reachable_peers` also read.
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

    fn sample_peer_doc(did: &str, status: Option<&str>, nebula_ip_cidr: Option<&str>) -> DidDocument {
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
            sgx_node_name: Some("peer-node".to_string()),
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
        std::fs::create_dir_all(dir).expect("peers dir");
        std::fs::write(
            dir.join(format!("did_doc_{name}.json")),
            serde_json::to_vec(doc).expect("serialize peer doc"),
        )
        .expect("write peer doc");
    }

    fn sample_entry(id: &str, propagated: bool) -> CrlEntry {
        CrlEntry {
            context: vec![CRL_CONTEXT_CORE.into(), CRL_CONTEXT_SGX.into()],
            id: id.into(),
            r#type: vec!["VerifiableCredential".into(), "RevocationCredential".into()],
            revoked_did: format!("did:guardian:{id}"),
            device_id: None,
            user_id: None,
            circle_id: "circle-alpha".into(),
            reason: RevocationReason::Compromised,
            severity: Severity::Critical,
            timestamp: "2026-08-31T00:00:00Z".into(),
            revoker_did: "did:guardian:self".into(),
            revoker_role: RevokerRole::Owner,
            evidence: None,
            proof: Proof::default(),
            peers_notified: vec![],
            propagated,
        }
    }

    fn config(max_retries: u32) -> OfflineConfig {
        OfflineConfig {
            enabled: true,
            sync_interval_secs: 20,
            max_retries,
            flush_rounds: 1,
            probe_timeout_ms: 200,
        }
    }

    #[test]
    fn sync_state_persistence_round_trips_and_ignores_missing_or_malformed_files() {
        let _lock = crate::test_support::blocking_env_lock();
        let temp = TempDir::new().expect("tempdir");
        let _base = CrlBaseGuard::set(temp.path());
        SYNC_STATE.write().expect("sync state write").clear();

        load_sync_state();
        assert!(sync_state_snapshot().is_empty());

        SYNC_STATE.write().expect("sync state write").insert(
            "did:guardian:peer".into(),
            PeerSyncState {
                last_seen_merkle_root: "root-1".into(),
                last_seen_sequence: 7,
                last_sync_at: "2026-08-31T00:00:00Z".into(),
            },
        );
        persist_sync_state();
        SYNC_STATE.write().expect("sync state write").clear();
        load_sync_state();
        assert_eq!(
            sync_state_snapshot()["did:guardian:peer"].last_seen_sequence,
            7
        );

        std::fs::write(sync_state_path(), b"not-json").expect("write malformed state");
        SYNC_STATE.write().expect("sync state write").clear();
        load_sync_state();
        assert!(sync_state_snapshot().is_empty());
    }

    #[test]
    fn pending_fingerprints_and_settlement_deliver_propagated_and_park_exhausted_entries() {
        let _lock = crate::test_support::blocking_env_lock();
        let temp = TempDir::new().expect("tempdir");
        let _base = CrlBaseGuard::set(temp.path());
        let delivered = sample_entry("delivered", true);
        let retry = sample_entry("retry", false);
        let already_parked = sample_entry("parked", false);
        queue::enqueue(&delivered).expect("queue delivered");
        queue::enqueue(&retry).expect("queue retry");
        queue::enqueue(&already_parked).expect("queue parked");
        queue::record_attempt(&already_parked.id, Some("offline".into()), 1)
            .expect("park pending entry");

        let fingerprints = pending_fingerprints();
        assert_eq!(fingerprints.len(), 3);

        let mut crl = CertificateRevocationList::new("did:guardian:self", "circle-alpha");
        crl.entries.push(delivered.clone());
        crl.recompute_root();
        persistence::save_crl(&crl).expect("save local CRL");

        assert_eq!(
            settle_pending("nodeA", &config(1), &fingerprints).expect("settle queue"),
            1
        );
        let remaining = queue::list().expect("remaining queue");
        assert_eq!(remaining.len(), 2);
        assert!(remaining.iter().all(|item| item.parked));
        assert!(remaining.iter().any(|item| item.entry.id == retry.id));
        assert!(remaining.iter().any(|item| item.entry.id == already_parked.id));
    }

    #[test]
    fn cycle_report_and_observability_accessors_have_stable_public_shapes() {
        let report = CycleReport {
            online: false,
            reachable_peers: 0,
            reconciled: 2,
            fetched: 3,
            delivered: 4,
            pending_remaining: 5,
        };
        let json = serde_json::to_value(report).expect("serialize cycle report");
        assert_eq!(json["online"], false);
        assert_eq!(json["reconciled"], 2);
        let _ = sync_cycles();
        let _ = reconnects();
        let _ = entries_delivered();
        let _ = entries_fetched();
        let _ = is_online();
    }

    #[test]
    fn record_local_vector_for_defaults_when_no_local_crl_then_reflects_saved_crl() {
        let _lock = crate::test_support::blocking_env_lock();
        let temp = TempDir::new().expect("tempdir");
        let _base = CrlBaseGuard::set(temp.path());
        SYNC_STATE.write().expect("sync state write").clear();

        record_local_vector_for("did:guardian:peer-a");
        let snapshot = sync_state_snapshot();
        let state = snapshot
            .get("did:guardian:peer-a")
            .expect("peer entry recorded");
        assert_eq!(state.last_seen_sequence, 0);
        assert!(state.last_seen_merkle_root.is_empty());
        assert!(!state.last_sync_at.is_empty());

        let mut crl = CertificateRevocationList::new("did:guardian:self", "circle-alpha");
        crl.entries.push(sample_entry("entry-1", true));
        crl.sequence = 9;
        crl.recompute_root();
        let expected_root = crl.merkle_root.clone();
        persistence::save_crl(&crl).expect("save local CRL");

        record_local_vector_for("did:guardian:peer-a");
        let snapshot = sync_state_snapshot();
        let state = snapshot
            .get("did:guardian:peer-a")
            .expect("peer entry recorded again");
        assert_eq!(state.last_seen_sequence, 9);
        assert_eq!(state.last_seen_merkle_root, expected_root);
    }

    #[tokio::test]
    async fn reachable_peers_returns_empty_when_no_peer_docs_present() {
        let _lock = crate::test_support::async_env_lock().await;
        let temp = TempDir::new().expect("tempdir");
        let peers_dir = temp.path().join("peers-missing");
        let _peers_guard = EnvGuard::set(crate::did::doc_persistence::PEERS_DOC_DIR_ENV, &peers_dir);

        let reachable = reachable_peers("did:guardian:self", &config(1)).await;
        assert!(reachable.is_empty());
    }

    #[tokio::test]
    async fn reachable_peers_distinguishes_reachable_from_unreachable_peers() {
        let _lock = crate::test_support::async_env_lock().await;
        let temp = TempDir::new().expect("tempdir");
        let _base = CrlBaseGuard::set(temp.path());
        let peers_dir = temp.path().join("peers");
        let _peers_guard = EnvGuard::set(crate::did::doc_persistence::PEERS_DOC_DIR_ENV, &peers_dir);

        // A bound-but-listening loopback socket = reachable peer.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let listen_addr = listener.local_addr().expect("addr");
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        // Bind-then-drop reserves a free port nobody listens on = unreachable.
        let dead_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind dead");
        let dead_addr = dead_listener.local_addr().expect("dead addr");
        drop(dead_listener);

        write_peer_doc(
            &peers_dir,
            "reachable",
            &sample_peer_doc(
                "did:guardian:reachable-peer",
                Some("active"),
                Some(&format!("{}/24", listen_addr.ip())),
            ),
        );
        write_peer_doc(
            &peers_dir,
            "unreachable",
            &sample_peer_doc(
                "did:guardian:unreachable-peer",
                Some("active"),
                Some(&format!("{}/24", dead_addr.ip())),
            ),
        );

        // Same gossip port for both candidates: overlay_ip differs instead.
        std::env::set_var("SGX_CRL_GOSSIP_PORT", listen_addr.port().to_string());
        let reachable = reachable_peers("did:guardian:self", &config(1)).await;
        std::env::remove_var("SGX_CRL_GOSSIP_PORT");

        assert_eq!(reachable.len(), 1);
        assert_eq!(reachable[0].did, "did:guardian:reachable-peer");
        accept_task.await.expect("accept task joined");
    }

    #[tokio::test]
    async fn run_cycle_offline_path_reports_zero_reachable_and_reconciles_pending() {
        let _lock = crate::test_support::async_env_lock().await;
        let temp = TempDir::new().expect("tempdir");
        let _base = CrlBaseGuard::set(temp.path());
        let did_path = temp.path().join("did.json");
        let peers_dir = temp.path().join("peers-empty");
        make_did_record("did:guardian:offline-node").save(did_path.to_str().unwrap()).expect("save did");
        let _did_guard = EnvGuard::set("SGX_GUARDIAN_DID_PATH", &did_path);
        let _peers_guard = EnvGuard::set(crate::did::doc_persistence::PEERS_DOC_DIR_ENV, &peers_dir);

        // A locally-issued, not-yet-propagated entry so reconcile_from_local
        // has something to pick up.
        let mut crl = CertificateRevocationList::new("did:guardian:offline-node", "circle-alpha");
        let mut local_entry = sample_entry("local-1", false);
        local_entry.revoker_did = "did:guardian:offline-node".into();
        crl.entries.push(local_entry);
        crl.recompute_root();
        persistence::save_crl(&crl).expect("save local CRL");

        let resolver = Resolver::new(ResolverConfig::default());
        let report = run_cycle("nodeA", &resolver, &config(3))
            .await
            .expect("cycle result");

        assert!(!report.online);
        assert_eq!(report.reachable_peers, 0);
        assert_eq!(report.reconciled, 1);
        assert_eq!(report.fetched, 0);
        assert_eq!(report.delivered, 0);
        assert_eq!(report.pending_remaining, queue::count());
    }

    #[tokio::test]
    async fn run_cycle_online_path_counts_reachable_peer_and_survives_round_error() {
        let _lock = crate::test_support::async_env_lock().await;
        let temp = TempDir::new().expect("tempdir");
        let _base = CrlBaseGuard::set(temp.path());
        let did_path = temp.path().join("did.json");
        let peers_dir = temp.path().join("peers");
        make_did_record("did:guardian:online-node").save(did_path.to_str().unwrap()).expect("save did");
        let _did_guard = EnvGuard::set("SGX_GUARDIAN_DID_PATH", &did_path);
        let _peers_guard = EnvGuard::set(crate::did::doc_persistence::PEERS_DOC_DIR_ENV, &peers_dir);

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        // Accept the connection then drop it immediately: the peer looks
        // reachable at the TCP level, but the gossip handshake fails fast
        // (EOF) instead of hanging on the protocol's read timeout.
        let server = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });

        write_peer_doc(
            &peers_dir,
            "peer",
            &sample_peer_doc(
                "did:guardian:online-peer",
                Some("active"),
                Some(&format!("{}/24", addr.ip())),
            ),
        );
        std::env::set_var("SGX_CRL_GOSSIP_PORT", addr.port().to_string());

        let resolver = Resolver::new(ResolverConfig::default());
        let report = run_cycle("nodeA", &resolver, &config(3)).await;
        std::env::remove_var("SGX_CRL_GOSSIP_PORT");
        server.await.expect("server task joined");

        let report = report.expect("cycle result");
        assert!(report.online);
        assert_eq!(report.reachable_peers, 1);
        assert_eq!(report.fetched, 0);
        assert_eq!(report.delivered, 0);
    }
}
