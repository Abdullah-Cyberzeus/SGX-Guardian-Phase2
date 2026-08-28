//! Coverage-wave-1 tests for:
//!   - src/nebula/registry_sync.rs   (registry sync TCP server + client)
//!   - src/crl/gossip/engine.rs      (CRL gossip: metrics, listener, protocol validation)
//!   - src/crl/gossip/emergency.rs   (CRL emergency broadcast: metrics, UDP listener)
//!   - src/xfer/engine.rs            (file transfer: metrics, outer send/listen API)
//!
//! These are NEW tests only; no existing file is modified. Where a real
//! peer/identity/hardware round trip would be required and is genuinely out
//! of scope for a unit/integration test (e.g. `resolve_overlay_ip`'s infinite
//! CA-retry loop, or CACHE_PATH functions hard-coded to /var/lib paths with
//! no env override), we skip it and note why in the PR/report rather than
//! faking it.
//!
//! All tests that mutate process-wide environment variables serialize
//! through `lock_env()` below, and each such test explicitly sets every
//! variable it depends on (rather than relying on ambient absence), because
//! this binary runs its `#[tokio::test]`/`#[test]` functions in parallel
//! threads within one process.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

use sgx_guardian_client::crl::entry::{
    CrlEntry, RevocationReason, RevokerRole, Severity, CRL_CONTEXT_CORE, CRL_CONTEXT_SGX,
};
use sgx_guardian_client::crl::gossip::emergency::{
    self as gossip_emergency, RevocationNotice, KIND_NOTICE,
};
use sgx_guardian_client::crl::gossip::engine as gossip_engine;
use sgx_guardian_client::crl::gossip::protocol::{SyncRequest, KIND_REQUEST};
use sgx_guardian_client::crl::gossip::GossipConfig;
use sgx_guardian_client::did::doc_persistence;
use sgx_guardian_client::did::doc_sign;
use sgx_guardian_client::did::document::{DidDocument, DocBuildInput, Proof};
use sgx_guardian_client::did::persistence::DerivationProof;
use sgx_guardian_client::did::{Did, DidRecord, Resolver};
use sgx_guardian_client::key_manager::KeyManager;
use sgx_guardian_client::nebula::overlay_registry::OverlayRegistry;
use sgx_guardian_client::nebula::registry_sync::{
    start_registry_server, RegistryRequest, RegistryResponse, REGISTRY_SYNC_PORT,
};
use sgx_guardian_client::vc::issue::DEVICE_KEY_DIR_ENV;
use sgx_guardian_client::xfer::engine as xfer_engine;
use sgx_guardian_client::xfer::errors::XferError;
use sgx_guardian_client::xfer::manifest::FileManifest;
use sgx_guardian_client::xfer::protocol as xfer_protocol;
use sgx_guardian_client::xfer::XferConfig;

// ─────────────────────────────────────────────────────────────────────────
// Shared env-mutation lock + RAII restore helper (this file only touches
// process env inside a held lock, and always restores the previous value).
// ─────────────────────────────────────────────────────────────────────────

static ENV_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

async fn lock_env() -> tokio::sync::MutexGuard<'static, ()> {
    ENV_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

struct EnvGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &Path) -> Self {
        let previous = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self { key, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Shared identity-building helpers (mirrors the pattern already used by
// src/xfer/tests/mod.rs and src/xfer/engine.rs's internal test module, but
// reimplemented here since those helpers are private to the crate's own
// #[cfg(test)] modules and are not visible from an external `tests/` crate).
// ─────────────────────────────────────────────────────────────────────────

struct TestIdentity {
    did: String,
    record: DidRecord,
    doc: DidDocument,
}

fn make_identity(
    temp: &tempfile::TempDir,
    node_name: &str,
    seed: u8,
    overlay_ip: &str,
) -> TestIdentity {
    let key_path = temp.path().join(format!("{}.key", node_name));
    let km = KeyManager::load_or_generate(key_path.to_str().expect("key path")).expect("key");
    let did = Did::from_id_bytes(&[seed; 32]);
    let pubkey = km.pubkey_der().expect("pubkey");
    let overlay = format!("{}/32", overlay_ip);
    let mut doc = DidDocument::build(DocBuildInput {
        did: did.as_str(),
        node_name: Some(node_name),
        current_dkp_version: 1,
        current_dkp_pubkey_der: &pubkey,
        overlay_ip_cidr: Some(&overlay),
        attestation_bind: None,
        cert_bootstrap_bind: None,
        revoked: vec![],
        previous_version_id: 0,
        created_at: None,
        status: Some("active".into()),
    })
    .expect("build doc");
    let vm_ref = doc.verification_method.first().expect("vm").id.clone();
    doc_sign::sign_in_place(&mut doc, &km, &vm_ref).expect("sign doc");
    let record = DidRecord {
        did: did.to_string(),
        method: "guardian".into(),
        method_version: "1.0".into(),
        did_id_b58: did.msi().to_string(),
        did_id_hex: hex::encode(did.id_bytes()),
        created_at: chrono::Utc::now().to_rfc3339(),
        deactivated_at: None,
        derivation: DerivationProof {
            se050_uid: format!("{}-uid", node_name),
            se050_uid_source: "fallback".into(),
            dkp_v1_pubkey_sha256_b16: String::new(),
            dkp_v1_pubkey_path: String::new(),
            dkp_v1_pubkey_der_b64: None,
            dik_pubkey_sha256_b16: String::new(),
            dik_pubkey_der_b64: None,
        },
        current_dkp_version: 1,
        deriv_signature_b64: String::new(),
    };
    TestIdentity {
        did: record.did.clone(),
        record,
        doc,
    }
}

async fn read_line(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> String {
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
        .await
        .expect("read timeout")
        .expect("read ok");
    line
}

// ═══════════════════════════════════════════════════════════════════════
// SECTION 1: src/nebula/registry_sync.rs
// ═══════════════════════════════════════════════════════════════════════

async fn send_registry_request(req: &RegistryRequest) -> RegistryResponse {
    let addr = format!("127.0.0.1:{}", REGISTRY_SYNC_PORT);
    let stream = TcpStream::connect(&addr).await.expect("connect registry");
    send_registry_request_raw(stream, &serde_json::to_string(req).expect("serialize")).await
}

async fn send_registry_request_raw(stream: TcpStream, body: &str) -> RegistryResponse {
    let (read_half, mut write_half) = stream.into_split();
    let mut line = body.to_string();
    line.push('\n');
    write_half
        .write_all(line.as_bytes())
        .await
        .expect("write registry request");
    let mut reader = BufReader::new(read_half);
    let response_line = read_line(&mut reader).await;
    serde_json::from_str(response_line.trim()).expect("parse registry response")
}

/// Single consolidated test: `start_registry_server` binds the hard-coded
/// REGISTRY_SYNC_PORT (50062), so only ONE test in the whole workspace may
/// hold that listener open at a time. We exercise every branch of the
/// (private) `handle_registry_connection` dispatcher reachable from a
/// non-CA test process (argv[1] is never literally "nodeA" here, matching
/// the existing convention documented in tests/registry_sync_test.rs).
#[tokio::test]
async fn registry_server_dispatches_all_request_kinds() {
    let mut registry = OverlayRegistry::new("guardian-circle-alpha", "192.168.100", "ca-node");
    registry.assign_ip("ca-node").expect("assign ca-node");
    registry
        .assign_ip("existing-node")
        .expect("assign existing-node");
    let shared = Arc::new(RwLock::new(registry));
    tokio::spawn(start_registry_server(shared));
    // Give the listener a moment to bind before the first connection.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // "list" — always allowed, returns a registry summary.
    let resp = send_registry_request(&RegistryRequest {
        action: "list".into(),
        node_name: String::new(),
        pubkey_prefix: None,
        did_doc_json: None,
        did_query: None,
        status_list_body: None,
    })
    .await;
    assert!(resp.success);
    assert!(resp.registry_summary.is_some());

    // "query" — found.
    let resp = send_registry_request(&RegistryRequest {
        action: "query".into(),
        node_name: "existing-node".into(),
        pubkey_prefix: None,
        did_doc_json: None,
        did_query: None,
        status_list_body: None,
    })
    .await;
    assert!(resp.success);
    assert!(resp.ip_cidr.is_some());

    // "query" — not found.
    let resp = send_registry_request(&RegistryRequest {
        action: "query".into(),
        node_name: "totally-unknown-node".into(),
        pubkey_prefix: None,
        did_doc_json: None,
        did_query: None,
        status_list_body: None,
    })
    .await;
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("not found in registry"));

    // "assign" — this test process is not "nodeA" so this must be rejected.
    let resp = send_registry_request(&RegistryRequest {
        action: "assign".into(),
        node_name: "newbie".into(),
        pubkey_prefix: Some("prefix".into()),
        did_doc_json: None,
        did_query: None,
        status_list_body: None,
    })
    .await;
    assert!(!resp.success);
    assert_eq!(resp.error.unwrap(), "Only CA can assign IPs");

    // "publish_did_doc" — CA-only.
    let resp = send_registry_request(&RegistryRequest {
        action: "publish_did_doc".into(),
        node_name: String::new(),
        pubkey_prefix: None,
        did_doc_json: Some("{}".into()),
        did_query: None,
        status_list_body: None,
    })
    .await;
    assert!(!resp.success);
    assert_eq!(resp.error.unwrap(), "Only CA can ingest DID documents");

    // "snapshot_did_doc" — CA-only.
    let resp = send_registry_request(&RegistryRequest {
        action: "snapshot_did_doc".into(),
        node_name: String::new(),
        pubkey_prefix: None,
        did_doc_json: None,
        did_query: None,
        status_list_body: None,
    })
    .await;
    assert!(!resp.success);
    assert_eq!(
        resp.error.unwrap(),
        "Only CA can serve DID document snapshots"
    );

    // "resolve_did" — CA-only.
    let resp = send_registry_request(&RegistryRequest {
        action: "resolve_did".into(),
        node_name: String::new(),
        pubkey_prefix: None,
        did_doc_json: None,
        did_query: Some("did:guardian:someone".into()),
        status_list_body: None,
    })
    .await;
    assert!(!resp.success);
    assert_eq!(
        resp.error.unwrap(),
        "Only CA can serve DID document point lookups"
    );

    // "snapshot" — CA-only serving path.
    let resp = send_registry_request(&RegistryRequest {
        action: "snapshot".into(),
        node_name: String::new(),
        pubkey_prefix: None,
        did_doc_json: None,
        did_query: None,
        status_list_body: None,
    })
    .await;
    assert!(!resp.success);
    assert_eq!(resp.error.unwrap(), "Only CA can serve registry snapshots");

    // "status_list_snapshot" — also gated by the same CA-only check.
    let resp = send_registry_request(&RegistryRequest {
        action: "status_list_snapshot".into(),
        node_name: String::new(),
        pubkey_prefix: None,
        did_doc_json: None,
        did_query: None,
        status_list_body: None,
    })
    .await;
    assert!(!resp.success);
    assert_eq!(resp.error.unwrap(), "Only CA can serve registry snapshots");

    // Unknown action.
    let resp = send_registry_request(&RegistryRequest {
        action: "totally_bogus_action".into(),
        node_name: String::new(),
        pubkey_prefix: None,
        did_doc_json: None,
        did_query: None,
        status_list_body: None,
    })
    .await;
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("Unknown action"));

    // Oversized line (> 8192 bytes).
    let addr = format!("127.0.0.1:{}", REGISTRY_SYNC_PORT);
    let stream = TcpStream::connect(&addr).await.expect("connect");
    let huge = "x".repeat(9000);
    let resp = send_registry_request_raw(stream, &huge).await;
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("Request too large"));

    // Invalid JSON body.
    let stream = TcpStream::connect(&addr).await.expect("connect");
    let resp = send_registry_request_raw(stream, "{not valid json至").await;
    assert!(!resp.success);
    assert!(resp.error.unwrap().contains("Invalid JSON"));

    // Empty line: server just closes without writing a response.
    let stream = TcpStream::connect(&addr).await.expect("connect");
    let (read_half, mut write_half) = stream.into_split();
    write_half.write_all(b"\n").await.expect("write empty line");
    let mut reader = BufReader::new(read_half);
    let mut buf = String::new();
    let n = reader
        .read_line(&mut buf)
        .await
        .expect("read after empty line");
    assert_eq!(n, 0, "server must close the connection without a response");
}

// ═══════════════════════════════════════════════════════════════════════
// SECTION 2: src/crl/gossip/engine.rs
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn gossip_engine_metrics_getters_do_not_panic() {
    // These pub getters are never exercised by src/crl/gossip/engine.rs's
    // own internal unit tests (which only test pure helpers), nor
    // transitively by other test suites. Just observing them is new
    // coverage of their (trivial) bodies.
    let _ = gossip_engine::rounds_initiated();
    let _ = gossip_engine::rounds_served();
    let _ = gossip_engine::entries_merged_total();
    let _ = gossip_engine::last_round();
}

#[tokio::test]
async fn gossip_engine_run_round_once_fails_without_local_identity() {
    let _lock = lock_env().await;
    let temp = tempfile::TempDir::new().expect("tempdir");
    let missing_did_path = temp.path().join("no-such-identity").join("did.json");
    let _did_guard = EnvGuard::set("SGX_GUARDIAN_DID_PATH", &missing_did_path);

    let resolver = Resolver::new(Default::default());
    let config = GossipConfig {
        enabled: true,
        port: 58261,
        interval_secs: 60,
        threshold_pct: 80,
        emergency_enabled: false,
        emergency_port: 58262,
        emergency_ttl: 1,
    };
    let result = gossip_engine::run_round_once("node-under-test", &resolver, &config).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("did record"));
}

#[tokio::test]
async fn active_gossip_peers_filters_self_inactive_and_missing_mesh_endpoint() {
    let _lock = lock_env().await;
    let temp = tempfile::TempDir::new().expect("tempdir");
    let peers_dir = temp.path().join("peer_docs");
    let _peers_guard = EnvGuard::set(doc_persistence::PEERS_DOC_DIR_ENV, &peers_dir);

    let self_identity = make_identity(&temp, "self-node", 0x31, "192.168.100.1");
    let active = make_identity(&temp, "active-peer", 0x32, "192.168.100.2");
    let mut inactive = make_identity(&temp, "inactive-peer", 0x33, "192.168.100.3");
    inactive.doc.sgx_status = Some("inactive".into());
    let mut no_mesh = make_identity(&temp, "no-mesh-peer", 0x34, "192.168.100.4");
    no_mesh.doc.service.clear();

    for doc in [&self_identity.doc, &active.doc, &inactive.doc, &no_mesh.doc] {
        doc_persistence::save_peer(doc).expect("save peer fixture");
    }

    let peers = gossip_engine::active_gossip_peers(&self_identity.did);
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].did, active.did);
    assert_eq!(peers[0].node_name, "active-peer");
    assert_eq!(peers[0].overlay_ip, "192.168.100.2");
}

/// Connects directly to a real `listener_task` instance and exercises the
/// inbound TCP dispatcher without needing a fully-verified peer identity:
/// malformed JSON is rejected before `load_identity` even runs, and a
/// well-formed request is rejected once `load_identity` fails naturally
/// (no on-disk DID record for this synthetic path).
#[tokio::test]
async fn gossip_engine_listener_rejects_malformed_and_unidentified_requests() {
    let _lock = lock_env().await;
    let temp = tempfile::TempDir::new().expect("tempdir");
    let missing_did_path = temp.path().join("nope").join("did.json");
    let _did_guard = EnvGuard::set("SGX_GUARDIAN_DID_PATH", &missing_did_path);

    let node_id = "node-under-test".to_string();
    let resolver = Resolver::new(Default::default());
    let config = GossipConfig {
        enabled: true,
        port: 58263,
        interval_secs: 60,
        threshold_pct: 80,
        emergency_enabled: false,
        emergency_port: 58264,
        emergency_ttl: 1,
    };
    tokio::spawn(gossip_engine::listener_task(
        node_id,
        resolver,
        config.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(200)).await;
    let addr = format!("127.0.0.1:{}", config.port);

    // Malformed JSON: handle_inbound returns Err before writing anything;
    // the connection is simply closed.
    let stream = TcpStream::connect(&addr).await.expect("connect");
    let (read_half, mut write_half) = stream.into_split();
    write_half
        .write_all(b"this is not json\n")
        .await
        .expect("write garbage");
    let mut reader = BufReader::new(read_half);
    let mut buf = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut buf)).await;
    // Either EOF (0 bytes) or a closed/errored read — both indicate the
    // listener rejected the frame without crashing; the important thing is
    // that this reached `read_json_line` + the parse-failure branch.
    assert!(buf.is_empty());

    // Well-formed SyncRequest, but load_identity fails (no DID record on
    // disk at the path we pinned above) -> server replies with a rejection
    // SyncResponse carrying an error message.
    let request = SyncRequest {
        kind: KIND_REQUEST.to_string(),
        circle_id: "guardian-circle-alpha".into(),
        sender_did: "did:guardian:someone-else".into(),
        sequence: 0,
        merkle_root: String::new(),
        fingerprints: vec![],
    };
    let stream = TcpStream::connect(&addr).await.expect("connect 2");
    let (read_half, mut write_half) = stream.into_split();
    let mut line = serde_json::to_string(&request).expect("serialize request");
    line.push('\n');
    write_half
        .write_all(line.as_bytes())
        .await
        .expect("write request");
    let mut reader = BufReader::new(read_half);
    let response_line = read_line(&mut reader).await;
    let response: sgx_guardian_client::crl::gossip::protocol::SyncResponse =
        serde_json::from_str(response_line.trim()).expect("parse sync response");
    assert!(response.error.is_some());
    assert!(response.error.unwrap().contains("did record"));
}

// ═══════════════════════════════════════════════════════════════════════
// SECTION 3: src/crl/gossip/emergency.rs
// ═══════════════════════════════════════════════════════════════════════

fn sample_crl_entry(severity: Severity, revoked_did: &str) -> CrlEntry {
    CrlEntry {
        context: vec![CRL_CONTEXT_CORE.into(), CRL_CONTEXT_SGX.into()],
        id: "urn:uuid:cov-wave1-emergency".into(),
        r#type: vec!["VerifiableCredential".into(), "RevocationCredential".into()],
        revoked_did: revoked_did.to_string(),
        device_id: None,
        user_id: None,
        circle_id: "guardian-circle-alpha".into(),
        reason: RevocationReason::Compromised,
        severity,
        timestamp: "2026-07-06T00:00:00Z".into(),
        revoker_did: "did:guardian:owner".into(),
        revoker_role: RevokerRole::Owner,
        evidence: None,
        proof: Proof::default(),
        peers_notified: Vec::new(),
        propagated: false,
    }
}

#[test]
fn emergency_metrics_getters_do_not_panic() {
    let _ = gossip_emergency::notices_sent();
    let _ = gossip_emergency::notices_received();
    let _ = gossip_emergency::notices_merged();
    let _ = gossip_emergency::notices_rebroadcast();
    let _ = gossip_emergency::sessions_terminated_total();
    let _ = gossip_emergency::last_notice();
}

#[tokio::test]
async fn broadcast_for_entry_short_circuits_for_non_critical_severity() {
    // No env setup needed: broadcast_for_entry's severity gate runs before
    // any identity/network work, so a non-critical entry returns
    // synchronously without spawning anything.
    let entry = sample_crl_entry(Severity::Medium, "did:guardian:target-noncritical");
    gossip_emergency::broadcast_for_entry("node-under-test".to_string(), entry);
    // Nothing to await: the function is fire-and-forget and, for a
    // non-critical entry, never reaches tokio::spawn. This is a smoke test
    // that the early-return branch executes without panicking.
}

#[tokio::test]
async fn broadcast_for_entry_short_circuits_when_emergency_gossip_is_disabled() {
    let _lock = lock_env().await;
    let disabled = std::path::Path::new("false");
    let _enabled_guard = EnvGuard::set("SGX_CRL_EMERGENCY_ENABLED", disabled);
    let before = gossip_emergency::notices_sent();

    let entry = sample_crl_entry(Severity::Critical, "did:guardian:target-disabled");
    gossip_emergency::broadcast_for_entry("node-under-test".to_string(), entry);
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(gossip_emergency::notices_sent(), before);
}

#[tokio::test]
async fn broadcast_for_entry_spawns_and_fails_closed_without_identity_for_critical_entry() {
    let _lock = lock_env().await;
    let temp = tempfile::TempDir::new().expect("tempdir");
    let missing_did_path = temp.path().join("nope").join("did.json");
    let _did_guard = EnvGuard::set("SGX_GUARDIAN_DID_PATH", &missing_did_path);

    let entry = sample_crl_entry(Severity::Critical, "did:guardian:target-critical");
    gossip_emergency::broadcast_for_entry("node-under-test".to_string(), entry);
    // Give the spawned broadcast_once() task time to run through
    // load_identity() (which fails: no DID record at the pinned path) and
    // log its warning. No externally observable counter changes on this
    // path (NOTICES_SENT is only bumped after a successful send), so this
    // is a smoke test that nothing panics inside the spawned task.
    tokio::time::sleep(Duration::from_millis(150)).await;
}

/// Real UDP round trip against the public `listener_task`: a malformed
/// datagram must be dropped silently, and a well-formed
/// `crl_revocation_notice` must bump `notices_received()` even though the
/// deeper merge/verify pipeline fails closed afterwards (no local identity
/// configured for this synthetic path).
#[tokio::test]
async fn emergency_listener_processes_datagrams_over_real_udp() {
    let _lock = lock_env().await;
    let temp = tempfile::TempDir::new().expect("tempdir");
    let missing_did_path = temp.path().join("nope").join("did.json");
    let _did_guard = EnvGuard::set("SGX_GUARDIAN_DID_PATH", &missing_did_path);

    let node_id = "node-under-test".to_string();
    let resolver = Resolver::new(Default::default());
    let config = GossipConfig {
        enabled: true,
        port: 58265,
        interval_secs: 60,
        threshold_pct: 80,
        emergency_enabled: true,
        emergency_port: 58266,
        emergency_ttl: 1,
    };
    tokio::spawn(gossip_emergency::listener_task(
        node_id,
        resolver,
        config.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(200)).await;
    let addr = format!("127.0.0.1:{}", config.emergency_port);

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client socket");

    // Malformed datagram: dropped before NOTICES_RECEIVED is touched.
    socket
        .send_to(b"not a valid notice", &addr)
        .await
        .expect("send garbage");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Well-formed notice with the correct kind: NOTICES_RECEIVED increments
    // even though the subsequent load_identity() call fails closed.
    let before = gossip_emergency::notices_received();
    let notice = RevocationNotice {
        kind: KIND_NOTICE.to_string(),
        circle_id: "guardian-circle-alpha".into(),
        origin_did: "did:guardian:origin".into(),
        notice_id: "cov-wave1-notice".into(),
        ttl: 0,
        sent_at: "2026-07-06T00:00:00Z".into(),
        entry: sample_crl_entry(Severity::Low, "did:guardian:target-udp"),
    };
    let bytes = serde_json::to_vec(&notice).expect("serialize notice");
    socket.send_to(&bytes, &addr).await.expect("send notice");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        gossip_emergency::notices_received() > before,
        "well-formed notice must be counted as received"
    );

    // Wrong kind: parses fine but is rejected by the kind check before the
    // counter increments again for THIS datagram.
    let mut wrong_kind = notice.clone();
    wrong_kind.kind = "not_a_real_kind".into();
    let bytes = serde_json::to_vec(&wrong_kind).expect("serialize wrong-kind notice");
    socket
        .send_to(&bytes, &addr)
        .await
        .expect("send wrong-kind notice");
    tokio::time::sleep(Duration::from_millis(100)).await;
}

// ═══════════════════════════════════════════════════════════════════════
// SECTION 4: src/xfer/engine.rs
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn xfer_metrics_getters_do_not_panic() {
    let _ = xfer_engine::transfers_sent();
    let _ = xfer_engine::transfers_received();
    let _ = xfer_engine::bytes_transferred();
    let _ = xfer_engine::last_transfer();
}

#[tokio::test]
async fn send_file_rejects_when_transfer_disabled() {
    let config = XferConfig {
        enabled: false,
        port: 0,
        chunk_bytes: 65_536,
        max_file_bytes: 1_048_576,
    };
    let result = xfer_engine::send_file(
        "node-under-test".into(),
        config,
        "did:guardian:actor".into(),
        "did:guardian:peer".into(),
        std::path::PathBuf::from("/does/not/matter"),
    )
    .await;
    match result {
        Err(XferError::Conflict(message)) => {
            assert!(message.contains("disabled via SGX_XFER_ENABLED"));
        }
        other => panic!("expected Conflict error, got {:?}", other),
    }
}

#[tokio::test]
async fn send_vault_record_rejects_when_transfer_disabled() {
    let config = XferConfig {
        enabled: false,
        port: 0,
        chunk_bytes: 65_536,
        max_file_bytes: 1_048_576,
    };
    let result = xfer_engine::send_vault_record(
        "node-under-test".into(),
        config,
        "did:guardian:actor".into(),
        "did:guardian:peer".into(),
        "vault-record-that-is-never-read".into(),
    )
    .await;
    assert!(matches!(result, Err(XferError::Conflict(message)) if message.contains("disabled")));
}

#[tokio::test]
async fn cancel_transfer_unknown_id_returns_false() {
    let _lock = lock_env().await;
    let temp = tempfile::TempDir::new().expect("tempdir");
    let xfer_base = temp.path().join("xfer");
    let _xfer_guard = EnvGuard::set(
        sgx_guardian_client::xfer::persistence::XFER_BASE_ENV,
        &xfer_base,
    );

    let found = xfer_engine::cancel_transfer("no-such-transfer-id")
        .await
        .expect("cancel_transfer should not error for an unknown id");
    assert!(!found);
}

/// Real end-to-end round trip through the PUBLIC send API
/// (`send_file` -> spawned `run_outbound` -> real `TcpStream::connect`)
/// against a hand-rolled fake receiver that rejects the offer. This
/// exercises the entire outer orchestration layer (send_file/send_source/
/// prepare_outbound_from_source/ACTIVE_SENDS bookkeeping/run_outbound's
/// real network connect) that the crate's own internal tests never reach
/// (they call the private `run_outbound_stream` directly over an in-memory
/// duplex, bypassing send_file/listener_task/handle_inbound entirely).
#[tokio::test]
async fn send_file_completes_real_round_trip_and_records_peer_rejection() {
    let _lock = lock_env().await;
    let temp = tempfile::TempDir::new().expect("tempdir");

    let did_path = temp.path().join("identity").join("did.json");
    let peers_dir = temp.path().join("peer_docs");
    let key_dir = temp.path().join("runtime_keys");
    let xfer_base = temp.path().join("xfer");
    std::fs::create_dir_all(&peers_dir).expect("peers dir");
    std::fs::create_dir_all(&key_dir).expect("key dir");

    // Fake receiver: a bare TcpListener bound to an OS-assigned free port.
    let fake_receiver = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake receiver");
    let receiver_port = fake_receiver.local_addr().expect("local addr").port();

    let sender = make_identity(&temp, "nodeA-sender", 0x41, "127.0.0.1");
    let receiver_peer = make_identity(&temp, "nodeB-receiver", 0x42, "127.0.0.1");

    sender
        .record
        .save(did_path.to_str().expect("did path"))
        .expect("save sender did record");

    let _did_guard = EnvGuard::set("SGX_GUARDIAN_DID_PATH", &did_path);
    let _peers_guard = EnvGuard::set(doc_persistence::PEERS_DOC_DIR_ENV, &peers_dir);
    let _key_guard = EnvGuard::set(DEVICE_KEY_DIR_ENV, &key_dir);
    let _xfer_guard = EnvGuard::set(
        sgx_guardian_client::xfer::persistence::XFER_BASE_ENV,
        &xfer_base,
    );

    doc_persistence::save_peer(&receiver_peer.doc).expect("save receiver peer doc");

    // Clone out the plain String values we need so the spawned closure below
    // does not have to move (or partially borrow) the whole TestIdentity
    // structs — keeps `sender`/`receiver_peer` fully usable afterward.
    let sender_did = sender.did.clone();
    let receiver_did = receiver_peer.did.clone();
    let expected_sender_did = sender_did.clone();
    let rejection_sender_did = receiver_did.clone();

    // Fake receiver task: accept one connection, read the offer, reject it.
    let fake_task = tokio::spawn(async move {
        let (stream, _addr) = fake_receiver.accept().await.expect("accept");
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let line = xfer_protocol::read_json_line(&mut reader)
            .await
            .expect("read offer");
        let offer: xfer_protocol::XferOffer =
            serde_json::from_str(line.trim()).expect("parse offer");
        assert_eq!(offer.kind, xfer_protocol::KIND_OFFER);
        assert_eq!(offer.sender_did, expected_sender_did);
        let rejection = xfer_protocol::XferAccept {
            kind: xfer_protocol::KIND_ACCEPT.to_string(),
            circle_id: offer.circle_id.clone(),
            sender_did: rejection_sender_did,
            transfer_id: offer.manifest.transfer_id.clone(),
            accept: false,
            have_chunks: Vec::new(),
            error: Some("cov-wave1 fake receiver rejects".to_string()),
        };
        xfer_protocol::write_json_line(&mut write_half, &rejection)
            .await
            .expect("write rejection");
        offer.manifest.transfer_id
    });

    let payload_path = temp.path().join("payload.bin");
    std::fs::write(&payload_path, vec![9u8; 4096]).expect("write payload");

    let config = XferConfig {
        enabled: true,
        port: receiver_port,
        chunk_bytes: 1024,
        max_file_bytes: 1_048_576,
    };

    let transfer_id = xfer_engine::send_file(
        "nodeA-sender".into(),
        config,
        sender_did,
        receiver_did,
        payload_path,
    )
    .await
    .expect("send_file should accept and spawn the outbound task");

    let offered_transfer_id = tokio::time::timeout(Duration::from_secs(5), fake_task)
        .await
        .expect("fake receiver timed out")
        .expect("fake receiver task panicked");
    assert_eq!(offered_transfer_id, transfer_id);

    // Poll the outbox until the spawned run_outbound task has recorded the
    // rejection as a Failed transfer (bounded wait, no fixed sleep needed).
    let mut last_error = None;
    for _ in 0..50 {
        if let Some(progress) = sgx_guardian_client::xfer::store::load_outbox(&transfer_id)
            .await
            .expect("load outbox")
        {
            if progress.status == sgx_guardian_client::xfer::store::TransferStatus::Failed {
                last_error = progress.last_error;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let last_error = last_error.expect("outbound transfer should have failed");
    assert!(last_error.contains("cov-wave1 fake receiver rejects"));
}

/// Real inbound TCP round trip against the public `listener_task`,
/// exercising `handle_inbound_stream`'s early zero-trust rejection
/// branches (wrong kind / circle mismatch / self-offer / unknown sender)
/// that the crate's own internal tests never reach (they only test the
/// full-acceptance happy paths and a mid-transfer cancel).
#[tokio::test]
async fn xfer_listener_rejects_offers_on_every_early_validation_branch() {
    let _lock = lock_env().await;
    let temp = tempfile::TempDir::new().expect("tempdir");

    let did_path = temp.path().join("identity").join("did.json");
    let peers_dir = temp.path().join("peer_docs"); // left empty on purpose
    let key_dir = temp.path().join("runtime_keys");
    let xfer_base = temp.path().join("xfer");
    std::fs::create_dir_all(&peers_dir).expect("peers dir");
    std::fs::create_dir_all(&key_dir).expect("key dir");

    let receiver = make_identity(&temp, "nodeC-receiver", 0x43, "127.0.0.1");
    receiver
        .record
        .save(did_path.to_str().expect("did path"))
        .expect("save receiver did record");

    let _did_guard = EnvGuard::set("SGX_GUARDIAN_DID_PATH", &did_path);
    let _peers_guard = EnvGuard::set(doc_persistence::PEERS_DOC_DIR_ENV, &peers_dir);
    let _key_guard = EnvGuard::set(DEVICE_KEY_DIR_ENV, &key_dir);
    let _xfer_guard = EnvGuard::set(
        sgx_guardian_client::xfer::persistence::XFER_BASE_ENV,
        &xfer_base,
    );

    let resolver = Resolver::new(Default::default());
    let config = XferConfig {
        enabled: true,
        port: 58301,
        chunk_bytes: 1024,
        max_file_bytes: 1_048_576,
    };
    tokio::spawn(xfer_engine::listener_task(
        "nodeC-receiver".to_string(),
        resolver,
        config.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(200)).await;
    let addr = format!("127.0.0.1:{}", config.port);

    fn dummy_manifest(circle_id: &str, sender_did: &str) -> FileManifest {
        FileManifest {
            transfer_id: format!("xfer-cov-wave1-{}", uuid::Uuid::new_v4()),
            circle_id: circle_id.to_string(),
            sender_did: sender_did.to_string(),
            filename: "dummy.bin".into(),
            size: 4,
            chunk_bytes: 4,
            chunk_count: 1,
            chunk_digests: vec!["00".repeat(32)],
            file_sha256: "11".repeat(32),
            created_at: chrono::Utc::now().to_rfc3339(),
            proof: Proof::default(),
        }
    }

    async fn send_offer_and_read_accept(
        addr: &str,
        offer: &xfer_protocol::XferOffer,
    ) -> xfer_protocol::XferAccept {
        let stream = TcpStream::connect(addr).await.expect("connect");
        let (read_half, mut write_half) = stream.into_split();
        xfer_protocol::write_json_line(&mut write_half, offer)
            .await
            .expect("write offer");
        let mut reader = BufReader::new(read_half);
        let line = xfer_protocol::read_json_line(&mut reader)
            .await
            .expect("read accept");
        serde_json::from_str(line.trim()).expect("parse accept")
    }

    let other_did = "did:guardian:not-a-peer".to_string();

    // 1) Wrong top-level kind.
    let mut offer = xfer_protocol::XferOffer {
        kind: "not_an_offer".into(),
        circle_id: "guardian-circle-alpha".into(),
        sender_did: other_did.clone(),
        manifest: dummy_manifest("guardian-circle-alpha", &other_did),
    };
    let accept = send_offer_and_read_accept(&addr, &offer).await;
    assert!(!accept.accept);
    assert!(accept
        .error
        .expect("error present")
        .contains("unexpected message kind"));

    // 2) Correct kind, wrong circle.
    offer.kind = xfer_protocol::KIND_OFFER.to_string();
    offer.circle_id = "some-other-circle".into();
    offer.manifest = dummy_manifest("some-other-circle", &other_did);
    let accept = send_offer_and_read_accept(&addr, &offer).await;
    assert!(!accept.accept);
    assert!(accept
        .error
        .expect("error present")
        .contains("circle mismatch"));

    // 3) Correct circle, sender_did equals the receiver's own DID.
    offer.circle_id = "guardian-circle-alpha".into();
    offer.sender_did = receiver.did.clone();
    offer.manifest = dummy_manifest("guardian-circle-alpha", &receiver.did);
    let accept = send_offer_and_read_accept(&addr, &offer).await;
    assert!(!accept.accept);
    assert!(accept
        .error
        .expect("error present")
        .contains("sender_did equals local DID"));

    // 4) Correct circle, distinct sender, but sender has no saved peer doc.
    offer.sender_did = other_did.clone();
    offer.manifest = dummy_manifest("guardian-circle-alpha", &other_did);
    let accept = send_offer_and_read_accept(&addr, &offer).await;
    assert!(!accept.accept);
    assert!(accept
        .error
        .expect("error present")
        .contains("sender not in local peer directory"));
}

// Sanity check that our shared identity helper produces a DID document the
// gossip peer-directory filter actually accepts (SGXNebulaMesh service +
// active status) — guards against the fixture silently drifting from the
// production schema and every "peer found" branch above going untested by
// accident.
#[test]
fn make_identity_helper_produces_active_mesh_peer() {
    let temp = tempfile::TempDir::new().expect("tempdir");
    let identity = make_identity(&temp, "sanity-node", 0x99, "127.0.0.1");
    assert_eq!(identity.doc.sgx_status.as_deref(), Some("active"));
    assert!(identity
        .doc
        .service
        .iter()
        .any(|svc| svc.svc_type == "SGXNebulaMesh" && svc.service_endpoint.contains("127.0.0.1")));
}
