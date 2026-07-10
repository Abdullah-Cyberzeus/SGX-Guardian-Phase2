use crate::did::doc_persistence::{
    self, CA_AGGREGATE_PATH_ENV, PEERS_DOC_DIR_ENV, SELF_DOC_PATH_ENV, VERSION_COUNTER_PATH_ENV,
};
use crate::did::doc_sign;
use crate::did::document::{DidDocument, DocBuildInput};
use crate::did::{Did, DidError, ResolutionSource, Resolver, ResolverConfig};
use crate::key_manager::KeyManager;
use crate::nebula::registry_sync::{RegistryRequest, RegistryResponse, REGISTRY_SYNC_PORT};
use base64::Engine as _;
use std::ffi::OsString;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

struct EnvGuard {
    self_doc_prev: Option<OsString>,
    peers_dir_prev: Option<OsString>,
    aggregate_prev: Option<OsString>,
    counter_prev: Option<OsString>,
}

impl EnvGuard {
    fn new(
        self_doc_path: &std::path::Path,
        peers_dir: &std::path::Path,
        aggregate: &std::path::Path,
    ) -> Self {
        let counter_path = self_doc_path.with_file_name("self_version_counter");
        let self_doc_prev = std::env::var_os(SELF_DOC_PATH_ENV);
        let peers_dir_prev = std::env::var_os(PEERS_DOC_DIR_ENV);
        let aggregate_prev = std::env::var_os(CA_AGGREGATE_PATH_ENV);
        let counter_prev = std::env::var_os(VERSION_COUNTER_PATH_ENV);
        std::env::set_var(SELF_DOC_PATH_ENV, self_doc_path);
        std::env::set_var(PEERS_DOC_DIR_ENV, peers_dir);
        std::env::set_var(CA_AGGREGATE_PATH_ENV, aggregate);
        std::env::set_var(VERSION_COUNTER_PATH_ENV, counter_path);
        Self {
            self_doc_prev,
            peers_dir_prev,
            aggregate_prev,
            counter_prev,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        restore_env(SELF_DOC_PATH_ENV, self.self_doc_prev.take());
        restore_env(PEERS_DOC_DIR_ENV, self.peers_dir_prev.take());
        restore_env(CA_AGGREGATE_PATH_ENV, self.aggregate_prev.take());
        restore_env(VERSION_COUNTER_PATH_ENV, self.counter_prev.take());
    }
}

fn restore_env(key: &str, value: Option<OsString>) {
    if let Some(value) = value {
        std::env::set_var(key, value);
    } else {
        std::env::remove_var(key);
    }
}

fn signed_doc_with_status(
    did: &str,
    node_name: &str,
    version: u32,
    current_dkp_version: u32,
    status: &str,
) -> DidDocument {
    let td = TempDir::new().expect("tempdir");
    let key_path = td.path().join("dkp.key");
    let km = KeyManager::load_or_generate(key_path.to_str().expect("key path")).expect("key");
    let der = km.pubkey_der().expect("pubkey der");
    let mut doc = DidDocument::build(DocBuildInput {
        did,
        node_name: Some(node_name),
        current_dkp_version,
        current_dkp_pubkey_der: &der,
        overlay_ip_cidr: Some("192.168.100.10/24"),
        attestation_bind: Some(("192.168.100.10", 50051)),
        cert_bootstrap_bind: Some(("192.168.100.10", 50061)),
        revoked: vec![],
        previous_version_id: version.saturating_sub(1),
        created_at: Some("2026-06-03T10:00:00Z".to_string()),
        status: Some(status.to_string()),
    })
    .expect("build did doc");
    let vm_ref = doc.verification_method[0].id.clone();
    doc_sign::sign_in_place(&mut doc, &km, &vm_ref).expect("sign did doc");
    doc
}

fn signed_doc(did: &str, node_name: &str, version: u32, current_dkp_version: u32) -> DidDocument {
    signed_doc_with_status(did, node_name, version, current_dkp_version, "active")
}

async fn spawn_mock_resolve_server(
    expected_did: String,
    doc: DidDocument,
) -> tokio::task::JoinHandle<()> {
    let listener = TcpListener::bind(("127.0.0.1", REGISTRY_SYNC_PORT))
        .await
        .expect("bind mock resolver");
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept resolve");
        let (reader, mut writer) = stream.into_split();
        let mut buffered = BufReader::new(reader);
        let mut line = String::new();
        buffered.read_line(&mut line).await.expect("read resolve");
        let request: RegistryRequest =
            serde_json::from_str(line.trim()).expect("resolve request json");
        assert_eq!(request.action, "resolve_did");
        assert_eq!(request.did_query.as_deref(), Some(expected_did.as_str()));

        let mut response = serde_json::to_string(&RegistryResponse {
            success: true,
            did_doc_json: Some(serde_json::to_string(&doc).expect("doc json")),
            ..RegistryResponse::default()
        })
        .expect("resolve response");
        response.push('\n');
        writer
            .write_all(response.as_bytes())
            .await
            .expect("write resolve response");
    })
}

fn resolver(ca_host: &str) -> Resolver {
    Resolver::new(ResolverConfig {
        ca_host: ca_host.to_string(),
        ..Default::default()
    })
}

#[tokio::test]
async fn resolves_from_local_peer_doc() {
    let _lock = doc_persistence::lock_test_env();
    let td = TempDir::new().expect("tempdir");
    let self_doc_path = td.path().join("identity").join("did_doc.json");
    let peers_dir = td.path().join("identity").join("peers");
    let aggregate = td.path().join("identity").join("circle_did_docs.json");
    let _env = EnvGuard::new(&self_doc_path, &peers_dir, &aggregate);

    let did = Did::from_id_bytes(&[11u8; 32]).to_string();
    let doc = signed_doc(&did, "nodeB", 4, 3);
    doc_persistence::save_peer(&doc).expect("save peer");

    let result = resolver("").resolve(&did).await.expect("resolve");
    assert_eq!(result.source, ResolutionSource::LocalPeerDoc);
    assert_eq!(result.did, did);
    assert_eq!(result.status, "active");
    assert_eq!(result.services.len(), 3);
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(result.public_key_der_b64)
            .expect("decode der")
            .len(),
        91
    );
}

#[tokio::test]
async fn mem_cache_hit_within_ttl() {
    let _lock = doc_persistence::lock_test_env();
    let td = TempDir::new().expect("tempdir");
    let self_doc_path = td.path().join("identity").join("did_doc.json");
    let peers_dir = td.path().join("identity").join("peers");
    let aggregate = td.path().join("identity").join("circle_did_docs.json");
    let _env = EnvGuard::new(&self_doc_path, &peers_dir, &aggregate);

    let did = Did::from_id_bytes(&[12u8; 32]).to_string();
    let doc = signed_doc(&did, "nodeB", 5, 4);
    doc_persistence::save_peer(&doc).expect("save peer");

    let resolver = resolver("");
    let first = resolver.resolve(&did).await.expect("first resolve");
    let second = resolver.resolve(&did).await.expect("second resolve");

    assert_eq!(first.source, ResolutionSource::LocalPeerDoc);
    assert_eq!(second.source, ResolutionSource::MemCache);
    assert!(second.ttl_remaining_sec > 0);
    assert!(second.ttl_remaining_sec <= 3600);
}

#[tokio::test]
async fn invalidate_refreshes_after_peer_doc_update() {
    let _lock = doc_persistence::lock_test_env();
    let td = TempDir::new().expect("tempdir");
    let self_doc_path = td.path().join("identity").join("did_doc.json");
    let peers_dir = td.path().join("identity").join("peers");
    let aggregate = td.path().join("identity").join("circle_did_docs.json");
    let _env = EnvGuard::new(&self_doc_path, &peers_dir, &aggregate);

    let did = Did::from_id_bytes(&[22u8; 32]).to_string();
    let original = signed_doc(&did, "nodeB", 5, 4);
    let updated = signed_doc(&did, "nodeB", 6, 5);
    doc_persistence::save_peer(&original).expect("save original peer");

    let resolver = resolver("");
    let first = resolver.resolve(&did).await.expect("first resolve");
    assert_eq!(first.source, ResolutionSource::LocalPeerDoc);
    assert_eq!(first.version_id, 5);
    assert_eq!(first.dkp_version, 4);

    doc_persistence::save_peer(&updated).expect("save updated peer");
    let stale = resolver
        .resolve(&did)
        .await
        .expect("stale mem-cache resolve");
    assert_eq!(stale.source, ResolutionSource::MemCache);
    assert_eq!(stale.version_id, 5);

    resolver.invalidate(&did).await;
    let refreshed = resolver.resolve(&did).await.expect("refreshed resolve");
    assert_eq!(refreshed.source, ResolutionSource::LocalPeerDoc);
    assert_eq!(refreshed.version_id, 6);
    assert_eq!(refreshed.dkp_version, 5);
}

#[tokio::test]
async fn rejected_aggregate_doc_does_not_seed_mem_cache() {
    let _lock = doc_persistence::lock_test_env();
    let td = TempDir::new().expect("tempdir");
    let self_doc_path = td.path().join("identity").join("did_doc.json");
    let peers_dir = td.path().join("identity").join("peers");
    let aggregate = td.path().join("identity").join("circle_did_docs.json");
    let _env = EnvGuard::new(&self_doc_path, &peers_dir, &aggregate);

    let did = Did::from_id_bytes(&[23u8; 32]).to_string();
    let current = signed_doc(&did, "nodeB", 6, 5);
    let stale = signed_doc(&did, "nodeB", 5, 4);
    doc_persistence::save_self(&current).expect("save self");
    doc_persistence::write_self_floor_version(current.sgx_version_id)
        .expect("write self floor version");
    doc_persistence::save_ca_aggregate(&[stale]).expect("save stale aggregate");

    let resolver = resolver("");
    let err = resolver
        .resolve(&did)
        .await
        .expect_err("stale aggregate should fail replay protection");
    assert!(matches!(
        err,
        DidError::ReplayedOldVersion {
            incoming: 5,
            known: 6
        }
    ));

    doc_persistence::save_ca_aggregate(&[]).expect("clear aggregate");
    let err = resolver
        .resolve(&did)
        .await
        .expect_err("stale aggregate must not be cached");
    assert!(matches!(err, DidError::Unresolvable(ref value) if value == &did));
}

#[tokio::test]
async fn resolves_from_local_aggregate() {
    let _lock = doc_persistence::lock_test_env();
    let td = TempDir::new().expect("tempdir");
    let self_doc_path = td.path().join("identity").join("did_doc.json");
    let peers_dir = td.path().join("identity").join("peers");
    let aggregate = td.path().join("identity").join("circle_did_docs.json");
    let _env = EnvGuard::new(&self_doc_path, &peers_dir, &aggregate);

    let did = Did::from_id_bytes(&[13u8; 32]).to_string();
    let doc = signed_doc(&did, "nodeC", 3, 2);
    doc_persistence::save_ca_aggregate(&[doc]).expect("save aggregate");

    let result = resolver("").resolve(&did).await.expect("resolve");
    assert_eq!(result.source, ResolutionSource::LocalAggregate);
    assert_eq!(result.did, did);
}

#[tokio::test]
async fn resolves_from_ca_network() {
    let _lock = doc_persistence::lock_test_env();
    let td = TempDir::new().expect("tempdir");
    let self_doc_path = td.path().join("identity").join("did_doc.json");
    let peers_dir = td.path().join("identity").join("peers");
    let aggregate = td.path().join("identity").join("circle_did_docs.json");
    let _env = EnvGuard::new(&self_doc_path, &peers_dir, &aggregate);

    let did = Did::from_id_bytes(&[14u8; 32]).to_string();
    let doc = signed_doc(&did, "nodeD", 6, 5);
    let handle = spawn_mock_resolve_server(did.clone(), doc).await;

    let result = resolver("127.0.0.1").resolve(&did).await.expect("resolve");
    handle.await.expect("mock server");

    assert_eq!(result.source, ResolutionSource::CaNetwork);
    assert_eq!(result.did, did);
}

#[tokio::test]
async fn unreachable_ca_network_returns_friendly_message() {
    let _lock = doc_persistence::lock_test_env();
    let td = TempDir::new().expect("tempdir");
    let self_doc_path = td.path().join("identity").join("did_doc.json");
    let peers_dir = td.path().join("identity").join("peers");
    let aggregate = td.path().join("identity").join("circle_did_docs.json");
    let _env = EnvGuard::new(&self_doc_path, &peers_dir, &aggregate);

    let did = Did::from_id_bytes(&[15u8; 32]).to_string();
    let resolver = Resolver::new(ResolverConfig {
        ca_host: "203.0.113.1".to_string(),
        network_timeout: Duration::from_millis(10),
        ..Default::default()
    });

    let err = resolver.resolve(&did).await.expect_err("unreachable ca");
    match err {
        DidError::ResolutionFailed(message) => {
            assert_eq!(message, "CA registry unavailable at 203.0.113.1:50062.");
        }
        other => panic!("expected resolution failure, got {other:?}"),
    }
}

#[tokio::test]
async fn reject_deactivated_mode_returns_deactivated_error() {
    let _lock = doc_persistence::lock_test_env();
    let td = TempDir::new().expect("tempdir");
    let self_doc_path = td.path().join("identity").join("did_doc.json");
    let peers_dir = td.path().join("identity").join("peers");
    let aggregate = td.path().join("identity").join("circle_did_docs.json");
    let _env = EnvGuard::new(&self_doc_path, &peers_dir, &aggregate);

    let did = Did::from_id_bytes(&[23u8; 32]).to_string();
    let doc = signed_doc_with_status(&did, "nodeE", 7, 6, "deactivated");
    doc_persistence::save_peer(&doc).expect("save deactivated peer");

    let err = Resolver::new(ResolverConfig {
        reject_deactivated: true,
        ..Default::default()
    })
    .resolve(&did)
    .await
    .expect_err("reject deactivated");

    assert!(matches!(err, DidError::Deactivated(_)));
}

#[tokio::test]
async fn malformed_did_returns_invalid_format() {
    let _lock = doc_persistence::lock_test_env();
    let err = resolver("")
        .resolve("did:guardian:FAKE123")
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        DidError::Base58(_) | DidError::InvalidFormat(_)
    ));
}
