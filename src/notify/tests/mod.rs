use super::bus;
use super::model::{NotificationEvent, NotificationKind};
use super::prefs::NotificationPrefs;
use super::store::{configured_max_events, NotificationStore};
use crate::did::doc_persistence;
use crate::did::doc_sign;
use crate::did::document::{DidDocument, DocBuildInput};
use crate::did::{Did, DidRecord};
use crate::key_manager::KeyManager;
use crate::notify::NotifyConfig;
use crate::vc::issue::DEVICE_KEY_DIR_ENV;
use chrono::Utc;
use std::sync::{Mutex, OnceLock};
use tempfile::TempDir;
use tokio::time::{timeout, Duration};

static TEST_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

struct NotifyEnv {
    _guard: std::sync::MutexGuard<'static, ()>,
    _did_guard: std::sync::MutexGuard<'static, ()>,
    _td: TempDir,
    restore: Vec<(&'static str, Option<String>)>,
    node_id: String,
}

impl NotifyEnv {
    fn new(node_id: &str, seed: u8) -> Self {
        let guard = TEST_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let did_guard = doc_persistence::lock_test_env();
        let td = TempDir::new().expect("notify tempdir");
        let base = td.path();
        let notify_base = base.join("notify");
        let identity_dir = base.join("identity");
        let did_path = identity_dir.join("did.json");
        let self_doc_path = identity_dir.join("did_doc.json");
        let peers_dir = identity_dir.join("peers");
        let aggregate_path = identity_dir.join("circle_did_docs.json");
        let floor_path = identity_dir.join("self_version");
        let key_dir = base.join("keys");
        std::fs::create_dir_all(&peers_dir).expect("peers dir");
        std::fs::create_dir_all(&key_dir).expect("key dir");
        std::fs::create_dir_all(&notify_base).expect("notify dir");

        let restore = vec![
            (
                "SGX_GUARDIAN_NOTIFY_BASE",
                std::env::var("SGX_GUARDIAN_NOTIFY_BASE").ok(),
            ),
            (
                "SGX_NOTIFY_MAX_EVENTS",
                std::env::var("SGX_NOTIFY_MAX_EVENTS").ok(),
            ),
            (
                "SGX_GUARDIAN_DID_PATH",
                std::env::var("SGX_GUARDIAN_DID_PATH").ok(),
            ),
            (
                crate::did::doc_persistence::SELF_DOC_PATH_ENV,
                std::env::var(crate::did::doc_persistence::SELF_DOC_PATH_ENV).ok(),
            ),
            (
                crate::did::doc_persistence::PEERS_DOC_DIR_ENV,
                std::env::var(crate::did::doc_persistence::PEERS_DOC_DIR_ENV).ok(),
            ),
            (
                crate::did::doc_persistence::CA_AGGREGATE_PATH_ENV,
                std::env::var(crate::did::doc_persistence::CA_AGGREGATE_PATH_ENV).ok(),
            ),
            (
                crate::did::doc_persistence::VERSION_COUNTER_PATH_ENV,
                std::env::var(crate::did::doc_persistence::VERSION_COUNTER_PATH_ENV).ok(),
            ),
            (DEVICE_KEY_DIR_ENV, std::env::var(DEVICE_KEY_DIR_ENV).ok()),
        ];

        std::env::set_var("SGX_GUARDIAN_NOTIFY_BASE", &notify_base);
        std::env::set_var("SGX_GUARDIAN_DID_PATH", &did_path);
        std::env::set_var(
            crate::did::doc_persistence::SELF_DOC_PATH_ENV,
            &self_doc_path,
        );
        std::env::set_var(crate::did::doc_persistence::PEERS_DOC_DIR_ENV, &peers_dir);
        std::env::set_var(
            crate::did::doc_persistence::CA_AGGREGATE_PATH_ENV,
            &aggregate_path,
        );
        std::env::set_var(
            crate::did::doc_persistence::VERSION_COUNTER_PATH_ENV,
            &floor_path,
        );
        std::env::set_var(DEVICE_KEY_DIR_ENV, &key_dir);

        let key_path = key_dir.join(format!("device_{}.key", node_id));
        let km = KeyManager::load_or_generate(key_path.to_str().expect("key path")).expect("key");
        let pubkey = km.pubkey_der().expect("pubkey");
        let did = Did::from_id_bytes(&[seed; 32]);
        let did_str = did.to_string();
        let now = Utc::now().to_rfc3339();
        let record = DidRecord {
            did: did_str.clone(),
            method: "guardian".into(),
            method_version: "1.0".into(),
            did_id_b58: did.msi().to_string(),
            did_id_hex: hex::encode(did.id_bytes()),
            created_at: now.clone(),
            deactivated_at: None,
            derivation: crate::did::persistence::DerivationProof {
                se050_uid: "01".into(),
                se050_uid_source: "test".into(),
                dkp_v1_pubkey_sha256_b16: "01".into(),
                dkp_v1_pubkey_path: "test".into(),
                dkp_v1_pubkey_der_b64: None,
                dik_pubkey_sha256_b16: "01".into(),
                dik_pubkey_der_b64: None,
            },
            current_dkp_version: 1,
            deriv_signature_b64: String::new(),
        };
        record
            .save(did_path.to_str().expect("did path"))
            .expect("save did record");

        let mut doc = DidDocument::build(DocBuildInput {
            did: &did_str,
            node_name: Some(node_id),
            current_dkp_version: 1,
            current_dkp_pubkey_der: &pubkey,
            overlay_ip_cidr: Some("127.0.0.1/32"),
            attestation_bind: None,
            cert_bootstrap_bind: None,
            revoked: vec![],
            previous_version_id: 0,
            created_at: Some(now),
            status: Some("active".into()),
        })
        .expect("build did doc");
        let vm_ref = doc.verification_method.first().expect("vm").id.clone();
        doc_sign::sign_in_place(&mut doc, &km, &vm_ref).expect("sign did doc");
        doc_persistence::save_self(&doc).expect("save self doc");

        Self {
            _guard: guard,
            _did_guard: did_guard,
            _td: td,
            restore,
            node_id: node_id.to_string(),
        }
    }
}

impl Drop for NotifyEnv {
    fn drop(&mut self) {
        for (key, value) in self.restore.drain(..) {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

#[tokio::test]
async fn publish_is_non_blocking_without_subscribers() {
    bus::publish(sample_event("1", NotificationKind::AlertLow));
}

#[tokio::test]
async fn subscribe_receives_published_events() {
    let mut rx = bus::subscribe();
    let event = sample_event("2", NotificationKind::AlertHigh);
    bus::publish(event.clone());
    let received = timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("receive timeout")
        .expect("receive event");
    assert_eq!(received.id, event.id);
    assert_eq!(received.kind, event.kind);
}

/// The notify bus is one process-global broadcast channel (see
/// `notify::bus`), shared by every test in this binary — so a subscriber can
/// observe events published by other tests running concurrently. Filter by
/// `ref_id` (unique per call below) instead of assuming the next `recv()` is
/// necessarily ours.
async fn recv_by_ref_id(
    rx: &mut tokio::sync::broadcast::Receiver<NotificationEvent>,
    ref_id: &str,
) -> NotificationEvent {
    loop {
        let event = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("receive timeout")
            .expect("receive event");
        if event.ref_id.as_deref() == Some(ref_id) {
            return event;
        }
    }
}

#[tokio::test]
async fn publish_circle_helpers_broadcast_the_right_kind() {
    let mut rx = bus::subscribe();

    super::publish_circle_new_message(
        "did:guardian:alice",
        "did:guardian:alice",
        "publish-helpers-msg-1",
    );
    let event = recv_by_ref_id(&mut rx, "publish-helpers-msg-1").await;
    assert_eq!(event.kind, NotificationKind::CircleNewMessage);
    assert_eq!(event.actor_did.as_deref(), Some("did:guardian:alice"));

    super::publish_circle_incoming_call(
        "did:guardian:bob",
        "did:guardian:bob",
        "publish-helpers-call-1",
    );
    let event = recv_by_ref_id(&mut rx, "publish-helpers-call-1").await;
    assert_eq!(event.kind, NotificationKind::CircleIncomingCall);

    super::publish_circle_member_joined(
        "did:guardian:alice",
        "Alice",
        "Family",
        "publish-helpers-circle-1",
    );
    let event = recv_by_ref_id(&mut rx, "publish-helpers-circle-1").await;
    assert_eq!(event.kind, NotificationKind::CircleMemberJoined);
    assert!(event.body.contains("Alice") && event.body.contains("Family"));

    super::publish_circle_file_shared(
        "did:guardian:carol",
        "did:guardian:carol",
        "report.pdf",
        "urn:uuid:publish-helpers-vault-1",
    );
    let event = recv_by_ref_id(&mut rx, "urn:uuid:publish-helpers-vault-1").await;
    assert_eq!(event.kind, NotificationKind::CircleFileShared);
}

#[test]
fn prefs_filter_mapping_matches_kinds() {
    let mut prefs = NotificationPrefs::default();
    assert!(prefs.allows(NotificationKind::AlertHigh));
    prefs.alerts.high = false;
    prefs.devices.pending_approval = false;
    prefs.circles.new_message = false;
    assert!(!prefs.allows(NotificationKind::AlertHigh));
    assert!(!prefs.allows(NotificationKind::DevicePendingApproval));
    assert!(!prefs.allows(NotificationKind::CircleFileShared));
    assert!(prefs.allows(NotificationKind::CircleIncomingCall));
}

#[test]
fn signed_prefs_round_trip_and_tamper_rejected() {
    let env = NotifyEnv::new("nodeA", 41);
    let path = NotifyConfig::from_env().prefs_path();
    let prefs = NotificationPrefs::create_signed_default(&env.node_id).expect("sign prefs");
    prefs.verify().expect("verify signed prefs");
    prefs.save_atomic(&path).expect("save prefs");
    let loaded = NotificationPrefs::load_from_path(&path)
        .expect("load prefs")
        .expect("prefs should exist");
    assert_eq!(loaded.sequence, 1);

    let mut tampered = loaded.clone();
    tampered.alerts.high = false;
    let bytes = serde_json::to_vec_pretty(&tampered).expect("serialize tampered");
    std::fs::write(&path, bytes).expect("write tampered");
    assert!(NotificationPrefs::load_from_path(&path).is_err());
}

#[test]
fn store_eviction_round_trip_and_replay_after() {
    let _env = NotifyEnv::new("nodeA", 42);
    std::env::set_var("SGX_NOTIFY_MAX_EVENTS", "2");
    assert_eq!(configured_max_events(), 2);

    let path = NotifyConfig::from_env().events_path();
    let mut store = NotificationStore::default();
    store.append(sample_event("1", NotificationKind::AlertLow), 2);
    store.append(sample_event("2", NotificationKind::AlertMedium), 2);
    store.append(sample_event("3", NotificationKind::DeviceDiscovered), 2);
    store.save_atomic(&path).expect("save events");

    let loaded = NotificationStore::load_from_path(&path, 2).expect("load events");
    let history = loaded.history(10);
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].id, "3");
    assert_eq!(history[1].id, "2");

    let replay = loaded.replay_after("2");
    assert_eq!(replay.len(), 1);
    assert_eq!(replay[0].id, "3");
    assert_eq!(loaded.unread_count(), 2);
}

#[test]
fn mark_read_and_mark_all_read_update_counts() {
    let _env = NotifyEnv::new("nodeA", 43);
    let path = NotifyConfig::from_env().events_path();
    let mut store = NotificationStore::default();
    store.append(sample_event("11", NotificationKind::AlertLow), 10);
    store.append(sample_event("12", NotificationKind::AlertMedium), 10);
    assert!(store.mark_read("11"));
    assert_eq!(store.unread_count(), 1);
    assert_eq!(store.mark_all_read(), 1);
    assert_eq!(store.unread_count(), 0);
    store.save_atomic(&path).expect("save read state");
    let loaded = NotificationStore::load_from_path(&path, 10).expect("reload read state");
    assert_eq!(loaded.unread_count(), 0);
}

fn sample_event(id: &str, kind: NotificationKind) -> NotificationEvent {
    NotificationEvent {
        id: id.to_string(),
        kind,
        title: "sample".into(),
        body: "sample body".into(),
        severity: "info".into(),
        ref_id: None,
        created_at: Utc::now().to_rfc3339(),
        read: false,
        actor_did: None,
    }
}
