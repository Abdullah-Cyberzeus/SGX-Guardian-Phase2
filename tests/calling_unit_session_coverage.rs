use chrono::{Duration, Utc};
use sgx_guardian_client::call::{
    CallError, CallHistoryStore, CallSession, CallSessionStatus, CallState, MediaType,
    SessionManager,
};
use std::sync::Arc;
use tempfile::tempdir;

fn new_session() -> CallSession {
    CallSession::new(
        "node-a".into(),
        "vid-a".into(),
        "node-b".into(),
        "vid-b".into(),
        vec![MediaType::Audio, MediaType::Video],
        "nonce-session".into(),
    )
    .expect("valid call session")
}

async fn manager_at_media_negotiation(manager: &SessionManager) -> String {
    let id = manager
        .create_session(
            "node-a".into(),
            "vid-a".into(),
            "node-b".into(),
            "vid-b".into(),
            vec![MediaType::Audio, MediaType::Video],
            "nonce-manager".into(),
        )
        .await
        .expect("create session");
    manager
        .set_receiver_acceptance(&id, "vid-b-confirmed".into(), vec![MediaType::Audio])
        .await
        .expect("accept media");
    for state in [
        CallState::LocalPolicyCheck,
        CallState::OfferSent,
        CallState::Verifying,
        CallState::Authorizing,
        CallState::Accepted,
        CallState::MediaNegotiation,
    ] {
        manager
            .update_session_state(&id, state, format!("advance to {state}"))
            .await
            .expect("valid lifecycle transition");
    }
    id
}

#[test]
fn session_validates_media_nonce_acceptance_and_safe_snapshot() {
    assert!(CallSession::new(
        "a".into(),
        "va".into(),
        "b".into(),
        "vb".into(),
        vec![],
        "nonce".into(),
    )
    .is_err());

    let mut session = new_session();
    assert_eq!(session.state, CallState::Idle);
    assert_eq!(session.duration_seconds(), 0);
    session.use_nonce().expect("first nonce use");
    assert!(matches!(
        session.use_nonce(),
        Err(CallError::NonceReused { .. })
    ));
    assert!(session.receiver_accepted(vec![]).is_err());
    session
        .receiver_accepted(vec![MediaType::Audio])
        .expect("receiver accepts audio");

    let snapshot = session.status_snapshot();
    assert_eq!(snapshot.state, "idle");
    assert_eq!(
        snapshot.requested_media,
        vec![MediaType::Audio, MediaType::Video]
    );
    assert_eq!(snapshot.accepted_media, vec![MediaType::Audio]);
    let json = serde_json::to_value(snapshot).expect("serialize public status");
    assert!(json.get("nonce").is_none());
    assert!(json.get("initiator_nebula_ip").is_none());
}

#[test]
fn direct_session_tracks_timing_history_and_terminal_state() {
    let mut session = new_session();
    session
        .transition(CallState::LocalPolicyCheck, "policy".into())
        .unwrap();
    session
        .transition(CallState::OfferSent, "offer".into())
        .unwrap();
    session
        .transition(CallState::Verifying, "verify".into())
        .unwrap();
    session
        .transition(CallState::Authorizing, "authorize".into())
        .unwrap();
    session
        .transition(CallState::Accepted, "accepted".into())
        .unwrap();
    session
        .transition(CallState::MediaNegotiation, "webrtc".into())
        .unwrap();
    session
        .transition(CallState::Connected, "media".into())
        .unwrap();
    session.started_at = Some(Utc::now() - Duration::seconds(8));
    session
        .transition(CallState::EndCall, "hangup".into())
        .unwrap();

    assert!(session.duration_seconds() >= 8);
    assert!(session.state.is_terminal());
    assert!(session.get_state_history().contains("Connected -> EndCall"));
    assert!(session.status_snapshot().terminal);
    assert!(session
        .transition(CallState::Idle, "illegal".into())
        .is_err());
}

#[tokio::test]
async fn manager_connects_only_after_both_media_endpoints_are_ready() {
    let manager = SessionManager::new();
    let id = manager_at_media_negotiation(&manager).await;

    assert!(!manager.mark_media_ready(&id, true).await.unwrap());
    assert_eq!(
        manager.get_session(&id).await.unwrap().state,
        CallState::MediaNegotiation
    );
    assert!(manager.mark_media_ready(&id, false).await.unwrap());
    assert_eq!(
        manager.get_session(&id).await.unwrap().state,
        CallState::Connected
    );
    assert!(manager.mark_media_ready("missing", true).await.is_err());

    manager.end_session(&id).await.unwrap();
    manager
        .end_session(&id)
        .await
        .expect("ending is idempotent");
    assert!(manager.get_active_sessions().await.is_empty());
    assert_eq!(manager.list_statuses().await.len(), 1);
}

#[tokio::test]
async fn manager_requires_matching_dtls_fingerprints_for_both_participants() {
    let manager = SessionManager::new();
    let id = manager_at_media_negotiation(&manager).await;
    manager
        .record_signaled_fingerprint(&id, "node-a", "AA:AA".into())
        .await
        .unwrap();
    manager
        .record_signaled_fingerprint(&id, "node-b", "BB:BB".into())
        .await
        .unwrap();

    assert!(!manager
        .confirm_dtls_fingerprint(&id, "node-a", "wrong".into())
        .await
        .unwrap());
    assert!(!manager
        .confirm_dtls_fingerprint(&id, "node-b", "BB:BB".into())
        .await
        .unwrap());
    assert!(!manager
        .get_session(&id)
        .await
        .unwrap()
        .encryption_verified());
    assert!(manager
        .confirm_dtls_fingerprint(&id, "node-a", "AA:AA".into())
        .await
        .unwrap());
    assert!(manager
        .get_session(&id)
        .await
        .unwrap()
        .encryption_verified());
    assert!(manager
        .confirm_dtls_fingerprint(&id, "outsider", "CC:CC".into())
        .await
        .is_err());
}

#[tokio::test]
async fn manager_updates_receiver_identity_endpoints_and_emits_events() {
    let manager = SessionManager::new();
    let mut events = manager.subscribe();
    let id = manager
        .create_session(
            "node-a".into(),
            "vid-a".into(),
            "placeholder".into(),
            "".into(),
            vec![MediaType::Audio],
            "nonce-events".into(),
        )
        .await
        .unwrap();
    assert_eq!(events.recv().await.unwrap().event, "call_created");

    manager
        .set_nebula_endpoints(
            &id,
            Some("192.168.100.1".into()),
            Some("192.168.100.2".into()),
        )
        .await
        .unwrap();
    assert!(manager
        .set_receiver_acceptance_with_device(&id, "".into(), vec![MediaType::Audio], None)
        .await
        .is_err());
    manager
        .set_receiver_acceptance_with_device(
            &id,
            "vid-b".into(),
            vec![MediaType::Audio],
            Some("node-b".into()),
        )
        .await
        .unwrap();
    assert_eq!(events.recv().await.unwrap().event, "call_media_accepted");
    manager.notify(&id, "test_event").await.unwrap();
    assert_eq!(events.recv().await.unwrap().event, "test_event");

    let session = manager.get_session(&id).await.unwrap();
    assert_eq!(session.receiver.device_id, "node-b");
    assert_eq!(session.receiver.virtual_id, "vid-b");
    assert_eq!(session.receiver_nebula_ip.as_deref(), Some("192.168.100.2"));
}

#[test]
fn history_store_normalizes_outcomes_media_and_upserts() {
    let dir = tempdir().unwrap();
    let store = Arc::new(CallHistoryStore::new(dir.path().join("calls.json")));
    assert_eq!(store.path(), dir.path().join("calls.json"));
    assert!(store.list().is_empty());
    let now = Utc::now();
    let mut status = CallSessionStatus {
        session_id: "call-1".into(),
        state: "ended".into(),
        terminal: true,
        media_connected: false,
        initiator_device_id: "node-a".into(),
        receiver_device_id: "node-b".into(),
        requested_media: vec![MediaType::Audio, MediaType::Video],
        accepted_media: vec![],
        created_at: now - Duration::seconds(5),
        updated_at: now,
        started_at: None,
        ended_at: Some(now),
        duration_seconds: 0,
        local_media_ready: false,
        remote_media_ready: false,
        encryption_verified: false,
    };
    store.record_direct(&status);
    assert_eq!(store.list()[0].outcome, "cancelled");
    assert_eq!(
        store.list()[0].media,
        vec![MediaType::Audio, MediaType::Video]
    );

    status.duration_seconds = 5;
    status.accepted_media = vec![MediaType::Audio];
    store.record_direct(&status);
    let records = store.list();
    assert_eq!(records.len(), 1, "same call ID must be upserted");
    assert_eq!(records[0].outcome, "completed");
    assert_eq!(records[0].media, vec![MediaType::Audio]);
}
