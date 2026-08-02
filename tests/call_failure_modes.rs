use async_trait::async_trait;
use sgx_guardian_client::call::policy::PolicyEnforcer;
use sgx_guardian_client::call::{CallOffer, CallSession, CallState, MediaType, SessionManager};
use sgx_guardian_client::key_manager::KeyManager;
use std::sync::Arc;
use tempfile::tempdir;

struct DenyEnforcer;

#[async_trait]
impl PolicyEnforcer for DenyEnforcer {
    async fn allow_call(
        &self,
        _session: &CallSession,
    ) -> sgx_guardian_client::call::CallResult<bool> {
        Ok(false)
    }
}

#[test]
fn test_empty_requested_media_fails() {
    let result = CallSession::new(
        "device1".to_string(),
        "virtual1".to_string(),
        "device2".to_string(),
        "virtual2".to_string(),
        vec![],
        "nonce123".to_string(),
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn test_policy_denied_call_state() {
    let manager = SessionManager::with_enforcer(Arc::new(DenyEnforcer));
    let session_id = manager
        .create_session(
            "device1".to_string(),
            "virtual1".to_string(),
            "device2".to_string(),
            "virtual2".to_string(),
            vec![MediaType::Audio],
            "nonce123".to_string(),
        )
        .await
        .expect("create session");

    let result = manager
        .update_session_state(
            &session_id,
            CallState::Accepted,
            "policy denied".to_string(),
        )
        .await;
    assert!(result.is_err());
}

#[test]
fn test_invalid_state_transition_fails() {
    let mut session = CallSession::new(
        "device1".to_string(),
        "virtual1".to_string(),
        "device2".to_string(),
        "virtual2".to_string(),
        vec![MediaType::Audio],
        "nonce123".to_string(),
    )
    .unwrap();

    let result = session.transition(CallState::Connected, "invalid jump".to_string());
    assert!(result.is_err());
}

#[tokio::test]
async fn test_receiver_acceptance_rejects_empty_media() {
    let mut session = CallSession::new(
        "device1".to_string(),
        "virtual1".to_string(),
        "device2".to_string(),
        "virtual2".to_string(),
        vec![MediaType::Audio],
        "nonce123".to_string(),
    )
    .unwrap();

    let result = session.receiver_accepted(vec![]);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_offer_signature_rejects_missing_fields() {
    let temp = tempdir().expect("create temp dir");
    let key_path = temp.path().join("offline_key.pk8");
    let key_manager = KeyManager::load_or_generate(key_path.to_str().unwrap()).expect("load key");

    let offer = CallOffer::new(
        "".to_string(),
        "virtual1".to_string(),
        "session1".to_string(),
        "nonce123".to_string(),
        vec![MediaType::Audio],
        &key_manager,
    )
    .await;
    assert!(offer.is_err());
}
