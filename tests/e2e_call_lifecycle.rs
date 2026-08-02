use sgx_guardian_client::call::{CallAnswer, CallOffer, CallState, MediaType, SessionManager};
use sgx_guardian_client::key_manager::KeyManager;
use tempfile::tempdir;

#[tokio::test]
async fn test_full_call_lifecycle_happy_path() {
    let temp = tempdir().expect("create temp dir");
    let key_path = temp.path().join("node_key.pk8");
    let key_manager = KeyManager::load_or_generate(key_path.to_str().unwrap()).expect("load key");

    let session_manager = SessionManager::new();
    let session_id = session_manager
        .create_session(
            "initiator-node".to_string(),
            "initiator-virtual".to_string(),
            "receiver-node".to_string(),
            "receiver-virtual".to_string(),
            vec![MediaType::Audio, MediaType::Video],
            "nonce-e2e".to_string(),
        )
        .await
        .expect("create session");

    let offer = CallOffer::new(
        "initiator-node".to_string(),
        "initiator-virtual".to_string(),
        session_id.clone(),
        "nonce-e2e".to_string(),
        vec![MediaType::Audio, MediaType::Video],
        &key_manager,
    )
    .await
    .expect("create offer");

    let offer_json = offer.to_json().expect("serialize offer");
    let parsed_offer = CallOffer::from_json(&offer_json).expect("deserialize offer");
    assert_eq!(parsed_offer.session_id, session_id);
    assert_eq!(
        parsed_offer.requested_media,
        vec![MediaType::Audio, MediaType::Video]
    );

    session_manager
        .update_session_state(
            &session_id,
            CallState::LocalPolicyCheck,
            "Local policy check".to_string(),
        )
        .await
        .expect("update local policy");
    session_manager
        .update_session_state(&session_id, CallState::OfferSent, "Offer sent".to_string())
        .await
        .expect("update state");

    let answer = CallAnswer::accept(
        "receiver-node".to_string(),
        "receiver-virtual".to_string(),
        session_id.clone(),
        "nonce-e2e".to_string(),
        vec![MediaType::Audio],
        &key_manager,
    )
    .await
    .expect("create answer");

    let answer_json = answer.to_json().expect("serialize answer");
    let parsed_answer = CallAnswer::from_json(&answer_json).expect("deserialize answer");
    assert!(parsed_answer.accepted);
    assert_eq!(parsed_answer.accepted_media, vec![MediaType::Audio]);

    session_manager
        .update_session_state(&session_id, CallState::Verifying, "Verifying".to_string())
        .await
        .expect("verifying state");
    session_manager
        .update_session_state(
            &session_id,
            CallState::Authorizing,
            "Authorizing".to_string(),
        )
        .await
        .expect("authorizing state");
    session_manager
        .update_session_state(
            &session_id,
            CallState::Accepted,
            "Call accepted".to_string(),
        )
        .await
        .expect("accept state");
    session_manager
        .update_session_state(
            &session_id,
            CallState::MediaNegotiation,
            "Media negotiation".to_string(),
        )
        .await
        .expect("media negotiation state");
    session_manager
        .update_session_state(&session_id, CallState::Connected, "Connected".to_string())
        .await
        .expect("connected state");
    session_manager
        .end_session(&session_id)
        .await
        .expect("end call");

    let session = session_manager
        .get_session(&session_id)
        .await
        .expect("retrieve session");
    assert_eq!(session.state, CallState::EndCall);
    assert!(session.duration_seconds() >= 0);
    assert!(
        session
            .get_state_history()
            .contains("OfferSent -> Accepted")
            || session
                .get_state_history()
                .contains("Accepted -> MediaNegotiation")
    );
}
