use serde_json::json;
use sgx_guardian_client::call::nebula_signaling::NebulaClient;
use sgx_guardian_client::call::{
    CallAnswer, CallOffer, CallState, MediaType, NebulaSignaling, SessionManager,
};
use sgx_guardian_client::key_manager::KeyManager;
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn test_offline_call_offer_answer_flow() {
    let temp = tempdir().expect("create temp dir");
    let key_path = temp.path().join("offline_test_key.pk8");
    let key_manager = KeyManager::load_or_generate(key_path.to_str().unwrap()).expect("load key");

    let session_manager = SessionManager::new();
    let session_id = session_manager
        .create_session(
            "offline-initiator".to_string(),
            "offline-virtual".to_string(),
            "offline-receiver".to_string(),
            "offline-virtual-receiver".to_string(),
            vec![MediaType::Audio],
            "nonce-offline".to_string(),
        )
        .await
        .expect("create session");

    let offer = CallOffer::new(
        "offline-initiator".to_string(),
        "offline-virtual".to_string(),
        session_id.clone(),
        "nonce-offline".to_string(),
        vec![MediaType::Audio],
        &key_manager,
    )
    .await
    .expect("create offer");

    let signaling = NebulaSignaling::new(Arc::new(NebulaClient));
    let offer_message = json!({
        "type": "call_offer",
        "device_id": offer.device_id,
        "virtual_id": offer.virtual_id,
        "session_id": offer.session_id,
        "timestamp": offer.timestamp.to_rfc3339(),
        "nonce": offer.nonce,
        "requested_media": offer.requested_media,
        "signature": offer.signature,
    })
    .to_string();

    let parsed = signaling
        .handle_message(&offer_message)
        .await
        .expect("parse offer message");
    match parsed {
        sgx_guardian_client::call::nebula_signaling::SignalingMessage::Offer(parsed_offer) => {
            assert_eq!(parsed_offer.session_id, session_id);
            assert_eq!(parsed_offer.device_id, "offline-initiator");
        }
        _ => panic!("Expected offer message"),
    }

    let answer = CallAnswer::accept(
        "offline-receiver".to_string(),
        "offline-virtual-receiver".to_string(),
        session_id.clone(),
        "nonce-offline".to_string(),
        vec![MediaType::Audio],
        &key_manager,
    )
    .await
    .expect("create answer");

    let answer_message = json!({
        "type": "call_answer",
        "device_id": answer.device_id,
        "virtual_id": answer.virtual_id,
        "session_id": answer.session_id,
        "timestamp": answer.timestamp.to_rfc3339(),
        "nonce": answer.nonce,
        "accepted_media": answer.accepted_media,
        "accepted": answer.accepted,
        "rejection_reason": answer.rejection_reason,
        "signature": answer.signature,
    })
    .to_string();

    let parsed_answer = signaling
        .handle_message(&answer_message)
        .await
        .expect("parse answer message");
    match parsed_answer {
        sgx_guardian_client::call::nebula_signaling::SignalingMessage::Answer(answer) => {
            assert!(answer.accepted);
        }
        _ => panic!("Expected answer message"),
    }

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
        .expect("update offer sent");
    session_manager
        .update_session_state(&session_id, CallState::Verifying, "Verifying".to_string())
        .await
        .expect("update verifying");
    session_manager
        .update_session_state(
            &session_id,
            CallState::Authorizing,
            "Authorizing".to_string(),
        )
        .await
        .expect("update authorizing");
    session_manager
        .update_session_state(&session_id, CallState::Accepted, "Accepted".to_string())
        .await
        .expect("update accepted");
}
