use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sgx_guardian_client::chat::models::{ChatMessageRecord, MessageStatus};
use sgx_guardian_client::chat::storage::{
    append_group_message, append_p2p_message, read_group_history, read_p2p_history,
};

async fn setup_test_dirs() {
    let path = "/tmp/sgx-guardian-chat-tests";
    std::env::set_var("CHAT_STORAGE_DIR", path);
    let _ = tokio::fs::create_dir_all(format!("{}/p2p", path)).await;
    let _ = tokio::fs::create_dir_all(format!("{}/group", path)).await;
}

#[tokio::test]
async fn test_storage_concurrency_p2p() {
    setup_test_dirs().await;
    let peer_did = "did:guardian:test_peer_concurrent";

    let path = "/tmp/sgx-guardian-chat-tests";
    let safe_name = URL_SAFE_NO_PAD.encode(peer_did.as_bytes());
    let _ = tokio::fs::remove_file(format!("{}/p2p/{}.jsonl", path, safe_name)).await;

    let mut handles = vec![];

    // Spawn 50 tasks trying to append simultaneously
    for i in 0..50 {
        let handle = tokio::spawn(async move {
            let record = ChatMessageRecord {
                message_id: format!("msg_{}", i),
                sender_did: "did:guardian:me".to_string(),
                recipient_did: "did:guardian:test_peer_concurrent".to_string(),
                group_id: None,
                timestamp: 1672531200,
                seq_no: i,
                encrypted_payload: "encrypted_data".to_string(),
                signature: "sig".to_string(),
                status: MessageStatus::Delivered,
                read_by: Vec::new(),
            };
            append_p2p_message("did:guardian:test_peer_concurrent", &record)
                .await
                .unwrap();
        });
        handles.push(handle);
    }

    // Wait for all to finish
    for h in handles {
        h.await.unwrap();
    }

    let history = read_p2p_history(peer_did)
        .await
        .expect("Failed to read history");
    assert_eq!(
        history.len(),
        50,
        "Not all 50 messages were appended due to race condition!"
    );
}

#[tokio::test]
async fn test_storage_concurrency_group() {
    setup_test_dirs().await;
    let group_id = "test_group_concurrent";

    let path = "/tmp/sgx-guardian-chat-tests";
    let safe_name = URL_SAFE_NO_PAD.encode(group_id.as_bytes());
    let _ = tokio::fs::remove_file(format!("{}/group/{}.jsonl", path, safe_name)).await;

    let mut handles = vec![];

    for i in 0..20 {
        let handle = tokio::spawn(async move {
            let record = ChatMessageRecord {
                message_id: format!("gmsg_{}", i),
                sender_did: "did:guardian:me".to_string(),
                recipient_did: "group:test_group_concurrent".to_string(),
                group_id: Some(group_id.to_string()),
                timestamp: 1672531200,
                seq_no: i,
                encrypted_payload: "group_encrypted".to_string(),
                signature: "sig".to_string(),
                status: MessageStatus::Delivered,
                read_by: Vec::new(),
            };
            append_group_message(group_id, &record).await.unwrap();
        });
        handles.push(handle);
    }

    for h in handles {
        h.await.unwrap();
    }

    let history = read_group_history(group_id)
        .await
        .expect("Failed to read group history");
    assert_eq!(
        history.len(),
        20,
        "Not all 20 group messages were appended!"
    );
}
