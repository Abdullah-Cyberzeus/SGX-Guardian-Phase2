//! Host-only end-to-end coverage for the chat transport.
//!
//! This deliberately starts only the chat gRPC services, rather than the full
//! Guardian daemon.  It therefore runs on a developer machine with no SE050,
//! Nebula daemon, nftables privileges, or board-specific paths.  The test
//! still exercises the production REST handler, trusted-peer gate, gRPC
//! transport, JSONL persistence, group fan-out, and missed-message sync.

use axum::{extract::State, Json};
use sgx_guardian_client::api::handlers::chat::{self, MarkReadRequest, SendMessageRequest};
use sgx_guardian_client::api::state::AppState;
use sgx_guardian_client::chat::grpc_server::MyChatService;
use sgx_guardian_client::chat::models::{ChatMessageRecord, MessageStatus};
use sgx_guardian_client::chat::storage::{
    append_p2p_message, read_group_history, read_p2p_history,
};
use sgx_guardian_client::did::doc_persistence;
use sgx_guardian_client::proto::sgx::chat_service_client::ChatServiceClient;
use sgx_guardian_client::proto::sgx::chat_service_server::ChatServiceServer;
use sgx_guardian_client::proto::sgx::PushMessageRequest;
use sgx_guardian_client::testkit::bootstrap_owner_identity;
use sgx_guardian_client::vc::credential::CredentialRole;
use sgx_guardian_client::vc::issue::{self, IssueRequest};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::oneshot;
use tonic::transport::{Channel, Server};
use tonic::Code;

fn state(node_id: &str, root: &std::path::Path) -> std::sync::Arc<AppState> {
    AppState::for_tests(root, node_id, root.join("config").display().to_string())
}

fn isolate_circle_identity(root: &std::path::Path) {
    std::env::set_var("SGX_FORCE_SOFTWARE_KEYS", "1");
    std::env::set_var("SGX_GUARDIAN_CIRCLE_BASE", root.join("circle-base"));
    std::env::set_var("SGX_GUARDIAN_VC_BASE", root.join("vc-base"));
    std::env::set_var("SGX_GUARDIAN_DID_PATH", root.join("did.json"));
    std::env::set_var("SGX_GUARDIAN_DEVICE_KEY_DIR", root.join("device-keys"));
    std::env::set_var(
        sgx_guardian_client::virtual_id::RUNTIME_VID_STATE_DIR_ENV,
        root.join("virtual-id"),
    );
    std::env::set_var(doc_persistence::SELF_DOC_PATH_ENV, root.join("did_doc.json"));
    std::env::set_var(doc_persistence::PEERS_DOC_DIR_ENV, root.join("did-peers"));
    std::env::set_var(
        doc_persistence::CA_AGGREGATE_PATH_ENV,
        root.join("ca-aggregate.json"),
    );
    std::env::set_var(
        doc_persistence::VERSION_COUNTER_PATH_ENV,
        root.join("did-version-counter"),
    );
}

async fn write_trusted_peer(state: &AppState, did: &str, peer_id: &str, port: u16) {
    let path = std::path::Path::new(&state.log_dir_primary).join("trusted_peers.json");
    tokio::fs::create_dir_all(path.parent().expect("log directory"))
        .await
        .unwrap();
    let peers = serde_json::json!([{
        "did": did,
        "peer_id": peer_id,
        "ip": "127.0.0.1",
        "status": "trusted",
        // Production derives chat port as attestation port + 100.
        "attestation_port": port - 100,
    }]);
    tokio::fs::write(path, serde_json::to_vec(&peers).unwrap())
        .await
        .unwrap();
}

async fn start_peer(state: Arc<AppState>) -> (String, oneshot::Sender<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    tokio::spawn(async move {
        Server::builder()
            .add_service(ChatServiceServer::new(MyChatService { state }))
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await
            .unwrap();
    });
    (addr.to_string(), shutdown_tx)
}

async fn wait_for_message(peer_did: &str, message_id: &str) -> ChatMessageRecord {
    for _ in 0..50 {
        let history = read_p2p_history(peer_did).await.unwrap();
        if let Some(message) = history.into_iter().find(|m| m.message_id == message_id) {
            return message;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for message {message_id} in {peer_did} history");
}

async fn wait_for_status(
    peer_did: &str,
    message_id: &str,
    status: MessageStatus,
) -> ChatMessageRecord {
    for _ in 0..50 {
        let history = read_p2p_history(peer_did).await.unwrap();
        if let Some(message) = history
            .into_iter()
            .find(|m| m.message_id == message_id && m.status == status)
        {
            return message;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for message {message_id} in {peer_did} history to reach {status:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn host_chat_round_trip_group_sync_and_trust_gate() {
    // `chat::storage` reads this once per process. This integration-test file
    // contains one test, ensuring its storage is private and deterministic.
    let temp = TempDir::new().unwrap();
    std::env::set_var("CHAT_STORAGE_DIR", temp.path().join("chat"));
    std::env::set_var("SGX_GUARDIAN_VAULT_BASE", temp.path().join("vault"));
    isolate_circle_identity(temp.path());

    let state_a = state("nodeA", &temp.path().join("node-a"));
    let state_b = state("nodeB", &temp.path().join("node-b"));
    let state_c = state("nodeC", &temp.path().join("node-c"));
    let did_a = state_a.device_did.clone();
    let did_b = state_b.device_did.clone();
    let did_c = state_c.device_did.clone();
    bootstrap_owner_identity(
        "nodeA",
        &did_a,
        &temp.path().join("device-keys"),
        "192.168.100.1/24",
    )
    .expect("bootstrap nodeA Circle owner identity");
    let (owner, owner_key) =
        sgx_guardian_client::circle::store::load_runtime_signing_context("nodeA")
            .expect("load nodeA signing identity");
    sgx_guardian_client::circle::store::create_circle(
        "nodeA",
        "group:host-test".to_string(),
        "Host integration group".to_string(),
        String::new(),
        did_a.clone(),
    )
    .expect("create host integration Circle");
    for member_did in [&did_b, &did_c] {
        issue::issue_membership_vc(
            &owner,
            &owner_key,
            IssueRequest {
                subject_did: member_did,
                role: CredentialRole::Member,
                permissions: issue::default_permissions_for_role(CredentialRole::Member),
                circle_id: "group:host-test",
                node_hint: None,
                duration_days: Some(issue::DEFAULT_VC_DURATION_DAYS),
            },
        )
        .expect("issue host integration Circle membership");
    }
    let (addr_a, shutdown_a) = start_peer(state_a.clone()).await;
    let (addr_b, shutdown_b) = start_peer(state_b.clone()).await;
    let (addr_c, shutdown_c) = start_peer(state_c.clone()).await;
    let port_b = addr_b.rsplit_once(':').unwrap().1.parse::<u16>().unwrap();
    let port_c = addr_c.rsplit_once(':').unwrap().1.parse::<u16>().unwrap();

    write_trusted_peer(&state_a, &did_b, &format!("nodeB:{}", port_b - 100), port_b).await;
    // Group fan-out requires both recipients in nodeA's registry.
    let peers_path = std::path::Path::new(&state_a.log_dir_primary).join("trusted_peers.json");
    let a_peers = serde_json::json!([
        {"did": did_b.clone(), "peer_id": format!("nodeB:{}", port_b - 100), "ip": "127.0.0.1", "status": "trusted"},
        {"did": did_c.clone(), "peer_id": format!("nodeC:{}", port_c - 100), "ip": "127.0.0.1", "status": "trusted"}
    ]);
    tokio::fs::write(peers_path, serde_json::to_vec(&a_peers).unwrap())
        .await
        .unwrap();
    let port_a = addr_a.rsplit_once(':').unwrap().1.parse::<u16>().unwrap();
    write_trusted_peer(&state_b, &did_a, &format!("nodeA:{}", port_a - 100), port_a).await;
    write_trusted_peer(&state_c, &did_a, &format!("nodeA:{}", port_a - 100), port_a).await;

    // P2P send: use the production REST handler, then observe delivery at B.
    let response = chat::send_message(
        State(state_a.clone()),
        None,
        Json(SendMessageRequest {
            recipient_did: did_b.clone(),
            content: Some("hello from the host harness".to_string()),
            attachment_id: None,
            is_group: false,
            message_id: None,
        }),
    )
    .await
    .unwrap()
    .0;
    assert_eq!(response.status, "accepted_by_guardian");
    let received = wait_for_message(&did_a, &response.message_id).await;
    assert_eq!(
        received.encrypted_payload,
        r#"{"attachment_id":null,"attachment_mime":null,"attachment_name":null,"attachment_size":null,"content":"hello from the host harness"}"#
    );

    assert_eq!(received.status, MessageStatus::Delivered);

    // The delivery push to B ran in the background; A's own copy should now
    // reflect that success instead of staying `Pending` forever.
    let sent_record = wait_for_status(
        &did_b,
        &response.message_id,
        MessageStatus::DeliveredToRemoteGuardian,
    )
    .await;
    assert_eq!(sent_record.status, MessageStatus::DeliveredToRemoteGuardian);

    let replay = chat::send_message(
        State(state_a.clone()),
        None,
        Json(SendMessageRequest {
            recipient_did: did_b.clone(),
            content: Some("hello from the host harness".to_string()),
            attachment_id: None,
            is_group: false,
            message_id: Some(response.message_id.clone()),
        }),
    )
    .await
    .unwrap()
    .0;
    assert_eq!(replay.message_id, response.message_id);
    assert_eq!(replay.status, "delivered_to_remote_guardian");

    let mismatch = chat::send_message(
        State(state_a.clone()),
        None,
        Json(SendMessageRequest {
            recipient_did: did_b.clone(),
            content: Some("different body".to_string()),
            attachment_id: None,
            is_group: false,
            message_id: Some(response.message_id.clone()),
        }),
    )
    .await;
    assert!(mismatch.is_err());

    // A receipt follows the same Nebula/plaintext path and no longer needs
    // local mTLS files. B's real DID is accepted by A's trusted-peer gate.
    let receipt = chat::mark_as_read(
        State(state_b.clone()),
        None,
        Json(MarkReadRequest {
            message_id: response.message_id.clone(),
            original_sender_did: did_a.clone(),
            group_id: None,
        }),
    )
    .await
    .unwrap()
    .0;
    assert_eq!(receipt.status, "read_logged");
    let receipt_path = temp.path().join("chat/read_receipts.jsonl");
    for _ in 0..50 {
        let text = tokio::fs::read_to_string(&receipt_path)
            .await
            .unwrap_or_default();
        if text.contains(&response.message_id) && text.contains(&did_b) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let receipt_text = tokio::fs::read_to_string(&receipt_path).await.unwrap();
    assert!(receipt_text.contains(&response.message_id));
    assert!(receipt_text.contains(&did_b));

    // Group fan-out: the shared host harness storage keeps one idempotent
    // conversation record while each trusted peer receives a gRPC push.
    let group_response = chat::send_message(
        State(state_a.clone()),
        None,
        Json(SendMessageRequest {
            recipient_did: "group:host-test".to_string(),
            content: Some("host group message".to_string()),
            attachment_id: None,
            is_group: true,
            message_id: None,
        }),
    )
    .await
    .unwrap()
    .0;
    for _ in 0..50 {
        let group_deliveries = read_group_history("group:host-test")
            .await
            .unwrap()
            .into_iter()
            .filter(|m| m.message_id == group_response.message_id)
            .collect::<Vec<_>>();
        if group_deliveries.len() == 1
            && group_deliveries[0].status == MessageStatus::DeliveredToRemoteGuardian
        {
            assert!(group_deliveries.iter().all(|m| m.encrypted_payload
                == r#"{"attachment_id":null,"attachment_mime":null,"attachment_name":null,"attachment_size":null,"content":"host group message"}"#));
            assert!(group_deliveries
                .iter()
                .any(|m| m.recipient_did == "group:host-test"));
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        read_group_history("group:host-test")
            .await
            .unwrap()
            .iter()
            .filter(|m| m.message_id == group_response.message_id)
            .count(),
        1,
        "group history must retain one idempotent sender copy after fan-out"
    );

    // A peer can return missed messages through SyncMessages. Seed B's side
    // with a later sequence record, then run the production sync client.
    append_p2p_message(
        &did_a,
        &ChatMessageRecord {
            message_id: "host-sync-message".to_string(),
            sender_did: did_b.clone(),
            recipient_did: did_a.clone(),
            group_id: None,
            timestamp: 1_700_000_000,
            seq_no: 99,
            encrypted_payload: r#"{"attachment_id":null,"content":"replayed after reconnect"}"#
                .to_string(),
            signature: String::new(),
            status: MessageStatus::Delivered,
            read_by: Vec::new(),
        },
    )
    .await
    .unwrap();
    sgx_guardian_client::chat::grpc_client::request_sync_from_peer(
        did_a.clone(),
        did_b.clone(),
        addr_b.clone(),
        1,
    )
    .await
    .unwrap();
    assert_eq!(
        wait_for_message(&did_b, "host-sync-message")
            .await
            .encrypted_payload,
        r#"{"attachment_id":null,"content":"replayed after reconnect"}"#
    );

    // Trust gate: an unauthorised claimed DID is rejected before persistence.
    let channel = Channel::from_shared(format!("http://{addr_b}"))
        .unwrap()
        .connect_lazy();
    let mut client = ChatServiceClient::new(channel);
    let err = client
        .push_message(PushMessageRequest {
            message_id: "untrusted-message".to_string(),
            sender_did: "did:guardian:untrusted".to_string(),
            recipient_did: did_b.clone(),
            timestamp: 1,
            seq_no: 1,
            encrypted_payload: "must not persist".to_string(),
            signature: String::new(),
            group_id: String::new(),
            relay_did: String::new(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);

    // Attachment streaming is a separate, chunked protocol: the chat message
    // carries metadata while the receiver pulls verified, decrypted bytes
    // over the same attested Nebula gRPC channel from the sender's Vault.
    let attachment_bytes = vec![0x5au8; 150_000];
    let attachment_source = temp.path().join("attachment-source.bin");
    tokio::fs::write(&attachment_source, &attachment_bytes)
        .await
        .unwrap();
    let attachment_record = sgx_guardian_client::vault::ingest::ingest_chat_attachment(
        sgx_guardian_client::vault::VaultNamespace::Personal,
        &did_a,
        &attachment_source,
        sgx_guardian_client::vault::ingest::IngestMeta {
            filename: "host-proof.bin".to_string(),
            mime: "application/octet-stream".to_string(),
            sha256_plain: hex::encode(Sha256::digest(&attachment_bytes)),
            size_plain: attachment_bytes.len() as u64,
            chunk_bytes: sgx_guardian_client::vault::VaultConfig::DEFAULT_CHUNK_BYTES,
        },
        None,
    )
    .await
    .unwrap();
    let attachment_id = attachment_record.vault_id;

    let channel = Channel::from_shared(format!("http://{addr_a}"))
        .unwrap()
        .connect_lazy();
    let mut attachment_client = ChatServiceClient::new(channel);
    let mut attachment_stream = attachment_client
        .get_attachment(sgx_guardian_client::proto::sgx::GetAttachmentRequest {
            requester_did: did_b.clone(),
            attachment_id: attachment_id.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    let mut downloaded = Vec::new();
    while let Some(chunk) = attachment_stream.message().await.unwrap() {
        assert_eq!(chunk.attachment_id, attachment_id);
        assert_eq!(chunk.file_name, "host-proof.bin");
        assert_eq!(chunk.total_size, attachment_bytes.len() as u64);
        downloaded.extend_from_slice(&chunk.data);
    }
    assert_eq!(downloaded, attachment_bytes);

    let _ = shutdown_a.send(());
    let _ = shutdown_b.send(());
    let _ = shutdown_c.send(());
}
