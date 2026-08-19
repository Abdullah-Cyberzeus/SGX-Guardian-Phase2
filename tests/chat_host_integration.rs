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
use sgx_guardian_client::circle::persistence::CIRCLE_BASE_ENV;
use sgx_guardian_client::circle::{members, store};
use sgx_guardian_client::did::doc_persistence::{
    self, CA_AGGREGATE_PATH_ENV, PEERS_DOC_DIR_ENV, SELF_DOC_PATH_ENV, VERSION_COUNTER_PATH_ENV,
};
use sgx_guardian_client::did::doc_sign;
use sgx_guardian_client::did::document::{DidDocument, DocBuildInput};
use sgx_guardian_client::did::persistence::{DerivationProof, DidRecord};
use sgx_guardian_client::did::Did;
use sgx_guardian_client::proto::sgx::chat_service_client::ChatServiceClient;
use sgx_guardian_client::proto::sgx::chat_service_server::ChatServiceServer;
use sgx_guardian_client::proto::sgx::PushMessageRequest;
use sgx_guardian_client::vc::credential::CredentialRole;
use sgx_guardian_client::vc::issue::{self, IssueRequest, DEVICE_KEY_DIR_ENV};
use sgx_guardian_client::vc::persistence::VC_BASE_ENV;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::oneshot;
use tonic::transport::{Channel, Server};
use tonic::Code;

const DID_PATH_ENV: &str = "SGX_GUARDIAN_DID_PATH";

fn state(node_id: &str, root: &std::path::Path) -> std::sync::Arc<AppState> {
    AppState::for_tests(root, node_id, root.join("config").display().to_string())
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

fn seed_circle_state(node_a_root: &Path, state_a: &AppState, did_b: &str, did_c: &str) {
    let did_path = node_a_root.join("did.json");
    let self_doc_path = node_a_root.join("did_doc.json");
    let peers_dir = node_a_root.join("peers");
    let aggregate_path = node_a_root.join("circle_did_docs.json");
    let version_counter_path = node_a_root.join("self_version_counter");
    let vc_base = node_a_root.join("vc");
    let circle_base = node_a_root.join("circles");
    let key_dir = node_a_root.join("sgx-agent");

    std::env::set_var(SELF_DOC_PATH_ENV, &self_doc_path);
    std::env::set_var(PEERS_DOC_DIR_ENV, &peers_dir);
    std::env::set_var(CA_AGGREGATE_PATH_ENV, &aggregate_path);
    std::env::set_var(VERSION_COUNTER_PATH_ENV, &version_counter_path);
    std::env::set_var(VC_BASE_ENV, &vc_base);
    std::env::set_var(CIRCLE_BASE_ENV, &circle_base);
    std::env::set_var(DEVICE_KEY_DIR_ENV, &key_dir);
    std::env::set_var(DID_PATH_ENV, &did_path);

    let did = Did::parse(&state_a.device_did).expect("parse nodeA DID");
    let record = DidRecord {
        did: state_a.device_did.clone(),
        method: "guardian".to_string(),
        method_version: "1.0".to_string(),
        did_id_b58: did.msi().to_string(),
        did_id_hex: hex::encode(did.id_bytes()),
        created_at: chrono::Utc::now().to_rfc3339(),
        deactivated_at: None,
        derivation: DerivationProof {
            se050_uid: "test".to_string(),
            se050_uid_source: "test".to_string(),
            dkp_v1_pubkey_sha256_b16: "test".to_string(),
            dkp_v1_pubkey_path: "test".to_string(),
            dkp_v1_pubkey_der_b64: None,
            dik_pubkey_sha256_b16: "test".to_string(),
            dik_pubkey_der_b64: None,
        },
        current_dkp_version: 1,
        deriv_signature_b64: String::new(),
    };
    record
        .save(did_path.to_str().expect("did path"))
        .expect("save DID record");

    let mut self_doc = DidDocument::build(DocBuildInput {
        did: &state_a.device_did,
        node_name: Some("nodeA"),
        current_dkp_version: 1,
        current_dkp_pubkey_der: &state_a.device_pubkey_point,
        overlay_ip_cidr: Some("127.0.0.1/24"),
        attestation_bind: Some(("127.0.0.1", 50051)),
        cert_bootstrap_bind: Some(("127.0.0.1", 50061)),
        revoked: vec![],
        previous_version_id: 0,
        created_at: Some(chrono::Utc::now().to_rfc3339()),
        status: Some("active".to_string()),
    })
    .expect("build DID doc");
    let vm_ref = self_doc
        .verification_method
        .first()
        .expect("verification method")
        .id
        .clone();
    doc_sign::sign_in_place(&mut self_doc, state_a.signer.as_ref(), &vm_ref).expect("sign DID doc");
    doc_persistence::save_self(&self_doc).expect("save self DID doc");
    doc_persistence::save_peer(&self_doc).expect("save peer DID doc");
    doc_persistence::save_ca_aggregate(std::slice::from_ref(&self_doc)).expect("save aggregate");

    issue::ensure_owner_vc(&record, state_a.signer.as_ref()).expect("mesh owner VC");
    let group_id = "group:host-test";
    store::create_circle(
        "nodeA",
        group_id.to_string(),
        "Host Test Group".to_string(),
        "Integration group".to_string(),
        state_a.device_did.clone(),
    )
    .expect("create chat group circle");

    issue::issue_membership_vc(
        &record,
        state_a.signer.as_ref(),
        IssueRequest {
            subject_did: &record.did,
            role: CredentialRole::Owner,
            permissions: issue::default_permissions_for_role(CredentialRole::Owner),
            circle_id: group_id,
            node_hint: Some("nodeA".to_string()),
            duration_days: None,
        },
    )
    .expect("group owner VC");

    members::add_member("nodeA", group_id, did_b, CredentialRole::Member, 30)
        .expect("add nodeB to chat group");
    members::add_member("nodeA", group_id, did_c, CredentialRole::Member, 30)
        .expect("add nodeC to chat group");
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

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn host_chat_round_trip_group_sync_and_trust_gate() {
    // `chat::storage` reads this once per process. This integration-test file
    // contains one test, ensuring its storage is private and deterministic.
    let temp = TempDir::new().unwrap();
    std::env::set_var("CHAT_STORAGE_DIR", temp.path().join("chat"));

    let state_a = state("nodeA", &temp.path().join("node-a"));
    let state_b = state("nodeB", &temp.path().join("node-b"));
    let state_c = state("nodeC", &temp.path().join("node-c"));
    let did_a = state_a.device_did.clone();
    let did_b = state_b.device_did.clone();
    let did_c = state_c.device_did.clone();
    seed_circle_state(&temp.path().join("node-a"), &state_a, &did_b, &did_c);
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
        Json(SendMessageRequest {
            recipient_did: did_b.clone(),
            content: Some("hello from the host harness".to_string()),
            attachment_id: None,
            is_group: false,
        }),
    )
    .await
    .unwrap()
    .0;
    assert_eq!(response.status, "queued");
    let received = wait_for_message(&did_a, &response.message_id).await;
    assert_eq!(
        received.encrypted_payload,
        r#"{"attachment_id":null,"content":"hello from the host harness"}"#
    );

    assert_eq!(received.status, MessageStatus::Delivered);

    // A receipt follows the same Nebula/plaintext path and no longer needs
    // local mTLS files. B's real DID is accepted by A's trusted-peer gate.
    let receipt = chat::mark_as_read(
        State(state_b.clone()),
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

    // Group fan-out: the sender stores one group record and each trusted peer
    // receives an individual gRPC push.
    let group_response = chat::send_message(
        State(state_a.clone()),
        Json(SendMessageRequest {
            recipient_did: "group:host-test".to_string(),
            content: Some("host group message".to_string()),
            attachment_id: None,
            is_group: true,
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
        if group_deliveries.len() == 3 {
            assert!(group_deliveries.iter().all(|m| m.encrypted_payload
                == r#"{"attachment_id":null,"content":"host group message"}"#));
            assert!(group_deliveries
                .iter()
                .any(|m| m.recipient_did == "group:host-test"));
            assert!(group_deliveries.iter().any(|m| m.recipient_did == did_b));
            assert!(group_deliveries.iter().any(|m| m.recipient_did == did_c));
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
        3,
        "group history must contain sender copy plus both trusted peer deliveries"
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
            recipient_did: did_b,
            timestamp: 1,
            seq_no: 1,
            encrypted_payload: "must not persist".to_string(),
            signature: String::new(),
            group_id: String::new(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);

    let _ = shutdown_a.send(());
    let _ = shutdown_b.send(());
    let _ = shutdown_c.send(());
}
