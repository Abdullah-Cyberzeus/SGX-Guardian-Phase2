//! Integration tests for `src/chat/grpc_client.rs` (real baseline 0/268 —
//! the plan doc's prior "109/268, 40.7%" claim did not survive
//! re-verification).
//!
//! All four public functions are gRPC client calls; this reuses the
//! in-process mock-gRPC-server pattern already proven for `cert_client.rs`'s
//! tests (`tonic::transport::Server` bound to an ephemeral loopback port) so
//! the client's request-construction, response-parsing, and error-mapping
//! logic can be exercised without any real network or CA/peer process.

use futures_util::stream;
use sgx_guardian_client::chat::grpc_client::{
    download_attachment_from_peer, push_message_to_peer, push_receipt_to_peer,
    request_sync_from_peer,
};
use sgx_guardian_client::proto::sgx::chat_service_server::{ChatService, ChatServiceServer};
use sgx_guardian_client::proto::sgx::{
    AttachmentChunk, GetAttachmentRequest, PushMessageRequest, PushMessageResponse,
    PushReceiptRequest, PushReceiptResponse, SyncRequest,
};
use std::pin::Pin;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

type ChunkStream = Pin<Box<dyn tokio_stream::Stream<Item = Result<AttachmentChunk, Status>> + Send>>;
type SyncStream = Pin<Box<dyn tokio_stream::Stream<Item = Result<PushMessageRequest, Status>> + Send>>;

#[derive(Default)]
struct MockChatService {
    push_message_error: bool,
    push_receipt_error: bool,
    attachment_chunks: Vec<AttachmentChunk>,
    attachment_error: bool,
    sync_messages: Vec<PushMessageRequest>,
    sync_stream_error: bool,
    sync_rpc_error: bool,
}

#[tonic::async_trait]
impl ChatService for MockChatService {
    async fn push_message(
        &self,
        _request: Request<PushMessageRequest>,
    ) -> Result<Response<PushMessageResponse>, Status> {
        if self.push_message_error {
            return Err(Status::unavailable("mock push_message failure"));
        }
        Ok(Response::new(PushMessageResponse {
            message_id: "mock-message-id".to_string(),
            status: "delivered".to_string(),
        }))
    }

    async fn push_receipt(
        &self,
        _request: Request<PushReceiptRequest>,
    ) -> Result<Response<PushReceiptResponse>, Status> {
        if self.push_receipt_error {
            return Err(Status::unavailable("mock push_receipt failure"));
        }
        Ok(Response::new(PushReceiptResponse {
            message_id: "mock-message-id".to_string(),
            status: "receipt_logged".to_string(),
        }))
    }

    type GetAttachmentStream = ChunkStream;

    async fn get_attachment(
        &self,
        _request: Request<GetAttachmentRequest>,
    ) -> Result<Response<Self::GetAttachmentStream>, Status> {
        if self.attachment_error {
            return Err(Status::not_found("mock attachment not found"));
        }
        let chunks: Vec<Result<AttachmentChunk, Status>> =
            self.attachment_chunks.iter().cloned().map(Ok).collect();
        let stream: ChunkStream = Box::pin(stream::iter(chunks));
        Ok(Response::new(stream))
    }

    type SyncMessagesStream = SyncStream;

    async fn sync_messages(
        &self,
        _request: Request<SyncRequest>,
    ) -> Result<Response<Self::SyncMessagesStream>, Status> {
        if self.sync_rpc_error {
            return Err(Status::unavailable("mock sync_messages failure"));
        }
        if self.sync_stream_error {
            let stream: SyncStream = Box::pin(stream::iter(vec![Err(Status::internal(
                "mock mid-stream failure",
            ))]));
            return Ok(Response::new(stream));
        }
        let items: Vec<Result<PushMessageRequest, Status>> =
            self.sync_messages.iter().cloned().map(Ok).collect();
        let stream: SyncStream = Box::pin(stream::iter(items));
        Ok(Response::new(stream))
    }
}

async fn spawn_mock(service: MockChatService) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock chat service");
    let addr = listener.local_addr().expect("local addr").to_string();
    let incoming = TcpListenerStream::new(listener);
    let handle = tokio::spawn(async move {
        let _ = Server::builder()
            .add_service(ChatServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, handle)
}

fn base_push_message() -> PushMessageRequest {
    PushMessageRequest {
        message_id: "msg-1".to_string(),
        sender_did: "did:guardian:sender".to_string(),
        recipient_did: "did:guardian:recipient".to_string(),
        timestamp: 1_700_000_000,
        seq_no: 1,
        encrypted_payload: "encrypted-blob".to_string(),
        signature: "sig".to_string(),
        group_id: String::new(),
        relay_did: String::new(),
    }
}

#[tokio::test]
async fn push_message_to_peer_succeeds_against_a_mock_server() {
    let (addr, handle) = spawn_mock(MockChatService::default()).await;
    push_message_to_peer(addr, base_push_message())
        .await
        .expect("push should succeed");
    handle.abort();
}

#[tokio::test]
async fn push_message_to_peer_surfaces_a_grpc_error() {
    let (addr, handle) = spawn_mock(MockChatService {
        push_message_error: true,
        ..Default::default()
    })
    .await;
    let err = push_message_to_peer(addr, base_push_message())
        .await
        .expect_err("server error should surface");
    assert!(err.to_string().contains("mock push_message failure"));
    handle.abort();
}

#[tokio::test]
async fn push_message_to_peer_rejects_an_invalid_endpoint_uri() {
    let err = push_message_to_peer("[invalid".to_string(), base_push_message())
        .await
        .expect_err("invalid URI must fail");
    assert!(err.to_string().contains("Invalid endpoint URI"));
}

#[tokio::test]
async fn push_message_to_peer_reports_connection_failure_for_a_closed_port() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    drop(listener);
    let err = push_message_to_peer(addr, base_push_message())
        .await
        .expect_err("closed port should fail to connect");
    assert!(err.to_string().contains("gRPC connect"));
}

#[tokio::test]
async fn push_receipt_to_peer_succeeds_against_a_mock_server() {
    let (addr, handle) = spawn_mock(MockChatService::default()).await;
    let request = PushReceiptRequest {
        message_id: "msg-1".to_string(),
        reader_did: "did:guardian:reader".to_string(),
        timestamp: 1_700_000_000,
        group_id: String::new(),
    };
    push_receipt_to_peer("did:guardian:reader".to_string(), addr, request)
        .await
        .expect("push receipt should succeed");
    handle.abort();
}

#[tokio::test]
async fn push_receipt_to_peer_surfaces_a_grpc_error() {
    let (addr, handle) = spawn_mock(MockChatService {
        push_receipt_error: true,
        ..Default::default()
    })
    .await;
    let request = PushReceiptRequest {
        message_id: "msg-1".to_string(),
        reader_did: "did:guardian:reader".to_string(),
        timestamp: 1_700_000_000,
        group_id: String::new(),
    };
    let err = push_receipt_to_peer("did:guardian:reader".to_string(), addr, request)
        .await
        .expect_err("server error should surface");
    assert!(err.to_string().contains("mock push_receipt failure"));
    handle.abort();
}

#[tokio::test]
async fn request_sync_from_peer_processes_an_empty_stream() {
    let (addr, handle) = spawn_mock(MockChatService::default()).await;
    request_sync_from_peer(
        "did:guardian:local".to_string(),
        "did:guardian:peer".to_string(),
        addr,
        0,
    )
    .await
    .expect("empty sync should succeed");
    handle.abort();
}

#[tokio::test]
async fn request_sync_from_peer_surfaces_an_rpc_error() {
    let (addr, handle) = spawn_mock(MockChatService {
        sync_rpc_error: true,
        ..Default::default()
    })
    .await;
    let err = request_sync_from_peer(
        "did:guardian:local".to_string(),
        "did:guardian:peer".to_string(),
        addr,
        0,
    )
    .await
    .expect_err("rpc error should surface");
    assert!(err.to_string().contains("mock sync_messages failure"));
    handle.abort();
}

#[tokio::test]
async fn request_sync_from_peer_surfaces_a_mid_stream_error() {
    let (addr, handle) = spawn_mock(MockChatService {
        sync_stream_error: true,
        ..Default::default()
    })
    .await;
    let err = request_sync_from_peer(
        "did:guardian:local".to_string(),
        "did:guardian:peer".to_string(),
        addr,
        0,
    )
    .await
    .expect_err("mid-stream error should surface");
    assert!(err.to_string().contains("mock mid-stream failure"));
    handle.abort();
}

fn env_lock_temp() -> tempfile::TempDir {
    let temp = tempfile::tempdir().expect("tempdir");
    std::env::set_var("SGX_GUARDIAN_VAULT_BASE", temp.path());
    std::env::set_var("SGX_FORCE_SOFTWARE_KEYS", "1");
    std::env::set_var("CHAT_STORAGE_DIR", temp.path().join("chat"));
    temp
}

#[tokio::test]
async fn request_sync_from_peer_persists_a_valid_p2p_message() {
    let _temp = env_lock_temp();
    let mut msg = base_push_message();
    msg.recipient_did = "did:guardian:local".to_string();
    msg.sender_did = "did:guardian:peer".to_string();
    let (addr, handle) = spawn_mock(MockChatService {
        sync_messages: vec![msg],
        ..Default::default()
    })
    .await;
    request_sync_from_peer(
        "did:guardian:local".to_string(),
        "did:guardian:peer".to_string(),
        addr,
        0,
    )
    .await
    .expect("valid p2p message should sync");
    handle.abort();
}

#[tokio::test]
async fn request_sync_from_peer_rejects_a_relay_did_that_does_not_match_peer_or_local() {
    let _temp = env_lock_temp();
    let mut msg = base_push_message();
    msg.recipient_did = "did:guardian:local".to_string();
    msg.sender_did = "did:guardian:someone-else".to_string();
    msg.relay_did = "did:guardian:untrusted-relay".to_string();
    let (addr, handle) = spawn_mock(MockChatService {
        sync_messages: vec![msg],
        ..Default::default()
    })
    .await;
    let err = request_sync_from_peer(
        "did:guardian:local".to_string(),
        "did:guardian:peer".to_string(),
        addr,
        0,
    )
    .await
    .expect_err("mismatched relay_did must be rejected");
    assert!(err.to_string().contains("Security Violation"));
    handle.abort();
}

#[tokio::test]
async fn request_sync_from_peer_rejects_a_message_not_addressed_to_local_or_peer() {
    let _temp = env_lock_temp();
    let mut msg = base_push_message();
    msg.recipient_did = "did:guardian:some-third-party".to_string();
    let (addr, handle) = spawn_mock(MockChatService {
        sync_messages: vec![msg],
        ..Default::default()
    })
    .await;
    let err = request_sync_from_peer(
        "did:guardian:local".to_string(),
        "did:guardian:peer".to_string(),
        addr,
        0,
    )
    .await
    .expect_err("message not addressed to local/peer must be rejected");
    assert!(err.to_string().contains("Security Violation"));
    handle.abort();
}

#[tokio::test]
async fn request_sync_from_peer_rejects_identical_sender_and_recipient() {
    let _temp = env_lock_temp();
    let mut msg = base_push_message();
    msg.sender_did = "did:guardian:local".to_string();
    msg.recipient_did = "did:guardian:local".to_string();
    let (addr, handle) = spawn_mock(MockChatService {
        sync_messages: vec![msg],
        ..Default::default()
    })
    .await;
    let err = request_sync_from_peer(
        "did:guardian:local".to_string(),
        "did:guardian:peer".to_string(),
        addr,
        0,
    )
    .await
    .expect_err("identical sender/recipient must be rejected");
    assert!(err
        .to_string()
        .contains("Sender and recipient cannot be identical"));
    handle.abort();
}

#[tokio::test]
async fn download_attachment_from_peer_rejects_an_invalid_attachment_id() {
    let _temp = env_lock_temp();
    let err = download_attachment_from_peer(
        "did:guardian:local".to_string(),
        "did:guardian:peer".to_string(),
        "127.0.0.1:1".to_string(),
        "..".to_string(),
        "did:guardian:sender".to_string(),
        "did:guardian:recipient".to_string(),
        None,
    )
    .await
    .expect_err("invalid attachment id must be rejected before any network call");
    assert!(err.to_string().contains("invalid attachment ID"));
}

#[tokio::test]
async fn download_attachment_from_peer_downloads_and_verifies_a_full_attachment() {
    let _temp = env_lock_temp();
    let content = b"hello chat attachment";
    let hash = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(content))
    };
    let chunk = AttachmentChunk {
        attachment_id: "urn-test-attachment".to_string(),
        file_name: "note.txt".to_string(),
        mime_type: "text/plain".to_string(),
        total_size: content.len() as u64,
        sha256_hash: hash,
        data: content.to_vec(),
    };
    let (addr, handle) = spawn_mock(MockChatService {
        attachment_chunks: vec![chunk],
        ..Default::default()
    })
    .await;

    download_attachment_from_peer(
        "did:guardian:local".to_string(),
        "did:guardian:peer".to_string(),
        addr,
        "urn-test-attachment".to_string(),
        "did:guardian:sender".to_string(),
        "did:guardian:recipient".to_string(),
        None,
    )
    .await
    .expect("full valid attachment stream should ingest successfully");
    handle.abort();
}

#[tokio::test]
async fn download_attachment_from_peer_rejects_a_checksum_mismatch() {
    let _temp = env_lock_temp();
    let content = b"tampered content";
    let chunk = AttachmentChunk {
        attachment_id: "urn-test-bad-hash".to_string(),
        file_name: "note.txt".to_string(),
        mime_type: "text/plain".to_string(),
        total_size: content.len() as u64,
        sha256_hash: "0".repeat(64),
        data: content.to_vec(),
    };
    let (addr, handle) = spawn_mock(MockChatService {
        attachment_chunks: vec![chunk],
        ..Default::default()
    })
    .await;

    let err = download_attachment_from_peer(
        "did:guardian:local".to_string(),
        "did:guardian:peer".to_string(),
        addr,
        "urn-test-bad-hash".to_string(),
        "did:guardian:sender".to_string(),
        "did:guardian:recipient".to_string(),
        None,
    )
    .await
    .expect_err("checksum mismatch must be rejected");
    assert!(err.to_string().contains("checksum mismatch"));
    handle.abort();
}

#[tokio::test]
async fn download_attachment_from_peer_surfaces_the_grpc_error() {
    let _temp = env_lock_temp();
    let (addr, handle) = spawn_mock(MockChatService {
        attachment_error: true,
        ..Default::default()
    })
    .await;
    let err = download_attachment_from_peer(
        "did:guardian:local".to_string(),
        "did:guardian:peer".to_string(),
        addr,
        "urn-test-missing".to_string(),
        "did:guardian:sender".to_string(),
        "did:guardian:recipient".to_string(),
        None,
    )
    .await
    .expect_err("server error should surface");
    assert!(err.to_string().contains("mock attachment not found"));
    handle.abort();
}

#[tokio::test]
async fn request_sync_from_peer_persists_a_group_message_and_downloads_its_referenced_attachment() {
    let _temp = env_lock_temp();
    let content = b"group attachment bytes";
    let hash = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(content))
    };
    let chunk = AttachmentChunk {
        attachment_id: "urn-group-attachment".to_string(),
        file_name: "photo.jpg".to_string(),
        mime_type: "image/jpeg".to_string(),
        total_size: content.len() as u64,
        sha256_hash: hash,
        data: content.to_vec(),
    };
    let mut msg = base_push_message();
    msg.recipient_did = "did:guardian:local".to_string();
    msg.sender_did = "did:guardian:peer".to_string();
    msg.group_id = "circle-alpha".to_string();
    msg.encrypted_payload = r#"{"attachment_id":"urn-group-attachment"}"#.to_string();

    let (addr, handle) = spawn_mock(MockChatService {
        sync_messages: vec![msg],
        attachment_chunks: vec![chunk],
        ..Default::default()
    })
    .await;

    request_sync_from_peer(
        "did:guardian:local".to_string(),
        "did:guardian:peer".to_string(),
        addr,
        0,
    )
    .await
    .expect("group message with a referenced attachment should sync and download");
    handle.abort();
}
