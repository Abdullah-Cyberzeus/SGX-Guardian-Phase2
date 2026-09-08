use sgx_guardian_client::api::handlers::xfer::{
    CancelResponse, InboxResponse, SendRequest, SendResponse, TransferListResponse,
    TransferSummary,
};
use sgx_guardian_client::xfer::engine::{
    bytes_transferred, cancel_transfer, last_transfer, send_source, transfers_received,
    transfers_sent, SendSource,
};
use sgx_guardian_client::xfer::errors::XferError;
use sgx_guardian_client::xfer::persistence::XFER_BASE_ENV;
use sgx_guardian_client::xfer::{XferConfig, MAX_TRANSFER_FILE_BYTES};

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_env() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct EnvGuard {
    key: &'static str,
    old: Option<std::ffi::OsString>,
}

impl EnvGuard {
    fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        let old = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, old }
    }
    fn remove(key: &'static str) -> Self {
        let old = std::env::var_os(key);
        std::env::remove_var(key);
        Self { key, old }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(value) = self.old.take() {
            std::env::set_var(self.key, value);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

#[test]
fn send_request_accepts_path_only() {
    let req: SendRequest = serde_json::from_str(r#"{"peer_did":"did:p","path":"/tmp/a"}"#).unwrap();
    assert_eq!(req.path.as_deref(), Some("/tmp/a"));
    assert!(req.vault_id.is_none());
}

#[test]
fn send_request_accepts_vault_only() {
    let req: SendRequest = serde_json::from_str(r#"{"peer_did":"did:p","vault_id":"v"}"#).unwrap();
    assert_eq!(req.vault_id.as_deref(), Some("v"));
}

#[test]
fn send_request_accepts_both_for_handler_validation() {
    let req: SendRequest = serde_json::from_str(r#"{"peer_did":"did:p","path":"p","vault_id":"v"}"#).unwrap();
    assert!(req.path.is_some() && req.vault_id.is_some());
}

#[test]
fn send_response_round_trips() {
    let response = SendResponse { status: "accepted".into(), transfer_id: "t".into(), message: "queued".into() };
    assert_eq!(serde_json::from_str::<SendResponse>(&serde_json::to_string(&response).unwrap()).unwrap().transfer_id, "t");
}

#[test]
fn transfer_summary_serializes_optionals() {
    let summary = TransferSummary {
        transfer_id: "t".into(),
        direction: "outbound".into(),
        status: "queued".into(),
        circle_id: "c".into(),
        filename: "f.txt".into(),
        size: 1,
        chunk_bytes: 2,
        chunk_count: 3,
        peer_did: Some("did:p".into()),
        sender_did: Some("did:s".into()),
        file_path: Some("/tmp/f".into()),
        sent_chunks: Some(0),
        requested_chunks: Some(3),
        received_chunks: None,
        bytes_sent: Some(0),
        last_error: None,
        updated_at: "t".into(),
        completed_at: None,
    };
    assert_eq!(serde_json::to_value(summary).unwrap()["chunk_count"], 3);
}

#[test]
fn transfer_list_response_serializes_counters() {
    let response = TransferListResponse {
        count: 0,
        transfers: vec![],
        transfers_sent: 1,
        transfers_received: 2,
        bytes_transferred: 3,
        last_transfer: None,
    };
    assert_eq!(serde_json::to_value(response).unwrap()["bytes_transferred"], 3);
}

#[test]
fn cancel_response_serializes_message() {
    let response = CancelResponse { status: "cancelled".into(), transfer_id: "t".into(), message: "done".into() };
    assert_eq!(serde_json::to_value(response).unwrap()["status"], "cancelled");
}

#[test]
fn inbox_response_serializes_empty() {
    let response = InboxResponse { count: 0, files: vec![] };
    assert_eq!(serde_json::to_value(response).unwrap()["files"].as_array().unwrap().len(), 0);
}

#[test]
fn default_xfer_config_has_safe_limits() {
    let _env_lock = lock_env();
    let _a = EnvGuard::remove("SGX_XFER_ENABLED");
    let _b = EnvGuard::remove("SGX_XFER_PORT");
    let _c = EnvGuard::remove("SGX_XFER_CHUNK_BYTES");
    let _d = EnvGuard::remove("SGX_XFER_MAX_FILE_BYTES");
    let cfg = XferConfig::from_env();
    assert!(cfg.enabled);
    assert_eq!(cfg.port, XferConfig::DEFAULT_PORT);
    assert_eq!(cfg.max_file_bytes, MAX_TRANSFER_FILE_BYTES);
}

macro_rules! enabled_env_tests {
    ($($name:ident => $value:expr, $expected:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            let _env_lock = lock_env();
            let _guard = EnvGuard::set("SGX_XFER_ENABLED", $value);
            assert_eq!(XferConfig::from_env().enabled, $expected);
        }
    )+};
}

enabled_env_tests! {
    enabled_false_string => "false", false,
    enabled_zero_string => "0", false,
    enabled_off_string => "off", false,
    enabled_true_string => "true", true,
    enabled_yes_string => "yes", true,
}

macro_rules! port_env_tests {
    ($($name:ident => $value:expr, $expected:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            let _env_lock = lock_env();
            let _guard = EnvGuard::set("SGX_XFER_PORT", $value);
            assert_eq!(XferConfig::from_env().port, $expected);
        }
    )+};
}

port_env_tests! {
    port_accepts_valid => "60000", 60000,
    port_rejects_zero => "0", XferConfig::DEFAULT_PORT,
    port_rejects_text => "bad", XferConfig::DEFAULT_PORT,
    port_trims_spaces => " 60001 ", 60001,
}

macro_rules! chunk_env_tests {
    ($($name:ident => $value:expr, $expected:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            let _env_lock = lock_env();
            let _guard = EnvGuard::set("SGX_XFER_CHUNK_BYTES", $value);
            assert_eq!(XferConfig::from_env().chunk_bytes, $expected);
        }
    )+};
}

chunk_env_tests! {
    chunk_clamps_low => "1", 65536,
    chunk_accepts_middle => "131072", 131072,
    chunk_clamps_high => "999999", 524288,
    chunk_rejects_text => "bad", XferConfig::DEFAULT_CHUNK_BYTES,
}

macro_rules! max_file_env_tests {
    ($($name:ident => $value:expr, $expected:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            let _env_lock = lock_env();
            let _guard = EnvGuard::set("SGX_XFER_MAX_FILE_BYTES", $value);
            assert_eq!(XferConfig::from_env().max_file_bytes, $expected);
        }
    )+};
}

max_file_env_tests! {
    max_file_rejects_zero => "0", XferConfig::DEFAULT_MAX_FILE_BYTES,
    max_file_accepts_small => "1024", 1024,
    max_file_clamps_large => "999999999", MAX_TRANSFER_FILE_BYTES,
    max_file_rejects_text => "bad", XferConfig::DEFAULT_MAX_FILE_BYTES,
}

#[tokio::test]
async fn send_source_disabled_rejects_path_before_filesystem() {
    let cfg = XferConfig { enabled: false, port: 1, chunk_bytes: 65_536, max_file_bytes: 1 };
    let err = send_source("node".into(), cfg, "did:a".into(), "did:p".into(), SendSource::Path("missing".into())).await.unwrap_err();
    assert!(matches!(err, XferError::Conflict(_)));
}

#[tokio::test]
async fn send_source_disabled_rejects_vault_before_lookup() {
    let cfg = XferConfig { enabled: false, port: 1, chunk_bytes: 65_536, max_file_bytes: 1 };
    let err = send_source("node".into(), cfg, "did:a".into(), "did:p".into(), SendSource::VaultId("vault".into())).await.unwrap_err();
    assert!(matches!(err, XferError::Conflict(_)));
}

#[tokio::test]
async fn cancel_missing_transfer_returns_false() {
    let _env_lock = lock_env();
    let dir = tempfile::tempdir().unwrap();
    let _guard = EnvGuard::set(XFER_BASE_ENV, dir.path());
    assert!(!cancel_transfer("missing").await.unwrap());
}

#[tokio::test]
async fn cancel_empty_transfer_id_returns_false() {
    let _env_lock = lock_env();
    let dir = tempfile::tempdir().unwrap();
    let _guard = EnvGuard::set(XFER_BASE_ENV, dir.path());
    assert!(!cancel_transfer("").await.unwrap());
}

#[test]
fn xfer_counters_are_readable() {
    let _ = transfers_sent();
    let _ = transfers_received();
    let _ = bytes_transferred();
    let _ = last_transfer();
}

#[test]
fn send_source_path_variant_debug_mentions_path() {
    assert!(format!("{:?}", SendSource::Path("a.txt".into())).contains("Path"));
}

#[test]
fn send_source_vault_variant_debug_mentions_vault() {
    assert!(format!("{:?}", SendSource::VaultId("v".into())).contains("VaultId"));
}

#[test]
fn xfer_error_display_file_too_large() {
    assert_eq!(XferError::FileTooLarge { size: 2, max: 1 }.to_string(), "file too large: 2 > 1");
}

#[test]
fn xfer_error_display_circle_mismatch() {
    assert!(XferError::CircleMismatch { expected: "a".into(), got: "b".into() }.to_string().contains("expected a"));
}

#[test]
fn xfer_error_display_cancelled() {
    assert_eq!(XferError::Cancelled("t".into()).to_string(), "transfer cancelled: t");
}

#[test]
fn xfer_error_display_peer_not_found() {
    assert!(XferError::PeerNotFound("did:p".into()).to_string().contains("peer not found"));
}

#[test]
fn xfer_error_display_source_not_found() {
    assert!(XferError::SourceNotFound("missing".into()).to_string().contains("source not found"));
}

#[test]
fn xfer_error_display_transfer_not_found() {
    assert!(XferError::TransferNotFound("t".into()).to_string().contains("transfer not found"));
}

#[test]
fn xfer_error_display_hash_mismatch() {
    assert!(XferError::HashMismatch { expected: "a".into(), got: "b".into() }.to_string().contains("hash mismatch"));
}

#[test]
fn xfer_error_display_invalid_proof() {
    assert!(XferError::InvalidProof("sig".into()).to_string().contains("invalid transfer proof"));
}

#[test]
fn xfer_error_display_revoked_peer() {
    assert!(XferError::RevokedPeer("did:p".into()).to_string().contains("peer is revoked"));
}

#[test]
fn xfer_error_display_invalid_structure() {
    assert!(XferError::InvalidStructure("bad".into()).to_string().contains("invalid transfer structure"));
}

#[test]
fn send_source_clone_preserves_variant() {
    let cloned = SendSource::VaultId("v".into()).clone();
    assert!(matches!(cloned, SendSource::VaultId(id) if id == "v"));
}

#[tokio::test]
async fn cancel_missing_transfer_is_idempotent() {
    let _env_lock = lock_env();
    let dir = tempfile::tempdir().unwrap();
    let _guard = EnvGuard::set(XFER_BASE_ENV, dir.path());
    assert!(!cancel_transfer("missing").await.unwrap());
    assert!(!cancel_transfer("missing").await.unwrap());
}

macro_rules! send_request_peer_cases {
    ($($name:ident => $peer:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            let value = serde_json::json!({"peer_did": $peer, "path": "p"});
            let req: SendRequest = serde_json::from_value(value).unwrap();
            assert_eq!(req.peer_did, $peer);
        }
    )+};
}

send_request_peer_cases! {
    peer_empty_deserializes_for_handler_validation => "",
    peer_did_deserializes => "did:guardian:peer",
    peer_space_deserializes => "peer space",
    peer_long_deserializes => "peer-abcdefghijklmnopqrstuvwxyz",
    peer_uuid_deserializes => "550e8400-e29b-41d4-a716-446655440000"
}
