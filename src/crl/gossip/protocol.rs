//! Wire protocol for the CRL gossip exchange.
//!
//! Transport: newline-delimited JSON over TCP - the same house pattern as
//! `nebula::registry_sync` (port 50062) and `did::doc_distribution`. The
//! stream rides the encrypted Nebula overlay, but the channel is NEVER the
//! trust anchor: every `CrlEntry` carries its own issuer signature and is
//! re-verified on receipt via `crl::verify::verify_entry`.
//!
//! Exchange shape (push-pull anti-entropy, one connection):
//!   initiator -> responder : SyncRequest  { fingerprints, merkle_root, .. }
//!   responder -> initiator : SyncResponse { entries (initiator-missing),
//!                                          want (responder-missing) }
//!   initiator -> responder : SyncPush     { entries matching `want` }
//!   responder -> initiator : SyncAck      { merged, merkle_root }

use crate::crl::entry::{CrlEntry, UnrevokeTombstone};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

/// Hard cap on a single protocol line (memory-abuse guard).
pub const MAX_LINE_BYTES: usize = 1_048_576;
/// Hard cap on entries carried in one message.
pub const MAX_ENTRIES_PER_MESSAGE: usize = 1000;
/// Per-read timeout (mirrors `doc_distribution::REQ_TIMEOUT_SECS`).
pub const IO_TIMEOUT_SECS: u64 = 10;

pub const KIND_REQUEST: &str = "crl_sync_request";
pub const KIND_RESPONSE: &str = "crl_sync_response";
pub const KIND_PUSH: &str = "crl_sync_push";
pub const KIND_ACK: &str = "crl_sync_ack";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    pub kind: String,
    pub circle_id: String,
    pub sender_did: String,
    pub sequence: u64,
    pub merkle_root: String,
    pub fingerprints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    pub kind: String,
    pub circle_id: String,
    pub sender_did: String,
    pub sequence: u64,
    pub merkle_root: String,
    /// Full entries the initiator is missing (responder-has / initiator-lacks).
    pub entries: Vec<CrlEntry>,
    /// Full tombstones the initiator is missing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tombstones: Vec<UnrevokeTombstone>,
    /// Fingerprints the responder is missing (initiator-has / responder-lacks).
    pub want: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPush {
    pub kind: String,
    pub entries: Vec<CrlEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tombstones: Vec<UnrevokeTombstone>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncAck {
    pub kind: String,
    pub merged: usize,
    pub merkle_root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn write_json_line<W, T>(writer: &mut W, message: &T) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut line = serde_json::to_string(message).map_err(std::io::Error::other)?;
    if line.len() > MAX_LINE_BYTES {
        return Err(std::io::Error::other(
            "gossip message exceeds MAX_LINE_BYTES",
        ));
    }
    line.push('\n');
    writer.write_all(line.as_bytes()).await
}

pub async fn read_json_line<R>(reader: &mut R) -> std::io::Result<String>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = String::new();
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(IO_TIMEOUT_SECS),
        reader.read_line(&mut line),
    )
    .await
    .map_err(|_| std::io::Error::other("gossip read timeout"))??;
    if bytes == 0 {
        return Err(std::io::Error::other("gossip peer closed connection"));
    }
    if line.len() > MAX_LINE_BYTES {
        return Err(std::io::Error::other("gossip line exceeds MAX_LINE_BYTES"));
    }
    Ok(line)
}
