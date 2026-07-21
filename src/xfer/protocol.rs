//! Wire protocol for resumable file transfer.

use crate::xfer::manifest::FileManifest;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

/// Hard cap on a single protocol line (memory-abuse guard).
pub const MAX_LINE_BYTES: usize = 1_048_576;
/// Per-read timeout.
pub const IO_TIMEOUT_SECS: u64 = 10;
/// Final receiver response timeout after sender transmits `xfer_done`.
pub const RECEIVER_RESPONSE_TIMEOUT_SECS: u64 = 60;

pub const KIND_OFFER: &str = "xfer_offer";
pub const KIND_ACCEPT: &str = "xfer_accept";
pub const KIND_CHUNK: &str = "xfer_chunk";
pub const KIND_DONE: &str = "xfer_done";
pub const KIND_ACK: &str = "xfer_ack";
pub const KIND_CANCEL: &str = "xfer_cancel";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XferOffer {
    pub kind: String,
    pub circle_id: String,
    pub sender_did: String,
    pub manifest: FileManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XferAccept {
    pub kind: String,
    pub circle_id: String,
    pub sender_did: String,
    pub transfer_id: String,
    pub accept: bool,
    pub have_chunks: Vec<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XferChunk {
    pub kind: String,
    pub transfer_id: String,
    pub index: u32,
    pub sha256: String,
    pub data_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XferDone {
    pub kind: String,
    pub transfer_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XferCancel {
    pub kind: String,
    pub transfer_id: String,
    pub circle_id: String,
    pub sender_did: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XferAck {
    pub kind: String,
    pub transfer_id: String,
    pub received: usize,
    pub sha256_ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct KindEnvelope {
    pub kind: String,
}

pub async fn write_json_line<W, T>(writer: &mut W, message: &T) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut line = serde_json::to_string(message).map_err(std::io::Error::other)?;
    if line.len() > MAX_LINE_BYTES {
        return Err(std::io::Error::other("xfer message exceeds MAX_LINE_BYTES"));
    }
    line.push('\n');
    writer.write_all(line.as_bytes()).await
}

pub async fn read_json_line<R>(reader: &mut R) -> std::io::Result<String>
where
    R: AsyncBufRead + Unpin,
{
    read_json_line_with_timeout(reader, std::time::Duration::from_secs(IO_TIMEOUT_SECS)).await
}

pub async fn read_json_line_with_timeout<R>(
    reader: &mut R,
    timeout: std::time::Duration,
) -> std::io::Result<String>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = String::new();
    let bytes = tokio::time::timeout(timeout, reader.read_line(&mut line))
        .await
        .map_err(|_| std::io::Error::other("xfer read timeout"))??;
    if bytes == 0 {
        return Err(std::io::Error::other("xfer peer closed connection"));
    }
    if line.len() > MAX_LINE_BYTES {
        return Err(std::io::Error::other("xfer line exceeds MAX_LINE_BYTES"));
    }
    Ok(line)
}
