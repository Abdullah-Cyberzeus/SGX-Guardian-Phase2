//! Transfer engine: inbound listener + outbound sender tasks.

use super::errors::XferError;
use super::manifest::{inspect_file_blocking, FileManifest};
use super::persistence;
use super::protocol::{
    self, KindEnvelope, XferAccept, XferAck, XferCancel, XferChunk, XferDone, XferOffer,
    KIND_ACCEPT, KIND_ACK, KIND_CANCEL, KIND_CHUNK, KIND_DONE, KIND_OFFER,
};
use super::store::{self, TransferStatus};
use super::verify;
use super::XferConfig;
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::crl::gossip::engine::{active_gossip_peers, did_record_path, GossipPeer};
use crate::did::{DidRecord, Resolver};
use crate::key_manager::KeyManager;
use crate::vault::namespace::validate_vault_id;
use base64::{engine::general_purpose, Engine as _};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::fs::OpenOptions;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

static TRANSFERS_SENT: AtomicU64 = AtomicU64::new(0);
static TRANSFERS_RECEIVED: AtomicU64 = AtomicU64::new(0);
static BYTES_TRANSFERRED: AtomicU64 = AtomicU64::new(0);
static LAST_TRANSFER: Lazy<RwLock<Option<LastTransfer>>> = Lazy::new(|| RwLock::new(None));
static ACTIVE_SENDS: Lazy<DashMap<String, Arc<AtomicBool>>> = Lazy::new(DashMap::new);

#[derive(Debug, Clone, Serialize)]
pub struct LastTransfer {
    pub direction: String,
    pub transfer_id: String,
    pub peer_did: String,
    pub filename: String,
    pub bytes: u64,
    pub chunks: u32,
    pub status: String,
    pub at: String,
}

#[derive(Debug, Clone)]
struct PreparedTransfer {
    node_id: String,
    peer: GossipPeer,
    manifest: FileManifest,
    file_path: PathBuf,
    staged_plaintext: Option<StagedPlaintext>,
}

#[derive(Debug, Clone)]
struct StagedPlaintext {
    dir_path: PathBuf,
    file_path: PathBuf,
}

#[derive(Debug, Clone)]
pub enum SendSource {
    Path(PathBuf),
    VaultId(String),
}

pub fn transfers_sent() -> u64 {
    TRANSFERS_SENT.load(Ordering::Relaxed)
}

pub fn transfers_received() -> u64 {
    TRANSFERS_RECEIVED.load(Ordering::Relaxed)
}

pub fn bytes_transferred() -> u64 {
    BYTES_TRANSFERRED.load(Ordering::Relaxed)
}

pub fn last_transfer() -> Option<LastTransfer> {
    LAST_TRANSFER.read().ok().and_then(|guard| guard.clone())
}

fn record_last_transfer(transfer: LastTransfer) {
    if let Ok(mut guard) = LAST_TRANSFER.write() {
        *guard = Some(transfer);
    }
}

fn load_identity(node_id: &str) -> Result<(DidRecord, Arc<KeyManager>, String), XferError> {
    let record = DidRecord::load(&did_record_path())?;
    let km = crate::vc::issue::load_runtime_key_manager(node_id)
        .map_err(|error| XferError::InvalidStructure(format!("key manager: {}", error)))?;
    let circle_id = crate::crl::issue::current_circle_id()
        .unwrap_or_else(|_| crate::crl::issue::DEFAULT_CIRCLE_ID.to_string());
    Ok((record, km, circle_id))
}

pub async fn send_file(
    node_id: String,
    config: XferConfig,
    peer_did: String,
    path: PathBuf,
) -> Result<String, XferError> {
    send_source(node_id, config, peer_did, SendSource::Path(path)).await
}

pub async fn send_vault_record(
    node_id: String,
    config: XferConfig,
    peer_did: String,
    vault_id: String,
) -> Result<String, XferError> {
    send_source(node_id, config, peer_did, SendSource::VaultId(vault_id)).await
}

pub async fn send_source(
    node_id: String,
    config: XferConfig,
    peer_did: String,
    source: SendSource,
) -> Result<String, XferError> {
    if !config.enabled {
        return Err(XferError::Conflict(
            "file transfer is disabled via SGX_XFER_ENABLED".to_string(),
        ));
    }
    let prepared = prepare_outbound_from_source(&node_id, &peer_did, source, &config).await?;
    let transfer_id = prepared.manifest.transfer_id.clone();
    if ACTIVE_SENDS.contains_key(&transfer_id) {
        return Err(XferError::Conflict(format!(
            "transfer {} is already active",
            transfer_id
        )));
    }
    let cancel_flag = Arc::new(AtomicBool::new(false));
    ACTIVE_SENDS.insert(transfer_id.clone(), cancel_flag.clone());
    let config_for_task = config.clone();
    let node_id_for_task = prepared.node_id.clone();
    tokio::spawn(async move {
        let transfer_id = prepared.manifest.transfer_id.clone();
        let outcome = run_outbound(prepared, &config_for_task, cancel_flag.clone()).await;
        if let Err(error) = outcome {
            let message = error.to_string();
            let _ = match error {
                XferError::Cancelled(_) => {
                    store::update_outbox(&transfer_id, |progress| {
                        progress.status = TransferStatus::Cancelled;
                        progress.last_error = Some(message.clone());
                    })
                    .await
                }
                _ => {
                    store::update_outbox(&transfer_id, |progress| {
                        progress.status = TransferStatus::Failed;
                        progress.last_error = Some(message.clone());
                    })
                    .await
                }
            };
            log_audit(
                &node_id_for_task,
                AuditCategory::Xfer,
                AuditSeverity::Warning,
                AuditAction::Failed,
                &format!("XFER outbound transfer {} failed: {}", transfer_id, message),
            );
        }
        ACTIVE_SENDS.remove(&transfer_id);
    });
    Ok(transfer_id)
}

pub async fn cancel_transfer(transfer_id: &str) -> Result<bool, XferError> {
    let mut found = false;
    if let Some(flag) = ACTIVE_SENDS.get(transfer_id) {
        flag.store(true, Ordering::Relaxed);
        found = true;
    }
    if store::load_outbox(transfer_id).await?.is_some() {
        found = true;
        let _ = store::update_outbox(transfer_id, |progress| {
            progress.status = TransferStatus::Cancelled;
            progress.last_error = Some("cancelled by user".to_string());
        })
        .await?;
    }
    if store::cancel_transfer_files(transfer_id).await? {
        found = true;
    }
    Ok(found)
}

async fn prepare_outbound_from_source(
    node_id: &str,
    peer_did: &str,
    source: SendSource,
    config: &XferConfig,
) -> Result<PreparedTransfer, XferError> {
    let (record, km, circle_id) = load_identity(node_id)?;
    let peer = active_gossip_peers(&record.did)
        .into_iter()
        .find(|peer| peer.did == peer_did)
        .ok_or_else(|| XferError::PeerNotFound(peer_did.to_string()))?;
    let chunk_bytes = config.chunk_bytes;
    let max_file_bytes = config.max_file_bytes;
    let (path, file_path_display, material, staged_plaintext) =
        prepare_outbound_material(source, chunk_bytes, max_file_bytes).await?;
    let vm_ref = format!("{}#dkp-v{}", record.did, record.current_dkp_version.max(1));
    let manifest =
        FileManifest::build_signed(&circle_id, &record.did, material, chunk_bytes, &km, &vm_ref)?;
    let create_result = store::create_outbox(peer_did, &file_path_display, &manifest).await;
    if let Err(error) = create_result {
        if let Some(staged_plaintext) = &staged_plaintext {
            let _ = cleanup_outbound_staging(staged_plaintext).await;
        }
        return Err(error);
    }
    Ok(PreparedTransfer {
        node_id: node_id.to_string(),
        peer,
        manifest,
        file_path: path,
        staged_plaintext,
    })
}

async fn prepare_outbound_material(
    source: SendSource,
    chunk_bytes: u32,
    max_file_bytes: u64,
) -> Result<
    (
        PathBuf,
        String,
        crate::xfer::manifest::FileMaterial,
        Option<StagedPlaintext>,
    ),
    XferError,
> {
    match source {
        SendSource::Path(path) => {
            if path.as_os_str().is_empty() {
                return Err(XferError::InvalidStructure(
                    "file path must not be empty".to_string(),
                ));
            }
            let inspect_path = path.clone();
            let material = tokio::task::spawn_blocking(move || {
                inspect_file_blocking(inspect_path, chunk_bytes, max_file_bytes)
            })
            .await
            .map_err(|error| {
                XferError::InvalidStructure(format!("inspect file task: {}", error))
            })??;
            let file_path_display = path.display().to_string();
            Ok((path, file_path_display, material, None))
        }
        SendSource::VaultId(vault_id) => {
            let staged_plaintext = stage_vault_record(&vault_id, max_file_bytes).await?;
            let inspect_path = staged_plaintext.file_path.clone();
            let material_result = tokio::task::spawn_blocking(move || {
                inspect_file_blocking(inspect_path, chunk_bytes, max_file_bytes)
            })
            .await
            .map_err(|error| XferError::InvalidStructure(format!("inspect file task: {}", error)));
            let material = match material_result {
                Ok(Ok(material)) => material,
                Ok(Err(error)) => {
                    let _ = cleanup_outbound_staging(&staged_plaintext).await;
                    return Err(error);
                }
                Err(error) => {
                    let _ = cleanup_outbound_staging(&staged_plaintext).await;
                    return Err(error);
                }
            };
            Ok((
                staged_plaintext.file_path.clone(),
                format!("vault:{}", vault_id),
                material,
                Some(staged_plaintext),
            ))
        }
    }
}

async fn stage_vault_record(
    vault_id: &str,
    max_file_bytes: u64,
) -> Result<StagedPlaintext, XferError> {
    let vault_id = validate_vault_id(vault_id)
        .map_err(|error| XferError::InvalidStructure(error.to_string()))?;
    let config = crate::vault::VaultConfig::from_env();
    let record = crate::vault::persistence::find_record(&config, &vault_id)
        .await
        .map_err(map_vault_error)?
        .ok_or_else(|| XferError::SourceNotFound(format!("vault file not found: {}", vault_id)))?;
    if record.size_plain > max_file_bytes {
        return Err(XferError::FileTooLarge {
            size: record.size_plain,
            max: max_file_bytes,
        });
    }

    let staging_id = format!("vault-send-{}", Uuid::new_v4());
    let dir_path = persistence::create_secure_staging_dir(&staging_id).await?;
    let file_path = dir_path.join(crate::xfer::manifest::safe_manifest_name(&record.filename));
    if let Err(error) = crate::vault::ingest::decrypt_record_to_path(&record, &file_path)
        .await
        .map_err(map_vault_error)
    {
        let staged_plaintext = StagedPlaintext {
            dir_path,
            file_path,
        };
        let _ = cleanup_outbound_staging(&staged_plaintext).await;
        return Err(error);
    }

    Ok(StagedPlaintext {
        dir_path,
        file_path,
    })
}

async fn cleanup_outbound_staging(staged_plaintext: &StagedPlaintext) -> Result<(), XferError> {
    if let Err(error) = crate::vault::ingest::cleanup_plaintext(&staged_plaintext.file_path).await {
        if !matches!(error, crate::vault::VaultError::Io(ref io) if io.kind() == std::io::ErrorKind::NotFound)
        {
            return Err(map_vault_error(error));
        }
    }
    match tokio::fs::remove_dir_all(&staged_plaintext.dir_path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn map_vault_error(error: crate::vault::VaultError) -> XferError {
    match error {
        crate::vault::VaultError::NotFound(message) => XferError::SourceNotFound(message),
        crate::vault::VaultError::InvalidStructure(message) => XferError::InvalidStructure(message),
        crate::vault::VaultError::Conflict(message) => XferError::Conflict(message),
        crate::vault::VaultError::Integrity { expected, got } => {
            XferError::HashMismatch { expected, got }
        }
        crate::vault::VaultError::Io(io) if io.kind() == std::io::ErrorKind::NotFound => {
            XferError::SourceNotFound(io.to_string())
        }
        other => XferError::Conflict(other.to_string()),
    }
}

async fn run_outbound(
    prepared: PreparedTransfer,
    config: &XferConfig,
    cancel_flag: Arc<AtomicBool>,
) -> Result<(), XferError> {
    if cancel_flag.load(Ordering::Relaxed) {
        return Err(XferError::Cancelled(prepared.manifest.transfer_id.clone()));
    }

    store::update_outbox(&prepared.manifest.transfer_id, |progress| {
        progress.status = TransferStatus::Connecting;
    })
    .await?;

    let addr = format!("{}:{}", prepared.peer.overlay_ip, config.port);
    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(protocol::IO_TIMEOUT_SECS),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| XferError::InvalidStructure(format!("timeout connecting {}", addr)))??;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    run_outbound_stream_with_cleanup(prepared, &mut reader, &mut write_half, cancel_flag).await
}

async fn run_outbound_stream_with_cleanup<R, W>(
    prepared: PreparedTransfer,
    reader: &mut BufReader<R>,
    writer: &mut W,
    cancel_flag: Arc<AtomicBool>,
) -> Result<(), XferError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let staged_plaintext = prepared.staged_plaintext.clone();
    let outcome = run_outbound_stream(prepared, reader, writer, cancel_flag).await;
    if let Some(staged_plaintext) = staged_plaintext {
        match cleanup_outbound_staging(&staged_plaintext).await {
            Ok(()) => outcome,
            Err(cleanup_error) => outcome.and(Err(cleanup_error)),
        }
    } else {
        outcome
    }
}

async fn run_outbound_stream<R, W>(
    prepared: PreparedTransfer,
    reader: &mut BufReader<R>,
    writer: &mut W,
    cancel_flag: Arc<AtomicBool>,
) -> Result<(), XferError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if cancel_flag.load(Ordering::Relaxed) {
        return Err(XferError::Cancelled(prepared.manifest.transfer_id.clone()));
    }

    let offer = XferOffer {
        kind: KIND_OFFER.to_string(),
        circle_id: prepared.manifest.circle_id.clone(),
        sender_did: prepared.manifest.sender_did.clone(),
        manifest: prepared.manifest.clone(),
    };
    protocol::write_json_line(writer, &offer).await?;

    let line = protocol::read_json_line(reader).await?;
    let accept: XferAccept = serde_json::from_str(line.trim())?;
    if let Some(error) = accept.error.as_deref() {
        return Err(XferError::Conflict(format!(
            "peer {} rejected transfer {}: {}",
            prepared.peer.did, prepared.manifest.transfer_id, error
        )));
    }
    if accept.kind != KIND_ACCEPT {
        return Err(XferError::InvalidStructure(format!(
            "unexpected message kind '{}'",
            accept.kind
        )));
    }
    if accept.transfer_id != prepared.manifest.transfer_id {
        return Err(XferError::InvalidStructure(format!(
            "transfer id mismatch: expected {}, got {}",
            prepared.manifest.transfer_id, accept.transfer_id
        )));
    }
    if accept.sender_did != prepared.peer.did {
        return Err(XferError::InvalidStructure(format!(
            "peer identity mismatch: expected {}, got {}",
            prepared.peer.did, accept.sender_did
        )));
    }
    if accept.circle_id != prepared.manifest.circle_id {
        return Err(XferError::CircleMismatch {
            expected: prepared.manifest.circle_id.clone(),
            got: accept.circle_id,
        });
    }
    let have = accept
        .have_chunks
        .into_iter()
        .map(|index| {
            if index >= prepared.manifest.chunk_count {
                Err(XferError::InvalidStructure(format!(
                    "peer reported out-of-range chunk {}",
                    index
                )))
            } else {
                Ok(index)
            }
        })
        .collect::<Result<HashSet<_>, _>>()?;
    let missing = (0..prepared.manifest.chunk_count)
        .filter(|index| !have.contains(index))
        .collect::<Vec<_>>();

    store::update_outbox(&prepared.manifest.transfer_id, |progress| {
        progress.status = TransferStatus::Sending;
        progress.requested_chunks = missing.len() as u32;
        progress.sent_chunks = 0;
        progress.bytes_sent = 0;
        progress.last_error = None;
    })
    .await?;

    if !missing.is_empty() {
        let mut file = tokio::fs::File::open(&prepared.file_path).await?;
        for index in missing.iter().copied() {
            if cancel_flag.load(Ordering::Relaxed) {
                send_cancel(writer, &prepared.manifest).await;
                return Err(XferError::Cancelled(prepared.manifest.transfer_id.clone()));
            }
            let payload = read_chunk_from_file(&mut file, &prepared.manifest, index).await?;
            let sha256 = prepared.manifest.chunk_digests[index as usize].clone();
            let message = XferChunk {
                kind: KIND_CHUNK.to_string(),
                transfer_id: prepared.manifest.transfer_id.clone(),
                index,
                sha256,
                data_b64: general_purpose::STANDARD.encode(&payload),
            };
            protocol::write_json_line(writer, &message).await?;
            BYTES_TRANSFERRED.fetch_add(payload.len() as u64, Ordering::Relaxed);
            store::update_outbox(&prepared.manifest.transfer_id, |progress| {
                progress.sent_chunks += 1;
                progress.bytes_sent += payload.len() as u64;
            })
            .await?;
        }
    }

    if cancel_flag.load(Ordering::Relaxed) {
        send_cancel(writer, &prepared.manifest).await;
        return Err(XferError::Cancelled(prepared.manifest.transfer_id.clone()));
    }

    let done = XferDone {
        kind: KIND_DONE.to_string(),
        transfer_id: prepared.manifest.transfer_id.clone(),
    };
    protocol::write_json_line(writer, &done).await?;

    let ack_line = protocol::read_json_line_with_timeout(
        reader,
        std::time::Duration::from_secs(protocol::RECEIVER_RESPONSE_TIMEOUT_SECS),
    )
    .await?;
    let ack: XferAck = serde_json::from_str(ack_line.trim())?;
    if ack.kind != KIND_ACK {
        return Err(XferError::InvalidStructure(format!(
            "unexpected ack kind '{}'",
            ack.kind
        )));
    }
    if ack.transfer_id != prepared.manifest.transfer_id {
        return Err(XferError::InvalidStructure(format!(
            "ack transfer mismatch: expected {}, got {}",
            prepared.manifest.transfer_id, ack.transfer_id
        )));
    }
    if let Some(error) = ack.error {
        return Err(XferError::Conflict(format!(
            "receiver failed transfer {}: {}",
            prepared.manifest.transfer_id, error
        )));
    }
    if !ack.sha256_ok {
        return Err(XferError::HashMismatch {
            expected: prepared.manifest.file_sha256.clone(),
            got: "receiver-reported-mismatch".to_string(),
        });
    }

    store::update_outbox(&prepared.manifest.transfer_id, |progress| {
        progress.status = TransferStatus::Completed;
        progress.completed_at = Some(chrono::Utc::now().to_rfc3339());
        progress.last_error = None;
    })
    .await?;

    TRANSFERS_SENT.fetch_add(1, Ordering::Relaxed);
    record_last_transfer(LastTransfer {
        direction: "sent".into(),
        transfer_id: prepared.manifest.transfer_id.clone(),
        peer_did: prepared.peer.did.clone(),
        filename: prepared.manifest.filename.clone(),
        bytes: prepared.manifest.size,
        chunks: prepared.manifest.chunk_count,
        status: "completed".into(),
        at: chrono::Utc::now().to_rfc3339(),
    });
    log_audit(
        &prepared.node_id,
        AuditCategory::Xfer,
        AuditSeverity::Info,
        AuditAction::Succeeded,
        &format!(
            "XFER sent transfer_id={} peer={} file={} requested_chunks={} bytes={}",
            prepared.manifest.transfer_id,
            prepared.peer.did,
            prepared.manifest.filename,
            missing.len(),
            prepared.manifest.size
        ),
    );
    println!(
        "📦 XFER sent transfer_id={} peer={} file={} requested_chunks={}",
        prepared.manifest.transfer_id,
        prepared.peer.did,
        prepared.manifest.filename,
        missing.len()
    );
    Ok(())
}

pub async fn listener_task(node_id: String, resolver: Resolver, config: XferConfig) {
    let addr = format!("0.0.0.0:{}", config.port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(listener) => {
            println!("📦 XFER listener on {}", addr);
            listener
        }
        Err(error) => {
            eprintln!("❌ XFER bind failed on {}: {}", addr, error);
            log_audit(
                &node_id,
                AuditCategory::Xfer,
                AuditSeverity::Critical,
                AuditAction::Failed,
                &format!("XFER listener bind failed on {}: {}", addr, error),
            );
            return;
        }
    };
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let node_id = node_id.clone();
                let resolver = resolver.clone();
                let config = config.clone();
                tokio::spawn(async move {
                    if let Err(reason) = handle_inbound(stream, &node_id, &resolver, &config).await
                    {
                        tracing::warn!("XFER inbound from {} failed: {}", peer_addr, reason);
                    }
                });
            }
            Err(error) => eprintln!("XFER accept error: {}", error),
        }
    }
}

async fn handle_inbound(
    stream: TcpStream,
    node_id: &str,
    resolver: &Resolver,
    _config: &XferConfig,
) -> Result<(), XferError> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    handle_inbound_stream(&mut reader, &mut write_half, node_id, resolver, _config).await
}

async fn handle_inbound_stream<R, W>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    node_id: &str,
    resolver: &Resolver,
    _config: &XferConfig,
) -> Result<(), XferError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let line = protocol::read_json_line(reader).await?;
    let offer: XferOffer = serde_json::from_str(line.trim())?;

    let (record, _km, circle_id) = match load_identity(node_id) {
        Ok(identity) => identity,
        Err(error) => {
            reject(
                writer,
                node_id,
                &offer.circle_id,
                &offer.manifest.transfer_id,
                &error.to_string(),
            )
            .await;
            return Err(error);
        }
    };

    if offer.kind != KIND_OFFER {
        let reason = format!("unexpected message kind '{}'", offer.kind);
        reject(
            writer,
            &record.did,
            &circle_id,
            &offer.manifest.transfer_id,
            &reason,
        )
        .await;
        return Err(XferError::InvalidStructure(reason));
    }
    if offer.circle_id != circle_id {
        let reason = format!(
            "circle mismatch: local={} peer={}",
            circle_id, offer.circle_id
        );
        reject(
            writer,
            &record.did,
            &circle_id,
            &offer.manifest.transfer_id,
            &reason,
        )
        .await;
        return Err(XferError::CircleMismatch {
            expected: circle_id,
            got: offer.circle_id,
        });
    }
    if offer.sender_did == record.did {
        let reason = "sender_did equals local DID".to_string();
        reject(
            writer,
            &record.did,
            &offer.circle_id,
            &offer.manifest.transfer_id,
            &reason,
        )
        .await;
        return Err(XferError::InvalidStructure(reason));
    }
    if crate::crl::is_revoked(&offer.sender_did) {
        let reason = format!("sender is revoked: {}", offer.sender_did);
        audit_reject(
            node_id,
            &offer.sender_did,
            &offer.manifest.transfer_id,
            &reason,
        );
        reject(
            writer,
            &record.did,
            &offer.circle_id,
            &offer.manifest.transfer_id,
            &reason,
        )
        .await;
        return Err(XferError::RevokedPeer(offer.sender_did));
    }
    let peers = active_gossip_peers(&record.did);
    let Some(sender) = peers
        .iter()
        .find(|peer| peer.did == offer.sender_did)
        .cloned()
    else {
        let reason = format!("sender not in local peer directory: {}", offer.sender_did);
        audit_reject(
            node_id,
            &offer.sender_did,
            &offer.manifest.transfer_id,
            &reason,
        );
        reject(
            writer,
            &record.did,
            &offer.circle_id,
            &offer.manifest.transfer_id,
            &reason,
        )
        .await;
        return Err(XferError::PeerNotFound(offer.sender_did));
    };
    if offer.manifest.sender_did != sender.did {
        let reason = format!(
            "manifest sender mismatch: offer={}, manifest={}",
            sender.did, offer.manifest.sender_did
        );
        reject(
            writer,
            &record.did,
            &offer.circle_id,
            &offer.manifest.transfer_id,
            &reason,
        )
        .await;
        return Err(XferError::InvalidStructure(reason));
    }
    if offer.manifest.circle_id != offer.circle_id {
        let reason = format!(
            "manifest circle mismatch: offer={}, manifest={}",
            offer.circle_id, offer.manifest.circle_id
        );
        reject(
            writer,
            &record.did,
            &offer.circle_id,
            &offer.manifest.transfer_id,
            &reason,
        )
        .await;
        return Err(XferError::InvalidStructure(reason));
    }
    if let Err(error) = verify::verify_manifest(
        &offer.manifest,
        resolver,
        &offer.sender_did,
        &offer.circle_id,
    )
    .await
    {
        audit_reject(
            node_id,
            &offer.sender_did,
            &offer.manifest.transfer_id,
            &error.to_string(),
        );
        reject(
            writer,
            &record.did,
            &offer.circle_id,
            &offer.manifest.transfer_id,
            &error.to_string(),
        )
        .await;
        return Err(error);
    }

    let state = store::prepare_receiver(&offer.manifest).await?;
    let have_chunks = if state.status == TransferStatus::Completed
        && tokio::fs::try_exists(persistence::final_path(
            &offer.manifest.circle_id,
            &offer.manifest.transfer_id,
            &offer.manifest.filename,
        ))
        .await?
    {
        (0..offer.manifest.chunk_count).collect()
    } else {
        state.have_chunks()
    };
    let accept = XferAccept {
        kind: KIND_ACCEPT.to_string(),
        circle_id: offer.manifest.circle_id.clone(),
        sender_did: record.did.clone(),
        transfer_id: offer.manifest.transfer_id.clone(),
        accept: true,
        have_chunks: have_chunks.clone(),
        error: None,
    };
    protocol::write_json_line(writer, &accept).await?;
    log_audit(
        node_id,
        AuditCategory::Xfer,
        AuditSeverity::Info,
        AuditAction::Succeeded,
        &format!(
            "XFER offer accepted transfer_id={} sender={} file={} have_chunks={}",
            offer.manifest.transfer_id,
            sender.did,
            offer.manifest.filename,
            have_chunks.len()
        ),
    );

    let final_path = persistence::final_path(
        &offer.manifest.circle_id,
        &offer.manifest.transfer_id,
        &offer.manifest.filename,
    );
    let already_completed = state.status == TransferStatus::Completed;
    let mut part_file = if already_completed {
        None
    } else {
        Some(open_part_file(&offer.manifest).await?)
    };

    loop {
        let line = protocol::read_json_line(reader).await?;
        let envelope: KindEnvelope = serde_json::from_str(line.trim())?;
        match envelope.kind.as_str() {
            KIND_CHUNK => {
                let chunk: XferChunk = serde_json::from_str(line.trim())?;
                let Some(file) = part_file.as_mut() else {
                    return Err(XferError::Conflict(format!(
                        "transfer {} already completed",
                        offer.manifest.transfer_id
                    )));
                };
                handle_chunk(node_id, &offer.manifest, file, chunk).await?;
            }
            KIND_CANCEL => {
                let cancel: XferCancel = serde_json::from_str(line.trim())?;
                validate_cancel(&offer.manifest, &cancel).await?;
                drop(part_file.take());
                store::remove_receiver_transfer_dir(
                    &offer.manifest.circle_id,
                    &offer.manifest.transfer_id,
                )
                .await?;
                log_audit(
                    node_id,
                    AuditCategory::Xfer,
                    AuditSeverity::Warning,
                    AuditAction::Failed,
                    &format!(
                        "XFER receiver cancelled transfer_id={} sender={}",
                        offer.manifest.transfer_id, offer.manifest.sender_did
                    ),
                );
                return Err(XferError::Cancelled(offer.manifest.transfer_id.clone()));
            }
            KIND_DONE => {
                let done: XferDone = serde_json::from_str(line.trim())?;
                if done.transfer_id != offer.manifest.transfer_id {
                    return Err(XferError::InvalidStructure(format!(
                        "done transfer mismatch: expected {}, got {}",
                        offer.manifest.transfer_id, done.transfer_id
                    )));
                }
                break;
            }
            other => {
                return Err(XferError::InvalidStructure(format!(
                    "unexpected message kind '{}'",
                    other
                )))
            }
        }
    }

    drop(part_file.take());

    if already_completed && state.vault_id.is_some() {
        let ack = XferAck {
            kind: KIND_ACK.to_string(),
            transfer_id: offer.manifest.transfer_id.clone(),
            received: offer.manifest.chunk_count as usize,
            sha256_ok: true,
            error: None,
        };
        protocol::write_json_line(writer, &ack).await?;
        return Ok(());
    }

    let Some(state) =
        store::load_receiver_state(&offer.manifest.circle_id, &offer.manifest.transfer_id).await?
    else {
        return Err(XferError::TransferNotFound(
            offer.manifest.transfer_id.clone(),
        ));
    };
    if state.received_chunks.len() != offer.manifest.chunk_count as usize {
        let missing = offer.manifest.chunk_count as usize - state.received_chunks.len();
        let reason = format!("transfer incomplete: {} chunk(s) still missing", missing);
        let _ = store::mark_receiver_failed(&offer.manifest, &reason).await;
        let ack = XferAck {
            kind: KIND_ACK.to_string(),
            transfer_id: offer.manifest.transfer_id.clone(),
            received: state.received_chunks.len(),
            sha256_ok: false,
            error: Some(reason.clone()),
        };
        protocol::write_json_line(writer, &ack).await?;
        return Err(XferError::InvalidStructure(reason));
    }

    let candidate_path = if tokio::fs::try_exists(&final_path).await? {
        final_path.clone()
    } else {
        persistence::part_path(
            &offer.manifest.circle_id,
            &offer.manifest.transfer_id,
            &offer.manifest.filename,
        )
    };
    let actual_sha256 = compute_file_sha256(candidate_path.clone()).await?;
    if actual_sha256 != offer.manifest.file_sha256 {
        let reason = format!(
            "whole-file hash mismatch expected={} got={}",
            offer.manifest.file_sha256, actual_sha256
        );
        let _ = store::mark_receiver_failed(&offer.manifest, &reason).await;
        log_audit(
            node_id,
            AuditCategory::Xfer,
            AuditSeverity::Warning,
            AuditAction::Failed,
            &format!(
                "XFER hash mismatch transfer_id={} sender={} file={}: {}",
                offer.manifest.transfer_id, sender.did, offer.manifest.filename, reason
            ),
        );
        let ack = XferAck {
            kind: KIND_ACK.to_string(),
            transfer_id: offer.manifest.transfer_id.clone(),
            received: state.received_chunks.len(),
            sha256_ok: false,
            error: Some(reason.clone()),
        };
        protocol::write_json_line(writer, &ack).await?;
        return Err(XferError::HashMismatch {
            expected: offer.manifest.file_sha256.clone(),
            got: actual_sha256,
        });
    }

    let mime = crate::vault::ingest::infer_mime(&offer.manifest.filename);
    let record = match crate::vault::ingest::ingest_file(
        &offer.manifest.circle_id,
        &offer.manifest.sender_did,
        &candidate_path,
        crate::vault::ingest::IngestMeta {
            filename: offer.manifest.filename.clone(),
            mime,
            sha256_plain: offer.manifest.file_sha256.clone(),
            size_plain: offer.manifest.size,
            chunk_bytes: offer.manifest.chunk_bytes,
        },
    )
    .await
    {
        Ok(record) => record,
        Err(error) => {
            let reason = format!("vault ingest failed: {}", error);
            let _ = store::mark_receiver_failed(&offer.manifest, &reason).await;
            log_audit(
                node_id,
                AuditCategory::Vault,
                AuditSeverity::Warning,
                AuditAction::Failed,
                &format!(
                    "vault ingest failed transfer_id={} sender={} file={}: {}",
                    offer.manifest.transfer_id, sender.did, offer.manifest.filename, reason
                ),
            );
            let ack = XferAck {
                kind: KIND_ACK.to_string(),
                transfer_id: offer.manifest.transfer_id.clone(),
                received: state.received_chunks.len(),
                sha256_ok: false,
                error: Some(reason.clone()),
            };
            protocol::write_json_line(writer, &ack).await?;
            return Err(XferError::Conflict(reason));
        }
    };
    store::mark_receiver_complete_with_vault(&offer.manifest, &record.vault_id).await?;

    let ack = XferAck {
        kind: KIND_ACK.to_string(),
        transfer_id: offer.manifest.transfer_id.clone(),
        received: offer.manifest.chunk_count as usize,
        sha256_ok: true,
        error: None,
    };
    protocol::write_json_line(writer, &ack).await?;

    TRANSFERS_RECEIVED.fetch_add(1, Ordering::Relaxed);
    record_last_transfer(LastTransfer {
        direction: "received".into(),
        transfer_id: offer.manifest.transfer_id.clone(),
        peer_did: sender.did.clone(),
        filename: offer.manifest.filename.clone(),
        bytes: offer.manifest.size,
        chunks: offer.manifest.chunk_count,
        status: "completed".into(),
        at: chrono::Utc::now().to_rfc3339(),
    });
    log_audit(
        node_id,
        AuditCategory::Xfer,
        AuditSeverity::Info,
        AuditAction::Succeeded,
        &format!(
            "XFER received transfer_id={} sender={} file={} bytes={}",
            offer.manifest.transfer_id, sender.did, offer.manifest.filename, offer.manifest.size
        ),
    );
    println!(
        "📦 XFER received transfer_id={} sender={} file={}",
        offer.manifest.transfer_id, sender.did, offer.manifest.filename
    );
    Ok(())
}

async fn send_cancel<W>(writer: &mut W, manifest: &FileManifest)
where
    W: AsyncWrite + Unpin,
{
    let cancel = XferCancel {
        kind: KIND_CANCEL.to_string(),
        transfer_id: manifest.transfer_id.clone(),
        circle_id: manifest.circle_id.clone(),
        sender_did: manifest.sender_did.clone(),
    };
    let _ = protocol::write_json_line(writer, &cancel).await;
}

async fn handle_chunk(
    node_id: &str,
    manifest: &FileManifest,
    file: &mut tokio::fs::File,
    chunk: XferChunk,
) -> Result<(), XferError> {
    if chunk.transfer_id != manifest.transfer_id {
        return Err(XferError::InvalidStructure(format!(
            "chunk transfer mismatch: expected {}, got {}",
            manifest.transfer_id, chunk.transfer_id
        )));
    }
    let expected_len = manifest.chunk_len(chunk.index)?;
    let payload = general_purpose::STANDARD.decode(&chunk.data_b64)?;
    if payload.len() != expected_len {
        return Err(XferError::InvalidStructure(format!(
            "chunk {} length mismatch: expected {}, got {}",
            chunk.index,
            expected_len,
            payload.len()
        )));
    }
    let actual_sha256 = hex::encode(Sha256::digest(&payload));
    let expected_sha256 = manifest
        .chunk_digests
        .get(chunk.index as usize)
        .ok_or_else(|| {
            XferError::InvalidStructure(format!("missing digest for chunk {}", chunk.index))
        })?;
    if chunk.sha256 != *expected_sha256 || actual_sha256 != *expected_sha256 {
        let reason = format!(
            "chunk {} hash mismatch expected={} wire={} actual={}",
            chunk.index, expected_sha256, chunk.sha256, actual_sha256
        );
        let _ = store::mark_receiver_failed(manifest, &reason).await;
        log_audit(
            node_id,
            AuditCategory::Xfer,
            AuditSeverity::Warning,
            AuditAction::Failed,
            &format!(
                "XFER rejected chunk transfer_id={} index={}: {}",
                manifest.transfer_id, chunk.index, reason
            ),
        );
        return Err(XferError::HashMismatch {
            expected: expected_sha256.clone(),
            got: actual_sha256,
        });
    }

    let offset = chunk.index as u64 * manifest.chunk_bytes as u64;
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    if !payload.is_empty() {
        file.write_all(&payload).await?;
    }
    file.sync_data().await?;
    store::record_chunk(manifest, chunk.index).await?;
    BYTES_TRANSFERRED.fetch_add(payload.len() as u64, Ordering::Relaxed);
    Ok(())
}

async fn read_chunk_from_file(
    file: &mut tokio::fs::File,
    manifest: &FileManifest,
    index: u32,
) -> Result<Vec<u8>, XferError> {
    let len = manifest.chunk_len(index)?;
    let offset = index as u64 * manifest.chunk_bytes as u64;
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    let mut buf = vec![0_u8; len];
    if len > 0 {
        file.read_exact(&mut buf).await?;
    }
    Ok(buf)
}

async fn open_part_file(manifest: &FileManifest) -> Result<tokio::fs::File, XferError> {
    let path = persistence::part_path(
        &manifest.circle_id,
        &manifest.transfer_id,
        &manifest.filename,
    );
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .await?;
    file.set_len(manifest.size).await?;
    Ok(file)
}

async fn compute_file_sha256(path: PathBuf) -> Result<String, XferError> {
    tokio::task::spawn_blocking(move || {
        let mut file = std::fs::File::open(&path)?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; 262_144];
        loop {
            let read = std::io::Read::read(&mut file, &mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok::<String, XferError>(hex::encode(hasher.finalize()))
    })
    .await
    .map_err(|error| XferError::InvalidStructure(format!("hash task: {}", error)))?
}

async fn reject<W>(
    writer: &mut W,
    local_identity: &str,
    circle_id: &str,
    transfer_id: &str,
    reason: &str,
) where
    W: AsyncWrite + Unpin,
{
    let response = XferAccept {
        kind: KIND_ACCEPT.to_string(),
        circle_id: circle_id.to_string(),
        sender_did: local_identity.to_string(),
        transfer_id: transfer_id.to_string(),
        accept: false,
        have_chunks: Vec::new(),
        error: Some(reason.to_string()),
    };
    let _ = protocol::write_json_line(writer, &response).await;
}

fn audit_reject(node_id: &str, sender_did: &str, transfer_id: &str, reason: &str) {
    log_audit(
        node_id,
        AuditCategory::Xfer,
        AuditSeverity::Warning,
        AuditAction::Rejected,
        &format!(
            "XFER rejected transfer_id={} sender={}: {}",
            transfer_id, sender_did, reason
        ),
    );
}

async fn validate_cancel(manifest: &FileManifest, cancel: &XferCancel) -> Result<(), XferError> {
    if cancel.transfer_id != manifest.transfer_id {
        return Err(XferError::InvalidStructure(format!(
            "cancel transfer mismatch: expected {}, got {}",
            manifest.transfer_id, cancel.transfer_id
        )));
    }
    if cancel.circle_id != manifest.circle_id {
        return Err(XferError::CircleMismatch {
            expected: manifest.circle_id.clone(),
            got: cancel.circle_id.clone(),
        });
    }
    if cancel.sender_did != manifest.sender_did {
        return Err(XferError::InvalidStructure(format!(
            "cancel sender mismatch: expected {}, got {}",
            manifest.sender_did, cancel.sender_did
        )));
    }

    let state = store::load_receiver_state(&manifest.circle_id, &manifest.transfer_id)
        .await?
        .ok_or_else(|| XferError::TransferNotFound(manifest.transfer_id.clone()))?;
    if state.transfer_id != cancel.transfer_id
        || state.circle_id != cancel.circle_id
        || state.sender_did != cancel.sender_did
    {
        return Err(XferError::Conflict(format!(
            "cancel message does not match active receiver state for {}",
            manifest.transfer_id
        )));
    }
    if state.status != TransferStatus::Receiving {
        return Err(XferError::Conflict(format!(
            "cancel for {} rejected because receiver state is {:?}",
            manifest.transfer_id, state.status
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::doc_sign;
    use crate::did::document::{DidDocument, DocBuildInput};
    use crate::did::persistence::DerivationProof;
    use crate::did::{Did, DidRecord};
    use crate::key_manager::KeyManager;
    use crate::xfer::manifest::inspect_file_blocking;
    use std::collections::HashMap;
    use tempfile::TempDir;

    struct EnvRestore {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvRestore {
        fn set(key: &'static str, value: &std::path::Path) -> Self {
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            if let Some(value) = &self.previous {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    struct TestIdentity {
        did: String,
        record: DidRecord,
        km: KeyManager,
        doc: DidDocument,
    }

    struct ReceiverEnv {
        _xfer_base: EnvRestore,
        _vault_base: EnvRestore,
        _did_path: EnvRestore,
        _peers_dir: EnvRestore,
        _key_dir: EnvRestore,
        _vault_profile: crate::vault::wrapper::TestRuntimeProfileGuard,
        _vault_backend: Option<crate::vault::wrapper::TestSe050WrapBackendGuard>,
    }

    #[derive(Default)]
    struct MockSe050State {
        available: bool,
        provision_count: usize,
        wrap_count: usize,
        unwrap_count: usize,
        wrap_delay_ms: u64,
        keys: HashMap<String, u8>,
    }

    struct MockSe050Backend {
        state: Arc<std::sync::Mutex<MockSe050State>>,
    }

    impl MockSe050Backend {
        fn available_with_wrap_delay(wrap_delay_ms: u64) -> Arc<Self> {
            Arc::new(Self {
                state: Arc::new(std::sync::Mutex::new(MockSe050State {
                    available: true,
                    wrap_delay_ms,
                    ..Default::default()
                })),
            })
        }

        fn key_mask(key_id: &str) -> u8 {
            sha2::Sha256::digest(key_id.as_bytes())[0]
        }
    }

    impl crate::vault::wrapper::Se050WrapBackend for MockSe050Backend {
        fn slot_exists(&self, key_id: &str) -> Result<bool, crate::vault::VaultError> {
            let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if !state.available {
                return Err(crate::vault::VaultError::Crypto(
                    "mock SE050 unavailable".to_string(),
                ));
            }
            Ok(state.keys.contains_key(key_id))
        }

        fn provision_key(&self, key_id: &str) -> Result<(), crate::vault::VaultError> {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if !state.available {
                return Err(crate::vault::VaultError::Crypto(
                    "mock SE050 unavailable".to_string(),
                ));
            }
            state.provision_count += 1;
            state
                .keys
                .entry(key_id.to_string())
                .or_insert_with(|| Self::key_mask(key_id));
            Ok(())
        }

        fn wrap(&self, key_id: &str, plain: &[u8]) -> Result<Vec<u8>, crate::vault::VaultError> {
            let (mask, delay_ms) = {
                let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
                if !state.available {
                    return Err(crate::vault::VaultError::Crypto(
                        "mock SE050 unavailable".to_string(),
                    ));
                }
                state.wrap_count += 1;
                let mask = *state.keys.get(key_id).ok_or_else(|| {
                    crate::vault::VaultError::Crypto(format!("mock key missing: {}", key_id))
                })?;
                (mask, state.wrap_delay_ms)
            };
            if delay_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            }
            Ok(plain.iter().map(|byte| byte ^ mask).collect())
        }

        fn unwrap(
            &self,
            key_id: &str,
            wrapped: &[u8],
        ) -> Result<Vec<u8>, crate::vault::VaultError> {
            let mask = {
                let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
                if !state.available {
                    return Err(crate::vault::VaultError::Crypto(
                        "mock SE050 unavailable".to_string(),
                    ));
                }
                state.unwrap_count += 1;
                *state.keys.get(key_id).ok_or_else(|| {
                    crate::vault::VaultError::Crypto(format!("mock key missing: {}", key_id))
                })?
            };
            Ok(wrapped.iter().map(|byte| byte ^ mask).collect())
        }
    }

    fn make_identity(temp: &TempDir, node_name: &str, seed: u8, overlay_ip: &str) -> TestIdentity {
        let key_path = temp.path().join(format!("{}.key", node_name));
        let km = KeyManager::load_or_generate(key_path.to_str().expect("key path")).expect("key");
        let did = Did::from_id_bytes(&[seed; 32]);
        let pubkey = km.pubkey_der().expect("pubkey");
        let overlay = format!("{}/32", overlay_ip);
        let mut doc = DidDocument::build(DocBuildInput {
            did: did.as_str(),
            node_name: Some(node_name),
            current_dkp_version: 1,
            current_dkp_pubkey_der: &pubkey,
            overlay_ip_cidr: Some(&overlay),
            attestation_bind: None,
            cert_bootstrap_bind: None,
            revoked: vec![],
            previous_version_id: 0,
            created_at: None,
            status: Some("active".into()),
        })
        .expect("build doc");
        let vm_ref = doc.verification_method.first().expect("vm").id.clone();
        doc_sign::sign_in_place(&mut doc, &km, &vm_ref).expect("sign doc");
        let record = DidRecord {
            did: did.to_string(),
            method: "guardian".into(),
            method_version: "1.0".into(),
            did_id_b58: did.msi().to_string(),
            did_id_hex: hex::encode(did.id_bytes()),
            created_at: chrono::Utc::now().to_rfc3339(),
            deactivated_at: None,
            derivation: DerivationProof {
                se050_uid: format!("{}-uid", node_name),
                se050_uid_source: "fallback".into(),
                dkp_v1_pubkey_sha256_b16: String::new(),
                dkp_v1_pubkey_path: String::new(),
                dkp_v1_pubkey_der_b64: None,
                dik_pubkey_sha256_b16: String::new(),
                dik_pubkey_der_b64: None,
            },
            current_dkp_version: 1,
            deriv_signature_b64: String::new(),
        };
        TestIdentity {
            did: record.did.clone(),
            record,
            km,
            doc,
        }
    }

    fn configure_receiver_env(
        temp: &TempDir,
        receiver: &TestIdentity,
        sender: &TestIdentity,
    ) -> ReceiverEnv {
        configure_receiver_env_with_vault(
            temp,
            receiver,
            sender,
            crate::vault::wrapper::RuntimeProfile::Docker,
            None,
        )
    }

    fn configure_receiver_env_with_vault(
        temp: &TempDir,
        receiver: &TestIdentity,
        sender: &TestIdentity,
        vault_profile: crate::vault::wrapper::RuntimeProfile,
        vault_backend: Option<Arc<dyn crate::vault::wrapper::Se050WrapBackend>>,
    ) -> ReceiverEnv {
        let xfer_base = temp.path().join("xfer");
        let vault_base = temp.path().join("vault");
        let did_path = temp.path().join("identity").join("did.json");
        let peers_dir = temp.path().join("peer_docs");
        let key_dir = temp.path().join("runtime_keys");
        std::fs::create_dir_all(&peers_dir).expect("peers dir");
        std::fs::create_dir_all(&key_dir).expect("key dir");
        receiver
            .record
            .save(did_path.to_str().expect("did path"))
            .expect("save did record");
        let xfer_base_guard = EnvRestore::set(crate::xfer::persistence::XFER_BASE_ENV, &xfer_base);
        let vault_base_guard = EnvRestore::set(crate::vault::VAULT_BASE_ENV, &vault_base);
        let did_path_guard = EnvRestore::set("SGX_GUARDIAN_DID_PATH", &did_path);
        let peers_dir_guard =
            EnvRestore::set(crate::did::doc_persistence::PEERS_DOC_DIR_ENV, &peers_dir);
        let key_dir_guard = EnvRestore::set(crate::vc::issue::DEVICE_KEY_DIR_ENV, &key_dir);
        let vault_profile_guard = crate::vault::wrapper::test_force_runtime_profile(vault_profile);
        let vault_backend_guard =
            vault_backend.map(crate::vault::wrapper::test_override_se050_wrap_backend);
        crate::did::doc_persistence::save_peer(&sender.doc).expect("save sender peer doc");
        crate::vc::issue::load_runtime_key_manager("nodeB").expect("warm receiver key manager");
        ReceiverEnv {
            _xfer_base: xfer_base_guard,
            _vault_base: vault_base_guard,
            _did_path: did_path_guard,
            _peers_dir: peers_dir_guard,
            _key_dir: key_dir_guard,
            _vault_profile: vault_profile_guard,
            _vault_backend: vault_backend_guard,
        }
    }

    fn spawn_receiver(
        stream: tokio::io::DuplexStream,
    ) -> tokio::task::JoinHandle<Result<(), XferError>> {
        let resolver = Resolver::new(Default::default());
        tokio::spawn(async move {
            let (read_half, write_half) = tokio::io::split(stream);
            let mut reader = BufReader::new(read_half);
            let mut writer = write_half;
            handle_inbound_stream(
                &mut reader,
                &mut writer,
                "nodeB",
                &resolver,
                &XferConfig {
                    enabled: true,
                    port: 0,
                    chunk_bytes: 1024,
                    max_file_bytes: 1_048_576,
                },
            )
            .await
        })
    }

    async fn build_prepared_transfer(
        temp: &TempDir,
        sender: &TestIdentity,
        receiver: &TestIdentity,
        filename: &str,
        bytes: &[u8],
        chunk_bytes: u32,
    ) -> PreparedTransfer {
        let file_path = temp.path().join(filename);
        tokio::fs::write(&file_path, bytes)
            .await
            .expect("write payload");
        let material = inspect_file_blocking(
            file_path.clone(),
            chunk_bytes,
            (bytes.len() as u64).saturating_add(1),
        )
        .expect("inspect file");
        let manifest = FileManifest::build_signed(
            crate::crl::issue::DEFAULT_CIRCLE_ID,
            &sender.did,
            material,
            chunk_bytes,
            &sender.km,
            &format!("{}#dkp-v1", sender.did),
        )
        .expect("build manifest");
        store::create_outbox(&receiver.did, &file_path.display().to_string(), &manifest)
            .await
            .expect("create outbox");
        PreparedTransfer {
            node_id: "nodeA".into(),
            peer: GossipPeer {
                did: receiver.did.clone(),
                node_name: "nodeB".into(),
                overlay_ip: "127.0.0.1".into(),
            },
            manifest,
            file_path,
            staged_plaintext: None,
        }
    }

    fn test_payload(len: usize) -> Vec<u8> {
        (0..len).map(|index| (index % 251) as u8).collect()
    }

    async fn create_sender_vault_record(
        temp: &TempDir,
        sender: &TestIdentity,
        filename: &str,
        payload: &[u8],
    ) -> crate::vault::VaultRecord {
        let path = temp.path().join(format!("vault-source-{}", filename));
        tokio::fs::write(&path, payload)
            .await
            .expect("write vault source");
        crate::vault::ingest::ingest_upload_file(
            crate::vault::VaultNamespace::Personal,
            &sender.did,
            &path,
            crate::vault::ingest::IngestMeta {
                filename: filename.to_string(),
                mime: crate::vault::ingest::infer_mime(filename),
                sha256_plain: hex::encode(sha2::Sha256::digest(payload)),
                size_plain: payload.len() as u64,
                chunk_bytes: crate::vault::VaultConfig::DEFAULT_CHUNK_BYTES,
            },
            String::new(),
        )
        .await
        .expect("store sender vault record")
    }

    #[tokio::test]
    async fn xfer_normal_transfer_completes() {
        let _env_lock = crate::xfer::lock_test_env().await;
        let temp = TempDir::new().expect("tempdir");
        let sender = make_identity(&temp, "nodeA", 0x11, "127.0.0.1");
        let receiver = make_identity(&temp, "nodeB", 0x22, "127.0.0.1");
        let _env = configure_receiver_env(&temp, &receiver, &sender);
        let payload = test_payload(8 * 1024);
        let prepared =
            build_prepared_transfer(&temp, &sender, &receiver, "normal.bin", &payload, 1024).await;
        let manifest = prepared.manifest.clone();
        let (sender_stream, receiver_stream) = tokio::io::duplex(1 << 20);
        let receiver_task = spawn_receiver(receiver_stream);
        let (sender_read, sender_write) = tokio::io::split(sender_stream);
        let mut sender_reader = BufReader::new(sender_read);
        let mut sender_writer = sender_write;

        run_outbound_stream(
            prepared,
            &mut sender_reader,
            &mut sender_writer,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .expect("normal transfer should complete");
        receiver_task
            .await
            .expect("receiver join")
            .expect("receiver result");

        let final_path = persistence::final_path(
            &manifest.circle_id,
            &manifest.transfer_id,
            &manifest.filename,
        );
        assert!(!tokio::fs::try_exists(&final_path)
            .await
            .expect("check final path"));

        let state = store::load_receiver_state(&manifest.circle_id, &manifest.transfer_id)
            .await
            .expect("load state")
            .expect("receiver state");
        assert_eq!(state.status, TransferStatus::Completed);
        assert_eq!(state.received_chunks.len(), manifest.chunk_count as usize);
        let vault_id = state.vault_id.clone().expect("vault id");
        let record = crate::vault::persistence::find_record(
            &crate::vault::VaultConfig::from_env(),
            &vault_id,
        )
        .await
        .expect("find vault record")
        .expect("vault record");
        let temp_out = crate::vault::ingest::decrypt_record_to_temp(&record)
            .await
            .expect("decrypt vault blob");
        let downloaded = tokio::fs::read(temp_out).await.expect("read decrypted");
        assert_eq!(downloaded, payload);
        assert_eq!(
            hex::encode(sha2::Sha256::digest(&downloaded)),
            manifest.file_sha256
        );

        let outbox = store::load_outbox(&manifest.transfer_id)
            .await
            .expect("load outbox")
            .expect("outbox");
        assert_eq!(outbox.status, TransferStatus::Completed);
    }

    #[tokio::test]
    async fn xfer_hardware_transfer_waits_for_se050_ingest_ack_and_preserves_download_hash() {
        let _env_lock = crate::xfer::lock_test_env().await;
        let temp = TempDir::new().expect("tempdir");
        let sender = make_identity(&temp, "nodeA", 0x13, "127.0.0.1");
        let receiver = make_identity(&temp, "nodeB", 0x24, "127.0.0.1");
        let backend =
            MockSe050Backend::available_with_wrap_delay(protocol::IO_TIMEOUT_SECS * 1_000 + 500);
        let _env = configure_receiver_env_with_vault(
            &temp,
            &receiver,
            &sender,
            crate::vault::wrapper::RuntimeProfile::Production,
            Some(backend),
        );
        let payload = test_payload(8 * 1024);
        let prepared = build_prepared_transfer(
            &temp,
            &sender,
            &receiver,
            "hardware-xfer.bin",
            &payload,
            1024,
        )
        .await;
        let manifest = prepared.manifest.clone();
        let (sender_stream, receiver_stream) = tokio::io::duplex(1 << 20);
        let receiver_task = spawn_receiver(receiver_stream);
        let (sender_read, sender_write) = tokio::io::split(sender_stream);
        let mut sender_reader = BufReader::new(sender_read);
        let mut sender_writer = sender_write;

        let started = std::time::Instant::now();
        run_outbound_stream(
            prepared,
            &mut sender_reader,
            &mut sender_writer,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .expect("hardware transfer should complete");
        assert!(
            started.elapsed()
                >= std::time::Duration::from_millis(protocol::IO_TIMEOUT_SECS * 1_000),
            "sender should wait beyond the default IO timeout for the final ACK"
        );
        receiver_task
            .await
            .expect("receiver join")
            .expect("receiver result");

        let state = store::load_receiver_state(&manifest.circle_id, &manifest.transfer_id)
            .await
            .expect("load state")
            .expect("receiver state");
        assert_eq!(state.status, TransferStatus::Completed);
        let vault_id = state.vault_id.clone().expect("vault id");
        let outbox = store::load_outbox(&manifest.transfer_id)
            .await
            .expect("load outbox")
            .expect("outbox");
        assert_eq!(outbox.status, TransferStatus::Completed);

        let config = crate::vault::VaultConfig::from_env();
        let record = crate::vault::persistence::find_record(&config, &vault_id)
            .await
            .expect("find vault record")
            .expect("vault record");
        let temp_out = crate::vault::ingest::decrypt_record_to_temp(&record)
            .await
            .expect("decrypt vault blob");
        let downloaded = tokio::fs::read(temp_out).await.expect("read decrypted");
        assert_eq!(
            hex::encode(sha2::Sha256::digest(&downloaded)),
            manifest.file_sha256
        );
        assert_eq!(record.sha256_plain, manifest.file_sha256);
    }

    #[tokio::test]
    async fn inbox_hides_dead_download_link_after_vault_deletion() {
        let _env_lock = crate::xfer::lock_test_env().await;
        let temp = TempDir::new().expect("tempdir");
        let sender = make_identity(&temp, "nodeA", 0x12, "127.0.0.1");
        let receiver = make_identity(&temp, "nodeB", 0x23, "127.0.0.1");
        let _env = configure_receiver_env(&temp, &receiver, &sender);
        let payload = test_payload(4 * 1024);
        let prepared =
            build_prepared_transfer(&temp, &sender, &receiver, "history.bin", &payload, 1024).await;
        let manifest = prepared.manifest.clone();
        let (sender_stream, receiver_stream) = tokio::io::duplex(1 << 20);
        let receiver_task = spawn_receiver(receiver_stream);
        let (sender_read, sender_write) = tokio::io::split(sender_stream);
        let mut sender_reader = BufReader::new(sender_read);
        let mut sender_writer = sender_write;

        run_outbound_stream(
            prepared,
            &mut sender_reader,
            &mut sender_writer,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .expect("transfer should complete");
        receiver_task
            .await
            .expect("receiver join")
            .expect("receiver result");

        let state = store::load_receiver_state(&manifest.circle_id, &manifest.transfer_id)
            .await
            .expect("load state")
            .expect("receiver state");
        let vault_id = state.vault_id.clone().expect("vault id");
        let config = crate::vault::VaultConfig::from_env();
        let record = crate::vault::persistence::find_record(&config, &vault_id)
            .await
            .expect("find vault record")
            .expect("vault record");
        crate::vault::persistence::delete_record(&config, &record)
            .await
            .expect("delete vault record");

        let inbox = store::list_inbox().await.expect("list inbox");
        let item = inbox
            .into_iter()
            .find(|item| item.transfer_id == manifest.transfer_id)
            .expect("inbox history item");

        assert!(item.completed);
        assert_eq!(item.vault_id.as_deref(), Some(vault_id.as_str()));
        assert_eq!(item.path, None);
        assert_eq!(item.download_path, None);
        assert!(!item.vault_available);
    }

    #[tokio::test]
    async fn xfer_resume_transfer_completes_with_existing_chunks() {
        let _env_lock = crate::xfer::lock_test_env().await;
        let temp = TempDir::new().expect("tempdir");
        let sender = make_identity(&temp, "nodeA", 0x33, "127.0.0.1");
        let receiver = make_identity(&temp, "nodeB", 0x44, "127.0.0.1");
        let _env = configure_receiver_env(&temp, &receiver, &sender);
        let payload = test_payload(6 * 1024);
        let prepared =
            build_prepared_transfer(&temp, &sender, &receiver, "resume.bin", &payload, 2048).await;
        let manifest = prepared.manifest.clone();

        store::prepare_receiver(&manifest)
            .await
            .expect("prepare receiver state");
        let mut source = tokio::fs::File::open(&prepared.file_path)
            .await
            .expect("open source");
        let first_chunk = read_chunk_from_file(&mut source, &manifest, 0)
            .await
            .expect("read first chunk");
        let mut part_file = open_part_file(&manifest).await.expect("open part");
        part_file
            .write_all(&first_chunk)
            .await
            .expect("write first chunk");
        part_file.sync_data().await.expect("sync part");
        drop(part_file);
        store::record_chunk(&manifest, 0)
            .await
            .expect("record first chunk");

        let (sender_stream, receiver_stream) = tokio::io::duplex(1 << 20);
        let receiver_task = spawn_receiver(receiver_stream);
        let (sender_read, sender_write) = tokio::io::split(sender_stream);
        let mut sender_reader = BufReader::new(sender_read);
        let mut sender_writer = sender_write;

        run_outbound_stream(
            prepared,
            &mut sender_reader,
            &mut sender_writer,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .expect("resume transfer should complete");
        receiver_task
            .await
            .expect("receiver join")
            .expect("receiver result");

        let final_path = persistence::final_path(
            &manifest.circle_id,
            &manifest.transfer_id,
            &manifest.filename,
        );
        assert!(!tokio::fs::try_exists(&final_path)
            .await
            .expect("check final path"));

        let outbox = store::load_outbox(&manifest.transfer_id)
            .await
            .expect("load outbox")
            .expect("outbox");
        assert_eq!(outbox.status, TransferStatus::Completed);
        assert_eq!(outbox.requested_chunks, manifest.chunk_count - 1);
        assert_eq!(outbox.sent_chunks, manifest.chunk_count - 1);

        let state = store::load_receiver_state(&manifest.circle_id, &manifest.transfer_id)
            .await
            .expect("load state")
            .expect("receiver state");
        assert!(state.vault_id.is_some());
    }

    #[tokio::test]
    async fn xfer_mid_transfer_cancel_removes_receiver_directory() {
        let _env_lock = crate::xfer::lock_test_env().await;
        let temp = TempDir::new().expect("tempdir");
        let sender = make_identity(&temp, "nodeA", 0x55, "127.0.0.1");
        let receiver = make_identity(&temp, "nodeB", 0x66, "127.0.0.1");
        let xfer_base = temp.path().join("xfer");
        let _xfer_env = EnvRestore::set(crate::xfer::persistence::XFER_BASE_ENV, &xfer_base);
        let payload = test_payload(256 * 1024);
        let manifest =
            build_prepared_transfer(&temp, &sender, &receiver, "cancel.bin", &payload, 1024)
                .await
                .manifest;
        store::prepare_receiver(&manifest)
            .await
            .expect("prepare receiver state");
        let part_file = open_part_file(&manifest).await.expect("open part file");
        drop(part_file);

        let cancel = XferCancel {
            kind: KIND_CANCEL.to_string(),
            transfer_id: manifest.transfer_id.clone(),
            circle_id: manifest.circle_id.clone(),
            sender_did: manifest.sender_did.clone(),
        };
        validate_cancel(&manifest, &cancel)
            .await
            .expect("cancel should validate");
        store::remove_receiver_transfer_dir(&manifest.circle_id, &manifest.transfer_id)
            .await
            .expect("remove receiver dir");

        let transfer_dir =
            persistence::inbox_transfer_dir(&manifest.circle_id, &manifest.transfer_id);
        assert!(
            !tokio::fs::try_exists(&transfer_dir)
                .await
                .expect("check transfer dir"),
            "receiver transfer directory should be removed"
        );
        let final_path = persistence::final_path(
            &manifest.circle_id,
            &manifest.transfer_id,
            &manifest.filename,
        );
        assert!(
            !tokio::fs::try_exists(&final_path)
                .await
                .expect("check final path"),
            "final file should not exist after cancel"
        );
        assert!(
            store::load_receiver_state(&manifest.circle_id, &manifest.transfer_id)
                .await
                .expect("load receiver state")
                .is_none()
        );
        assert!(
            store::load_manifest(&manifest.circle_id, &manifest.transfer_id)
                .await
                .expect("load manifest")
                .is_none()
        );
    }

    #[tokio::test]
    async fn xfer_vault_source_transfer_completes_and_preserves_sender_record() {
        let _env_lock = crate::xfer::lock_test_env().await;
        let temp = TempDir::new().expect("tempdir");
        let sender = make_identity(&temp, "nodeA", 0x77, "127.0.0.1");
        let receiver = make_identity(&temp, "nodeB", 0x88, "127.0.0.1");
        let _env = configure_receiver_env(&temp, &receiver, &sender);
        let payload = test_payload(12 * 1024);
        let sender_record =
            create_sender_vault_record(&temp, &sender, "vault-send.bin", &payload).await;
        let sender_record_before = sender_record.clone();
        let vault_config = crate::vault::VaultConfig::from_env();
        let sender_blob_path =
            crate::vault::persistence::record_blob_path(&vault_config, &sender_record);
        let sender_blob_before = tokio::fs::read(&sender_blob_path)
            .await
            .expect("read sender blob");

        let staged_plaintext = stage_vault_record(
            &sender_record.vault_id,
            crate::xfer::MAX_TRANSFER_FILE_BYTES,
        )
        .await
        .expect("stage sender vault record");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let dir_mode = tokio::fs::metadata(&staged_plaintext.dir_path)
                .await
                .expect("staging dir metadata")
                .permissions()
                .mode()
                & 0o777;
            let file_mode = tokio::fs::metadata(&staged_plaintext.file_path)
                .await
                .expect("staging file metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700);
            assert_eq!(file_mode, 0o600);
        }

        let material = inspect_file_blocking(
            staged_plaintext.file_path.clone(),
            1024,
            crate::xfer::MAX_TRANSFER_FILE_BYTES,
        )
        .expect("inspect staged plaintext");
        let manifest = FileManifest::build_signed(
            crate::crl::issue::DEFAULT_CIRCLE_ID,
            &sender.did,
            material,
            1024,
            &sender.km,
            &format!("{}#dkp-v1", sender.did),
        )
        .expect("build manifest");
        store::create_outbox(
            &receiver.did,
            &format!("vault:{}", sender_record.vault_id),
            &manifest,
        )
        .await
        .expect("create outbox");
        let prepared = PreparedTransfer {
            node_id: "nodeA".into(),
            peer: GossipPeer {
                did: receiver.did.clone(),
                node_name: "nodeB".into(),
                overlay_ip: "127.0.0.1".into(),
            },
            manifest: manifest.clone(),
            file_path: staged_plaintext.file_path.clone(),
            staged_plaintext: Some(staged_plaintext.clone()),
        };

        let (sender_stream, receiver_stream) = tokio::io::duplex(1 << 20);
        let receiver_task = spawn_receiver(receiver_stream);
        let (sender_read, sender_write) = tokio::io::split(sender_stream);
        let mut sender_reader = BufReader::new(sender_read);
        let mut sender_writer = sender_write;

        run_outbound_stream_with_cleanup(
            prepared,
            &mut sender_reader,
            &mut sender_writer,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .expect("vault source transfer should complete");
        receiver_task
            .await
            .expect("receiver join")
            .expect("receiver result");

        assert!(
            !tokio::fs::try_exists(&staged_plaintext.dir_path)
                .await
                .expect("check staging dir"),
            "sender staging directory should be removed"
        );

        let sender_record_after =
            crate::vault::persistence::find_record(&vault_config, &sender_record.vault_id)
                .await
                .expect("find sender record")
                .expect("sender record exists");
        assert_eq!(sender_record_after, sender_record_before);
        assert_eq!(
            tokio::fs::read(&sender_blob_path)
                .await
                .expect("read sender blob after"),
            sender_blob_before
        );

        let receiver_state = store::load_receiver_state(&manifest.circle_id, &manifest.transfer_id)
            .await
            .expect("load receiver state")
            .expect("receiver state");
        let receiver_vault_id = receiver_state.vault_id.expect("receiver vault id");
        assert_ne!(receiver_vault_id, sender_record.vault_id);

        let receiver_record =
            crate::vault::persistence::find_record(&vault_config, &receiver_vault_id)
                .await
                .expect("find receiver record")
                .expect("receiver vault record");
        let decrypted = crate::vault::ingest::decrypt_record_to_temp(&receiver_record)
            .await
            .expect("decrypt receiver record");
        assert_eq!(
            tokio::fs::read(&decrypted)
                .await
                .expect("read receiver payload"),
            payload
        );
    }

    #[tokio::test]
    async fn xfer_vault_source_cleanup_runs_when_receiver_rejects() {
        let _env_lock = crate::xfer::lock_test_env().await;
        let temp = TempDir::new().expect("tempdir");
        let sender = make_identity(&temp, "nodeA", 0x79, "127.0.0.1");
        let receiver = make_identity(&temp, "nodeB", 0x8A, "127.0.0.1");
        let _env = configure_receiver_env(&temp, &receiver, &sender);
        let payload = test_payload(4 * 1024);
        let sender_record =
            create_sender_vault_record(&temp, &sender, "vault-reject.bin", &payload).await;
        let staged_plaintext = stage_vault_record(
            &sender_record.vault_id,
            crate::xfer::MAX_TRANSFER_FILE_BYTES,
        )
        .await
        .expect("stage sender vault record");
        let material = inspect_file_blocking(
            staged_plaintext.file_path.clone(),
            1024,
            crate::xfer::MAX_TRANSFER_FILE_BYTES,
        )
        .expect("inspect staged plaintext");
        let manifest = FileManifest::build_signed(
            crate::crl::issue::DEFAULT_CIRCLE_ID,
            &sender.did,
            material,
            1024,
            &sender.km,
            &format!("{}#dkp-v1", sender.did),
        )
        .expect("build manifest");
        store::create_outbox(
            &receiver.did,
            &format!("vault:{}", sender_record.vault_id),
            &manifest,
        )
        .await
        .expect("create outbox");
        let prepared = PreparedTransfer {
            node_id: "nodeA".into(),
            peer: GossipPeer {
                did: receiver.did.clone(),
                node_name: "nodeB".into(),
                overlay_ip: "127.0.0.1".into(),
            },
            manifest: manifest.clone(),
            file_path: staged_plaintext.file_path.clone(),
            staged_plaintext: Some(staged_plaintext.clone()),
        };

        let (sender_stream, peer_stream) = tokio::io::duplex(1 << 20);
        let peer_did = receiver.did.clone();
        let reject_task = tokio::spawn(async move {
            let (read_half, mut write_half) = tokio::io::split(peer_stream);
            let mut reader = BufReader::new(read_half);
            let line = protocol::read_json_line(&mut reader)
                .await
                .expect("read offer");
            let offer: XferOffer = serde_json::from_str(line.trim()).expect("decode offer");
            let reject = XferAccept {
                kind: KIND_ACCEPT.to_string(),
                circle_id: offer.circle_id,
                sender_did: peer_did,
                transfer_id: offer.manifest.transfer_id,
                accept: false,
                have_chunks: Vec::new(),
                error: Some("vault quota exceeded".to_string()),
            };
            protocol::write_json_line(&mut write_half, &reject)
                .await
                .expect("write reject");
        });
        let (sender_read, sender_write) = tokio::io::split(sender_stream);
        let mut sender_reader = BufReader::new(sender_read);
        let mut sender_writer = sender_write;

        let error = run_outbound_stream_with_cleanup(
            prepared,
            &mut sender_reader,
            &mut sender_writer,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .expect_err("transfer should be rejected");
        assert!(error.to_string().contains("vault quota exceeded"));
        reject_task.await.expect("reject task join");

        assert!(
            !tokio::fs::try_exists(&staged_plaintext.dir_path)
                .await
                .expect("check staging dir"),
            "sender staging directory should be removed after rejection"
        );
    }

    #[tokio::test]
    async fn xfer_size_limit_accepts_exact_50_mib_and_rejects_oversize_sources() {
        let _env_lock = crate::xfer::lock_test_env().await;
        let temp = TempDir::new().expect("tempdir");
        let sender = make_identity(&temp, "nodeA", 0x7B, "127.0.0.1");
        let receiver = make_identity(&temp, "nodeB", 0x8C, "127.0.0.1");
        let _env = configure_receiver_env(&temp, &receiver, &sender);
        let limit = crate::xfer::MAX_TRANSFER_FILE_BYTES;

        let exact_path = temp.path().join("exact-50mib.bin");
        std::fs::File::create(&exact_path)
            .expect("create exact file")
            .set_len(limit)
            .expect("size exact file");
        let (_path, _display, material, staged) =
            prepare_outbound_material(SendSource::Path(exact_path), 524_288, limit)
                .await
                .expect("exact 50 MiB path source should be accepted");
        assert_eq!(material.size, limit);
        assert!(staged.is_none());

        let oversize_path = temp.path().join("oversize-path.bin");
        std::fs::File::create(&oversize_path)
            .expect("create oversize file")
            .set_len(limit + 1)
            .expect("size oversize file");
        let error = prepare_outbound_material(SendSource::Path(oversize_path), 524_288, limit)
            .await
            .expect_err("oversize path source must be rejected");
        assert!(matches!(
            error,
            XferError::FileTooLarge {
                size,
                max
            } if size == limit + 1 && max == limit
        ));

        let oversize_record = crate::vault::VaultRecord {
            vault_id: format!("urn:uuid:{}", Uuid::new_v4()),
            namespace: crate::vault::VaultNamespace::PERSONAL_STORAGE_KEY.to_string(),
            circle_id: String::new(),
            filename: "oversize-vault.bin".into(),
            mime: "application/octet-stream".into(),
            size_plain: limit + 1,
            size_cipher: 1,
            sha256_plain: "aa".repeat(32),
            sender_did: sender.did.clone(),
            received_at: chrono::Utc::now().to_rfc3339(),
            source: crate::vault::VaultSource::Upload,
            folder_id: String::new(),
            starred: false,
            enc: crate::vault::EncMeta {
                algo: "AES-256-GCM/STREAM-BE32".into(),
                chunk_bytes: crate::vault::VaultConfig::DEFAULT_CHUNK_BYTES,
                base_nonce_b64: "bm9uY2VwcmU=".into(),
                wrapped_dek_b64: "d3JhcHBlZA==".into(),
                wrap_scheme: "software-hkdf".into(),
                wrap_key_id: "software-master-v1".into(),
            },
        };
        crate::vault::persistence::save_record(
            &crate::vault::VaultConfig::from_env(),
            &oversize_record,
        )
        .await
        .expect("save oversize vault record");
        let error = stage_vault_record(&oversize_record.vault_id, limit)
            .await
            .expect_err("oversize vault source must be rejected");
        assert!(matches!(
            error,
            XferError::FileTooLarge {
                size,
                max
            } if size == limit + 1 && max == limit
        ));
        assert!(
            !tokio::fs::try_exists(&crate::xfer::persistence::staging_dir())
                .await
                .expect("check staging base"),
            "oversize vault records should be rejected before staging"
        );
    }
}
