use crate::did::doc_persistence::{
    list_peer_docs, load_ca_aggregate, save_ca_aggregate, save_peer,
};
use crate::did::doc_sign::verify_with_replay_protection;
use crate::did::document::DidDocument;
use crate::did::errors::DidError;
use crate::nebula::registry_sync::{RegistryRequest, RegistryResponse, REGISTRY_SYNC_PORT};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const REQ_TIMEOUT_SECS: u64 = 10;

pub async fn publish_to_ca(
    ca_host: &str,
    node_name: &str,
    doc: &DidDocument,
) -> Result<(), DidError> {
    let json = serde_json::to_string(doc)?;
    let req = RegistryRequest {
        action: "publish_did_doc".into(),
        node_name: node_name.to_string(),
        pubkey_prefix: None,
        did_doc_json: Some(json),
        did_query: None,
    };
    let resp = send_request(ca_host, &req).await?;
    if !resp.success {
        return Err(DidError::InvalidFormat(format!(
            "CA rejected DID document: {}",
            resp.error.unwrap_or_default()
        )));
    }
    Ok(())
}

pub async fn pull_and_apply_aggregate(ca_host: &str) -> Result<Vec<String>, DidError> {
    let req = RegistryRequest {
        action: "snapshot_did_doc".into(),
        node_name: String::new(),
        pubkey_prefix: None,
        did_doc_json: None,
        did_query: None,
    };
    let resp = send_request(ca_host, &req).await?;
    if !resp.success {
        return Err(DidError::InvalidFormat(format!(
            "snapshot_did_doc failed: {}",
            resp.error.unwrap_or_default()
        )));
    }

    let raw = resp.did_doc_aggregate_json.unwrap_or_else(|| "[]".into());
    let docs: Vec<DidDocument> = serde_json::from_str(&raw)?;
    let mut updated_dids = Vec::new();
    for doc in docs {
        let floor = local_floor_version(&doc);
        match verify_with_replay_protection(&doc, floor) {
            Ok(()) => {
                if save_peer(&doc).is_ok() {
                    updated_dids.push(doc.id.clone());
                }
            }
            Err(e) => {
                tracing::warn!("Rejecting DID document {}: {}", doc.id, e);
            }
        }
    }
    Ok(updated_dids)
}

pub async fn ca_ingest_published(payload: &str) -> Result<(), DidError> {
    let doc: DidDocument = serde_json::from_str(payload)?;
    let floor = crate::did::doc_persistence::load_peer(&doc.did()?)?
        .map(|existing| existing.sgx_version_id)
        .unwrap_or(0);
    verify_with_replay_protection(&doc, floor)?;
    save_peer(&doc)?;
    let aggregate = list_peer_docs()?;
    save_ca_aggregate(&aggregate)?;
    Ok(())
}

pub async fn ca_export_aggregate() -> Result<String, DidError> {
    let docs = load_ca_aggregate()?;
    Ok(serde_json::to_string(&docs)?)
}

pub async fn send_request(
    ca_host: &str,
    req: &RegistryRequest,
) -> Result<RegistryResponse, DidError> {
    let addr = format!("{}:{}", ca_host, REGISTRY_SYNC_PORT);
    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(REQ_TIMEOUT_SECS),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| {
        DidError::Io(std::io::Error::other(format!(
            "timeout connecting {}",
            addr
        )))
    })?
    .map_err(|e| DidError::Io(std::io::Error::other(format!("connect {}: {}", addr, e))))?;

    let (reader, mut writer) = stream.into_split();
    let mut json = serde_json::to_string(req)?;
    json.push('\n');
    writer
        .write_all(json.as_bytes())
        .await
        .map_err(|e| DidError::Io(std::io::Error::other(format!("write: {}", e))))?;

    let mut br = BufReader::new(reader);
    let mut line = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(REQ_TIMEOUT_SECS),
        br.read_line(&mut line),
    )
    .await
    .map_err(|_| DidError::Io(std::io::Error::other("read timeout")))?
    .map_err(|e| DidError::Io(std::io::Error::other(format!("read: {}", e))))?;

    let resp: RegistryResponse = serde_json::from_str(line.trim())?;
    Ok(resp)
}

fn local_floor_version(doc: &DidDocument) -> u32 {
    if let Ok(Some(self_doc)) = crate::did::doc_persistence::load_self() {
        if self_doc.id == doc.id {
            return crate::did::doc_persistence::read_self_floor_version();
        }
    }
    match doc.did() {
        Ok(did) => crate::did::doc_persistence::load_peer(&did)
            .ok()
            .flatten()
            .map(|existing| existing.sgx_version_id)
            .unwrap_or(0),
        Err(_) => 0,
    }
}
