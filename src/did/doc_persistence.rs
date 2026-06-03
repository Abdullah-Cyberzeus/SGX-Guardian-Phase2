use crate::did::document::DidDocument;
use crate::did::errors::DidError;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

pub const SELF_DOC_PATH: &str = "/var/lib/sgx-guardian/identity/did_doc.json";
pub const PEERS_DOC_DIR: &str = "/var/lib/sgx-guardian/identity/peers";
pub const CA_AGGREGATE_PATH: &str = "/var/lib/sgx-guardian/identity/circle_did_docs.json";
pub const SELF_DOC_PATH_ENV: &str = "SGX_GUARDIAN_DID_DOC_PATH";
pub const PEERS_DOC_DIR_ENV: &str = "SGX_GUARDIAN_DID_PEERS_DIR";
pub const CA_AGGREGATE_PATH_ENV: &str = "SGX_GUARDIAN_DID_CA_AGGREGATE_PATH";

pub fn configured_self_doc_path() -> PathBuf {
    env::var(SELF_DOC_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(SELF_DOC_PATH))
}

pub fn configured_peers_doc_dir() -> PathBuf {
    env::var(PEERS_DOC_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(PEERS_DOC_DIR))
}

pub fn configured_ca_aggregate_path() -> PathBuf {
    env::var(CA_AGGREGATE_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(CA_AGGREGATE_PATH))
}

pub fn load_doc_at_path(path: &Path) -> Result<DidDocument, DidError> {
    let s = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&s)?)
}

fn atomic_write(path: &str, content: &[u8]) -> Result<(), DidError> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = format!("{}.tmp", path);
    fs::write(&tmp, content)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn save_self(doc: &DidDocument) -> Result<(), DidError> {
    let json = serde_json::to_vec_pretty(doc)?;
    let path = configured_self_doc_path();
    atomic_write(&path.to_string_lossy(), &json)
}

pub fn load_self() -> Result<Option<DidDocument>, DidError> {
    let path = configured_self_doc_path();
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(load_doc_at_path(&path)?))
}

pub fn save_peer(doc: &DidDocument) -> Result<(), DidError> {
    let did = doc.did()?;
    let path = configured_peers_doc_dir().join(format!("did_doc_{}.json", did.msi()));
    let json = serde_json::to_vec_pretty(doc)?;
    atomic_write(&path.to_string_lossy(), &json)
}

pub fn load_peer(did: &crate::did::Did) -> Result<Option<DidDocument>, DidError> {
    let path = configured_peers_doc_dir().join(format!("did_doc_{}.json", did.msi()));
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(load_doc_at_path(&path)?))
}

pub fn list_peer_docs() -> Result<Vec<DidDocument>, DidError> {
    let peers_dir = configured_peers_doc_dir();
    if !peers_dir.exists() {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(&peers_dir)? {
        let e = entry?;
        let p = e.path();
        if !p.is_file() {
            continue;
        }
        let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !(name.starts_with("did_doc_") && name.ends_with(".json")) {
            continue;
        }
        let Ok(doc) = load_doc_at_path(&p) else {
            continue;
        };
        out.push(doc);
    }
    Ok(out)
}

pub fn save_ca_aggregate(docs: &[DidDocument]) -> Result<(), DidError> {
    let json = serde_json::to_vec_pretty(docs)?;
    let path = configured_ca_aggregate_path();
    atomic_write(&path.to_string_lossy(), &json)
}

pub fn load_ca_aggregate() -> Result<Vec<DidDocument>, DidError> {
    let path = configured_ca_aggregate_path();
    if !path.exists() {
        return Ok(vec![]);
    }
    let s = fs::read_to_string(path)?;
    let docs: Vec<DidDocument> = serde_json::from_str(&s)?;
    Ok(docs)
}
