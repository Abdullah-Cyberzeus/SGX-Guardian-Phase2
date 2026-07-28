use crate::did::errors::DidError;
use crate::did::persistence::DEFAULT_PEERS_DIR;
use crate::did::Did;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerDidEntry {
    pub did: String,
    pub node_id: String,
    pub current_pubkey_der_b64: String,
    pub current_dkp_version: u32,
    pub last_seen: String,
    pub source: String,
}

fn entry_path(dir: &str, did: &Did) -> PathBuf {
    Path::new(dir).join(format!("did_{}.json", did.msi()))
}

pub fn upsert(dir: &str, entry: &PeerDidEntry) -> Result<(), DidError> {
    fs::create_dir_all(dir)?;
    let did = Did::parse(&entry.did)?;
    let path = entry_path(dir, &did);
    let json = serde_json::to_string_pretty(entry)?;
    let tmp = format!("{}.tmp", path.display());
    fs::write(&tmp, json)?;
    fs::rename(tmp, path)?;
    Ok(())
}

pub fn get(dir: &str, did: &Did) -> Result<Option<PeerDidEntry>, DidError> {
    let path = entry_path(dir, did);
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read_to_string(path)?;
    let entry = serde_json::from_str::<PeerDidEntry>(&data)?;
    Ok(Some(entry))
}

pub fn list(dir: &str) -> Result<Vec<PeerDidEntry>, DidError> {
    if !Path::new(dir).exists() {
        return Ok(vec![]);
    }

    let mut out = Vec::new();
    for item in fs::read_dir(dir)? {
        let item = item?;
        let path = item.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !(name.starts_with("did_") && name.ends_with(".json")) {
            continue;
        }

        let Ok(data) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(entry) = serde_json::from_str::<PeerDidEntry>(&data) else {
            continue;
        };
        out.push(entry);
    }

    Ok(out)
}

pub fn default_peers_dir() -> &'static str {
    DEFAULT_PEERS_DIR
}
