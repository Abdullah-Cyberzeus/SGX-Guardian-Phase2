use crate::did::Did;
use crate::vc::credential::VerifiableCredential;
use crate::vc::errors::VcError;
use crate::vc::status_list::StatusListCredential;
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const VC_BASE: &str = "/var/lib/sgx-guardian/identity/vc";
pub const VC_BASE_ENV: &str = "SGX_GUARDIAN_VC_BASE";

pub fn base_dir() -> PathBuf {
    env::var(VC_BASE_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(VC_BASE))
}

pub fn issued_dir() -> PathBuf {
    base_dir().join("issued")
}

pub fn own_dir() -> PathBuf {
    base_dir().join("own")
}

pub fn peers_dir() -> PathBuf {
    base_dir().join("peers")
}

pub fn status_list_path() -> PathBuf {
    base_dir().join("status_list.json")
}

pub fn status_list_index_path() -> PathBuf {
    base_dir().join("status_list_index.json")
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), VcError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut file = File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    sync_parent_dir(path)?;
    Ok(())
}

fn safe_id(id: &str) -> String {
    id.replace([':', '/'], "_")
}

pub fn issued_path_for_id(id: &str) -> PathBuf {
    issued_dir().join(format!("{}.json", safe_id(id)))
}

pub fn own_path_for_id(id: &str) -> PathBuf {
    own_dir().join(format!("{}.json", safe_id(id)))
}

pub fn peer_path_for_subject(peer_did: &str) -> PathBuf {
    let msi = Did::parse(peer_did)
        .map(|did| did.msi().to_string())
        .unwrap_or_else(|_| safe_id(peer_did));
    peers_dir().join(format!("did_vc_{}.json", msi))
}

pub fn save_issued(vc: &VerifiableCredential) -> Result<(), VcError> {
    let path = issued_path_for_id(&vc.id);
    write_atomic(&path, &serde_json::to_vec_pretty(vc)?)
}

pub fn save_own(vc: &VerifiableCredential) -> Result<(), VcError> {
    let path = own_path_for_id(&vc.id);
    write_atomic(&path, &serde_json::to_vec_pretty(vc)?)
}

pub fn save_peer(peer_did: &str, vc: &VerifiableCredential) -> Result<(), VcError> {
    let path = peer_path_for_subject(peer_did);
    write_atomic(&path, &serde_json::to_vec_pretty(vc)?)
}

pub fn save_status_list_credential(cred: &StatusListCredential) -> Result<(), VcError> {
    let path = status_list_path();
    write_atomic(&path, &serde_json::to_vec_pretty(cred)?)
}

pub fn save_status_list_raw(body: &str) -> Result<(), VcError> {
    let path = status_list_path();
    write_atomic(&path, body.as_bytes())
}

pub fn load_issued(id: &str) -> Result<VerifiableCredential, VcError> {
    let path = issued_path_for_id(id);
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

pub fn load_own(id: &str) -> Result<VerifiableCredential, VcError> {
    let path = own_path_for_id(id);
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

pub fn load_peer(peer_did: &str) -> Result<VerifiableCredential, VcError> {
    let path = peer_path_for_subject(peer_did);
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

pub fn load_status_list_credential() -> Result<StatusListCredential, VcError> {
    Ok(serde_json::from_slice(&fs::read(status_list_path())?)?)
}

pub fn load_status_list_raw() -> Result<String, VcError> {
    Ok(fs::read_to_string(status_list_path())?)
}

pub fn load_status_list_index_raw() -> Result<String, VcError> {
    Ok(fs::read_to_string(status_list_index_path())?)
}

pub fn load_own_any() -> Result<Option<VerifiableCredential>, VcError> {
    let dir = own_dir();
    if !dir.exists() {
        return Ok(None);
    }
    let mut preferred: Option<(bool, std::time::SystemTime, VerifiableCredential)> = None;
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let modified = entry.metadata()?.modified()?;
        let Ok(bytes) = fs::read(entry.path()) else {
            continue;
        };
        let Ok(vc) = serde_json::from_slice::<VerifiableCredential>(&bytes) else {
            continue;
        };
        let is_mesh_circle = vc.credential_subject.circle_id == crate::vc::issue::DEFAULT_CIRCLE_ID;
        let should_replace = preferred
            .as_ref()
            .map(|(best_is_mesh, ts, _)| {
                (is_mesh_circle && !best_is_mesh) || (is_mesh_circle == *best_is_mesh && modified > *ts)
            })
            .unwrap_or(true);
        if should_replace {
            preferred = Some((is_mesh_circle, modified, vc));
        }
    }
    Ok(preferred.map(|(_, _, vc)| vc))
}

pub fn list_issued() -> Result<Vec<VerifiableCredential>, VcError> {
    list_from_dir(&issued_dir())
}

pub fn list_own() -> Result<Vec<VerifiableCredential>, VcError> {
    list_from_dir(&own_dir())
}

pub fn list_peers() -> Result<Vec<VerifiableCredential>, VcError> {
    list_from_dir(&peers_dir())
}

pub fn find_issued_for_subject(
    subject_did: &str,
    circle_id: &str,
) -> Result<Option<VerifiableCredential>, VcError> {
    let mut matches = list_issued_for_subject(subject_did)?
        .into_iter()
        .filter(|vc| vc.credential_subject.circle_id == circle_id)
        .collect::<Vec<_>>();
    matches.sort_by(|a, b| a.issuance_date.cmp(&b.issuance_date));
    Ok(matches.pop())
}

pub fn list_issued_for_subject(subject_did: &str) -> Result<Vec<VerifiableCredential>, VcError> {
    let mut out = list_issued()?
        .into_iter()
        .filter(|vc| vc.subject_did() == subject_did)
        .collect::<Vec<_>>();
    out.sort_by(|a, b| a.issuance_date.cmp(&b.issuance_date));
    Ok(out)
}

pub fn find_issued_for_subject_and_role(
    subject_did: &str,
    circle_id: &str,
    role: &crate::vc::credential::CredentialRole,
) -> Result<Option<VerifiableCredential>, VcError> {
    let mut matches = list_issued()?
        .into_iter()
        .filter(|vc| {
            vc.subject_did() == subject_did
                && vc.credential_subject.circle_id == circle_id
                && &vc.credential_subject.role == role
        })
        .collect::<Vec<_>>();
    matches.sort_by(|a, b| a.issuance_date.cmp(&b.issuance_date));
    Ok(matches.pop())
}

pub fn find_vc_by_id(id: &str) -> Result<Option<VerifiableCredential>, VcError> {
    for vc in list_issued()?
        .into_iter()
        .chain(list_own()?)
        .chain(list_peers()?)
    {
        if vc.id == id {
            return Ok(Some(vc));
        }
    }
    Ok(None)
}

fn list_from_dir(dir: &Path) -> Result<Vec<VerifiableCredential>, VcError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.path().is_file() {
            continue;
        }
        let Ok(bytes) = fs::read(entry.path()) else {
            continue;
        };
        let Ok(vc) = serde_json::from_slice::<VerifiableCredential>(&bytes) else {
            continue;
        };
        out.push(vc);
    }
    out.sort_by(|a, b| a.issuance_date.cmp(&b.issuance_date));
    Ok(out)
}

fn sync_parent_dir(path: &Path) -> Result<(), VcError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}
