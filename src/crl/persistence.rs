use crate::crl::entry::CrlEntry;
use crate::crl::errors::CrlError;
use crate::crl::list::CertificateRevocationList;
use std::path::PathBuf;

pub const CRL_BASE: &str = "/var/lib/sgx-guardian/identity/crl";
#[cfg(test)]
pub const CRL_BASE_ENV: &str = "SGX_GUARDIAN_CRL_BASE";

pub fn crl_path() -> PathBuf {
    crl_base().join("crl.json")
}

pub fn entries_dir() -> PathBuf {
    crl_base().join("entries")
}

pub fn pending_dir() -> PathBuf {
    crl_base().join("pending")
}

fn write_atomic(path: &PathBuf, bytes: &[u8]) -> Result<(), CrlError> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn id_to_filename(id: &str) -> String {
    // urn:uuid:xxxx → urn_uuid_xxxx (filesystem-safe)
    id.replace(':', "_").replace('/', "_")
}

pub fn save_entry(e: &CrlEntry) -> Result<(), CrlError> {
    let path = entries_dir().join(format!("{}.json", id_to_filename(&e.id)));
    write_atomic(&path, &serde_json::to_vec_pretty(e)?)?;
    Ok(())
}

pub fn list_entries() -> Result<Vec<CrlEntry>, CrlError> {
    let dir = entries_dir();
    if !dir.exists() {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    for ent in std::fs::read_dir(&dir)? {
        let ent = ent?;
        if !ent.path().is_file() {
            continue;
        }
        if ent.path().extension().map(|e| e == "tmp").unwrap_or(false) {
            continue;
        }
        let bytes = std::fs::read(ent.path())?;
        let e: CrlEntry = serde_json::from_slice(&bytes)?;
        out.push(e);
    }
    Ok(out)
}

pub fn save_crl(crl: &CertificateRevocationList) -> Result<(), CrlError> {
    write_atomic(&crl_path(), &serde_json::to_vec_pretty(crl)?)?;
    Ok(())
}

pub fn load_crl() -> Result<Option<CertificateRevocationList>, CrlError> {
    let p = crl_path();
    if !p.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&p)?;
    let crl: CertificateRevocationList = serde_json::from_slice(&bytes)?;
    Ok(Some(crl))
}

fn crl_base() -> PathBuf {
    #[cfg(test)]
    {
        if let Ok(path) = std::env::var(CRL_BASE_ENV) {
            return path.into();
        }
    }
    CRL_BASE.into()
}
