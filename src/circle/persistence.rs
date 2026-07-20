use crate::circle::errors::CircleError;
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const CIRCLE_BASE: &str = "/var/lib/sgx-guardian/identity/circles";
pub const CIRCLE_BASE_ENV: &str = "SGX_GUARDIAN_CIRCLE_BASE";

pub fn base_dir() -> PathBuf {
    env::var(CIRCLE_BASE_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(CIRCLE_BASE))
}

pub fn registry_path() -> PathBuf {
    base_dir().join("circles.json")
}

pub fn invites_dir() -> PathBuf {
    base_dir().join("invites")
}

pub fn invite_path(invite_id: &str) -> PathBuf {
    invites_dir().join(format!("{}.json", safe_id(invite_id)))
}

pub fn redeemed_path() -> PathBuf {
    invites_dir().join("redeemed.json")
}

pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), CircleError> {
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
    id.replace([':', '/', '\\'], "_")
}

fn sync_parent_dir(path: &Path) -> Result<(), CircleError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}
