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

pub fn received_invites_dir() -> PathBuf {
    base_dir().join("received_invites")
}

pub fn snapshots_dir() -> PathBuf {
    base_dir().join("member_snapshots")
}

pub fn invite_path(invite_id: &str) -> PathBuf {
    invites_dir().join(format!("{}.json", safe_id(invite_id)))
}

pub fn snapshot_path(circle_id: &str) -> PathBuf {
    snapshots_dir().join(format!("{}.json", safe_id(circle_id)))
}

pub fn received_invite_path(invite_id: &str) -> PathBuf {
    received_invites_dir().join(format!("{}.json", safe_id(invite_id)))
}

pub fn redeemed_path() -> PathBuf {
    invites_dir().join("redeemed.json")
}

pub fn hidden_invites_path() -> PathBuf {
    invites_dir().join("hidden_history.json")
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

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn safe_id_replaces_path_separators_and_colons() {
        assert_eq!(safe_id("did:guardian:abc"), "did_guardian_abc");
        assert_eq!(safe_id("a/b\\c"), "a_b_c");
        assert_eq!(safe_id("plain-id"), "plain-id");
    }

    #[test]
    fn invite_path_sanitizes_invite_id() {
        let path = invite_path("did:guardian:abc/1");
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some("did_guardian_abc_1.json")
        );
    }
}
