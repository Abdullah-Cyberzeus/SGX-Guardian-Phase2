// src/policy_state.rs
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub const POLICY_DIR: &str = "policies";
pub const ACTIVE_POLICY: &str = "policies/active_policy.yaml";
pub const BACKUP_POLICY: &str = "policies/backup_policy.yaml";
pub const PENDING_POLICY: &str = "policies/pending_policy.yaml";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationOutcome {
    Unchanged,
    Activated { backup_rotated: bool },
}

/// Ensure policy directory exists
pub fn ensure_policy_dir() -> Result<()> {
    if !Path::new(POLICY_DIR).exists() {
        fs::create_dir_all(POLICY_DIR).context("Failed to create policy directory")?;
    }
    Ok(())
}

/// Atomically promote pending policy to active with rollback
pub fn activate_policy(
    pending_yaml: &str,
    incoming_policy_digest: &str,
) -> Result<ActivationOutcome> {
    ensure_policy_dir()?;

    let active_path = PathBuf::from(ACTIVE_POLICY);
    let backup_path = PathBuf::from(BACKUP_POLICY);
    let pending_path = PathBuf::from(PENDING_POLICY);

    activate_policy_with_paths(
        &active_path,
        &backup_path,
        &pending_path,
        pending_yaml,
        incoming_policy_digest,
    )
}

pub fn current_active_policy_digest() -> Result<Option<String>> {
    let active_path = Path::new(ACTIVE_POLICY);
    if !active_path.exists() {
        return Ok(None);
    }

    let active_bytes = fs::read(active_path).context("Failed to read active policy")?;
    Ok(Some(hex::encode(Sha256::digest(&active_bytes))))
}

fn activate_policy_with_paths(
    active_path: &Path,
    backup_path: &Path,
    pending_path: &Path,
    pending_yaml: &str,
    incoming_policy_digest: &str,
) -> Result<ActivationOutcome> {
    if let Some(current_digest) = current_policy_digest(active_path)? {
        if current_digest.eq_ignore_ascii_case(incoming_policy_digest) {
            return Ok(ActivationOutcome::Unchanged);
        }
    }

    // Write pending policy
    fs::write(pending_path, pending_yaml).context("Failed to write pending policy")?;

    // Backup active policy (if exists)
    let mut backup_rotated = false;
    if active_path.exists() {
        fs::copy(active_path, backup_path).context("Failed to backup active policy")?;
        backup_rotated = true;
    }

    // Promote pending → active (atomic replace)
    fs::rename(pending_path, active_path).context("Failed to activate new policy")?;

    Ok(ActivationOutcome::Activated { backup_rotated })
}

fn current_policy_digest(active_path: &Path) -> Result<Option<String>> {
    if !active_path.exists() {
        return Ok(None);
    }

    let active_bytes = fs::read(active_path).context("Failed to read active policy")?;
    Ok(Some(hex::encode(Sha256::digest(&active_bytes))))
}

/// Rollback active policy from backup
pub fn rollback_policy() -> Result<()> {
    if Path::new(BACKUP_POLICY).exists() {
        fs::copy(BACKUP_POLICY, ACTIVE_POLICY).context("Failed to rollback policy")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn same_digest_is_noop_and_preserves_backup() {
        let td = tempdir().expect("failed to create temp dir");
        let active_path = td.path().join("active_policy.yaml");
        let backup_path = td.path().join("backup_policy.yaml");
        let pending_path = td.path().join("pending_policy.yaml");

        let active_yaml = "policy_id: same\nversion: \"1\"\nrules: []\n";
        let original_backup_yaml = "policy_id: previous\nversion: \"1\"\nrules: []\n";

        fs::write(&active_path, active_yaml).expect("failed to write active");
        fs::write(&backup_path, original_backup_yaml).expect("failed to write backup");

        let digest = hex::encode(Sha256::digest(active_yaml.as_bytes()));
        let outcome = activate_policy_with_paths(
            &active_path,
            &backup_path,
            &pending_path,
            active_yaml,
            &digest,
        )
        .expect("activation should succeed");

        assert_eq!(outcome, ActivationOutcome::Unchanged);
        assert_eq!(
            fs::read_to_string(&backup_path).expect("failed to read backup"),
            original_backup_yaml
        );
        assert!(
            !pending_path.exists(),
            "pending policy should not be written"
        );
    }

    #[test]
    fn new_digest_rotates_backup_and_promotes_active() {
        let td = tempdir().expect("failed to create temp dir");
        let active_path = td.path().join("active_policy.yaml");
        let backup_path = td.path().join("backup_policy.yaml");
        let pending_path = td.path().join("pending_policy.yaml");

        let old_active_yaml = "policy_id: old\nversion: \"1\"\nrules: []\n";
        let new_active_yaml = "policy_id: new\nversion: \"1\"\nrules: []\n";

        fs::write(&active_path, old_active_yaml).expect("failed to write old active");
        let new_digest = hex::encode(Sha256::digest(new_active_yaml.as_bytes()));

        let outcome = activate_policy_with_paths(
            &active_path,
            &backup_path,
            &pending_path,
            new_active_yaml,
            &new_digest,
        )
        .expect("activation should succeed");

        assert_eq!(
            outcome,
            ActivationOutcome::Activated {
                backup_rotated: true
            }
        );
        assert_eq!(
            fs::read_to_string(&active_path).expect("failed to read active"),
            new_active_yaml
        );
        assert_eq!(
            fs::read_to_string(&backup_path).expect("failed to read backup"),
            old_active_yaml
        );
        assert!(!pending_path.exists(), "pending policy should be promoted");
    }
}
