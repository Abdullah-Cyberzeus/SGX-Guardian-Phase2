// src/policy_state.rs
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

pub const POLICY_DIR: &str = "policies";
pub const ACTIVE_POLICY: &str = "policies/active_policy.yaml";
pub const BACKUP_POLICY: &str = "policies/backup_policy.yaml";
pub const PENDING_POLICY: &str = "policies/pending_policy.yaml";

/// Ensure policy directory exists
pub fn ensure_policy_dir() -> Result<()> {
    if !Path::new(POLICY_DIR).exists() {
        fs::create_dir_all(POLICY_DIR).context("Failed to create policy directory")?;
    }
    Ok(())
}

/// Atomically promote pending policy to active with rollback
pub fn activate_policy(pending_yaml: &str) -> Result<()> {
    ensure_policy_dir()?;

    // Write pending policy
    fs::write(PENDING_POLICY, pending_yaml).context("Failed to write pending policy")?;

    // Backup active policy (if exists)
    if Path::new(ACTIVE_POLICY).exists() {
        fs::copy(ACTIVE_POLICY, BACKUP_POLICY).context("Failed to backup active policy")?;
    }

    // Promote pending → active (atomic replace)
    fs::rename(PENDING_POLICY, ACTIVE_POLICY).context("Failed to activate new policy")?;

    Ok(())
}

/// Rollback active policy from backup
pub fn rollback_policy() -> Result<()> {
    if Path::new(BACKUP_POLICY).exists() {
        fs::copy(BACKUP_POLICY, ACTIVE_POLICY).context("Failed to rollback policy")?;
    }
    Ok(())
}
