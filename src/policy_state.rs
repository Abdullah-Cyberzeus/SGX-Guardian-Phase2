// src/policy_state.rs
use crate::enforcement::uep::{MediaType, RbacRule, Role};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

pub const POLICY_DIR: &str = "/etc/sgx-guardian/policies";
pub const ACTIVE_POLICY: &str = "/etc/sgx-guardian/policies/active_policy.yaml";
pub const BACKUP_POLICY: &str = "/etc/sgx-guardian/policies/backup_policy.yaml";
pub const PENDING_POLICY: &str = "/etc/sgx-guardian/policies/pending_policy.yaml";
const POLICY_DIR_ENV: &str = "SGX_GUARDIAN_POLICY_DIR";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationOutcome {
    Unchanged,
    Activated { backup_rotated: bool },
}

fn policy_dir_path() -> PathBuf {
    std::env::var_os(POLICY_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(POLICY_DIR))
}

fn active_policy_path() -> PathBuf {
    policy_dir_path().join("active_policy.yaml")
}

pub fn active_policy_file_path() -> PathBuf {
    active_policy_path()
}

fn backup_policy_path() -> PathBuf {
    policy_dir_path().join("backup_policy.yaml")
}

fn pending_policy_path() -> PathBuf {
    policy_dir_path().join("pending_policy.yaml")
}

/// Ensure policy directory exists
pub fn ensure_policy_dir() -> Result<()> {
    let policy_dir = policy_dir_path();
    if !policy_dir.exists() {
        fs::create_dir_all(&policy_dir).context("Failed to create policy directory")?;
    }
    Ok(())
}

/// Atomically promote pending policy to active with rollback
pub fn activate_policy(
    pending_yaml: &str,
    incoming_policy_digest: &str,
) -> Result<ActivationOutcome> {
    ensure_policy_dir()?;

    let active_path = active_policy_path();
    let backup_path = backup_policy_path();
    let pending_path = pending_policy_path();

    activate_policy_with_paths(
        &active_path,
        &backup_path,
        &pending_path,
        pending_yaml,
        incoming_policy_digest,
    )
}

pub fn current_active_policy_digest() -> Result<Option<String>> {
    let active_path = active_policy_path();
    if !active_path.exists() {
        return Ok(None);
    }

    let active_bytes = fs::read(&active_path).context("Failed to read active policy")?;
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
    let backup_path = backup_policy_path();
    let active_path = active_policy_path();
    if backup_path.exists() {
        fs::copy(&backup_path, &active_path).context("Failed to rollback policy")?;
    }
    Ok(())
}

/// Load RBAC rules from the active policy YAML
///
/// Expects the policy YAML to have a structure like:
/// ```yaml
/// policy_id: "..."
/// version: "..."
/// rbac_rules:
///   - caller_role: admin
///     target_role: operator
///     allowed_media_types:
///       - voice
///       - video
/// ```
pub fn load_rbac_rules() -> Result<Vec<RbacRule>> {
    let active_path = active_policy_path();

    // If no active policy, return default rules
    if !active_path.exists() {
        return Ok(crate::enforcement::uep::UepEngine::default_rules());
    }

    let policy_yaml =
        fs::read_to_string(&active_path).context("Failed to read active policy for RBAC rules")?;

    let policy: serde_yaml::Value =
        serde_yaml::from_str(&policy_yaml).context("Failed to parse active policy YAML")?;

    // Try to extract rbac_rules from the policy
    let rbac_rules = policy
        .get("rbac_rules")
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|rule_val| {
                    let caller_role = rule_val
                        .get("caller_role")
                        .and_then(|v| v.as_str())
                        .and_then(Role::from_str)?;
                    let target_role = rule_val
                        .get("target_role")
                        .and_then(|v| v.as_str())
                        .and_then(Role::from_str)?;

                    let allowed_media_types = rule_val
                        .get("allowed_media_types")
                        .and_then(|v| v.as_sequence())
                        .map(|seq| {
                            seq.iter()
                                .filter_map(|mt_val| mt_val.as_str().and_then(MediaType::from_str))
                                .collect::<HashSet<_>>()
                        })
                        .unwrap_or_default();

                    Some(RbacRule {
                        caller_role,
                        target_role,
                        allowed_media_types,
                    })
                })
                .collect()
        });

    // If rules found in policy, return them; otherwise use defaults
    Ok(rbac_rules.unwrap_or_else(|| crate::enforcement::uep::UepEngine::default_rules()))
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

    #[test]
    fn load_rbac_rules_with_explicit_rules() {
        let td = tempdir().expect("failed to create temp dir");
        std::env::set_var("SGX_GUARDIAN_POLICY_DIR", td.path());

        let policy_with_rbac = r#"
policy_id: test
version: "1.0"
rbac_rules:
  - caller_role: admin
    target_role: operator
    allowed_media_types:
      - voice
      - video
  - caller_role: operator
    target_role: camera
    allowed_media_types:
      - voice
"#;

        ensure_policy_dir().expect("create policy dir");
        let active_path = active_policy_path();
        fs::write(&active_path, policy_with_rbac).expect("write policy");

        let rules = load_rbac_rules().expect("load rbac rules");
        assert!(!rules.is_empty());
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn load_rbac_rules_returns_defaults_when_missing() {
        let td = tempdir().expect("failed to create temp dir");
        std::env::set_var("SGX_GUARDIAN_POLICY_DIR", td.path());

        ensure_policy_dir().expect("create policy dir");
        // Don't write a policy file

        let rules = load_rbac_rules().expect("load default rbac rules");
        // Should get default rules when no active policy exists
        assert!(!rules.is_empty());
    }
}
