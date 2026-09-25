//! `CircleEnrollmentPolicy` (P2.3) — the rules a CA applies to new join
//! requests. Phase 2 only writes the defaults; Phase 4 reads `approval` to
//! decide manual-vs-automatic, Phase 5 reads `attestation`/`pcr_baselines`,
//! and Phase 10 is what actually lets an operator edit this after creation.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// How a join request is approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    /// An admin must approve every request by hand (today's YAML-approval
    /// flow, `cert_service.rs`).
    Manual,
    /// A valid join code (§5.2 of the plan) is sufficient on its own.
    JoinCodeAuto,
    /// A join code authenticates the request, but an admin still approves it.
    JoinCodeThenManual,
}

impl Default for ApprovalMode {
    fn default() -> Self {
        // Matches today's only implemented path (manual YAML approval) — a
        // circle created before Phase 4 ships join codes has nothing else to
        // fall back to.
        Self::Manual
    }
}

/// How strictly hardware attestation is required at enrollment (Phase 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationRequirement {
    /// A member without valid PCR/hardware evidence is rejected.
    Required,
    /// Evidence is checked when present but not demanded — for mixed
    /// hardware/software-key fleets and dev builds.
    Preferred,
    Off,
}

impl Default for AttestationRequirement {
    fn default() -> Self {
        // The plan's own recommendation (§12, open decision 3): Preferred in
        // dev builds, Required in release builds. Phase 5 does not exist yet
        // to enforce Required meaningfully, so Preferred is the only default
        // that does not silently lock out every join attempt today.
        Self::Preferred
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircleEnrollmentPolicy {
    #[serde(default)]
    pub approval: ApprovalMode,
    #[serde(default)]
    pub attestation: AttestationRequirement,
    /// Key backends a member is allowed to enroll with, e.g. `["se050",
    /// "tpm", "software"]`. Empty means "no restriction" — the CA does not
    /// yet have any members to compare a real fleet policy against at the
    /// moment of creation.
    #[serde(default)]
    pub allowed_hw_backends: Vec<String>,
    /// PCR baselines this circle recognises as trusted. Starts empty — a
    /// fresh circle has no baselines until Phase 5's enrollment flow or an
    /// admin adds one.
    #[serde(default)]
    pub pcr_baselines: Vec<String>,
    /// `None` means unlimited.
    #[serde(default)]
    pub max_members: Option<u32>,
    #[serde(default = "default_cert_validity_days")]
    pub cert_validity_days: u32,
    /// Roles a joining member may request (`member`, `lighthouse`, `relay`,
    /// `lh_relay` — see `cert_service::ApprovalDecision`). Empty means all
    /// four are allowed, matching today's unrestricted YAML-approval flow.
    #[serde(default)]
    pub allow_roles: Vec<String>,
}

fn default_cert_validity_days() -> u32 {
    365
}

impl Default for CircleEnrollmentPolicy {
    fn default() -> Self {
        Self {
            approval: ApprovalMode::default(),
            attestation: AttestationRequirement::default(),
            allowed_hw_backends: Vec::new(),
            pcr_baselines: Vec::new(),
            max_members: None,
            cert_validity_days: default_cert_validity_days(),
            allow_roles: Vec::new(),
        }
    }
}

/// `<var>/mesh/ca/policy.json`.
pub fn path_for(paths: &crate::startup::GuardianPaths) -> PathBuf {
    paths.var_root.join("mesh").join("ca").join("policy.json")
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy at {path} is unreadable: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("policy at {path} is not valid JSON: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
}

/// Reads the current circle's enrollment policy, or `None` if this Guardian
/// has never created/joined a circle (no `mesh/ca/policy.json` written yet).
pub fn load(paths: &crate::startup::GuardianPaths) -> Result<Option<CircleEnrollmentPolicy>, PolicyError> {
    let path = path_for(paths);
    match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text)
            .map(Some)
            .map_err(|source| PolicyError::Parse {
                path: path.display().to_string(),
                source,
            }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(PolicyError::Io {
            path: path.display().to_string(),
            source,
        }),
    }
}

/// Writes the policy atomically (temp file + rename), matching
/// `MeshProfile::save`'s pattern.
pub fn save(paths: &crate::startup::GuardianPaths, policy: &CircleEnrollmentPolicy) -> Result<(), PolicyError> {
    let path = path_for(paths);
    save_to(&path, policy)
}

/// [`save`] against an explicit path — used by [`super::create_circle`] to
/// write into the staging directory before the transaction commits (P2.2).
pub fn save_to(path: &Path, policy: &CircleEnrollmentPolicy) -> Result<(), PolicyError> {
    let dir = path.parent().expect("policy path always has a parent");
    let io_err = |source: std::io::Error| PolicyError::Io {
        path: path.display().to_string(),
        source,
    };
    std::fs::create_dir_all(dir).map_err(io_err)?;
    let body = serde_json::to_vec_pretty(policy).map_err(|source| PolicyError::Parse {
        path: path.display().to_string(),
        source,
    })?;
    let tmp = dir.join(format!(".policy.json.{}.tmp", std::process::id()));
    std::fs::write(&tmp, &body).map_err(io_err)?;
    std::fs::rename(&tmp, path).map_err(io_err)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::startup::GuardianPaths;

    #[test]
    fn defaults_match_the_plans_own_recommendation() {
        let policy = CircleEnrollmentPolicy::default();
        assert_eq!(policy.approval, ApprovalMode::Manual);
        assert_eq!(policy.attestation, AttestationRequirement::Preferred);
        assert_eq!(policy.cert_validity_days, 365);
        assert_eq!(policy.max_members, None);
        assert!(policy.pcr_baselines.is_empty());
    }

    #[test]
    fn a_saved_policy_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        let mut policy = CircleEnrollmentPolicy::default();
        policy.max_members = Some(50);
        policy.allow_roles = vec!["member".to_string(), "relay".to_string()];

        save(&paths, &policy).unwrap();
        let loaded = load(&paths).unwrap().expect("policy must be present");
        assert_eq!(loaded, policy);
    }

    #[test]
    fn no_policy_yet_reads_as_none_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        assert!(load(&paths).unwrap().is_none());
    }

    #[test]
    fn unknown_fields_from_a_future_phase_do_not_break_loading() {
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        let path = path_for(&paths);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut value = serde_json::to_value(CircleEnrollmentPolicy::default()).unwrap();
        value["phase_10_field"] = serde_json::json!("ignored");
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(load(&paths).unwrap().is_some());
    }
}
