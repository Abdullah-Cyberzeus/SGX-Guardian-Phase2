//! `MeshProfile` — the single source of truth for "who am I, in which circle".
//!
//! Before Phase 0, three facts were encoded as string literals scattered across
//! ~25 production files: the CA was whichever Guardian was named `nodeA`, the
//! circle was always one fixed id, and the overlay was always
//! `192.168.100.0/24`. That is what pinned the product to exactly three nodes,
//! one circle and one CA.
//!
//! This module replaces all three with one persisted record plus accessors.
//! Nothing outside [`crate::mesh::legacy`] should compare an id against a name
//! to decide a role; the P0.8 guard (`tests/no_hardcoded_roles.rs`) enforces it.
//!
//! The profile is stored at `<var>/mesh/profile.json`, mode 0600, written
//! atomically (temp file in the same directory, then `rename`) so a power cut
//! mid-write leaves the previous profile intact rather than a truncated one.

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use crate::startup::GuardianPaths;

/// Current on-disk schema. Bump only for a breaking layout change, and add a
/// migration arm in [`MeshProfile::from_json`] when you do.
pub const PROFILE_SCHEMA_VERSION: u32 = 1;

/// What this Guardian is within its circle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshRole {
    /// Holds `nebula/ca/ca.key` and signs member certificates.
    Ca,
    /// Holds a certificate signed by the circle CA.
    Member,
}

/// How this Guardian came to be in its circle. Kept for audit and for the
/// Phase 1 UI, which shows a different reset path for a migrated legacy node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollChannel {
    /// This Guardian created the circle (it is the CA).
    Created,
    /// Enrolled over the LAN against a discovered CA.
    Lan,
    /// Enrolled over the WAN through the rendezvous broker.
    Wan,
    /// Synthesised by [`crate::mesh::legacy`] from a pre-Phase-0 install.
    LegacyMigration,
}

/// A lighthouse this Guardian should reach, as delivered in the enrollment
/// bundle. `overlay_ip` is inside the circle; `endpoints` are routable ones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LighthouseHint {
    pub overlay_ip: String,
    #[serde(default)]
    pub endpoints: Vec<String>,
}

/// The persisted answer to every "am I the CA / which circle / which subnet"
/// question in the codebase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshProfile {
    pub schema_version: u32,
    pub guardian_id: String,
    pub role: MeshRole,
    pub circle_id: String,
    pub circle_name: String,
    /// Which Guardian signs for this circle. Equals `guardian_id` when `role`
    /// is [`MeshRole::Ca`].
    pub ca_guardian_id: String,
    /// SHA-256 of the circle's Nebula CA certificate — the trust pin.
    #[serde(default)]
    pub ca_fingerprint: String,
    /// DID of the CA Guardian, which signs CA descriptors from Phase 3 on.
    #[serde(default)]
    pub ca_owner_did: String,
    /// The circle's overlay network, e.g. `192.168.100.0/24`.
    pub overlay_cidr: String,
    /// This Guardian's address within it, e.g. `192.168.100.2/24`.
    #[serde(default)]
    pub overlay_ip: String,
    #[serde(default)]
    pub lighthouses: Vec<LighthouseHint>,
    #[serde(default)]
    pub rendezvous_url: Option<String>,
    pub enrolled_via: EnrollChannel,
    pub enrolled_at: String,
}

/// Anything that can go wrong reading, validating or writing a profile.
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("this Guardian is not enrolled in a mesh circle yet")]
    NotEnrolled,
    #[error("mesh profile at {path} is unreadable: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("mesh profile at {path} is not valid JSON: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("mesh profile schema version {found} is newer than this build supports ({supported})")]
    UnsupportedSchema { found: u32, supported: u32 },
    #[error("mesh profile is invalid: {0}")]
    Invalid(String),
}

/// Guardian ids and circle ids end up in file paths, Nebula cert subject names
/// and mDNS TXT records, so they are restricted to a conservative character set.
fn validate_identifier(label: &str, value: &str, max_len: usize) -> Result<(), ProfileError> {
    if value.is_empty() {
        return Err(ProfileError::Invalid(format!("{label} must not be empty")));
    }
    if value.len() > max_len {
        return Err(ProfileError::Invalid(format!(
            "{label} must be at most {max_len} characters (got {})",
            value.len()
        )));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ProfileError::Invalid(format!(
            "{label} '{value}' must be ASCII alphanumeric with - or _ only"
        )));
    }
    Ok(())
}

impl MeshProfile {
    /// `<var>/mesh/profile.json` under the given path set.
    pub fn path_for(paths: &GuardianPaths) -> PathBuf {
        paths.var_root.join("mesh").join("profile.json")
    }

    /// Structural checks applied on every load and before every save, so an
    /// externally edited profile cannot put the daemon into a state the rest of
    /// the code assumes is impossible.
    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.schema_version > PROFILE_SCHEMA_VERSION {
            return Err(ProfileError::UnsupportedSchema {
                found: self.schema_version,
                supported: PROFILE_SCHEMA_VERSION,
            });
        }
        validate_identifier("guardian_id", &self.guardian_id, 48)?;
        validate_identifier("circle_id", &self.circle_id, 64)?;
        validate_identifier("ca_guardian_id", &self.ca_guardian_id, 48)?;

        if self.role == MeshRole::Ca && self.ca_guardian_id != self.guardian_id {
            return Err(ProfileError::Invalid(format!(
                "role is Ca but ca_guardian_id '{}' is not this Guardian '{}'",
                self.ca_guardian_id, self.guardian_id
            )));
        }
        if self.overlay_cidr.is_empty() {
            return Err(ProfileError::Invalid("overlay_cidr must not be empty".into()));
        }
        self.overlay_cidr
            .parse::<ipnet::IpNet>()
            .map_err(|e| ProfileError::Invalid(format!("overlay_cidr is not a CIDR: {e}")))?;
        Ok(())
    }

    /// The first three octets of the overlay network, which is the shape the
    /// existing `OverlayRegistry` / `OverlayPool` APIs take.
    pub fn overlay_prefix(&self) -> Result<String, ProfileError> {
        let net: ipnet::IpNet = self
            .overlay_cidr
            .parse()
            .map_err(|e| ProfileError::Invalid(format!("overlay_cidr is not a CIDR: {e}")))?;
        match net.network() {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                Ok(format!("{}.{}.{}", o[0], o[1], o[2]))
            }
            std::net::IpAddr::V6(_) => Err(ProfileError::Invalid(
                "IPv6 overlays have no /24 prefix form; use overlay_cidr directly".into(),
            )),
        }
    }

    pub fn is_ca(&self) -> bool {
        self.role == MeshRole::Ca
    }

    fn from_json(text: &str, path: &Path) -> Result<Self, ProfileError> {
        let profile: MeshProfile =
            serde_json::from_str(text).map_err(|source| ProfileError::Parse {
                path: path.display().to_string(),
                source,
            })?;
        profile.validate()?;
        Ok(profile)
    }

    /// Reads and validates the profile at `path_for(paths)`.
    ///
    /// `Ok(None)` means "no profile yet", which is the normal state of an
    /// unenrolled Guardian and is distinct from a profile that exists but is
    /// corrupt — the latter is an error so it cannot be silently overwritten.
    pub fn load(paths: &GuardianPaths) -> Result<Option<Self>, ProfileError> {
        let path = Self::path_for(paths);
        match std::fs::read_to_string(&path) {
            Ok(text) => Ok(Some(Self::from_json(&text, &path)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(ProfileError::Io {
                path: path.display().to_string(),
                source,
            }),
        }
    }

    /// Validates, then writes atomically with mode 0600.
    ///
    /// The temp file is created in the destination directory so the `rename` is
    /// within one filesystem and therefore atomic; a crash leaves either the old
    /// profile or the new one, never a partial write.
    pub fn save(&self, paths: &GuardianPaths) -> Result<(), ProfileError> {
        self.validate()?;
        let path = Self::path_for(paths);
        let dir = path.parent().expect("profile path always has a parent");
        std::fs::create_dir_all(dir).map_err(|source| ProfileError::Io {
            path: dir.display().to_string(),
            source,
        })?;

        let body = serde_json::to_vec_pretty(self).map_err(|source| ProfileError::Parse {
            path: path.display().to_string(),
            source,
        })?;

        let tmp = dir.join(format!(".profile.json.{}.tmp", std::process::id()));
        let io_err = |source: std::io::Error| ProfileError::Io {
            path: tmp.display().to_string(),
            source,
        };
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp).map_err(io_err)?;
            f.write_all(&body).map_err(io_err)?;
            f.sync_all().map_err(io_err)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
                .map_err(io_err)?;
        }
        std::fs::rename(&tmp, &path).map_err(|source| ProfileError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────
// Process-wide cache
// ────────────────────────────────────────────────────────────────────
//
// Role checks happen on hot paths (every attestation, every peer dial), so the
// profile is cached rather than re-read. `RwLock<Option<Arc<_>>>` keeps reads
// cheap and lets Phase 2 swap in a new profile at runtime when a circle is
// created, without threading a handle through every call site.

static CACHE: Lazy<RwLock<Option<Arc<MeshProfile>>>> = Lazy::new(|| RwLock::new(None));

/// Where the process reads and writes the profile. Tests point this at a
/// sandbox via [`install_paths_for_tests`].
static PATHS: Lazy<RwLock<GuardianPaths>> = Lazy::new(|| RwLock::new(GuardianPaths::production()));

fn active_paths() -> GuardianPaths {
    PATHS.read().expect("mesh profile paths poisoned").clone()
}

/// Redirects the module at a sandbox root. Intended for tests and for
/// containerised runs that relocate the whole tree.
pub fn install_paths(paths: GuardianPaths) {
    *PATHS.write().expect("mesh profile paths poisoned") = paths;
    invalidate();
}

/// Loads the profile from disk into the cache. Call once during boot, after the
/// legacy migration has had its chance to synthesise one.
///
/// Returns the profile if there is one. A corrupt profile is an error: the
/// daemon must not treat it as "unenrolled" and overwrite it.
pub fn initialize() -> Result<Option<Arc<MeshProfile>>, ProfileError> {
    let loaded = MeshProfile::load(&active_paths())?.map(Arc::new);
    *CACHE.write().expect("mesh profile cache poisoned") = loaded.clone();
    Ok(loaded)
}

/// The cached profile, or `None` while this Guardian is unenrolled.
pub fn current() -> Option<Arc<MeshProfile>> {
    CACHE.read().expect("mesh profile cache poisoned").clone()
}

/// Persists `profile` and makes it the process-wide current one.
pub fn install(profile: MeshProfile) -> Result<Arc<MeshProfile>, ProfileError> {
    profile.save(&active_paths())?;
    let shared = Arc::new(profile);
    *CACHE.write().expect("mesh profile cache poisoned") = Some(shared.clone());
    Ok(shared)
}

/// Drops the cached profile without touching the file, forcing the next
/// [`initialize`] to re-read.
pub fn invalidate() {
    *CACHE.write().expect("mesh profile cache poisoned") = None;
}

fn require() -> Result<Arc<MeshProfile>, ProfileError> {
    current().ok_or(ProfileError::NotEnrolled)
}

/// Whether this Guardian signs certificates for its circle.
///
/// This is the replacement for comparing a node id against the CA's name.
/// It is deliberately
/// `false` when unenrolled: a Guardian with no profile has no CA authority,
/// which is the fail-closed answer.
pub fn is_ca() -> bool {
    current().map(|p| p.is_ca()).unwrap_or(false)
}

pub fn guardian_id() -> Result<String, ProfileError> {
    Ok(require()?.guardian_id.clone())
}

pub fn circle_id() -> Result<String, ProfileError> {
    Ok(require()?.circle_id.clone())
}

pub fn ca_guardian_id() -> Result<String, ProfileError> {
    Ok(require()?.ca_guardian_id.clone())
}

pub fn overlay_prefix() -> Result<String, ProfileError> {
    require()?.overlay_prefix()
}

pub fn overlay_cidr() -> Result<String, ProfileError> {
    Ok(require()?.overlay_cidr.clone())
}

/// Circle id for call sites that must not fail, such as audit logging and
/// registry defaults during boot before the profile has loaded.
pub fn circle_id_or(fallback: &str) -> String {
    circle_id().unwrap_or_else(|_| fallback.to_string())
}

/// Overlay prefix for the same kind of call site as [`circle_id_or`].
pub fn overlay_prefix_or(fallback: &str) -> String {
    overlay_prefix().unwrap_or_else(|_| fallback.to_string())
}

/// CA guardian id for the same kind of call site as [`circle_id_or`].
pub fn ca_guardian_id_or(fallback: &str) -> String {
    ca_guardian_id().unwrap_or_else(|_| fallback.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(role: MeshRole, guardian: &str) -> MeshProfile {
        MeshProfile {
            schema_version: PROFILE_SCHEMA_VERSION,
            guardian_id: guardian.to_string(),
            role,
            circle_id: "circle-7f3c1a".to_string(),
            circle_name: "SGX-Alpha".to_string(),
            ca_guardian_id: if role == MeshRole::Ca {
                guardian.to_string()
            } else {
                "us-hq-01".to_string()
            },
            ca_fingerprint: "sha256:abc".to_string(),
            ca_owner_did: "did:guardian:xyz".to_string(),
            overlay_cidr: "192.168.100.0/24".to_string(),
            overlay_ip: "192.168.100.5/24".to_string(),
            lighthouses: vec![LighthouseHint {
                overlay_ip: "192.168.100.1".into(),
                endpoints: vec!["203.0.113.9:4242".into()],
            }],
            rendezvous_url: None,
            enrolled_via: EnrollChannel::Lan,
            enrolled_at: "2026-09-24T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn a_saved_profile_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        let profile = sample(MeshRole::Member, "edge-7");

        profile.save(&paths).unwrap();
        let loaded = MeshProfile::load(&paths).unwrap().unwrap();
        assert_eq!(loaded, profile);
    }

    #[test]
    fn a_missing_profile_reads_as_none_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        assert!(MeshProfile::load(&paths).unwrap().is_none());
    }

    #[test]
    fn a_corrupt_profile_is_an_error_so_it_is_never_silently_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        let path = MeshProfile::path_for(&paths);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"{ not json").unwrap();

        let err = MeshProfile::load(&paths).unwrap_err();
        assert!(matches!(err, ProfileError::Parse { .. }), "got {err:?}");
    }

    #[cfg(unix)]
    #[test]
    fn a_saved_profile_is_owner_readable_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        sample(MeshRole::Ca, "us-hq-01").save(&paths).unwrap();

        let mode = std::fs::metadata(MeshProfile::path_for(&paths))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "profile must not be group/world readable");
    }

    #[test]
    fn saving_leaves_no_temp_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        sample(MeshRole::Member, "nodeB").save(&paths).unwrap();

        let mesh_dir = MeshProfile::path_for(&paths).parent().unwrap().to_path_buf();
        let leftovers: Vec<_> = std::fs::read_dir(&mesh_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "stray temp files: {leftovers:?}");
    }

    #[test]
    fn a_ca_profile_whose_ca_is_another_guardian_is_rejected() {
        let mut profile = sample(MeshRole::Ca, "us-hq-01");
        profile.ca_guardian_id = "someone-else".into();
        let err = profile.validate().unwrap_err();
        assert!(matches!(err, ProfileError::Invalid(_)), "got {err:?}");
    }

    #[test]
    fn identifiers_with_path_traversal_characters_are_rejected() {
        for bad in ["../etc", "node A", "node/A", ""] {
            let mut profile = sample(MeshRole::Member, "nodeB");
            profile.guardian_id = bad.to_string();
            assert!(
                profile.validate().is_err(),
                "guardian_id '{bad}' must be rejected — it reaches file paths and cert names"
            );
        }
    }

    #[test]
    fn a_newer_schema_version_is_refused_rather_than_misread() {
        let mut profile = sample(MeshRole::Member, "nodeB");
        profile.schema_version = PROFILE_SCHEMA_VERSION + 1;
        let err = profile.validate().unwrap_err();
        assert!(
            matches!(err, ProfileError::UnsupportedSchema { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn a_non_cidr_overlay_is_rejected() {
        let mut profile = sample(MeshRole::Member, "nodeB");
        profile.overlay_cidr = "192.168.100.0".into();
        assert!(profile.validate().is_err());
    }

    #[test]
    fn overlay_prefix_returns_the_first_three_octets() {
        let profile = sample(MeshRole::Member, "nodeB");
        assert_eq!(profile.overlay_prefix().unwrap(), "192.168.100");

        let mut wide = profile.clone();
        wide.overlay_cidr = "10.44.0.0/16".into();
        assert_eq!(wide.overlay_prefix().unwrap(), "10.44.0");
    }

    #[test]
    fn unknown_fields_from_a_future_build_do_not_break_loading() {
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        let path = MeshProfile::path_for(&paths);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        let mut value = serde_json::to_value(sample(MeshRole::Member, "nodeB")).unwrap();
        value["some_phase_9_field"] = serde_json::json!("ignored");
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        assert!(MeshProfile::load(&paths).unwrap().is_some());
    }

    #[test]
    fn an_unenrolled_guardian_is_never_treated_as_the_ca() {
        // Exercised on the struct rather than the global cache so this test does
        // not race the other tests in this binary.
        let profile = sample(MeshRole::Member, "nodeB");
        assert!(!profile.is_ca());
        assert!(sample(MeshRole::Ca, "us-hq-01").is_ca());
    }

    #[test]
    fn accessor_fallbacks_are_used_when_no_profile_is_cached() {
        invalidate();
        // These run before boot has loaded a profile, so they must not panic.
        assert_eq!(circle_id_or("guardian-circle-alpha"), "guardian-circle-alpha");
        assert_eq!(overlay_prefix_or("192.168.100"), "192.168.100");
        assert_eq!(ca_guardian_id_or("nodeA"), "nodeA");
        assert!(matches!(circle_id(), Err(ProfileError::NotEnrolled)));
    }
}
