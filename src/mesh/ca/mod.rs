//! `mesh::ca::create_circle` (P2.1/P2.2) — the operator explicitly making
//! this Guardian the CA of a brand-new circle.
//!
//! ## Ordering the plan states loosely but the code requires strictly
//!
//! The plan's own prose lists the steps as "...create the Circle record and
//! self-issued owner VC, write the MeshProfile..." — but
//! `vc::issue::can_bootstrap_issue` only allows a self-issued VC when
//! `mesh::ca_guardian_id()` (which reads `MeshProfile`) already resolves to
//! *this* Guardian. So `MeshProfile` has to be written **before** the VC is
//! issued, not after. This module follows the order the code actually needs:
//! CA material → own cert → PA key → `MeshProfile` → Circle record + owner VC
//! → lifecycle transition.
//!
//! ## Crash safety (P2.2)
//!
//! Every file this writes to the real `nebula/` tree is generated in
//! `mesh/staging/create-<ts>/` first and only `rename`d into place once
//! everything has succeeded. A crash mid-creation leaves an abandoned staging
//! directory and an untouched (or absent) `nebula/`, never the previous
//! `ca.rs:96` "partial CA state → manual intervention" failure mode — there
//! is nothing to intervene on, since nothing real was ever half-written.
//! [`cleanup_stale_staging`] removes old staging directories at boot.
//!
//! ## No live activation from this call
//!
//! `mesh::activation::activate_mesh` only runs from `main()`, with 14
//! parameters that live in its stack frame (P1.2) — there is no live path
//! into it from a running API handler. This module does the (purely local,
//! filesystem/crypto) creation work and returns; the API handler (P2.4)
//! is what asks the process to restart afterward, so the *next* boot's
//! already-proven `resolve_boot_state → CircleMember → activate_mesh` path
//! brings Nebula up.

pub mod descriptor;
pub mod policy;

use crate::mesh::profile::{EnrollChannel, MeshProfile, MeshRole, PROFILE_SCHEMA_VERSION};
use crate::nebula::ca::{CaIdentity, NebulaCA};
use crate::nebula::models::CircleMembership;
use crate::nebula::overlay_registry::OverlayRegistry;
use crate::startup::GuardianPaths;
use chrono::Utc;
use std::path::PathBuf;

/// What the operator supplies when creating a circle. Everything is
/// optional — `create_circle` fills in the plan's stated defaults.
#[derive(Debug, Clone, Default)]
pub struct CreateCircleOptions {
    pub overlay_cidr: Option<String>,
    pub policy: Option<policy::CircleEnrollmentPolicy>,
}

/// What the caller (the API handler) needs to report success and drive the
/// "CA fingerprint in words + hex" success screen (P2.5).
#[derive(Debug, Clone)]
pub struct CreatedCircle {
    pub circle_id: String,
    pub circle_name: String,
    pub ca_fingerprint: String,
    pub overlay_cidr: String,
    pub overlay_ip: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CreateCircleError {
    #[error("this Guardian already has a circle profile — reset it before creating another")]
    AlreadyEnrolled,
    #[error("this Guardian already has Nebula CA material on disk from a previous install")]
    NebulaMaterialExists,
    #[error(
        "overlay_cidr must be a /24 in this release (variable-width overlays are a later phase): {0}"
    )]
    UnsupportedCidr(String),
    #[error("invalid circle name: {0}")]
    InvalidName(String),
    #[error("staging directory error: {0}")]
    Staging(#[source] std::io::Error),
    #[error("Nebula CA generation failed: {0}")]
    Nebula(#[source] std::io::Error),
    #[error("local Nebula keygen failed: {0}")]
    Keygen(#[source] crate::mesh::enroll::keys::KeygenError),
    #[error("could not read the generated CA fingerprint")]
    MissingFingerprint,
    #[error("mesh profile error: {0}")]
    Profile(#[source] crate::mesh::profile::ProfileError),
    #[error("lifecycle error: {0}")]
    Lifecycle(#[source] crate::mesh::lifecycle::LifecycleError),
    #[error("policy save failed: {0}")]
    Policy(#[source] policy::PolicyError),
    #[error("circle record error: {0}")]
    CircleStore(#[source] crate::circle::errors::CircleError),
    #[error("owner credential issuance failed: {0}")]
    Vc(String),
    #[error("commit failed: {0}")]
    Commit(#[source] std::io::Error),
}

const CROCKFORD_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// `"circle-" + 12 random Crockford-base32 characters` (P2.1). Crockford's
/// alphabet — no `0`, `1`, `2`... wait: it *excludes* the visually ambiguous
/// `I`, `L`, `O`, `U`, which is exactly why it is the standard choice for a
/// code a human might ever need to read back or type (Phase 4's join codes
/// reuse this circle_id verbatim). No crate added for this — twelve alphabet
/// lookups is little enough to hand-roll rather than take on a new
/// dependency for.
fn generate_circle_id() -> String {
    let mut id = String::with_capacity(7 + 12);
    id.push_str("circle-");
    for _ in 0..12 {
        let idx = (rand::random::<u8>() as usize) % CROCKFORD_ALPHABET.len();
        id.push(CROCKFORD_ALPHABET[idx] as char);
    }
    id
}

fn validate_circle_name(name: &str) -> Result<String, CreateCircleError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return Err(CreateCircleError::InvalidName(
            "must be 1-64 characters".into(),
        ));
    }
    // Reaches the Nebula CA subject name and, later, mDNS TXT records (§5.1)
    // — kept to a conservative, definitely-safe character set rather than
    // whatever `nebula-cert` or mDNS happen to tolerate today.
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_'))
    {
        return Err(CreateCircleError::InvalidName(
            "must be alphanumeric, spaces, - or _ only".into(),
        ));
    }
    Ok(trimmed.to_string())
}

fn validate_overlay_cidr(cidr: &str) -> Result<String, CreateCircleError> {
    let net: ipnet::IpNet = cidr
        .parse()
        .map_err(|_| CreateCircleError::UnsupportedCidr(cidr.to_string()))?;
    // The rest of the codebase — OverlayRegistry, mesh::overlay_prefix(),
    // every "192.168.100"-shaped literal P0.6 replaced — is built around a
    // three-octet "/24" prefix end to end. Accepting a real /16 here would
    // need that model changed too, which is bigger surgery than this task;
    // the plan's "/16–/24" is aspirational until then.
    match net {
        ipnet::IpNet::V4(v4) if v4.prefix_len() == 24 => Ok(net.to_string()),
        _ => Err(CreateCircleError::UnsupportedCidr(cidr.to_string())),
    }
}

fn staging_dir(paths: &GuardianPaths) -> PathBuf {
    paths
        .var_root
        .join("mesh")
        .join("staging")
        .join(format!("create-{}", Utc::now().timestamp_millis()))
}

/// The real Nebula tree this creation ultimately commits into —
/// intentionally the exact same path every other Nebula-facing piece of code
/// already assumes (`cert_service.rs`, `mesh::activation`, etc.), not a
/// mesh-owned path, since it's the thing all of those read from after a
/// restart.
fn live_nebula_dir(paths: &GuardianPaths) -> PathBuf {
    paths.var_root.join("nebula")
}

/// Removes staging directories left behind by a process that died mid-create
/// (P2.2). Called once at boot, alongside `mesh::legacy::migrate_and_initialize`
/// — safe to call unconditionally: a stale staging directory was, by
/// construction, never referenced by anything that committed.
pub fn cleanup_stale_staging(paths: &GuardianPaths) {
    let staging_root = paths.var_root.join("mesh").join("staging");
    let Ok(entries) = std::fs::read_dir(&staging_root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Err(e) = std::fs::remove_dir_all(&path) {
                eprintln!(
                    "⚠️ Could not remove stale mesh creation staging directory {}: {e}",
                    path.display()
                );
            } else {
                println!(
                    "🧹 Removed stale mesh creation staging directory {}",
                    path.display()
                );
            }
        }
    }
}

/// Creates a new mesh circle with this Guardian as its CA (P2.1).
///
/// Async only because [`crate::mesh::lifecycle::transition_to`] and the
/// filesystem work here are synchronous, but the API handler calling this
/// runs in an async context and this keeps the call site uniform with the
/// rest of `mesh::`; nothing here actually awaits.
pub async fn create_circle(
    paths: &GuardianPaths,
    guardian_id: &str,
    name: String,
    options: CreateCircleOptions,
) -> Result<CreatedCircle, CreateCircleError> {
    if crate::mesh::profile::current().is_some() {
        return Err(CreateCircleError::AlreadyEnrolled);
    }
    let live_nebula = live_nebula_dir(paths);
    if NebulaCA::ca_cert_exists(&live_nebula.display().to_string())
        || live_nebula.join("nodes").join(format!("{guardian_id}.crt")).exists()
    {
        return Err(CreateCircleError::NebulaMaterialExists);
    }

    let circle_name = validate_circle_name(&name)?;
    let overlay_cidr = validate_overlay_cidr(
        options
            .overlay_cidr
            .as_deref()
            .unwrap_or(crate::mesh::legacy::LEGACY_OVERLAY_CIDR),
    )?;
    let overlay_prefix = overlay_cidr
        .split('/')
        .next()
        .and_then(|addr| {
            let octets: Vec<&str> = addr.split('.').collect();
            (octets.len() == 4).then(|| octets[..3].join("."))
        })
        .ok_or_else(|| CreateCircleError::UnsupportedCidr(overlay_cidr.clone()))?;
    let circle_id = generate_circle_id();
    let policy = options.policy.unwrap_or_default();
    let identity = CaIdentity::for_circle(&circle_name);

    let _ = crate::mesh::lifecycle::transition_to(
        crate::mesh::lifecycle::LifecycleState::CreatingCircle,
        None,
    );

    let staging = staging_dir(paths);
    let staging_nebula = staging.join("nebula");
    std::fs::create_dir_all(&staging_nebula).map_err(CreateCircleError::Staging)?;

    // ── 1. Generate the circle's Nebula CA ────────────────────────────
    let staging_nebula_str = staging_nebula.display().to_string();
    NebulaCA::generate_ca_with(&staging_nebula_str, &identity).map_err(CreateCircleError::Nebula)?;

    // ── 2. This Guardian's own overlay IP + keypair + self-signed cert ──
    let mut overlay_registry = OverlayRegistry::load_or_create(
        &staging_nebula.join("overlay_registry.json").display().to_string(),
        &circle_id,
        &overlay_prefix,
        guardian_id,
    );
    let overlay_ip = overlay_registry
        .assign_ip(guardian_id)
        .map_err(|e| CreateCircleError::Nebula(std::io::Error::other(e)))?;
    overlay_registry
        .save(&staging_nebula.join("overlay_registry.json").display().to_string())
        .map_err(|e| CreateCircleError::Nebula(std::io::Error::other(e)))?;

    let keypair = crate::mesh::enroll::keys::ensure_local_keypair(&staging_nebula_str, guardian_id)
        .map_err(CreateCircleError::Keygen)?;

    let membership = CircleMembership {
        node_name: guardian_id.to_string(),
        circle_id: circle_id.clone(),
        vc_hash: "circle-owner-self-signed".to_string(),
        is_valid: true,
    };
    NebulaCA::issue_node_cert_from_pub_with(
        &staging_nebula_str,
        &membership,
        &overlay_ip,
        &keypair.public_key_pem,
        &identity,
    )
    .map_err(CreateCircleError::Nebula)?;

    let ca_fingerprint = NebulaCA::ca_fingerprint(&staging_nebula_str)
        .ok_or(CreateCircleError::MissingFingerprint)?;

    // ── 3. Policy Authority key ─────────────────────────────────────────
    // Device-wide, fixed path (/etc/sgx-guardian/policies/...), already
    // idempotent — not circle-specific state, so not part of the staged
    // nebula/ commit below.
    if let Err(e) = crate::policy_authority::PaKey::load_or_generate() {
        eprintln!("⚠️ PA key bootstrap failed during circle creation: {e} — manual signing required");
    }

    // ── 4. Circle enrollment policy ──────────────────────────────────────
    policy::save_to(&staging.join("policy.json"), &policy).map_err(CreateCircleError::Policy)?;

    // ── 5. Commit: rename staging into place ────────────────────────────
    // The one moment this function can partially fail *after* real state
    // exists — but by then `staging_nebula` and `live_nebula` are both fully
    // formed trees, so a crash between these two renames leaves `nebula/`
    // either fully absent or fully present, never partial.
    //
    // `live_nebula` can already exist here even though the guard at the top
    // of this function found no CA cert and no signed node cert: the legacy
    // self-bootstrap enrollment attempt in `mesh::activation::activate_mesh`
    // runs in the background on every boot (P1.2) and, when it finds a LAN
    // CA, calls `cert_client::request_certificate_from_ca` — which mints
    // this Guardian's own `nodes/<guardian_id>.{key,pub}` straight into the
    // *live* tree before it even knows whether a signed cert will come back.
    // If that request doesn't fully complete, the bare keypair is left
    // behind. `std::fs::rename` onto an existing non-empty directory fails
    // with `ENOTEMPTY`, so that harmless leftover would otherwise block
    // every circle creation. Re-run the same "no real identity material"
    // check right before committing (this narrows, but cannot fully close,
    // the race against that background task) and only clear the directory
    // when it still holds nothing but that leftover — never when it holds
    // an actual CA cert or signed node cert.
    if live_nebula.exists() {
        if NebulaCA::ca_cert_exists(&live_nebula.display().to_string())
            || live_nebula.join("nodes").join(format!("{guardian_id}.crt")).exists()
        {
            return Err(CreateCircleError::NebulaMaterialExists);
        }
        std::fs::remove_dir_all(&live_nebula).map_err(CreateCircleError::Commit)?;
    }
    if let Some(parent) = live_nebula.parent() {
        std::fs::create_dir_all(parent).map_err(CreateCircleError::Commit)?;
    }
    std::fs::rename(&staging_nebula, &live_nebula).map_err(CreateCircleError::Commit)?;
    let live_policy = policy::path_for(paths);
    if let Some(parent) = live_policy.parent() {
        std::fs::create_dir_all(parent).map_err(CreateCircleError::Commit)?;
    }
    std::fs::rename(staging.join("policy.json"), &live_policy).map_err(CreateCircleError::Commit)?;
    let _ = std::fs::remove_dir_all(&staging);

    // ── 6. MeshProfile — before the VC (see module doc comment on why) ──
    let mesh_profile = MeshProfile {
        schema_version: PROFILE_SCHEMA_VERSION,
        guardian_id: guardian_id.to_string(),
        role: MeshRole::Ca,
        circle_id: circle_id.clone(),
        circle_name: circle_name.clone(),
        ca_guardian_id: guardian_id.to_string(),
        ca_fingerprint: ca_fingerprint.clone(),
        ca_owner_did: crate::did::DidRecord::load(crate::did::DEFAULT_DID_PATH)
            .map(|r| r.did)
            .unwrap_or_default(),
        overlay_cidr: overlay_cidr.clone(),
        overlay_ip: overlay_ip.clone(),
        lighthouses: Vec::new(),
        rendezvous_url: None,
        enrolled_via: EnrollChannel::Created,
        enrolled_at: Utc::now().to_rfc3339(),
    };
    crate::mesh::profile::install(mesh_profile).map_err(CreateCircleError::Profile)?;

    // ── 7. Self-issued owner VC, then the Circle{kind: Mesh} record ─────
    // The VC has to come first: on a brand-new Guardian, `circle::store`
    // has no `circle_registry.json` yet, and `load_or_seed_unlocked` seeds
    // that very first registry by reading this Guardian's own local
    // membership VC (`vc::persistence::load_own_mesh()`) — so creating the
    // circle record before the VC exists fails with "local membership VC
    // not found for circle registry seed" every time, not just sometimes.
    // Issuing the VC has no dependency on the circle record existing (only
    // on the `MeshProfile` installed in step 6, via `can_bootstrap_issue`),
    // so the reverse order is safe.
    let issuer_did = crate::did::DidRecord::load(crate::did::DEFAULT_DID_PATH)
        .map_err(|e| CreateCircleError::Vc(format!("load own DID: {e}")))?;
    let km = crate::vc::issue::load_runtime_key_manager(guardian_id)
        .map_err(|e| CreateCircleError::Vc(format!("load signing key: {e}")))?;
    let role = crate::vc::credential::CredentialRole::Owner;
    if let Err(e) = crate::vc::issue::issue_membership_vc_with_outcome(
        &issuer_did,
        &km,
        crate::vc::issue::IssueRequest {
            subject_did: &issuer_did.did,
            role: role.clone(),
            permissions: crate::vc::issue::default_permissions_for_role(role),
            circle_id: &circle_id,
            node_hint: Some(guardian_id.to_string()),
            duration_days: Some(policy.cert_validity_days as i64),
        },
    ) {
        // Logged loudly rather than swallowed, mirroring the same
        // best-effort precedent `cert_service.rs`'s VC issuance already
        // sets for the LAN enrollment path — but note this is no longer
        // purely cosmetic: the circle-record creation just below now
        // depends on it for a first-time registry seed, and will fail with
        // the same "local membership VC not found" error if this did.
        eprintln!("⚠️ Self-issued owner VC could not be created: {e} — some owner-only actions may need it later");
    }

    crate::circle::store::create_circle_of_kind(
        guardian_id,
        circle_id.clone(),
        circle_name.clone(),
        String::new(),
        issuer_did.did.clone(),
        crate::circle::model::CircleKind::Mesh,
    )
    .map_err(CreateCircleError::CircleStore)?;

    // ── 8. Lifecycle: CreatingCircle → CircleMember ──────────────────────
    // Not → ONLINE: that transition belongs to `activate_mesh` succeeding,
    // which only happens for real on the restart the API handler (P2.4)
    // triggers after this returns.
    crate::mesh::lifecycle::transition_to(
        crate::mesh::lifecycle::LifecycleState::CircleMember,
        None,
    )
    .map_err(CreateCircleError::Lifecycle)?;

    Ok(CreatedCircle {
        circle_id,
        circle_name,
        ca_fingerprint,
        overlay_cidr,
        overlay_ip,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_circle_ids_have_the_documented_shape() {
        let id = generate_circle_id();
        assert!(id.starts_with("circle-"));
        assert_eq!(id.len(), "circle-".len() + 12);
        for c in id.strip_prefix("circle-").unwrap().chars() {
            assert!(
                CROCKFORD_ALPHABET.contains(&(c as u8)),
                "{c} is not in the Crockford alphabet"
            );
        }
    }

    #[test]
    fn two_generated_ids_are_not_equal() {
        // Not a rigorous uniqueness proof — a cheap, fast smoke test that
        // catches the obvious "forgot to randomise" regression.
        assert_ne!(generate_circle_id(), generate_circle_id());
    }

    #[test]
    fn circle_names_reject_empty_and_overlong_and_unsafe_characters() {
        assert!(validate_circle_name("").is_err());
        assert!(validate_circle_name("   ").is_err());
        assert!(validate_circle_name(&"x".repeat(65)).is_err());
        assert!(validate_circle_name("SGX-Alpha_1 Home").is_ok());
        assert!(validate_circle_name("circle; rm -rf /").is_err());
    }

    #[test]
    fn only_slash_24_overlay_cidrs_are_accepted_today() {
        assert!(validate_overlay_cidr("192.168.100.0/24").is_ok());
        assert!(validate_overlay_cidr("10.20.0.0/16").is_err());
        assert!(validate_overlay_cidr("not-a-cidr").is_err());
    }

    #[tokio::test]
    async fn a_guardian_with_an_existing_profile_cannot_create_a_second_circle() {
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        crate::mesh::profile::install_paths(paths.clone());

        let profile = MeshProfile {
            schema_version: PROFILE_SCHEMA_VERSION,
            guardian_id: "us-hq-01".into(),
            role: MeshRole::Ca,
            circle_id: "circle-existing0001".into(),
            circle_name: "Existing".into(),
            ca_guardian_id: "us-hq-01".into(),
            ca_fingerprint: "sha256:abc".into(),
            ca_owner_did: "did:guardian:xyz".into(),
            overlay_cidr: "192.168.100.0/24".into(),
            overlay_ip: "192.168.100.1/24".into(),
            lighthouses: Vec::new(),
            rendezvous_url: None,
            enrolled_via: EnrollChannel::Created,
            enrolled_at: Utc::now().to_rfc3339(),
        };
        crate::mesh::profile::install(profile).unwrap();

        let result = create_circle(
            &paths,
            "us-hq-01",
            "New Circle".into(),
            CreateCircleOptions::default(),
        )
        .await;
        assert!(matches!(result, Err(CreateCircleError::AlreadyEnrolled)));

        crate::mesh::profile::invalidate();
    }

    #[test]
    fn cleanup_removes_stale_staging_directories_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        let stale = staging_dir(&paths).join("nebula");
        std::fs::create_dir_all(&stale).unwrap();
        std::fs::write(stale.join("marker"), b"leftover").unwrap();
        let live = live_nebula_dir(&paths);
        std::fs::create_dir_all(&live).unwrap();
        std::fs::write(live.join("untouched"), b"real").unwrap();

        cleanup_stale_staging(&paths);

        assert!(!paths.var_root.join("mesh").join("staging").read_dir()
            .map(|mut d| d.next().is_some())
            .unwrap_or(false));
        assert!(live.join("untouched").exists(), "must never touch the live tree");
    }

}
