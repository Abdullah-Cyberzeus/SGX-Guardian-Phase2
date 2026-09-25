//! P4.6 — validates a [`SignedEnrollmentBundle`] (§5.3: "tampering any
//! bundle field makes B reject it") and installs it: the CA cert, this
//! Guardian's own signed member cert, its membership VC, and a
//! `MeshProfile{role: Member}`.
//!
//! Deliberately **not** the staged-directory-then-rename pattern
//! `mesh::ca::create_circle` uses — that pattern exists to make a
//! multi-file *CA* tree (a whole new `ca/` + `nodes/` + registry) commit
//! atomically. A joiner's `nebula/` directory holds at most its own
//! already-generated keypair before this runs (nothing else can exist yet:
//! `MeshProfile` — the thing that would make this Guardian look
//! enrolled — is the very last thing this function writes), so a crash
//! mid-install just leaves the cert files present without a profile, which
//! a retry (the same bundle, re-fetched from the persisted `request_id`)
//! overwrites with identical content. There is no partial *other* state to
//! protect against the way there was for a brand-new CA tree.

use crate::mesh::ca::bundle::{BundleError, SignedEnrollmentBundle};
use crate::mesh::profile::{EnrollChannel, MeshProfile, MeshRole, PROFILE_SCHEMA_VERSION};
use crate::startup::GuardianPaths;
use chrono::Utc;
use std::fs;

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("bundle failed verification — not installing: {0}")]
    Verify(#[from] BundleError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("could not save the membership credential: {0}")]
    Vc(String),
    #[error("could not install the mesh profile: {0}")]
    Profile(#[from] crate::mesh::profile::ProfileError),
}

pub fn install(
    paths: &GuardianPaths,
    guardian_id: &str,
    signed: &SignedEnrollmentBundle,
) -> Result<(), InstallError> {
    signed.verify()?;
    let bundle = &signed.bundle;

    let nebula_dir = paths.var_root.join("nebula");
    fs::create_dir_all(nebula_dir.join("ca"))?;
    fs::create_dir_all(nebula_dir.join("nodes"))?;
    fs::write(nebula_dir.join("ca").join("ca.crt"), &bundle.ca_cert_pem)?;
    fs::write(
        nebula_dir.join("nodes").join(format!("{guardian_id}.crt")),
        &bundle.member_cert_pem,
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(
            nebula_dir.join("ca").join("ca.crt"),
            fs::Permissions::from_mode(0o644),
        );
        let _ = fs::set_permissions(
            nebula_dir.join("nodes").join(format!("{guardian_id}.crt")),
            fs::Permissions::from_mode(0o644),
        );
    }

    crate::vc::persistence::save_own(&bundle.member_vc)
        .map_err(|e| InstallError::Vc(e.to_string()))?;

    // Without this, the local circle registry has no record of this circle
    // at all yet, and the first thing to read it (`circle::store::load_or_seed_unlocked`)
    // falls back to seeding a generic placeholder ("Mesh Circle" / a stock
    // description) — the same gap `mesh::ca::create_circle` already had to
    // route around (P2's `load_registry_or_empty`) for the CA's own record.
    // A member needs its own copy of the real `Circle{kind: Mesh}` too, with
    // the operator-chosen name the bundle actually carries.
    // Best-effort: a failure here leaves the cosmetic "Mesh Circle"
    // placeholder in place but must not block the rest of installation —
    // Nebula connectivity (the load-bearing part of joining) does not
    // depend on this local registry entry at all.
    if let Err(e) = crate::circle::store::create_circle_of_kind(
        guardian_id,
        bundle.circle_id.clone(),
        bundle.circle_name.clone(),
        String::new(),
        signed.ca_did_document.id.clone(),
        crate::circle::model::CircleKind::Mesh,
    ) {
        eprintln!("⚠️ Could not create the local Circle record for {}: {e} — the UI may show a placeholder name until this is retried", bundle.circle_name);
    }

    let mesh_profile = MeshProfile {
        schema_version: PROFILE_SCHEMA_VERSION,
        guardian_id: guardian_id.to_string(),
        role: MeshRole::Member,
        circle_id: bundle.circle_id.clone(),
        circle_name: bundle.circle_name.clone(),
        ca_guardian_id: bundle.ca_guardian_id.clone(),
        ca_fingerprint: bundle.ca_fingerprint.clone(),
        ca_owner_did: signed.ca_did_document.id.clone(),
        overlay_cidr: bundle.overlay_cidr.clone(),
        overlay_ip: bundle.overlay_ip.clone(),
        lighthouses: Vec::new(),
        rendezvous_url: None,
        enrolled_via: EnrollChannel::Lan,
        enrolled_at: Utc::now().to_rfc3339(),
    };
    crate::mesh::profile::install(mesh_profile)?;

    // Mirrors `mesh::ca::create_circle`'s own final step exactly, including
    // the reason: `activate_mesh` (the thing that actually brings the
    // Nebula tunnel up with this new cert) only ever runs from `main()`'s
    // own stack frame — there is no live path into it from here either.
    // This transition just records that installation succeeded; the
    // caller orchestrating the join (the `/api/v1/mesh/join` handler) is
    // what schedules the restart afterward, same as circle creation's
    // handler does.
    let _ = crate::mesh::lifecycle::transition_to(
        crate::mesh::lifecycle::LifecycleState::CircleMember,
        None,
    );

    Ok(())
}
