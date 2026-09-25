//! The "who am I, in which circle" layer.
//!
//! Phase 0 lands the foundation: a persisted [`profile::MeshProfile`] that
//! replaces the name-based role checks (role by node name), the constant
//! circle id and the constant overlay
//! (`192.168.100.0/24`) that together pinned the product to three nodes, one
//! circle and one CA.
//!
//! Later phases add `lifecycle`, `activation`, `ca/`, `enroll/`, `discovery/`
//! and `joincode` alongside these; see
//! `docs/Guardian_Mesh_Enrollment_Complete_Plan.md` §4.1.

pub mod activation;
pub mod ca;
pub mod discovery;
pub mod enroll;
pub mod legacy;
pub mod lifecycle;
pub mod profile;

pub use profile::{is_ca, MeshProfile, MeshRole};

/// Where a fresh unit's generated id is persisted (P1.9), so it survives
/// restarts without needing a DID to already exist.
const FRESH_ID_MARKER: &str = "/var/lib/sgx-guardian/.guardian_id";

/// Resolves the id for a Guardian launched with no CLI argument.
///
/// The plan's own language ("derive `gx-<first 8 of DID hash>`") assumes a
/// DID already exists, but DID creation itself is keyed by `node_id` from the
/// very first lines of `main()` — KeyManager file paths, PCR baseline paths,
/// and the DID method's own storage are all `device_<node_id>.*`. Deriving
/// the id *from* the DID would mean generating keys and a DID under one id,
/// then relocating every one of those files to a new id, which is real
/// migration surgery main() does not do today.
///
/// This is the stopgap the plan explicitly anticipates ("let the operator
/// rename it in SU01 before enrollment" — i.e. this id was always meant to be
/// disposable): generate a random id once, persist it so it is stable across
/// restarts, and never derive it from — or default it to — a fixed name. That
/// keeps the one safety property `main.rs`'s CLI parsing already enforces
/// intact: an unconfigured Guardian must never silently become the CA by
/// sharing a name with one.
pub fn fresh_guardian_id() -> String {
    if let Ok(existing) = std::fs::read_to_string(FRESH_ID_MARKER) {
        let existing = existing.trim();
        if !existing.is_empty() {
            return existing.to_string();
        }
    }

    let bytes: [u8; 4] = rand::random();
    let id = format!("gx-{}", hex::encode(bytes));

    if let Some(dir) = std::path::Path::new(FRESH_ID_MARKER).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Err(e) = std::fs::write(FRESH_ID_MARKER, &id) {
        eprintln!(
            "⚠️ Could not persist generated Guardian id to {FRESH_ID_MARKER}: {e} —              a new id will be generated on every restart until this is writable"
        );
    }
    id
}

/// This Guardian's own id.
///
/// Prefers the mesh profile, then the CLI argument the daemon was launched
/// with, and only then the pre-Phase-0 default. Call sites used to spell that
/// default inline as a bare string, which is why a Guardian launched without an
/// argument silently believed it was the CA.
pub fn local_guardian_id() -> String {
    profile::guardian_id()
        .ok()
        .or_else(|| std::env::args().nth(1).filter(|id| !id.is_empty()))
        .unwrap_or_else(|| legacy::LEGACY_CA_GUARDIAN_ID.to_string())
}

/// The id of the Guardian that signs for this circle.
///
/// Replaces the many lookups that asked registries and config for the entry
/// named after the pre-Phase-0 CA. Falls back to that name so a legacy cohort
/// that has not yet written a profile keeps resolving exactly as before.
pub fn ca_guardian_id() -> String {
    profile::ca_guardian_id_or(legacy::LEGACY_CA_GUARDIAN_ID)
}

/// This circle's id, falling back to the pre-Phase-0 constant.
pub fn circle_id() -> String {
    profile::circle_id_or(legacy::LEGACY_CIRCLE_ID)
}

/// This circle's overlay `/24` prefix, falling back to the pre-Phase-0 constant.
pub fn overlay_prefix() -> String {
    profile::overlay_prefix_or(legacy::LEGACY_OVERLAY_PREFIX)
}

/// This circle's full overlay CIDR, falling back to the pre-Phase-0 constant.
///
/// For call sites (allow-lists, subnet defaults) that want the whole
/// `a.b.c.0/24` rather than just the host-address helpers above.
pub fn overlay_cidr_or_default() -> String {
    profile::current()
        .map(|p| p.overlay_cidr.clone())
        .unwrap_or_else(|| legacy::LEGACY_OVERLAY_CIDR.to_string())
}

/// The `host`th address in this circle's overlay, e.g. `192.168.100.1`.
///
/// The well-known hosts were written out as literals all over the codebase
/// (`.1` for the CA, `.10` for the VPS lighthouse, `.2` for the first member),
/// which silently assumed one fixed subnet for every deployment. Deriving them
/// from the profile keeps the same addresses for a migrated circle while
/// letting a new circle choose its own range.
pub fn overlay_host(host: u8) -> String {
    format!("{}.{}", overlay_prefix(), host)
}

/// [`overlay_host`] with the circle's prefix length appended, e.g.
/// `192.168.100.2/24`.
pub fn overlay_host_cidr(host: u8) -> String {
    let len = profile::current()
        .and_then(|p| p.overlay_cidr.split('/').nth(1).map(|s| s.to_string()))
        .unwrap_or_else(|| "24".to_string());
    format!("{}/{}", overlay_host(host), len)
}
