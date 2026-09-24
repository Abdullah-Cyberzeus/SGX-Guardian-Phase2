//! Migration of pre-Phase-0 installs onto [`MeshProfile`].
//!
//! **This is the only production module allowed to contain the literal
//! `"nodeA"`.** The P0.8 guard (`tests/no_hardcoded_roles.rs`) enforces that,
//! and the reason is that the mapping has to live somewhere: a Guardian
//! installed before Phase 0 encodes its role as its name, and the first boot
//! after the upgrade is the last moment that fact is still available.
//!
//! The migration is derived from what is on disk, never from configuration:
//!
//! | On disk | Becomes |
//! |---|---|
//! | `nebula/ca/ca.key` + `ca.crt` | `role = Ca`, `ca_guardian_id = <this node>` |
//! | `nebula/nodes/<id>.crt` only  | `role = Member`, `ca_guardian_id = "nodeA"` |
//! | neither                        | no profile — the Guardian is UNENROLLED |
//!
//! It is idempotent (an existing profile is left untouched) and never
//! destructive (it only ever creates `mesh/profile.json`).

use chrono::Utc;

use super::profile::{EnrollChannel, LighthouseHint, MeshProfile, MeshRole, ProfileError,
                     PROFILE_SCHEMA_VERSION};
use crate::startup::GuardianPaths;

/// The circle every pre-Phase-0 install implicitly belonged to.
pub const LEGACY_CIRCLE_ID: &str = "guardian-circle-alpha";
/// Its display name, shown in the Phase 1 setup UI for migrated nodes.
pub const LEGACY_CIRCLE_NAME: &str = "Guardian Circle Alpha";
/// The overlay every pre-Phase-0 install implicitly used.
pub const LEGACY_OVERLAY_CIDR: &str = "192.168.100.0/24";
/// Its `/24` prefix, which is the shape the overlay registry APIs take.
pub const LEGACY_OVERLAY_PREFIX: &str = "192.168.100";
/// The name that used to mean "this Guardian is the CA".
pub const LEGACY_CA_GUARDIAN_ID: &str = "nodeA";

/// The three Guardians every pre-Phase-0 deployment consisted of, in order.
///
/// Kept only so a cohort whose `config/<node>.yaml` files predate the `ports:`
/// block keeps resolving the ports it always did. New code must not derive
/// anything from this list; see [`legacy_ports_for`].
pub const LEGACY_COHORT: [&str; 3] = ["nodeA", "nodeB", "nodeC"];

/// Default ports when no configuration supplies them (P0.7).
pub const DEFAULT_GRPC_PORT: u16 = 50051;
pub const DEFAULT_CHAT_PORT: u16 = 50251;
/// The attestation listener has always been the gRPC port plus 100.
pub const ATTESTATION_PORT_OFFSET: u16 = 100;

/// The pre-Phase-0 name-derived port map.
///
/// Ports used to be a `match` on the node's *name*, in five separate places
/// (`startup::config`, `attestation_service`, `p2p_discovery`, `client`,
/// `startup::bootstrap`). That is what made the three-node limit literal: a
/// Guardian called anything else silently collided with the CA's ports.
///
/// P0.7 moves the real answer into `NodeConfig.ports`. This map remains as the
/// fallback for config files written before that block existed, which is why it
/// lives in the legacy module: it is a compatibility shim, not a lookup table
/// new code should reach for.
///
/// Returns `(grpc, chat)`, or `None` for any id outside the legacy cohort —
/// deliberately, so a new Guardian gets the documented defaults instead of
/// inheriting a port from whichever name it happens to resemble.
pub fn legacy_ports_for(node_id: &str) -> Option<(u16, u16)> {
    match node_id {
        "nodeA" => Some((50051, 50251)),
        "nodeB" => Some((50052, 50252)),
        "nodeC" => Some((50053, 50253)),
        _ => None,
    }
}

/// The legacy cohort's gRPC ports, for the first-boot config generator.
pub fn legacy_default_node_ports() -> [(&'static str, u16); 3] {
    [("nodeA", 50051), ("nodeB", 50052), ("nodeC", 50053)]
}

/// Host port and container address of a legacy dev-cohort container.
///
/// `docker-compose.dev.yml` and `optional/container-cohort/` run the three
/// named Guardians on one host with name-derived published ports. That mapping
/// is fixture data about those specific containers, so it lives here rather
/// than in the API handlers, where it read as a rule about Guardians in general.
///
/// Returns `(host_port_env_key, default_host_port, container_overlay_url)`, or
/// `None` for any Guardian that is not part of that dev cohort.
pub fn dev_cohort_container(node_id: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match node_id {
        "nodeA" => Some(("NODEA_REST_PORT", "18443", "http://172.31.250.10:8443")),
        "nodeB" => Some(("NODEB_REST_PORT", "28443", "http://172.31.250.11:8443")),
        "nodeC" => Some(("NODEC_REST_PORT", "38443", "http://172.31.250.12:8443")),
        _ => None,
    }
}

/// The legacy cohort member that held the `n`th overlay address, used to map a
/// dev-cohort container URL back to a Guardian id.
pub fn dev_cohort_member_at_overlay_host(host: u8) -> Option<&'static str> {
    LEGACY_COHORT.get(host.checked_sub(1)? as usize).copied()
}

/// What [`migrate_if_needed`] did, for logging and for the Phase 1 lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationOutcome {
    /// A profile already existed; nothing was written.
    AlreadyMigrated,
    /// A profile was synthesised from on-disk Nebula material.
    Migrated(Box<MeshProfile>),
    /// No CA key and no member certificate — a fresh, unenrolled Guardian.
    NothingToMigrate,
}

fn read_ca_fingerprint(nebula_base: &std::path::Path) -> String {
    // Reuses the existing helper so the migrated pin is byte-identical to the
    // fingerprint the daemon already prints and compares at boot.
    crate::nebula::ca::NebulaCA::ca_fingerprint(&nebula_base.display().to_string())
        .unwrap_or_default()
}

/// Recovers this Guardian's overlay address from the certificate it already
/// holds, so the migrated profile agrees with what Nebula is actually running.
///
/// Returns an empty string when the certificate cannot be read — `overlay_ip`
/// is optional in the profile, and a migration must never fail because
/// `nebula-cert` is momentarily unavailable.
fn read_overlay_ip(nebula_base: &std::path::Path, guardian_id: &str) -> String {
    let cert = nebula_base.join("nodes").join(format!("{guardian_id}.crt"));
    if !cert.exists() {
        return String::new();
    }
    crate::startup::nebula_cert::read_ip_from_nebula_cert(
        &nebula_base.display().to_string(),
        guardian_id,
    )
    .unwrap_or_default()
}

/// Pulls the lighthouse hints out of the registry the legacy bootstrap synced.
fn read_lighthouses(nebula_base: &std::path::Path) -> Vec<LighthouseHint> {
    let path = nebula_base.join("lighthouse_registry.json");
    let Ok(registry) =
        crate::nebula::lighthouse::LighthouseRegistry::load(&path.display().to_string())
    else {
        return Vec::new();
    };
    // `static_host_map_entries` already pairs each lighthouse's overlay IP with
    // its routable endpoint, which is exactly the shape of a `LighthouseHint`.
    registry
        .static_host_map_entries()
        .into_iter()
        .map(|(overlay_ip, endpoint)| LighthouseHint {
            overlay_ip,
            endpoints: if endpoint.is_empty() {
                Vec::new()
            } else {
                vec![endpoint]
            },
        })
        .collect()
}

/// Derives a [`MeshProfile`] from a pre-Phase-0 install, or `None` when there
/// is nothing to derive one from.
///
/// Pure with respect to the profile file: it reads Nebula material and returns
/// a value. [`migrate_if_needed`] is the part that writes.
pub fn derive_profile(paths: &GuardianPaths, guardian_id: &str) -> Option<MeshProfile> {
    let nebula_base = paths.var_root.join("nebula");
    let ca_key = nebula_base.join("ca").join("ca.key");
    let ca_crt = nebula_base.join("ca").join("ca.crt");
    let member_crt = nebula_base.join("nodes").join(format!("{guardian_id}.crt"));

    // Holding the CA private key is what made a node the CA before Phase 0 —
    // a far better signal than the name, and it stays true for a CA that was
    // renamed. The name is only the fallback for members (below), which have
    // no local evidence of who signed for them beyond the convention.
    let is_ca = ca_key.exists() && ca_crt.exists();
    if !is_ca && !member_crt.exists() {
        return None;
    }

    let role = if is_ca { MeshRole::Ca } else { MeshRole::Member };
    let ca_guardian_id = if is_ca {
        guardian_id.to_string()
    } else {
        LEGACY_CA_GUARDIAN_ID.to_string()
    };

    Some(MeshProfile {
        schema_version: PROFILE_SCHEMA_VERSION,
        guardian_id: guardian_id.to_string(),
        role,
        circle_id: LEGACY_CIRCLE_ID.to_string(),
        circle_name: LEGACY_CIRCLE_NAME.to_string(),
        ca_guardian_id,
        ca_fingerprint: read_ca_fingerprint(&nebula_base),
        // Legacy installs never published a CA DID, so the descriptor pin of
        // §4.5 is empty here. Phase 3 fills it on the first descriptor fetch;
        // until then the migrated node keeps trusting the CA cert it already
        // installed, which is exactly its pre-migration trust position.
        ca_owner_did: String::new(),
        overlay_cidr: LEGACY_OVERLAY_CIDR.to_string(),
        overlay_ip: read_overlay_ip(&nebula_base, guardian_id),
        lighthouses: read_lighthouses(&nebula_base),
        rendezvous_url: None,
        enrolled_via: EnrollChannel::LegacyMigration,
        enrolled_at: Utc::now().to_rfc3339(),
    })
}

/// Ensures a profile exists, synthesising one from a legacy install if needed.
///
/// Idempotent: a Guardian that already has a profile is returned
/// [`MigrationOutcome::AlreadyMigrated`] without the file being touched.
pub fn migrate_if_needed(
    paths: &GuardianPaths,
    guardian_id: &str,
) -> Result<MigrationOutcome, ProfileError> {
    if MeshProfile::load(paths)?.is_some() {
        return Ok(MigrationOutcome::AlreadyMigrated);
    }

    let Some(profile) = derive_profile(paths, guardian_id) else {
        return Ok(MigrationOutcome::NothingToMigrate);
    };

    profile.save(paths)?;
    Ok(MigrationOutcome::Migrated(Box::new(profile)))
}

/// Boot entry point: migrate if needed, then load the profile into the
/// process-wide cache. Returns the profile, or `None` if unenrolled.
pub fn migrate_and_initialize(
    paths: &GuardianPaths,
    guardian_id: &str,
) -> Result<Option<std::sync::Arc<MeshProfile>>, ProfileError> {
    super::profile::install_paths(paths.clone());
    match migrate_if_needed(paths, guardian_id)? {
        MigrationOutcome::Migrated(profile) => {
            tracing::info!(
                guardian_id,
                role = ?profile.role,
                circle_id = %profile.circle_id,
                "migrated a pre-Phase-0 install onto a mesh profile"
            );
        }
        MigrationOutcome::AlreadyMigrated => {}
        MigrationOutcome::NothingToMigrate => {
            tracing::info!(guardian_id, "no mesh profile and no legacy material — unenrolled");
        }
    }
    super::profile::initialize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: std::path::PathBuf, body: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn make_ca_node(paths: &GuardianPaths) {
        let nebula = paths.var_root.join("nebula");
        write(nebula.join("ca/ca.key"), "CA KEY");
        write(nebula.join("ca/ca.crt"), "CA CERT");
    }

    fn make_member_node(paths: &GuardianPaths, id: &str) {
        let nebula = paths.var_root.join("nebula");
        write(nebula.join("ca/ca.crt"), "CA CERT");
        write(nebula.join(format!("nodes/{id}.crt")), "MEMBER CERT");
    }

    #[test]
    fn a_legacy_ca_node_migrates_to_the_ca_role() {
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        make_ca_node(&paths);

        let profile = derive_profile(&paths, "nodeA").expect("a CA node must migrate");
        assert_eq!(profile.role, MeshRole::Ca);
        assert_eq!(profile.ca_guardian_id, "nodeA");
        assert_eq!(profile.circle_id, LEGACY_CIRCLE_ID);
        assert_eq!(profile.enrolled_via, EnrollChannel::LegacyMigration);
        profile.validate().unwrap();
    }

    #[test]
    fn a_renamed_ca_migrates_on_the_key_it_holds_not_on_its_name() {
        // The whole point of B3: holding ca.key is what makes a Guardian the CA.
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        make_ca_node(&paths);

        let profile = derive_profile(&paths, "us-hq-01").unwrap();
        assert_eq!(profile.role, MeshRole::Ca);
        assert_eq!(profile.ca_guardian_id, "us-hq-01");
    }

    #[test]
    fn a_legacy_member_migrates_to_the_member_role_pointing_at_node_a() {
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        make_member_node(&paths, "nodeB");

        let profile = derive_profile(&paths, "nodeB").unwrap();
        assert_eq!(profile.role, MeshRole::Member);
        assert_eq!(profile.ca_guardian_id, LEGACY_CA_GUARDIAN_ID);
        profile.validate().unwrap();
    }

    #[test]
    fn a_fresh_guardian_has_nothing_to_migrate() {
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        assert!(derive_profile(&paths, "edge-7").is_none());
        assert_eq!(
            migrate_if_needed(&paths, "edge-7").unwrap(),
            MigrationOutcome::NothingToMigrate
        );
        assert!(MeshProfile::load(&paths).unwrap().is_none());
    }

    #[test]
    fn migration_is_idempotent_and_never_overwrites_an_existing_profile() {
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        make_ca_node(&paths);

        let first = migrate_if_needed(&paths, "nodeA").unwrap();
        assert!(matches!(first, MigrationOutcome::Migrated(_)));
        let after_first = MeshProfile::load(&paths).unwrap().unwrap();

        // A second boot — and a third, with a different id, simulating a rename
        // after migration. Neither may rewrite the profile.
        assert_eq!(
            migrate_if_needed(&paths, "nodeA").unwrap(),
            MigrationOutcome::AlreadyMigrated
        );
        assert_eq!(
            migrate_if_needed(&paths, "renamed-later").unwrap(),
            MigrationOutcome::AlreadyMigrated
        );
        assert_eq!(MeshProfile::load(&paths).unwrap().unwrap(), after_first);
    }

    #[test]
    fn migration_does_not_delete_or_modify_legacy_nebula_material() {
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        make_ca_node(&paths);
        let nebula = paths.var_root.join("nebula");

        migrate_if_needed(&paths, "nodeA").unwrap();

        assert_eq!(std::fs::read_to_string(nebula.join("ca/ca.key")).unwrap(), "CA KEY");
        assert_eq!(std::fs::read_to_string(nebula.join("ca/ca.crt")).unwrap(), "CA CERT");
    }

    #[test]
    fn a_member_whose_cert_is_for_another_guardian_is_not_migrated() {
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        make_member_node(&paths, "nodeB");

        // nodeC has a CA cert on disk but no certificate of its own: it never
        // completed enrollment, so it must come up UNENROLLED rather than
        // claiming membership it cannot prove.
        assert!(derive_profile(&paths, "nodeC").is_none());
    }
}
