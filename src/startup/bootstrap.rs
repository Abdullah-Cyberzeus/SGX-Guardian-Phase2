//! First-boot filesystem bootstrapping: required directories, default node
//! configs, the default policy schema, and pruning of stale Nebula approval
//! requests.
//!
//! Every function takes the [`GuardianPaths`] it should operate on so the
//! whole sequence is exercisable against a tempdir.

use super::GuardianPaths;
use std::path::{Path, PathBuf};

/// Directories the daemon requires before any subsystem starts, expressed
/// relative to their owning root.
pub const ETC_DIRECTORIES: [&str; 4] = ["config", "schemas", "policies", "threat"];
pub const VAR_DIRECTORIES: [&str; 9] = [
    "keys",
    "pcr",
    "boot",
    "sgx-agent",
    "identity",
    "identity/peers",
    "nebula/ca",
    "nebula/nodes",
    "nebula/requests",
];

/// The byte-identical default policy schema shipped with every node.
///
/// This string must stay byte-identical across builds: the same binary on
/// every board yields the same canonical digest, which is what lets a fresh
/// cohort attest to each other before any operator policy is pushed.
pub const DEFAULT_POLICY_SCHEMA: &str = "---\npolicy_id: \"123e4567-e89b-12d3-a456-426614174000\"\nversion: \"1.0.0\"\ndescription: \"Default Guardian Edge Policy\"\nrules:\n  - id: \"rule-001\"\n    action: \"ALLOW\"\n    src: \"10.0.0.0/24\"\n    dst: \"0.0.0.0/0\"\n    protocol: \"TCP\"\n    port: 443\n  - id: \"rule-005\"\n    action: \"DENY\"\n    src: \"0.0.0.0/0\"\n    dst: \"10.0.0.10\"\n    protocol: \"UDP\"\n";

/// Node ids the daemon ships default configuration for, with their gRPC port.
pub const DEFAULT_NODE_PORTS: [(&str, u16); 3] =
    [("nodeA", 50051), ("nodeB", 50052), ("nodeC", 50053)];

/// Every absolute directory that must exist before startup continues.
pub fn required_directories(paths: &GuardianPaths) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = ETC_DIRECTORIES
        .iter()
        .map(|dir| paths.etc_root.join(dir))
        .collect();
    dirs.extend(VAR_DIRECTORIES.iter().map(|dir| paths.var_root.join(dir)));
    dirs.push(paths.log_root.clone());
    dirs
}

/// Creates every required directory, returning the ones that could not be
/// created together with the reason. Startup continues on failure — a missing
/// directory surfaces later as a specific subsystem error rather than an
/// opaque boot abort.
pub fn ensure_directories(paths: &GuardianPaths) -> Vec<(PathBuf, String)> {
    let mut failures = Vec::new();
    for dir in required_directories(paths) {
        if let Err(error) = std::fs::create_dir_all(&dir) {
            failures.push((dir, error.to_string()));
        }
    }
    failures
}

/// The default per-node YAML written on first boot when no config exists.
pub fn default_node_config_yaml(node_id: &str, port: u16) -> String {
    let letter = node_id.strip_prefix("node").unwrap_or(node_id);
    let lan_fqdn = crate::lan_name::fqdn(node_id);
    format!(
        "---\nnode_id: \"{node_id}\"\nhostname: \"{lan_fqdn}\"\nip: \"0.0.0.0\"\nport: {port}\npublic_key: \"placeholder-key-{letter}\"\n\napi:\n  tls:\n    enabled: true\n    require_https: true\n\nrelay:\n  enabled: false\n  max_peers: 5\n  max_bandwidth_mbps: 10\n  alert_threshold_pct: 80\n\nsecure_element:\n  enabled: true\n  scp_key_path: \"/home/root/se05x_mw_v04.05.01/simw-top/scripts/se050F_scp_keys.txt\"\n  interface: \"t1oi2c\"\n  auth_type: \"PlatformSCP\"\n  connection_type: \"se05x\"\n"
    )
}

/// Writes default configs for any node whose config file is absent and keeps
/// the `<etc>/<node>.yaml` mirror in sync. Returns the node ids that were
/// newly created.
pub fn ensure_default_node_configs(paths: &GuardianPaths) -> Vec<String> {
    let mut created = Vec::new();
    for (node_id, port) in DEFAULT_NODE_PORTS {
        let config_path = paths.node_config(node_id);
        if !config_path.exists() {
            if let Some(parent) = config_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if std::fs::write(&config_path, default_node_config_yaml(node_id, port)).is_ok() {
                created.push(node_id.to_string());
            }
        }
        let mirror_path = paths.node_config_mirror(node_id);
        if !mirror_path.exists() && config_path.exists() {
            let _ = std::fs::copy(&config_path, &mirror_path);
        }
    }
    created
}

/// Writes [`DEFAULT_POLICY_SCHEMA`] when no schema is present.
/// Returns `true` when a schema was created by this call.
pub fn ensure_default_policy_schema(paths: &GuardianPaths) -> bool {
    let schema_path = paths.policy_schema();
    if schema_path.exists() {
        return false;
    }
    if let Some(parent) = schema_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&schema_path, DEFAULT_POLICY_SCHEMA).is_ok()
}

/// The canonical digest of the active schema, which operators compare across
/// boards. `None` means the schema is missing or invalid, in which case
/// attestation falls back to the constant default digest.
pub fn schema_canonical_digest(paths: &GuardianPaths) -> Option<String> {
    let yaml = std::fs::read_to_string(paths.policy_schema()).ok()?;
    digest_of_policy_yaml(&yaml)
}

/// The canonical digest of a policy YAML document.
pub fn digest_of_policy_yaml(yaml: &str) -> Option<String> {
    use sha2::Digest;
    let parsed = crate::policy::validate_policy(yaml).ok()?;
    let canonical = crate::policy::canonical_policy_bytes(&parsed);
    Some(hex::encode(sha2::Sha256::digest(&canonical)))
}

/// Fields every Nebula approval request YAML must carry to be readable by the
/// current binary.
const REQUIRED_APPROVAL_FIELDS: [&str; 5] = [
    "node_id",
    "requested_at",
    "overlay_ip",
    "public_key_fingerprint",
    "approve",
];

/// Approval verdicts the current schema understands. Anything else (including
/// `approve: true`, which an older binary wrote before approval became a role
/// name) belongs to a previous format.
const KNOWN_APPROVAL_VERDICTS: [&str; 8] = [
    "false",
    "member",
    "lighthouse",
    "relay",
    "lh_relay",
    "reject",
    "no",
    "lh",
];

/// Whether an approval request YAML matches the schema this binary reads.
///
/// Incompatible files are removed rather than repaired: a half-understood
/// approval could otherwise grant an unintended overlay role.
pub fn approval_request_is_compatible(content: &str) -> bool {
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(content) else {
        return false;
    };
    let Some(mapping) = value.as_mapping() else {
        return false;
    };
    let has_required = REQUIRED_APPROVAL_FIELDS
        .iter()
        .all(|key| mapping.contains_key(serde_yaml::Value::String((*key).to_string())));
    if !has_required {
        return false;
    }
    match mapping.get(serde_yaml::Value::String("approve".to_string())) {
        Some(serde_yaml::Value::String(verdict)) => {
            KNOWN_APPROVAL_VERDICTS.contains(&verdict.as_str())
        }
        Some(serde_yaml::Value::Bool(approved)) => !approved,
        _ => false,
    }
}

/// Deletes approval request YAMLs written by an incompatible binary version.
/// Returns the file names that were removed. Only `nodeA` (the CA) runs this.
pub fn prune_incompatible_approvals(dir: &Path) -> Vec<String> {
    let mut removed = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return removed;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.ends_with(".yaml") {
            continue;
        }
        let compatible = std::fs::read_to_string(&path)
            .map(|content| approval_request_is_compatible(&content))
            .unwrap_or(false);
        if !compatible {
            let name = name.to_string();
            if std::fs::remove_file(&path).is_ok() {
                removed.push(name);
            }
        }
    }
    removed.sort();
    removed
}

/// Runs the whole first-boot bootstrap sequence for `node_id`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BootstrapReport {
    pub directory_failures: Vec<PathBuf>,
    pub created_configs: Vec<String>,
    pub created_schema: bool,
    pub pruned_approvals: Vec<String>,
    pub schema_digest: Option<String>,
}

/// `is_ca` gates the approval pruning step, which only the CA node performs.
pub fn bootstrap_filesystem(paths: &GuardianPaths, is_ca: bool) -> BootstrapReport {
    let directory_failures = ensure_directories(paths)
        .into_iter()
        .map(|(path, _)| path)
        .collect();
    let pruned_approvals = if is_ca {
        prune_incompatible_approvals(&paths.nebula_requests())
    } else {
        Vec::new()
    };
    let created_configs = ensure_default_node_configs(paths);
    let created_schema = ensure_default_policy_schema(paths);
    let schema_digest = schema_canonical_digest(paths);
    BootstrapReport {
        directory_failures,
        created_configs,
        created_schema,
        pruned_approvals,
        schema_digest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox() -> (tempfile::TempDir, GuardianPaths) {
        let temp = tempfile::tempdir().expect("create sandbox root");
        let paths = GuardianPaths::rooted_at(temp.path());
        (temp, paths)
    }

    #[test]
    fn required_directories_cover_every_root() {
        let paths = GuardianPaths::rooted_at("/base");
        let dirs = required_directories(&paths);
        assert_eq!(
            dirs.len(),
            ETC_DIRECTORIES.len() + VAR_DIRECTORIES.len() + 1
        );
        assert!(dirs.contains(&PathBuf::from("/base/etc/sgx-guardian/policies")));
        assert!(dirs.contains(&PathBuf::from("/base/var/lib/sgx-guardian/identity/peers")));
        assert!(dirs.contains(&PathBuf::from("/base/var/lib/sgx-guardian/nebula/requests")));
        assert!(dirs.contains(&PathBuf::from("/base/var/log/sgx-guardian")));
    }

    #[test]
    fn ensure_directories_creates_everything_and_is_idempotent() {
        let (_temp, paths) = sandbox();

        assert!(ensure_directories(&paths).is_empty());
        for dir in required_directories(&paths) {
            assert!(dir.is_dir(), "{} should exist", dir.display());
        }
        assert!(
            ensure_directories(&paths).is_empty(),
            "a second run must be a no-op"
        );
    }

    #[test]
    fn ensure_directories_reports_paths_blocked_by_an_existing_file() {
        let (temp, paths) = sandbox();
        // A regular file where a directory belongs makes create_dir_all fail.
        std::fs::create_dir_all(temp.path().join("etc")).expect("create etc");
        std::fs::write(temp.path().join("etc/sgx-guardian"), b"not a directory")
            .expect("write blocking file");

        let failures = ensure_directories(&paths);

        assert!(
            failures
                .iter()
                .any(|(path, _)| path.starts_with(&paths.etc_root)),
            "etc directories should be reported as failures: {failures:?}"
        );
        assert!(
            failures.iter().all(|(_, reason)| !reason.is_empty()),
            "each failure should carry a reason"
        );
    }

    #[test]
    fn default_node_config_yaml_is_valid_and_node_specific() {
        for (node_id, port) in DEFAULT_NODE_PORTS {
            let yaml = default_node_config_yaml(node_id, port);
            let parsed: crate::config_loader::NodeConfig =
                serde_yaml::from_str(&yaml).expect("default config must parse");
            assert_eq!(parsed.node_id, node_id);
            assert_eq!(parsed.port, port);
            assert_eq!(parsed.hostname, crate::lan_name::fqdn(node_id));
            assert_eq!(parsed.ip, "0.0.0.0");
            let api = parsed.api_or_default();
            assert!(api.tls.enabled);
            assert!(api.tls.require_https);
            let relay = parsed.relay_or_default();
            assert!(!relay.enabled);
            assert_eq!(relay.max_peers, 5);
        }
    }

    #[test]
    fn default_node_config_yaml_handles_ids_without_the_node_prefix() {
        let yaml = default_node_config_yaml("edge-7", 50060);
        assert!(yaml.contains("placeholder-key-edge-7"), "{yaml}");
        assert!(yaml.contains("node_id: \"edge-7\""), "{yaml}");
    }

    #[test]
    fn ensure_default_node_configs_writes_missing_files_and_mirrors_them() {
        let (_temp, paths) = sandbox();
        ensure_directories(&paths);

        let created = ensure_default_node_configs(&paths);

        assert_eq!(created, vec!["nodeA", "nodeB", "nodeC"]);
        for (node_id, _) in DEFAULT_NODE_PORTS {
            assert!(paths.node_config(node_id).is_file());
            assert!(paths.node_config_mirror(node_id).is_file());
        }
        assert!(
            ensure_default_node_configs(&paths).is_empty(),
            "existing configs must not be rewritten"
        );
    }

    #[test]
    fn ensure_default_node_configs_preserves_operator_edits() {
        let (_temp, paths) = sandbox();
        ensure_directories(&paths);
        let config_path = paths.node_config("nodeA");
        std::fs::write(&config_path, "operator: edited").expect("seed operator config");

        let created = ensure_default_node_configs(&paths);

        assert_eq!(created, vec!["nodeB", "nodeC"]);
        assert_eq!(
            std::fs::read_to_string(&config_path).expect("read config"),
            "operator: edited"
        );
        assert_eq!(
            std::fs::read_to_string(paths.node_config_mirror("nodeA")).expect("read mirror"),
            "operator: edited",
            "the mirror is seeded from whatever the dynamic config holds"
        );
    }

    #[test]
    fn default_policy_schema_is_written_once_and_hashes_consistently() {
        let (_temp, paths) = sandbox();
        ensure_directories(&paths);

        assert!(ensure_default_policy_schema(&paths));
        assert!(
            !ensure_default_policy_schema(&paths),
            "an existing schema must be left alone"
        );

        let digest = schema_canonical_digest(&paths).expect("default schema must be valid");
        assert_eq!(digest.len(), 64);
        assert_eq!(
            digest,
            digest_of_policy_yaml(DEFAULT_POLICY_SCHEMA).expect("constant is valid"),
            "the on-disk schema must hash to the shipped constant"
        );
    }

    #[test]
    fn schema_digest_is_none_for_missing_or_invalid_schemas() {
        let (_temp, paths) = sandbox();
        assert!(schema_canonical_digest(&paths).is_none(), "missing schema");

        ensure_directories(&paths);
        std::fs::write(paths.policy_schema(), "rules: [ this is not a policy").expect("write");
        assert!(schema_canonical_digest(&paths).is_none(), "invalid schema");

        assert!(digest_of_policy_yaml("").is_none());
    }

    #[test]
    fn approval_requests_are_compatible_only_with_the_current_schema() {
        let complete = |approve: &str| {
            format!(
                "node_id: nodeB\nrequested_at: 2026-01-01T00:00:00Z\noverlay_ip: 192.168.100.5/24\npublic_key_fingerprint: abc123\napprove: {approve}\n"
            )
        };

        for verdict in KNOWN_APPROVAL_VERDICTS {
            assert!(
                approval_request_is_compatible(&complete(verdict)),
                "{verdict} is a known verdict"
            );
        }
        assert!(
            approval_request_is_compatible(&complete("false")),
            "an unapproved boolean-shaped request stays readable"
        );
        assert!(
            !approval_request_is_compatible(&complete("true")),
            "approve: true is the pre-role format"
        );
        assert!(
            !approval_request_is_compatible(&complete("supervisor")),
            "unknown verdicts are not understood"
        );
        assert!(
            !approval_request_is_compatible(&complete("42")),
            "non-string, non-bool verdicts are not understood"
        );
        assert!(
            !approval_request_is_compatible(
                "node_id: nodeB\nrequested_at: 2026-01-01T00:00:00Z\napprove: member\n"
            ),
            "missing required fields"
        );
        assert!(
            !approval_request_is_compatible("- just\n- a\n- sequence\n"),
            "a non-mapping document"
        );
        assert!(
            !approval_request_is_compatible("key: [unterminated"),
            "unparseable YAML"
        );
    }

    #[test]
    fn prune_removes_only_incompatible_yaml_files() {
        let temp = tempfile::tempdir().expect("create requests dir");
        let dir = temp.path();
        let compatible = "node_id: nodeB\nrequested_at: 2026-01-01T00:00:00Z\noverlay_ip: 192.168.100.5/24\npublic_key_fingerprint: abc123\napprove: member\n";
        std::fs::write(dir.join("keep.yaml"), compatible).expect("write");
        std::fs::write(dir.join("stale.yaml"), "approve: true\n").expect("write");
        std::fs::write(dir.join("broken.yaml"), "key: [unterminated").expect("write");
        std::fs::write(dir.join("notes.txt"), "approve: true\n").expect("write");

        let removed = prune_incompatible_approvals(dir);

        assert_eq!(removed, vec!["broken.yaml", "stale.yaml"]);
        assert!(dir.join("keep.yaml").exists());
        assert!(
            dir.join("notes.txt").exists(),
            "non-YAML files are not touched"
        );
    }

    #[test]
    fn prune_on_a_missing_directory_is_a_no_op() {
        let temp = tempfile::tempdir().expect("create temp");
        assert!(prune_incompatible_approvals(&temp.path().join("absent")).is_empty());
    }

    #[test]
    fn bootstrap_filesystem_runs_the_whole_first_boot_sequence_for_the_ca() {
        let (_temp, paths) = sandbox();
        std::fs::create_dir_all(paths.nebula_requests()).expect("create requests dir");
        std::fs::write(
            paths.nebula_requests().join("stale.yaml"),
            "approve: true\n",
        )
        .expect("write stale approval");

        let report = bootstrap_filesystem(&paths, true);

        assert!(report.directory_failures.is_empty());
        assert_eq!(report.created_configs, vec!["nodeA", "nodeB", "nodeC"]);
        assert!(report.created_schema);
        assert_eq!(report.pruned_approvals, vec!["stale.yaml"]);
        assert!(report.schema_digest.is_some());
    }

    #[test]
    fn bootstrap_filesystem_skips_approval_pruning_on_member_nodes() {
        let (_temp, paths) = sandbox();
        std::fs::create_dir_all(paths.nebula_requests()).expect("create requests dir");
        let stale = paths.nebula_requests().join("stale.yaml");
        std::fs::write(&stale, "approve: true\n").expect("write stale approval");

        let report = bootstrap_filesystem(&paths, false);

        assert!(report.pruned_approvals.is_empty());
        assert!(stale.exists(), "members never prune the CA's request queue");

        let second = bootstrap_filesystem(&paths, false);
        assert!(second.created_configs.is_empty());
        assert!(!second.created_schema);
    }
}
