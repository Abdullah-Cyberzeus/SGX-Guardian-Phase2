//! Node configuration loading, topology selection and policy rendering used
//! during startup.
//!
//! These were inline closures and nested `fn`s inside `main()`, which made the
//! fallback and unknown-node branches unreachable from tests. They are plain
//! functions over [`GuardianPaths`] here.

use super::GuardianPaths;
use crate::config_loader::{load_config, NodeConfig, RelayLimitsConfig};

/// The minimal valid policy used when the schema file cannot be read at all.
pub const FALLBACK_POLICY_YAML: &str =
    "---\npolicy_id: \"default\"\nversion: \"0.0.0\"\ndescription: \"Empty default\"\nrules: []\n";

/// gRPC port for a node id when no configuration supplies one.
pub fn default_port_for(node_id: &str) -> u16 {
    match node_id {
        "nodeA" => 50051,
        "nodeB" => 50052,
        _ => 50053,
    }
}

/// The plaintext chat gRPC port. Unlike [`default_port_for`], an unknown node
/// id falls back to nodeA's port rather than nodeC's — the chat service is
/// reached over the authenticated Nebula overlay, and pointing an unrecognised
/// node at the CA's port keeps a misconfigured member reachable.
pub fn chat_grpc_port(node_id: &str) -> u16 {
    match node_id {
        "nodeB" => 50252,
        "nodeC" => 50253,
        _ => 50251,
    }
}

/// The last-resort configuration used when neither config path is readable.
pub fn default_node_config(node_id: &str) -> NodeConfig {
    let suffix = node_id.strip_prefix("node").unwrap_or(node_id);
    NodeConfig {
        node_id: node_id.to_string(),
        device_name: None,
        hostname: format!("guardian-node-{suffix}"),
        display_hostname: None,
        ip: "0.0.0.0".to_string(),
        port: default_port_for(node_id),
        public_key: format!("placeholder-key-{suffix}"),
        offline_mode: 1,
        metrics: None,
        relay: None,
        api: None,
    }
}

/// Loads a node config, preferring the dynamic `config/` copy that discovery
/// rewrites, then the mirror in the etc root, then built-in defaults.
///
/// Startup never fails on a bad config: an unreachable peer entry must not
/// stop this node from booting, so an invalid file degrades to defaults.
pub fn load_config_safe(paths: &GuardianPaths, node_id: &str) -> NodeConfig {
    for candidate in [
        paths.node_config(node_id),
        paths.node_config_mirror(node_id),
    ] {
        if let Some(path) = candidate.to_str() {
            if let Ok(config) = load_config(path) {
                return config;
            }
        }
    }
    default_node_config(node_id)
}

/// The three-node cohort this build knows about, loaded in a fixed order.
#[derive(Debug, Clone)]
pub struct Cohort {
    pub node_a: NodeConfig,
    pub node_b: NodeConfig,
    pub node_c: NodeConfig,
}

impl Cohort {
    pub fn load(paths: &GuardianPaths) -> Self {
        Self {
            node_a: load_config_safe(paths, "nodeA"),
            node_b: load_config_safe(paths, "nodeB"),
            node_c: load_config_safe(paths, "nodeC"),
        }
    }

    /// Relay limits for the node this process is running as. An unknown node
    /// id gets the conservative built-in limits rather than another node's.
    pub fn relay_limits_for(&self, node_id: &str) -> RelayLimitsConfig {
        match node_id {
            "nodeA" => self.node_a.relay_or_default(),
            "nodeB" => self.node_b.relay_or_default(),
            "nodeC" => self.node_c.relay_or_default(),
            _ => RelayLimitsConfig::default(),
        }
    }

    /// Splits the cohort into (this node, its peers).
    ///
    /// `None` for an unrecognised node id — the caller must refuse to start
    /// rather than guess a role, since guessing could silently promote a node
    /// to CA.
    pub fn split(&self, node_id: &str) -> Option<(NodeConfig, Vec<NodeConfig>)> {
        match node_id {
            "nodeA" => Some((
                self.node_a.clone(),
                vec![self.node_b.clone(), self.node_c.clone()],
            )),
            "nodeB" => Some((
                self.node_b.clone(),
                vec![self.node_a.clone(), self.node_c.clone()],
            )),
            "nodeC" => Some((
                self.node_c.clone(),
                vec![self.node_a.clone(), self.node_b.clone()],
            )),
            _ => None,
        }
    }
}

/// The IP a broadcast announcement should carry: the freshly detected LAN
/// address when detection succeeded, otherwise whatever the config holds.
pub fn broadcast_ip(detected_ip: &str, configured_ip: &str) -> String {
    if detected_ip.is_empty() {
        configured_ip.to_string()
    } else {
        detected_ip.to_string()
    }
}

/// Reads the active policy schema, falling back to [`FALLBACK_POLICY_YAML`].
pub fn read_policy_schema_or_fallback(paths: &GuardianPaths) -> String {
    std::fs::read_to_string(paths.policy_schema())
        .unwrap_or_else(|_| FALLBACK_POLICY_YAML.to_string())
}

/// Renders a policy document as the operator-facing summary lines printed at
/// startup, or the parse error that prevented it.
pub fn policy_summary_lines(yaml: &str, label: &str) -> Result<Vec<String>, String> {
    let parsed = crate::policy::validate_policy(yaml).map_err(|error| error.to_string())?;
    let mut lines = vec![format!(
        "Policy Loaded ({}): ID = {}, Version = {}",
        label, parsed.policy_id, parsed.version
    )];
    for rule in parsed.rules {
        lines.push(format!(
            " - Rule {}: {} {} -> {} (protocol: {}{})",
            rule.id,
            rule.action,
            rule.src,
            rule.dst,
            rule.protocol,
            rule.port
                .map(|port| format!(", port: {port}"))
                .unwrap_or_default()
        ));
    }
    Ok(lines)
}

/// Prints [`policy_summary_lines`], routing a parse failure to stderr.
pub fn print_policy_from_yaml(yaml: &str, label: &str) {
    match policy_summary_lines(yaml, label) {
        Ok(lines) => {
            for line in lines {
                println!("{line}");
            }
        }
        Err(error) => eprintln!("❌ Failed to parse {label} policy: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::startup::bootstrap;

    fn sandbox() -> (tempfile::TempDir, GuardianPaths) {
        let temp = tempfile::tempdir().expect("create sandbox root");
        let paths = GuardianPaths::rooted_at(temp.path());
        bootstrap::ensure_directories(&paths);
        (temp, paths)
    }

    #[test]
    fn ports_are_derived_per_node_with_a_shared_fallback() {
        assert_eq!(default_port_for("nodeA"), 50051);
        assert_eq!(default_port_for("nodeB"), 50052);
        assert_eq!(default_port_for("nodeC"), 50053);
        assert_eq!(default_port_for("nodeZ"), 50053);
        assert_eq!(chat_grpc_port("nodeA"), 50251);
        assert_eq!(chat_grpc_port("nodeB"), 50252);
        assert_eq!(chat_grpc_port("nodeC"), 50253);
        assert_eq!(
            chat_grpc_port("nodeZ"),
            50251,
            "an unknown node id falls back to the CA's chat port"
        );
    }

    #[test]
    fn default_node_config_is_valid_and_derives_its_suffix() {
        let config = default_node_config("nodeB");
        assert_eq!(config.node_id, "nodeB");
        assert_eq!(config.hostname, "guardian-node-B");
        assert_eq!(config.public_key, "placeholder-key-B");
        assert_eq!(config.port, 50052);
        assert!(config.offline_cache_enabled());
        assert!(
            config.validate().is_ok(),
            "the fallback must satisfy validation so startup can continue: {:?}",
            config.validate().err()
        );

        let unprefixed = default_node_config("edge-7");
        assert_eq!(unprefixed.hostname, "guardian-node-edge-7");
        assert_eq!(unprefixed.port, 50053);
    }

    #[test]
    fn load_config_safe_prefers_the_dynamic_config_directory() {
        let (_temp, paths) = sandbox();
        std::fs::write(
            paths.node_config("nodeA"),
            "node_id: nodeA\nhostname: dynamic\nip: 10.0.0.7\nport: 50051\npublic_key: k\n",
        )
        .expect("write dynamic config");
        std::fs::write(
            paths.node_config_mirror("nodeA"),
            "node_id: nodeA\nhostname: mirror\nip: 10.0.0.8\nport: 50051\npublic_key: k\n",
        )
        .expect("write mirror config");

        let config = load_config_safe(&paths, "nodeA");

        assert_eq!(config.hostname, "dynamic");
        assert_eq!(config.ip, "10.0.0.7");
    }

    #[test]
    fn load_config_safe_falls_back_to_the_mirror_then_to_defaults() {
        let (_temp, paths) = sandbox();
        std::fs::write(
            paths.node_config_mirror("nodeB"),
            "node_id: nodeB\nhostname: mirror\nip: 10.0.0.8\nport: 50052\npublic_key: k\n",
        )
        .expect("write mirror config");

        assert_eq!(load_config_safe(&paths, "nodeB").hostname, "mirror");
        assert_eq!(
            load_config_safe(&paths, "nodeC").hostname,
            "guardian-node-C",
            "no file at either path falls through to the built-in default"
        );
    }

    #[test]
    fn load_config_safe_rejects_an_invalid_config_instead_of_returning_it() {
        let (_temp, paths) = sandbox();
        // Valid YAML, but validate() rejects the port.
        std::fs::write(
            paths.node_config("nodeA"),
            "node_id: nodeA\nhostname: broken\nip: 10.0.0.7\nport: 0\npublic_key: k\n",
        )
        .expect("write invalid config");

        let config = load_config_safe(&paths, "nodeA");

        assert_eq!(config.hostname, "guardian-node-A");
        assert_eq!(config.port, 50051);
    }

    #[test]
    fn cohort_load_uses_the_shipped_defaults_after_bootstrap() {
        let (_temp, paths) = sandbox();
        bootstrap::ensure_default_node_configs(&paths);

        let cohort = Cohort::load(&paths);

        assert_eq!(cohort.node_a.port, 50051);
        assert_eq!(cohort.node_b.port, 50052);
        assert_eq!(cohort.node_c.port, 50053);
        assert_eq!(cohort.node_b.hostname, crate::lan_name::fqdn("nodeB"));
    }

    #[test]
    fn relay_limits_come_from_the_running_node_and_default_for_unknown_ids() {
        let (_temp, paths) = sandbox();
        std::fs::write(
            paths.node_config("nodeB"),
            "node_id: nodeB\nhostname: b\nip: 10.0.0.8\nport: 50052\npublic_key: k\nrelay:\n  enabled: true\n  max_peers: 12\n  max_bandwidth_mbps: 40\n  alert_threshold_pct: 55\n",
        )
        .expect("write relay config");
        let cohort = Cohort::load(&paths);

        let limits = cohort.relay_limits_for("nodeB");
        assert!(limits.enabled);
        assert_eq!(limits.max_peers, 12);
        assert_eq!(limits.max_bandwidth_mbps, 40);
        assert_eq!(limits.alert_threshold_pct, 55);

        for node_id in ["nodeA", "nodeC", "nodeZ"] {
            let fallback = cohort.relay_limits_for(node_id);
            assert!(!fallback.enabled, "{node_id} must not inherit nodeB limits");
            assert_eq!(fallback.max_peers, 5);
        }
    }

    #[test]
    fn split_returns_this_node_and_its_peers_for_every_known_id() {
        let (_temp, paths) = sandbox();
        bootstrap::ensure_default_node_configs(&paths);
        let cohort = Cohort::load(&paths);

        for (node_id, expected_peers) in [
            ("nodeA", ["nodeB", "nodeC"]),
            ("nodeB", ["nodeA", "nodeC"]),
            ("nodeC", ["nodeA", "nodeB"]),
        ] {
            let (this_node, peers) = cohort.split(node_id).expect("known node id");
            assert_eq!(this_node.node_id, node_id);
            let peer_ids: Vec<_> = peers.iter().map(|peer| peer.node_id.as_str()).collect();
            assert_eq!(peer_ids, expected_peers);
        }
    }

    #[test]
    fn split_refuses_an_unknown_node_id() {
        let (_temp, paths) = sandbox();
        let cohort = Cohort::load(&paths);
        assert!(cohort.split("nodeZ").is_none());
        assert!(cohort.split("").is_none());
    }

    #[test]
    fn broadcast_ip_prefers_a_detected_address() {
        assert_eq!(broadcast_ip("10.0.0.5", "0.0.0.0"), "10.0.0.5");
        assert_eq!(broadcast_ip("", "192.168.1.4"), "192.168.1.4");
        assert_eq!(broadcast_ip("", ""), "");
    }

    #[test]
    fn policy_schema_read_falls_back_to_the_minimal_document() {
        let (_temp, paths) = sandbox();

        assert_eq!(read_policy_schema_or_fallback(&paths), FALLBACK_POLICY_YAML);
        assert!(
            crate::policy::validate_policy(FALLBACK_POLICY_YAML).is_ok(),
            "the fallback must itself be a valid policy"
        );

        bootstrap::ensure_default_policy_schema(&paths);
        assert_eq!(
            read_policy_schema_or_fallback(&paths),
            bootstrap::DEFAULT_POLICY_SCHEMA
        );
    }

    #[test]
    fn policy_summary_renders_every_rule_with_and_without_a_port() {
        let lines = policy_summary_lines(bootstrap::DEFAULT_POLICY_SCHEMA, "NEW")
            .expect("default schema parses");

        assert_eq!(lines.len(), 3);
        assert_eq!(
            lines[0],
            "Policy Loaded (NEW): ID = 123e4567-e89b-12d3-a456-426614174000, Version = 1.0.0"
        );
        assert_eq!(
            lines[1],
            " - Rule rule-001: ALLOW 10.0.0.0/24 -> 0.0.0.0/0 (protocol: TCP, port: 443)"
        );
        assert_eq!(
            lines[2], " - Rule rule-005: DENY 0.0.0.0/0 -> 10.0.0.10 (protocol: UDP)",
            "a rule without a port omits the port clause entirely"
        );
    }

    #[test]
    fn policy_summary_reports_a_parse_error_and_an_empty_rule_set() {
        let error = policy_summary_lines("rules: [ unterminated", "BACKUP")
            .expect_err("invalid YAML must not parse");
        assert!(!error.is_empty());

        let empty = policy_summary_lines(FALLBACK_POLICY_YAML, "FALLBACK").expect("valid");
        assert_eq!(empty.len(), 1);

        // The printing wrapper must tolerate both outcomes without panicking.
        print_policy_from_yaml(FALLBACK_POLICY_YAML, "FALLBACK");
        print_policy_from_yaml("rules: [ unterminated", "BACKUP");
    }
}
