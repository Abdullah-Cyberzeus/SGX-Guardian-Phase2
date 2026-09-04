//! Testable startup logic extracted from the `sgx-guardian` binary entry point.
//!
//! `src/main.rs` used to carry configuration validation, filesystem
//! bootstrapping, command dispatch and startup decisions inline, which made
//! every one of those branches reachable only by running the real daemon
//! against real hardware. The behaviour lives here instead, parameterised by
//! [`GuardianPaths`] so tests can point it at a tempdir, leaving `main()`
//! responsible for parsing, wiring and exit status.

pub mod admin_tls;
pub mod audit_paths;
pub mod bootstrap;
pub mod config;
pub mod did_boot;
pub mod nebula_cert;
pub mod pcr_status;

use std::path::{Path, PathBuf};

/// Production filesystem roots the daemon reads and writes.
pub const DEFAULT_ETC_ROOT: &str = "/etc/sgx-guardian";
pub const DEFAULT_VAR_ROOT: &str = "/var/lib/sgx-guardian";
pub const DEFAULT_LOG_ROOT: &str = "/var/log/sgx-guardian";

/// The three filesystem roots every startup step is resolved against.
///
/// Production uses [`GuardianPaths::production`]; tests use
/// [`GuardianPaths::rooted_at`] so no step can touch the real system tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardianPaths {
    pub etc_root: PathBuf,
    pub var_root: PathBuf,
    pub log_root: PathBuf,
}

impl Default for GuardianPaths {
    fn default() -> Self {
        Self::production()
    }
}

impl GuardianPaths {
    pub fn production() -> Self {
        Self {
            etc_root: PathBuf::from(DEFAULT_ETC_ROOT),
            var_root: PathBuf::from(DEFAULT_VAR_ROOT),
            log_root: PathBuf::from(DEFAULT_LOG_ROOT),
        }
    }

    /// Mirrors the production layout underneath `base`, for tests and for
    /// containerised runs that relocate the whole tree.
    pub fn rooted_at(base: impl AsRef<Path>) -> Self {
        let base = base.as_ref();
        Self {
            etc_root: base.join("etc/sgx-guardian"),
            var_root: base.join("var/lib/sgx-guardian"),
            log_root: base.join("var/log/sgx-guardian"),
        }
    }

    /// `<etc>/config/<node>.yaml` — the dynamic config the broadcast/discovery
    /// loops rewrite.
    pub fn node_config(&self, node_id: &str) -> PathBuf {
        self.etc_root.join("config").join(format!("{node_id}.yaml"))
    }

    /// `<etc>/<node>.yaml` — the mirror copy kept in sync with the dynamic one.
    pub fn node_config_mirror(&self, node_id: &str) -> PathBuf {
        self.etc_root.join(format!("{node_id}.yaml"))
    }

    pub fn policy_schema(&self) -> PathBuf {
        self.etc_root.join("schemas/uep_policy_v1.yaml")
    }

    pub fn signed_policy(&self) -> PathBuf {
        self.etc_root.join("policies/policy.sig")
    }

    pub fn backup_policy(&self) -> PathBuf {
        self.etc_root.join("policies/backup_policy.yaml")
    }

    pub fn nebula_requests(&self) -> PathBuf {
        self.var_root.join("nebula/requests")
    }

    pub fn node_key(&self, node_id: &str) -> PathBuf {
        self.var_root
            .join("sgx-agent")
            .join(format!("device_{node_id}.key"))
    }

    pub fn node_cert(&self, node_id: &str) -> PathBuf {
        self.var_root
            .join("sgx-agent")
            .join(format!("device_{node_id}_cert.der"))
    }

    pub fn pcr_snapshot(&self, node_id: &str) -> PathBuf {
        self.var_root
            .join("pcr")
            .join(format!("{node_id}_current.json"))
    }

    pub fn pcr_baseline(&self, node_id: &str) -> PathBuf {
        self.etc_root.join(format!("pcr_{node_id}_baseline.json"))
    }

    pub fn boot_chain_status(&self, node_id: &str) -> PathBuf {
        self.var_root
            .join("boot")
            .join(format!("{node_id}_chain_status.json"))
    }
}

/// Reads an environment variable as one of the documented truthy spellings.
///
/// Deliberately strict: only the exact lowercase/uppercase spellings the
/// operator documentation lists enable a gate, so a typo fails closed rather
/// than silently arming a hardware requirement.
pub fn env_true(key: &str) -> bool {
    matches!(
        std::env::var(key).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("on")
    )
}

/// Compares two JSON payloads semantically, falling back to trimmed text
/// comparison when either side is not valid JSON.
pub fn json_equivalent(a: &str, b: &str) -> bool {
    let va = serde_json::from_str::<serde_json::Value>(a);
    let vb = serde_json::from_str::<serde_json::Value>(b);
    match (va, vb) {
        (Ok(lhs), Ok(rhs)) => lhs == rhs,
        _ => a.trim() == b.trim(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_paths_use_the_documented_system_roots() {
        let paths = GuardianPaths::production();
        assert_eq!(paths.etc_root, Path::new(DEFAULT_ETC_ROOT));
        assert_eq!(paths.var_root, Path::new(DEFAULT_VAR_ROOT));
        assert_eq!(paths.log_root, Path::new(DEFAULT_LOG_ROOT));
        assert_eq!(GuardianPaths::default(), paths);
    }

    #[test]
    fn rooted_paths_mirror_the_production_layout_under_a_base() {
        let paths = GuardianPaths::rooted_at("/tmp/sandbox");
        assert_eq!(paths.etc_root, Path::new("/tmp/sandbox/etc/sgx-guardian"));
        assert_eq!(
            paths.var_root,
            Path::new("/tmp/sandbox/var/lib/sgx-guardian")
        );
        assert_eq!(
            paths.log_root,
            Path::new("/tmp/sandbox/var/log/sgx-guardian")
        );
    }

    #[test]
    fn derived_paths_match_the_layout_the_daemon_expects() {
        let paths = GuardianPaths::rooted_at("/base");
        assert_eq!(
            paths.node_config("nodeA"),
            Path::new("/base/etc/sgx-guardian/config/nodeA.yaml")
        );
        assert_eq!(
            paths.node_config_mirror("nodeA"),
            Path::new("/base/etc/sgx-guardian/nodeA.yaml")
        );
        assert_eq!(
            paths.policy_schema(),
            Path::new("/base/etc/sgx-guardian/schemas/uep_policy_v1.yaml")
        );
        assert_eq!(
            paths.signed_policy(),
            Path::new("/base/etc/sgx-guardian/policies/policy.sig")
        );
        assert_eq!(
            paths.backup_policy(),
            Path::new("/base/etc/sgx-guardian/policies/backup_policy.yaml")
        );
        assert_eq!(
            paths.nebula_requests(),
            Path::new("/base/var/lib/sgx-guardian/nebula/requests")
        );
        assert_eq!(
            paths.node_key("nodeB"),
            Path::new("/base/var/lib/sgx-guardian/sgx-agent/device_nodeB.key")
        );
        assert_eq!(
            paths.node_cert("nodeB"),
            Path::new("/base/var/lib/sgx-guardian/sgx-agent/device_nodeB_cert.der")
        );
        assert_eq!(
            paths.pcr_snapshot("nodeC"),
            Path::new("/base/var/lib/sgx-guardian/pcr/nodeC_current.json")
        );
        assert_eq!(
            paths.pcr_baseline("nodeC"),
            Path::new("/base/etc/sgx-guardian/pcr_nodeC_baseline.json")
        );
        assert_eq!(
            paths.boot_chain_status("nodeC"),
            Path::new("/base/var/lib/sgx-guardian/boot/nodeC_chain_status.json")
        );
    }

    #[test]
    fn env_true_accepts_only_the_documented_truthy_spellings() {
        let _lock = crate::test_support::blocking_env_lock();
        const KEY: &str = "SGX_STARTUP_TEST_GATE";
        let previous = std::env::var_os(KEY);

        std::env::remove_var(KEY);
        assert!(!env_true(KEY));
        for value in ["1", "true", "TRUE", "yes", "on"] {
            std::env::set_var(KEY, value);
            assert!(env_true(KEY), "{value} should enable the gate");
        }
        for value in ["0", "false", "True", "YES", "off", "", " true "] {
            std::env::set_var(KEY, value);
            assert!(!env_true(KEY), "{value:?} should not enable the gate");
        }

        match previous {
            Some(value) => std::env::set_var(KEY, value),
            None => std::env::remove_var(KEY),
        }
    }

    #[test]
    fn json_equivalent_compares_semantically_then_falls_back_to_text() {
        assert!(json_equivalent(
            r#"{"node":"nodeA","ports":[443,80]}"#,
            r#"{ "ports": [443, 80], "node": "nodeA" }"#,
        ));
        assert!(!json_equivalent("[1,2]", "[2,1]"));
        assert!(json_equivalent("  not-json  ", "not-json"));
        assert!(!json_equivalent("not-json-a", "not-json-b"));
        assert!(!json_equivalent(r#"{"valid":true}"#, "not-json"));
    }
}
