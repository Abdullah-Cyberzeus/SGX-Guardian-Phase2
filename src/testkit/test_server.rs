//! Configuration and identity isolation for the ephemeral E2E test Guardian.
//!
//! The behaviour lives here rather than in `src/bin/test_guardian_server.rs`
//! so the environment defaults and path isolation — the parts that decide
//! whether a test run touches the real `/var/lib/sgx-guardian` tree — are
//! covered by tests instead of only by running the binary.

use crate::did::doc_persistence;
use std::path::{Path, PathBuf};

pub const PORT_ENV: &str = "TEST_GUARDIAN_PORT";
pub const STATE_DIR_ENV: &str = "TEST_GUARDIAN_STATE_DIR";
pub const NODE_ID_ENV: &str = "TEST_GUARDIAN_NODE_ID";
pub const ADMIN_EMAIL_ENV: &str = "TEST_GUARDIAN_ADMIN_EMAIL";
pub const ADMIN_PASSWORD_ENV: &str = "TEST_GUARDIAN_ADMIN_PASSWORD";

pub const DEFAULT_PORT: u16 = 8443;
/// `vc::issue::configured_ca_did` hardcodes the Circle-owner bootstrap check
/// to node name "nodeA"; a different id needs an owner seeded another way.
pub const DEFAULT_NODE_ID: &str = "nodeA";
pub const DEFAULT_ADMIN_EMAIL: &str = "admin@sgx-guardian.local";
/// Chosen only to satisfy the real password policy — never used outside this
/// ephemeral test server.
pub const DEFAULT_ADMIN_PASSWORD: &str = "AdminTest123!";
/// No real `nebula0` TUN interface exists in a test environment, but group
/// calls and similar need a plausible overlay IP to resolve.
pub const DEFAULT_OVERLAY_IP: &str = "192.168.100.1";
pub const DEFAULT_OVERLAY_CIDR: &str = "192.168.100.1/24";

/// Everything the test Guardian needs to boot, resolved from the environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestServerConfig {
    pub port: u16,
    pub state_dir: PathBuf,
    pub node_id: String,
    pub admin_email: String,
    pub admin_password: String,
}

impl TestServerConfig {
    /// Resolves the configuration, defaulting the state directory to a
    /// PID-scoped directory under the OS temp dir so concurrent runs do not
    /// share state.
    pub fn from_env() -> Self {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// [`TestServerConfig::from_env`] against an arbitrary variable source.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let port = lookup(PORT_ENV)
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_PORT);
        let state_dir = lookup(STATE_DIR_ENV).map(PathBuf::from).unwrap_or_else(|| {
            std::env::temp_dir().join(format!("sgx-test-guardian-{}", std::process::id()))
        });
        Self {
            port,
            state_dir,
            node_id: lookup(NODE_ID_ENV).unwrap_or_else(|| DEFAULT_NODE_ID.to_string()),
            admin_email: lookup(ADMIN_EMAIL_ENV).unwrap_or_else(|| DEFAULT_ADMIN_EMAIL.to_string()),
            admin_password: lookup(ADMIN_PASSWORD_ENV)
                .unwrap_or_else(|| DEFAULT_ADMIN_PASSWORD.to_string()),
        }
    }

    pub fn config_dir(&self) -> PathBuf {
        self.state_dir.join("config")
    }

    pub fn device_key_dir(&self) -> PathBuf {
        self.state_dir.join("device-keys")
    }
}

/// The environment variables that redirect every identity/storage path at
/// `state_dir`, as `(key, value)` pairs.
///
/// Returned rather than set directly so a test can assert the full set without
/// mutating the process environment.
pub fn identity_overrides(state_dir: &Path) -> Vec<(&'static str, String)> {
    let at = |name: &str| state_dir.join(name).to_string_lossy().into_owned();
    vec![
        ("SGX_FORCE_SOFTWARE_KEYS", "1".to_string()),
        ("SGX_GUARDIAN_CIRCLE_BASE", at("circle-base")),
        ("SGX_GUARDIAN_VC_BASE", at("vc-base")),
        ("SGX_GUARDIAN_DID_PATH", at("did.json")),
        ("SGX_GUARDIAN_DEVICE_KEY_DIR", at("device-keys")),
        (
            crate::virtual_id::RUNTIME_VID_STATE_DIR_ENV,
            at("virtual-id"),
        ),
        (doc_persistence::SELF_DOC_PATH_ENV, at("did_doc.json")),
        (doc_persistence::PEERS_DOC_DIR_ENV, at("did-peers")),
        (
            doc_persistence::CA_AGGREGATE_PATH_ENV,
            at("ca-aggregate.json"),
        ),
        (
            doc_persistence::VERSION_COUNTER_PATH_ENV,
            at("did-version-counter"),
        ),
    ]
}

/// Points every Circle/VC/DID storage path at `state_dir` and forces software
/// key signing — this test server has no hardware SE050 to fall back on.
///
/// The overlay IP override is only applied when unset, so a caller can pin a
/// different address.
pub fn isolate_identity_paths(state_dir: &Path) {
    for (key, value) in identity_overrides(state_dir) {
        std::env::set_var(key, value);
    }
    if std::env::var("SGX_NEBULA_LOCAL_IP_OVERRIDE").is_err() {
        std::env::set_var("SGX_NEBULA_LOCAL_IP_OVERRIDE", DEFAULT_OVERLAY_IP);
    }
}

/// Creates the state and config directories the server writes into.
pub fn prepare_state_dirs(config: &TestServerConfig) -> std::io::Result<()> {
    std::fs::create_dir_all(&config.state_dir)?;
    std::fs::create_dir_all(config.config_dir())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup_from(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        move |key| map.get(key).cloned()
    }

    #[test]
    fn an_empty_environment_yields_the_documented_defaults() {
        let config = TestServerConfig::from_lookup(|_| None);

        assert_eq!(config.port, DEFAULT_PORT);
        assert_eq!(config.node_id, DEFAULT_NODE_ID);
        assert_eq!(config.admin_email, DEFAULT_ADMIN_EMAIL);
        assert_eq!(config.admin_password, DEFAULT_ADMIN_PASSWORD);
        assert!(
            config
                .state_dir
                .to_string_lossy()
                .contains(&std::process::id().to_string()),
            "the default state dir is PID-scoped so concurrent runs stay isolated: {}",
            config.state_dir.display()
        );
        assert!(config.state_dir.starts_with(std::env::temp_dir()));
    }

    #[test]
    fn every_variable_overrides_its_default() {
        let config = TestServerConfig::from_lookup(lookup_from(&[
            (PORT_ENV, "9100"),
            (STATE_DIR_ENV, "/tmp/custom-state"),
            (NODE_ID_ENV, "nodeB"),
            (ADMIN_EMAIL_ENV, "qa@example.com"),
            (ADMIN_PASSWORD_ENV, "Sup3rSecret!"),
        ]));

        assert_eq!(config.port, 9100);
        assert_eq!(config.state_dir, Path::new("/tmp/custom-state"));
        assert_eq!(config.node_id, "nodeB");
        assert_eq!(config.admin_email, "qa@example.com");
        assert_eq!(config.admin_password, "Sup3rSecret!");
    }

    #[test]
    fn an_unparseable_port_falls_back_to_the_default() {
        for value in ["", "not-a-port", "70000", "-1"] {
            let config = TestServerConfig::from_lookup(lookup_from(&[(PORT_ENV, value)]));
            assert_eq!(config.port, DEFAULT_PORT, "{value:?}");
        }
    }

    #[test]
    fn derived_directories_hang_off_the_state_dir() {
        let config =
            TestServerConfig::from_lookup(lookup_from(&[(STATE_DIR_ENV, "/tmp/custom-state")]));

        assert_eq!(config.config_dir(), Path::new("/tmp/custom-state/config"));
        assert_eq!(
            config.device_key_dir(),
            Path::new("/tmp/custom-state/device-keys")
        );
    }

    #[test]
    fn every_identity_path_is_redirected_under_the_state_dir() {
        let state_dir = Path::new("/tmp/isolated-guardian");

        let overrides = identity_overrides(state_dir);

        let forced: Vec<_> = overrides
            .iter()
            .filter(|(key, _)| *key == "SGX_FORCE_SOFTWARE_KEYS")
            .collect();
        assert_eq!(forced.len(), 1);
        assert_eq!(forced[0].1, "1", "the test server has no hardware backend");

        for (key, value) in &overrides {
            if *key == "SGX_FORCE_SOFTWARE_KEYS" {
                continue;
            }
            assert!(
                value.starts_with("/tmp/isolated-guardian/"),
                "{key} must not escape the state dir: {value}"
            );
            assert!(
                !value.contains("/var/lib/sgx-guardian"),
                "{key} must never point at the production tree: {value}"
            );
        }
    }

    #[test]
    fn the_override_set_covers_every_did_document_path() {
        let overrides = identity_overrides(Path::new("/tmp/isolated-guardian"));
        let keys: Vec<&str> = overrides.iter().map(|(key, _)| *key).collect();

        for required in [
            "SGX_GUARDIAN_CIRCLE_BASE",
            "SGX_GUARDIAN_VC_BASE",
            "SGX_GUARDIAN_DID_PATH",
            "SGX_GUARDIAN_DEVICE_KEY_DIR",
            crate::virtual_id::RUNTIME_VID_STATE_DIR_ENV,
            doc_persistence::SELF_DOC_PATH_ENV,
            doc_persistence::PEERS_DOC_DIR_ENV,
            doc_persistence::CA_AGGREGATE_PATH_ENV,
            doc_persistence::VERSION_COUNTER_PATH_ENV,
        ] {
            assert!(keys.contains(&required), "{required} must be redirected");
        }
    }

    #[test]
    fn prepare_state_dirs_creates_both_directories_and_is_idempotent() {
        let temp = tempfile::tempdir().expect("create sandbox");
        let config = TestServerConfig::from_lookup(lookup_from(&[(
            STATE_DIR_ENV,
            temp.path().join("guardian").to_str().expect("utf-8"),
        )]));

        prepare_state_dirs(&config).expect("create state dirs");
        assert!(config.state_dir.is_dir());
        assert!(config.config_dir().is_dir());

        prepare_state_dirs(&config).expect("a second run is a no-op");
    }

    #[test]
    fn isolating_identity_paths_applies_every_override_to_the_environment() {
        let _lock = crate::test_support::blocking_env_lock();
        let temp = tempfile::tempdir().expect("create sandbox");
        let previous: Vec<_> = identity_overrides(temp.path())
            .into_iter()
            .map(|(key, _)| (key, std::env::var_os(key)))
            .collect();
        let previous_overlay = std::env::var_os("SGX_NEBULA_LOCAL_IP_OVERRIDE");
        std::env::remove_var("SGX_NEBULA_LOCAL_IP_OVERRIDE");

        isolate_identity_paths(temp.path());

        for (key, expected) in identity_overrides(temp.path()) {
            assert_eq!(std::env::var(key).ok().as_deref(), Some(expected.as_str()));
        }
        assert_eq!(
            std::env::var("SGX_NEBULA_LOCAL_IP_OVERRIDE")
                .ok()
                .as_deref(),
            Some(DEFAULT_OVERLAY_IP)
        );

        // An operator-supplied overlay address is preserved.
        std::env::set_var("SGX_NEBULA_LOCAL_IP_OVERRIDE", "10.9.9.9");
        isolate_identity_paths(temp.path());
        assert_eq!(
            std::env::var("SGX_NEBULA_LOCAL_IP_OVERRIDE")
                .ok()
                .as_deref(),
            Some("10.9.9.9")
        );

        for (key, value) in previous {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
        match previous_overlay {
            Some(value) => std::env::set_var("SGX_NEBULA_LOCAL_IP_OVERRIDE", value),
            None => std::env::remove_var("SGX_NEBULA_LOCAL_IP_OVERRIDE"),
        }
    }
}
