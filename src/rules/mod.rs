pub mod bus;
pub mod errors;
pub mod eval;
pub mod exec;
pub mod model;
pub mod persistence;
pub mod store;

pub use errors::{RulesError, RulesResult};
pub use model::{
    Condition, Rule, RuleAction, RuleDraft, RuleEvent, RuleExecution, RulePatch, RuleRegistry,
    RuleTrigger,
};

use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use persistence::RulesPaths;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct RulesConfig {
    pub paths: RulesPaths,
    pub dry_run: bool,
    pub max_executions: usize,
    pub threat_config_path: PathBuf,
    pub threat_state_dir: PathBuf,
    pub discovery_config_path: PathBuf,
    pub transport_lock_dir: PathBuf,
    pub transport_lock_interface: Option<String>,
}

impl RulesConfig {
    pub fn from_env() -> Self {
        Self {
            paths: RulesPaths::from_env(),
            dry_run: std::env::var(persistence::RULES_DRYRUN_ENV)
                .map(|value| value != "0" && !value.eq_ignore_ascii_case("false"))
                .unwrap_or(true),
            max_executions: std::env::var(persistence::RULES_MAX_EXECUTIONS_ENV)
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(2000),
            threat_config_path: std::env::var("SGX_RULES_THREAT_CONFIG")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/etc/sgx-guardian/threat/config.yaml")),
            threat_state_dir: std::env::var("SGX_RULES_THREAT_STATE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/var/lib/sgx-guardian/threat")),
            discovery_config_path: std::env::var("SGX_RULES_DISCOVERY_CONFIG")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/etc/sgx-guardian/discovery/nmap.yaml")),
            transport_lock_dir: std::env::var("SGX_GUARDIAN_COT_LOCK_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/var/lib/sgx-guardian/cot")),
            transport_lock_interface: std::env::var("SGX_RULES_LOCK_INTERFACE")
                .ok()
                .filter(|value| !value.trim().is_empty()),
        }
    }
}

pub fn spawn(node_id: String) {
    let config = RulesConfig::from_env();
    tokio::spawn(async move {
        log_audit(
            &node_id,
            AuditCategory::Rules,
            AuditSeverity::Info,
            AuditAction::Started,
            &format!(
                "rules engine started dry_run={} base={}",
                config.dry_run,
                config.paths.base.display()
            ),
        );
        let mut rx = bus::subscribe();
        loop {
            match rx.recv().await {
                Ok(event) => exec::process_event(config.clone(), node_id.clone(), event).await,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    log_audit(
                        &node_id,
                        AuditCategory::Rules,
                        AuditSeverity::Warning,
                        AuditAction::Failed,
                        &format!("rules engine skipped {} lagged event(s)", skipped),
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

pub fn publish(event: RuleEvent) {
    bus::publish(event);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EnvGuard(Vec<(&'static str, Option<std::ffi::OsString>)>);

    impl EnvGuard {
        fn capture(keys: &[&'static str]) -> Self {
            Self(
                keys.iter()
                    .map(|key| (*key, std::env::var_os(key)))
                    .collect(),
            )
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, previous) in self.0.drain(..) {
                if let Some(previous) = previous {
                    std::env::set_var(key, previous);
                } else {
                    std::env::remove_var(key);
                }
            }
        }
    }

    #[test]
    fn rules_config_parses_overrides_defaults_invalid_limits_and_empty_interface() {
        let _lock = crate::test_support::blocking_env_lock();
        let keys = [
            persistence::RULES_BASE_ENV,
            persistence::RULES_DRYRUN_ENV,
            persistence::RULES_MAX_EXECUTIONS_ENV,
            "SGX_RULES_THREAT_CONFIG",
            "SGX_RULES_THREAT_STATE_DIR",
            "SGX_RULES_DISCOVERY_CONFIG",
            "SGX_GUARDIAN_COT_LOCK_DIR",
            "SGX_RULES_LOCK_INTERFACE",
        ];
        let _guard = EnvGuard::capture(&keys);
        for key in keys {
            std::env::remove_var(key);
        }

        let defaults = RulesConfig::from_env();
        assert!(defaults.dry_run);
        assert_eq!(defaults.max_executions, 2000);
        assert!(defaults.transport_lock_interface.is_none());

        std::env::set_var(persistence::RULES_BASE_ENV, "/tmp/rules-test");
        std::env::set_var(persistence::RULES_DRYRUN_ENV, "0");
        std::env::set_var(persistence::RULES_MAX_EXECUTIONS_ENV, "25");
        std::env::set_var("SGX_RULES_THREAT_CONFIG", "/tmp/threat.yaml");
        std::env::set_var("SGX_RULES_THREAT_STATE_DIR", "/tmp/threat-state");
        std::env::set_var("SGX_RULES_DISCOVERY_CONFIG", "/tmp/discovery.yaml");
        std::env::set_var("SGX_GUARDIAN_COT_LOCK_DIR", "/tmp/cot-lock");
        std::env::set_var("SGX_RULES_LOCK_INTERFACE", "eth9");
        let configured = RulesConfig::from_env();
        assert!(!configured.dry_run);
        assert_eq!(configured.max_executions, 25);
        assert_eq!(configured.paths.base, PathBuf::from("/tmp/rules-test"));
        assert_eq!(
            configured.threat_config_path,
            PathBuf::from("/tmp/threat.yaml")
        );
        assert_eq!(
            configured.threat_state_dir,
            PathBuf::from("/tmp/threat-state")
        );
        assert_eq!(
            configured.discovery_config_path,
            PathBuf::from("/tmp/discovery.yaml")
        );
        assert_eq!(
            configured.transport_lock_dir,
            PathBuf::from("/tmp/cot-lock")
        );
        assert_eq!(configured.transport_lock_interface.as_deref(), Some("eth9"));

        std::env::set_var(persistence::RULES_DRYRUN_ENV, "FALSE");
        std::env::set_var(persistence::RULES_MAX_EXECUTIONS_ENV, "0");
        std::env::set_var("SGX_RULES_LOCK_INTERFACE", "   ");
        let invalid = RulesConfig::from_env();
        assert!(!invalid.dry_run);
        assert_eq!(invalid.max_executions, 2000);
        assert!(invalid.transport_lock_interface.is_none());

        std::env::set_var(persistence::RULES_DRYRUN_ENV, "yes");
        std::env::set_var(persistence::RULES_MAX_EXECUTIONS_ENV, "invalid");
        let enabled = RulesConfig::from_env();
        assert!(enabled.dry_run);
        assert_eq!(enabled.max_executions, 2000);
    }
}
