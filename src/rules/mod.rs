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
