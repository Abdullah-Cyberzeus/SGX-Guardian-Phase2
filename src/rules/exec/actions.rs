use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::discovery::{NmapConfig, NmapRunner, ScanIntensity};
use crate::rules::model::{Rule, RuleAction, RuleEvent};
use crate::rules::RulesConfig;
use crate::threat::blocker::Blocker;
use crate::threat::config::SuricataConfig;
use crate::threat::inventory::AlertInventory;
use crate::threat::threat_alert::{Severity as ThreatSeverity, ThreatAlert, ThreatCategory};
use chrono::Utc;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ActionReport {
    pub action: String,
    pub outcome: String,
    pub message: String,
}

pub async fn execute_action(
    config: &RulesConfig,
    node_id: &str,
    rule: &Rule,
    event: &RuleEvent,
    action: &RuleAction,
) -> ActionReport {
    match action {
        RuleAction::RaiseAlert { severity } => raise_alert(config, node_id, rule, event, severity),
        RuleAction::Notify { severity } => notify(node_id, rule, event, severity),
        RuleAction::BlockIp { ttl_secs } => block_ip(config, node_id, event, *ttl_secs).await,
        RuleAction::RunScan { intensity } => run_scan(config, node_id, intensity).await,
        RuleAction::RevokeDid => revoke_did(node_id, rule, event).await,
        RuleAction::LockTransport => lock_transport(config, node_id).await,
        RuleAction::EmergencyKeyRotation => emergency_key_rotation(node_id).await,
    }
}

pub fn dry_run_report(action: &RuleAction) -> ActionReport {
    ActionReport {
        action: action.label(),
        outcome: "dry-run".to_string(),
        message: "would-run; SGX_RULES_DRYRUN is enabled".to_string(),
    }
}

pub fn downgraded_report(action: &RuleAction) -> ActionReport {
    ActionReport {
        action: action.label(),
        outcome: "downgraded".to_string(),
        message: "destructive action requires allow_destructive=true; downgraded to critical alert"
            .to_string(),
    }
}

fn raise_alert(
    config: &RulesConfig,
    node_id: &str,
    rule: &Rule,
    event: &RuleEvent,
    severity: &str,
) -> ActionReport {
    let severity = parse_threat_severity(severity).unwrap_or(ThreatSeverity::High);
    let src_ip = event.src_ip().unwrap_or("0.0.0.0").to_string();
    let dst_ip = match event {
        RuleEvent::ThreatAlert { alert, .. } => alert.dst_ip.clone(),
        _ => "0.0.0.0".to_string(),
    };
    let alert = ThreatAlert {
        alert_id: format!("rules-{}-{}", rule.rule_id, Uuid::new_v4()),
        timestamp: Utc::now(),
        src_ip,
        src_port: event.ports().first().copied().unwrap_or(0),
        dst_ip,
        dst_port: event.ports().get(1).copied().unwrap_or(0),
        protocol: "RULE".to_string(),
        signature_id: 9_900_000,
        signature: format!("Rules engine alert: {}", rule.name),
        category: ThreatCategory::PolicyViolation,
        severity,
        rev: 1,
        gid: 1,
        event_type: "rules".to_string(),
        blocked: false,
    };

    let path = config.threat_state_dir.join("alerts.jsonl");
    let result = (|| {
        let mut inventory = AlertInventory::load_from_path(&path)
            .map_err(|error| format!("load alert inventory: {}", error))?;
        inventory.ingest(alert);
        inventory
            .save_atomic(&path)
            .map_err(|error| format!("save alert inventory: {}", error))
    })();

    match result {
        Ok(()) => {
            log_audit(
                node_id,
                AuditCategory::Rules,
                AuditSeverity::Warning,
                AuditAction::Created,
                &format!(
                    "rules alert raised by {} ({})",
                    rule.rule_id,
                    event.summary()
                ),
            );
            ActionReport {
                action: RuleAction::RaiseAlert {
                    severity: severity.as_str().to_string(),
                }
                .label(),
                outcome: "executed".to_string(),
                message: format!("raised synthetic threat alert in {}", path.display()),
            }
        }
        Err(message) => ActionReport {
            action: RuleAction::RaiseAlert {
                severity: severity.as_str().to_string(),
            }
            .label(),
            outcome: "failed".to_string(),
            message,
        },
    }
}

fn notify(node_id: &str, rule: &Rule, event: &RuleEvent, severity: &str) -> ActionReport {
    let audit_severity = parse_audit_severity(severity);
    log_audit(
        node_id,
        AuditCategory::Rules,
        audit_severity,
        AuditAction::Queued,
        &format!("rules notification {}: {}", rule.rule_id, event.summary()),
    );
    ActionReport {
        action: RuleAction::Notify {
            severity: severity.to_string(),
        }
        .label(),
        outcome: "executed".to_string(),
        message: "notification published to audit/notification seam".to_string(),
    }
}

async fn block_ip(
    config: &RulesConfig,
    node_id: &str,
    event: &RuleEvent,
    ttl_secs: Option<u64>,
) -> ActionReport {
    let Some(ip) = event.src_ip().map(str::to_string) else {
        return ActionReport {
            action: RuleAction::BlockIp { ttl_secs }.label(),
            outcome: "failed".to_string(),
            message: "event has no source IP to block".to_string(),
        };
    };

    let cfg = SuricataConfig::load(&config.threat_config_path).unwrap_or_default();
    let blocker = Blocker::new(
        Arc::new(Mutex::new(cfg)),
        node_id.to_string(),
        config.threat_state_dir.clone(),
    );

    match blocker.block_ip_for_rule(&ip, ttl_secs).await {
        Ok(attempt) if attempt.blocked => ActionReport {
            action: RuleAction::BlockIp { ttl_secs }.label(),
            outcome: "executed".to_string(),
            message: format!("blocked {}", ip),
        },
        Ok(attempt) => ActionReport {
            action: RuleAction::BlockIp { ttl_secs }.label(),
            outcome: "failed".to_string(),
            message: attempt
                .reason
                .unwrap_or_else(|| format!("{} was already blocked or exempt", ip)),
        },
        Err(error) => ActionReport {
            action: RuleAction::BlockIp { ttl_secs }.label(),
            outcome: "failed".to_string(),
            message: error.to_string(),
        },
    }
}

async fn run_scan(config: &RulesConfig, node_id: &str, intensity: &str) -> ActionReport {
    let intensity_value = match parse_scan_intensity(intensity) {
        Some(value) => value,
        None => {
            return ActionReport {
                action: RuleAction::RunScan {
                    intensity: intensity.to_string(),
                }
                .label(),
                outcome: "failed".to_string(),
                message: format!("invalid scan intensity: {}", intensity),
            }
        }
    };

    let cfg = NmapConfig::load(&config.discovery_config_path).unwrap_or_default();
    let target = cfg.resolved_target_cidr();
    match NmapRunner::run_with_intensity(&cfg, &target, intensity_value).await {
        Ok(xml) => {
            log_audit(
                node_id,
                AuditCategory::Rules,
                AuditSeverity::Info,
                AuditAction::Succeeded,
                &format!(
                    "rules scan completed intensity={} target={} bytes={}",
                    intensity,
                    target,
                    xml.len()
                ),
            );
            ActionReport {
                action: RuleAction::RunScan {
                    intensity: intensity.to_string(),
                }
                .label(),
                outcome: "executed".to_string(),
                message: format!("scan completed target={} bytes={}", target, xml.len()),
            }
        }
        Err(error) => ActionReport {
            action: RuleAction::RunScan {
                intensity: intensity.to_string(),
            }
            .label(),
            outcome: "failed".to_string(),
            message: error.to_string(),
        },
    }
}

async fn revoke_did(node_id: &str, rule: &Rule, event: &RuleEvent) -> ActionReport {
    let Some(target_did) = event.target_did().map(str::to_string) else {
        return ActionReport {
            action: RuleAction::RevokeDid.label(),
            outcome: "failed".to_string(),
            message: "event has no DID to revoke".to_string(),
        };
    };
    let rule_id = rule.rule_id.clone();
    let result = tokio::task::spawn_blocking(move || {
        let (revoker, km) = crate::crl::issue::load_runtime_signing_context()?;
        let (circle_id, role) = crate::crl::issue::local_revocation_context(&revoker)?;
        crate::crl::issue::issue_revocation(
            &revoker,
            role,
            &km,
            crate::crl::issue::IssueRequest {
                revoked_did: &target_did,
                reason: crate::crl::entry::RevocationReason::PolicyViolation,
                severity: crate::crl::entry::Severity::Critical,
                circle_id: &circle_id,
                device_id: None,
                user_id: None,
                evidence: Some(crate::crl::entry::RevocationEvidence {
                    note: Some(format!("rules engine action from {}", rule_id)),
                    ..crate::crl::entry::RevocationEvidence::default()
                }),
            },
        )
    })
    .await;

    match result {
        Ok(Ok(entry)) => {
            log_audit(
                node_id,
                AuditCategory::Rules,
                AuditSeverity::Critical,
                AuditAction::Revoked,
                &format!("rules revoked DID via CRL entry {}", entry.id),
            );
            ActionReport {
                action: RuleAction::RevokeDid.label(),
                outcome: "executed".to_string(),
                message: format!("issued CRL entry {}", entry.id),
            }
        }
        Ok(Err(error)) => ActionReport {
            action: RuleAction::RevokeDid.label(),
            outcome: "failed".to_string(),
            message: error.to_string(),
        },
        Err(error) => ActionReport {
            action: RuleAction::RevokeDid.label(),
            outcome: "failed".to_string(),
            message: format!("revocation task join error: {}", error),
        },
    }
}

async fn lock_transport(config: &RulesConfig, node_id: &str) -> ActionReport {
    let Some(interface) = config.transport_lock_interface.clone() else {
        return ActionReport {
            action: RuleAction::LockTransport.label(),
            outcome: "failed".to_string(),
            message: "SGX_RULES_LOCK_INTERFACE is required for live LockTransport".to_string(),
        };
    };
    if !valid_interface_name(&interface) {
        return ActionReport {
            action: RuleAction::LockTransport.label(),
            outcome: "failed".to_string(),
            message: format!("invalid interface name: {}", interface),
        };
    }

    let path = config.transport_lock_dir.join(format!("{}.lock", node_id));
    let write = write_lock_file(&path, &interface);
    match write {
        Ok(()) => {
            log_audit(
                node_id,
                AuditCategory::Rules,
                AuditSeverity::Critical,
                AuditAction::Applied,
                &format!("rules locked transport to {}", interface),
            );
            ActionReport {
                action: RuleAction::LockTransport.label(),
                outcome: "executed".to_string(),
                message: format!("transport locked to {}", interface),
            }
        }
        Err(error) => ActionReport {
            action: RuleAction::LockTransport.label(),
            outcome: "failed".to_string(),
            message: error.to_string(),
        },
    }
}

async fn emergency_key_rotation(node_id: &str) -> ActionReport {
    let Some(cli) = resolve_pa_cli_path() else {
        return ActionReport {
            action: RuleAction::EmergencyKeyRotation.label(),
            outcome: "failed".to_string(),
            message: "sgx-pa-cli not found".to_string(),
        };
    };
    match tokio::process::Command::new(&cli)
        .arg("emergency-rotate")
        .output()
        .await
    {
        Ok(output) if output.status.success() => {
            log_audit(
                node_id,
                AuditCategory::Rules,
                AuditSeverity::Critical,
                AuditAction::Succeeded,
                "rules emergency key rotation completed",
            );
            ActionReport {
                action: RuleAction::EmergencyKeyRotation.label(),
                outcome: "executed".to_string(),
                message: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            }
        }
        Ok(output) => ActionReport {
            action: RuleAction::EmergencyKeyRotation.label(),
            outcome: "failed".to_string(),
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        },
        Err(error) => ActionReport {
            action: RuleAction::EmergencyKeyRotation.label(),
            outcome: "failed".to_string(),
            message: error.to_string(),
        },
    }
}

fn parse_threat_severity(value: &str) -> Option<ThreatSeverity> {
    match normalized(value).as_str() {
        "info" => Some(ThreatSeverity::Info),
        "low" => Some(ThreatSeverity::Low),
        "medium" => Some(ThreatSeverity::Medium),
        "high" => Some(ThreatSeverity::High),
        "critical" => Some(ThreatSeverity::Critical),
        _ => None,
    }
}

fn parse_audit_severity(value: &str) -> AuditSeverity {
    match normalized(value).as_str() {
        "critical" => AuditSeverity::Critical,
        "high" | "medium" => AuditSeverity::Warning,
        _ => AuditSeverity::Info,
    }
}

fn parse_scan_intensity(value: &str) -> Option<ScanIntensity> {
    match normalized(value).as_str() {
        "stealth" => Some(ScanIntensity::Stealth),
        "standard" => Some(ScanIntensity::Standard),
        "aggressive" => Some(ScanIntensity::Aggressive),
        _ => None,
    }
}

fn normalized(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

fn valid_interface_name(value: &str) -> bool {
    !value.trim().is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == ':')
}

fn write_lock_file(path: &Path, interface: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("{}\n", interface))
}

fn resolve_pa_cli_path() -> Option<PathBuf> {
    if let Ok(override_path) = std::env::var("SGX_PA_CLI_PATH") {
        let path = PathBuf::from(override_path);
        if path.is_file() {
            return Some(path);
        }
    }
    which::which("sgx-pa-cli").ok().or_else(|| {
        [
            "/usr/local/bin/sgx-pa-cli",
            "/usr/bin/sgx-pa-cli",
            "/bin/sgx-pa-cli",
        ]
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::model::RuleDraft;
    use crate::rules::persistence::RulesPaths;

    /// Serializes tests that mutate the process-wide `SGX_PA_CLI_PATH` env
    /// var. Routed through the crate-wide lock because `api::handlers::dkp`,
    /// `api::handlers::threat` and `api::handlers::discovery` redirect the same
    /// variable — a lock private to this module excluded none of them.
    fn env_guard() -> crate::test_support::EnvLockGuard {
        crate::test_support::env_lock()
    }

    fn test_config(base: &std::path::Path) -> RulesConfig {
        RulesConfig {
            paths: RulesPaths::from_base(base.join("rules_base")),
            dry_run: true,
            max_executions: 100,
            threat_config_path: base.join("threat_config.yaml"),
            threat_state_dir: base.join("threat_state"),
            discovery_config_path: base.join("discovery.yaml"),
            transport_lock_dir: base.join("cot_lock"),
            transport_lock_interface: None,
        }
    }

    fn test_rule() -> Rule {
        Rule::from_draft(RuleDraft {
            name: Some("test rule".to_string()),
            ..RuleDraft::default()
        })
    }

    fn make_executable(path: &std::path::Path, script: &str) {
        std::fs::write(path, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(path, perms).unwrap();
        }
    }

    #[test]
    fn parse_threat_severity_is_case_and_dash_insensitive_with_fallback() {
        assert_eq!(
            parse_threat_severity("Critical"),
            Some(ThreatSeverity::Critical)
        );
        assert_eq!(parse_threat_severity("high"), Some(ThreatSeverity::High));
        assert_eq!(parse_threat_severity("  Low  "), Some(ThreatSeverity::Low));
        assert_eq!(parse_threat_severity("not-a-severity"), None);
    }

    #[test]
    fn parse_audit_severity_buckets_unknown_values_as_info() {
        assert_eq!(parse_audit_severity("critical"), AuditSeverity::Critical);
        assert_eq!(parse_audit_severity("High"), AuditSeverity::Warning);
        assert_eq!(parse_audit_severity("medium"), AuditSeverity::Warning);
        assert_eq!(parse_audit_severity("low"), AuditSeverity::Info);
        assert_eq!(parse_audit_severity("garbage"), AuditSeverity::Info);
    }

    #[test]
    fn parse_scan_intensity_rejects_unknown_values() {
        assert_eq!(
            parse_scan_intensity("Aggressive"),
            Some(ScanIntensity::Aggressive)
        );
        assert_eq!(
            parse_scan_intensity("stealth"),
            Some(ScanIntensity::Stealth)
        );
        assert_eq!(parse_scan_intensity("turbo"), None);
    }

    #[test]
    fn valid_interface_name_rejects_empty_and_shell_metacharacters() {
        assert!(valid_interface_name("eth0"));
        assert!(valid_interface_name("wlan0.100"));
        assert!(valid_interface_name("veth-abc_1:2"));
        assert!(!valid_interface_name(""));
        assert!(!valid_interface_name("   "));
        assert!(!valid_interface_name("eth0; rm -rf /"));
        assert!(!valid_interface_name("eth0 && echo pwned"));
        assert!(!valid_interface_name("eth0/../etc"));
    }

    #[test]
    fn normalized_trims_lowercases_and_converts_dashes() {
        assert_eq!(normalized("  High-Risk "), "high_risk");
        assert_eq!(normalized("Already_Snake"), "already_snake");
    }

    #[test]
    fn dry_run_report_formats_action_label_and_outcome() {
        let report = dry_run_report(&RuleAction::Notify {
            severity: "info".to_string(),
        });
        assert_eq!(report.outcome, "dry-run");
        assert_eq!(report.action, "Notify(info)");
        assert!(report.message.contains("SGX_RULES_DRYRUN"));
    }

    #[test]
    fn downgraded_report_formats_action_label_and_outcome() {
        let report = downgraded_report(&RuleAction::LockTransport);
        assert_eq!(report.outcome, "downgraded");
        assert_eq!(report.action, "LockTransport");
        assert!(report.message.contains("allow_destructive"));
    }

    #[test]
    fn write_lock_file_creates_parent_dirs_and_writes_interface() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("subdir").join("node.lock");
        write_lock_file(&path, "eth0").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "eth0\n");
    }

    #[test]
    fn resolve_pa_cli_path_prefers_env_override_when_file_exists() {
        let _guard = env_guard();
        let dir = tempfile::tempdir().unwrap();
        let fake_cli = dir.path().join("sgx-pa-cli");
        make_executable(&fake_cli, "#!/bin/sh\nexit 0\n");

        std::env::set_var("SGX_PA_CLI_PATH", &fake_cli);
        let resolved = resolve_pa_cli_path();
        std::env::remove_var("SGX_PA_CLI_PATH");

        assert_eq!(resolved, Some(fake_cli));
    }

    #[test]
    fn resolve_pa_cli_path_ignores_override_pointing_to_missing_file() {
        let _guard = env_guard();
        std::env::set_var(
            "SGX_PA_CLI_PATH",
            "/nonexistent/path/sgx-pa-cli-does-not-exist",
        );
        let resolved = resolve_pa_cli_path();
        std::env::remove_var("SGX_PA_CLI_PATH");

        assert_ne!(
            resolved,
            Some(std::path::PathBuf::from(
                "/nonexistent/path/sgx-pa-cli-does-not-exist"
            ))
        );
    }

    #[test]
    fn raise_alert_writes_to_threat_state_dir_and_reports_executed() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        let rule = test_rule();
        let event = RuleEvent::sample_threat("node-1");

        let report = raise_alert(&config, "node-1", &rule, &event, "critical");
        assert_eq!(report.outcome, "executed");
        assert!(config.threat_state_dir.join("alerts.jsonl").exists());
    }

    #[test]
    fn raise_alert_falls_back_to_high_severity_for_unknown_value() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        let rule = test_rule();
        let event = RuleEvent::sample_threat("node-1");

        let report = raise_alert(&config, "node-1", &rule, &event, "not-a-real-severity");
        assert_eq!(report.outcome, "executed");
        assert!(report.action.contains("high"));
    }

    #[test]
    fn raise_alert_reports_failed_when_state_dir_cannot_be_created() {
        let dir = tempfile::tempdir().unwrap();
        // A regular file where a directory is expected makes create_dir_all fail.
        let blocker_file = dir.path().join("blocker_file");
        std::fs::write(&blocker_file, b"x").unwrap();
        let mut config = test_config(dir.path());
        config.threat_state_dir = blocker_file.join("nested");
        let rule = test_rule();
        let event = RuleEvent::sample_threat("node-1");

        let report = raise_alert(&config, "node-1", &rule, &event, "high");
        assert_eq!(report.outcome, "failed");
    }

    #[test]
    fn notify_builds_executed_report_with_severity_label() {
        let rule = test_rule();
        let event = RuleEvent::sample_threat("node-1");
        let report = notify("node-1", &rule, &event, "critical");
        assert_eq!(report.outcome, "executed");
        assert_eq!(report.action, "Notify(critical)");
    }

    #[tokio::test]
    async fn block_ip_reports_failed_when_event_has_no_source_ip() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        let event = RuleEvent::GeofenceEntry {
            node_id: "n".to_string(),
            device_id: "d".to_string(),
            zone: "z".to_string(),
        };
        let report = block_ip(&config, "node-1", &event, Some(60)).await;
        assert_eq!(report.outcome, "failed");
        assert!(report.message.contains("no source IP"));
    }

    #[tokio::test]
    async fn block_ip_reports_failed_for_unparseable_source_ip() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        let event = RuleEvent::DeviceDiscovered {
            node_id: "n".to_string(),
            device_id: "d".to_string(),
            ip: "not-an-ip".to_string(),
            status: "unauthorized".to_string(),
            ports: vec![],
            zone: None,
        };
        let report = block_ip(&config, "node-1", &event, None).await;
        assert_eq!(report.outcome, "failed");
    }

    #[tokio::test]
    async fn run_scan_reports_failed_for_invalid_intensity() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        let report = run_scan(&config, "node-1", "warp-speed").await;
        assert_eq!(report.outcome, "failed");
        assert!(report.message.contains("invalid scan intensity"));
    }

    #[tokio::test]
    async fn revoke_did_reports_failed_when_event_has_no_target_did() {
        let rule = test_rule();
        let event = RuleEvent::sample_threat("node-1");
        let report = revoke_did("node-1", &rule, &event).await;
        assert_eq!(report.outcome, "failed");
        assert!(report.message.contains("no DID"));
    }

    #[tokio::test]
    async fn lock_transport_reports_failed_when_interface_not_configured() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        let report = lock_transport(&config, "node-1").await;
        assert_eq!(report.outcome, "failed");
        assert!(report.message.contains("SGX_RULES_LOCK_INTERFACE"));
    }

    #[tokio::test]
    async fn lock_transport_reports_failed_for_invalid_interface_name() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = test_config(dir.path());
        config.transport_lock_interface = Some("eth0; rm -rf /".to_string());
        let report = lock_transport(&config, "node-1").await;
        assert_eq!(report.outcome, "failed");
        assert!(report.message.contains("invalid interface name"));
    }

    #[tokio::test]
    async fn lock_transport_writes_lock_file_for_valid_interface() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = test_config(dir.path());
        config.transport_lock_interface = Some("eth0".to_string());
        let report = lock_transport(&config, "node-1").await;
        assert_eq!(report.outcome, "executed");
        assert!(config.transport_lock_dir.join("node-1.lock").exists());
        let content =
            std::fs::read_to_string(config.transport_lock_dir.join("node-1.lock")).unwrap();
        assert_eq!(content, "eth0\n");
    }

    #[tokio::test]
    async fn emergency_key_rotation_reports_executed_on_success() {
        let _guard = env_guard();
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("sgx-pa-cli");
        make_executable(&script, "#!/bin/sh\necho rotated\nexit 0\n");

        std::env::set_var("SGX_PA_CLI_PATH", &script);
        let report = emergency_key_rotation("node-1").await;
        std::env::remove_var("SGX_PA_CLI_PATH");

        assert_eq!(report.outcome, "executed");
        assert_eq!(report.message, "rotated");
    }

    #[tokio::test]
    async fn emergency_key_rotation_reports_failed_on_nonzero_exit() {
        let _guard = env_guard();
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("sgx-pa-cli");
        make_executable(&script, "#!/bin/sh\necho boom 1>&2\nexit 1\n");

        std::env::set_var("SGX_PA_CLI_PATH", &script);
        let report = emergency_key_rotation("node-1").await;
        std::env::remove_var("SGX_PA_CLI_PATH");

        assert_eq!(report.outcome, "failed");
        assert_eq!(report.message, "boom");
    }

    #[tokio::test]
    async fn emergency_key_rotation_reports_failed_when_cli_not_found() {
        let _guard = env_guard();
        std::env::remove_var("SGX_PA_CLI_PATH");
        // This assumes the sandbox has no real `sgx-pa-cli` on PATH or in the
        // hardcoded fallback directories, which holds for standard dev/CI images.
        let report = emergency_key_rotation("node-1").await;
        assert_eq!(report.outcome, "failed");
        assert_eq!(report.message, "sgx-pa-cli not found");
    }

    #[tokio::test]
    async fn execute_action_dispatches_every_variant_via_safe_paths() {
        let _guard = env_guard();
        std::env::remove_var("SGX_PA_CLI_PATH");

        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        let rule = test_rule();
        // No source IP and no target DID, so BlockIp/RevokeDid take their safe
        // early-return branches instead of touching a real firewall or CRL signer.
        let event = RuleEvent::GeofenceEntry {
            node_id: "n".to_string(),
            device_id: "d".to_string(),
            zone: "z".to_string(),
        };

        let raise = execute_action(
            &config,
            "node-1",
            &rule,
            &event,
            &RuleAction::RaiseAlert {
                severity: "high".to_string(),
            },
        )
        .await;
        assert_eq!(raise.outcome, "executed");

        let notify_report = execute_action(
            &config,
            "node-1",
            &rule,
            &event,
            &RuleAction::Notify {
                severity: "info".to_string(),
            },
        )
        .await;
        assert_eq!(notify_report.outcome, "executed");

        let block = execute_action(
            &config,
            "node-1",
            &rule,
            &event,
            &RuleAction::BlockIp { ttl_secs: None },
        )
        .await;
        assert_eq!(block.outcome, "failed");

        let scan = execute_action(
            &config,
            "node-1",
            &rule,
            &event,
            &RuleAction::RunScan {
                intensity: "invalid".to_string(),
            },
        )
        .await;
        assert_eq!(scan.outcome, "failed");

        let revoke = execute_action(&config, "node-1", &rule, &event, &RuleAction::RevokeDid).await;
        assert_eq!(revoke.outcome, "failed");

        let lock =
            execute_action(&config, "node-1", &rule, &event, &RuleAction::LockTransport).await;
        assert_eq!(lock.outcome, "failed");

        let rotation = execute_action(
            &config,
            "node-1",
            &rule,
            &event,
            &RuleAction::EmergencyKeyRotation,
        )
        .await;
        assert_eq!(rotation.outcome, "failed");
    }
}
