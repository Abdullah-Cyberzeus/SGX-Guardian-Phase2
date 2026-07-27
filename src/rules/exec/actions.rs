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
}
