//! Policy-driven open-port posture checks.
//!
//! This module is deliberately separate from telemetry anomaly scoring. A port
//! number is not an anomaly and has no fixed vulnerability severity: the final
//! posture combines the configured typical risk, scan CVSS evidence, and asset
//! exposure/configuration context.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AssetSecurityContext {
    #[serde(default)]
    pub network_exposure: String,
    #[serde(default)]
    pub transport_security: String,
    #[serde(default)]
    pub authentication: String,
    #[serde(default)]
    pub patch_status: String,
    #[serde(default)]
    pub service_required: Option<bool>,
    #[serde(default)]
    pub business_impact: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InventoryDevice {
    #[serde(default)]
    pub node: Option<String>,
    pub ip: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub security_context: AssetSecurityContext,
    #[serde(default)]
    pub open_ports: Vec<InventoryPort>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InventoryPort {
    pub port: u16,
    pub protocol: String,
    #[serde(default)]
    pub service: String,
    #[serde(default)]
    pub product_version: Option<String>,
    #[serde(default)]
    pub scripts: Vec<serde_json::Value>,
    #[serde(default)]
    pub security_context: Option<AssetSecurityContext>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub enum PortSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl PortSeverity {
    fn raised(self, count: usize) -> Self {
        match (self, count) {
            (Self::Low, 0) | (Self::Medium, 0) | (Self::High, 0) | (Self::Critical, _) => self,
            (Self::Low, 1) => Self::Medium,
            (Self::Low, 2) => Self::High,
            (Self::Low, _) => Self::Critical,
            (Self::Medium, 1) => Self::High,
            (Self::Medium, _) => Self::Critical,
            (Self::High, _) => Self::Critical,
        }
    }
}

impl fmt::Display for PortSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        })
    }
}

const DEFAULT_RULES_PATH: &str = "config/port_security_rules.json";

#[derive(Debug, Clone, Deserialize)]
pub struct PortRule {
    pub name: String,
    pub ports: Vec<u16>,
    #[serde(default)]
    pub protocols: Vec<String>,
    pub severity: PortSeverity,
    pub reason: String,
    pub recommendation: String,
    pub proposed_action: String,
    #[serde(default)]
    pub risk_tags: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PortRuleSet {
    pub version: u32,
    pub rules: Vec<PortRule>,
}

impl PortRuleSet {
    pub fn load_or_default(path: impl AsRef<Path>) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .filter(|r: &Self| r.version == 1 && !r.rules.is_empty())
            .unwrap_or_else(Self::builtin_default)
    }
    pub fn matching_rule(&self, port: u16, protocol: &str) -> Option<&PortRule> {
        self.rules.iter().find(|r| {
            (r.ports.is_empty() || r.ports.contains(&port))
                && (r.protocols.is_empty()
                    || r.protocols.iter().any(|p| p.eq_ignore_ascii_case(protocol)))
        })
    }
    fn builtin_default() -> Self {
        Self { version: 1, rules: vec![PortRule {
        name: "generic_open_service".into(), ports: vec![], protocols: vec![], severity: PortSeverity::Medium,
        reason: "An open service needs an owner, a business purpose, and restricted exposure.".into(),
        recommendation: "Review {service} on {protocol}/{port}; confirm it is required and restrict access to approved peers.".into(),
        proposed_action: "review_and_restrict_service".into(), risk_tags: vec![],
    }] }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PortRecommendation {
    pub message: String,
    pub proposed_action: String,
    pub automatic_execution: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortFinding {
    pub source: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub asset_status: String,
    pub port: u16,
    pub protocol: String,
    pub service: String,
    pub product_version: Option<String>,
    pub max_cvss: Option<f64>,
    pub typical_severity: PortSeverity,
    pub severity: PortSeverity,
    pub severity_source: String,
    pub severity_reason: String,
    pub severity_adjustments: Vec<String>,
    pub asset_context: AssetSecurityContext,
    pub recommendation: PortRecommendation,
}

#[derive(Debug, Serialize)]
pub struct PortSecurityReport {
    pub schema_version: u32,
    pub purpose: String,
    pub source_inventory: String,
    pub findings: Vec<PortFinding>,
}

pub fn load_inventory(path: impl AsRef<Path>) -> anyhow::Result<Vec<InventoryDevice>> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}
pub fn finding_from_inventory(d: &InventoryDevice, p: &InventoryPort) -> PortFinding {
    let rules = PortRuleSet::load_or_default(DEFAULT_RULES_PATH);
    finding_from_inventory_with_rules(d, p, &rules)
}
pub fn finding_from_inventory_with_rules(
    d: &InventoryDevice,
    p: &InventoryPort,
    rules: &PortRuleSet,
) -> PortFinding {
    let context = p
        .security_context
        .clone()
        .unwrap_or_else(|| d.security_context.clone());
    make_finding(
        "nmap_inventory",
        &d.ip,
        d.hostname.clone(),
        &d.status,
        p.port,
        &p.protocol,
        &p.service,
        p.product_version.clone(),
        max_cvss_from_vulners(&p.scripts),
        context,
        rules,
    )
}
pub fn simulated_open_port(ip: &str, port: u16, service: &str) -> PortFinding {
    let rules = PortRuleSet::load_or_default(DEFAULT_RULES_PATH);
    simulated_open_port_with_rules(ip, port, service, &rules)
}
pub fn simulated_open_port_with_rules(
    ip: &str,
    port: u16,
    service: &str,
    rules: &PortRuleSet,
) -> PortFinding {
    make_finding(
        "simulated_open_port",
        ip,
        None,
        "simulation",
        port,
        "tcp",
        service,
        None,
        None,
        AssetSecurityContext::default(),
        rules,
    )
}
pub fn save_report(report: &PortSecurityReport) -> anyhow::Result<PathBuf> {
    let root = PathBuf::from("data/port_security_reports");
    std::fs::create_dir_all(&root)?;
    let top = std::fs::read_dir(&root)?
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().to_str().map(str::to_owned))
        .filter_map(|n| n.strip_prefix("run_")?.parse::<u32>().ok())
        .max()
        .unwrap_or(0);
    let dir = root.join(format!("run_{:03}", top + 1));
    std::fs::create_dir_all(&dir)?;
    let output = dir.join("port_security_report.json");
    std::fs::write(&output, serde_json::to_string_pretty(report)?)?;
    Ok(output)
}

fn make_finding(
    source: &str,
    ip: &str,
    hostname: Option<String>,
    asset_status: &str,
    port: u16,
    protocol: &str,
    service: &str,
    product_version: Option<String>,
    max_cvss: Option<f64>,
    context: AssetSecurityContext,
    rules: &PortRuleSet,
) -> PortFinding {
    let rule = rules
        .matching_rule(port, protocol)
        .expect("policy must include a generic open-service rule");
    let typical = rule.severity;
    let (severity, source_label, reason, adjustments, recommendation) =
        classify(rule, port, protocol, service, max_cvss, &context);
    PortFinding {
        source: source.into(),
        ip: ip.into(),
        hostname,
        asset_status: asset_status.into(),
        port,
        protocol: protocol.into(),
        service: service.into(),
        product_version,
        max_cvss,
        typical_severity: typical,
        severity,
        severity_source: source_label,
        severity_reason: reason,
        severity_adjustments: adjustments,
        asset_context: context,
        recommendation,
    }
}
fn max_cvss_from_vulners(s: &[serde_json::Value]) -> Option<f64> {
    s.iter()
        .filter(|x| x.get("id").and_then(|v| v.as_str()) == Some("vulners"))
        .filter_map(|x| x.get("output").and_then(|v| v.as_str()))
        .flat_map(|x| x.split_whitespace())
        .filter_map(|x| x.parse::<f64>().ok())
        .filter(|x| (0.0..=10.0).contains(x))
        .max_by(|a, b| a.total_cmp(b))
}

fn classify(
    rule: &PortRule,
    port: u16,
    protocol: &str,
    service: &str,
    cvss: Option<f64>,
    ctx: &AssetSecurityContext,
) -> (
    PortSeverity,
    String,
    String,
    Vec<String>,
    PortRecommendation,
) {
    if let Some(v) = cvss {
        let s = if v >= 9.0 {
            PortSeverity::Critical
        } else if v >= 7.0 {
            PortSeverity::High
        } else if v >= 4.0 {
            PortSeverity::Medium
        } else {
            PortSeverity::Low
        };
        return (s,"nmap_vulners_cvss".into(),format!("Nmap vulners reported maximum CVSS {v:.1}; CVSS evidence takes priority over a typical port label."),vec![],PortRecommendation{message:format!("{service} on {protocol}/{port} has scan evidence of a {s} vulnerability (CVSS {v:.1}). Restrict access immediately and patch or disable it after approval."),proposed_action:"restrict_access_and_patch".into(),automatic_execution:false});
    }
    let mut adjustments = Vec::new();
    let mut raises = 0usize;
    if eq(&ctx.network_exposure, "public") {
        raises += 1;
        adjustments
            .push("Internet-facing exposure increases reachability by untrusted users.".into());
    }
    if matches_any(&ctx.transport_security, &["none", "plaintext"]) && has_tag(rule, "plaintext") {
        raises += 1;
        adjustments.push(
            "Transport encryption is not enforced for a service that can carry sensitive data."
                .into(),
        );
    }
    if matches_any(&ctx.authentication, &["none", "default", "weak"]) {
        raises += 1;
        adjustments.push("Authentication is missing, default, or weak.".into());
    }
    if eq(&ctx.patch_status, "outdated") {
        raises += 1;
        adjustments.push("The service is marked outdated and needs patch review.".into());
    }
    if matches_any(&ctx.business_impact, &["high", "critical"]) {
        raises += 1;
        adjustments.push("The asset has high business impact.".into());
    }
    let severity = rule.severity.raised(raises);
    let base_message = template(&rule.recommendation, service, protocol, port);
    let (message, action) = if ctx.service_required == Some(false) {
        (format!("{base_message} The asset record says this service is not required: disable it and block the port after owner approval."),"disable_unrequired_service".into())
    } else if severity > rule.severity {
        (format!("{base_message} Because of the recorded exposure/configuration, prioritize restricting access and correcting the listed controls."),rule.proposed_action.clone())
    } else {
        (base_message, rule.proposed_action.clone())
    };
    (
        severity,
        format!("policy_rule:{}", rule.name),
        rule.reason.clone(),
        adjustments,
        PortRecommendation {
            message,
            proposed_action: action,
            automatic_execution: false,
        },
    )
}
fn template(t: &str, s: &str, p: &str, n: u16) -> String {
    t.replace("{service}", s)
        .replace("{protocol}", p)
        .replace("{port}", &n.to_string())
}
fn eq(v: &str, w: &str) -> bool {
    v.eq_ignore_ascii_case(w)
}
fn matches_any(v: &str, values: &[&str]) -> bool {
    values.iter().any(|x| eq(v, x))
}
fn has_tag(rule: &PortRule, tag: &str) -> bool {
    rule.risk_tags.iter().any(|x| eq(x, tag))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cvss_evidence_overrides_typical_label() {
        let r = PortRuleSet::builtin_default();
        let f = make_finding(
            "t",
            "x",
            None,
            "t",
            22,
            "tcp",
            "ssh",
            None,
            Some(9.8),
            AssetSecurityContext::default(),
            &r,
        );
        assert_eq!(f.severity, PortSeverity::Critical);
    }
    #[test]
    fn public_plaintext_telnet_remains_critical() {
        let r = PortRuleSet {
            version: 1,
            rules: vec![PortRule {
                name: "telnet".into(),
                ports: vec![23],
                protocols: vec!["tcp".into()],
                severity: PortSeverity::Critical,
                reason: "plain".into(),
                recommendation: "disable {service}".into(),
                proposed_action: "disable".into(),
                risk_tags: vec!["plaintext".into()],
            }],
        };
        let f = make_finding(
            "t",
            "x",
            None,
            "t",
            23,
            "tcp",
            "telnet",
            None,
            None,
            AssetSecurityContext {
                network_exposure: "public".into(),
                transport_security: "none".into(),
                authentication: "none".into(),
                patch_status: "outdated".into(),
                service_required: Some(false),
                business_impact: "high".into(),
            },
            &r,
        );
        assert_eq!(f.severity, PortSeverity::Critical);
        assert!(!f.severity_adjustments.is_empty());
    }
}
