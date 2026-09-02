//! Runtime-loadable recommendation rules.  Operators can change the JSON
//! file and restart the engine without rebuilding Rust code.

use serde::{Deserialize, Serialize};

use crate::features::FEATURE_NAMES;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActionDefinition {
    pub kind: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PatternRule {
    pub name: String,
    pub signature: Vec<String>,
    #[serde(default = "default_min_overlap")]
    pub min_overlap: usize,
    #[serde(default)]
    pub severity_hint: Option<String>,
    pub recommendation: String,
    #[serde(default)]
    pub action: Option<ActionDefinition>,
}

fn default_min_overlap() -> usize {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleFile {
    pub version: u32,
    pub rules: Vec<PatternRule>,
}

impl RuleFile {
    pub fn builtin_default() -> Self {
        Self {
            version: 1,
            rules: vec![
                rule("portscan-like", &["conn_rate", "net_rx_pkts_rate", "net_tx_pkts_rate"], 2, "high", "Node {node}: possible connection scan. Evidence: {features}. Review the source peer and rate-limit new connections only if this traffic is not expected.", "rate_limit_peer"),
                rule("dos_flood-like", &["net_rx_bytes_rate", "net_tx_bytes_rate", "cpu_util_pct", "load1"], 2, "critical", "Node {node}: possible traffic flood. Evidence: {features}. Check traffic source and node load; apply a temporary traffic limit if the burst is not expected.", "rate_limit_traffic"),
                rule("resource_exhaustion-like", &["cpu_util_pct", "mem_used_pct", "open_fds", "load1"], 2, "high", "Node {node}: possible resource exhaustion. Evidence: {features}. Check processes, open connections, memory, and CPU before taking action.", "inspect_node_resources"),
                rule("proto_violation-like", &["proto_violation_rate", "error_rate"], 2, "high", "Node {node}: unusual protocol or error activity. Evidence: {features}. Review protocol, policy, and audit logs for this time window.", "review_audit_logs"),
                rule("peer_anomaly-like", &["active_peers", "relay_ratio", "relay_bytes_rate"], 2, "medium", "Node {node}: unusual peer or relay activity. Evidence: {features}. Check peer membership and relay connectivity.", "inspect_overlay_peers"),
            ],
        }
    }

    /// Missing, malformed, or unsafe configuration must not stop scoring.
    pub fn load_or_default(path: &str) -> Self {
        match std::fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|text| serde_json::from_str::<Self>(&text).map_err(|e| e.to_string()))
            .and_then(|rules| rules.validate().map(|_| rules))
        {
            Ok(rules) => rules,
            Err(error) => {
                eprintln!("warning: recommendation rules at '{path}' are unavailable or invalid ({error}); using built-in defaults");
                Self::builtin_default()
            }
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err(format!("unsupported version {}", self.version));
        }
        if self.rules.is_empty() {
            return Err("rules must not be empty".to_string());
        }
        for rule in &self.rules {
            if rule.name.trim().is_empty() {
                return Err("rule name must not be empty".to_string());
            }
            if rule.signature.is_empty() {
                return Err(format!("rule '{}' has an empty signature", rule.name));
            }
            if rule.min_overlap == 0 || rule.min_overlap > rule.signature.len() {
                return Err(format!("rule '{}' has invalid min_overlap", rule.name));
            }
            if rule.recommendation.trim().is_empty() {
                return Err(format!("rule '{}' has an empty recommendation", rule.name));
            }
            for feature in &rule.signature {
                if !FEATURE_NAMES.contains(&feature.as_str()) {
                    return Err(format!(
                        "rule '{}' uses unknown feature '{}'",
                        rule.name, feature
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn best_match<'a>(&'a self, topk: &[String]) -> Option<&'a PatternRule> {
        self.rules
            .iter()
            .map(|rule| {
                (
                    rule,
                    rule.signature
                        .iter()
                        .filter(|f| topk.iter().any(|top| top == *f))
                        .count(),
                )
            })
            .filter(|(rule, overlap)| *overlap >= rule.min_overlap)
            .max_by_key(|(_, overlap)| *overlap)
            .map(|(rule, _)| rule)
    }
}

fn rule(
    name: &str,
    signature: &[&str],
    min_overlap: usize,
    severity: &str,
    recommendation: &str,
    action: &str,
) -> PatternRule {
    PatternRule {
        name: name.to_string(),
        signature: signature.iter().map(|s| (*s).to_string()).collect(),
        min_overlap,
        severity_hint: Some(severity.to_string()),
        recommendation: recommendation.to_string(),
        action: Some(ActionDefinition {
            kind: action.to_string(),
            params: serde_json::json!({}),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn builtin_rules_validate() {
        assert!(RuleFile::builtin_default().validate().is_ok());
    }
    #[test]
    fn unknown_feature_is_rejected() {
        let mut rules = RuleFile::builtin_default();
        rules.rules[0].signature.push("not_a_feature".to_string());
        assert!(rules.validate().is_err());
    }
}
