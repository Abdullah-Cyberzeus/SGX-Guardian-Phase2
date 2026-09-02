//! Alert layer (D7): the structured output of the engine, plus the
//! `AlertSink` boundary trait (standalone: stdout/file; SGX: audit log).

use serde::{Deserialize, Serialize};

use crate::roles::NodeRole;
use crate::rules::{ActionDefinition, RuleFile};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// M3 FIX: which tier's score/threshold actually decided a given alert.
/// Fusion is worst-tier-wins (max), so without this every alert was an
/// unattributed lump -- there was no way to tell whether a batch of false
/// positives came from Tier-1 (the always-on z-score baseline) or Tier-2
/// (the trained IsolationForest, when attached). engine.rs sets this to
/// whichever tier's score/threshold was actually used to decide the alert.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertTier {
    /// Tier-1 (ZScoreModel) decided this alert -- either no Tier-2 model
    /// was attached, or Tier-2 wasn't the deciding score.
    Tier1,
    /// Tier-2 (trained IsolationForestModel) decided this alert, using its
    /// own D9-calibrated threshold.
    Tier2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyAlert {
    pub ts: u64,
    pub node: String,
    /// Trusted deployment role attached by the engine; not inferred from the
    /// anomaly score and not part of the 19 model features.
    pub role: NodeRole,
    pub score: f64,
    pub confidence: f64,
    pub severity: Severity,
    pub topk: Vec<String>,
    pub reason: String,
    pub recommendation: String,
    /// Optional structured follow-up for a future policy/enforcement layer.
    /// The engine only reports it; it never performs a blocking action itself.
    pub action: Option<ActionDefinition>,
    /// M3 FIX: which tier decided this alert (see `AlertTier`). Lets false
    /// positives be counted/localised per tier instead of staying an
    /// unattributed lump under max-fusion.
    pub tier: AlertTier,
}

/// M2 + M3 FIX: summarize a batch of alerts for reporting -- per-tier
/// counts (M3: "you cannot fix what you cannot localise") and an
/// alerts/hour rate (M2: a raw percentage like "1.5% FPR" can undersell
/// how unusable an alert volume actually is; e.g. ~110 alerts in a 2-hour
/// file is ~55 alerts/hour per node, which reads very differently).
#[derive(Debug, Clone, Copy, Default)]
pub struct AlertSummary {
    pub total: usize,
    pub tier1_count: usize,
    pub tier2_count: usize,
    pub alerts_per_hour: f64,
}

/// `window_ms` is the total duration (in the same clock as `ts`, e.g. the
/// span of the input file being replayed) the alerts were drawn from.
pub fn summarize_alerts(alerts: &[AnomalyAlert], window_ms: u64) -> AlertSummary {
    let total = alerts.len();
    let tier1_count = alerts.iter().filter(|a| a.tier == AlertTier::Tier1).count();
    let tier2_count = alerts.iter().filter(|a| a.tier == AlertTier::Tier2).count();
    let hours = (window_ms as f64) / (1000.0 * 60.0 * 60.0);
    let alerts_per_hour = if hours > 0.0 {
        total as f64 / hours
    } else {
        0.0
    };
    AlertSummary {
        total,
        tier1_count,
        tier2_count,
        alerts_per_hour,
    }
}

pub trait AlertSink: Send + Sync {
    fn emit(&self, alert: AnomalyAlert);
}

/// Standalone sink: prints alerts to stdout as JSON.
pub struct StdoutSink;

impl AlertSink for StdoutSink {
    fn emit(&self, alert: AnomalyAlert) {
        match serde_json::to_string(&alert) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("failed to serialize alert: {e}"),
        }
    }
}

// =============================================================================
// D7: severity banding, reason text, recommendation text.
//
// This module knows nothing about *why* an anomaly is happening (no packet
// contents, no IPs, no attacker identity -- this system only ever sees
// telemetry numbers). What it CAN do is say which features drove the score
// and match that combination against known attack-pattern *signatures* from
// the synthetic generator's 5 attack types, so the alert is a useful
// starting point for a human, not a root-cause diagnosis.
// =============================================================================

/// Finer severity banding than the old 3-bucket version. Only called once
/// `value` has already cleared `alert_threshold` (0.8 by default) in
/// engine.rs, so this just splits the alerting range further.
pub fn severity_for(value: f64) -> Severity {
    if value >= 0.95 {
        Severity::Critical
    } else if value >= 0.9 {
        Severity::High
    } else if value >= 0.8 {
        Severity::Medium
    } else {
        Severity::Low // reachable if a caller ever lowers alert_threshold below 0.8
    }
}

fn plain_feature(feature: &str) -> &'static str {
    match feature {
        "net_rx_bytes_rate" => "incoming traffic volume",
        "net_tx_bytes_rate" => "outgoing traffic volume",
        "net_rx_pkts_rate" => "incoming packet rate",
        "net_tx_pkts_rate" => "outgoing packet rate",
        "conn_rate" => "new connection rate",
        "nebula_mbps" => "overlay bandwidth",
        "active_peers" => "active peer count",
        "relay_ratio" => "relay usage ratio",
        "relay_bytes_rate" => "relay traffic volume",
        "open_fds" => "open connection/file count",
        "load1" => "system workload",
        "cpu_util_pct" => "CPU usage",
        "mem_used_pct" => "memory usage",
        "cot_switches_rate" => "context-switch activity",
        "cot_latency_avg_ms" => "operation latency",
        "policy_event_rate" => "policy-change activity",
        "attest_rate" => "attestation activity",
        "proto_violation_rate" => "invalid protocol-message rate",
        "error_rate" => "error rate",
        _ => "telemetry value",
    }
}

fn has_any(topk: &[String], names: &[&str]) -> bool {
    topk.iter().any(|feature| names.contains(&feature.as_str()))
}

fn observed_areas(topk: &[String]) -> Vec<&'static str> {
    let mut areas = Vec::new();
    if has_any(
        topk,
        &[
            "net_rx_bytes_rate",
            "net_tx_bytes_rate",
            "net_rx_pkts_rate",
            "net_tx_pkts_rate",
            "conn_rate",
        ],
    ) {
        areas.push("network activity");
    }
    if has_any(
        topk,
        &[
            "nebula_mbps",
            "active_peers",
            "relay_ratio",
            "relay_bytes_rate",
        ],
    ) {
        areas.push("peer or relay activity");
    }
    if has_any(
        topk,
        &[
            "cpu_util_pct",
            "mem_used_pct",
            "open_fds",
            "load1",
            "cot_switches_rate",
            "cot_latency_avg_ms",
        ],
    ) {
        areas.push("system resource activity");
    }
    if has_any(
        topk,
        &[
            "policy_event_rate",
            "attest_rate",
            "proto_violation_rate",
            "error_rate",
        ],
    ) {
        areas.push("security or protocol activity");
    }
    if areas.is_empty() {
        areas.push("telemetry activity");
    }
    areas
}

fn join_words(words: &[&str]) -> String {
    match words {
        [] => String::new(),
        [one] => (*one).to_string(),
        [first, second] => format!("{first} and {second}"),
        _ => format!(
            "{} and {}",
            words[..words.len() - 1].join(", "),
            words[words.len() - 1]
        ),
    }
}

fn suggested_actions(topk: &[String]) -> Vec<&'static str> {
    let mut actions = Vec::new();
    if has_any(
        topk,
        &[
            "net_rx_bytes_rate",
            "net_tx_bytes_rate",
            "net_rx_pkts_rate",
            "net_tx_pkts_rate",
            "conn_rate",
        ],
    ) {
        actions.push("review recent peers and connection growth; apply a temporary rate limit only if the traffic is not expected");
    }
    if has_any(
        topk,
        &[
            "nebula_mbps",
            "active_peers",
            "relay_ratio",
            "relay_bytes_rate",
        ],
    ) {
        actions.push("check overlay peer status and relay connectivity");
    }
    if has_any(
        topk,
        &[
            "cpu_util_pct",
            "mem_used_pct",
            "open_fds",
            "load1",
            "cot_switches_rate",
            "cot_latency_avg_ms",
        ],
    ) {
        actions.push("check running processes, open connections, and node resource usage");
    }
    if has_any(
        topk,
        &[
            "policy_event_rate",
            "attest_rate",
            "proto_violation_rate",
            "error_rate",
        ],
    ) {
        actions
            .push("review policy, attestation, and protocol/audit logs for the same time window");
    }
    if actions.is_empty() {
        actions.push("review the node telemetry and recent operational changes");
    }
    actions
}

/// A stable incident class for alert de-duplication.  Unlike the full
/// (and often changing) top-k list, this remains the same during one
/// port-scan/flood/resource/protocol incident.  A different class is still
/// allowed to alert while this class is cooling down.
pub fn incident_category(topk: &[String]) -> String {
    incident_category_with_rules(topk, &RuleFile::builtin_default())
}

/// Same category lookup, but using rules loaded at runtime by the engine.
pub fn incident_category_with_rules(topk: &[String], rules: &RuleFile) -> String {
    if let Some(rule) = rules.best_match(topk) {
        return rule.name.clone();
    }

    // Unknown signals still get a stable broad class, so a changing top-k
    // cannot create a new notification every few seconds.
    if topk.iter().any(|f| {
        matches!(
            f.as_str(),
            "proto_violation_rate" | "error_rate" | "policy_event_rate"
        )
    }) {
        "generic-protocol".to_string()
    } else if topk.iter().any(|f| {
        matches!(
            f.as_str(),
            "cpu_util_pct" | "mem_used_pct" | "open_fds" | "load1"
        )
    }) {
        "generic-resource".to_string()
    } else if topk.iter().any(|f| {
        matches!(
            f.as_str(),
            "conn_rate"
                | "net_rx_bytes_rate"
                | "net_tx_bytes_rate"
                | "net_rx_pkts_rate"
                | "net_tx_pkts_rate"
                | "active_peers"
                | "relay_ratio"
                | "relay_bytes_rate"
        )
    }) {
        "generic-network".to_string()
    } else {
        "generic-telemetry".to_string()
    }
}

/// Build the human-readable `reason` string from the fused score and its
/// topk features.
pub fn build_reason(node: &str, value: f64, threshold: f64, topk: &[String]) -> String {
    let evidence = if topk.is_empty() {
        "no standout features recorded".to_string()
    } else {
        topk.iter()
            .map(|feature| plain_feature(feature))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let areas = join_words(&observed_areas(topk));
    format!("node {node}: unusual {areas}; score {value:.3} (threshold {threshold:.3}). Evidence: {evidence}.")
}

/// Build a dynamic, evidence-based recommendation. The text comes from the
/// actual top features, not a guessed/hardcoded attack family.
pub fn build_recommendation(topk: &[String]) -> String {
    build_recommendation_for_role(topk, NodeRole::Unknown)
}

/// Same evidence-based recommendation, with role-aware operational guidance.
/// It never treats a normal anomaly score as proof of unauthorised behaviour.
pub fn build_recommendation_for_role(topk: &[String], role: NodeRole) -> String {
    let evidence = if topk.is_empty() {
        "no single telemetry value stood out".to_string()
    } else {
        topk.iter()
            .map(|feature| plain_feature(feature))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let areas = join_words(&observed_areas(topk));
    let actions = suggested_actions(topk).join("; then ");
    let role_note = match role {
        NodeRole::Admin if has_any(topk, &["policy_event_rate", "attest_rate", "proto_violation_rate", "error_rate"]) =>
            " If this coincides with approved administration, verify the change ticket and audit record.",
        NodeRole::Member if has_any(topk, &["policy_event_rate", "attest_rate", "proto_violation_rate", "error_rate"]) =>
            " Confirm that the activity is within this member node's assigned task; policy and device changes require admin approval.",
        NodeRole::Admin => " Verify whether this coincides with approved administration or maintenance.",
        NodeRole::Member => " Confirm that the activity is within this member node's assigned task.",
        NodeRole::Unknown => "",
    };
    format!("What happened: unusual {areas}. Evidence: {evidence}. Recommended action: {actions}.{role_note}")
}

/// Human text and a machine-readable action from the externally configured
/// rule set. Generic evidence-based text remains the safe fallback.
pub fn build_recommendation_with_rules(
    node: &str,
    topk: &[String],
    role: NodeRole,
    rules: &RuleFile,
) -> (String, Option<ActionDefinition>) {
    if let Some(rule) = rules.best_match(topk) {
        let features = if topk.is_empty() {
            "no standout telemetry values".to_string()
        } else {
            topk.iter()
                .map(|feature| plain_feature(feature))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let text = rule
            .recommendation
            .replace("{node}", node)
            .replace("{features}", &features);
        return (
            format!("{}{}", text, role_note(topk, role)),
            rule.action.clone(),
        );
    }
    (
        build_recommendation_for_role(topk, role),
        Some(generic_investigation_action(topk)),
    )
}

/// A rule may not match every mixed or unfamiliar top-k combination. Keep
/// the downstream contract non-null while remaining safe: this is an
/// investigation request, never an automatic block/restart action.
fn generic_investigation_action(topk: &[String]) -> ActionDefinition {
    let mut candidate_actions = Vec::new();
    if has_any(
        topk,
        &[
            "net_rx_bytes_rate",
            "net_tx_bytes_rate",
            "net_rx_pkts_rate",
            "net_tx_pkts_rate",
            "conn_rate",
        ],
    ) {
        candidate_actions.push("review_network_activity");
    }
    if has_any(
        topk,
        &[
            "nebula_mbps",
            "active_peers",
            "relay_ratio",
            "relay_bytes_rate",
        ],
    ) {
        candidate_actions.push("inspect_overlay_peers");
    }
    if has_any(
        topk,
        &[
            "cpu_util_pct",
            "mem_used_pct",
            "open_fds",
            "load1",
            "cot_switches_rate",
            "cot_latency_avg_ms",
        ],
    ) {
        candidate_actions.push("inspect_node_resources");
    }
    if has_any(
        topk,
        &[
            "policy_event_rate",
            "attest_rate",
            "proto_violation_rate",
            "error_rate",
        ],
    ) {
        candidate_actions.push("review_audit_logs");
    }
    if candidate_actions.is_empty() {
        candidate_actions.push("review_node_telemetry");
    }
    ActionDefinition {
        kind: "investigate_anomaly".to_string(),
        params: serde_json::json!({
            "automatic_execution": false,
            "evidence_features": topk,
            "candidate_actions": candidate_actions,
        }),
    }
}

fn role_note(topk: &[String], role: NodeRole) -> &'static str {
    match role {
        NodeRole::Admin if has_any(topk, &["policy_event_rate", "attest_rate", "proto_violation_rate", "error_rate"]) =>
            " If this coincides with approved administration, verify the change ticket and audit record.",
        NodeRole::Member if has_any(topk, &["policy_event_rate", "attest_rate", "proto_violation_rate", "error_rate"]) =>
            " Confirm that the activity is within this member node's assigned task; policy and device changes require admin approval.",
        NodeRole::Admin => " Verify whether this coincides with approved administration or maintenance.",
        NodeRole::Member => " Confirm that the activity is within this member node's assigned task.",
        NodeRole::Unknown => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_bands_match_value() {
        assert!(matches!(severity_for(0.99), Severity::Critical));
        assert!(matches!(severity_for(0.92), Severity::High));
        assert!(matches!(severity_for(0.85), Severity::Medium));
        assert!(matches!(severity_for(0.5), Severity::Low));
    }

    #[test]
    fn network_recommendation_uses_plain_language_and_actions() {
        let topk = vec![
            "conn_rate".to_string(),
            "net_rx_pkts_rate".to_string(),
            "load1".to_string(),
        ];
        let reason = build_reason("node1", 0.9, 0.8, &topk);
        assert!(reason.contains("network activity"));
        assert!(reason.contains("new connection rate"));
        let rec = build_recommendation(&topk);
        assert!(rec.contains("What happened:"));
        assert!(rec.contains("Recommended action:"));
        assert!(rec.contains("rate limit"));
    }

    #[test]
    fn resource_recommendation_combines_actual_evidence() {
        let topk = vec!["net_rx_bytes_rate".to_string(), "cpu_util_pct".to_string()];
        let rec = build_recommendation(&topk);
        assert!(rec.contains("incoming traffic volume"));
        assert!(rec.contains("CPU usage"));
    }

    #[test]
    fn unmatched_topk_falls_back_to_generic() {
        let topk = vec!["cot_latency_avg_ms".to_string()];
        let rec = build_recommendation(&topk);
        assert!(rec.contains("operation latency"));
    }

    #[test]
    fn incident_category_is_stable_for_same_attack_family() {
        let first = vec![
            "conn_rate".to_string(),
            "net_rx_pkts_rate".to_string(),
            "load1".to_string(),
        ];
        let second = vec![
            "conn_rate".to_string(),
            "net_tx_pkts_rate".to_string(),
            "proto_violation_rate".to_string(),
        ];
        assert_eq!(incident_category(&first), "portscan-like");
        assert_eq!(incident_category(&second), "portscan-like");
    }

    #[test]
    fn incident_category_keeps_unrelated_families_separate() {
        let network = vec!["conn_rate".to_string()];
        let resource = vec!["open_fds".to_string()];
        assert_eq!(incident_category(&network), "generic-network");
        assert_eq!(incident_category(&resource), "generic-resource");
    }

    #[test]
    fn empty_topk_does_not_panic() {
        let topk: Vec<String> = vec![];
        let reason = build_reason("node1", 0.9, 0.8, &topk);
        assert!(reason.contains("no standout features"));
        let rec = build_recommendation(&topk);
        assert!(rec.contains("review the node telemetry"));
    }

    fn dummy_alert(tier: AlertTier) -> AnomalyAlert {
        AnomalyAlert {
            ts: 0,
            node: "test-node".to_string(),
            role: NodeRole::Unknown,
            score: 0.9,
            confidence: 0.9,
            severity: Severity::High,
            topk: vec![],
            reason: String::new(),
            recommendation: String::new(),
            action: None,
            tier,
        }
    }

    #[test]
    fn member_protocol_recommendation_adds_role_guidance() {
        let topk = vec!["policy_event_rate".to_string(), "error_rate".to_string()];
        let rec = build_recommendation_for_role(&topk, NodeRole::Member);
        assert!(rec.contains("member node's assigned task"));
        assert!(rec.contains("admin approval"));
    }

    #[test]
    fn shipped_recommendation_rules_load_and_template() {
        let text = std::fs::read_to_string("config/recommendation_rules.json").unwrap();
        let rules: RuleFile = serde_json::from_str(&text).unwrap();
        rules.validate().unwrap();
        let topk = vec!["conn_rate".to_string(), "net_rx_pkts_rate".to_string()];
        let (text, action) =
            build_recommendation_with_rules("nodeA", &topk, NodeRole::Unknown, &rules);
        assert!(text.contains("nodeA"));
        assert!(text.contains("new connection rate"));
        assert_eq!(action.unwrap().kind, "rate_limit_peer");
    }

    #[test]
    fn generic_recommendation_still_has_safe_machine_action() {
        let rules = RuleFile::builtin_default();
        let topk = vec!["cot_latency_avg_ms".to_string(), "error_rate".to_string()];
        let (_, action) =
            build_recommendation_with_rules("nodeA", &topk, NodeRole::Unknown, &rules);
        let action = action.expect("generic recommendation must be integrable");
        assert_eq!(action.kind, "investigate_anomaly");
        assert_eq!(action.params["automatic_execution"], false);
    }

    #[test]
    fn summarize_alerts_counts_per_tier_and_rate() {
        let alerts = vec![
            dummy_alert(AlertTier::Tier1),
            dummy_alert(AlertTier::Tier2),
            dummy_alert(AlertTier::Tier2),
        ];
        // 2 hours of window -> 3 alerts / 2 hours = 1.5 alerts/hour
        let summary = summarize_alerts(&alerts, 2 * 60 * 60 * 1000);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.tier1_count, 1);
        assert_eq!(summary.tier2_count, 2);
        assert!((summary.alerts_per_hour - 1.5).abs() < 1e-9);
    }
}
