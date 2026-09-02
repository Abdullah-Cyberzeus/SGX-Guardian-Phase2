//! Terminal live-stream demonstration for a senior review.
//!
//! Replays a CSV as if one telemetry sample arrives at a time.  The displayed
//! NORMAL / ANOMALY status is decided by the models, not by the CSV label.
//! The label is shown separately as `demo_label` only so the audience can
//! verify whether the detector caught the injected window.
//!
//! Usage:
//!   cargo run --example run_live_stream_demo -- data/nodeA_attacks.csv
//!   cargo run --example run_live_stream_demo -- data/nodeA_attacks.csv 1 86400 1000
//!   cargo run --example run_live_stream_demo -- data/nodeB_attacks.csv 1 86400 1000
//!   cargo run --example run_live_stream_demo -- data/demo_nodeA_portscan_live.csv 1 340 1000 --baseline-config config/baseline_lifecycle_demo_5min.json
//!   cargo run --example run_live_stream_demo -- data/demo_nodeA_portscan_90sec.csv 1 180 150 --baseline-config config/baseline_lifecycle_demo_90sec.json --demo-switch-at-row 90
//!
//! Arguments: CSV path, 1-based start row, number of rows, delay in ms.

use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

use serde::Serialize;
use sgx_anomaly_engine::alert::{build_recommendation_with_rules, severity_for};
use sgx_anomaly_engine::baseline::{BaselineKind, BaselineLifecycle, BaselineLifecycleConfig};
use sgx_anomaly_engine::features::FeatureExtractor;
use sgx_anomaly_engine::model::{AnomalyModel, IsolationForestModel, Score, ZScoreModel};
use sgx_anomaly_engine::port_security::PortFinding;
use sgx_anomaly_engine::roles::RoleRegistry;
use sgx_anomaly_engine::rules::{ActionDefinition, RuleFile};
use sgx_anomaly_engine::security_context::{CorrelatedPortContext, SecurityContextStore};
use sgx_anomaly_engine::telemetry::csv_replay::CsvReplaySource;
use sgx_anomaly_engine::TelemetrySource;

fn forest_path(node: &str) -> anyhow::Result<&'static str> {
    match node {
        "nodeA" => Ok("data/nodeA_forest.json"),
        "nodeB" => Ok("data/nodeB_forest.json"),
        _ => Err(anyhow::anyhow!(
            "no exported forest configured for node '{node}'"
        )),
    }
}

fn hit(score: &Score, raw_threshold: Option<f64>) -> bool {
    match (score.raw_value, raw_threshold) {
        (Some(raw), Some(threshold)) => raw >= threshold,
        _ => score.value >= 0.8,
    }
}

fn baseline_display_name(kind: BaselineKind) -> &'static str {
    match kind {
        BaselineKind::Global => "Global Baseline",
        BaselineKind::PerNode => "Adaptive Baseline",
    }
}

const DETAIL_LABEL_WIDTH: usize = 20;
const DETAIL_VALUE_WIDTH: usize = 72;

fn detail_border() {
    println!(
        "+----------------------+--------------------------------------------------------------------------+"
    );
}

fn wrap_detail_value(value: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();

    for word in value.split_whitespace() {
        let proposed_len =
            line.chars().count() + usize::from(!line.is_empty()) + word.chars().count();
        if proposed_len > DETAIL_VALUE_WIDTH && !line.is_empty() {
            lines.push(line);
            line = String::new();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }

    if line.is_empty() {
        lines.push("-".to_string());
    } else {
        lines.push(line);
    }
    lines
}

fn detail_row(label: &str, value: impl AsRef<str>) {
    for (index, line) in wrap_detail_value(value.as_ref()).iter().enumerate() {
        let display_label = if index == 0 { label } else { "" };
        println!("| {display_label:<DETAIL_LABEL_WIDTH$} | {line:<DETAIL_VALUE_WIDTH$} |");
    }
}

#[derive(Serialize)]
struct RecommendationRecord {
    display_row: usize,
    source_time_ms: u64,
    baseline: String,
    decision: String,
    triggering_tier: String,
    score: f64,
    /// Confidence from the same model tier whose score is displayed as
    /// `score`. There is deliberately one final confidence per row.
    confidence: f64,
    severity: String,
    evidence_features: Vec<String>,
    recommendation: String,
    proposed_action: Option<ActionDefinition>,
    port_security_context: Option<CorrelatedPortContext>,
}

#[derive(Serialize)]
struct PortSecurityContextRecord {
    display_row: usize,
    source_time_ms: u64,
    baseline: String,
    telemetry_decision: String,
    context: CorrelatedPortContext,
}

#[derive(Serialize)]
struct RecommendationRun {
    schema_version: u32,
    node: String,
    source_csv: String,
    purpose: String,
    recommendations: Vec<RecommendationRecord>,
    port_security_contexts: Vec<PortSecurityContextRecord>,
    port_inventory: Option<Vec<PortFinding>>,
}

fn recommendation_output_path(node: &str) -> anyhow::Result<PathBuf> {
    let node_dir = PathBuf::from("data/recommendation_records").join(node);
    std::fs::create_dir_all(&node_dir)?;
    let highest = std::fs::read_dir(&node_dir)?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
        .filter_map(|name| name.strip_prefix("run_")?.parse::<u32>().ok())
        .max()
        .unwrap_or(0);
    let run_dir = node_dir.join(format!("run_{:03}", highest + 1));
    std::fs::create_dir_all(&run_dir)?;
    Ok(run_dir.join("recommendations.json"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let csv_path = args
        .get(1)
        .map(String::as_str)
        .unwrap_or("data/nodeA_attacks.csv");
    let start_row: usize = args.get(2).and_then(|v| v.parse().ok()).unwrap_or(1);
    let requested_count: Option<usize> = args.get(3).and_then(|v| v.parse().ok());
    let delay_ms: u64 = args.get(4).and_then(|v| v.parse().ok()).unwrap_or(1_000);
    let baseline_config_path = args
        .iter()
        .position(|arg| arg == "--baseline-config")
        .and_then(|index| args.get(index + 1))
        .map(String::as_str);
    let demo_switch_at_row: Option<usize> = args
        .iter()
        .position(|arg| arg == "--demo-switch-at-row")
        .and_then(|index| args.get(index + 1))
        .and_then(|value| value.parse().ok());
    let row_detail = args.iter().any(|arg| arg == "--row-detail");
    let security_context_path = args
        .iter()
        .position(|arg| arg == "--security-context")
        .and_then(|index| args.get(index + 1))
        .map(String::as_str);

    if start_row == 0 || requested_count == Some(0) {
        return Err(anyhow::anyhow!("start row and count must be positive"));
    }

    let mut source = CsvReplaySource::load(csv_path)?;
    if start_row > source.len() {
        return Err(anyhow::anyhow!(
            "start row {start_row} is beyond this CSV's {} rows",
            source.len()
        ));
    }
    let available = source.len() - start_row + 1;
    let count = requested_count.unwrap_or(available).min(available);
    let node = source.peek_next_node().unwrap_or("unknown").to_string();
    let role = RoleRegistry::from_path("config/node_roles.json")?.role_for(&node);
    let security_context = security_context_path
        .map(SecurityContextStore::load)
        .transpose()?;
    let node_port_inventory = security_context
        .as_ref()
        .and_then(|store| store.posture_for_node(&node));
    let rules = RuleFile::load_or_default("config/recommendation_rules.json");
    let recommendation_path = recommendation_output_path(&node)?;
    let mut recommendation_records = Vec::new();
    let mut port_security_context_records = Vec::new();
    let mut warming_rows = 0usize;
    let mut normal_rows = 0usize;
    let mut anomaly_rows = 0usize;
    let mut global_rows = 0usize;
    let mut per_node_rows = 0usize;
    let mut tier1_alerts = 0usize;
    let mut tier2_alerts = 0usize;
    let mut fused_alerts = 0usize;
    let (mut forest, mut baseline_lifecycle) = match baseline_config_path {
        Some(path) => {
            let config = BaselineLifecycleConfig::from_path(path)?;
            let (lifecycle, model) = if demo_switch_at_row.is_some() {
                BaselineLifecycle::load_global(node.clone(), config)?
            } else {
                BaselineLifecycle::load(node.clone(), config)?
            };
            println!(
                "baseline mode: starting with {}",
                baseline_display_name(lifecycle.active_kind)
            );
            (model, Some(lifecycle))
        }
        None => (
            IsolationForestModel::load_from_json(forest_path(&node)?)?,
            None,
        ),
    };
    let mut z_threshold = forest.tier1_z_alert_threshold();
    let mut forest_threshold = forest.raw_alert_threshold();
    let tier1 = match z_threshold {
        Some(z) => ZScoreModel::new(3.0).with_z_alert_threshold(z),
        None => ZScoreModel::new(3.0),
    };
    let mut extractor = FeatureExtractor::new(0.3);

    println!("LIVE TELEMETRY STREAM DEMO");
    println!("source={csv_path}  node={node}  start_row={start_row}  delay={delay_ms}ms");
    println!("The expected label is for demo verification only; the model never receives it.");
    if !row_detail {
        println!("+------+----------+------------+-----------+----------+----------+---------+----------------------+-----------------------------------+");
        println!("| Row  | Baseline | Decision   | Trigger   | Score    | Confidence| Severity| Expected demo label  | Row summary (why / action)        |");
        println!("+------+----------+------------+-----------+----------+----------+---------+----------------------+-----------------------------------+");
    }

    // Fast-forward silently so Tier-1 gets the same normal baseline it
    // would have accumulated in a real stream before this presentation
    // window begins.
    for _ in 1..start_row {
        let raw = source.poll().await;
        let fv = extractor.update(&raw);
        let t1 = tier1.peek(&node, &fv.0);
        let t2 = forest.score(&node, &extractor.last_raw());
        // During warm-up there is no trustworthy baseline yet, so rows must
        // be folded even if their provisional score looks extreme. After
        // warm-up, never learn from a detected candidate.
        if t1.confidence < 1.0 || (!hit(&t1, z_threshold) && !hit(&t2, forest_threshold)) {
            tier1.fold(&node, &fv.0);
        }
    }

    for offset in 0..count {
        let display_row = offset + 1;
        let demo_label = source.peek_next_label().unwrap_or("end").to_string();
        let raw = source.poll().await;
        let fv = extractor.update(&raw);
        if let Some(lifecycle) = &mut baseline_lifecycle {
            // The optional row switch is presentation-only: one displayed
            // row represents one telemetry second, letting a 90-second
            // lifecycle be demonstrated at a readable terminal speed.
            let reload = if demo_switch_at_row == Some(display_row) {
                lifecycle.reload_now()
            } else {
                lifecycle.maybe_reload()
            };
            match reload {
                Ok(Some((kind, model))) => {
                    forest = model;
                    z_threshold = forest.tier1_z_alert_threshold();
                    forest_threshold = forest.raw_alert_threshold();
                    println!(
                        "\n========== BASELINE UPDATE: switched to {} at display row {} ==========\n",
                        baseline_display_name(kind),
                        display_row
                    );
                }
                Ok(None) => {}
                Err(error) => eprintln!("baseline update skipped: {error}"),
            }
        }
        let t1 = tier1.peek(&node, &fv.0);
        let t2 = forest.score(&node, &extractor.last_raw());
        let t1_hit = hit(&t1, z_threshold);
        let t2_hit = hit(&t2, forest_threshold);

        let (status, tier, chosen) = if t1.confidence < 1.0 {
            ("WARMING", "-", &t1)
        } else if t1_hit && t2_hit {
            (
                "ANOMALY",
                "T1+T2",
                if t1.value >= t2.value { &t1 } else { &t2 },
            )
        } else if t1_hit {
            ("ANOMALY", "Tier-1", &t1)
        } else if t2_hit {
            ("ANOMALY", "Tier-2", &t2)
        } else {
            ("NORMAL", "-", if t1.value >= t2.value { &t1 } else { &t2 })
        };

        let features = if chosen.topk.is_empty() {
            "-".to_string()
        } else {
            chosen.topk.join(", ")
        };
        let severity = if status == "ANOMALY" {
            format!("{:?}", severity_for(chosen.value))
        } else {
            "-".to_string()
        };
        let confidence_summary = format!("{:.0}%", chosen.confidence * 100.0);
        let baseline = baseline_lifecycle
            .as_ref()
            .map(|lifecycle| baseline_display_name(lifecycle.active_kind).to_string())
            .unwrap_or_else(|| "Fixed".to_string());
        match baseline.as_str() {
            "Global Baseline" => global_rows += 1,
            "Adaptive Baseline" => per_node_rows += 1,
            _ => {}
        }
        match status {
            "WARMING" => warming_rows += 1,
            "NORMAL" => normal_rows += 1,
            "ANOMALY" => {
                anomaly_rows += 1;
                match tier {
                    "Tier-1" => tier1_alerts += 1,
                    "Tier-2" => tier2_alerts += 1,
                    "T1+T2" => fused_alerts += 1,
                    _ => {}
                }
            }
            _ => {}
        }
        let alert_info = if status == "ANOMALY" {
            Some(build_recommendation_with_rules(
                &node,
                &chosen.topk,
                role,
                &rules,
            ))
        } else {
            None
        };
        let port_context = security_context
            .as_ref()
            .and_then(|store| store.context_for(&node, display_row, csv_path));
        if let Some(context) = &port_context {
            port_security_context_records.push(PortSecurityContextRecord {
                display_row,
                source_time_ms: raw.ts_ms,
                baseline: baseline.clone(),
                telemetry_decision: status.to_string(),
                context: context.clone(),
            });
        }
        let row_summary = match (status, &alert_info) {
            ("WARMING", _) => "learning the normal baseline".to_string(),
            ("NORMAL", _) => "within calibrated thresholds; monitor".to_string(),
            ("ANOMALY", Some((_, action))) => format!(
                "evidence: {}; action: {}",
                features,
                action
                    .as_ref()
                    .map(|action| action.kind.as_str())
                    .unwrap_or("investigate")
            ),
            _ => "model decision pending".to_string(),
        };
        if row_detail {
            let (recommendation_text, action_name) = match &alert_info {
                Some((recommendation, action)) => (
                    recommendation.as_str(),
                    action
                        .as_ref()
                        .map(|action| action.kind.as_str())
                        .unwrap_or("investigate"),
                ),
                None if status == "WARMING" => (
                    "Initial normal baseline is still being collected.",
                    "no containment action",
                ),
                None => (
                    "Telemetry is within calibrated thresholds.",
                    "continue monitoring",
                ),
            };
            let t1_raw = t1.raw_value.unwrap_or(t1.value);
            let t2_raw = t2.raw_value.unwrap_or(t2.value);
            let t1_threshold = z_threshold
                .map(|value| format!("{value:.3}"))
                .unwrap_or_else(|| "default 0.800".to_string());
            let t2_threshold = forest_threshold
                .map(|value| format!("{value:.3}"))
                .unwrap_or_else(|| "default 0.800".to_string());
            let t1_state = if t1.confidence < 1.0 {
                "WARMING - collecting node history"
            } else if t1_hit {
                "ALERT"
            } else {
                "clear"
            };
            let t2_state = if t1.confidence < 1.0 && t2_hit {
                "candidate (suppressed while Tier-1 warms)"
            } else if t2_hit {
                "ALERT"
            } else {
                "clear"
            };

            let baseline_state = if t1.confidence < 1.0 {
                "WARMING"
            } else {
                "READY"
            };
            println!("\n==========================================================");
            println!("Replay Row {display_row:03}");
            println!("==========================================================");

            println!("\nRow Information");
            detail_border();
            detail_row("Row", display_row.to_string());
            detail_row("Node", &node);
            detail_row("Time", format!("{} ms", raw.ts_ms));
            detail_row(
                "Expected label",
                format!("{demo_label} (not used by model)"),
            );
            detail_border();

            println!("\nModel Decision");
            detail_border();
            detail_row(
                "Tier-1 z-score",
                format!("{t1_raw:.3}  | threshold {t1_threshold}  | {t1_state}"),
            );
            detail_row(
                "Tier-1 confidence",
                format!("{:.1}%", t1.confidence * 100.0),
            );
            detail_row(
                "Tier-2 IF score",
                format!("{t2_raw:.3}  | threshold {t2_threshold}  | {t2_state}"),
            );
            detail_row(
                "Tier-2 confidence",
                format!("{:.1}%", t2.confidence * 100.0),
            );
            detail_row("Fused decision", format!("{status} via {tier}"));
            detail_row(
                "Final row score",
                format!(
                    "{:.3} (score of the selected triggering tier)",
                    chosen.value
                ),
            );
            detail_row(
                "Final confidence",
                format!(
                    "{:.1}% (confidence of the tier that supplied final score {:.3})",
                    chosen.confidence * 100.0,
                    chosen.value
                ),
            );
            detail_row("Severity", &severity);
            detail_border();

            println!("\nBaseline");
            detail_border();
            detail_row(
                "Model baseline",
                format!("{baseline} (Tier-2 forest and calibrated thresholds)"),
            );
            detail_row("Tier-1 status", baseline_state);
            detail_row(
                "Saved evidence",
                "Baseline JSON and model snapshot saved for this run",
            );
            detail_border();

            println!("\nRecommendation");
            println!("  Evidence: {features}");
            println!("  Advice: {recommendation_text}");
            println!("  Proposed action: {action_name}");
            println!("  Integration record: recommendation JSON saved for this run");
            if let Some(context) = &port_context {
                println!("\nPort Security Context");
                if let Some(finding) = &context.nmap_finding {
                    println!(
                        "  Nmap: {}:{}/{} ({}) | typical {} | final {}{}",
                        finding.ip,
                        finding.port,
                        finding.protocol,
                        finding.service,
                        finding.typical_severity,
                        finding.severity,
                        finding
                            .max_cvss
                            .map(|cvss| format!(" | CVSS {cvss:.1}"))
                            .unwrap_or_default(),
                    );
                    println!("  Why: {}", finding.severity_reason);
                    for adjustment in &finding.severity_adjustments {
                        println!("  Context factor: {adjustment}");
                    }
                    println!("  Port advice: {}", finding.recommendation.message);
                    println!("  Port action: {}", finding.recommendation.proposed_action);
                } else {
                    println!(
                        "  Nmap: no matching inventory record for {}:{}",
                        context.target_ip, context.target_port
                    );
                }
                if let Some(event) = &context.suricata_event {
                    println!(
                        "  Suricata: {} | {}",
                        event.event_type,
                        event.signature.as_deref().unwrap_or("no alert signature")
                    );
                    if let Some(level) = &event.severity_label {
                        println!("  Suricata severity: {level}");
                    }
                } else {
                    println!("  Suricata: no matching event record");
                }
                println!(
                    "  Correlated incident urgency: {}",
                    context.incident_urgency
                );
                println!("  Correlation: {}", context.correlation_reason);
            }
        } else {
            println!(
                "| {display_row:>4} | {:<8} | {:<10} | {:<9} | {:>7.3}  | {:<9} | {:<7} | {:<20} | {}",
                baseline, status, tier, chosen.value, confidence_summary, severity, demo_label, row_summary,
            );
        }
        if let Some((recommendation, action)) = alert_info {
            if !row_detail {
                println!("+----------------+-------------------------------------------------------------------+");
                println!("| Evidence       | {features}");
                println!("| Recommendation | {recommendation}");
                if let Some(action) = &action {
                    println!("| Proposed action| {}", action.kind);
                }
                println!("+----------------+-------------------------------------------------------------------+");
            }
            recommendation_records.push(RecommendationRecord {
                display_row,
                source_time_ms: raw.ts_ms,
                baseline,
                decision: status.to_string(),
                triggering_tier: tier.to_string(),
                score: chosen.value,
                confidence: chosen.confidence,
                severity,
                evidence_features: chosen.topk.clone(),
                recommendation,
                proposed_action: action,
                port_security_context: port_context,
            });
        }
        io::stdout().flush()?;

        // Never fold a detected candidate: it must not become "normal".
        if t1.confidence < 1.0 || (!t1_hit && !t2_hit) {
            tier1.fold(&node, &fv.0);
        }
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }

    if !row_detail {
        println!("+------+----------+------------+-----------+----------+----------+---------+----------------------+-----------------------------------+");
    }
    println!("stream finished: {count} samples displayed");
    let alert_rate = 100.0 * anomaly_rows as f64 / count as f64;
    println!("\n========================== LIVE STREAM SUMMARY ==========================");
    println!("+--------------------------+---------------------------------------------+");
    println!("| DATA PROCESSED           | {count} telemetry rows                         |");
    println!(
        "| BASELINE WARM-UP         | {warming_rows} row(s)                                  |"
    );
    println!(
        "| NORMAL                   | {normal_rows} row(s)                                  |"
    );
    println!("| ANOMALIES                | {anomaly_rows} row(s) ({alert_rate:.2}%)                         |");
    println!("+--------------------------+---------------------------------------------+");
    println!(
        "| GLOBAL BASELINE          | {global_rows} displayed row(s)                         |"
    );
    println!(
        "| ADAPTIVE BASELINE        | {per_node_rows} displayed row(s)                         |"
    );
    println!("+--------------------------+---------------------------------------------+");
    println!(
        "| TIER-1 ONLY ALERTS       | {tier1_alerts}                                           |"
    );
    println!(
        "| TIER-2 ONLY ALERTS       | {tier2_alerts}                                           |"
    );
    println!(
        "| FUSED T1+T2 ALERTS       | {fused_alerts}                                           |"
    );
    println!("+--------------------------+---------------------------------------------+");
    println!("\n======================= OPEN-PORT SUMMARY FOR {node} =======================");
    detail_border();
    match &node_port_inventory {
        Some(findings) if findings.is_empty() => {
            detail_row(
                "Port state",
                "NO - latest Nmap inventory reports no open ports",
            );
        }
        Some(findings) => {
            detail_row(
                "Port state",
                format!("OPEN - {} port(s) in latest Nmap inventory", findings.len()),
            );
            for finding in findings {
                detail_row(
                    "Open port",
                    format!(
                        "{}/{} {} | severity {}",
                        finding.port, finding.protocol, finding.service, finding.severity
                    ),
                );
                detail_row("Why", &finding.severity_reason);
                detail_row("Recommendation", &finding.recommendation.message);
                detail_row("Action", &finding.recommendation.proposed_action);
            }
        }
        None => detail_row(
            "Port state",
            "UNKNOWN - no Nmap inventory was supplied for this node",
        ),
    }
    detail_border();
    let recommendation_run = RecommendationRun {
        schema_version: 1,
        node,
        source_csv: csv_path.to_string(),
        purpose: "machine-readable anomaly and final node open-port recommendations for downstream integration".to_string(),
        recommendations: recommendation_records,
        port_security_contexts: port_security_context_records,
        port_inventory: node_port_inventory,
    };
    std::fs::write(
        &recommendation_path,
        serde_json::to_string_pretty(&recommendation_run)?,
    )?;
    println!("Recommendation JSON: {}", recommendation_path.display());
    Ok(())
}
