//! Recall/FPR report in the D8/D9 solution doc's format: per-attack-type
//! ROW-LEVEL recall %, and overall normal FPR %, for the FUSED engine
//! (Tier-1 calibrated z-score OR Tier-2 calibrated Isolation Forest).
//!
//! WHY THIS IS A SEPARATE TOOL FROM run_d5_d6_d7_demo.rs:
//! That demo reports "attack window CAUGHT/MISSED" (did at least one ALERT
//! fire during the window) and counts EMITTED alerts, which are throttled
//! by the engine's 60s cooldown -- correct for "how noisy would this be
//! live", wrong for "how good is the model's per-row detection". A 300-row
//! attack window that fires one alert then cools down for the rest is
//! CAUGHT (window-level), but that tells you nothing about what fraction
//! of the window's rows the model would have flagged if asked every time.
//!
//! This tool instead asks, independently for EVERY row: "does this row's
//! fused score clear its own tier's calibrated threshold?" -- exactly
//! evaluate.py's philosophy (report the raw detection rate, never gate it
//! by an alerting/UX mechanism like cooldown). That is what the D8/D9
//! solution doc's numbers (portscan 90.7%, dos_flood 94.2%, etc.) are.
//!
//! USAGE:
//!   cargo run --example run_recall_report -- [csv_path] [forest_json_path]
//!   csv_path         : e.g. data/nodeA_attacks.csv (default)
//!   forest_json_path : e.g. data/nodeA_forest.json (default: inferred from
//!                      the CSV's node column, same convention as
//!                      run_d5_d6_d7_demo.rs's forest_path_for_node)
//!
//! Examples:
//!   cargo run --example run_recall_report -- data/nodeA_attacks.csv
//!   cargo run --example run_recall_report -- data/nodeB_attacks.csv data/nodeB_forest.json

use std::collections::BTreeMap;

use sgx_anomaly_engine::features::FeatureExtractor;
use sgx_anomaly_engine::model::{AnomalyModel, IsolationForestModel, ZScoreModel};
use sgx_anomaly_engine::telemetry::csv_replay::CsvReplaySource;
use sgx_anomaly_engine::TelemetrySource;

fn forest_path_for_node(node: &str) -> anyhow::Result<&'static str> {
    match node {
        "nodeA" => Ok("data/nodeA_forest.json"),
        "nodeB" => Ok("data/nodeB_forest.json"),
        "nodeC" => Ok("data/nodeC_forest.json"),
        _ => Err(anyhow::anyhow!(
            "no D9 forest configured for node '{node}' -- pass the forest JSON path explicitly as the 2nd arg"
        )),
    }
}

/// (node, label) per row, same shape run_d5_d6_d7_demo.rs uses.
fn read_ground_truth(path: &str) -> anyhow::Result<Vec<(String, String)>> {
    let content = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in content.lines().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split(',').collect();
        out.push((cols[1].to_string(), cols[2].to_string())); // (node, label)
    }
    Ok(out)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let csv_path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "data/nodeA_attacks.csv".to_string());

    let ground_truth = read_ground_truth(&csv_path)?;
    let node_name = ground_truth
        .first()
        .map(|(n, _)| n.clone())
        .unwrap_or_else(|| "demo-node".into());

    let forest_path = match args.get(2) {
        Some(p) => p.clone(),
        None => forest_path_for_node(&node_name)?.to_string(),
    };

    let tier2 = IsolationForestModel::load_from_json(&forest_path)?;
    // Same calibrated-Tier-1 fix as run_d5_d6_d7_demo.rs: pull
    // z_alert_threshold out of the SAME forest JSON export_model.py wrote
    // it into. Without this, Tier-1 runs uncalibrated and every number
    // below would silently be wrong (see model.rs's tier1_z_alert_threshold
    // doc comment for the full story).
    let tier1_z_alert_threshold = tier2.tier1_z_alert_threshold();
    if tier1_z_alert_threshold.is_none() {
        println!(
            "WARNING: {forest_path} has no z_alert_threshold -- Tier-1 will be scored \
             UNCALIBRATED, so recall/FPR numbers below will NOT match the calibrated \
             pipeline. Re-run export_model.py (current version) to fix."
        );
    }
    let tier1 = match tier1_z_alert_threshold {
        Some(z) => ZScoreModel::new(3.0).with_z_alert_threshold(z),
        None => ZScoreModel::new(3.0),
    };
    let tier2_raw_threshold = tier2.raw_alert_threshold();

    let mut source = CsvReplaySource::load(&csv_path)?;
    let mut extractor = FeatureExtractor::new(0.3);

    // Per-label tallies: (total rows, rows the fused score would flag).
    // "normal" tallies double as the FPR denominator/numerator.
    let mut tallies: BTreeMap<String, (usize, usize)> = BTreeMap::new();

    for (_, label) in &ground_truth {
        tallies.entry(label.clone()).or_insert((0, 0));
    }

    // Mirrors engine.rs's tick(): fold is gated on confidence AND cooldown,
    // not just "was this row flagged". `min_confidence`/`cooldown_ms` match
    // EngineConfig::default(). Without the confidence gate specifically,
    // row 1's zero-baseline (count=0, mean=0, std floored) spuriously
    // clears Tier-1's raw threshold for almost any nonzero input, fold
    // gets skipped, the baseline stays at mean=0 forever, and every
    // subsequent row ALSO spuriously clears that still-zero baseline --
    // a permanent 100%-FPR lockout with nothing to do with real model
    // quality (this was caught by a first run of this tool reporting
    // 100% FPR/recall everywhere -- see the fix note above main()).
    let min_confidence: f64 = 0.5;
    let cooldown_ms: u64 = 60_000;
    let mut cooldown_until: Option<u64> = None;

    for (row_idx, (_node, label)) in ground_truth.iter().enumerate() {
        let raw = source.poll().await;
        let fv = extractor.update(&raw);

        // Tier-1: score against the baseline as it stands, matching
        // model.rs's peek-then-conditionally-fold pattern (engine.rs).
        let tier1_score = tier1.peek(&node_name, &fv.0);
        let tier1_hit = match (tier1_score.raw_value, tier1_z_alert_threshold) {
            (Some(raw_z), Some(z)) => raw_z >= z,
            _ => false, // uncalibrated: don't silently count anything as a "hit"
        };

        // Tier-2: score the RAW (unsmoothed) vector, same train/serve
        // parity requirement engine.rs documents.
        let raw_vector = extractor.last_raw();
        let tier2_score = tier2.score(&node_name, &raw_vector);
        let tier2_hit = match (tier2_score.raw_value, tier2_raw_threshold) {
            (Some(raw_s), Some(t)) => raw_s >= t,
            _ => false,
        };

        // TALLY definition: pure raw-threshold crossing, no confidence or
        // cooldown gating -- this is the detection-QUALITY metric
        // (evaluate.py's philosophy: report the raw rate, never gate it
        // by an alerting/UX mechanism).
        let fused_hit = tier1_hit || tier2_hit;

        let entry = tallies.entry(label.clone()).or_insert((0, 0));
        entry.0 += 1;
        if fused_hit {
            entry.1 += 1;
        }

        // FOLD decision: replicate engine.rs's tick() exactly (confidence
        // gate + cooldown) so Tier-1's baseline evolves the same way it
        // would live. This is a SEPARATE decision from the tally above --
        // an attack row folded into "normal" would poison the baseline
        // (see engine.rs's baseline-poisoning fix), and an early
        // low-confidence spike must still fold or the cold-start lockout
        // above recurs.
        let would_alert_now = tier1_score.confidence >= min_confidence && fused_hit;
        let currently_cooling_down = matches!(cooldown_until, Some(until) if raw.ts_ms < until);
        if !currently_cooling_down && !would_alert_now {
            tier1.fold(&node_name, &fv.0);
        }
        if !currently_cooling_down && would_alert_now {
            cooldown_until = Some(raw.ts_ms + cooldown_ms);
        }

        let _ = row_idx; // not otherwise used; kept for clarity/future debugging
    }

    println!("{}", "=".repeat(78));
    println!("RECALL / FPR REPORT -- {csv_path} (node={node_name}, forest={forest_path})");
    println!("{}", "=".repeat(78));
    println!(
        "\n{:<22} {:>10} {:>10} {:>10}",
        "label", "rows", "flagged", "rate"
    );
    println!("{}", "-".repeat(56));

    let normal = tallies.get("normal").copied().unwrap_or((0, 0));
    if normal.0 > 0 {
        let fpr = 100.0 * normal.1 as f64 / normal.0 as f64;
        println!(
            "{:<22} {:>10} {:>10} {:>9.3}%  <- FPR",
            "normal", normal.0, normal.1, fpr
        );
    }
    for (label, (total, flagged)) in &tallies {
        if label == "normal" {
            continue;
        }
        let recall = if *total > 0 {
            100.0 * *flagged as f64 / *total as f64
        } else {
            0.0
        };
        let flag = if recall >= 85.0 {
            ""
        } else {
            "  (below 85% target)"
        };
        println!(
            "{:<22} {:>10} {:>10} {:>9.3}%  <- recall{flag}",
            label, total, flagged, recall
        );
    }

    println!("\nMethod: every row scored independently against each tier's calibrated");
    println!("threshold (Tier-1 z_alert_threshold OR Tier-2 threshold_raw), NOT gated by");
    println!("the engine's alert cooldown/min_confidence -- this matches evaluate.py's");
    println!("philosophy (report detection quality, not alerting-UX throttling) and is");
    println!("the same definition the D8/D9 solution doc's numbers use.");

    Ok(())
}
