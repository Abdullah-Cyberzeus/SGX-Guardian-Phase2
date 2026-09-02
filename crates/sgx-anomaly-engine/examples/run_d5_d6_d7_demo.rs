//! D5 + D6 + D7 demo only (scoring -> engine loop -> alerts). Skips D1/D2/D3/D4
//! printouts -- see run_d1_to_d7_full_pipeline_demo.rs for the full walkthrough.
//!
//! USAGE:
//!   cargo run --example run_d5_d6_d7_demo -- [csv_path] [rows] [alert_threshold]
//!   csv_path        : any CSV in the standard schema (default: data/senior_test.csv)
//!   rows            : comma-separated 1-based row numbers to preview D5 scores for
//!                     (default: auto-picks 2 baseline rows + first attack window)
//!   alert_threshold : optional Tier-2 alert threshold override (otherwise
//!                     the node model's D9-calibrated threshold is used)
//!
//! Examples:
//!   cargo run --example run_d5_d6_d7_demo -- data/syn_heavy.csv
//!   cargo run --example run_d5_d6_d7_demo -- data/syn_light.csv 1,2,50,51
//!   cargo run --example run_d5_d6_d7_demo -- data/nodeA_attacks.csv 1,2 0.9

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sgx_anomaly_engine::alert::{AlertSink, AlertTier, AnomalyAlert};
use sgx_anomaly_engine::engine::{AnomalyEngine, EngineConfig};
use sgx_anomaly_engine::features::FeatureExtractor;
use sgx_anomaly_engine::model::{AnomalyModel, IsolationForestModel, ZScoreModel};
use sgx_anomaly_engine::telemetry::csv_replay::CsvReplaySource;
use sgx_anomaly_engine::TelemetrySource;

const DEFAULT_CSV_PATH: &str = "data/senior_test.csv";
const WIDTH: usize = 78;

fn forest_path_for_node(node: &str) -> anyhow::Result<&'static str> {
    match node {
        "nodeA" => Ok("data/nodeA_forest.json"),
        "nodeB" => Ok("data/nodeB_forest.json"),
        "nodeC" => Ok("data/nodeC_forest.json"),
        _ => Err(anyhow::anyhow!("no D9 forest configured for node '{node}' -- expected the CSV's node column to be nodeA/nodeB/nodeC")),
    }
}

fn section(title: &str) {
    println!("\n+{}+", "=".repeat(WIDTH - 2));
    println!("| {:<width$} |", title, width = WIDTH - 4);
    println!("+{}+", "=".repeat(WIDTH - 2));
}

fn subrule(title: &str) {
    println!("\n+{}+", "-".repeat(WIDTH - 2));
    println!("| {:<width$} |", title, width = WIDTH - 4);
    println!("+{}+", "-".repeat(WIDTH - 2));
}

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

fn first_attack_window(ground_truth: &[(String, String)]) -> Option<(String, usize)> {
    ground_truth
        .iter()
        .enumerate()
        .find(|(_, (_, label))| label != "normal")
        .map(|(i, (_, label))| (label.clone(), i + 1))
}

/// Collapse the ground-truth label column into contiguous (label, start_row,
/// end_row) windows, skipping "normal". Rows are 1-based.
fn attack_windows(ground_truth: &[(String, String)]) -> Vec<(String, usize, usize)> {
    let mut windows = Vec::new();
    let mut current: Option<(String, usize, usize)> = None;
    for (i, (_, label)) in ground_truth.iter().enumerate() {
        let row = i + 1;
        if label == "normal" {
            if let Some(w) = current.take() {
                windows.push(w);
            }
            continue;
        }
        match &mut current {
            Some((cur_label, _start, end)) if cur_label == label => *end = row,
            _ => {
                if let Some(w) = current.take() {
                    windows.push(w);
                }
                current = Some((label.clone(), row, row));
            }
        }
    }
    if let Some(w) = current.take() {
        windows.push(w);
    }
    windows
}

fn parse_rows(arg: &str) -> Vec<usize> {
    arg.split(',')
        .filter_map(|s| s.trim().parse::<usize>().ok())
        .filter(|n| *n >= 1)
        .collect()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}..", &s[..max.saturating_sub(2)])
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let csv_path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| DEFAULT_CSV_PATH.to_string());
    let rows_arg = args.get(2).cloned();
    let tier2_threshold_override: Option<f64> = args.get(3).and_then(|s| s.parse().ok());

    let ground_truth = read_ground_truth(&csv_path)?;
    let node_name = ground_truth
        .first()
        .map(|(n, _)| n.clone())
        .unwrap_or_else(|| "demo-node".into());
    let forest_path = forest_path_for_node(&node_name)?;
    let rows_to_preview = match rows_arg {
        Some(s) => parse_rows(&s),
        None => {
            let mut r = vec![1, 2];
            if let Some((_, start)) = first_attack_window(&ground_truth) {
                r.push(start);
                r.push(start + 1);
            }
            r
        }
    };
    let windows = attack_windows(&ground_truth);

    // =====================================================================
    // DATASET
    // =====================================================================
    section(&format!("DATASET: {csv_path}"));
    println!("total rows   : {}", ground_truth.len());
    println!("preview rows : {rows_to_preview:?}");

    let mut label_counts: BTreeMap<String, usize> = BTreeMap::new();
    for (_, label) in &ground_truth {
        *label_counts.entry(label.clone()).or_insert(0) += 1;
    }
    let normal_count = label_counts.get("normal").copied().unwrap_or(0);
    let attack_count: usize = label_counts
        .iter()
        .filter(|(l, _)| l.as_str() != "normal")
        .map(|(_, c)| c)
        .sum();

    subrule("Label breakdown");
    println!("  {:<22} {:>10}  {:>8}", "label", "rows", "%");
    println!("  {}", "-".repeat(44));
    println!(
        "  {:<22} {:>10}  {:>7.1}%",
        "normal",
        normal_count,
        100.0 * normal_count as f64 / ground_truth.len() as f64
    );
    for (label, count) in &label_counts {
        if label != "normal" {
            println!(
                "  {:<22} {:>10}  {:>7.1}%",
                label,
                count,
                100.0 * *count as f64 / ground_truth.len() as f64
            );
        }
    }
    println!("  {}", "-".repeat(44));
    println!("  {:<22} {:>10}", "total attack rows", attack_count);

    subrule("Labeled attack windows");
    if windows.is_empty() {
        println!("  none found -- every row is labeled \"normal\"");
    } else {
        println!(
            "  {:<8} {:<10} {:<20} {:>6}",
            "start", "end", "label", "rows"
        );
        println!("  {}", "-".repeat(48));
        for (label, start, end) in &windows {
            println!(
                "  {:<8} {:<10} {:<20} {:>6}",
                start,
                end,
                label,
                end - start + 1
            );
        }
    }

    // =====================================================================
    // D5 -- score the chosen rows with both tiers, in isolation
    // =====================================================================
    section("D5 -- MODEL LAYER (Tier-1 Z-Score + Tier-2 Isolation Forest)");
    {
        let mut source = CsvReplaySource::load(&csv_path)?;
        let mut extractor = FeatureExtractor::new(0.3);
        let tier1 = ZScoreModel::new(3.0);
        let tier2 = IsolationForestModel::load_from_json(forest_path)?;
        let node = node_name.clone();
        let max_row = *rows_to_preview.iter().max().unwrap_or(&2);

        println!(
            "  {:<6} {:<16} {:>8} {:>6}  {:<28}  {:>8} {:>6}  {:<28}",
            "row",
            "label",
            "T1 val",
            "conf",
            "T1 top features",
            "T2 val",
            "conf",
            "T2 top features"
        );
        println!("  {}", "-".repeat(WIDTH - 2));

        for row_num in 1..=max_row {
            let label = source.peek_next_label().unwrap_or("?").to_string();
            let raw = source.poll().await;
            let fv = extractor.update(&raw);
            if !extractor.warm() {
                continue;
            }
            let t1 = tier1.score(&node, &fv.0);
            let t2 = tier2.score(&node, &fv.0);
            if rows_to_preview.contains(&row_num) {
                let t1_top = truncate(&format!("{:?}", t1.topk), 28);
                let t2_top = truncate(&format!("{:?}", t2.topk), 28);
                println!(
                    "  {:<6} {:<16} {:>8.3} {:>6.3}  {:<28}  {:>8.3} {:>6.3}  {:<28}",
                    row_num,
                    label,
                    t1.value,
                    t1.confidence,
                    t1_top,
                    t2.value,
                    t2.confidence,
                    t2_top
                );
            }
        }
    }
    println!(
        "\n(Rows not listed above were still scored, to keep D5's per-node baseline correct.)"
    );

    // =====================================================================
    // D6 + D7 -- run the real engine end-to-end, print alerts as they fire
    // =====================================================================
    section("D6 + D7 -- ENGINE LOOP + ALERTS");
    println!(
        "poll -> D5 fuse (worst-tier-wins) -> threshold/cooldown -> D7 reason/recommendation\n"
    );

    struct TrackedSource {
        inner: CsvReplaySource,
        row: Arc<Mutex<usize>>,
    }
    #[async_trait::async_trait]
    impl TelemetrySource for TrackedSource {
        async fn poll(&mut self) -> sgx_anomaly_engine::RawSample {
            let sample = self.inner.poll().await;
            *self.row.lock().unwrap() += 1;
            sample
        }
    }

    #[derive(Clone)]
    struct FiredAlert {
        row: usize,
        true_label: String,
        score: f64,
        severity: String,
        status: String,
        reason: String,
        recommendation: String,
        // M3: which tier decided this alert.
        tier: AlertTier,
    }

    struct DemoSink {
        ground_truth: Vec<(String, String)>,
        windows: Vec<(String, usize, usize)>,
        row: Arc<Mutex<usize>>,
        fired: Mutex<Vec<FiredAlert>>,
        // M2/M3: raw alerts kept alongside `fired` purely so
        // `alert::summarize_alerts` (per-tier counts + alerts/hour) can be
        // called on them at the end, without re-deriving that from
        // FiredAlert's already-summarized fields.
        raw: Mutex<Vec<AnomalyAlert>>,
    }
    impl AlertSink for DemoSink {
        fn emit(&self, alert: AnomalyAlert) {
            let row = *self.row.lock().unwrap();
            let label = self
                .ground_truth
                .get(row.saturating_sub(1))
                .map(|(_, l)| l.as_str())
                .unwrap_or("?");
            let in_window = self.windows.iter().find(|(_, s, e)| row >= *s && row <= *e);
            let status = match in_window {
                Some((w_label, s, e)) => format!("TP ({w_label} {s}-{e})"),
                None if label == "normal" => "FALSE POSITIVE".to_string(),
                None => "unlabeled-window".to_string(),
            };
            self.fired.lock().unwrap().push(FiredAlert {
                row,
                true_label: label.to_string(),
                score: alert.score,
                severity: format!("{:?}", alert.severity),
                status,
                reason: alert.reason.clone(),
                recommendation: alert.recommendation.clone(),
                tier: alert.tier,
            });
            self.raw.lock().unwrap().push(alert);
        }
    }

    let node_row_counter = Arc::new(Mutex::new(0usize));
    let source = Box::new(TrackedSource {
        inner: CsvReplaySource::load(&csv_path)?,
        row: node_row_counter.clone(),
    });
    let tier2 = IsolationForestModel::load_from_json(forest_path)?;
    // Default alert_threshold: this model's own D9-calibrated cutoff
    // (train_iforest.py/evaluate.py's chosen threshold_raw, baked into the
    // exported JSON) -- so each node automatically uses ITS OWN validated
    // threshold with no manual editing required. The CLI arg (if given)
    // still overrides this for one-off experiments.
    let alert_threshold = tier2_threshold_override.unwrap_or_else(|| tier2.threshold());

    // FIX: pull Tier-1's calibrated cutoff out of the SAME forest JSON
    // (export_model.py writes it there) BEFORE tier2 is moved into the
    // engine below -- without this, the demo silently ran Tier-1
    // uncalibrated (AnomalyEngine::new's default), which is exactly the
    // 1382-false-positive behavior the calibration fix exists to remove.
    // `None` only for an older/hand-written forest JSON that predates
    // Tier-1 calibration; in that case Tier-1 stays uncalibrated on
    // purpose, same as before this fix existed.
    let tier1_z_alert_threshold = tier2.tier1_z_alert_threshold();

    let sink = Arc::new(DemoSink {
        ground_truth: ground_truth.clone(),
        windows: windows.clone(),
        row: node_row_counter,
        fired: Mutex::new(Vec::new()),
        raw: Mutex::new(Vec::new()),
    });

    let demo_poll_interval = Duration::from_micros(500); // wall-clock throttle only, unrelated to cooldown now
    let mut engine = AnomalyEngine::new(node_name, source, sink.clone())
        .try_with_baseline_lifecycle("config/baseline_lifecycle.json")?;
    engine = match tier1_z_alert_threshold {
        Some(z) => engine.with_tier1_calibrated_z(z),
        None => {
            println!(
                "WARNING: {forest_path} has no z_alert_threshold -- Tier-1 will run \
                 UNCALIBRATED for this demo (re-export with the current export_model.py \
                 to fix)."
            );
            engine
        }
    };
    let mut engine = engine.with_alpha(0.3).with_config(EngineConfig {
        poll_interval: demo_poll_interval,
        alert_threshold,
        min_confidence: 0.5,
        // IMPORTANT: cooldown is compared against each sample's own
        // ts_ms (data time), not wall-clock (see engine.rs's Finding #1
        // fix) -- CSV rows advance ts_ms by 1000ms each, so this must
        // be a REAL duration in that same clock (5 minutes of DATA time),
        // not scaled down with demo_poll_interval like it used to be.
        // Using a wall-clock-scaled value here (e.g. demo_poll_interval
        // * 60 = 30ms) would be smaller than a single row's ts_ms step,
        // so cooldown would never suppress anything.
        cooldown: Duration::from_secs(5 * 60),
    });

    let threshold_note = if tier2_threshold_override.is_some() {
        format!("override={alert_threshold:.4}")
    } else {
        format!("model's own D9-calibrated threshold={alert_threshold:.4}")
    };
    println!("Running the engine against all {} rows (model={forest_path}; alert_threshold: {threshold_note})...", ground_truth.len());
    // IMPORTANT: drive the engine by calling tick() once per row directly,
    // NOT via engine.run() (which paces itself against a REAL wall-clock
    // tokio::time::interval) wrapped in a wall-clock timeout. That
    // combination was non-deterministic: on a slower/busier run, fewer
    // ticks could complete within the fixed timeout window, silently
    // skipping trailing rows -- so the SET of rows actually scored (and
    // therefore which alerts fired) varied between runs of the exact same
    // input and config. Calling tick() in a plain row-count loop processes
    // every row every time, with no dependency on wall-clock speed.
    for _ in 0..ground_truth.len() {
        engine.tick().await;
    }

    let fired = sink.fired.lock().unwrap();

    subrule("Alerts fired");
    if fired.is_empty() {
        println!("  (none)");
    } else {
        println!(
            "  {:<6} {:<14} {:>7} {:<10} {:<6} {:<20}",
            "row", "true label", "score", "severity", "tier", "status"
        );
        println!("  {}", "-".repeat(72));
        for a in fired.iter() {
            println!(
                "  {:<6} {:<14} {:>7.3} {:<10} {:<6} {:<20}",
                a.row,
                a.true_label,
                a.score,
                a.severity,
                format!("{:?}", a.tier),
                a.status
            );
        }
    }

    subrule("Alert details (reason / recommendation)");
    if fired.is_empty() {
        println!("  (none)");
    } else {
        for a in fired.iter() {
            println!("  row {}:", a.row);
            println!("    reason:         {}", a.reason);
            println!("    recommendation: {}", a.recommendation);
        }
    }

    // =====================================================================
    // RESULT
    // =====================================================================
    section("RESULT");
    if fired.is_empty() {
        println!("No alerts fired.");
    } else {
        let mut true_positive_rows = 0usize;
        let mut false_positive_rows = 0usize;
        let mut windows_caught: BTreeSet<usize> = BTreeSet::new();
        for a in fired.iter() {
            match windows
                .iter()
                .position(|(_, s, e)| a.row >= *s && a.row <= *e)
            {
                Some(idx) => {
                    true_positive_rows += 1;
                    windows_caught.insert(idx);
                }
                None => false_positive_rows += 1,
            }
        }
        println!(
            "{} alert(s) fired out of {} rows.\n",
            fired.len(),
            ground_truth.len()
        );
        println!("  {:<20} {:>8}", "true positives", true_positive_rows);
        println!("  {:<20} {:>8}", "false positives", false_positive_rows);

        // M2 + M3: per-tier breakdown and alerts/hour, using alert.rs's
        // summarize_alerts helper. Localises false positives to Tier-1
        // (z-score) vs Tier-2 (trained forest) instead of an unattributed
        // lump, and reports alert VOLUME in a more legible unit than a raw
        // percentage -- a 1-2% FPR sounds small but can still mean dozens
        // of alerts/hour in practice.
        let raw_alerts = sink.raw.lock().unwrap();
        // CSV rows advance ts_ms by 1000ms each (1 row = 1 second of data
        // time -- see the cooldown comment above), so total window
        // duration in ms is just the row count * 1000.
        let window_ms = ground_truth.len() as u64 * 1000;
        let summary = sgx_anomaly_engine::alert::summarize_alerts(&raw_alerts, window_ms);
        subrule("Alert volume: per-tier breakdown + rate");
        println!("  {:<20} {:>8}", "Tier-1 alerts", summary.tier1_count);
        println!("  {:<20} {:>8}", "Tier-2 alerts", summary.tier2_count);
        println!("  {:<20} {:>8.2}", "alerts/hour", summary.alerts_per_hour);
        drop(raw_alerts);

        subrule("Attack windows: caught vs missed");
        println!(
            "  {:<8} {:<10} {:<20} {:<8}",
            "start", "end", "label", "status"
        );
        println!("  {}", "-".repeat(48));
        for (i, (label, start, end)) in windows.iter().enumerate() {
            let status = if windows_caught.contains(&i) {
                "CAUGHT"
            } else {
                "MISSED"
            };
            println!("  {:<8} {:<10} {:<20} {:<8}", start, end, label, status);
        }
    }

    Ok(())
}
