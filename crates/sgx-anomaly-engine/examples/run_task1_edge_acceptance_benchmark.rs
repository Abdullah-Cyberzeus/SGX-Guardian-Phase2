use anyhow::Context;
use sgx_anomaly_engine::edge_acceptance::{
    acceptance_verdict, latency_stats, model_size_pass, AcceptanceChecks, EdgeBenchmarkReport,
    MemoryValidation, ModelFootprint, TargetProfile, MAX_MODEL_BYTES,
};
use sgx_anomaly_engine::model::{AnomalyModel, IsolationForestModel};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|window| window[0] == flag)
        .map(|window| window[1].clone())
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| arg == flag)
}

fn usage() {
    eprintln!(
        "Usage: cargo run --example run_task1_edge_acceptance_benchmark -- --model data/nodeA_forest.json --node nodeA --samples 5000 --out data/task1_edge_acceptance/nodeA_edge_benchmark.json [--target-profile desktop-dev|board] [--require-board]"
    );
}

fn synthetic_task1_vector(iteration: usize) -> [f64; 19] {
    let drift = (iteration % 17) as f64;
    [
        1250.0 + drift,
        980.0 + drift,
        8.0,
        7.0,
        0.01,
        4.0 + drift / 10.0,
        0.2,
        0.18,
        12.0,
        0.7,
        2.0,
        1.0,
        1.5,
        35.0,
        22.0,
        128.0,
        0.95,
        0.02,
        1.0,
    ]
}

fn target_board_validated(profile: &str, require_board: bool) -> bool {
    let env_override = env::var("TASK1_TARGET_BOARD_VALIDATED")
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    env_override || require_board || profile.eq_ignore_ascii_case("board")
}

fn build_profile() -> String {
    if cfg!(debug_assertions) {
        "debug".to_string()
    } else {
        "release".to_string()
    }
}

fn write_report(path: &Path, report: &EdgeBenchmarkReport) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(report)?;
    fs::write(path, json).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    if has_flag(&args, "--help") || args.len() == 1 {
        usage();
        return Ok(());
    }

    let model_path = arg_value(&args, "--model").unwrap_or_else(|| "data/nodeA_forest.json".into());
    let node_id = arg_value(&args, "--node").unwrap_or_else(|| "nodeA".into());
    let samples: usize = arg_value(&args, "--samples")
        .unwrap_or_else(|| "5000".into())
        .parse()
        .context("--samples must be a positive integer")?;
    if samples == 0 {
        anyhow::bail!("--samples must be greater than zero");
    }
    let out_path =
        PathBuf::from(arg_value(&args, "--out").unwrap_or_else(|| {
            format!("data/task1_edge_acceptance/{node_id}_edge_benchmark.json")
        }));
    let target_profile =
        arg_value(&args, "--target-profile").unwrap_or_else(|| "desktop-dev".into());
    let require_board = has_flag(&args, "--require-board");

    let model = IsolationForestModel::load_from_json(&model_path)?;
    let size_bytes = fs::metadata(&model_path)
        .with_context(|| format!("failed to stat model artifact {model_path}"))?
        .len();

    let mut durations_ms = Vec::with_capacity(samples);
    let mut last_score = None;
    for i in 0..samples {
        let vector = synthetic_task1_vector(i);
        let started = Instant::now();
        let score = model.score(&node_id, &vector);
        durations_ms.push(started.elapsed().as_secs_f64() * 1000.0);
        last_score = Some(score);
    }

    let latency = latency_stats(durations_ms)?;
    let model_ok = model_size_pass(size_bytes);
    let board_ok = target_board_validated(&target_profile, require_board);
    let verdict = acceptance_verdict(model_ok, latency.pass, board_ok);

    let report = EdgeBenchmarkReport {
        schema_version: 1,
        issue: "Task1 Issue #10 - embedded/edge acceptance benchmark".to_string(),
        node_id: node_id.clone(),
        target: TargetProfile {
            profile_name: target_profile,
            os: env::consts::OS.to_string(),
            arch: env::consts::ARCH.to_string(),
            family: env::consts::FAMILY.to_string(),
            build_profile: build_profile(),
            target_board_validated: board_ok,
        },
        model: ModelFootprint {
            artifact_path: model_path.clone(),
            size_bytes,
            size_mib: size_bytes as f64 / (1024.0 * 1024.0),
            max_allowed_bytes: MAX_MODEL_BYTES,
            pass: model_ok,
        },
        memory: MemoryValidation {
            rss_measured: false,
            status: "pending_target_board_measurement".to_string(),
            note: "Portable demo records model footprint and latency. Real RSS must be captured by running this same command on the target board OS.".to_string(),
        },
        checks: AcceptanceChecks {
            model_size_pass: model_ok,
            p95_latency_pass: latency.pass,
            target_board_validated: board_ok,
        },
        latency,
        final_verdict: verdict,
    };

    write_report(&out_path, &report)?;

    let score = last_score.expect("samples > 0");
    println!("==========================================================================");
    println!("TASK 1 - ISSUE #10 EDGE / BOARD ACCEPTANCE BENCHMARK");
    println!("==========================================================================");
    println!("Node                     : {}", report.node_id);
    println!("Model artifact           : {}", report.model.artifact_path);
    println!(
        "Model size               : {:.3} MiB / limit {:.3} MiB => {}",
        report.model.size_mib,
        report.model.max_allowed_bytes as f64 / (1024.0 * 1024.0),
        if report.model.pass { "PASS" } else { "FAIL" }
    );
    println!(
        "Target                   : {} {} ({}, {})",
        report.target.os, report.target.arch, report.target.family, report.target.build_profile
    );
    println!(
        "Board validation         : {}",
        if report.target.target_board_validated {
            "YES"
        } else {
            "PENDING - rerun same command on real board"
        }
    );
    println!("Samples scored           : {}", report.latency.samples);
    println!("Avg latency              : {:.6} ms", report.latency.avg_ms);
    println!("P50 latency              : {:.6} ms", report.latency.p50_ms);
    println!(
        "P95 latency              : {:.6} ms / limit {:.1} ms => {}",
        report.latency.p95_ms,
        report.latency.p95_limit_ms,
        if report.latency.pass { "PASS" } else { "FAIL" }
    );
    println!("P99 latency              : {:.6} ms", report.latency.p99_ms);
    println!("Last anomaly score       : {:.6}", score.value);
    println!(
        "Last model confidence    : {:.2}%",
        score.confidence * 100.0
    );
    println!("Top contributors         : {}", score.topk.join(", "));
    println!("Memory/RSS               : {}", report.memory.status);
    println!("Saved JSON               : {}", out_path.display());
    println!("Final verdict            : {:?}", report.final_verdict);
    println!("NOTE: full Issue #10 closure requires running this benchmark on the actual board.");

    Ok(())
}
