//! D10 — Python↔Rust score parity.
//!
//! Loads a real exported forest JSON (export_model.py's output) plus a
//! fixture of (vector, python_raw_score, python_value) pairs computed by
//! the SAME Python model that produced that JSON (dump_parity_fixture.py,
//! run against train_iforest.py's joblib output -- NOT re-derived from the
//! JSON, so this genuinely checks two independent implementations agree,
//! not that the JSON round-trips through itself).
//!
//! For each case, calls `IsolationForestModel::score()` and asserts the
//! Rust raw score matches Python's to within 1e-6 -- the same tolerance
//! `model.rs`'s `c(n)` doc comment already commits to. A failure here means
//! an actual Rust/Python scoring bug, which is exactly the kind of thing
//! the senior review's H1 finding flagged as a more likely explanation for
//! a live-vs-evaluate.py FPR/recall gap than "different distributions" --
//! this test is what rules that possibility in or out, cheaply, before
//! spending time on data-side theories.
//!
//! HOW TO (RE)GENERATE THE FIXTURE THIS TEST READS:
//!   cd anomaly-training
//!   python dump_parity_fixture.py --model trained/nodeA \
//!       --normal data/nodeA_normal.csv --attacks data/nodeA_attacks.csv \
//!       --out ../sgx-anomaly-engine/tests/fixtures/nodeA_parity.json
//!
//! If no fixture file exists yet, this test is SKIPPED (prints a message
//! and returns) rather than failing the whole suite -- D9's trained model
//! is a prerequisite this test can't fabricate on its own, same spirit as
//! the placeholder this file replaces.

use serde::Deserialize;
use sgx_anomaly_engine::model::{AnomalyModel, IsolationForestModel, ZScoreModel};

#[derive(Debug, Deserialize)]
struct ParityCase {
    vector: Vec<f64>,
    label: String,
    python_raw_score: f64,
    #[allow(dead_code)] // cross-checked informally; the raw_score assertion is the real gate
    python_value: f64,
}

#[derive(Debug, Deserialize)]
struct ParityFixture {
    cases: Vec<ParityCase>,
    #[serde(default)]
    tier1_cases: Vec<Tier1ParityCase>,
}

#[derive(Debug, Deserialize)]
struct Tier1ParityCase {
    vector: Vec<f64>,
    label: String,
    python_max_z: f64,
}

/// Raw-score tolerance. Matches model.rs's own documented commitment (see
/// the `c(n)` doc comment): sklearn's exact asymptotic c(n) formula should
/// match to ~1e-16 in principle, but real trained forests (many trees,
/// real floating-point accumulation across a full averaging step) leave
/// some headroom -- 1e-6 is tight enough to catch a genuine algorithmic
/// mismatch (wrong split direction, wrong c(n) formula, wrong leaf-size
/// correction) while not being so tight it flags ordinary float noise.
const RAW_SCORE_TOLERANCE: f64 = 1e-6;

fn fixture_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/nodeA_parity.json")
}

fn forest_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("data/nodeA_forest.json")
}

#[test]
fn rust_scores_match_python_within_tolerance() {
    let fixture_path = fixture_path();
    let forest_path = forest_path();

    if !fixture_path.exists() || !forest_path.exists() {
        eprintln!(
            "D10 parity test SKIPPED: missing {} and/or {}. Generate them with \
             dump_parity_fixture.py + export_model.py (see this file's module docs) \
             before relying on this test -- it is not yet verifying anything.",
            fixture_path.display(),
            forest_path.display()
        );
        return;
    }

    let fixture_json = std::fs::read_to_string(&fixture_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", fixture_path.display()));
    let fixture: ParityFixture = serde_json::from_str(&fixture_json)
        .unwrap_or_else(|e| panic!("invalid parity fixture JSON: {e}"));

    assert!(
        !fixture.cases.is_empty(),
        "parity fixture has zero cases -- nothing to check"
    );

    let model = IsolationForestModel::load_from_json(forest_path.to_str().unwrap())
        .unwrap_or_else(|e| panic!("failed to load {}: {e}", forest_path.display()));

    let mut worst_diff = 0.0_f64;
    let mut failures = Vec::new();

    for (i, case) in fixture.cases.iter().enumerate() {
        assert_eq!(
            case.vector.len(),
            19,
            "fixture case {i} ({}) does not have 19 features",
            case.label
        );
        let mut vector = [0.0_f64; 19];
        vector.copy_from_slice(&case.vector);

        let score = model.score("nodeA", &vector);
        let rust_raw = score.raw_value.unwrap_or_else(|| {
            panic!(
                "case {i} ({}): Rust score has no raw_value -- Tier-2 should always set this",
                case.label
            )
        });

        let diff = (rust_raw - case.python_raw_score).abs();
        worst_diff = worst_diff.max(diff);
        if diff > RAW_SCORE_TOLERANCE {
            failures.push(format!(
                "  case {i} (label={}): rust_raw={rust_raw:.9} python_raw={:.9} diff={diff:.2e} (tolerance {RAW_SCORE_TOLERANCE:.0e})",
                case.label, case.python_raw_score
            ));
        }
    }

    if !failures.is_empty() {
        panic!(
            "D10 PARITY FAILURE: {}/{} case(s) exceeded the raw-score tolerance. This means Rust and \
             Python disagree on scoring -- a real algorithmic bug (wrong split direction, wrong c(n), \
             wrong leaf-size correction), NOT a data or threshold problem. Worst diff observed: {worst_diff:.2e}.\n{}",
            failures.len(),
            fixture.cases.len(),
            failures.join("\n")
        );
    }

    eprintln!(
        "D10 parity OK: {} case(s) checked, worst |rust_raw - python_raw| = {worst_diff:.2e} (tolerance {RAW_SCORE_TOLERANCE:.0e})",
        fixture.cases.len()
    );
}

#[test]
fn rust_tier1_scores_match_python_when_fixture_includes_stream() {
    let fixture_path = fixture_path();
    if !fixture_path.exists() {
        eprintln!(
            "D10 Tier-1 parity test SKIPPED: missing {}",
            fixture_path.display()
        );
        return;
    }
    let fixture: ParityFixture =
        serde_json::from_str(&std::fs::read_to_string(&fixture_path).expect("read parity fixture"))
            .expect("parse parity fixture");
    if fixture.tier1_cases.is_empty() {
        eprintln!(
            "D10 Tier-1 parity test SKIPPED: fixture has no tier1_cases; regenerate it with dump_parity_fixture.py"
        );
        return;
    }

    let model = ZScoreModel::new(3.0);
    for (i, case) in fixture.tier1_cases.iter().enumerate() {
        assert_eq!(
            case.vector.len(),
            19,
            "Tier-1 case {i} ({}) does not have 19 features",
            case.label
        );
        let mut vector = [0.0_f64; 19];
        vector.copy_from_slice(&case.vector);
        let rust_max_z = model
            .score("tier1-parity", &vector)
            .raw_value
            .expect("Tier-1 raw max|z|");
        let diff = (rust_max_z - case.python_max_z).abs();
        assert!(
            diff <= 1e-9,
            "Tier-1 parity mismatch at case {i} ({}): Rust={rust_max_z:.12}, Python={:.12}, diff={diff:.2e}",
            case.label,
            case.python_max_z,
        );
    }
}
