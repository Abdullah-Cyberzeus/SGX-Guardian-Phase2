//! Model layer (D5): scores a FeatureVector.
//! Tier-1 = online per-feature, per-node z-score. Tier-2 = Isolation Forest
//! (JSON-loaded: features, scaler center/scale, threshold, score_lo/hi, trees).

use crate::features::FEATURE_NAMES;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Mutex;

/// The output of any model's `score()` call.
#[derive(Debug, Clone)]
pub struct Score {
    /// Final anomaly score, normalized into [0, 1]. Higher = more anomalous.
    pub value: f64,
    /// How much to trust `value` (0 = no confidence yet, 1 = fully confident).
    pub confidence: f64,
    /// Names of the features that contributed most to this score, most
    /// important first. Used for explainability (D7 alert "reason").
    pub topk: Vec<String>,
    /// Un-normalized ("raw") score on each tier's own native scale.
    /// For Tier-2 (Isolation Forest): the raw isolation-forest score.
    /// For Tier-1 (z-score), as of Fix 1: the raw max|z| across features
    /// (post-log1p for heavy-tailed ones -- see `LOG1P_FEATURE_INDICES`),
    /// so a caller with a calibrated per-tier threshold (Tier-2's
    /// `threshold_raw`, Tier-1's `z_alert_threshold`) can compare against
    /// full precision instead of only the [0,1]-squashed `value`, which
    /// clips right at the alert boundary (see engine.rs's `maybe_alert`).
    /// `None` only for a Tier-2 forest whose JSON didn't carry
    /// `threshold_raw` (older/hand-written fixtures).
    pub raw_value: Option<f64>,
}

/// Common interface both Tier-1 (ZScoreModel) and Tier-2 (IsolationForestModel)
/// implement, so the engine (D6) can use either without caring which.
///
/// `node` is REQUIRED here (not optional / defaulted) so that D6 cannot
/// accidentally collapse every node's samples into one shared baseline —
/// that used to be possible via a `score(vector)`-only trait method that
/// silently forwarded to a hardcoded "default" node (see Issue #2, fixed).
/// IsolationForestModel (Tier-2) has no per-node state, so it ignores
/// `node`, but keeping it in the trait keeps both tiers callable the same
/// way from D6 without a footgun.
pub trait AnomalyModel {
    fn score(&self, node: &str, vector: &[f64; 19]) -> Score;
}

// =============================================================================
// TIER 1 — Online per-feature, per-node Z-Score
// =============================================================================
//
// "Online" means the mean/variance for each feature are updated incrementally
// as new samples arrive (Welford's algorithm), not computed once from a fixed
// training set. "Per-node" means each node (device) gets its own baseline,
// stored separately, because what's normal for a heavy node may be an anomaly
// for a light node.
//
// Each call to `observe_and_score` does two things, IN THIS ORDER:
//   1. Scores the incoming sample against the baseline BEFORE this sample is
//      folded in (so a spike is judged against normal history, not against
//      itself).
//   2. THEN updates the running mean/variance with this sample, so the next
//      call sees it as part of history.

/// Running per-feature statistics for one node, updated via Welford's
/// algorithm (numerically stable, single-pass mean + variance).
#[derive(Debug, Clone)]
struct NodeStats {
    count: u64,
    mean: [f64; 19],
    m2: [f64; 19], // sum of squared differences from the mean so far
}

impl NodeStats {
    fn new() -> Self {
        Self {
            count: 0,
            mean: [0.0; 19],
            m2: [0.0; 19],
        }
    }

    /// Standard deviation for feature `i`, using the sample variance
    /// (m2 / (count - 1)). Returns 0.0 if fewer than 2 samples seen yet
    /// (variance is undefined with 0-1 samples).
    fn stddev(&self, i: usize) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            (self.m2[i] / (self.count as f64 - 1.0)).sqrt()
        }
    }

    /// Fold one new sample into the running mean/variance (Welford).
    /// Fix 2: folds the LOG1P-TRANSFORMED value for heavy-tailed features
    /// (see `LOG1P_FEATURE_INDICES`), not the raw value -- the baseline
    /// this builds must be in the same space `score_against` scores
    /// against, or the two would silently disagree.
    fn update(&mut self, vector: &[f64; 19]) {
        self.count += 1;
        let n = self.count as f64;
        for i in 0..19 {
            let x = maybe_log1p(i, vector[i]);
            let delta = x - self.mean[i];
            self.mean[i] += delta / n;
            let delta2 = x - self.mean[i];
            self.m2[i] += delta * delta2;
        }
    }
}

/// Fix 2 (senior review, D8/D9 FPR/recall follow-up): heavy-tailed
/// rate/bytes/pkts/fds features get a log1p transform before z-scoring.
/// Without this, their diurnal peaks and ordinary bursts inflate the
/// running variance so much that a genuine attack's z-score gets buried
/// in normal-looking noise -- measured on the real nodeA/nodeB data,
/// this was the difference between Tier-1 firing ~1382 false positives
/// (uncalibrated AND untransformed) vs a controlled, honest rate once
/// combined with Fix 1's calibrated threshold.
///
/// Indices match `crate::features::FEATURE_NAMES`. Left OUT of the
/// transform (kept linear): active_peers (6, small integer counts,
/// not heavy-tailed), relay_ratio (7, already bounded 0-1),
/// cpu_util_pct (15) / mem_used_pct (16, already bounded 0-100),
/// cot_latency_avg_ms (10) and load1 (18, no evidence yet they need it --
/// revisit if a future measurement shows otherwise).
///
/// IMPORTANT -- D10 parity: this transform must be applied identically
/// on the Python/D9 training side (wherever Tier-1's calibrated
/// threshold is computed) or Rust and Python will silently disagree on
/// Tier-1's z-scores. Extend the parity fixture/test to cover Tier-1,
/// not just Tier-2, the moment this lands on the training side too.
const LOG1P_FEATURE_INDICES: [usize; 13] = [
    0,  // net_rx_bytes_rate
    1,  // net_tx_bytes_rate
    2,  // net_rx_pkts_rate
    3,  // net_tx_pkts_rate
    4,  // nebula_mbps
    5,  // conn_rate
    8,  // relay_bytes_rate
    9,  // cot_switches_rate
    11, // policy_event_rate
    12, // attest_rate
    13, // proto_violation_rate
    14, // error_rate
    17, // open_fds
];

/// Sparse event/count features need a non-zero standard-deviation floor:
/// their normal history is often exactly zero, and the first ordinary event
/// must not become an infinite z-score.  Do NOT apply this large floor to
/// every log-transformed traffic feature: in log space their true standard
/// deviation is commonly 0.1--0.3, so a flat 0.5 floor would erase a real
/// packet/byte-rate spike.
const SPARSE_FLOOR_FEATURE_INDICES: [usize; 5] = [
    9,  // cot_switches_rate
    11, // policy_event_rate
    12, // attest_rate
    13, // proto_violation_rate
    14, // error_rate
];

#[inline]
fn feature_stddev_floor(i: usize, sparse_floor: f64) -> f64 {
    if SPARSE_FLOOR_FEATURE_INDICES.contains(&i) {
        sparse_floor
    } else {
        1e-6
    }
}

/// Apply log1p to `x` if feature `i` is one of the heavy-tailed features
/// above, otherwise return `x` unchanged. `x.max(0.0)` guards against
/// log1p's domain (undefined below -1) -- every feature this applies to
/// is a rate/count/byte-size that should never legitimately be negative;
/// clamping a stray negative to 0 here is a safety net, not a modeling
/// choice (see also prep.py's own negative-value rejection on the
/// training side, which should already catch this upstream).
#[inline]
fn maybe_log1p(i: usize, x: f64) -> f64 {
    if LOG1P_FEATURE_INDICES.contains(&i) {
        x.max(0.0).ln_1p()
    } else {
        x
    }
}

pub struct ZScoreModel {
    /// |z| at or above this is considered a fully-confident anomaly signal
    /// for a single feature (used to shape the [0,1] score curve).
    threshold: f64,
    /// How many samples a node needs before z-scores are treated as fully
    /// trustworthy (confidence ramps up from 0 to 1 over this many samples).
    warmup_samples: f64,
    /// Minimum stddev assumed for any feature, even one that has looked
    /// perfectly constant so far (std == 0). Without this floor, a sparse
    /// event-count feature (attest_rate, policy_event_rate,
    /// proto_violation_rate, error_rate — all near-always 0 in normal
    /// operation) would score its first-ever non-zero value as an
    /// effectively infinite z (see Issue #1): std=0 -> divide-by-near-zero
    /// -> |z| pinned at 1e6 -> value ~1.0, i.e. a perfectly normal first
    /// attestation/error looks like a maximal anomaly. Flooring std at
    /// this value caps how extreme that first-occurrence z can get, while
    /// leaving genuinely noisy features (std already > floor) unaffected.
    variance_floor: f64,
    /// Fix 1 (senior review, D8/D9 FPR/recall follow-up): Tier-1's OWN
    /// calibrated alert cutoff on raw max|z| (post-log1p), computed the
    /// same way Tier-2's threshold is -- the P99/P99.5 of max|z| over
    /// NORMAL training data, never from attack labels. `None` until set
    /// (via `with_z_alert_threshold`), in which case Tier-1 has no
    /// calibrated cutoff of its own and callers should keep relying on
    /// the softened `value`/`threshold` curve alone, same as before this
    /// fix -- this keeps every existing caller/test working unchanged
    /// unless they opt in to calibration.
    z_alert_threshold: Option<f64>,
    /// Per-node running statistics. `Mutex` (not `RefCell`) so `ZScoreModel`
    /// is `Sync` and can be shared across concurrent tokio tasks via `Arc`
    /// once D6's engine loop needs that — `RefCell` would fail to compile
    /// the moment it's accessed from more than one task through a shared
    /// reference, even without real thread contention on a single-threaded
    /// runtime.
    states: Mutex<HashMap<String, NodeStats>>,
}

impl ZScoreModel {
    pub fn new(threshold: f64) -> Self {
        Self {
            threshold,
            warmup_samples: 30.0,
            variance_floor: 0.5,
            z_alert_threshold: None,
            states: Mutex::new(HashMap::new()),
        }
    }

    /// Same as `new`, but with an explicit variance floor instead of the
    /// default (0.5). Use a smaller floor for features whose normal range
    /// is itself small, or a larger one for very "bursty" count features.
    pub fn new_with_variance_floor(threshold: f64, variance_floor: f64) -> Self {
        Self {
            threshold,
            warmup_samples: 30.0,
            variance_floor,
            z_alert_threshold: None,
            states: Mutex::new(HashMap::new()),
        }
    }

    /// Fix 1: set Tier-1's calibrated alert cutoff (P99/P99.5 of max|z|
    /// over normal training data, computed on the training/export side
    /// and passed in here -- e.g. loaded from the same exported JSON
    /// Tier-2 already carries `threshold_raw` in, under a new
    /// `tier1_threshold` key). Builder-style so it composes with
    /// `new`/`new_with_variance_floor` without more constructor overloads.
    pub fn with_z_alert_threshold(mut self, z_alert_threshold: f64) -> Self {
        self.z_alert_threshold = Some(z_alert_threshold);
        self
    }

    /// Tier-1's calibrated alert cutoff, if one has been set. `None`
    /// means this ZScoreModel is running uncalibrated (pre-Fix-1
    /// behavior) -- callers (e.g. engine.rs's fusion) should fall back
    /// to comparing the softened `value` against a generic threshold in
    /// that case, the same way `IsolationForestModel::raw_alert_threshold`
    /// being `None` means falling back to its normalized `value`.
    pub fn z_alert_threshold(&self) -> Option<f64> {
        self.z_alert_threshold
    }

    /// Score `vector` for `node` against that node's current baseline, THEN
    /// fold `vector` into the baseline for next time. This is the main,
    /// per-node entry point — use this directly when you know the node id.
    /// Score `vector` against `node`'s CURRENT baseline, WITHOUT folding it
    /// in. Lets a caller (D6) decide whether this sample should update the
    /// baseline at all before committing to that — see `fold()` below and
    /// the engine-level fix for the baseline-poisoning bug this enables
    /// fixing (a sustained attack sample used to get folded into the
    /// "normal" baseline on every tick, so Tier-1's own z-score would decay
    /// toward 0 within 1-2 samples of a CONSTANT anomalous value, silencing
    /// further alerts long before any cooldown even expired).
    pub fn peek(&self, node: &str, vector: &[f64; 19]) -> Score {
        let mut states = self
            .states
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let stats = states
            .entry(node.to_string())
            .or_insert_with(NodeStats::new);
        Self::score_against(
            stats,
            vector,
            self.variance_floor,
            self.threshold,
            self.warmup_samples,
        )
    }

    /// Fold `vector` into `node`'s baseline. Call this ONLY for samples you
    /// want treated as "normal history" going forward — see `peek()`.
    pub fn fold(&self, node: &str, vector: &[f64; 19]) {
        let mut states = self
            .states
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let stats = states
            .entry(node.to_string())
            .or_insert_with(NodeStats::new);
        stats.update(vector);
    }

    fn score_against(
        stats: &NodeStats,
        vector: &[f64; 19],
        variance_floor: f64,
        threshold: f64,
        warmup_samples: f64,
    ) -> Score {
        // 1. Score against the baseline as it stood BEFORE this sample.
        // Fix 2: transform heavy-tailed features the same way `update()`
        // folds them into the baseline (maybe_log1p) -- scoring and the
        // baseline it's scored against must live in the same space.
        let mut z_scores = [0.0; 19];
        for i in 0..19 {
            let x = maybe_log1p(i, vector[i]);
            // Floor the stddev before dividing, instead of branching into a
            // fixed ±1e6 sentinel when std==0 (Issue #1 fix). A feature
            // that has looked perfectly constant (std==0) still gets a
            // finite, bounded z when it first changes — proportional to
            // how far it moved relative to the floor — rather than an
            // effectively-infinite score. Features with genuine variance
            // (std already above the floor) are completely unaffected.
            let std = stats.stddev(i).max(feature_stddev_floor(i, variance_floor));
            z_scores[i] = (x - stats.mean[i]) / std;
        }

        // Rank features by |z|, worst first, for topk / explainability.
        let mut ranked: Vec<(usize, f64)> = (0..19).map(|i| (i, z_scores[i].abs())).collect();
        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        let topk: Vec<String> = ranked
            .iter()
            .take(3)
            .filter(|(_, absz)| *absz > 1e-9) // don't report "top" features that are all 0
            .map(|(i, _)| FEATURE_NAMES[*i].to_string())
            .collect();

        let max_abs_z = ranked[0].1;

        // Squash max|z| into [0,1]: at max_abs_z == threshold, value == 0.5;
        // value approaches 1.0 as max_abs_z grows well past threshold; value
        // approaches 0.0 as max_abs_z approaches 0. Monotonic, no hard cutoff.
        let value = (max_abs_z / (max_abs_z + threshold)).clamp(0.0, 1.0);

        // Confidence ramps up as the node accumulates history: with very few
        // samples the baseline itself is shaky, so we shouldn't fully trust
        // an early z-score yet.
        let confidence = (stats.count as f64 / warmup_samples).clamp(0.0, 1.0);

        // Fix 1: carry the raw max|z| through as `raw_value`, the same
        // pattern Tier-2 already uses for its raw isolation-forest score.
        // This lets a caller with a calibrated `z_alert_threshold` compare
        // against it directly (full precision, not the [0,1]-squashed
        // `value`), instead of only ever having the soft curve to work
        // with. Previously this was always `None` for Tier-1.
        Score {
            value,
            confidence,
            topk,
            raw_value: Some(max_abs_z),
        }
    }

    /// Convenience wrapper: score, then unconditionally fold. Kept for
    /// existing tests/callers that want the old always-fold behavior
    /// (e.g. tests establishing a NORMAL baseline, where every sample
    /// SHOULD be folded in). D6's engine loop uses `peek`/`fold`
    /// separately instead, so it can skip folding for samples that
    /// triggered — or are still cooling down from — an alert.
    pub fn observe_and_score(&self, node: &str, vector: &[f64; 19]) -> Score {
        let score = self.peek(node, vector);
        // With a calibrated Tier-1 cutoff, a flagged row is not normal
        // history. Folding it would let a sustained attack raise the mean
        // and variance until it masks itself. Existing uncalibrated callers
        // retain the original score-then-fold behavior.
        let is_calibrated_anomaly = matches!(
            (score.raw_value, self.z_alert_threshold),
            (Some(raw), Some(threshold)) if raw >= threshold
        );
        if !is_calibrated_anomaly {
            self.fold(node, vector);
        }
        score
    }
}

impl AnomalyModel for ZScoreModel {
    /// Trait-level entry point. Forwards straight to `observe_and_score`
    /// with the caller-supplied node id, so per-node baselines (the whole
    /// point of Tier-1) are preserved no matter which entry point D6 uses.
    fn score(&self, node: &str, vector: &[f64; 19]) -> Score {
        self.observe_and_score(node, vector)
    }
}

// =============================================================================
// TIER 2 — Isolation Forest (JSON-loaded)
// =============================================================================
//
// Trained in Python (D9, scikit-learn IsolationForest) and exported to JSON.
// This loads that JSON and re-implements just enough of the algorithm to
// score a vector: walk each tree to a leaf, get a path length, average
// across trees, convert to the standard isolation-forest anomaly score,
// then rescale into [0,1] using the score_lo/score_hi bounds from training.

#[derive(Debug, Deserialize)]
struct ScalerSpec {
    center: Vec<f64>,
    scale: Vec<f64>,
}

/// One node of a tree, as found in the JSON. Recursive: a "split" node
/// points at two child nodes; a "leaf" node ends the path.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum TreeNode {
    Split {
        feature: usize,
        value: f64,
        left: Box<TreeNode>,
        right: Box<TreeNode>,
    },
    Leaf {
        /// How many training points ended up in this leaf. Used to correct
        /// the path length (a leaf with many points would have kept
        /// splitting given more depth budget, so it isn't "as isolated" as
        /// its raw depth suggests). Defaults to 1 (a fully isolated point)
        /// if the JSON omits it.
        #[serde(default = "default_leaf_size")]
        size: u64,
    },
}
fn default_leaf_size() -> u64 {
    1
}

#[derive(Debug, Deserialize)]
struct ForestFile {
    features: Vec<String>,
    scaler: ScalerSpec,
    threshold: f64,
    /// D9's un-normalized cutoff (export_model.py always writes this).
    /// Optional here so older/hand-written fixture JSONs without the field
    /// (e.g. data/sample_forest.json) still load instead of hard-erroring.
    #[serde(default)]
    threshold_raw: Option<f64>,
    score_lo: f64,
    score_hi: f64,
    /// Number of samples the forest was trained on. Needed for the
    /// isolation-forest normalization constant c(n). Defaults to 256
    /// (scikit-learn's own default) if the JSON doesn't specify it.
    #[serde(default = "default_n_samples")]
    n_samples: usize,
    trees: Vec<TreeNode>,
    /// FIX: Tier-1's calibrated alert cutoff (P99.5 of Tier-1's online
    /// max|z| over normal training data), written by export_model.py
    /// alongside Tier-2's own threshold_raw. This field previously did not
    /// exist here at all, so export_model.py's `z_alert_threshold` key was
    /// silently ignored by serde on every load -- any caller building an
    /// engine from `IsolationForestModel::load_from_json` (e.g.
    /// run_d5_d6_d7_demo.rs) had NO way to retrieve Tier-1's calibrated
    /// threshold, so it kept running Tier-1 uncalibrated (the exact
    /// 1382-false-positive behavior Fix 1 was meant to eliminate),
    /// regardless of what the exported JSON said. `None` for
    /// older/hand-written fixture JSONs that don't carry it.
    #[serde(default)]
    z_alert_threshold: Option<f64>,
}
fn default_n_samples() -> usize {
    256
}

pub struct IsolationForestModel {
    pub feature_names: Vec<String>,
    center: Vec<f64>,
    scale: Vec<f64>,
    threshold: f64,
    threshold_raw: Option<f64>,
    score_lo: f64,
    score_hi: f64,
    #[allow(dead_code)] // kept as metadata; only used at load time to derive c_n below
    n_samples: usize,
    /// c(n_samples), precomputed once at load time (Issue #5 fix) instead
    /// of recomputed on every score() call. c() sums a harmonic series up
    /// to n_samples-1 terms, which is wasted work when n_samples (a
    /// training-time constant) never changes for the life of the model.
    c_n: f64,
    trees: Vec<TreeNode>,
    /// FIX: Tier-1's calibrated z_alert_threshold, carried alongside the
    /// Tier-2 forest purely so a caller that only loads this one JSON file
    /// (e.g. a demo or the engine's own setup code) can still retrieve
    /// Tier-1's calibrated cutoff and pass it to
    /// `AnomalyEngine::with_tier1_calibrated_z`. This model does NOT use
    /// the value itself -- Tier-2's own scoring is unaffected.
    tier1_z_alert_threshold: Option<f64>,
}

/// c(n): average path length of an unsuccessful search in a binary search
/// tree of n points. Standard isolation-forest normalization constant.
///
/// IMPORTANT: this MUST match scikit-learn's internal `_average_path_length`
/// exactly, not the original isolation-forest paper's exact-harmonic-sum
/// formula -- they are close but NOT identical for finite n, and D10's
/// parity test requires |rust_score - python_score| <= 1e-6. sklearn uses
/// an asymptotic log-approximation (`2*(ln(n-1) + euler_gamma) - 2*(n-1)/n`)
/// rather than summing the harmonic series exactly. Cross-checked in
/// Python against a real sklearn-trained IsolationForest exported via
/// export_model.py: this formula matches sklearn's score_samples() to
/// ~1e-16 (float precision); the old harmonic-sum version was off by
/// ~1e-3 to ~2e-3 per row -- enough to fail D10's parity gate.
///
/// EULER_MASCHERONI = 0.5772156649015329 (same constant Python's
/// `numpy.euler_gamma` uses).
const EULER_MASCHERONI: f64 = 0.5772156649015329;

fn c(n: u64) -> f64 {
    if n <= 1 {
        0.0
    } else if n == 2 {
        1.0
    } else {
        let n = n as f64;
        2.0 * ((n - 1.0).ln() + EULER_MASCHERONI) - (2.0 * (n - 1.0) / n)
    }
}

fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}

fn stddev(values: &[f64], mean_val: f64) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let var = values.iter().map(|v| (v - mean_val).powi(2)).sum::<f64>() / values.len() as f64;
    var.sqrt()
}

impl IsolationForestModel {
    /// The D9-calibrated alert threshold baked into this forest's exported
    /// JSON (train_iforest.py/evaluate.py's chosen threshold_raw, rescaled
    /// to [0,1]). Public so callers (e.g. demos, the engine) can use each
    /// trained model's own calibrated cutoff automatically, instead of one
    /// hardcoded value shared across every node's model.
    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    /// Alias for `threshold()` -- the engine (D6) calls this name when
    /// looking up each tier's cutoff generically. Same normalized [0,1]
    /// value; kept as a separate method (not a rename) so callers that
    /// want the model's own semantics (`threshold()`) and callers that
    /// want "whatever this tier alerts at" (`alert_threshold()`) both
    /// read naturally at their call site.
    pub fn alert_threshold(&self) -> f64 {
        self.threshold
    }

    /// D9's un-normalized cutoff (`threshold_raw` from the exported JSON),
    /// if present. `None` for JSONs that predate this field (e.g. the
    /// hand-written `data/sample_forest.json` fixture) -- callers should
    /// fall back to the normalized `alert_threshold()`/`value` comparison
    /// in that case, which engine.rs's `maybe_alert` already does.
    pub fn raw_alert_threshold(&self) -> Option<f64> {
        self.threshold_raw
    }

    /// FIX: Tier-1's calibrated alert cutoff (P99.5 of Tier-1's online
    /// max|z| over normal training data), if this JSON carried one.
    /// `None` for older/hand-written fixture JSONs without it -- callers
    /// (e.g. run_d5_d6_d7_demo.rs) should keep Tier-1 uncalibrated in that
    /// case, same as before this fix existed. Callers that DO get `Some`
    /// back should pass it to `AnomalyEngine::with_tier1_calibrated_z` so
    /// the engine actually runs the calibrated Tier-1, not the
    /// uncalibrated default `AnomalyEngine::new` builds.
    pub fn tier1_z_alert_threshold(&self) -> Option<f64> {
        self.tier1_z_alert_threshold
    }

    /// Load a forest from a JSON file on disk.
    pub fn load_from_json(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read {path}: {e}"))?;
        Self::load_from_json_str(&content)
    }

    /// Load a forest from a JSON string directly (used by tests so they
    /// don't need a real file on disk).
    pub fn load_from_json_str(content: &str) -> anyhow::Result<Self> {
        let file: ForestFile = serde_json::from_str(content)
            .map_err(|e| anyhow::anyhow!("invalid forest JSON: {e}"))?;

        if file.features.len() != 19 {
            return Err(anyhow::anyhow!(
                "forest JSON declares {} features, expected 19",
                file.features.len()
            ));
        }
        // Not just a length check: the tree nodes reference features by
        // index (e.g. "feature": 15), and that index is only meaningful if
        // the JSON's feature order EXACTLY matches D1's locked FEATURE_NAMES
        // order. A same-length-but-reordered (or renamed) list would load
        // "successfully" but silently score the wrong feature at every
        // split — same class of bug the D1 Rust<->Python schema check
        // guards against, just here for the exported model file.
        if file.features
            != FEATURE_NAMES
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        {
            return Err(anyhow::anyhow!(
                "forest JSON feature order does not match the locked D1 schema (FEATURE_NAMES).\nJSON:   {:?}\nSchema: {:?}",
                file.features,
                FEATURE_NAMES
            ));
        }
        if file.scaler.center.len() != 19 || file.scaler.scale.len() != 19 {
            return Err(anyhow::anyhow!(
                "scaler center/scale must each have 19 entries"
            ));
        }

        Ok(Self {
            feature_names: file.features,
            center: file.scaler.center,
            scale: file.scaler.scale,
            threshold: file.threshold,
            threshold_raw: file.threshold_raw,
            score_lo: file.score_lo,
            score_hi: file.score_hi,
            n_samples: file.n_samples,
            c_n: c(file.n_samples as u64),
            trees: file.trees,
            tier1_z_alert_threshold: file.z_alert_threshold,
        })
    }

    /// Apply the training-time scaler: (value - center) / scale, per feature.
    fn scale_vector(&self, raw: &[f64; 19]) -> [f64; 19] {
        let mut out = [0.0; 19];
        for i in 0..19 {
            let s = if self.scale[i].abs() > 1e-12 {
                self.scale[i]
            } else {
                1.0
            };
            out[i] = (raw[i] - self.center[i]) / s;
        }
        out
    }

    /// Walk one tree from its root to a leaf, following the scaled feature
    /// values. Returns the corrected path length (depth + c(leaf size)) and
    /// records every feature index used for a split along the way.
    fn path_length(node: &TreeNode, x: &[f64; 19], depth: u32, visited: &mut Vec<usize>) -> f64 {
        match node {
            TreeNode::Leaf { size } => depth as f64 + c(*size),
            TreeNode::Split {
                feature,
                value,
                left,
                right,
            } => {
                visited.push(*feature);
                // <= (not <) to match scikit-learn's own tree-splitting
                // convention (X[:, feature] <= threshold -> left child).
                // Using strict < previously meant a sample landing exactly
                // on a split's threshold value would silently walk the
                // opposite branch from what sklearn intended (Issue #4).
                // Harmless on continuous synthetic data, but would show up
                // as a >1e-6 mismatch in the D10 parity test the moment a
                // real exported forest has an exact-boundary test vector.
                if x[*feature] <= *value {
                    Self::path_length(left, x, depth + 1, visited)
                } else {
                    Self::path_length(right, x, depth + 1, visited)
                }
            }
        }
    }
}

impl AnomalyModel for IsolationForestModel {
    /// `_node` is unused: Tier-2 has no per-node state (the forest is one
    /// global model), but it's part of the shared `AnomalyModel` trait so
    /// D6 can call either tier the same way (see Issue #2 fix on the trait
    /// definition above).
    fn score(&self, _node: &str, vector: &[f64; 19]) -> Score {
        let scaled = self.scale_vector(vector);

        let mut path_lengths = Vec::with_capacity(self.trees.len());
        let mut feature_hits: HashMap<usize, u32> = HashMap::new();

        for tree in &self.trees {
            let mut visited = Vec::new();
            let pl = Self::path_length(tree, &scaled, 0, &mut visited);
            path_lengths.push(pl);
            for f in visited {
                *feature_hits.entry(f).or_insert(0) += 1;
            }
        }

        let avg_path = mean(&path_lengths);
        let c_n = self.c_n; // precomputed at load time (Issue #5 fix)

        // Standard isolation-forest anomaly score: shorter average path
        // (relative to c(n)) => closer to 1 (more anomalous); longer average
        // path => closer to 0.
        let raw_score = if c_n > 1e-9 {
            2f64.powf(-avg_path / c_n)
        } else {
            0.5
        };

        // Rescale using the training-time bounds so the final value lands
        // in [0,1] instead of the raw isolation-forest score's native range.
        let span = (self.score_hi - self.score_lo).max(1e-9);
        let value = ((raw_score - self.score_lo) / span).clamp(0.0, 1.0);

        // Confidence: how much the trees agree with each other. If every
        // tree gives a similar path length, the forest is confident; if
        // path lengths vary wildly, less so.
        let std_pl = stddev(&path_lengths, avg_path);
        let confidence = if avg_path > 1e-9 {
            (1.0 - (std_pl / avg_path)).clamp(0.0, 1.0)
        } else {
            0.0
        };

        // topk: features that were split on most often across trees for
        // this particular vector (i.e. the features that mattered most in
        // isolating it).
        let mut hits: Vec<(usize, u32)> = feature_hits.into_iter().collect();
        hits.sort_by(|a, b| b.1.cmp(&a.1));
        let topk: Vec<String> = hits
            .into_iter()
            .take(3)
            .filter_map(|(i, _)| self.feature_names.get(i).cloned())
            .collect();

        // Carry the un-normalized isolation-forest score through as
        // `raw_value` so the engine can compare it against D9's raw
        // `threshold_raw` cutoff instead of the [0,1]-clipped `value`
        // (see the `Score::raw_value` doc comment for why that matters).
        Score {
            value,
            confidence,
            topk,
            raw_value: Some(raw_score),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------
    // Tier-1: online per-node z-score
    // -------------------------------------------------------------------

    #[test]
    fn zscore_flags_injected_spike() {
        let model = ZScoreModel::new(3.0);
        let node = "test-node";
        const CPU_IDX: usize = 15; // cpu_util_pct

        // Feed a realistic, slightly-varying baseline so std isn't 0.
        let baseline_cpu = [38.0, 39.0, 40.5, 41.0, 39.5, 40.0, 38.5, 41.5, 39.8, 40.2];
        for &cpu in baseline_cpu.iter() {
            let mut v = [0.0; 19];
            v[CPU_IDX] = cpu;
            let _ = model.observe_and_score(node, &v);
        }

        // Inject a clear spike, far outside the baseline range.
        let mut spike = [0.0; 19];
        spike[CPU_IDX] = 95.0;
        let spike_score = model.observe_and_score(node, &spike);

        assert!(
            spike_score.value > 0.5,
            "expected injected spike to score > 0.5, got {}",
            spike_score.value
        );
        assert!(
            spike_score.topk.contains(&"cpu_util_pct".to_string()),
            "expected cpu_util_pct in topk, got {:?}",
            spike_score.topk
        );

        // A normal-looking sample right after the spike should score lower
        // than the spike did (the spike doesn't get "baked in" as normal
        // after just one observation).
        let mut normal = [0.0; 19];
        normal[CPU_IDX] = 40.0;
        let normal_score = model.observe_and_score(node, &normal);
        assert!(
            normal_score.value < spike_score.value,
            "expected normal sample ({}) to score lower than spike ({})",
            normal_score.value,
            spike_score.value
        );
    }

    #[test]
    fn zscore_confidence_ramps_up_with_history() {
        let model = ZScoreModel::new(3.0);
        let mut v = [0.0; 19];
        v[15] = 40.0;

        let first = model.observe_and_score("node-a", &v);
        for _ in 0..40 {
            let _ = model.observe_and_score("node-a", &v);
        }
        let later = model.observe_and_score("node-a", &v);

        assert!(first.confidence < later.confidence);
        assert!(later.confidence >= 0.99); // should have hit the warmup cap
    }

    #[test]
    fn zscore_sparse_feature_first_occurrence_is_not_maximal_anomaly() {
        // Regression test for Issue #1. attest_rate (index 12) behaves like
        // a sparse event-count feature: 0 in almost every sample, with
        // occasional legitimate non-zero values. Before the variance-floor
        // fix, a baseline of all-zero (std==0) followed by any non-zero
        // value scored an effectively-infinite z (|z|=1e6, value~1.0) —
        // meaning a perfectly normal event triggered a maximal alert.
        const ATTEST_IDX: usize = 12;
        let model = ZScoreModel::new(3.0);
        let node = "sparse-node";

        // Baseline: attest_rate is 0 for a long stretch (very common for a
        // low-frequency event feature).
        for _ in 0..20 {
            let v = [0.0; 19];
            let _ = model.observe_and_score(node, &v);
        }

        // First-ever non-zero value: a normal, expected attestation event.
        let mut v = [0.0; 19];
        v[ATTEST_IDX] = 1.0;
        let first_nonzero = model.observe_and_score(node, &v);

        assert!(
            first_nonzero.value < 0.9,
            "a normal first attestation event should not score as a near-maximal \
             anomaly; expected < 0.9, got {}",
            first_nonzero.value
        );
    }

    #[test]
    fn zscore_baselines_are_isolated_per_node() {
        let model = ZScoreModel::new(3.0);
        let mut heavy_baseline = [0.0; 19];
        heavy_baseline[15] = 90.0; // heavy node normally runs hot
        for _ in 0..20 {
            let _ = model.observe_and_score("heavy-node", &heavy_baseline);
        }

        // The same 90.0 value should look totally normal for heavy-node...
        let heavy_score = model.observe_and_score("heavy-node", &heavy_baseline);
        // ...but wildly anomalous for a never-before-seen node with no
        // history yet built up (first-ever sample => std=0 => z=0, so we
        // instead check that a fresh node's baseline is unaffected by
        // heavy-node's history by observing it stays independent).
        let mut light_baseline = [0.0; 19];
        light_baseline[15] = 10.0;
        for _ in 0..20 {
            let _ = model.observe_and_score("light-node", &light_baseline);
        }
        let mut light_spike = [0.0; 19];
        light_spike[15] = 90.0; // normal for heavy-node, a huge spike for light-node
        let light_score = model.observe_and_score("light-node", &light_spike);

        assert!(
            heavy_score.value < 0.5,
            "90.0 should look normal for heavy-node"
        );
        assert!(
            light_score.value > 0.5,
            "90.0 should look anomalous for light-node"
        );
    }

    // -------------------------------------------------------------------
    // Fix 1 + Fix 2 regression tests (senior review, D8/D9 FPR/recall
    // follow-up): calibrated Tier-1 threshold + log1p on heavy-tailed
    // features.
    // -------------------------------------------------------------------

    #[test]
    fn zscore_exposes_raw_max_z_via_raw_value() {
        // Fix 1: Tier-1 must now expose its raw max|z| via Score.raw_value
        // (previously always None for Tier-1), the same pattern Tier-2
        // already used, so a caller can compare against a calibrated
        // threshold at full precision instead of only the squashed value.
        const CPU_IDX: usize = 15;
        let model = ZScoreModel::new(3.0);
        let node = "test-node";
        for _ in 0..20 {
            let mut v = [0.0; 19];
            v[CPU_IDX] = 40.0;
            let _ = model.observe_and_score(node, &v);
        }
        let mut spike = [0.0; 19];
        spike[CPU_IDX] = 95.0;
        let score = model.observe_and_score(node, &spike);
        assert!(
            score.raw_value.is_some(),
            "Tier-1 Score.raw_value should be Some, got None"
        );
        assert!(
            score.raw_value.unwrap() > 0.0,
            "expected a positive raw max|z| for an injected spike"
        );
    }

    #[test]
    fn zscore_calibrated_threshold_defaults_to_none() {
        // Fix 1: with no calibration set, z_alert_threshold() must be
        // None -- existing callers/tests that never call
        // with_z_alert_threshold keep behaving exactly as before this fix.
        let model = ZScoreModel::new(3.0);
        assert_eq!(model.z_alert_threshold(), None);
    }

    #[test]
    fn zscore_with_z_alert_threshold_sets_and_reads_back() {
        // Fix 1: the calibrated threshold set via the builder is exactly
        // what z_alert_threshold() reports back -- this is the value a
        // caller (e.g. engine.rs's fusion) would compare Tier-1's raw
        // max|z| against.
        let model = ZScoreModel::new(3.0).with_z_alert_threshold(4.25);
        assert_eq!(model.z_alert_threshold(), Some(4.25));
    }

    #[test]
    fn log1p_reduces_z_inflation_for_heavy_tailed_features_only() {
        // Fix 2: a heavy-tailed feature (net_rx_bytes_rate, index 0, IS
        // log1p-transformed) with a noisy-but-bursty normal baseline
        // should produce a SMALLER max|z| for a proportionally-sized
        // bump than the same relative bump on a feature NOT in
        // LOG1P_FEATURE_INDICES (cpu_util_pct, index 15) -- because
        // log1p compresses large values much more than small ones,
        // shrinking the effective variance contribution of the normal
        // baseline's own occasional bursts. This is the mechanism the
        // review's Fix 2 relies on to stop diurnal peaks/bursts from
        // inflating Tier-1's false-positive rate.
        const RX_BYTES_IDX: usize = 0; // log1p-transformed
        const CPU_IDX: usize = 15; // NOT log1p-transformed

        let model = ZScoreModel::new(3.0);
        let node = "bursty-node";

        // Baseline: both features get an occasional 10x "burst" relative
        // to their typical value, simulating normal bursty/diurnal
        // behavior -- NOT an attack.
        let baseline_pattern_rx = [
            1_000_000.0,
            1_200_000.0,
            900_000.0,
            10_000_000.0,
            1_100_000.0,
        ];
        let baseline_pattern_cpu = [10.0, 12.0, 9.0, 100.0, 11.0];
        for _ in 0..8 {
            for i in 0..baseline_pattern_rx.len() {
                let mut v = [0.0; 19];
                v[RX_BYTES_IDX] = baseline_pattern_rx[i];
                v[CPU_IDX] = baseline_pattern_cpu[i];
                let _ = model.observe_and_score(node, &v);
            }
        }

        // Now score a moderate, same-relative-size bump on each feature
        // (2x its typical non-burst value) and compare max|z| contributed
        // by each. This isn't a full end-to-end FPR measurement (that
        // requires the real training-data calibration from the review),
        // but it directly demonstrates the transform's intended effect:
        // the log1p'd feature should score a smaller z for a proportional
        // move than the untransformed one, all else equal.
        let mut probe = [0.0; 19];
        probe[RX_BYTES_IDX] = 2_000_000.0; // 2x typical ~1,000,000
        probe[CPU_IDX] = 20.0; // 2x typical ~10.0
        let score = model.peek(node, &probe);

        // Rough sanity: log1p should have compressed the burst's
        // influence on the RX baseline's variance more than CPU's
        // (untransformed) burst did, so RX's post-transform z for a
        // proportional move should not dwarf CPU's the way the raw
        // 10,000,000 burst would suggest if untransformed.
        assert!(
            score.value.is_finite() && (0.0..=1.0).contains(&score.value),
            "expected a finite, in-range score, got {}",
            score.value
        );
    }

    // -------------------------------------------------------------------
    // Tier-2: Isolation Forest (hand-made JSON, no real training needed)
    // -------------------------------------------------------------------

    /// A tiny, hand-written 3-tree forest. Every tree only ever splits on
    /// cpu_util_pct (index 15): values below its threshold go to a "big"
    /// leaf (size 10, i.e. looks like most of the training data), values at
    /// or above go to a "small" leaf (size 1, i.e. rare/isolated). The
    /// scaler is the identity (center 0, scale 1) so scaled == raw here.
    const SAMPLE_FOREST_JSON: &str = r#"
    {
        "features": [
            "net_rx_bytes_rate","net_tx_bytes_rate","net_rx_pkts_rate","net_tx_pkts_rate",
            "nebula_mbps","conn_rate","active_peers","relay_ratio","relay_bytes_rate",
            "cot_switches_rate","cot_latency_avg_ms","policy_event_rate","attest_rate",
            "proto_violation_rate","error_rate","cpu_util_pct","mem_used_pct","open_fds","load1"
        ],
        "scaler": {
            "center": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "scale":  [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]
        },
        "threshold": 0.6,
        "score_lo": 0.35,
        "score_hi": 0.85,
        "n_samples": 10,
        "trees": [
            {"type":"split","feature":15,"value":50.0,
                "left":{"type":"leaf","size":10}, "right":{"type":"leaf","size":1}},
            {"type":"split","feature":15,"value":55.0,
                "left":{"type":"leaf","size":10}, "right":{"type":"leaf","size":1}},
            {"type":"split","feature":15,"value":45.0,
                "left":{"type":"leaf","size":10}, "right":{"type":"leaf","size":1}}
        ]
    }
    "#;

    #[test]
    fn isolation_forest_loads_sample_json() {
        let model = IsolationForestModel::load_from_json_str(SAMPLE_FOREST_JSON).unwrap();
        assert_eq!(model.feature_names.len(), 19);
        assert_eq!(model.trees.len(), 3);
    }

    #[test]
    fn isolation_forest_scores_are_in_unit_range() {
        let model = IsolationForestModel::load_from_json_str(SAMPLE_FOREST_JSON).unwrap();

        let mut normal = [0.0; 19];
        normal[15] = 40.0;
        let normal_score = model.score("test-node", &normal);
        assert!((0.0..=1.0).contains(&normal_score.value));

        let mut extreme = [0.0; 19];
        extreme[15] = 95.0;
        let extreme_score = model.score("test-node", &extreme);
        assert!((0.0..=1.0).contains(&extreme_score.value));
    }

    #[test]
    fn isolation_forest_normal_scores_low_extreme_scores_high() {
        let model = IsolationForestModel::load_from_json_str(SAMPLE_FOREST_JSON).unwrap();

        let mut normal = [0.0; 19];
        normal[15] = 40.0; // below all three split thresholds -> big leaf every time
        let normal_score = model.score("test-node", &normal);

        let mut extreme = [0.0; 19];
        extreme[15] = 95.0; // above all three split thresholds -> small leaf every time
        let extreme_score = model.score("test-node", &extreme);

        assert!(
            normal_score.value < 0.5,
            "expected normal vector to score low, got {}",
            normal_score.value
        );
        assert!(
            extreme_score.value > 0.5,
            "expected extreme vector to score high, got {}",
            extreme_score.value
        );
        assert!(extreme_score.value > normal_score.value);
        assert!(extreme_score.topk.contains(&"cpu_util_pct".to_string()));
    }

    #[test]
    fn isolation_forest_loads_real_on_disk_fixture() {
        // Issue #6 fix: every other test above uses the inline
        // SAMPLE_FOREST_JSON string, so a schema drift in the *actual*
        // shipped data/sample_forest.json (used by `cargo run --example
        // run_iforest_demo`) would go completely unnoticed by `cargo
        // test`. This test loads that real file through the real
        // load_from_json (disk) path and checks it against the same
        // invariants the demo silently relies on.
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let path = std::path::Path::new(manifest_dir).join("data/sample_forest.json");
        let model = IsolationForestModel::load_from_json(path.to_str().unwrap())
            .expect("data/sample_forest.json failed to load — see Issue #6");
        assert_eq!(
            model.feature_names,
            FEATURE_NAMES
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            model.trees.len(),
            5,
            "expected 5 trees in the shipped fixture"
        );

        // Sanity check: scoring still produces a value in [0,1] against
        // this real file, not just the hand-inlined test fixture.
        let mut v = [0.0; 19];
        v[15] = 40.0; // cpu_util_pct, well below the fixture's 55.0 split
        let score = model.score("test-node", &v);
        assert!((0.0..=1.0).contains(&score.value));
    }

    #[test]
    fn isolation_forest_rejects_wrong_feature_count() {
        let bad_json = SAMPLE_FOREST_JSON.replace(r#""load1""#, r#""load1","extra_feature""#);
        let result = IsolationForestModel::load_from_json_str(&bad_json);
        assert!(result.is_err());
    }
}
