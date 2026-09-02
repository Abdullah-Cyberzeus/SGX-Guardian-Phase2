//! Engine loop (D6). Depends ONLY on the two traits, never on SGX types.
//!
//! One `AnomalyEngine` = one node's continuous scoring loop:
//!   poll (D4) -> FeatureExtractor.update (D3) -> model.score(node, vector) (D5)
//!   -> fuse tiers -> threshold + cooldown/hysteresis -> sink.emit (D7's AnomalyAlert)
//!
//! NOTE: `RawSample` (D4) carries no node id of its own — in this
//! standalone design one `TelemetrySource` instance represents one node's
//! stream, so the node id is supplied once at construction, not read off
//! each sample. This also means `model.score(&self.node, &vector)` is
//! always called with the real node id, never a placeholder default (see
//! the trait-level note in `model.rs` about Issue #2 — that footgun is
//! now caught at compile time since `node` is a mandatory trait argument).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::alert::{AlertSink, AnomalyAlert};
use crate::baseline::{BaselineLifecycle, BaselineLifecycleConfig};
use crate::features::FeatureExtractor;
use crate::model::{AnomalyModel, IsolationForestModel, Score, ZScoreModel};
use crate::roles::NodeRole;
use crate::roles::RoleBaseline;
use crate::rules::RuleFile;
use crate::telemetry::TelemetrySource;

/// Tunables for D6's threshold/cooldown/hysteresis behavior. Kept separate
/// from `AnomalyEngine`'s other fields so a later deliverable can load
/// these from config without touching the loop logic itself.
pub struct EngineConfig {
    /// How often to poll the source.
    pub poll_interval: Duration,
    /// Fused `score.value` at/above this is "anomalous enough to alert".
    pub alert_threshold: f64,
    /// Fused `score.confidence` must be at/above this to alert at all.
    /// Needed because Tier-1's baseline starts at mean=0 — the very first
    /// real sample on a node is scored against that empty baseline and
    /// can produce a high `value` purely from cold start, before there's
    /// been any real history to judge it against. `confidence` already
    /// tracks this (it ramps up with sample count); this gate makes sure
    /// D6 actually uses it instead of only looking at `value`.
    pub min_confidence: f64,
    /// Once an alert fires for this node, suppress further alerts for
    /// this long — the "cooldown/hysteresis" the plan's D6 asks for, so
    /// one ongoing anomaly doesn't produce one alert per poll.
    pub cooldown: Duration,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(1),
            alert_threshold: 0.8,
            min_confidence: 0.5,
            // A one-minute window still allowed several alerts per hour for
            // normal bursts in the 1 Hz replay. Five minutes preserves the
            // first alert for a sustained attack while reducing repeated
            // operational noise.
            cooldown: Duration::from_secs(5 * 60),
        }
    }
}

pub struct AnomalyEngine {
    node: String,
    source: Box<dyn TelemetrySource>,
    sink: Arc<dyn AlertSink>,
    extractor: FeatureExtractor,
    tier1: Arc<ZScoreModel>,
    /// Tier-2 is optional: it needs a real trained forest (D9's output),
    /// which doesn't exist yet. `None` means "run Tier-1 only" — same
    /// behavior as `run_full_pipeline_demo.rs` when no model_json path is
    /// given.
    tier2: Option<Arc<IsolationForestModel>>,
    /// Optional global -> per-node selector. It reloads only successfully
    /// exported models and never changes the locked 19-feature schema.
    baseline_lifecycle: Option<BaselineLifecycle>,
    config: EngineConfig,
    /// Cooldown expiry keyed by the anomaly's deciding tier and top features,
    /// in the SAME clock as `RawSample.ts_ms` (D4) -- NOT wall-clock.
    /// A portscan-like alert must not suppress a later, different
    /// resource-exhaustion-like alert on the same node.
    ///
    /// FIX: this used to be `Option<Instant>` (real wall-clock time),
    /// which made cooldown expiry depend on how fast the engine happened
    /// to process ticks -- fine on a real board (where poll_interval is a
    /// real 1s and ts_ms IS wall-clock), but non-deterministic when
    /// replaying historical data fast (e.g. demos compressing an hour of
    /// CSV into under a second): the SAME input file could produce
    /// different repeated-alert rows between runs, depending on OS
    /// scheduling jitter at that timescale. Anchoring to `ts_ms` instead
    /// makes cooldown expiry a pure function of the data, identical on
    /// every run regardless of processing speed -- and in production,
    /// ts_ms is populated from real time anyway (see scrape.rs), so this
    /// changes nothing about real-board behavior.
    cooldown_until: HashMap<String, u64>,
    /// Role baseline is deliberately shadow-only for now. It learns from
    /// normal rows but never changes current node-level fused decisions.
    role_baseline: Option<RoleBaseline>,
    /// Loaded once at startup. Invalid or missing JSON safely becomes the
    /// built-in rule set, so scoring never loses recommendation support.
    recommendation_rules: Arc<RuleFile>,
}

impl AnomalyEngine {
    /// `node` must be the real node id — it's what keeps Tier-1's
    /// per-node baseline (and any future per-node state) from mixing
    /// different nodes together.
    pub fn new(
        node: impl Into<String>,
        source: Box<dyn TelemetrySource>,
        sink: Arc<dyn AlertSink>,
    ) -> Self {
        Self {
            node: node.into(),
            source,
            sink,
            extractor: FeatureExtractor::new(0.3), // same alpha the demos use
            tier1: Arc::new(ZScoreModel::new(3.0)), // |z|=3 => value=0.5, matches demos
            tier2: None,
            baseline_lifecycle: None,
            config: EngineConfig::default(),
            cooldown_until: HashMap::new(),
            role_baseline: None,
            recommendation_rules: Arc::new(RuleFile::load_or_default(
                "config/recommendation_rules.json",
            )),
        }
    }

    /// Attach a trained Tier-2 model (D9's output). Optional — the engine
    /// runs fine on Tier-1 alone until a real forest exists.
    pub fn with_tier2(mut self, model: IsolationForestModel) -> Self {
        self.tier2 = Some(Arc::new(model));
        self
    }

    /// Load a per-node forest when available, otherwise the global fallback.
    /// The selected file is rechecked at the configured interval, so placing a
    /// validated per-node export after the minimum collection period promotes
    /// the running node without a manual code/config switch.
    pub fn try_with_baseline_lifecycle(mut self, config_path: &str) -> anyhow::Result<Self> {
        let config = BaselineLifecycleConfig::from_path(config_path)?;
        let (lifecycle, model) = BaselineLifecycle::load(self.node.clone(), config)?;
        eprintln!(
            "baseline selected for {}: {:?}",
            self.node, lifecycle.active_kind
        );
        self.tier2 = Some(Arc::new(model));
        self.baseline_lifecycle = Some(lifecycle);
        Ok(self)
    }
    pub fn with_tier1_calibrated_z(mut self, z_alert_threshold: f64) -> Self {
        self.tier1 = Arc::new(ZScoreModel::new(3.0).with_z_alert_threshold(z_alert_threshold));
        self
    }
    /// Attach a shared role baseline in shadow mode. This preserves the
    /// existing per-node global baseline and therefore leaves alert results
    /// unchanged while role-level normal history is collected.
    pub fn with_shadow_role_baseline(mut self, baseline: RoleBaseline) -> Self {
        self.role_baseline = Some(baseline);
        self
    }
    /// Override startup-loaded recommendation rules (primarily for callers
    /// embedding the engine or deterministic tests).
    pub fn with_recommendation_rules(mut self, rules: RuleFile) -> Self {
        self.recommendation_rules = Arc::new(rules);
        self
    }
    /// Override the default poll interval / threshold / cooldown.
    pub fn with_config(mut self, config: EngineConfig) -> Self {
        self.config = config;
        self
    }

    /// Override the default EWMA smoothing (0.3). Mainly useful for tests
    /// that want alpha=1.0 (no smoothing) so injected values show up
    /// immediately, same convention `run_full_pipeline_demo.rs` uses.
    pub fn with_alpha(mut self, alpha: f64) -> Self {
        self.extractor = FeatureExtractor::new(alpha);
        self
    }

    /// Override `alert_threshold` after construction. `run_d5_d6_d7_demo.rs`
    /// calls this via its 3rd CLI arg to experiment with different cutoffs
    /// against a given trained model.
    pub fn with_tier2_alert_threshold(mut self, threshold: f64) -> Self {
        self.config.alert_threshold = threshold;
        self
    }

    /// Main loop. Never returns under normal operation. Depends only on
    /// the two traits (`TelemetrySource`, `AlertSink`) — never on SGX
    /// types, so this same loop runs unchanged standalone and once D12
    /// swaps in `SgxTelemetrySource`/`SgxAlertSink`.
    pub async fn run(&mut self) {
        let mut interval = tokio::time::interval(self.config.poll_interval);
        loop {
            interval.tick().await;
            self.tick().await;
        }
    }

    /// One iteration of the loop, pulled out of `run()` so tests can call
    /// it directly against a `MockSource` instead of racing a real timer.
    pub async fn tick(&mut self) {
        if let Some(lifecycle) = &mut self.baseline_lifecycle {
            match lifecycle.maybe_reload() {
                Ok(Some((kind, model))) => {
                    eprintln!("baseline reloaded for {}: {:?}", self.node, kind);
                    self.tier2 = Some(Arc::new(model));
                }
                Ok(None) => {}
                Err(error) => eprintln!("baseline reload skipped for {}: {error}", self.node),
            }
        }
        // D4: get the next raw sample.
        let raw = self.source.poll().await;

        // D3: convert it into the 19-number feature vector.
        let fv = self.extractor.update(&raw);

        // D5, Tier-1: scores the SMOOTHED vector -- an online baseline
        // benefits from EWMA's noise reduction, and it isn't compared
        // against any fixed external reference, so smoothing is fine here.
        let tier1_score = self.tier1.peek(&self.node, &fv.0);

        // D5, Tier-2 (only if attached): scores the RAW (unsmoothed)
        // vector, NOT `fv.0`. D9 trained this model on raw CSV values with
        // no smoothing, so feeding it smoothed values at runtime is a
        // train/serve mismatch -- it also caused a real false-positive bug
        // where EWMA's decaying "memory" of an attack kept Tier-2 alerting
        // for a sample or two after the attack window had genuinely ended.
        // See FeatureExtractor::last_raw()'s doc comment for the full story.
        let raw_vector = self.extractor.last_raw();
        let tier2_score: Option<Score> = if let Some(model) = &self.tier2 {
            let model = Arc::clone(model);
            let node = self.node.clone();
            match tokio::task::spawn_blocking(move || model.score(&node, &raw_vector)).await {
                Ok(score) => Some(score),
                Err(e) => {
                    // A panic inside the blocking task shouldn't take down
                    // the whole engine loop — log and fall back to
                    // Tier-1-only for this one tick.
                    eprintln!("tier-2 scoring task failed: {e}");
                    None
                }
            }
        } else {
            None
        };

        // Fuse: worst-tier-wins (same strategy as the Python pipeline) —
        // the fused score is whichever tier is currently most alarmed,
        // not an average, so one tier catching something the other
        // misses still surfaces. `winning_tier` records which one, for
        // both alert attribution and the confidence gate below.
        // Each tier has a threshold on a different native score scale. A
        // normalized-score "winner" must never suppress an alert from the
        // other tier: fusion is explicitly OR, not "the higher normalized
        // score clears its own threshold".
        let tier1_hit = self.tier1_crosses_calibrated_threshold(&tier1_score);
        let tier2_hit = tier2_score
            .as_ref()
            .map(|score| self.tier2_crosses_calibrated_threshold(score))
            .unwrap_or(false);
        let (fused, winning_tier) =
            fuse_alerting(&tier1_score, tier2_score.as_ref(), tier1_hit, tier2_hit);
        let incident_key = incident_key(&fused, &self.recommendation_rules);

        // Decide, BEFORE emitting, whether this sample counts as "still
        // anomalous/cooling down" right now — if so, don't fold it into
        // Tier-1's baseline (it's attack behavior, not normal behavior).
        // Otherwise, fold it in as usual so the baseline keeps tracking
        // genuine normal drift over time.
        //
        // Gate on tier1_score.confidence, NOT fused.confidence -- see
        // fuse()'s doc comment. This must stay in sync with maybe_alert's
        // own gate below (both decide "would this alert fire", just at
        // slightly different points in the tick).
        let currently_cooling_down = matches!(
            self.cooldown_until.get(&incident_key),
            Some(until) if raw.ts_ms < *until
        );
        let threshold_crossed = tier1_hit || tier2_hit;
        let would_alert_now =
            tier1_score.confidence >= self.config.min_confidence && threshold_crossed;
        if !currently_cooling_down && !would_alert_now {
            self.tier1.fold(&self.node, &fv.0);
            if let Some(role_baseline) = &self.role_baseline {
                // Score is intentionally discarded in shadow mode. The role
                // baseline only receives rows that current production logic
                // has already judged normal, so attacks cannot poison it.
                let _shadow_score = role_baseline.peek(&self.node, &fv.0);
                role_baseline.fold_normal(&self.node, &fv.0);
            }
        }

        self.maybe_alert(
            fused,
            winning_tier,
            &incident_key,
            threshold_crossed,
            tier1_score.confidence,
            raw.ts_ms,
        );
    }

    fn tier1_crosses_calibrated_threshold(&self, score: &Score) -> bool {
        match (score.raw_value, self.tier1.z_alert_threshold()) {
            (Some(raw), Some(z)) => raw >= z,
            _ => score.value >= self.config.alert_threshold,
        }
    }

    fn tier2_crosses_calibrated_threshold(&self, score: &Score) -> bool {
        match (
            score.raw_value,
            self.tier2.as_ref().and_then(|m| m.raw_alert_threshold()),
        ) {
            (Some(raw), Some(t)) => raw >= t,
            _ => score.value >= self.config.alert_threshold,
        }
    }

    /// Threshold + cooldown/hysteresis: only actually emit an alert when
    /// the fused score clears `alert_threshold` AND the node isn't still
    /// inside a cooldown window from a previous alert.
    ///
    /// `ts_ms` is the CURRENT sample's own timestamp (D4's `RawSample.ts_ms`),
    /// not wall-clock -- see the `cooldown_until` field doc for why.
    ///
    /// `tier1_confidence` is TIER-1's own confidence, passed separately
    /// from `fused` -- the gate below must never use `fused.confidence`
    /// directly (see `fuse()`'s doc comment for why that was a real bug).
    fn maybe_alert(
        &mut self,
        fused: Score,
        winning_tier: crate::alert::AlertTier,
        incident_key: &str,
        threshold_crossed: bool,
        tier1_confidence: f64,
        ts_ms: u64,
    ) {
        if let Some(until) = self.cooldown_until.get(incident_key) {
            if ts_ms < *until {
                // Still cooling down from the last alert on this node —
                // this is the hysteresis the plan asks for: one ongoing
                // anomaly should not produce one alert per poll.
                return;
            }
        }

        if tier1_confidence < self.config.min_confidence {
            // Not enough history yet to trust ANY score for this node —
            // most relevant right after a node's very first few samples,
            // when Tier-1's baseline is still close to its cold-start
            // mean=0 state. Always Tier-1's confidence (warm-up), never
            // Tier-2's (tree-agreement) -- see fuse()'s doc comment.
            return;
        }

        if !threshold_crossed {
            return;
        }

        // Fires. Start (or restart) the cooldown window, anchored to this
        // sample's own timestamp so expiry is reproducible.
        self.cooldown_until.insert(
            incident_key.to_string(),
            ts_ms + self.config.cooldown.as_millis() as u64,
        );

        // D7: reason/recommendation/severity are built from the fused
        // topk features (crate::alert), not hardcoded here anymore.
        let role = self
            .role_baseline
            .as_ref()
            .map(|baseline| baseline.role_for(&self.node))
            .unwrap_or(NodeRole::Unknown);
        let (recommendation, action) = crate::alert::build_recommendation_with_rules(
            &self.node,
            &fused.topk,
            role,
            &self.recommendation_rules,
        );
        let alert = AnomalyAlert {
            ts: ts_ms,
            node: self.node.clone(),
            role,
            score: fused.value,
            confidence: fused.confidence,
            severity: crate::alert::severity_for(fused.value),
            reason: crate::alert::build_reason(
                &self.node,
                fused.value,
                self.config.alert_threshold,
                &fused.topk,
            ),
            recommendation,
            action,
            topk: fused.topk,
            tier: winning_tier,
        };

        self.sink.emit(alert);
    }
}

/// Worst-tier-wins fusion: take whichever tier scored higher. If Tier-2
/// isn't attached yet, Tier-1 alone decides. `topk`/`confidence` in the
/// returned `Score` are carried over from whichever tier "won", since
/// mixing per-tier explainability lists would not mean anything coherent.
///
/// Also returns `AlertTier` (which tier actually decided this), because
/// callers need it for two separate reasons:
///   1. `AnomalyAlert.tier` (M3 fix, see alert.rs) -- so false positives
///      can be localised to a tier instead of staying an unattributed lump.
///   2. `maybe_alert`'s confidence gate must use TIER-1's confidence
///      specifically, never whichever tier's Score happened to win here.
///      Tier-2's own "confidence" measures inter-tree agreement, not
///      history/warm-up -- a genuinely novel attack can make Tier-2's
///      trees strongly DISAGREE on path length (which is exactly what
///      lowers that number) even while its anomaly value is maxed out.
///      Gating on Tier-2's confidence in that case silently drops real
///      attacks (observed: value=1.000, tier2 confidence=0.468, alert
///      never fired). `fuse()` returning `fused.confidence` from Tier-2
///      and the caller gating on `fused.confidence` was exactly that bug
///      -- the fix is for the caller to gate on `tier1.confidence` always,
///      which `fuse()` enables by returning the winning tier explicitly.
fn fuse(tier1: &Score, tier2: Option<&Score>) -> (Score, crate::alert::AlertTier) {
    match tier2 {
        Some(t2) if t2.value > tier1.value => (t2.clone(), crate::alert::AlertTier::Tier2),
        _ => (tier1.clone(), crate::alert::AlertTier::Tier1),
    }
}

/// OR fusion with correct threshold attribution. If only one tier crossed
/// its own calibrated cutoff, that tier decides the alert even when the
/// other tier's normalized display score happens to be numerically larger.
fn fuse_alerting(
    tier1: &Score,
    tier2: Option<&Score>,
    tier1_hit: bool,
    tier2_hit: bool,
) -> (Score, crate::alert::AlertTier) {
    match (tier1_hit, tier2_hit, tier2) {
        (true, false, _) => (tier1.clone(), crate::alert::AlertTier::Tier1),
        (false, true, Some(t2)) => (t2.clone(), crate::alert::AlertTier::Tier2),
        _ => fuse(tier1, tier2),
    }
}

/// Stable de-duplication key for one anomaly family.  The exact top-k list
/// changes as an incident evolves, so it must not define a new incident on
/// every tick.  The category is shared across tiers: Tier-1 and Tier-2
/// agreeing on the same incident should produce one human notification.
fn incident_key(score: &Score, rules: &RuleFile) -> String {
    crate::alert::incident_category_with_rules(&score.topk, rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::RawSample;
    use std::sync::Mutex;

    /// Deterministic test source: replays a fixed list of RawSamples,
    /// repeating the last one forever once exhausted (so a test can poll
    /// past the end without panicking).
    struct FixedSampleSource {
        samples: Vec<RawSample>,
        next: usize,
    }

    #[async_trait::async_trait]
    impl TelemetrySource for FixedSampleSource {
        async fn poll(&mut self) -> RawSample {
            let i = self.next.min(self.samples.len() - 1);
            self.next += 1;
            self.samples[i].clone()
        }
    }

    // RawSample already derives Clone (telemetry/mod.rs) — no extra impl
    // needed here.

    /// Test sink: captures every alert instead of printing it.
    #[derive(Default)]
    struct CapturingSink {
        alerts: Mutex<Vec<AnomalyAlert>>,
    }
    impl AlertSink for CapturingSink {
        fn emit(&self, alert: AnomalyAlert) {
            self.alerts.lock().unwrap().push(alert);
        }
    }

    fn cpu_sample(ts_ms: u64, cpu: f64) -> RawSample {
        RawSample {
            ts_ms,
            cpu_util_pct: cpu,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn injected_spike_produces_exactly_one_alert_then_cooldown_suppresses_repeats() {
        // Baseline: a normal, slightly-varying cpu_util_pct, repeated
        // enough times (>= warmup_samples=30 in ZScoreModel) that
        // `confidence` is fully warmed up before the spike arrives — a
        // real deployment would have this from normal operation long
        // before any attack.
        let baseline_pattern = [38.0, 39.0, 40.5, 41.0, 39.5, 40.0, 38.5, 41.5, 39.8, 40.2];
        let mut samples: Vec<RawSample> = (0..40)
            .map(|i| {
                cpu_sample(
                    (i as u64 + 1) * 1000,
                    baseline_pattern[i % baseline_pattern.len()],
                )
            })
            .collect();

        // A sustained spike, far outside the baseline — repeated so the
        // cooldown behavior (not just the first alert) is exercised.
        for i in 0..5 {
            samples.push(cpu_sample((samples.len() as u64 + i + 1) * 1000, 99.0));
        }

        let source = Box::new(FixedSampleSource {
            samples: samples.clone(),
            next: 0,
        });
        let sink = Arc::new(CapturingSink::default());

        let mut engine = AnomalyEngine::new("test-node", source, sink.clone())
            .with_alpha(1.0) // disable EWMA smoothing so the spike is immediate
            .with_config(EngineConfig {
                poll_interval: Duration::from_millis(1), // irrelevant, tick() is called directly
                alert_threshold: 0.8,
                min_confidence: 0.5,
                cooldown: Duration::from_secs(60), // long enough that the test's later ticks stay inside it
            });

        for _ in 0..samples.len() {
            engine.tick().await;
        }

        let alerts = sink.alerts.lock().unwrap();
        assert_eq!(
            alerts.len(),
            1,
            "expected exactly one alert (spike fires once, cooldown suppresses the rest), got {}",
            alerts.len()
        );
        assert_eq!(alerts[0].node, "test-node");
        assert!(alerts[0].score >= 0.8);
        assert!(alerts[0].topk.contains(&"cpu_util_pct".to_string()));
    }

    #[tokio::test]
    async fn normal_baseline_alone_never_alerts() {
        let baseline_pattern = [
            38.0, 39.0, 40.5, 41.0, 39.5, 40.0, 38.5, 41.5, 39.8, 40.2, 39.0, 40.0,
        ];
        let samples: Vec<RawSample> = (0..40)
            .map(|i| {
                cpu_sample(
                    (i as u64 + 1) * 1000,
                    baseline_pattern[i % baseline_pattern.len()],
                )
            })
            .collect();

        let source = Box::new(FixedSampleSource {
            samples: samples.clone(),
            next: 0,
        });
        let sink = Arc::new(CapturingSink::default());

        let mut engine = AnomalyEngine::new("test-node", source, sink.clone()).with_alpha(1.0);

        for _ in 0..samples.len() {
            engine.tick().await;
        }

        assert!(
            sink.alerts.lock().unwrap().is_empty(),
            "a normal, slightly-varying baseline should never cross the alert threshold, even once confidence has warmed up"
        );
    }

    #[tokio::test]
    async fn tier2_runs_via_spawn_blocking_without_panicking() {
        // Exercises the Tier-2 code path specifically (spawn_blocking +
        // fuse), using the same on-disk fixture forest model.rs's own
        // tests load. Not asserting a specific score here — that's
        // model.rs's job — just that wiring a real IsolationForestModel
        // into the engine and ticking it doesn't panic or deadlock.
        let forest = IsolationForestModel::load_from_json("data/sample_forest.json")
            .expect("fixture forest should load");

        let samples: Vec<RawSample> = (0..5)
            .map(|i| cpu_sample((i as u64 + 1) * 1000, 40.0))
            .collect();
        let source = Box::new(FixedSampleSource {
            samples: samples.clone(),
            next: 0,
        });
        let sink = Arc::new(CapturingSink::default());

        let mut engine = AnomalyEngine::new("test-node", source, sink.clone())
            .with_tier2(forest)
            .with_alpha(1.0);

        for _ in 0..samples.len() {
            engine.tick().await;
        }
        // No panic/deadlock across 5 ticks with Tier-2 attached is the
        // whole point of this test.
    }

    #[tokio::test]
    async fn same_input_always_produces_identical_alerts() {
        // Regression test for the senior review's Finding #1: cooldown used
        // to be wall-clock-based (Instant::now()), so the same input file
        // could produce different repeated-alert rows between runs purely
        // from OS scheduling jitter. Now cooldown is anchored to each
        // sample's own ts_ms, so running the exact same input through the
        // exact same config must always fire on the exact same samples.
        let baseline_pattern = [38.0, 39.0, 40.5, 41.0, 39.5, 40.0, 38.5, 41.5, 39.8, 40.2];
        let mut samples: Vec<RawSample> = (0..40)
            .map(|i| {
                cpu_sample(
                    (i as u64 + 1) * 1000,
                    baseline_pattern[i % baseline_pattern.len()],
                )
            })
            .collect();
        // A long spike -- long enough that, with a short cooldown, it
        // would produce MORE than one alert if cooldown is working at all,
        // making this test meaningful (not just "always zero" or "always one").
        for i in 0..200 {
            samples.push(cpu_sample((samples.len() as u64 + i + 1) * 1000, 99.0));
        }

        async fn run_once(samples: &[RawSample]) -> Vec<(u64, f64)> {
            let source = Box::new(FixedSampleSource {
                samples: samples.to_vec(),
                next: 0,
            });
            let sink = Arc::new(CapturingSink::default());
            let mut engine = AnomalyEngine::new("test-node", source, sink.clone())
                .with_alpha(1.0)
                .with_config(EngineConfig {
                    poll_interval: Duration::from_millis(1), // irrelevant, tick() is called directly
                    alert_threshold: 0.8,
                    min_confidence: 0.5,
                    cooldown: Duration::from_secs(10), // short relative to the 200-sample spike, so it fires more than once
                });
            for _ in 0..samples.len() {
                engine.tick().await;
            }
            let result: Vec<(u64, f64)> = sink
                .alerts
                .lock()
                .unwrap()
                .iter()
                .map(|a| (a.ts, a.score))
                .collect();
            result
        }

        let run1 = run_once(&samples).await;
        let run2 = run_once(&samples).await;
        let run3 = run_once(&samples).await;

        assert!(
            run1.len() > 1,
            "test setup should produce more than one alert to be meaningful, got {}",
            run1.len()
        );
        assert_eq!(
            run1, run2,
            "same input/config must produce identical (ts, score) alert sequences"
        );
        assert_eq!(
            run1, run3,
            "same input/config must produce identical (ts, score) alert sequences"
        );
    }

    #[tokio::test]
    async fn high_value_low_tier2_confidence_still_alerts() {
        // Regression test for the confidence-gate bug (Part 4 Q5 / Part 5.1
        // of the review): a genuinely novel attack makes Tier-2's trees
        // DISAGREE on path length, which is exactly what LOWERS Tier-2's
        // own "tree agreement" confidence -- even while its anomaly VALUE
        // is maxed out. Gating on that confidence (instead of Tier-1's
        // warm-up confidence) silently dropped real attacks: the real
        // nodeA case scored value=1.000 but tier2 confidence=0.468/0.473,
        // below the 0.5 default, so no alert ever fired. This test builds
        // a small fixture forest whose trees deliberately disagree on the
        // same input (some isolate it almost immediately, others don't),
        // to reproduce "high value, low Tier-2 confidence" directly,
        // then asserts the engine STILL alerts -- proving the gate uses
        // Tier-1's warm-up confidence, not Tier-2's own.
        let disagreeing_forest_json = r#"{
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
            "threshold": 0.5,
            "score_lo": 0.2,
            "score_hi": 0.9,
            "n_samples": 10,
            "trees": [
                {"type":"split","feature":15,"value":50.0,
                    "left":{"type":"leaf","size":10}, "right":{"type":"leaf","size":1}},
                {"type":"split","feature":15,"value":50.0,
                    "left":{"type":"leaf","size":10}, "right":{"type":"leaf","size":1}},
                {"type":"split","feature":15,"value":50.0,
                    "left":{"type":"leaf","size":10}, "right":{"type":"leaf","size":1}},
                {"type":"split","feature":15,"value":95.0,
                    "left":{"type":"leaf","size":4}, "right":{"type":"leaf","size":1}},
                {"type":"split","feature":15,"value":50.0,
                    "left":{"type":"leaf","size":10}, "right":{"type":"leaf","size":1}}
            ]
        }"#;

        let path = std::env::temp_dir().join("test_disagreeing_forest.json");
        std::fs::write(&path, disagreeing_forest_json).unwrap();
        let forest = IsolationForestModel::load_from_json(path.to_str().unwrap())
            .expect("crafted disagreeing-trees fixture should load");

        // Sanity-check the fixture actually reproduces the bug scenario
        // BEFORE trusting the alert-fired assertion below -- if this
        // fails, the crafted forest needs adjusting, not the engine.
        //
        // cpu_util_pct=51.0 is deliberately BETWEEN the two split
        // thresholds (50.0 and 95.0): 4 of 5 trees (threshold=50) send it
        // right to a size-1 leaf (very short path -> "very anomalous"),
        // while 1 tree (threshold=95) sends it LEFT to a size-4 leaf
        // (longer path -> "fairly normal") -- a genuine 4-vs-1
        // disagreement on this one vector, which is exactly what pulls
        // Tier-2's tree-agreement confidence down while its rescaled
        // value (~0.82) stays comfortably above alert_threshold (0.8).
        // 51.0 (barely past the first threshold) is also deliberately
        // NOT extreme, so Tier-1's z-score-driven value (~0.78, computed
        // against the baseline below) stays BELOW Tier-2's value -- Tier-2
        // must genuinely win the max-fusion for `alerts[0].tier` to
        // legitimately come out `Tier2`, not just be asserted as such.
        // (An earlier version of this fixture used 99.0, which crossed
        // BOTH thresholds, so every tree took the same immediate
        // right-leaf branch and none of them ever disagreed -- confidence
        // came out 1.000 instead of low, and separately would have made
        // Tier-1's own z-score value saturate near 1.0 too, so Tier-1
        // would have won the fusion instead of Tier-2 regardless.)
        let probe = forest.score("probe-node", &{
            let mut v = [0.0; 19];
            v[15] = 51.0; // between the two thresholds -- see comment above
            v
        });
        assert!(
            probe.confidence < 0.5,
            "fixture setup problem: expected LOW tier-2 confidence (tree disagreement) for this \
             test to be meaningful, got confidence={:.3}. Adjust the crafted tree structure.",
            probe.confidence
        );
        assert!(
            probe.value >= 0.5,
            "fixture setup problem: expected HIGH tier-2 value despite low confidence, got value={:.3}",
            probe.value
        );

        // Warm up Tier-1 on an ordinary baseline first, same as the other
        // tests, so `min_confidence` is satisfied via TIER-1's warm-up —
        // the gate this test is protecting.
        let baseline_pattern = [38.0, 39.0, 40.5, 41.0, 39.5, 40.0, 38.5, 41.5, 39.8, 40.2];
        let mut samples: Vec<RawSample> = (0..40)
            .map(|i| {
                cpu_sample(
                    (i as u64 + 1) * 1000,
                    baseline_pattern[i % baseline_pattern.len()],
                )
            })
            .collect();
        // The "attack" sample: cpu_util_pct=51.0, same value the probe
        // above already confirmed gives Tier-2-wins / high-value /
        // low-Tier-2-confidence.
        samples.push(cpu_sample((samples.len() as u64 + 1) * 1000, 51.0));

        let source = Box::new(FixedSampleSource {
            samples: samples.clone(),
            next: 0,
        });
        let sink = Arc::new(CapturingSink::default());

        let mut engine = AnomalyEngine::new("test-node", source, sink.clone())
            .with_tier2(forest)
            .with_alpha(1.0)
            .with_config(EngineConfig {
                poll_interval: Duration::from_millis(1),
                alert_threshold: 0.8,
                min_confidence: 0.5, // gates on TIER-1's confidence, not tier2's
                cooldown: Duration::from_secs(60),
            });

        for _ in 0..samples.len() {
            engine.tick().await;
        }

        let alerts = sink.alerts.lock().unwrap();
        assert_eq!(
            alerts.len(),
            1,
            "a high-value attack must still alert even when TIER-2's own tree-agreement \
             confidence is low -- gating must use Tier-1's warm-up confidence, not Tier-2's. \
             Got {} alert(s).",
            alerts.len()
        );
        assert!(
            matches!(alerts[0].tier, crate::alert::AlertTier::Tier2),
            "this alert should be Tier-2-attributed"
        );
    }
}
