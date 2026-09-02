//! Locked 19-feature schema (D1).
//!
//! This list is the single source of truth for feature order. It must be
//! copied verbatim (same order) into the Python trainer's FEATURES list.
//! Any change here MUST be mirrored there, or Python<->Rust parity (D10)
//! will fail.

pub const FEATURE_NAMES: [&str; 19] = [
    "net_rx_bytes_rate",
    "net_tx_bytes_rate",
    "net_rx_pkts_rate",
    "net_tx_pkts_rate",
    "nebula_mbps",
    "conn_rate",
    "active_peers",
    "relay_ratio",
    "relay_bytes_rate",
    "cot_switches_rate",
    "cot_latency_avg_ms",
    "policy_event_rate",
    "attest_rate",
    "proto_violation_rate",
    "error_rate",
    "cpu_util_pct",
    "mem_used_pct",
    "open_fds",
    "load1",
];

/// The derived, ready-to-score feature vector (rates + rolling EWMA applied
/// to a RawSample). Order MUST match FEATURE_NAMES above.
///
/// This carries the SMOOTHED values only (unchanged from before, so every
/// existing `fv.0` call site keeps working as-is). The matching RAW
/// (unsmoothed) vector for the same sample is available separately via
/// `FeatureExtractor::last_raw()` -- see that method's doc comment for why
/// Tier-2 needs the raw vector instead of this smoothed one.
#[derive(Debug, Clone, Copy)]
pub struct FeatureVector(pub [f64; 19]);

/// D3: turns a stream of `RawSample` into a stream of `FeatureVector`.
///
/// - Counter fields (net_rx_bytes_total, conn_total, ...) become a
///   per-second rate: (current - previous) / dt_seconds.
/// - Gauge fields (cpu_util_pct, load1, ...) are used as-is.
/// - An EWMA (exponentially weighted moving average) is then applied to
///   every one of the 19 values to smooth out noise, with smoothing factor
///   `alpha` (0 < alpha <= 1; alpha = 1.0 disables smoothing entirely,
///   useful for tests; smaller alpha = smoother but slower to react).
pub struct FeatureExtractor {
    prev: Option<crate::telemetry::RawSample>,
    ewma: [f64; 19],
    last_raw: [f64; 19],
    alpha: f64,
    warm: bool,
}

impl FeatureExtractor {
    pub fn new(alpha: f64) -> Self {
        assert!(alpha > 0.0 && alpha <= 1.0, "alpha must be in (0, 1]");
        Self {
            prev: None,
            ewma: [0.0; 19],
            last_raw: [0.0; 19],
            alpha,
            warm: false,
        }
    }

    /// True once at least two samples have been seen (so rates are real,
    /// not the 0.0 placeholder used for the very first sample).
    pub fn warm(&self) -> bool {
        self.warm
    }

    /// The UNSMOOTHED (raw) vector from the most recent `update()` call --
    /// same 19 numbers, before EWMA is applied. Tier-2 (Isolation Forest)
    /// must score THIS, not the smoothed `FeatureVector`: D9's training
    /// (prep.py) fit the model on raw CSV values with no smoothing, so
    /// scoring smoothed values at runtime is a train/serve mismatch. It
    /// also directly caused a real bug: EWMA's exponential "memory" keeps
    /// smoothed values elevated for several samples after an attack window
    /// genuinely ends (smoothed[t] = alpha*raw[t] + (1-alpha)*smoothed[t-1]
    /// decays gradually, not instantly), so Tier-2 kept seeing high values
    /// and false-alerting one row after e.g. a proto_violation window had
    /// already ended. Tier-1 should keep using the smoothed `FeatureVector`
    /// (`.0`) -- it's an online baseline that benefits from the extra
    /// noise reduction and isn't trained against any fixed reference.
    pub fn last_raw(&self) -> [f64; 19] {
        self.last_raw
    }

    pub fn update(&mut self, raw: &crate::telemetry::RawSample) -> FeatureVector {
        let dt_seconds = match &self.prev {
            Some(p) => ((raw.ts_ms.saturating_sub(p.ts_ms)) as f64 / 1000.0).max(1e-3),
            None => 1.0,
        };

        let rate = |curr: u64, prev_val: u64| -> f64 {
            (curr.saturating_sub(prev_val)) as f64 / dt_seconds
        };

        let raw_values: [f64; 19] = match &self.prev {
            Some(p) => [
                rate(raw.net_rx_bytes_total, p.net_rx_bytes_total),
                rate(raw.net_tx_bytes_total, p.net_tx_bytes_total),
                rate(raw.net_rx_pkts_total, p.net_rx_pkts_total),
                rate(raw.net_tx_pkts_total, p.net_tx_pkts_total),
                raw.nebula_mbps,
                rate(raw.conn_total, p.conn_total),
                raw.active_peers,
                raw.relay_ratio,
                rate(raw.relay_bytes_total, p.relay_bytes_total),
                rate(raw.cot_switches_total, p.cot_switches_total),
                raw.cot_latency_avg_ms,
                rate(raw.policy_event_total, p.policy_event_total),
                rate(raw.attest_total, p.attest_total),
                rate(raw.proto_violation_total, p.proto_violation_total),
                rate(raw.error_total, p.error_total),
                raw.cpu_util_pct,
                raw.mem_used_pct,
                raw.open_fds,
                raw.load1,
            ],
            // First-ever sample: no previous counter to diff against, so
            // rates are reported as 0.0. Gauges are still real values.
            None => [
                0.0,
                0.0,
                0.0,
                0.0,
                raw.nebula_mbps,
                0.0,
                raw.active_peers,
                raw.relay_ratio,
                0.0,
                0.0,
                raw.cot_latency_avg_ms,
                0.0,
                0.0,
                0.0,
                0.0,
                raw.cpu_util_pct,
                raw.mem_used_pct,
                raw.open_fds,
                raw.load1,
            ],
        };

        let was_first_sample = self.prev.is_none();
        self.last_raw = raw_values;

        if was_first_sample {
            // Seed the EWMA state directly from the first observation
            // instead of blending against an internal 0.0 (Issue #3 fix).
            // Previously every feature's smoothed output started biased
            // low for roughly the first 1/alpha samples, since the first
            // `update()` produced `alpha * raw` rather than `raw`. Gauges
            // in particular (cpu_util_pct, load1, ...) have no reason to
            // start at a phantom "0" baseline just because it's the first
            // sample seen.
            self.ewma = raw_values;
        } else {
            for i in 0..19 {
                self.ewma[i] = self.alpha * raw_values[i] + (1.0 - self.alpha) * self.ewma[i];
            }
        }

        self.prev = Some(raw.clone());
        if !was_first_sample {
            self.warm = true;
        }

        FeatureVector(self.ewma)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_has_exactly_19_features() {
        assert_eq!(FEATURE_NAMES.len(), 19);
    }

    #[test]
    fn schema_matches_shared_json_source_of_truth() {
        // Cross-checks the hardcoded Rust list against schema/feature_names.json,
        // which the Python side (features.py) also reads. If someone edits one
        // side and forgets the other, this test fails instead of silently
        // diverging (see Issue #2).
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let json_path = std::path::Path::new(manifest_dir).join("../../schema/feature_names.json");
        let content = std::fs::read_to_string(&json_path)
            .unwrap_or_else(|e| panic!("could not read {json_path:?}: {e}"));
        let from_json: Vec<String> = content
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split(',')
            .map(|s| s.trim().trim_matches('"').to_string())
            .collect();
        let from_rust: Vec<String> = FEATURE_NAMES.iter().map(|s| s.to_string()).collect();
        assert_eq!(
            from_rust, from_json,
            "features.rs FEATURE_NAMES does not match schema/feature_names.json"
        );
    }

    #[test]
    fn schema_has_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for name in FEATURE_NAMES.iter() {
            assert!(seen.insert(name), "duplicate feature name: {name}");
        }
    }

    fn sample(
        ts_ms: u64,
        net_rx_bytes_total: u64,
        conn_total: u64,
        cpu_util_pct: f64,
    ) -> crate::telemetry::RawSample {
        crate::telemetry::RawSample {
            ts_ms,
            net_rx_bytes_total,
            conn_total,
            cpu_util_pct,
            ..Default::default()
        }
    }

    #[test]
    fn vector_has_19_values() {
        let mut extractor = FeatureExtractor::new(1.0);
        let fv = extractor.update(&sample(1000, 100, 1, 10.0));
        assert_eq!(fv.0.len(), 19);
    }

    #[test]
    fn first_sample_is_not_warm() {
        let mut extractor = FeatureExtractor::new(1.0);
        extractor.update(&sample(1000, 100, 1, 10.0));
        assert!(
            !extractor.warm(),
            "extractor should not be warm after only 1 sample"
        );
    }

    #[test]
    fn second_sample_is_warm() {
        let mut extractor = FeatureExtractor::new(1.0);
        extractor.update(&sample(1000, 100, 1, 10.0));
        extractor.update(&sample(2000, 200, 2, 12.0));
        assert!(extractor.warm(), "extractor should be warm after 2 samples");
    }

    #[test]
    fn counter_becomes_correct_rate() {
        // alpha = 1.0 disables EWMA smoothing so we can check the raw rate exactly.
        let mut extractor = FeatureExtractor::new(1.0);
        extractor.update(&sample(1000, 1000, 10, 10.0)); // t=1.000s, 1000 bytes so far
        let fv = extractor.update(&sample(2000, 3000, 10, 10.0)); // t=2.000s, 3000 bytes so far
                                                                  // delta = 2000 bytes over 1.0 second => 2000 bytes/sec
        assert!(
            (fv.0[0] - 2000.0).abs() < 1e-6,
            "expected net_rx_bytes_rate ~2000, got {}",
            fv.0[0]
        );
    }

    #[test]
    fn gauge_passes_through_unchanged() {
        let mut extractor = FeatureExtractor::new(1.0);
        extractor.update(&sample(1000, 0, 0, 42.5));
        let fv = extractor.update(&sample(2000, 0, 0, 55.0));
        // cpu_util_pct is feature index 15 (0-based), a gauge, no rate math applied.
        assert!(
            (fv.0[15] - 55.0).abs() < 1e-6,
            "expected cpu_util_pct passthrough 55.0, got {}",
            fv.0[15]
        );
    }

    #[test]
    fn counter_never_goes_negative_on_reset() {
        // If a counter resets (e.g. process restart), saturating_sub must not panic or go negative.
        let mut extractor = FeatureExtractor::new(1.0);
        extractor.update(&sample(1000, 5000, 50, 10.0));
        let fv = extractor.update(&sample(2000, 100, 1, 10.0)); // counter dropped
        assert!(
            fv.0[0] >= 0.0,
            "rate must never be negative even after counter reset"
        );
    }

    #[test]
    fn ewma_converges_to_constant_input() {
        // Feeding the same gauge value repeatedly should make the smoothed
        // output converge to that value, regardless of smoothing factor.
        let mut extractor = FeatureExtractor::new(0.3); // moderate smoothing
        let mut fv = extractor.update(&sample(1000, 0, 0, 50.0));
        for t in 2..50 {
            fv = extractor.update(&sample(t * 1000, 0, 0, 50.0));
        }
        // cpu_util_pct is index 15
        assert!(
            (fv.0[15] - 50.0).abs() < 0.01,
            "expected EWMA to converge to 50.0, got {}",
            fv.0[15]
        );
    }

    #[test]
    fn ewma_first_update_is_seeded_not_biased() {
        // Issue #3 fix: the very first update seeds the EWMA state directly
        // from the raw observation, rather than blending against a phantom
        // internal 0.0 (which used to bias every feature low for roughly
        // the first 1/alpha samples). So the first output must equal the
        // raw value exactly, regardless of alpha.
        let alpha = 0.3;
        let mut extractor = FeatureExtractor::new(alpha);
        let fv = extractor.update(&sample(1000, 0, 0, 80.0));
        assert!(
            (fv.0[15] - 80.0).abs() < 1e-9,
            "expected first output == raw (80.0), got {}",
            fv.0[15]
        );
    }

    #[test]
    fn ewma_second_update_applies_alpha_weight() {
        // The blending formula (new = alpha*raw + (1-alpha)*old) only
        // kicks in from the *second* update onward, once there's a real
        // seeded value to blend against.
        let alpha = 0.3;
        let mut extractor = FeatureExtractor::new(alpha);
        extractor.update(&sample(1000, 0, 0, 80.0)); // seeds ewma[15] = 80.0
        let fv = extractor.update(&sample(2000, 0, 0, 40.0));
        let expected = alpha * 40.0 + (1.0 - alpha) * 80.0;
        assert!(
            (fv.0[15] - expected).abs() < 1e-9,
            "expected {expected}, got {}",
            fv.0[15]
        );
    }

    #[test]
    fn ewma_alpha_one_disables_smoothing() {
        // alpha=1.0 means new = 1.0*raw + 0.0*old = raw, i.e. no smoothing —
        // this is the property every other test in this file relies on.
        let mut extractor = FeatureExtractor::new(1.0);
        extractor.update(&sample(1000, 0, 0, 12.0));
        let fv = extractor.update(&sample(2000, 0, 0, 99.0));
        assert!(
            (fv.0[15] - 99.0).abs() < 1e-9,
            "alpha=1.0 should pass the raw value through unsmoothed"
        );
    }
}
