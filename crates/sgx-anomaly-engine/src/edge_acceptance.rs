//! Task1 Issue #10: edge/board acceptance benchmark helpers.
//!
//! This module keeps laptop/dev results separate from real board validation.
//! The same benchmark can be rerun on target hardware without changing code.

use serde::{Deserialize, Serialize};

pub const MAX_MODEL_BYTES: u64 = 10 * 1024 * 1024;
pub const MAX_P95_LATENCY_MS: f64 = 100.0;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeAcceptanceVerdict {
    Pass,
    PassForCurrentMachinePendingTargetBoard,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetProfile {
    pub profile_name: String,
    pub os: String,
    pub arch: String,
    pub family: String,
    pub build_profile: String,
    pub target_board_validated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelFootprint {
    pub artifact_path: String,
    pub size_bytes: u64,
    pub size_mib: f64,
    pub max_allowed_bytes: u64,
    pub pass: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStats {
    pub samples: usize,
    pub min_ms: f64,
    pub avg_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    pub p95_limit_ms: f64,
    pub pass: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryValidation {
    pub rss_measured: bool,
    pub status: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptanceChecks {
    pub model_size_pass: bool,
    pub p95_latency_pass: bool,
    pub target_board_validated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeBenchmarkReport {
    pub schema_version: u32,
    pub issue: String,
    pub node_id: String,
    pub target: TargetProfile,
    pub model: ModelFootprint,
    pub latency: LatencyStats,
    pub memory: MemoryValidation,
    pub checks: AcceptanceChecks,
    pub final_verdict: EdgeAcceptanceVerdict,
}

pub fn model_size_pass(size_bytes: u64) -> bool {
    size_bytes <= MAX_MODEL_BYTES
}

pub fn p95_latency_pass(p95_ms: f64) -> bool {
    p95_ms.is_finite() && p95_ms <= MAX_P95_LATENCY_MS
}

pub fn percentile(sorted_values: &[f64], percentile: f64) -> Option<f64> {
    if sorted_values.is_empty() || !percentile.is_finite() {
        return None;
    }
    let percentile = percentile.clamp(0.0, 100.0);
    let last = sorted_values.len() - 1;
    let index = ((percentile / 100.0) * last as f64).round() as usize;
    sorted_values.get(index).copied()
}

pub fn latency_stats(mut values_ms: Vec<f64>) -> anyhow::Result<LatencyStats> {
    if values_ms.is_empty() {
        anyhow::bail!("latency benchmark needs at least one sample");
    }
    if values_ms.iter().any(|v| !v.is_finite() || *v < 0.0) {
        anyhow::bail!("latency benchmark produced an invalid duration");
    }

    values_ms.sort_by(|a, b| a.total_cmp(b));
    let samples = values_ms.len();
    let min_ms = values_ms[0];
    let max_ms = values_ms[samples - 1];
    let avg_ms = values_ms.iter().sum::<f64>() / samples as f64;
    let p50_ms = percentile(&values_ms, 50.0).unwrap();
    let p95_ms = percentile(&values_ms, 95.0).unwrap();
    let p99_ms = percentile(&values_ms, 99.0).unwrap();

    Ok(LatencyStats {
        samples,
        min_ms,
        avg_ms,
        p50_ms,
        p95_ms,
        p99_ms,
        max_ms,
        p95_limit_ms: MAX_P95_LATENCY_MS,
        pass: p95_latency_pass(p95_ms),
    })
}

pub fn acceptance_verdict(
    model_size_pass: bool,
    p95_latency_pass: bool,
    target_board_validated: bool,
) -> EdgeAcceptanceVerdict {
    if !model_size_pass || !p95_latency_pass {
        EdgeAcceptanceVerdict::Fail
    } else if target_board_validated {
        EdgeAcceptanceVerdict::Pass
    } else {
        EdgeAcceptanceVerdict::PassForCurrentMachinePendingTargetBoard
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_size_limit_is_enforced() {
        assert!(model_size_pass(MAX_MODEL_BYTES));
        assert!(!model_size_pass(MAX_MODEL_BYTES + 1));
    }

    #[test]
    fn p95_latency_limit_is_enforced() {
        assert!(p95_latency_pass(99.9));
        assert!(p95_latency_pass(MAX_P95_LATENCY_MS));
        assert!(!p95_latency_pass(100.1));
    }

    #[test]
    fn percentile_reads_sorted_values() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        assert_eq!(percentile(&values, 0.0), Some(1.0));
        assert_eq!(percentile(&values, 50.0), Some(3.0));
        assert_eq!(percentile(&values, 100.0), Some(5.0));
    }

    #[test]
    fn verdict_stays_pending_without_real_board_validation() {
        assert_eq!(
            acceptance_verdict(true, true, false),
            EdgeAcceptanceVerdict::PassForCurrentMachinePendingTargetBoard
        );
        assert_eq!(
            acceptance_verdict(true, true, true),
            EdgeAcceptanceVerdict::Pass
        );
        assert_eq!(
            acceptance_verdict(false, true, true),
            EdgeAcceptanceVerdict::Fail
        );
    }
}
