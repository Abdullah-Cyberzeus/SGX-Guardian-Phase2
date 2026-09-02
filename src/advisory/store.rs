use crate::advisory::errors::AdvisoryResult;
use crate::advisory::model::RemediationRecommendation;
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::path::Path;
use std::sync::OnceLock;
use tokio::sync::Mutex;

static STORE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub async fn append_capped(
    path: &Path,
    recommendation: RemediationRecommendation,
    cap: usize,
) -> AdvisoryResult<()> {
    let lock = STORE_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().await;

    let mut recommendations = load(path).await?;
    if let Some(existing) = recommendations
        .iter_mut()
        .rev()
        .find(|seen| seen.alert_id == recommendation.alert_id)
    {
        *existing = recommendation;
    } else {
        recommendations.push_back(recommendation);
    }
    while recommendations.len() > cap {
        recommendations.pop_front();
    }
    save_atomic(path, &recommendations).await
}

pub async fn list_recent(
    path: &Path,
    limit: usize,
) -> AdvisoryResult<Vec<RemediationRecommendation>> {
    let recommendations = load(path).await?;
    let mut items: Vec<_> = recommendations.into_iter().collect();
    if items.len() > limit {
        items.drain(..items.len() - limit);
    }
    Ok(items)
}

pub async fn find_for_alert(
    path: &Path,
    alert_id: &str,
) -> AdvisoryResult<Option<RemediationRecommendation>> {
    Ok(load(path)
        .await?
        .into_iter()
        .rev()
        .find(|recommendation| recommendation.alert_id == alert_id))
}

async fn load(path: &Path) -> AdvisoryResult<VecDeque<RemediationRecommendation>> {
    let bytes = match tokio::fs::read(path).await {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(VecDeque::new()),
        Err(err) => return Err(err.into()),
    };

    let mut recommendations = VecDeque::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let value: serde_json::Value = serde_json::from_slice(line)?;

        let had_advisory_confidence = value.get("advisory_confidence").is_some();
        let had_advisory_basis = value.get("advisory_basis").is_some();
        let had_risk_level = value
            .get("anomaly")
            .and_then(|anomaly| anomaly.get("risk_level"))
            .is_some();

        let mut recommendation: RemediationRecommendation = serde_json::from_value(value)?;

        normalize_legacy_recommendation(
            &mut recommendation,
            had_advisory_confidence,
            had_advisory_basis,
            had_risk_level,
        );

        recommendations.push_back(recommendation);
    }
    Ok(recommendations)
}

fn normalize_legacy_recommendation(
    recommendation: &mut RemediationRecommendation,
    had_advisory_confidence: bool,
    had_advisory_basis: bool,
    had_risk_level: bool,
) {
    // Older records stored advisory confidence only in `confidence`.
    // Backfill only when the new field was actually absent.
    if !had_advisory_confidence {
        recommendation.advisory_confidence = recommendation.confidence;
    }

    if !had_advisory_basis {
        recommendation.advisory_basis =
            "Legacy recommendation: advisory confidence preserved from the confidence field."
                .to_string();
    }

    // Legacy structured anomaly records predate risk_level.
    // Preserve explicitly persisted values on new-format records.
    if !had_risk_level {
        if let Some(anomaly) = recommendation.anomaly.as_mut() {
            anomaly.risk_level = if anomaly.score >= anomaly.critical_threshold {
                crate::advisory::model::AnomalyRiskLevel::Critical
            } else if anomaly.score >= anomaly.high_threshold {
                crate::advisory::model::AnomalyRiskLevel::High
            } else if anomaly.score >= anomaly.threshold {
                crate::advisory::model::AnomalyRiskLevel::Detected
            } else {
                crate::advisory::model::AnomalyRiskLevel::BelowDetection
            };
        }
    }
}

async fn save_atomic(
    path: &Path,
    recommendations: &VecDeque<RemediationRecommendation>,
) -> AdvisoryResult<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let tmp = path.with_extension("jsonl.tmp");
    let mut bytes = Vec::new();
    for recommendation in recommendations {
        serde_json::to_writer(&mut bytes, recommendation)?;
        bytes.push(b'\n');
    }
    tokio::fs::write(&tmp, bytes).await?;
    tokio::fs::rename(tmp, path).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::model::AnomalyRiskLevel;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn legacy_recommendation_load_preserves_confidence_and_anomaly() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "sgx-advisory-legacy-{}-{unique}.jsonl",
            std::process::id()
        ));

        let legacy = r#"{"rec_id":"legacy-rec","alert_id":"legacy-alert","title":"Legacy recommendation","summary":"Legacy persisted recommendation","severity":"high","confidence":0.7695204,"steps":[],"context":[],"references":[],"source":"anomaly-kb","anomaly":{"detected":true,"score":0.51,"threshold":0.5,"normalized_score":0.51,"detector":"task1-alert-scorer","contributors":[]},"generated_at":"2026-08-21T08:04:05Z"}"#;

        tokio::fs::write(&path, format!("{legacy}\n"))
            .await
            .expect("write legacy recommendation");

        let loaded = load(&path).await.expect("load legacy recommendation");
        let recommendation = loaded.front().expect("one recommendation");

        assert!((recommendation.advisory_confidence - recommendation.confidence).abs() < 1e-6);
        assert!(recommendation.advisory_basis.contains("Legacy"));

        let anomaly = recommendation
            .anomaly
            .as_ref()
            .expect("legacy structured anomaly");

        assert!((anomaly.high_threshold - 0.75).abs() < 1e-6);
        assert!((anomaly.critical_threshold - 0.90).abs() < 1e-6);
        assert_eq!(anomaly.risk_level, AnomalyRiskLevel::Detected);

        let _ = tokio::fs::remove_file(&path).await;
    }
}
