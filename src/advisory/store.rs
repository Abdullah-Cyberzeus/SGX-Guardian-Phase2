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
        recommendations.push_back(serde_json::from_slice(line)?);
    }
    Ok(recommendations)
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
