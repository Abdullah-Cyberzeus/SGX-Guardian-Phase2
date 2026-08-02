use crate::devices::errors::{DevicesError, DevicesResult};
use crate::devices::model::{DeviceScanProgressTransition, DeviceScanRun};
use chrono::Utc;
use std::path::Path;
use uuid::Uuid;

pub const SCAN_STEPS: [&str; 6] = [
    "Firmware Fingerprint",
    "Open Ports and Services",
    "Encryption Assessment",
    "Known Vulnerability Analysis",
    "Final Security Report",
    "Complete",
];

pub async fn append_run(path: &Path, run: &DeviceScanRun) -> DevicesResult<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut runs = load_runs(path).await.unwrap_or_default();
    runs.push(run.clone());
    if runs.len() > 200 {
        let keep_from = runs.len() - 200;
        runs.drain(0..keep_from);
    }
    let body = runs
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    tokio::fs::write(path, format!("{}\n", body)).await?;
    Ok(())
}

pub async fn load_runs(path: &Path) -> DevicesResult<Vec<DeviceScanRun>> {
    let text = match tokio::fs::read_to_string(path).await {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(DevicesError::from))
        .collect()
}

pub async fn find_run(path: &Path, device_id: &str, scan_id: &str) -> DevicesResult<DeviceScanRun> {
    load_runs(path)
        .await?
        .into_iter()
        .rev()
        .find(|run| run.device_id == device_id && run.scan_id == scan_id)
        .ok_or(DevicesError::NotFound)
}

pub async fn find_run_with_history(
    path: &Path,
    device_id: &str,
    scan_id: &str,
) -> DevicesResult<DeviceScanRun> {
    let matching = load_runs(path)
        .await?
        .into_iter()
        .filter(|run| run.device_id == device_id && run.scan_id == scan_id)
        .collect::<Vec<_>>();
    let mut latest = matching.last().cloned().ok_or(DevicesError::NotFound)?;
    latest.progress_history = progress_history(&matching);
    Ok(latest)
}

fn progress_history(runs: &[DeviceScanRun]) -> Vec<DeviceScanProgressTransition> {
    let mut history: Vec<DeviceScanProgressTransition> = Vec::new();
    for run in runs {
        let transition = DeviceScanProgressTransition {
            step: run.step,
            step_label: run.step_label.clone(),
            state: run.state.clone(),
            timestamp: run
                .updated_at
                .clone()
                .or_else(|| run.finished_at.clone())
                .unwrap_or_else(|| run.started_at.clone()),
        };
        let is_duplicate = history.last().is_some_and(|last| {
            last.step == transition.step
                && last.step_label == transition.step_label
                && last.state == transition.state
        });
        if !is_duplicate {
            history.push(transition);
        }
    }
    history
}

pub fn initial_run(device_id: String) -> DeviceScanRun {
    let now = Utc::now().to_rfc3339();
    DeviceScanRun {
        scan_id: Uuid::new_v4().to_string(),
        device_id,
        step: 1,
        step_label: SCAN_STEPS[0].to_string(),
        state: "running".to_string(),
        started_at: now.clone(),
        updated_at: Some(now),
        finished_at: None,
        findings: Vec::new(),
        recommendations: Vec::new(),
        firmware_assessment: None,
        progress_history: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_run(scan_id: &str, state: &str, step: u8) -> DeviceScanRun {
        DeviceScanRun {
            scan_id: scan_id.to_string(),
            device_id: "device-a".to_string(),
            step,
            step_label: format!("step {}", step),
            state: state.to_string(),
            started_at: "2026-07-24T00:00:00Z".to_string(),
            updated_at: Some(format!("2026-07-24T00:00:0{}Z", step)),
            finished_at: (state != "running").then(|| "2026-07-24T00:01:00Z".to_string()),
            findings: Vec::new(),
            recommendations: Vec::new(),
            firmware_assessment: None,
            progress_history: Vec::new(),
        }
    }

    #[tokio::test]
    async fn find_run_returns_latest_matching_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scans.jsonl");
        let running = scan_run("scan-1", "running", 1);
        let complete = scan_run("scan-1", "complete", 5);

        append_run(&path, &running).await.expect("append running");
        append_run(&path, &complete).await.expect("append complete");

        let found = find_run(&path, "device-a", "scan-1")
            .await
            .expect("find scan");
        assert_eq!(found.state, "complete");
        assert_eq!(found.step, 5);
    }

    #[tokio::test]
    async fn find_run_with_history_returns_latest_state_and_all_transitions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("scans.jsonl");
        for step in 1..=5 {
            append_run(&path, &scan_run("scan-1", "running", step))
                .await
                .expect("append running");
            append_run(&path, &scan_run("scan-1", "complete", step))
                .await
                .expect("append complete");
        }

        let found = find_run_with_history(&path, "device-a", "scan-1")
            .await
            .expect("find scan");

        assert_eq!(found.step, 5);
        assert_eq!(found.state, "complete");
        assert_eq!(
            found
                .progress_history
                .iter()
                .map(|entry| (entry.step, entry.state.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (1, "running"),
                (1, "complete"),
                (2, "running"),
                (2, "complete"),
                (3, "running"),
                (3, "complete"),
                (4, "running"),
                (4, "complete"),
                (5, "running"),
                (5, "complete"),
            ]
        );
    }
}
