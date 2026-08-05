use chrono::{Duration as ChronoDuration, Local};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::time::{self, Duration as TokioDuration};
use tracing::{error, info};

pub struct TelemetryPruner {
    dir: PathBuf,
    retention_days: i64,
}

impl TelemetryPruner {
    pub fn new<P: AsRef<Path>>(dir: P, retention_days: i64) -> Self {
        Self {
            dir: dir.as_ref().to_path_buf(),
            retention_days,
        }
    }

    /// Spawns a background task that runs pruning every 6 hours (and immediately on startup).
    pub fn start_background_pruner(self) {
        tokio::spawn(async move {
            let mut interval = time::interval(TokioDuration::from_secs(6 * 3600)); // Every 6 hours
            loop {
                interval.tick().await;
                self.prune().await;
            }
        });
    }

    /// Prunes files older than retention_days
    pub async fn prune(&self) -> usize {
        let threshold = Local::now() - ChronoDuration::days(self.retention_days);
        let mut deleted_count = 0;

        let mut entries = match fs::read_dir(&self.dir).await {
            Ok(e) => e,
            Err(_) => return 0,
        };

        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            if let Ok(metadata) = entry.metadata().await {
                if let Ok(modified) = metadata.modified() {
                    let modified_dt = chrono::DateTime::<Local>::from(modified);
                    if modified_dt < threshold {
                        if let Err(e) = fs::remove_file(&path).await {
                            error!("Failed to delete old telemetry log {:?}: {}", path, e);
                        } else {
                            deleted_count += 1;
                        }
                    }
                }
            }
        }

        if deleted_count > 0 {
            info!(
                "🗑️ Telemetry Pruner: Deleted {} log files older than {} days.",
                deleted_count, self.retention_days
            );
        }

        deleted_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    #[tokio::test]
    async fn test_pruner_handles_empty_dir() {
        let temp_dir = tempfile::tempdir().unwrap();
        let pruner = TelemetryPruner::new(temp_dir.path(), 3);
        let deleted = pruner.prune().await;
        assert_eq!(deleted, 0);
    }

    #[tokio::test]
    async fn test_pruner_keeps_recent_files() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("ha_telemetry_2026-07-22.log");
        File::create(&file_path).unwrap();

        let pruner = TelemetryPruner::new(temp_dir.path(), 3);
        let deleted = pruner.prune().await;
        assert_eq!(deleted, 0);
        assert!(file_path.exists());
    }
}
