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
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt;
    #[cfg(unix)]
    use std::time::{SystemTime, UNIX_EPOCH};

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

    #[cfg(unix)]
    fn set_mtime_offset_secs(path: &Path, offset_secs: i64) {
        let base = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let timestamp = base + offset_secs;
        let times = [
            libc::timespec {
                tv_sec: timestamp,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: timestamp,
                tv_nsec: 0,
            },
        ];
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let result = unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0) };
        assert_eq!(result, 0);
    }

    #[test]
    fn new_stores_directory_and_retention_days() {
        let temp_dir = tempfile::tempdir().unwrap();
        let pruner = TelemetryPruner::new(temp_dir.path(), 7);

        assert_eq!(pruner.dir, temp_dir.path());
        assert_eq!(pruner.retention_days, 7);
    }

    #[tokio::test]
    async fn prune_returns_zero_for_missing_directory_or_file_path() {
        let temp_dir = tempfile::tempdir().unwrap();
        let missing_dir = temp_dir.path().join("missing");
        let file_path = temp_dir.path().join("not-a-dir.log");
        File::create(&file_path).unwrap();

        assert_eq!(TelemetryPruner::new(&missing_dir, 3).prune().await, 0);
        assert_eq!(TelemetryPruner::new(&file_path, 3).prune().await, 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn prune_deletes_files_older_than_retention() {
        let temp_dir = tempfile::tempdir().unwrap();
        let old_file = temp_dir.path().join("old.log");
        let recent_file = temp_dir.path().join("recent.log");
        File::create(&old_file).unwrap();
        File::create(&recent_file).unwrap();
        set_mtime_offset_secs(&old_file, -5 * 24 * 3600);
        set_mtime_offset_secs(&recent_file, -3600);

        let deleted = TelemetryPruner::new(temp_dir.path(), 3).prune().await;

        assert_eq!(deleted, 1);
        assert!(!old_file.exists());
        assert!(recent_file.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn prune_keeps_file_at_newer_side_of_boundary() {
        let temp_dir = tempfile::tempdir().unwrap();
        let boundary_file = temp_dir.path().join("boundary.log");
        File::create(&boundary_file).unwrap();
        set_mtime_offset_secs(&boundary_file, -(3 * 24 * 3600) + 60);

        let deleted = TelemetryPruner::new(temp_dir.path(), 3).prune().await;

        assert_eq!(deleted, 0);
        assert!(boundary_file.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn prune_deletes_multiple_old_files_and_keeps_directories() {
        let temp_dir = tempfile::tempdir().unwrap();
        let old_a = temp_dir.path().join("old-a.log");
        let old_b = temp_dir.path().join("old-b.log");
        let old_dir = temp_dir.path().join("old-dir");
        File::create(&old_a).unwrap();
        File::create(&old_b).unwrap();
        std::fs::create_dir(&old_dir).unwrap();
        set_mtime_offset_secs(&old_a, -10 * 24 * 3600);
        set_mtime_offset_secs(&old_b, -4 * 24 * 3600);
        set_mtime_offset_secs(&old_dir, -10 * 24 * 3600);

        let deleted = TelemetryPruner::new(temp_dir.path(), 3).prune().await;

        assert_eq!(deleted, 2);
        assert!(!old_a.exists());
        assert!(!old_b.exists());
        assert!(old_dir.is_dir());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn zero_retention_keeps_future_dated_file_and_deletes_past_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let past_file = temp_dir.path().join("past.log");
        let future_file = temp_dir.path().join("future.log");
        File::create(&past_file).unwrap();
        File::create(&future_file).unwrap();
        set_mtime_offset_secs(&past_file, -60);
        set_mtime_offset_secs(&future_file, 60);

        let deleted = TelemetryPruner::new(temp_dir.path(), 0).prune().await;

        assert_eq!(deleted, 1);
        assert!(!past_file.exists());
        assert!(future_file.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn negative_retention_treats_current_files_as_old() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("current.log");
        File::create(&file_path).unwrap();
        set_mtime_offset_secs(&file_path, 0);

        let deleted = TelemetryPruner::new(temp_dir.path(), -1).prune().await;

        assert_eq!(deleted, 1);
        assert!(!file_path.exists());
    }
}
