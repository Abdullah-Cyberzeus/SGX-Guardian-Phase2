use chrono::Local;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::broadcast::error::RecvError;
use tracing::{error, info, warn};

use crate::homeassistant::events::{EventBus, HaEvent};
use crate::telemetry::pruner::TelemetryPruner;
use crate::telemetry::sampler::TelemetrySampler;

const MAX_FILE_SIZE_BYTES: u64 = 50 * 1024 * 1024; // 50MB per file cap

pub struct TelemetryCollector {
    bus: Arc<EventBus>,
    sampler: Arc<TelemetrySampler>,
    log_dir: PathBuf,
}

impl TelemetryCollector {
    pub fn new(bus: Arc<EventBus>, log_dir: PathBuf) -> Self {
        Self {
            bus,
            sampler: TelemetrySampler::default_60s(),
            log_dir,
        }
    }

    /// Starts the telemetry collector service & background pruner
    pub async fn start(self: Arc<Self>) {
        if let Err(e) = fs::create_dir_all(&self.log_dir).await {
            error!(
                "Failed to create telemetry directory {:?}: {}",
                self.log_dir, e
            );
            return;
        }

        // Start background 72-hour pruner (6-hour interval)
        let pruner = TelemetryPruner::new(&self.log_dir, 3);
        pruner.start_background_pruner();

        let mut receiver = self.bus.subscribe();
        let collector = Arc::clone(&self);

        tokio::spawn(async move {
            info!("📊 Telemetry Collector started.");
            loop {
                match receiver.recv().await {
                    Ok(HaEvent::StateChanged(val)) => {
                        collector.process_state_changed(val).await;
                    }
                    Ok(_) => {} // Ignore non-state events for telemetry storage
                    Err(RecvError::Lagged(skipped)) => {
                        warn!(
                            "Telemetry Collector lagged behind! Skipped {} events.",
                            skipped
                        );
                    }
                    Err(RecvError::Closed) => {
                        warn!("Event Bus closed. Stopping Telemetry Collector.");
                        break;
                    }
                }
            }
        });
    }

    async fn process_state_changed(&self, val: serde_json::Value) {
        // HA WebSocket format: { "event_type": "state_changed", "data": { "entity_id": "...", ... } }
        let data = match val.get("data") {
            Some(d) => d,
            None => return,
        };

        let entity_id = match data.get("entity_id").and_then(|e| e.as_str()) {
            Some(id) => id,
            None => return,
        };

        // 1. Apply 60s per-entity rate limit sampling for storage
        if !self.sampler.should_sample(entity_id).await {
            return; // Blocked by rate limiter
        }

        // 2. Format structured telemetry JSON record
        let record = serde_json::json!({
            "timestamp": Local::now().to_rfc3339(),
            "entity_id": entity_id,
            "state": data.get("new_state").and_then(|n| n.get("state")).and_then(|s| s.as_str()).unwrap_or("unknown"),
            "attributes": data.get("new_state").and_then(|n| n.get("attributes")).cloned().unwrap_or_default()
        });

        let mut json_line = serde_json::to_string(&record).unwrap_or_default();
        json_line.push('\n');

        // 3. Resolve active log file path with 50MB cap protection
        let target_path = self.resolve_active_log_file().await;

        // 4. Append to telemetry file
        match fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&target_path)
            .await
        {
            Ok(mut file) => {
                if let Err(e) = file.write_all(json_line.as_bytes()).await {
                    error!("Failed to write to telemetry log {:?}: {}", target_path, e);
                }
            }
            Err(e) => {
                error!("Failed to open telemetry log {:?}: {}", target_path, e);
            }
        }
    }

    /// Resolves daily log file path, applying 50MB early rotation suffixes (_001, _002...) if cap exceeded.
    async fn resolve_active_log_file(&self) -> PathBuf {
        let date_str = Local::now().format("%Y-%m-%d").to_string();
        let base_path = self.log_dir.join(format!("ha_telemetry_{}.log", date_str));

        // Check base file size
        if let Ok(metadata) = fs::metadata(&base_path).await {
            if metadata.len() < MAX_FILE_SIZE_BYTES {
                return base_path;
            }
        } else {
            return base_path; // File doesn't exist yet, use base_path
        }

        // Base file >= 50MB, find next available index suffix
        let mut index = 1;
        loop {
            let rotated_path = self
                .log_dir
                .join(format!("ha_telemetry_{}_{:03}.log", date_str, index));
            if let Ok(metadata) = fs::metadata(&rotated_path).await {
                if metadata.len() < MAX_FILE_SIZE_BYTES {
                    return rotated_path;
                }
            } else {
                return rotated_path;
            }
            index += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collector(log_dir: PathBuf, interval_secs: u64) -> TelemetryCollector {
        TelemetryCollector {
            bus: EventBus::new(),
            sampler: TelemetrySampler::new(interval_secs),
            log_dir,
        }
    }

    #[tokio::test]
    async fn state_change_processing_ignores_invalid_events_samples_and_writes_structured_json() {
        let temp = tempfile::tempdir().expect("tempdir");
        let collector = collector(temp.path().to_path_buf(), 60);

        collector.process_state_changed(serde_json::json!({})).await;
        collector
            .process_state_changed(serde_json::json!({"data": {}}))
            .await;
        assert_eq!(
            std::fs::read_dir(temp.path()).expect("read temp").count(),
            0
        );

        let event = serde_json::json!({
            "data": {
                "entity_id": "sensor.temperature",
                "new_state": {
                    "state": "21.5",
                    "attributes": {"unit_of_measurement": "C"}
                }
            }
        });
        collector.process_state_changed(event.clone()).await;
        collector.process_state_changed(event).await;

        let path = collector.resolve_active_log_file().await;
        let content = tokio::fs::read_to_string(path)
            .await
            .expect("read telemetry log");
        let lines = content.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 1, "second event must be rate-limited");
        let record: serde_json::Value = serde_json::from_str(lines[0]).expect("telemetry JSON");
        assert_eq!(record["entity_id"], "sensor.temperature");
        assert_eq!(record["state"], "21.5");
        assert_eq!(record["attributes"]["unit_of_measurement"], "C");

        collector
            .process_state_changed(serde_json::json!({
                "data": {"entity_id": "sensor.unknown", "new_state": null}
            }))
            .await;
        let content = tokio::fs::read_to_string(collector.resolve_active_log_file().await)
            .await
            .expect("read updated telemetry log");
        let unknown: serde_json::Value =
            serde_json::from_str(content.lines().last().expect("last record")).unwrap();
        assert_eq!(unknown["state"], "unknown");
        assert!(unknown["attributes"].is_null());
    }

    #[tokio::test]
    async fn active_log_resolution_uses_base_reuses_partial_suffix_and_advances_full_suffix() {
        let temp = tempfile::tempdir().expect("tempdir");
        let collector = collector(temp.path().to_path_buf(), 0);
        let base = collector.resolve_active_log_file().await;
        assert!(base
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("ha_telemetry_"));
        assert!(!base.file_name().unwrap().to_string_lossy().contains("_001"));

        std::fs::File::create(&base)
            .expect("create base")
            .set_len(MAX_FILE_SIZE_BYTES)
            .expect("size base");
        let first_rotated = collector.resolve_active_log_file().await;
        assert!(first_rotated
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains("_001.log"));

        std::fs::File::create(&first_rotated)
            .expect("create first rotation")
            .set_len(MAX_FILE_SIZE_BYTES)
            .expect("size first rotation");
        let second_rotated = collector.resolve_active_log_file().await;
        assert!(second_rotated
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains("_002.log"));

        std::fs::OpenOptions::new()
            .write(true)
            .open(&first_rotated)
            .expect("open first rotation")
            .set_len(1)
            .expect("shrink first rotation");
        assert_eq!(collector.resolve_active_log_file().await, first_rotated);
    }

    #[tokio::test]
    async fn collector_start_returns_cleanly_when_log_directory_cannot_be_created() {
        let temp = tempfile::tempdir().expect("tempdir");
        let file_path = temp.path().join("not-a-directory");
        tokio::fs::write(&file_path, b"file")
            .await
            .expect("write blocking file");
        Arc::new(collector(file_path, 60)).start().await;
    }
}
