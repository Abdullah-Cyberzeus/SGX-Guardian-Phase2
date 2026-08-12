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
