use crate::vault::{persistence, VaultConfig};
use tokio::time::{self, Duration as TokioDuration};
use tracing::{info, warn};

/// Periodically deletes Vault files (and their blobs) whose `expires_at` has
/// passed. Mirrors `telemetry::pruner::TelemetryPruner`.
pub struct VaultExpiryReaper {
    config: VaultConfig,
}

impl VaultExpiryReaper {
    pub fn new(config: VaultConfig) -> Self {
        Self { config }
    }

    /// Spawns a background task that sweeps every 15 minutes.
    pub fn start_background(self) {
        tokio::spawn(async move {
            let mut interval = time::interval(TokioDuration::from_secs(15 * 60));
            loop {
                interval.tick().await;
                let removed = self.sweep().await;
                if removed > 0 {
                    info!(removed, "vault expiry reaper removed expired files");
                }
            }
        });
    }

    pub async fn sweep(&self) -> usize {
        let records = match persistence::list_records(&self.config, None).await {
            Ok(records) => records,
            Err(error) => {
                warn!(%error, "vault expiry reaper failed to list records");
                return 0;
            }
        };

        let mut removed = 0;
        for record in records.into_iter().filter(|record| record.is_expired()) {
            match persistence::delete_record(&self.config, &record).await {
                Ok(()) => removed += 1,
                Err(error) => warn!(
                    vault_id = %record.vault_id,
                    %error,
                    "vault expiry reaper failed to delete expired file"
                ),
            }
        }
        removed
    }
}
