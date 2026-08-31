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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::model::{EncMeta, VaultRecord, VaultSource};

    fn record(id: &str, expires_at: &str) -> VaultRecord {
        VaultRecord {
            vault_id: id.into(),
            namespace: String::new(),
            circle_id: "circle-alpha".into(),
            filename: format!("{id}.txt"),
            mime: "text/plain".into(),
            size_plain: 4,
            size_cipher: 20,
            sha256_plain: "digest".into(),
            sender_did: "did:guardian:sender".into(),
            received_at: "2026-08-31T00:00:00Z".into(),
            source: VaultSource::Upload,
            folder_id: String::new(),
            starred: false,
            description: String::new(),
            owner_did: "did:guardian:owner".into(),
            revoked: false,
            revoked_at: None,
            expires_at: Some(expires_at.into()),
            conversation_recipient_did: None,
            message_id: None,
            enc: EncMeta {
                algo: "AES-256-GCM".into(),
                chunk_bytes: 1024,
                base_nonce_b64: "nonce".into(),
                wrapped_dek_b64: "wrapped".into(),
                wrap_scheme: "test".into(),
                wrap_key_id: "key-1".into(),
            },
        }
    }

    #[tokio::test]
    async fn sweep_removes_expired_metadata_and_blob_but_preserves_future_record() {
        let _lock = crate::vault::lock_test_env().await;
        let temp = tempfile::tempdir().expect("tempdir");
        let config = VaultConfig {
            base_dir: temp.path().to_path_buf(),
        };
        let expired = record(
            "expired",
            &(chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339(),
        );
        let future = record(
            "future",
            &(chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
        );
        persistence::save_record(&config, &expired)
            .await
            .expect("save expired");
        persistence::save_record(&config, &future)
            .await
            .expect("save future");
        for item in [&expired, &future] {
            let blob = persistence::record_blob_path(&config, item);
            tokio::fs::create_dir_all(blob.parent().expect("blob parent"))
                .await
                .expect("create blob directory");
            tokio::fs::write(blob, b"encrypted")
                .await
                .expect("write blob");
        }

        let reaper = VaultExpiryReaper::new(config.clone());
        assert_eq!(reaper.sweep().await, 1);
        assert!(!persistence::record_meta_path(&config, &expired).exists());
        assert!(!persistence::record_blob_path(&config, &expired).exists());
        assert!(persistence::record_meta_path(&config, &future).exists());
        assert!(persistence::record_blob_path(&config, &future).exists());
        assert_eq!(reaper.sweep().await, 0);
    }

    #[tokio::test]
    async fn sweep_returns_zero_when_metadata_directory_is_unreadable_as_a_directory() {
        let _lock = crate::vault::lock_test_env().await;
        let temp = tempfile::tempdir().expect("tempdir");
        let config = VaultConfig {
            base_dir: temp.path().to_path_buf(),
        };
        tokio::fs::write(persistence::meta_dir(&config), b"not a directory")
            .await
            .expect("write metadata blocker");
        assert_eq!(VaultExpiryReaper::new(config).sweep().await, 0);
    }
}
