use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use crate::automation::schema::RuleAction;
use crate::storage::file_lock::SecureFileStore;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingAction {
    pub id: String,
    pub rule_id: String,
    pub action: RuleAction,
    pub execute_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Default)]
struct PendingStoreData {
    pending: HashMap<String, PendingAction>,
}

pub struct PendingActionStore {
    cache: RwLock<HashMap<String, PendingAction>>,
    store: Arc<SecureFileStore>,
}

impl PendingActionStore {
    pub fn new(path: &str) -> Arc<Self> {
        let store = Arc::new(SecureFileStore::new(path));
        let mut cache = HashMap::new();

        if let Ok(Some(data)) = store.read() {
            if let Ok(store_data) = serde_json::from_slice::<PendingStoreData>(&data) {
                cache = store_data.pending;
                info!("Loaded {} pending actions from disk.", cache.len());
            }
        }

        Arc::new(Self {
            cache: RwLock::new(cache),
            store,
        })
    }

    pub async fn add_pending_action(&self, action: PendingAction) -> Result<(), String> {
        {
            let mut cache = self.cache.write().await;
            cache.insert(action.id.clone(), action);
        }
        self.persist().await
    }

    pub async fn remove_pending_action(&self, id: &str) -> Result<(), String> {
        {
            let mut cache = self.cache.write().await;
            if cache.remove(id).is_none() {
                return Ok(());
            }
        }
        self.persist().await
    }

    pub async fn get_all_pending(&self) -> Vec<PendingAction> {
        let cache = self.cache.read().await;
        cache.values().cloned().collect()
    }

    async fn persist(&self) -> Result<(), String> {
        let snapshot = self.cache.read().await.clone();
        let store_clone = self.store.clone();

        tokio::task::spawn_blocking(move || {
            store_clone.write_atomic(|_old| {
                let data = PendingStoreData { pending: snapshot };
                serde_json::to_vec_pretty(&data)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })
        })
        .await
        .map_err(|e| format!("Join error: {}", e))?
        .map_err(|e| format!("IO error: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_pending_action_store_persistence() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap().to_string();

        let pending_action = PendingAction {
            id: "pa_001".to_string(),
            rule_id: "rule_001".to_string(),
            action: RuleAction::Delay { delay_secs: 10 },
            execute_at: Utc::now(),
            created_at: Utc::now(),
        };

        {
            let store1 = PendingActionStore::new(&path);
            store1.add_pending_action(pending_action.clone()).await.unwrap();
        }

        let store2 = PendingActionStore::new(&path);
        let all = store2.get_all_pending().await;
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, "pa_001");
    }
}
