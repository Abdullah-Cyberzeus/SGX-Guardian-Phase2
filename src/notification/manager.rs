use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use crate::homeassistant::events::EventBus;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationRecord {
    pub id: String,
    pub title: String,
    pub message: String,
    pub severity: String, // "info", "warning", "critical"
    pub read: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct NotificationManager {
    storage_path: PathBuf,
    notifications: Arc<RwLock<Vec<NotificationRecord>>>,
    event_bus: Option<Arc<EventBus>>,
}

impl NotificationManager {
    pub fn load_or_create(storage_path: PathBuf, event_bus: Option<Arc<EventBus>>) -> Self {
        let notifs = if storage_path.exists() {
            Self::read_from_disk_internal(&storage_path).unwrap_or_else(|e| {
                eprintln!("⚠️ Failed to read notifications.json: {}, starting empty", e);
                Vec::new()
            })
        } else {
            vec![
                NotificationRecord {
                    id: "notif_boot_001".to_string(),
                    title: "System Booted".to_string(),
                    message: "SGX Guardian Node A initialized successfully.".to_string(),
                    severity: "info".to_string(),
                    read: false,
                    created_at: Utc::now(),
                },
                NotificationRecord {
                    id: "notif_boot_002".to_string(),
                    title: "HA Connected".to_string(),
                    message: "Home Assistant WebSocket connection established.".to_string(),
                    severity: "info".to_string(),
                    read: false,
                    created_at: Utc::now(),
                },
            ]
        };

        let manager = Self {
            storage_path: storage_path.clone(),
            notifications: Arc::new(RwLock::new(notifs)),
            event_bus,
        };

        // Persist initial boot state if missing
        if !storage_path.exists() {
            let _ = manager.save_to_disk_sync();
        }

        manager
    }

    pub async fn create_notification(
        &self,
        title: impl Into<String>,
        message: impl Into<String>,
        severity: impl Into<String>,
    ) -> NotificationRecord {
        let record = NotificationRecord {
            id: format!("notif_{}", uuid::Uuid::new_v4().simple()),
            title: title.into(),
            message: message.into(),
            severity: severity.into(),
            read: false,
            created_at: Utc::now(),
        };

        {
            if let Ok(mut list) = self.notifications.write() {
                list.push(record.clone());
            }
        }

        let _ = self.save_to_disk().await;

        // Broadcast notification over EventBus if connected
        if let Some(bus) = &self.event_bus {
            bus.publish(crate::homeassistant::events::HaEvent::NotificationCreated {
                id: record.id.clone(),
                title: record.title.clone(),
                message: record.message.clone(),
                severity: record.severity.clone(),
            });
        }

        record
    }

    pub async fn list_notifications(
        &self,
        unread_only: bool,
        severity_filter: Option<&str>,
    ) -> Vec<NotificationRecord> {
        let list = match self.notifications.read() {
            Ok(guard) => guard.clone(),
            Err(_) => Vec::new(),
        };
        list.into_iter()
            .filter(|n| {
                if unread_only && n.read {
                    return false;
                }
                if let Some(sev) = severity_filter {
                    if n.severity != sev {
                        return false;
                    }
                }
                true
            })
            .collect()
    }

    pub async fn mark_as_read(&self, ids: &[String]) -> usize {
        let mut updated = 0;
        if let Ok(mut list) = self.notifications.write() {
            for n in list.iter_mut() {
                if ids.contains(&n.id) {
                    if !n.read {
                        n.read = true;
                        updated += 1;
                    }
                }
            }
        }
        if updated > 0 {
            let _ = self.save_to_disk().await;
        }
        updated
    }

    async fn save_to_disk(&self) -> Result<(), String> {
        let list = match self.notifications.read() {
            Ok(guard) => guard.clone(),
            Err(_) => return Err("Lock poisoned".to_string()),
        };
        let path = self.storage_path.clone();
        tokio::task::spawn_blocking(move || {
            Self::write_to_disk_internal(&path, &list)
        })
        .await
        .map_err(|e| e.to_string())?
    }

    fn save_to_disk_sync(&self) -> Result<(), String> {
        let list = match self.notifications.read() {
            Ok(guard) => guard.clone(),
            Err(_) => return Err("Lock poisoned".to_string()),
        };
        Self::write_to_disk_internal(&self.storage_path, &list)
    }

    fn read_from_disk_internal(path: &Path) -> Result<Vec<NotificationRecord>, String> {
        let mut file = File::open(path).map_err(|e| e.to_string())?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).map_err(|e| e.to_string())?;
        serde_json::from_str(&contents).map_err(|e| e.to_string())
    }

    fn write_to_disk_internal(path: &Path, notifs: &[NotificationRecord]) -> Result<(), String> {
        let json = serde_json::to_string_pretty(notifs).map_err(|e| e.to_string())?;
        let mut file = File::create(path).map_err(|e| e.to_string())?;
        file.write_all(json.as_bytes()).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_notification_creation_and_persistence() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("notifications.json");

        let manager = NotificationManager::load_or_create(path.clone(), None);
        assert_eq!(manager.list_notifications(false, None).await.len(), 2);

        let created = manager
            .create_notification("Test Alert", "Device offline", "warning")
            .await;
        assert_eq!(created.title, "Test Alert");

        assert_eq!(manager.list_notifications(false, None).await.len(), 3);

        // Reload from disk
        let reloaded = NotificationManager::load_or_create(path, None);
        assert_eq!(reloaded.list_notifications(false, None).await.len(), 3);
    }

    #[tokio::test]
    async fn test_mark_as_read_and_filtering() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("notifications.json");

        let manager = NotificationManager::load_or_create(path, None);
        let notif = manager.create_notification("Critical Alert", "Battery empty", "critical").await;

        let unread = manager.list_notifications(true, None).await;
        assert!(unread.iter().any(|n| n.id == notif.id));

        let updated = manager.mark_as_read(&[notif.id.clone()]).await;
        assert_eq!(updated, 1);

        let unread_after = manager.list_notifications(true, None).await;
        assert!(!unread_after.iter().any(|n| n.id == notif.id));
    }
}
