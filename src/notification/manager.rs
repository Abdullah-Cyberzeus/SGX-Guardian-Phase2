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
                eprintln!(
                    "⚠️ Failed to read notifications.json: {}, starting empty",
                    e
                );
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
        tokio::task::spawn_blocking(move || Self::write_to_disk_internal(&path, &list))
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
        file.read_to_string(&mut contents)
            .map_err(|e| e.to_string())?;
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
        let notif = manager
            .create_notification("Critical Alert", "Battery empty", "critical")
            .await;

        let unread = manager.list_notifications(true, None).await;
        assert!(unread.iter().any(|n| n.id == notif.id));

        let updated = manager.mark_as_read(&[notif.id.clone()]).await;
        assert_eq!(updated, 1);

        let unread_after = manager.list_notifications(true, None).await;
        assert!(!unread_after.iter().any(|n| n.id == notif.id));
    }

    fn record(id: &str, severity: &str, read: bool) -> NotificationRecord {
        NotificationRecord {
            id: id.to_string(),
            title: format!("title-{id}"),
            message: format!("message-{id}"),
            severity: severity.to_string(),
            read,
            created_at: DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
                .unwrap()
                .with_timezone(&Utc),
        }
    }

    #[test]
    fn load_or_create_loads_existing_valid_json_without_boot_defaults() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("notifications.json");
        let existing = vec![record("existing-1", "warning", true)];
        NotificationManager::write_to_disk_internal(&path, &existing).unwrap();

        let manager = NotificationManager::load_or_create(path, None);
        let loaded = manager.notifications.read().unwrap().clone();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "existing-1");
        assert!(loaded[0].read);
    }

    #[tokio::test]
    async fn load_or_create_starts_empty_for_malformed_existing_json() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("notifications.json");
        std::fs::write(&path, "{not valid json").unwrap();

        let manager = NotificationManager::load_or_create(path.clone(), None);

        assert!(manager.list_notifications(false, None).await.is_empty());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "{not valid json");
    }

    #[tokio::test]
    async fn list_notifications_filters_by_unread_and_exact_severity() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("notifications.json");
        let manager = NotificationManager {
            storage_path: path,
            notifications: Arc::new(RwLock::new(vec![
                record("info-unread", "info", false),
                record("warning-read", "warning", true),
                record("warning-unread", "warning", false),
                record("critical-unread", "critical", false),
            ])),
            event_bus: None,
        };

        let all = manager.list_notifications(false, None).await;
        assert_eq!(all.len(), 4);

        let unread = manager.list_notifications(true, None).await;
        assert_eq!(unread.len(), 3);
        assert!(unread.iter().all(|n| !n.read));

        let warnings = manager.list_notifications(false, Some("warning")).await;
        assert_eq!(warnings.len(), 2);
        assert!(warnings.iter().all(|n| n.severity == "warning"));

        let unread_warnings = manager.list_notifications(true, Some("warning")).await;
        assert_eq!(unread_warnings.len(), 1);
        assert_eq!(unread_warnings[0].id, "warning-unread");

        assert!(manager
            .list_notifications(false, Some("WARNING"))
            .await
            .is_empty());
        assert!(manager
            .list_notifications(false, Some(""))
            .await
            .is_empty());
    }

    #[tokio::test]
    async fn create_notification_accepts_empty_and_unknown_severity_values() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("notifications.json");
        let manager = NotificationManager {
            storage_path: path.clone(),
            notifications: Arc::new(RwLock::new(Vec::new())),
            event_bus: None,
        };

        let empty = manager.create_notification("", "", "").await;
        let custom = manager
            .create_notification("Custom", "Custom message", "debug")
            .await;

        assert!(empty.id.starts_with("notif_"));
        assert_eq!(empty.title, "");
        assert_eq!(empty.message, "");
        assert_eq!(empty.severity, "");
        assert!(!empty.read);
        assert_eq!(custom.severity, "debug");

        let persisted = NotificationManager::read_from_disk_internal(&path).unwrap();
        assert_eq!(persisted.len(), 2);
        assert_eq!(persisted[1].title, "Custom");
    }

    #[tokio::test]
    async fn mark_as_read_counts_only_unread_matching_records() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("notifications.json");
        let manager = NotificationManager {
            storage_path: path.clone(),
            notifications: Arc::new(RwLock::new(vec![
                record("a", "info", false),
                record("b", "warning", true),
                record("c", "critical", false),
            ])),
            event_bus: None,
        };

        let updated = manager
            .mark_as_read(&[
                "a".to_string(),
                "a".to_string(),
                "b".to_string(),
                "missing".to_string(),
            ])
            .await;

        assert_eq!(updated, 1);
        let list = manager.list_notifications(false, None).await;
        assert!(list.iter().find(|n| n.id == "a").unwrap().read);
        assert!(list.iter().find(|n| n.id == "b").unwrap().read);
        assert!(!list.iter().find(|n| n.id == "c").unwrap().read);

        let persisted = NotificationManager::read_from_disk_internal(&path).unwrap();
        assert!(persisted.iter().find(|n| n.id == "a").unwrap().read);
    }

    #[tokio::test]
    async fn mark_as_read_with_empty_or_unknown_ids_is_noop_and_does_not_create_file() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("notifications.json");
        let manager = NotificationManager {
            storage_path: path.clone(),
            notifications: Arc::new(RwLock::new(vec![record("a", "info", false)])),
            event_bus: None,
        };

        assert_eq!(manager.mark_as_read(&[]).await, 0);
        assert_eq!(manager.mark_as_read(&["missing".to_string()]).await, 0);
        assert!(!path.exists());
    }

    #[test]
    fn disk_helpers_round_trip_empty_and_multiple_records() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("notifications.json");

        NotificationManager::write_to_disk_internal(&path, &[]).unwrap();
        assert!(NotificationManager::read_from_disk_internal(&path)
            .unwrap()
            .is_empty());

        let records = vec![
            record("a", "info", false),
            record("b", "critical", true),
        ];
        NotificationManager::write_to_disk_internal(&path, &records).unwrap();
        let loaded = NotificationManager::read_from_disk_internal(&path).unwrap();

        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].id, "a");
        assert_eq!(loaded[1].severity, "critical");
        assert!(std::fs::read_to_string(path).unwrap().contains('\n'));
    }

    #[test]
    fn disk_helpers_return_errors_for_missing_malformed_and_unwritable_paths() {
        let td = TempDir::new().unwrap();
        let missing = td.path().join("missing.json");
        assert!(NotificationManager::read_from_disk_internal(&missing).is_err());

        let malformed = td.path().join("malformed.json");
        std::fs::write(&malformed, "not json").unwrap();
        assert!(NotificationManager::read_from_disk_internal(&malformed).is_err());

        assert!(NotificationManager::write_to_disk_internal(td.path(), &[record("a", "info", false)])
            .is_err());
    }

    #[tokio::test]
    async fn save_errors_are_ignored_by_create_and_mark_read_but_memory_updates_remain() {
        let td = TempDir::new().unwrap();
        let manager = NotificationManager {
            storage_path: td.path().to_path_buf(),
            notifications: Arc::new(RwLock::new(vec![record("a", "info", false)])),
            event_bus: None,
        };

        let created = manager
            .create_notification("Still Stored", "Disk save fails", "warning")
            .await;
        assert_eq!(created.title, "Still Stored");
        assert_eq!(manager.list_notifications(false, None).await.len(), 2);

        let updated = manager.mark_as_read(&["a".to_string()]).await;
        assert_eq!(updated, 1);
        assert!(manager
            .list_notifications(false, None)
            .await
            .iter()
            .find(|n| n.id == "a")
            .unwrap()
            .read);
    }

    #[test]
    fn save_to_disk_sync_reports_poisoned_lock() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("notifications.json");
        let notifications = Arc::new(RwLock::new(vec![record("a", "info", false)]));
        let poisoned = Arc::clone(&notifications);
        let _ = std::thread::spawn(move || {
            let _guard = poisoned.write().unwrap();
            panic!("poison notification lock");
        })
        .join();
        let manager = NotificationManager {
            storage_path: path,
            notifications,
            event_bus: None,
        };

        assert_eq!(manager.save_to_disk_sync(), Err("Lock poisoned".to_string()));
    }

    #[tokio::test]
    async fn poisoned_lock_causes_safe_empty_or_noop_results() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("notifications.json");
        let notifications = Arc::new(RwLock::new(vec![record("a", "info", false)]));
        let poisoned = Arc::clone(&notifications);
        let _ = std::thread::spawn(move || {
            let _guard = poisoned.write().unwrap();
            panic!("poison notification lock");
        })
        .join();
        let manager = NotificationManager {
            storage_path: path,
            notifications,
            event_bus: None,
        };

        assert!(manager.list_notifications(false, None).await.is_empty());
        assert_eq!(manager.mark_as_read(&["a".to_string()]).await, 0);
        let created = manager
            .create_notification("Ignored", "Cannot acquire write lock", "info")
            .await;
        assert_eq!(created.title, "Ignored");
        assert!(manager.list_notifications(false, None).await.is_empty());
    }
}
