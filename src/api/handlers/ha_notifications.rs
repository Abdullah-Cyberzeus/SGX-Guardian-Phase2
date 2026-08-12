use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::api::handlers::pagination::{PaginatedResponse, PaginationParams};
use crate::api::state::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationRecord {
    pub id: String,
    pub title: String,
    pub message: String,
    pub severity: String, // "info", "warning", "critical"
    pub read: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Deserialize)]
pub struct NotificationQueryParams {
    pub unread: Option<bool>,
    pub severity: Option<String>,
    #[serde(flatten)]
    pub pagination: PaginationParams,
}

#[derive(Deserialize)]
pub struct MarkReadPayload {
    pub notification_ids: Vec<String>,
}

/// In-memory notification store shared across API sessions
pub struct NotificationStore {
    notifications: RwLock<Vec<NotificationRecord>>,
}

impl NotificationStore {
    pub fn new() -> Self {
        Self {
            notifications: RwLock::new(vec![
                NotificationRecord {
                    id: "notif_001".to_string(),
                    title: "System Booted".to_string(),
                    message: "SGX Guardian Node A initialized successfully.".to_string(),
                    severity: "info".to_string(),
                    read: false,
                    created_at: Utc::now(),
                },
                NotificationRecord {
                    id: "notif_002".to_string(),
                    title: "HA Connected".to_string(),
                    message: "Home Assistant WebSocket connection established.".to_string(),
                    severity: "info".to_string(),
                    read: false,
                    created_at: Utc::now(),
                },
            ]),
        }
    }

    pub async fn add_notification(&self, notif: NotificationRecord) {
        let mut list = self.notifications.write().await;
        list.push(notif);
    }

    pub async fn get_notifications(
        &self,
        unread_only: bool,
        severity_filter: Option<&str>,
    ) -> Vec<NotificationRecord> {
        let list = self.notifications.read().await;
        list.iter()
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
            .cloned()
            .collect()
    }

    pub async fn mark_as_read(&self, ids: &[String]) -> usize {
        let mut list = self.notifications.write().await;
        let mut updated = 0;
        for n in list.iter_mut() {
            if ids.contains(&n.id) {
                n.read = true;
                updated += 1;
            }
        }
        updated
    }
}

pub static GLOBAL_NOTIFICATIONS: once_cell::sync::Lazy<Arc<NotificationStore>> =
    once_cell::sync::Lazy::new(|| Arc::new(NotificationStore::new()));

/// GET /api/notifications?page=1&per_page=20&unread=true
pub async fn list_notifications(
    State(state): State<Arc<AppState>>,
    Query(query): Query<NotificationQueryParams>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let unread_only = query.unread.unwrap_or(false);

    let records = match state.get_notification_manager().await {
        Some(mgr) => {
            let notifs = mgr
                .list_notifications(unread_only, query.severity.as_deref())
                .await;
            notifs
                .into_iter()
                .map(|n| NotificationRecord {
                    id: n.id,
                    title: n.title,
                    message: n.message,
                    severity: n.severity,
                    read: n.read,
                    created_at: n.created_at,
                })
                .collect()
        }
        None => {
            GLOBAL_NOTIFICATIONS
                .get_notifications(unread_only, query.severity.as_deref())
                .await
        }
    };

    let paginated = PaginatedResponse::paginate(records, &query.pagination, 20);

    Ok((StatusCode::OK, Json(serde_json::json!(paginated))))
}

/// POST /api/notifications/read
pub async fn mark_notifications_read(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<MarkReadPayload>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let count = match state.get_notification_manager().await {
        Some(mgr) => mgr.mark_as_read(&payload.notification_ids).await,
        None => {
            GLOBAL_NOTIFICATIONS
                .mark_as_read(&payload.notification_ids)
                .await
        }
    };

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "success",
            "marked_read_count": count,
            "message": format!("Marked {} notification(s) as read", count)
        })),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_notification_store_operations() {
        let store = NotificationStore::new();

        let initial = store.get_notifications(false, None).await;
        assert_eq!(initial.len(), 2);

        let unread = store.get_notifications(true, None).await;
        assert_eq!(unread.len(), 2);

        let marked = store.mark_as_read(&["notif_001".to_string()]).await;
        assert_eq!(marked, 1);

        let unread_after = store.get_notifications(true, None).await;
        assert_eq!(unread_after.len(), 1);
        assert_eq!(unread_after[0].id, "notif_002");
    }
}
