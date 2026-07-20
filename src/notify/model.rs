use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NotificationCategory {
    Alerts,
    Devices,
    Circles,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NotificationKind {
    AlertHigh,
    AlertMedium,
    AlertLow,
    DeviceDiscovered,
    DevicePendingApproval,
    GuardianOffline,
    CircleNewMessage,
    CircleIncomingCall,
    CircleMemberJoined,
    CircleFileShared,
}

impl NotificationKind {
    pub fn category(self) -> NotificationCategory {
        match self {
            Self::AlertHigh | Self::AlertMedium | Self::AlertLow => NotificationCategory::Alerts,
            Self::DeviceDiscovered | Self::DevicePendingApproval | Self::GuardianOffline => {
                NotificationCategory::Devices
            }
            Self::CircleNewMessage
            | Self::CircleIncomingCall
            | Self::CircleMemberJoined
            | Self::CircleFileShared => NotificationCategory::Circles,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationEvent {
    pub id: String,
    pub kind: NotificationKind,
    pub title: String,
    pub body: String,
    pub severity: String,
    pub ref_id: Option<String>,
    pub created_at: String,
    pub read: bool,
}
