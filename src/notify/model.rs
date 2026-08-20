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
    CircleMemberPendingApproval,
    CircleMemberJoined,
    CircleFileShared,
}

impl NotificationKind {
    pub fn category(self) -> NotificationCategory {
        match self {
            Self::AlertHigh | Self::AlertMedium | Self::AlertLow => NotificationCategory::Alerts,
            Self::DeviceDiscovered
            | Self::DevicePendingApproval
            | Self::GuardianOffline
            | Self::CircleMemberPendingApproval => NotificationCategory::Devices,
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
    /// DID of whoever caused this event (the sender of a message, the
    /// caller, the new member). This notify bus has no per-client delivery
    /// targeting — every locally connected client (admin + every browser
    /// member) receives every event — so the client that originated the
    /// event uses this to skip showing itself its own notification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_did: Option<String>,
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn category_mapping_covers_every_kind() {
        let alerts = [
            NotificationKind::AlertHigh,
            NotificationKind::AlertMedium,
            NotificationKind::AlertLow,
        ];
        for kind in alerts {
            assert_eq!(kind.category(), NotificationCategory::Alerts);
        }

        let devices = [
            NotificationKind::DeviceDiscovered,
            NotificationKind::DevicePendingApproval,
            NotificationKind::GuardianOffline,
            NotificationKind::CircleMemberPendingApproval,
        ];
        for kind in devices {
            assert_eq!(kind.category(), NotificationCategory::Devices);
        }

        let circles = [
            NotificationKind::CircleNewMessage,
            NotificationKind::CircleIncomingCall,
            NotificationKind::CircleMemberJoined,
            NotificationKind::CircleFileShared,
        ];
        for kind in circles {
            assert_eq!(kind.category(), NotificationCategory::Circles);
        }
    }

    #[test]
    fn notification_kind_serializes_snake_case() {
        let json = serde_json::to_string(&NotificationKind::DevicePendingApproval).unwrap();
        assert_eq!(json, "\"device_pending_approval\"");
        let round_tripped: NotificationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(round_tripped, NotificationKind::DevicePendingApproval);
    }
}
