use serde::{Deserialize, Serialize};

/// Represents a single chat message envelope (P2P or Group).
/// Stored chronologically in append-only JSON Lines (.jsonl) files.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChatMessageRecord {
    pub message_id: String,
    pub sender_did: String,
    pub recipient_did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    pub timestamp: i64,
    pub seq_no: u64,
    pub encrypted_payload: String,
    pub signature: String,
    pub status: MessageStatus,
    #[serde(default)]
    pub read_by: Vec<String>,
}

/// Tracks the delivery and read status of a message.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MessageStatus {
    Pending,
    #[serde(rename = "accepted_by_guardian")]
    AcceptedByGuardian,
    Delivered,
    #[serde(rename = "delivered_to_remote_guardian")]
    DeliveredToRemoteGuardian,
    Read,
    Failed,
}

impl MessageStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageStatus::Pending => "pending",
            MessageStatus::AcceptedByGuardian => "accepted_by_guardian",
            MessageStatus::Delivered => "delivered",
            MessageStatus::DeliveredToRemoteGuardian => "delivered_to_remote_guardian",
            MessageStatus::Read => "read",
            MessageStatus::Failed => "failed",
        }
    }
}

/// Represents a historical event when a specific message was read by a user.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReadReceiptRecord {
    pub message_id: String,
    pub reader_did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    pub read_at: i64,
}

#[derive(Debug, Serialize, Clone)]
pub struct TypingEvent {
    pub conversation_id: String,
    pub sender_did: String,
    pub is_typing: bool,
}

#[derive(Debug, Serialize, Clone)]
#[serde(tag = "event_type")]
pub enum ChatEvent {
    NewMessage(ChatMessageRecord),
    ReadReceipt(ReadReceiptRecord),
    MessageStatus(ChatMessageRecord),
    Typing(TypingEvent),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typing_event_serializes_with_event_type_tag() {
        let event = ChatEvent::Typing(TypingEvent {
            conversation_id: "pair-a-b".to_string(),
            sender_did: "did:guardian:alice".to_string(),
            is_typing: true,
        });
        let json = serde_json::to_value(&event).expect("serialize typing event");
        assert_eq!(json["event_type"], "Typing");
        assert_eq!(json["conversation_id"], "pair-a-b");
        assert_eq!(json["sender_did"], "did:guardian:alice");
        assert_eq!(json["is_typing"], true);
    }
}
