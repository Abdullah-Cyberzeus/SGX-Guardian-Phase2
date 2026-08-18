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

/// Metadata for a chat attachment stored on the local Guardian.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttachmentRecord {
    pub file_id: String,
    pub message_id: String,
    pub file_name: String,
    #[serde(default = "default_attachment_mime")]
    pub mime_type: String,
    pub encrypted_size: u64,
    pub sha256_hash: String,
    pub local_path: String,
    pub encrypted_file_key: String,
}

fn default_attachment_mime() -> String {
    "application/octet-stream".to_string()
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
#[serde(tag = "event_type")]
pub enum ChatEvent {
    NewMessage(ChatMessageRecord),
    ReadReceipt(ReadReceiptRecord),
    MessageStatus(ChatMessageRecord),
}
