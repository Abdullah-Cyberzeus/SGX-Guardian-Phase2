use crate::vault::namespace::VaultNamespace;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VaultSource {
    FileTransfer,
    Upload,
    ChatAttachment,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncMeta {
    pub algo: String,
    pub chunk_bytes: u32,
    pub base_nonce_b64: String,
    pub wrapped_dek_b64: String,
    pub wrap_scheme: String,
    pub wrap_key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultRecord {
    pub vault_id: String,
    #[serde(default)]
    pub namespace: String,
    pub circle_id: String,
    pub filename: String,
    pub mime: String,
    pub size_plain: u64,
    pub size_cipher: u64,
    pub sha256_plain: String,
    pub sender_did: String,
    pub received_at: String,
    pub source: VaultSource,
    #[serde(default)]
    pub folder_id: String,
    #[serde(default)]
    pub starred: bool,
    /// Optional free-text note set at upload time (Files-tab uploads only).
    #[serde(default)]
    pub description: String,
    /// Explicit owner DID. Drives per-member filtering in the Personal
    /// namespace and owner-only controls (revoke/expiry/history). Distinct
    /// from `sender_did`, which records P2P transfer provenance.
    #[serde(default)]
    pub owner_did: String,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub revoked_at: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    /// Set only for 1:1 direct-message chat attachments, whose namespace is
    /// the sender's Personal store rather than a Circle. Grants the
    /// recipient access without adding a third namespace variant.
    #[serde(default)]
    pub conversation_recipient_did: Option<String>,
    /// Links a `ChatAttachment` record back to the chat message that
    /// references it, once that message has actually been created.
    #[serde(default)]
    pub message_id: Option<String>,
    pub enc: EncMeta,
}

impl VaultRecord {
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .as_deref()
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .is_some_and(|expires| expires <= chrono::Utc::now())
    }
}

impl VaultRecord {
    pub fn namespace_ref(&self) -> VaultNamespace {
        if self
            .namespace
            .eq_ignore_ascii_case(VaultNamespace::PERSONAL_STORAGE_KEY)
            || (self.namespace.trim().is_empty() && self.circle_id.trim().is_empty())
        {
            VaultNamespace::Personal
        } else if !self.namespace.trim().is_empty() {
            VaultNamespace::Circle(self.namespace.clone())
        } else {
            VaultNamespace::Circle(self.circle_id.clone())
        }
    }

    pub fn namespace_key(&self) -> String {
        self.namespace_ref().storage_key()
    }
}
