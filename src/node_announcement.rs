use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NodeAnnouncement {
    pub node_id: String,
    pub hostname: String,
    pub ip: String,
    pub port: u16,
    pub public_key: String,
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub timestamp: u64,
}

impl NodeAnnouncement {
    /// Create announcement with integrity digest.
    pub fn new_signed(
        node_id: String,
        hostname: String,
        ip: String,
        port: u16,
        public_key: String,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let msg = format!("{}{}{}{}{}", node_id, ip, port, public_key, timestamp);
        let digest = Sha256::digest(msg.as_bytes());
        let signature = hex::encode(digest);

        Self {
            node_id,
            hostname,
            ip,
            port,
            public_key,
            signature,
            timestamp,
        }
    }

    /// Verify integrity and reject stale announcements.
    pub fn verify_integrity(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now.saturating_sub(self.timestamp) > 120 {
            return false;
        }

        let msg = format!(
            "{}{}{}{}{}",
            self.node_id, self.ip, self.port, self.public_key, self.timestamp
        );
        let digest = Sha256::digest(msg.as_bytes());
        self.signature == hex::encode(digest)
    }
}
