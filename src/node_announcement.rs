use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NodeAnnouncement {
    pub node_id: String,
    pub hostname: String,
    pub ip: String,
    pub port: u16,
    pub public_key: String,
}