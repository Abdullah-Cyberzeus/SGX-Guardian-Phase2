use crate::netbridge::types::NetbridgeError;
use std::fs;
use std::path::Path;
use tracing::warn;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DhcpLease {
    pub expiry: i64,
    pub mac_address: String,
    pub ip_address: String,
    pub hostname: String,
    pub client_id: String,
}

pub struct LeaseManager {
    lease_file_path: String,
}

impl LeaseManager {
    pub fn new(path: &str) -> Self {
        LeaseManager {
            lease_file_path: path.to_string(),
        }
    }
}

impl Default for LeaseManager {
    fn default() -> Self {
        Self::new("/tmp/netbridge/dnsmasq.leases")
    }
}

impl LeaseManager {
    /// Reads and parses the dnsmasq.leases file to track connected clients.
    pub fn get_active_leases(&self) -> Result<Vec<DhcpLease>, NetbridgeError> {
        let path = Path::new(&self.lease_file_path);

        if !path.exists() {
            // File might not exist until the first device connects
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(path).map_err(NetbridgeError::IoError)?;
        let mut leases = Vec::new();

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                let expiry = parts[0].parse::<i64>().unwrap_or(0);

                leases.push(DhcpLease {
                    expiry,
                    mac_address: parts[1].to_string(),
                    ip_address: parts[2].to_string(),
                    hostname: parts[3].to_string(),
                    client_id: parts[4].to_string(),
                });
            } else {
                warn!("Found malformed line in dnsmasq.leases: {}", line);
            }
        }

        Ok(leases)
    }
}
