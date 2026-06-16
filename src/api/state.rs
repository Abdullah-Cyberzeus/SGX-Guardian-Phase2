//! Shared state passed to every handler.
//! Keeps all filesystem paths in one place so tests can swap them out.

use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub node_id: String,
    pub config_dir: String,           // /etc/sgx-guardian/config
    pub boot_dir: String,             // /var/lib/sgx-guardian/boot
    pub keys_dir: String,             // /var/lib/sgx-guardian/keys
    pub pcr_dir: String,              // /var/lib/sgx-guardian/pcr
    pub pcr_baseline_dir: String,     // /etc/sgx-guardian
    pub log_dir_primary: String,      // /var/log/sgx-guardian
    pub log_dir_fallback: String,     // logs
    pub discovery_config_dir: String, // /etc/sgx-guardian/discovery
    pub discovery_state_dir: String,  // /var/lib/sgx-guardian/discovery
}

impl AppState {
    pub fn from_env(node_id: String) -> Arc<Self> {
        Arc::new(Self {
            node_id,
            config_dir: "/etc/sgx-guardian/config".into(),
            boot_dir: "/var/lib/sgx-guardian/boot".into(),
            keys_dir: "/var/lib/sgx-guardian/keys".into(),
            pcr_dir: "/var/lib/sgx-guardian/pcr".into(),
            pcr_baseline_dir: "/etc/sgx-guardian".into(),
            log_dir_primary: "/var/log/sgx-guardian".into(),
            log_dir_fallback: "logs".into(),
            discovery_config_dir: "/etc/sgx-guardian/discovery".into(),
            discovery_state_dir: "/var/lib/sgx-guardian/discovery".into(),
        })
    }
}
