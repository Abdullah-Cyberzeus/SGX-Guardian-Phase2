//! Shared state passed to every handler.
//! Keeps all filesystem paths in one place so tests can swap them out.

use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub node_id: String,
    pub config_dir: String,
    pub boot_dir: String,
    pub keys_dir: String,
    pub pcr_dir: String,
    pub pcr_baseline_dir: String,
    pub log_dir_primary: String,
    pub log_dir_fallback: String,
    pub threat_config_path: String,
    pub threat_state_dir: String,
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
            threat_config_path: "/etc/sgx-guardian/threat/config.yaml".into(),
            threat_state_dir: "/var/lib/sgx-guardian/threat".into(),
        })
    }
}
