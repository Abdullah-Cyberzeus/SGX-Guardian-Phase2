// ===== Public exports for integration tests =====

// Core modules
pub mod advisory;
pub mod api;
pub mod chat;
pub mod contacts;

pub mod attestation_service;
pub mod audit;
pub mod automation;
pub mod backup;
pub mod call;
pub mod cert_client;
pub mod cert_service;
pub mod circle;
pub mod client;
pub mod cloud;
pub mod config_loader;
pub mod cot;
pub mod crl;
pub mod device;
pub mod devices;
pub mod did;
pub mod discovery; // Network discovery module
pub mod dusage;
pub mod enforcement;
pub mod geofence;
pub mod homeassistant;
pub mod integration;
pub mod kasa;
pub mod key_manager;
pub mod lan_name;
pub mod logging;
pub mod media;
pub mod metrics;
pub mod metrics_server;
pub mod nebula;
pub mod nest;
pub mod netbridge;
pub mod notification;
pub mod notify;
pub mod p2p_discovery;
pub mod policy;
pub mod policy_authority;
pub mod policy_manager;
pub mod policy_state;
pub mod rules;
pub mod runtime;
pub mod runtime_gates;
pub mod secure_element;
pub mod server;
pub mod startup;
pub mod storage;
pub mod telemetry;
pub mod testkit;
pub mod threat;
pub mod tls;
pub mod tpm;
pub mod vault;
pub mod vc;
pub mod virtual_id;
pub mod virtual_id_cache;
pub mod xfer;
// WiFi + Ethernet discovery modules
pub mod dynamic_config;
pub mod network_selector;
pub mod node_announcement;
pub mod node_broadcast;
pub mod node_listener;
#[cfg(test)]
mod test_support;

// gRPC proto (auto-generated)
pub mod proto {
    pub mod sgx {
        include!(concat!(env!("OUT_DIR"), "/sgx.rs"));
    }
}
pub fn add_numbers(a: i32, b: i32) -> i32 {
    a + b
}

#[cfg(test)]
pub mod test_utils {
    // Re-export rather than define: this used to be a second, independent
    // mutex guarding the same process environment as `test_support`'s.
    pub use crate::test_support::env_lock;
}
