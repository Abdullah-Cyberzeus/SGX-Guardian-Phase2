// ===== Public exports for integration tests =====

// Core modules
pub mod api;
pub mod attestation_service;
pub mod audit;
pub mod cert_client;
pub mod cert_service;
pub mod client;
pub mod cloud;
pub mod circle;
pub mod config_loader;
pub mod cot;
pub mod crl;
pub mod did;
pub mod discovery; // Network discovery module
pub mod enforcement;
pub mod key_manager;
pub mod logging;
pub mod metrics;
pub mod metrics_server;
pub mod nebula;
pub mod netbridge;
pub mod notify;
pub mod p2p_discovery;
pub mod policy;
pub mod policy_authority;
pub mod policy_manager;
pub mod policy_state;
pub mod runtime;
pub mod runtime_gates;
pub mod secure_element;
pub mod server;
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
