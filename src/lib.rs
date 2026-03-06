// ===== Public exports for integration tests =====

// Core modules
pub mod attestation_service;
pub mod audit;
pub mod cert_client;
pub mod cert_service;
pub mod client;
pub mod cloud;
pub mod config_loader;
pub mod cot;
pub mod enforcement;
pub mod key_manager;
pub mod logging;
pub mod metrics;
pub mod metrics_server;
pub mod nebula;
pub mod p2p_discovery;
pub mod policy;
pub mod policy_manager;
pub mod policy_state;
pub mod secure_element;
pub mod server;
pub mod tls;

// gRPC proto (auto-generated)
pub mod proto {
    pub mod sgx {
        include!(concat!(env!("OUT_DIR"), "/sgx.rs"));
    }
}
pub fn add_numbers(a: i32, b: i32) -> i32 {
    a + b
}
