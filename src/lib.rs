// ===== Public exports for integration tests =====

// Core modules
pub mod attestation_service;
pub mod client;
pub mod config_loader;
pub mod key_manager;
pub mod logging;
pub mod metrics;
pub mod p2p_discovery;
pub mod policy;
pub mod server;

// gRPC proto (auto-generated)
pub mod proto {
    pub mod sgx {
        include!(concat!(env!("OUT_DIR"), "/sgx.rs"));
    }
}

// (Optional) If you still need this from previous file:
pub fn add_numbers(a: i32, b: i32) -> i32 {
    a + b
}
