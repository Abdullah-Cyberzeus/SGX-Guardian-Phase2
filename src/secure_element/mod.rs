// src/secure_element/mod.rs
// ============================================================
// NXP SE050 Secure Element Integration Layer
// Chip: SE050F2HQ1Z018HZ | Interface: T=1 over I2C
// Middleware: NXP Plug & Trust v04.05.01 | CLI: ssscli
// ============================================================

pub mod config;
pub mod crypto;
pub mod dik;
pub mod dkp;
pub mod error;
pub mod key_meta;
pub mod key_storage;
pub mod pcr;
pub mod pcr_config;
pub mod safe_mode;
pub mod se050;
pub mod secure_boot;
pub mod sign;
pub mod ssscli;
pub mod tamper;
pub mod traits;

// Re-export commonly used types for convenience
pub use config::SeConfig;
pub use error::SeError;
pub use se050::Se050;
