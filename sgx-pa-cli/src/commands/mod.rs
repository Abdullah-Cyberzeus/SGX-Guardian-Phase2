//! Subcommand modules for the SGX Policy Authority CLI (`sgx-pa-cli`).
//! Each module implements one CLI feature such as key generation,
//! policy signing, viewing logs, checking status, attestation results,
//! and listing trusted peers.
pub mod attestation;
pub mod keygen;
pub mod logs;
pub mod peers;
pub mod sign;
pub mod status;
