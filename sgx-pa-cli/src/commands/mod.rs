//! Subcommand modules for the SGX Policy Authority CLI (`sgx-pa-cli`).
//! Each module implements one CLI feature such as key generation,
//! policy signing, viewing logs, checking status, attestation results,
//! and listing trusted peers.
pub mod attest_quote;
pub mod attestation;
pub mod boot_status;
pub mod dkp_revoke;
pub mod dkp_rotate;
pub mod dkp_status;
pub mod emergency_rotate;
pub mod keygen;
pub mod logs;
pub mod pcr_baseline;
pub mod pcr_status;
pub mod peers;
pub mod sign;
pub mod status;
pub mod verify;
