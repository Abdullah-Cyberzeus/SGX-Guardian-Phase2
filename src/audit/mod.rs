//! Audit logging module
//!
//! Provides structured, security-grade audit event definitions.
//! Actual persistence and tamper-evidence are added in later stages.

pub mod event;
pub mod hasher;
pub mod logger;
pub mod verifier;
pub mod writer;
