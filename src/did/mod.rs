//! W3C DID Core 1.0 implementation for `did:guardian`.

pub mod did;
pub mod errors;
pub mod method;
pub mod persistence;
pub mod registry;

pub use did::Did;
pub use errors::DidError;
pub use method::{create_if_absent, deactivate, resolve_local, update_dkp_version};
pub use persistence::{DidRecord, DEFAULT_DID_PATH, DEFAULT_IDENTITY_DIR, DEFAULT_PEERS_DIR};

#[cfg(test)]
mod tests;
