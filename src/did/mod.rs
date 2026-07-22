//! W3C DID Core 1.0 implementation for `did:guardian`.

#[path = "did.rs"]
mod did_impl;
pub mod errors;
pub mod method;
pub mod persistence;
pub mod registry;

pub(crate) use did_impl::derive;
pub use did_impl::Did;
pub use errors::DidError;
pub use method::{create_if_absent, deactivate, resolve_local, update_dkp_version};
pub use persistence::{DidRecord, DEFAULT_DID_PATH, DEFAULT_IDENTITY_DIR, DEFAULT_PEERS_DIR};

#[cfg(test)]
mod tests;
