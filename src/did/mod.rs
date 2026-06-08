//! W3C DID Core 1.0 implementation for `did:guardian`.

#[path = "did.rs"]
mod did_impl;
pub mod doc_distribution;
pub mod doc_persistence;
pub mod doc_sign;
pub mod document;
pub mod errors;
pub mod method;
pub mod persistence;
pub mod registry;
pub mod resolver;
pub mod resolver_cache;

pub(crate) use did_impl::derive;
pub use did_impl::Did;
pub use errors::DidError;
pub use method::{create_if_absent, deactivate, resolve_local, update_dkp_version};
pub use persistence::{DidRecord, DEFAULT_DID_PATH, DEFAULT_IDENTITY_DIR, DEFAULT_PEERS_DIR};
pub use resolver::{ResolutionResult, ResolutionSource, Resolver, ResolverConfig};

#[cfg(test)]
#[path = "tests/resolver_tests.rs"]
mod resolver_tests;
#[cfg(test)]
mod tests;
