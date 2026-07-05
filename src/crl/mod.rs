pub mod entry;
pub mod errors;
pub mod issue;
pub mod list;
pub mod persistence;
pub mod verify;

pub use entry::{
    CrlEntry, RevocationEvidence, RevocationReason, RevokerRole, Severity, CRL_CONTEXT_CORE,
    CRL_CONTEXT_SGX,
};
pub use errors::CrlError;
pub use list::CertificateRevocationList;

/// Fast O(log n) lookup: is this DID currently revoked?
///
/// Reads the locally-persisted `crl.json`. Callers that need fresher data
/// should first call gossip-pull (Sprint 4 Task 2) before this. For Phase
/// 2 baseline this is the canonical "are you allowed to talk" gate.
pub fn is_revoked(did: &str) -> bool {
    match persistence::load_crl() {
        Ok(Some(crl)) => crl.contains(did),
        _ => false,
    }
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
