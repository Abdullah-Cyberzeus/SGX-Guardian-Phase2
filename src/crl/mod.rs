pub mod entry;
pub mod errors;
pub mod gossip;
pub mod issue;
pub mod list;
pub mod offline;
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
/// should first wait for gossip convergence or trigger a fresh sync. For
/// the current baseline this is the canonical "are you allowed to talk" gate.
///
/// Fails CLOSED: if the CRL file exists but cannot be loaded or parsed, the
/// DID is treated as revoked until the CRL is readable again, rather than
/// silently letting revoked DIDs through.
pub fn is_revoked(did: &str) -> bool {
    match persistence::load_crl() {
        Ok(Some(crl)) => crl.contains(did),
        Ok(None) => false, // no CRL file yet — fresh install, no revocations
        Err(e) => {
            eprintln!("⚠️ CRL load failed (fail-closed): {}", e);
            true
        }
    }
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
