use std::io;

#[derive(Debug, thiserror::Error)]
pub enum DidError {
    #[error("DID file I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("DID JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid DID format: {0}")]
    InvalidFormat(String),

    #[error("Method mismatch: expected 'guardian', got '{0}'")]
    WrongMethod(String),

    #[error("Base58 decode error: {0}")]
    Base58(String),

    #[error("DID is deactivated (deactivated_at={0})")]
    Deactivated(String),

    #[error("DID derivation mismatch — current hardware does not match did.json")]
    DerivationMismatch,

    #[error("SE050 UID unavailable: {0}")]
    UidUnavailable(String),

    #[error("DKP public key unavailable at {0}")]
    DkpPubkeyMissing(String),

    #[error("DID derivation signature failed: {0}")]
    Signing(String),

    #[error("DID document signature invalid")]
    DerivSignatureInvalid,

    #[error(
        "DID Document replay: incoming version v{incoming} is older than locally known v{known}"
    )]
    ReplayedOldVersion { incoming: u32, known: u32 },

    #[error("DID unresolvable: no source returned a document for {0}")]
    Unresolvable(String),

    #[error("DID resolution failed: {0}")]
    ResolutionFailed(String),
}
