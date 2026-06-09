pub mod credential;
pub mod distribution;
pub mod errors;
pub mod issue;
pub mod persistence;
pub mod status_list;
pub mod verify;

pub use credential::{
    CredentialRole, CredentialStatus, CredentialSubject, MembershipStatus, VerifiableCredential,
    TYPE_CIRCLE_MEMBERSHIP, TYPE_VC, VC_CONTEXT_CORE, VC_CONTEXT_JWS_2020, VC_CONTEXT_SGX_CIRCLE,
    VC_CONTEXT_STATUS_LIST_2021,
};
pub use errors::VcError;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
