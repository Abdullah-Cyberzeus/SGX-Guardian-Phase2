//! Joiner-side enrollment.
//!
//! Phase 0 lands only [`keys`], the local Nebula key generation that stops
//! private keys being minted on — and shipped from — the CA (blocker B1).
//! Phase 4 adds `request`, `transport_lan`, `transport_wan` and `install`
//! alongside it; see `docs/Guardian_Mesh_Enrollment_Complete_Plan.md` §4.1.

pub mod keys;
