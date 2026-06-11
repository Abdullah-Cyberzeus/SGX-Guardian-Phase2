//! Sprint 6 Task 2: Two-Layer Identity Architecture.
//!
//! VirtualID = SHA-256(DOMAIN_TAG || len-prefixed(
//!     DID, CurrentDKP_PubKey, PCR_composite_digest,
//!     policy_digest, Nonce_I, Nonce_R
//! ))
//!
//! DID is the persistent identity anchor (Sprint 5 Task 1).
//! VirtualID is the session-scoped credential: it rotates whenever
//! DKP, PCR, policy, or session nonces change.

use sha2::{Digest, Sha256};

/// Domain-separation tag, bumped if the formula changes.
/// Format: `"SGX-VID-v" || ascii(version) || NUL`.
pub const VID_DOMAIN_TAG: &[u8] = b"SGX-VID-v1\0";

/// Inputs to VirtualID computation. Use this struct to make call sites explicit
/// and avoid positional-argument mistakes.
#[derive(Debug, Clone)]
pub struct VirtualIdInputs<'a> {
    pub did: &'a str,
    pub dkp_pubkey_der: &'a [u8],
    pub pcr_composite_digest: &'a [u8],
    pub policy_digest: &'a [u8],
    pub nonce_i: &'a [u8],
    pub nonce_r: &'a [u8],
}

impl<'a> VirtualIdInputs<'a> {
    /// Build the canonical byte sequence that gets hashed.
    /// Length-prefixed concatenation prevents collisions when any input is
    /// variable length, especially DID and public-key encodings.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            VID_DOMAIN_TAG.len()
                + 4
                + self.did.len()
                + 4
                + self.dkp_pubkey_der.len()
                + 4
                + self.pcr_composite_digest.len()
                + 4
                + self.policy_digest.len()
                + 4
                + self.nonce_i.len()
                + 4
                + self.nonce_r.len(),
        );
        buf.extend_from_slice(VID_DOMAIN_TAG);
        write_lp(&mut buf, self.did.as_bytes());
        write_lp(&mut buf, self.dkp_pubkey_der);
        write_lp(&mut buf, self.pcr_composite_digest);
        write_lp(&mut buf, self.policy_digest);
        write_lp(&mut buf, self.nonce_i);
        write_lp(&mut buf, self.nonce_r);
        buf
    }

    pub fn compute(&self) -> [u8; 32] {
        let out = Sha256::digest(self.canonical_bytes());
        let mut id = [0u8; 32];
        id.copy_from_slice(&out[..32]);
        id
    }
}

/// Length-prefixed write: 4-byte big-endian length, then bytes.
pub(crate) fn write_lp(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(&(b.len() as u32).to_be_bytes());
    buf.extend_from_slice(b);
}

/// Backward-compatible wrapper for transition-only callers.
#[deprecated(note = "use VirtualIdInputs::compute; DID-less signature removed in v1.1")]
pub fn compute_virtual_id_legacy(
    device_pubkey_der: &[u8],
    pcr_digest: &[u8],
    policy_digest: &[u8],
    nonce_i: &[u8],
    nonce_r: &[u8],
) -> [u8; 32] {
    VirtualIdInputs {
        did: "",
        dkp_pubkey_der: device_pubkey_der,
        pcr_composite_digest: pcr_digest,
        policy_digest,
        nonce_i,
        nonce_r,
    }
    .compute()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    fn sample_inputs<'a>() -> VirtualIdInputs<'a> {
        VirtualIdInputs {
            did: "did:guardian:abc",
            dkp_pubkey_der: &[0u8; 91],
            pcr_composite_digest: &[1u8; 32],
            policy_digest: &[2u8; 32],
            nonce_i: &[3u8; 32],
            nonce_r: &[4u8; 32],
        }
    }

    #[test]
    fn vid_001_deterministic_for_same_inputs() {
        let inp = sample_inputs();
        assert_eq!(inp.compute(), inp.compute());
    }

    #[test]
    fn vid_002_changes_when_did_changes() {
        let inp = sample_inputs();
        let changed = VirtualIdInputs {
            did: "did:guardian:xyz",
            ..inp.clone()
        };
        assert_ne!(inp.compute(), changed.compute());
    }

    #[test]
    fn vid_006_cross_session_unlinkability_from_nonces() {
        let inp = sample_inputs();
        let changed = VirtualIdInputs {
            nonce_i: &[9u8; 32],
            ..inp.clone()
        };
        assert_ne!(inp.compute(), changed.compute());
    }

    #[test]
    fn vid_009_length_prefix_prevents_collision() {
        let a = VirtualIdInputs {
            did: "did:guardian:AB",
            dkp_pubkey_der: b"CD",
            pcr_composite_digest: &[0u8; 32],
            policy_digest: &[0u8; 32],
            nonce_i: &[0u8; 32],
            nonce_r: &[0u8; 32],
        };
        let b = VirtualIdInputs {
            did: "did:guardian:A",
            dkp_pubkey_der: b"BCD",
            ..a.clone()
        };
        assert_ne!(a.compute(), b.compute());
    }

    #[test]
    fn vid_010_domain_tag_is_part_of_hash_input() {
        let inp = sample_inputs();
        let canonical = inp.canonical_bytes();
        assert!(canonical.starts_with(VID_DOMAIN_TAG));
        let without_tag = &canonical[VID_DOMAIN_TAG.len()..];
        let out = Sha256::digest(without_tag);
        assert_ne!(inp.compute().as_slice(), &out[..32]);
    }
}
