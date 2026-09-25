//! Mesh LAN CA discovery (P3.1–P3.4) — how a joining Guardian finds the
//! circles already running on its LAN.
//!
//! ## Two layers, deliberately split
//!
//! 1. **Presence** ([`advertise`]/[`browse`]'s beacon half): an unauthenticated
//!    "a CA exists, ask it at this address" pointer, broadcast over UDP
//!    (`CaBeacon`) and mDNS. Anyone on the LAN can send one, including a
//!    spoofer — that is fine, because nothing trusts it on its own.
//! 2. **Proof**: [`crate::mesh::ca::descriptor::CaDescriptor`], signed by the
//!    CA's own DID key and fetched straight from the address the beacon
//!    pointed at. This is the only thing [`DiscoveredCa::verified`] is based
//!    on. A spoofed beacon can get an entry to *appear* in a scan, pointing
//!    wherever the attacker likes, but it cannot make that entry verify
//!    without the real CA's private key — it just renders unverified and
//!    unselectable (P3.6), which is the phase's actual exit criterion.
//!
//! ## Scope note: mDNS browsing is not implemented in this pass
//!
//! `libmdns` (the only mDNS crate already in this workspace) is a responder
//! only — it has no client-side service *browsing* API. [`advertise`] still
//! publishes the `_sgx-ca._tcp` record with it (real interop value, zero new
//! risk), but [`browse`] discovers peers over the UDP `CaBeacon` channel
//! only. Adding a browsing-capable mDNS crate (e.g. `mdns-sd`) is a real,
//! separate dependency decision, not something to fold in silently here.
//!
//! ## Port note: the beacon does not reuse UDP 9000
//!
//! P3.7's own text says "beacon UDP 9000," reading as a reuse of the
//! existing broadcast port. In the actual tree, `node_listener.rs` already
//! binds `0.0.0.0:9000` exclusively for the legacy, unsigned
//! `NodeAnnouncement` receiver — a second exclusive bind on the same port
//! would fail outright, not "share" anything. `CaBeacon` uses its own port
//! instead ([`BEACON_PORT_ENV`], default [`DEFAULT_BEACON_PORT`]), with its
//! own firewall rule (P3.7, `src/enforcement/executor.rs`).

pub mod advertise;
pub mod browse;

use serde::{Deserialize, Serialize};

/// Env override for the `CaBeacon` UDP port — see the module doc's port note.
pub const BEACON_PORT_ENV: &str = "SGX_CA_BEACON_PORT";
pub const DEFAULT_BEACON_PORT: u16 = 9100;

pub fn beacon_port() -> u16 {
    std::env::var(BEACON_PORT_ENV)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_BEACON_PORT)
}

/// Env override for the descriptor/enrollment TCP listener — P3.1's
/// "enrollment port." Phase 4's real gRPC+TLS enrollment server (P4.2) is
/// expected to take this port over later; this phase's listener
/// ([`crate::mesh::ca::descriptor::serve_forever`]) is a plain-HTTP interim
/// implementation that only ever answers `GET /ca-descriptor`.
pub const DESCRIPTOR_PORT_ENV: &str = "SGX_CA_DESCRIPTOR_PORT";
pub const DEFAULT_DESCRIPTOR_PORT: u16 = 50071;

pub fn descriptor_port() -> u16 {
    std::env::var(DESCRIPTOR_PORT_ENV)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_DESCRIPTOR_PORT)
}

/// The unauthenticated "look here" pointer — see the module doc's presence
/// vs. proof split. `magic` is a cheap schema tag, not a security boundary:
/// it exists so a legacy `NodeAnnouncement` packet on a shared network never
/// gets mistaken for one of these (today they don't even share a port, per
/// the module doc, but the tag keeps that true if they ever do).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaBeacon {
    pub magic: String,
    pub circle_id: String,
    pub ca_guardian_id: String,
    pub lan_endpoint: String,
}

pub const CA_BEACON_MAGIC: &str = "sgx-ca-beacon-v1";

impl CaBeacon {
    pub fn new(circle_id: String, ca_guardian_id: String, lan_endpoint: String) -> Self {
        Self {
            magic: CA_BEACON_MAGIC.to_string(),
            circle_id,
            ca_guardian_id,
            lan_endpoint,
        }
    }
}

/// One LAN entry as the operator sees it (P3.6) — the result of fetching and
/// verifying (or failing to verify) a [`crate::mesh::ca::descriptor::CaDescriptor`]
/// from a discovered endpoint. Two Guardians that each created a circle
/// necessarily produce two of these with different `circle_id`/`fingerprint`
/// (Phase 2's own exit criterion, re-observed here as a discovery fact).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiscoveredCa {
    pub circle_id: String,
    pub circle_name: String,
    pub ca_guardian_id: String,
    pub fingerprint: String,
    pub fingerprint_words: String,
    pub lan_endpoint: String,
    pub verified: bool,
    pub policy_summary: Option<crate::mesh::ca::descriptor::PolicySummary>,
}

/// First 16 of the NATO phonetic alphabet — matches the frontend's own
/// `fingerprintPhrase()` in `SU02CreateCircle.tsx` exactly, so a CA's own
/// fingerprint phrase reads identically whether it is showing its own (P2.5)
/// or being looked at by a joiner discovering it (P3.6).
const NIBBLE_WORDS: [&str; 16] = [
    "Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot", "Golf", "Hotel", "India", "Juliet",
    "Kilo", "Lima", "Mike", "November", "Oscar", "Papa",
];

pub fn fingerprint_words(fingerprint: &str) -> String {
    let hex: String = fingerprint
        .strip_prefix("sha256:")
        .unwrap_or(fingerprint)
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_lowercase();
    hex.chars()
        .take(8)
        .filter_map(|c| c.to_digit(16))
        .map(|nibble| NIBBLE_WORDS[nibble as usize])
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_words_strips_the_sha256_prefix_and_takes_the_first_eight_nibbles() {
        let words = fingerprint_words("sha256:deadbeefcafe0000");
        // d=13 e=14 a=10 d=13 b=11 e=14 e=14 f=15, against the same
        // 0-indexed NIBBLE_WORDS order SU02CreateCircle.tsx's
        // `fingerprintPhrase()` uses.
        assert_eq!(
            words,
            "November Oscar Kilo November Lima Oscar Oscar Papa"
        );
    }

    #[test]
    fn fingerprint_words_ignores_non_hex_characters_rather_than_panicking() {
        let words = fingerprint_words("not-a-real-fingerprint");
        assert!(!words.contains('\u{0}'));
    }

    #[test]
    fn a_beacon_carries_the_documented_magic_tag() {
        let beacon = CaBeacon::new("circle-X".into(), "ca-1".into(), "10.0.0.5:50071".into());
        assert_eq!(beacon.magic, CA_BEACON_MAGIC);
    }
}
