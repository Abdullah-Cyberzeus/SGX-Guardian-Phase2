//! Per-DID VirtualID cache. Detects rotations and signals re-attestation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedVid {
    pub vid_hex: String,
    /// Stable component (no nonces) — used to classify rotations.
    /// SHA256(STABLE_TAG ‖ DID ‖ DKP_pub ‖ PCR_digest ‖ policy_digest), hex.
    #[serde(default)]
    pub stable_component_hex: String,
    /// Individual inputs at last observation. Hex-encoded for diagnostics
    /// and used to identify which input changed on the next rotation.
    #[serde(default)]
    pub dkp_pubkey_sha256_b16: String,
    #[serde(default)]
    pub pcr_composite_digest: String,
    #[serde(default)]
    pub policy_digest: String,
    pub observed_at: DateTime<Utc>,
    /// Categorical reason for the last rotation (typed) — replaces the
    /// freeform "input changed" string.
    #[serde(default)]
    pub last_rotation_reason: Option<RotationReason>,
    /// Last time we triggered a re-attestation for this peer. Used by the
    /// 30-second cooldown to suppress storms.
    #[serde(default)]
    pub last_reattest_triggered_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RotationReason {
    /// Only the session nonces changed. NOT a security event.
    NonceOnly,
    /// DKP public key changed (manual rotation or HKM lifecycle event).
    DkpRotated,
    /// PCR composite digest changed (firmware/boot state drift).
    PcrChanged,
    /// Policy digest changed (policy update applied).
    PolicyChanged,
    /// More than one security input changed simultaneously.
    MultipleSecurityInputs,
}

impl RotationReason {
    pub fn is_security_event(self) -> bool {
        !matches!(self, RotationReason::NonceOnly)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            RotationReason::NonceOnly => "nonce_only",
            RotationReason::DkpRotated => "dkp_rotated",
            RotationReason::PcrChanged => "pcr_changed",
            RotationReason::PolicyChanged => "policy_changed",
            RotationReason::MultipleSecurityInputs => "multiple_security_inputs",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VidObservation {
    /// First time we've ever seen this DID. Cache it.
    FirstSeen,
    /// Same VID as last time. Session continues.
    Unchanged,
    /// Different VID for the same DID. Classification tells caller whether
    /// to trigger re-attestation (security events only) or just log.
    Rotated {
        previous: String,
        reason: RotationReason,
        /// True if the cooldown allows a fresh re-attest trigger NOW.
        /// False means "security event detected but rate-limited; do not trigger".
        cooldown_allows_reattest: bool,
    },
}

#[derive(Clone)]
pub struct VirtualIdCache {
    inner: Arc<RwLock<HashMap<String, CachedVid>>>,
}

impl VirtualIdCache {
    /// Cooldown between successive re-attestation triggers for the same peer.
    pub const REATTEST_COOLDOWN: Duration = Duration::from_secs(30);

    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Observe a fresh evidence's VirtualID for a peer DID. Returns the
    /// classification and updates the cache atomically.
    pub async fn observe(&self, peer_did: &str, new_vid_hex: &str) -> VidObservation {
        self.observe_sync(peer_did, new_vid_hex)
    }

    /// New rich observation: callers pass full identity+state context, not
    /// just the VID hex. Lets us classify the rotation type.
    pub fn observe_rich(&self, ctx: &ObservationContext<'_>) -> VidObservation {
        let mut cache = self.inner.write().expect("VID cache poisoned");
        let now = Utc::now();

        match cache.get(ctx.peer_did).cloned() {
            None => {
                cache.insert(
                    ctx.peer_did.to_string(),
                    CachedVid {
                        vid_hex: ctx.new_vid_hex.to_string(),
                        stable_component_hex: ctx.new_stable_hex.to_string(),
                        dkp_pubkey_sha256_b16: ctx.new_dkp_fp.to_string(),
                        pcr_composite_digest: ctx.new_pcr_digest.to_string(),
                        policy_digest: ctx.new_policy_digest.to_string(),
                        observed_at: now,
                        last_rotation_reason: None,
                        last_reattest_triggered_at: None,
                    },
                );
                VidObservation::FirstSeen
            }
            Some(prev) if prev.vid_hex == ctx.new_vid_hex => {
                // Touch observed_at so dashboards know we're seeing fresh
                // evidence, but otherwise nothing changes.
                if let Some(slot) = cache.get_mut(ctx.peer_did) {
                    slot.observed_at = now;
                }
                VidObservation::Unchanged
            }
            Some(prev) => {
                let reason = classify_rotation(&prev, ctx);
                let previous_vid = prev.vid_hex.clone();
                let previous_reattest = prev.last_reattest_triggered_at;

                // Cooldown: even on a real security event, only trigger
                // re-attest if more than REATTEST_COOLDOWN has passed since
                // the last trigger for THIS peer.
                let cooldown_allows = reason.is_security_event()
                    && previous_reattest
                        .map(|t| {
                            (now - t).to_std().unwrap_or(Duration::from_secs(0))
                                >= Self::REATTEST_COOLDOWN
                        })
                        .unwrap_or(true);

                cache.insert(
                    ctx.peer_did.to_string(),
                    CachedVid {
                        vid_hex: ctx.new_vid_hex.to_string(),
                        stable_component_hex: ctx.new_stable_hex.to_string(),
                        dkp_pubkey_sha256_b16: ctx.new_dkp_fp.to_string(),
                        pcr_composite_digest: ctx.new_pcr_digest.to_string(),
                        policy_digest: ctx.new_policy_digest.to_string(),
                        observed_at: now,
                        last_rotation_reason: Some(reason),
                        last_reattest_triggered_at: if cooldown_allows {
                            Some(now)
                        } else {
                            previous_reattest
                        },
                    },
                );
                VidObservation::Rotated {
                    previous: previous_vid,
                    reason,
                    cooldown_allows_reattest: cooldown_allows,
                }
            }
        }
    }

    /// Back-compat wrapper for tests / call sites that only have the VID
    /// hex (e.g. unit tests). Treats the rotation as `MultipleSecurityInputs`
    /// if it can't determine specifics. Real production caller is
    /// `observe_rich`.
    pub fn observe_sync(&self, peer_did: &str, new_vid_hex: &str) -> VidObservation {
        self.observe_rich(&ObservationContext {
            peer_did,
            new_vid_hex,
            new_stable_hex: "",
            new_dkp_fp: "",
            new_pcr_digest: "",
            new_policy_digest: "",
        })
    }

    pub async fn current_for(&self, peer_did: &str) -> Option<CachedVid> {
        self.current_for_sync(peer_did)
    }

    pub fn current_for_sync(&self, peer_did: &str) -> Option<CachedVid> {
        self.inner
            .read()
            .expect("VID cache poisoned")
            .get(peer_did)
            .cloned()
    }

    pub async fn forget(&self, peer_did: &str) {
        self.inner
            .write()
            .expect("VID cache poisoned")
            .remove(peer_did);
    }

    pub async fn clear(&self) {
        self.clear_sync();
    }

    pub fn clear_sync(&self) {
        self.inner.write().expect("VID cache poisoned").clear();
    }

    pub async fn snapshot(&self) -> HashMap<String, CachedVid> {
        self.snapshot_sync()
    }

    pub fn snapshot_sync(&self) -> HashMap<String, CachedVid> {
        self.inner.read().expect("VID cache poisoned").clone()
    }
}

impl Default for VirtualIdCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Inputs the cache needs to classify rotations.
#[derive(Debug, Clone, Copy)]
pub struct ObservationContext<'a> {
    pub peer_did: &'a str,
    pub new_vid_hex: &'a str,
    pub new_stable_hex: &'a str,
    pub new_dkp_fp: &'a str,
    pub new_pcr_digest: &'a str,
    pub new_policy_digest: &'a str,
}

fn classify_rotation(prev: &CachedVid, ctx: &ObservationContext<'_>) -> RotationReason {
    // If the stable component matches, only the nonces changed.
    if !prev.stable_component_hex.is_empty() && prev.stable_component_hex == ctx.new_stable_hex {
        return RotationReason::NonceOnly;
    }

    // Otherwise diff the individual security inputs.
    let dkp_changed =
        !prev.dkp_pubkey_sha256_b16.is_empty() && prev.dkp_pubkey_sha256_b16 != ctx.new_dkp_fp;
    let pcr_changed =
        !prev.pcr_composite_digest.is_empty() && prev.pcr_composite_digest != ctx.new_pcr_digest;
    let policy_changed =
        !prev.policy_digest.is_empty() && prev.policy_digest != ctx.new_policy_digest;

    match (dkp_changed, pcr_changed, policy_changed) {
        (true, false, false) => RotationReason::DkpRotated,
        (false, true, false) => RotationReason::PcrChanged,
        (false, false, true) => RotationReason::PolicyChanged,
        // If two or more changed, OR if we have no prev metadata to diff
        // (legacy cache entry from before this fix), conservatively classify
        // as a multi-input rotation. Better safe than missing a real event.
        _ => RotationReason::MultipleSecurityInputs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;

    fn ctx<'a>(
        peer_did: &'a str,
        new_vid_hex: &'a str,
        new_stable_hex: &'a str,
        new_dkp_fp: &'a str,
        new_pcr_digest: &'a str,
        new_policy_digest: &'a str,
    ) -> ObservationContext<'a> {
        ObservationContext {
            peer_did,
            new_vid_hex,
            new_stable_hex,
            new_dkp_fp,
            new_pcr_digest,
            new_policy_digest,
        }
    }

    #[test]
    fn vid_cache_classifies_first_unchanged_and_rotated() {
        let cache = VirtualIdCache::new();
        assert_eq!(
            cache.observe_sync("did:guardian:a", "vid-1"),
            VidObservation::FirstSeen
        );
        assert_eq!(
            cache.observe_sync("did:guardian:a", "vid-1"),
            VidObservation::Unchanged
        );
        assert_eq!(
            cache.observe_sync("did:guardian:a", "vid-2"),
            VidObservation::Rotated {
                previous: "vid-1".to_string(),
                reason: RotationReason::MultipleSecurityInputs,
                cooldown_allows_reattest: true,
            }
        );
    }

    #[test]
    fn classify_nonce_only_no_storm() {
        let cache = VirtualIdCache::new();
        assert_eq!(
            cache.observe_rich(&ctx(
                "did:guardian:a",
                "vid-1",
                "stable-1",
                "dkp-1",
                "pcr-1",
                "policy-1"
            )),
            VidObservation::FirstSeen
        );
        assert_eq!(
            cache.observe_rich(&ctx(
                "did:guardian:a",
                "vid-2",
                "stable-1",
                "dkp-1",
                "pcr-1",
                "policy-1"
            )),
            VidObservation::Rotated {
                previous: "vid-1".to_string(),
                reason: RotationReason::NonceOnly,
                cooldown_allows_reattest: false,
            }
        );
    }

    #[test]
    fn classify_dkp_rotation() {
        let cache = VirtualIdCache::new();
        let _ = cache.observe_rich(&ctx(
            "did:guardian:a",
            "vid-1",
            "stable-1",
            "dkp-1",
            "pcr-1",
            "policy-1",
        ));
        assert_eq!(
            cache.observe_rich(&ctx(
                "did:guardian:a",
                "vid-2",
                "stable-2",
                "dkp-2",
                "pcr-1",
                "policy-1"
            )),
            VidObservation::Rotated {
                previous: "vid-1".to_string(),
                reason: RotationReason::DkpRotated,
                cooldown_allows_reattest: true,
            }
        );
    }

    #[test]
    fn classify_pcr_change() {
        let cache = VirtualIdCache::new();
        let _ = cache.observe_rich(&ctx(
            "did:guardian:a",
            "vid-1",
            "stable-1",
            "dkp-1",
            "pcr-1",
            "policy-1",
        ));
        assert_eq!(
            cache.observe_rich(&ctx(
                "did:guardian:a",
                "vid-2",
                "stable-2",
                "dkp-1",
                "pcr-2",
                "policy-1"
            )),
            VidObservation::Rotated {
                previous: "vid-1".to_string(),
                reason: RotationReason::PcrChanged,
                cooldown_allows_reattest: true,
            }
        );
    }

    #[test]
    fn classify_policy_change() {
        let cache = VirtualIdCache::new();
        let _ = cache.observe_rich(&ctx(
            "did:guardian:a",
            "vid-1",
            "stable-1",
            "dkp-1",
            "pcr-1",
            "policy-1",
        ));
        assert_eq!(
            cache.observe_rich(&ctx(
                "did:guardian:a",
                "vid-2",
                "stable-2",
                "dkp-1",
                "pcr-1",
                "policy-2"
            )),
            VidObservation::Rotated {
                previous: "vid-1".to_string(),
                reason: RotationReason::PolicyChanged,
                cooldown_allows_reattest: true,
            }
        );
    }

    #[test]
    fn cooldown_blocks_within_30s() {
        let cache = VirtualIdCache::new();
        let _ = cache.observe_rich(&ctx(
            "did:guardian:a",
            "vid-1",
            "stable-1",
            "dkp-1",
            "pcr-1",
            "policy-1",
        ));
        let _ = cache.observe_rich(&ctx(
            "did:guardian:a",
            "vid-2",
            "stable-2",
            "dkp-2",
            "pcr-1",
            "policy-1",
        ));
        assert_eq!(
            cache.observe_rich(&ctx(
                "did:guardian:a",
                "vid-3",
                "stable-3",
                "dkp-3",
                "pcr-1",
                "policy-1"
            )),
            VidObservation::Rotated {
                previous: "vid-2".to_string(),
                reason: RotationReason::DkpRotated,
                cooldown_allows_reattest: false,
            }
        );
    }

    #[test]
    fn cooldown_allows_after_30s() {
        let cache = VirtualIdCache::new();
        let _ = cache.observe_rich(&ctx(
            "did:guardian:a",
            "vid-1",
            "stable-1",
            "dkp-1",
            "pcr-1",
            "policy-1",
        ));
        let _ = cache.observe_rich(&ctx(
            "did:guardian:a",
            "vid-2",
            "stable-2",
            "dkp-2",
            "pcr-1",
            "policy-1",
        ));
        cache
            .inner
            .write()
            .expect("VID cache poisoned")
            .get_mut("did:guardian:a")
            .expect("cached peer missing")
            .last_reattest_triggered_at = Some(Utc::now() - ChronoDuration::seconds(31));
        assert_eq!(
            cache.observe_rich(&ctx(
                "did:guardian:a",
                "vid-3",
                "stable-3",
                "dkp-3",
                "pcr-1",
                "policy-1"
            )),
            VidObservation::Rotated {
                previous: "vid-2".to_string(),
                reason: RotationReason::DkpRotated,
                cooldown_allows_reattest: true,
            }
        );
    }
}
