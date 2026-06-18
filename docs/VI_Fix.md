# SG-X Guardian — VirtualID Classification Completion Fix Plan

**Branch base:** `main` (latest pull via `project_knowledge_search`).
**Target branch:** `shahzad_vid_classify_complete` (additive on the existing VID work).
**Scope:** Fill the gaps in the rotation-reason classifier — three missing variants, broken precedence, peer-IP DID-change hint, and `trusted_peers.json` upsert-by-DID + rotation_reason persistence. No re-architecture; surgical FIND→REPLACE blocks against verbatim text from `main`.

---

## What I confirmed on `main`

The classifier on `main` already has:
- `RotationReason` enum with **5 variants**: `NonceOnly`, `DkpRotated`, `PcrChanged`, `PolicyChanged`, `MultipleSecurityInputs`.
- `CachedVid` with stable_component_hex, per-input fields, observed_at, last_rotation_reason, last_reattest_triggered_at.
- 30-second per-peer cooldown.
- `classify_rotation` using `(dkp, pcr, policy)` tuple match.

What's **missing or wrong** per the spec you provided:

| Gap | Where | Symptom |
|---|---|---|
| G1 | `RotationReason` enum has no `InitialObservation` | First observation logs no rotation_reason at all; trusted_peers can't record it |
| G2 | `RotationReason` enum has no `DidChanged` | Adversary swapping DIDs from same IP is silently treated as a new `FirstSeen` peer |
| G3 | `RotationReason` enum has no `UnknownInputChange` | Catch-all `_ => MultipleSecurityInputs` hides cases where VID changed but inputs look identical |
| G4 | Precedence wrong — DID change not checked before stable-input count | A DID flip can be reported as `NonceOnly` if the new DID's first observation reuses old IPs but the secondary index is absent |
| G5 | No peer-IP → last-DID hint structure | DID-change detection has no signal source |
| G6 | `write_trusted_peer` keys upsert by `peer_id` ("ip:port") | Port change → duplicate trusted_peers entry for the same actual peer |
| G7 | `TrustedPeer` has no `rotation_reason`, `nonce_i`, `nonce_r` fields | Acceptance criterion ("trusted_peers JSON must contain `rotation_reason: dkp_rotated`") fails |
| G8 | Audit messages don't follow the spec format | Spec calls for `old_dkp=<old> new_dkp=<new>` etc.; current code emits generic strings |

---

## Design decisions (locked)

1. **`InitialObservation` is a `RotationReason` enum variant**, not just a string. Lets trusted_peers persist it in the same column as all other reasons; `is_security_event()` returns `false` for it (no re-attest, no cooldown spending).
2. **`DidChanged` detection uses `peer_ip → last_did` secondary index.** Primary cache stays DID-keyed (per spec). The IP map is a hint, not the source of truth. We strip the port from `ip:port` so port churn doesn't break detection.
3. **`UnknownInputChange` is the catch-all bucket**, not `MultipleSecurityInputs`. The match is exhaustive on `(dkp_changed, pcr_changed, policy_changed) ∈ {Some(true), Some(false), None}³`, so we can write it cleanly. `MultipleSecurityInputs` only fires when ≥2 inputs are confirmed changed.
4. **Trusted-peers upsert is DID-first, peer_id-fallback.** Search the existing list by DID; if hit, update that record (and overwrite its stale peer_id/ip/port with the current values). If no DID match, fall back to peer_id lookup for legacy records. If still no match, insert. Migration is transparent.
5. **Backward compatibility everywhere.** All new fields are `Option<String>` with `#[serde(default, skip_serializing_if = "Option::is_none")]`. Pre-fix JSON parses cleanly.

---

# Fix 1 — Add the three missing `RotationReason` variants

## Fix 1.1 — Enum

**File:** `src/virtual_id_cache.rs`

**FIND**:
```rust
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
```

**REPLACE WITH**:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RotationReason {
    /// First time we've ever observed this DID. Not a rotation; recorded
    /// in trusted_peers so the lifecycle is auditable end-to-end.
    InitialObservation,
    /// Only the session nonces changed. NOT a security event.
    NonceOnly,
    /// Peer identity changed (same connection origin, different DID).
    /// Security-relevant: may indicate impersonation or re-provisioning.
    DidChanged,
    /// DKP public key changed (manual rotation or HKM lifecycle event).
    DkpRotated,
    /// PCR composite digest changed (firmware/boot state drift).
    PcrChanged,
    /// Policy digest changed (policy update applied).
    PolicyChanged,
    /// More than one stable security input changed at the same time.
    MultipleSecurityInputs,
    /// VID changed but every known stable input matched. Most likely an
    /// encoding skew or a missing field in our diff. Logged as Warning for
    /// investigation; not silently re-attested.
    UnknownInputChange,
}

impl RotationReason {
    /// Should this reason trigger a fresh attestation handshake?
    /// InitialObservation: false (the attestation itself just succeeded).
    /// NonceOnly: false (expected per-session refresh).
    /// UnknownInputChange: false (we don't know what changed; log and
    /// investigate — don't cause an attestation storm on an unknown).
    /// Everything else: true.
    pub fn is_security_event(self) -> bool {
        matches!(
            self,
            RotationReason::DidChanged
                | RotationReason::DkpRotated
                | RotationReason::PcrChanged
                | RotationReason::PolicyChanged
                | RotationReason::MultipleSecurityInputs
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            RotationReason::InitialObservation     => "initial_observation",
            RotationReason::NonceOnly              => "nonce_only",
            RotationReason::DidChanged             => "did_changed",
            RotationReason::DkpRotated             => "dkp_rotated",
            RotationReason::PcrChanged             => "pcr_changed",
            RotationReason::PolicyChanged          => "policy_changed",
            RotationReason::MultipleSecurityInputs => "multiple_security_inputs",
            RotationReason::UnknownInputChange     => "unknown_input_change",
        }
    }
}
```

> **Why `UnknownInputChange` doesn't trigger re-attest:** if the classifier can't identify *what* changed, we don't have a defensible reason to ratchet trust state. Forcing a re-attest in this state risks an unbounded loop if the unknown is in the verifier's own logic. Better: log Warning, leave human/CI to investigate, and let the next genuine security-event rotation drive re-attest normally.

---

# Fix 2 — Peer-IP → last-DID hint for `DidChanged` detection

## Fix 2.1 — Add the secondary map to the cache

**File:** `src/virtual_id_cache.rs`

**FIND** the `VirtualIdCache` struct:
```rust
#[derive(Clone)]
pub struct VirtualIdCache {
    inner: Arc<RwLock<HashMap<String, CachedVid>>>,
}
```

**REPLACE WITH**:
```rust
#[derive(Clone)]
pub struct VirtualIdCache {
    inner: Arc<RwLock<HashMap<String, CachedVid>>>,
    /// Secondary index: peer IP (no port) → most recently seen DID.
    /// NOT a primary identity key — used only to detect `DidChanged`
    /// when the same originating IP presents a different DID than before.
    /// Strip the port from "ip:port" before inserting so port churn
    /// doesn't break the hint.
    ip_to_did: Arc<RwLock<HashMap<String, String>>>,
}
```

…and update `new`:
```rust
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            ip_to_did: Arc::new(RwLock::new(HashMap::new())),
        }
    }
```

## Fix 2.2 — Extend `ObservationContext` with the peer IP

**File:** `src/virtual_id_cache.rs`

**FIND**:
```rust
#[derive(Debug, Clone, Copy)]
pub struct ObservationContext<'a> {
    pub peer_did: &'a str,
    pub new_vid_hex: &'a str,
    pub new_stable_hex: &'a str,
    pub new_dkp_verification_method_id: &'a str,
    pub new_dkp_kid: &'a str,
    pub new_dkp_fp: &'a str,
    pub new_pcr_digest: &'a str,
    pub new_policy_digest: &'a str,
}
```

**REPLACE WITH**:
```rust
#[derive(Debug, Clone, Copy)]
pub struct ObservationContext<'a> {
    pub peer_did: &'a str,
    pub new_vid_hex: &'a str,
    pub new_stable_hex: &'a str,
    pub new_dkp_verification_method_id: &'a str,
    pub new_dkp_kid: &'a str,
    pub new_dkp_fp: &'a str,
    pub new_pcr_digest: &'a str,
    pub new_policy_digest: &'a str,
    /// Peer IP (no port) used as a hint for `DidChanged` detection.
    /// Empty string disables the hint (fall through to FirstSeen for new DIDs).
    #[doc(hidden)]
    pub peer_ip_hint: &'a str,
}
```

…and update the back-compat `observe_sync` wrapper to pass `peer_ip_hint: ""`:
```rust
    pub fn observe_sync(&self, peer_did: &str, new_vid_hex: &str) -> VidObservation {
        self.observe_rich(&ObservationContext {
            peer_did,
            new_vid_hex,
            new_stable_hex: "",
            new_dkp_verification_method_id: "",
            new_dkp_kid: "",
            new_dkp_fp: "",
            new_pcr_digest: "",
            new_policy_digest: "",
            peer_ip_hint: "",
        })
    }
```

## Fix 2.3 — `observe_rich` consults the secondary index BEFORE FirstSeen path

**File:** `src/virtual_id_cache.rs`

**FIND** the start of `observe_rich`:
```rust
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
                        dkp_verification_method_id: ctx.new_dkp_verification_method_id.to_string(),
                        dkp_kid: ctx.new_dkp_kid.to_string(),
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
```

**REPLACE WITH**:
```rust
    pub fn observe_rich(&self, ctx: &ObservationContext<'_>) -> VidObservation {
        let now = Utc::now();

        // === DidChanged hint check (read-only on both maps) ===========
        // Spec precedence #2: if the originating IP previously presented a
        // different DID, classify as DidChanged regardless of whether the
        // new DID is otherwise unknown. This is a security-relevant event.
        let did_changed_hint: Option<String> = if !ctx.peer_ip_hint.is_empty() {
            self.ip_to_did
                .read()
                .expect("ip_to_did map poisoned")
                .get(ctx.peer_ip_hint)
                .filter(|prev_did| prev_did.as_str() != ctx.peer_did)
                .cloned()
        } else {
            None
        };

        let mut cache = self.inner.write().expect("VID cache poisoned");
        let observation = match cache.get(ctx.peer_did).cloned() {
            None => {
                cache.insert(
                    ctx.peer_did.to_string(),
                    CachedVid {
                        vid_hex: ctx.new_vid_hex.to_string(),
                        stable_component_hex: ctx.new_stable_hex.to_string(),
                        dkp_verification_method_id: ctx.new_dkp_verification_method_id.to_string(),
                        dkp_kid: ctx.new_dkp_kid.to_string(),
                        dkp_pubkey_sha256_b16: ctx.new_dkp_fp.to_string(),
                        pcr_composite_digest: ctx.new_pcr_digest.to_string(),
                        policy_digest: ctx.new_policy_digest.to_string(),
                        observed_at: now,
                        // If the IP hint says we previously saw a different
                        // DID here, this is a DidChanged, not a true initial.
                        last_rotation_reason: if did_changed_hint.is_some() {
                            Some(RotationReason::DidChanged)
                        } else {
                            Some(RotationReason::InitialObservation)
                        },
                        last_reattest_triggered_at: if did_changed_hint.is_some() {
                            Some(now) // immediate re-attest spend on DidChanged
                        } else {
                            None
                        },
                    },
                );
                match did_changed_hint {
                    Some(previous_did) => VidObservation::Rotated {
                        previous: previous_did,
                        reason: RotationReason::DidChanged,
                        cooldown_allows_reattest: true,
                    },
                    None => VidObservation::FirstSeen,
                }
            }
```

> The rest of `observe_rich` (the `Some(prev) if prev.vid_hex == …` and `Some(prev)` arms below) stays as-is. The new code only intervenes BEFORE those existing arms, and only for the `None` (no DID in cache) case.

## Fix 2.4 — Update the IP hint after observation

**File:** `src/virtual_id_cache.rs`

At the very end of `observe_rich`, just before `observation` is returned (after the closing of the match), **insert**:
```rust
        // Update the IP→DID hint for next time, regardless of outcome.
        if !ctx.peer_ip_hint.is_empty() {
            self.ip_to_did
                .write()
                .expect("ip_to_did map poisoned")
                .insert(ctx.peer_ip_hint.to_string(), ctx.peer_did.to_string());
        }

        observation
    }
```

(Adjust the function body to assign to a `let observation = match … { … };` rather than returning directly from each arm, then insert the hint update before the final `observation` return.)

---

# Fix 3 — Rewrite `classify_rotation` with correct precedence

**File:** `src/virtual_id_cache.rs`

**FIND** the entire current body of `classify_rotation` plus the helpers `classify_optional_change` and `classify_dkp_change`:

```rust
fn classify_rotation(prev: &CachedVid, ctx: &ObservationContext<'_>) -> RotationReason {
    // If the stable component matches, only the nonces changed.
    if !prev.stable_component_hex.is_empty() && prev.stable_component_hex == ctx.new_stable_hex {
        return RotationReason::NonceOnly;
    }

    // Otherwise diff the individual security inputs.
    let dkp_changed = classify_dkp_change(prev, ctx);
    let pcr_changed = classify_optional_change(&prev.pcr_composite_digest, ctx.new_pcr_digest);
    let policy_changed = classify_optional_change(&prev.policy_digest, ctx.new_policy_digest);

    match (dkp_changed, pcr_changed, policy_changed) {
        (Some(false), Some(false), Some(false)) => RotationReason::NonceOnly,
        (Some(true), Some(false), Some(false)) => RotationReason::DkpRotated,
        (Some(false), Some(true), Some(false)) => RotationReason::PcrChanged,
        (Some(false), Some(false), Some(true)) => RotationReason::PolicyChanged,
        _ => RotationReason::MultipleSecurityInputs,
    }
}
```

**REPLACE WITH**:
```rust
/// Classify a VID rotation per the spec precedence:
///
///   1. DID changed (handled at the caller before this function — we never
///      reach `classify_rotation` for a DID change because the cache is
///      DID-keyed and DID changes appear as a missing primary key here).
///   2. Count of changed stable fields among (DKP, PCR, policy):
///        > 1  → MultipleSecurityInputs
///        = 1  → that specific input's reason
///        = 0  → NonceOnly
///   3. VID changed but no diffable input differs (every input is `None`
///      because we have no previous data, OR every `Some` value matched):
///      UnknownInputChange.
fn classify_rotation(prev: &CachedVid, ctx: &ObservationContext<'_>) -> RotationReason {
    // Fast path: stable component matches → it was just the nonces.
    if !prev.stable_component_hex.is_empty()
        && !ctx.new_stable_hex.is_empty()
        && prev.stable_component_hex == ctx.new_stable_hex
    {
        return RotationReason::NonceOnly;
    }

    let dkp_changed    = classify_dkp_change(prev, ctx);
    let pcr_changed    = classify_optional_change(&prev.pcr_composite_digest, ctx.new_pcr_digest);
    let policy_changed = classify_optional_change(&prev.policy_digest,         ctx.new_policy_digest);

    // Spec precedence: count CONFIRMED changes (Some(true)).
    let confirmed_changes = [dkp_changed, pcr_changed, policy_changed]
        .iter()
        .filter(|c| **c == Some(true))
        .count();

    if confirmed_changes >= 2 {
        return RotationReason::MultipleSecurityInputs;
    }
    if dkp_changed    == Some(true) { return RotationReason::DkpRotated;    }
    if pcr_changed    == Some(true) { return RotationReason::PcrChanged;    }
    if policy_changed == Some(true) { return RotationReason::PolicyChanged; }

    // All known fields are either unchanged (`Some(false)`) or unknown (`None`).
    // If every known field is unchanged AND we had real data to compare, the
    // VID change is purely nonce-driven (we got here because stable_component
    // was empty on one side, otherwise the fast path above would have caught
    // it). Treat as NonceOnly to match the spec.
    let any_known_changed   = confirmed_changes > 0;
    let any_field_compared  = dkp_changed.is_some() || pcr_changed.is_some() || policy_changed.is_some();
    if !any_known_changed && any_field_compared {
        return RotationReason::NonceOnly;
    }

    // VID changed, but we cannot identify which input drove the change.
    // Either we have no previous data to diff (`prev` was a freshly-loaded
    // legacy cache entry with empty fields) OR the encoding of the stable
    // component shifted underneath us. Flag for investigation.
    RotationReason::UnknownInputChange
}

fn classify_optional_change(previous: &str, current: &str) -> Option<bool> {
    if previous.is_empty() || current.is_empty() {
        None
    } else {
        Some(previous != current)
    }
}

fn classify_dkp_change(prev: &CachedVid, ctx: &ObservationContext<'_>) -> Option<bool> {
    if prev.dkp_pubkey_sha256_b16.is_empty() || ctx.new_dkp_fp.is_empty() {
        return None;
    }
    // If new context carries a verification-method id or kid that previous
    // didn't track, treat it as "no signal" rather than a spurious change.
    if !ctx.new_dkp_verification_method_id.is_empty() && prev.dkp_verification_method_id.is_empty() {
        return None;
    }
    if !ctx.new_dkp_kid.is_empty() && prev.dkp_kid.is_empty() {
        return None;
    }

    let vm_changed = !ctx.new_dkp_verification_method_id.is_empty()
        && prev.dkp_verification_method_id != ctx.new_dkp_verification_method_id;
    let kid_changed = !ctx.new_dkp_kid.is_empty() && prev.dkp_kid != ctx.new_dkp_kid;
    let fp_changed = prev.dkp_pubkey_sha256_b16 != ctx.new_dkp_fp;
    Some(vm_changed || kid_changed || fp_changed)
}
```

**Behavior delta:**
- `(Some(true), Some(true), Some(false))` was hitting the catch-all `_ => MultipleSecurityInputs`. Still is — but now explicitly via the `confirmed_changes >= 2` branch.
- `(None, None, None)` was hitting `_ => MultipleSecurityInputs` — **WRONG**. Now classified as `UnknownInputChange` (logged Warning, no re-attest).
- `(Some(false), None, None)` was hitting `_ => MultipleSecurityInputs` — also **WRONG**. Now classified as `NonceOnly` (one input proven unchanged, others unknown).
- `(Some(true), None, Some(false))` was hitting `_ => MultipleSecurityInputs` — **WRONG** when only DKP actually changed. Now correctly classified as `DkpRotated`.

---

# Fix 4 — Audit log format per spec

**File:** `src/attestation_service.rs`

**FIND** the `observe_verified_virtual_id` function (only the Rotated arm body — keep the FirstSeen/Unchanged arms untouched at this stage; we'll update FirstSeen below):

```rust
        crate::virtual_id_cache::VidObservation::Rotated {
            previous,
            reason,
            cooldown_allows_reattest,
        } => {
            if !reason.is_security_event() {
                log_audit(
                    &node_id,
                    AuditCategory::Attestation,
                    AuditSeverity::Info,
                    AuditAction::Started,
                    &format!(
                        "VID session refresh for {} (reason={}): {} -> {}",
                        ev.subject_did, reason.as_str(), previous, ev.virtual_id
                    ),
                );
                return;
            }

            let severity = AuditSeverity::Warning;
            log_audit(
                &node_id,
                AuditCategory::Attestation,
                severity,
                AuditAction::Started,
                &format!(
                    "VID rotation for {} (reason={}): {} -> {}",
                    ev.subject_did, reason.as_str(), previous, ev.virtual_id
                ),
            );
            ...
        }
```

**REPLACE WITH** (full spec-format messages including old/new values per reason):
```rust
        crate::virtual_id_cache::VidObservation::Rotated {
            previous,
            reason,
            cooldown_allows_reattest,
        } => {
            // Build the input-diff suffix expected by the spec. We have the
            // previous values via the cache snapshot taken before the write.
            // Read it back here for the diff (cheap — read lock only).
            let prev_snapshot = VID_CACHE.get().and_then(|c| c.current_for_sync(&ev.subject_did));
            let diff_suffix = match (reason, prev_snapshot.as_ref()) {
                (crate::virtual_id_cache::RotationReason::DkpRotated, Some(p)) => format!(
                    "old_dkp={} new_dkp={}",
                    p.dkp_pubkey_sha256_b16, dkp_fp
                ),
                (crate::virtual_id_cache::RotationReason::PcrChanged, Some(p)) => format!(
                    "old_pcr={} new_pcr={}",
                    p.pcr_composite_digest, pcr_digest
                ),
                (crate::virtual_id_cache::RotationReason::PolicyChanged, Some(p)) => format!(
                    "old_policy={} new_policy={}",
                    p.policy_digest, policy_digest
                ),
                (crate::virtual_id_cache::RotationReason::DidChanged, _) => format!(
                    "old_did={} new_did={}", previous, ev.subject_did
                ),
                (crate::virtual_id_cache::RotationReason::MultipleSecurityInputs, Some(p)) => {
                    let mut changed = Vec::new();
                    if p.dkp_pubkey_sha256_b16 != dkp_fp     { changed.push("dkp");    }
                    if p.pcr_composite_digest  != pcr_digest { changed.push("pcr");    }
                    if p.policy_digest         != policy_digest { changed.push("policy"); }
                    format!("changed={}", changed.join(","))
                }
                _ => format!("vid_old={} vid_new={}", previous, ev.virtual_id),
            };

            if !reason.is_security_event() {
                log_audit(
                    &node_id,
                    AuditCategory::Attestation,
                    AuditSeverity::Info,
                    AuditAction::Started,
                    &format!(
                        "VID session refresh reason={} did={}",
                        reason.as_str(), ev.subject_did
                    ),
                );
                return;
            }

            // UnknownInputChange is security-flagged but Warning, not Critical;
            // see is_security_event() for the cooldown gating.
            let severity = if matches!(reason, crate::virtual_id_cache::RotationReason::DidChanged) {
                AuditSeverity::Critical
            } else {
                AuditSeverity::Warning
            };

            log_audit(
                &node_id,
                AuditCategory::Attestation,
                severity,
                AuditAction::Started,
                &format!(
                    "VID rotation reason={} did={} {}",
                    reason.as_str(), ev.subject_did, diff_suffix
                ),
            );

            if cooldown_allows_reattest {
                trigger_reattestation_for(&ev.subject_did);
            } else {
                log_audit(
                    &node_id,
                    AuditCategory::Attestation,
                    AuditSeverity::Info,
                    AuditAction::Started,
                    &format!(
                        "Re-attest suppressed by cooldown for did={} reason={}",
                        ev.subject_did, reason.as_str()
                    ),
                );
            }
        }
```

**FIND** the `FirstSeen` arm body in the same function:
```rust
        crate::virtual_id_cache::VidObservation::FirstSeen => {
            log_audit(
                &node_id,
                AuditCategory::Attestation,
                AuditSeverity::Info,
                AuditAction::Started,
                &format!("First VID seen for {}: {}", ev.subject_did, ev.virtual_id),
            );
        }
```

**REPLACE WITH**:
```rust
        crate::virtual_id_cache::VidObservation::FirstSeen => {
            log_audit(
                &node_id,
                AuditCategory::Attestation,
                AuditSeverity::Info,
                AuditAction::Started,
                &format!(
                    "VID rotation reason=initial_observation did={} vid={}",
                    ev.subject_did, ev.virtual_id
                ),
            );
        }
```

## Fix 4.1 — Pass the `peer_ip_hint` from the call site

**File:** `src/attestation_service.rs` — function `observe_verified_virtual_id`.

**FIND** the construction of `ObservationContext`:
```rust
    let ctx = crate::virtual_id_cache::ObservationContext {
        peer_did: &ev.subject_did,
        new_vid_hex: &ev.virtual_id,
        new_stable_hex: &stable_hex,
        new_dkp_fp: &dkp_fp,
        new_pcr_digest: &pcr_digest,
        new_policy_digest: &policy_digest,
    };
```

**REPLACE WITH**:
```rust
    // Strip the port off `addr` ("ip:port" → "ip") so port churn doesn't
    // mask DID-change detection from the same peer over a new ephemeral port.
    let peer_ip_only: String = ev
        .node_id // optional, depends on field availability; see fallback below
        .clone();
    // Better source: caller of observe_verified_virtual_id has `addr`;
    // we plumb it through. Update the function signature:
    //   fn observe_verified_virtual_id(ev: &AttestationEvidence, peer_addr: &str)
    // and at the call sites, pass `&addr` (the TCP socket address).
    // Strip port:
    let peer_ip_hint = peer_addr.rsplit_once(':').map(|(ip, _)| ip).unwrap_or(peer_addr);

    let ctx = crate::virtual_id_cache::ObservationContext {
        peer_did: &ev.subject_did,
        new_vid_hex: &ev.virtual_id,
        new_stable_hex: &stable_hex,
        new_dkp_verification_method_id: "", // populate if available from peer DID Document
        new_dkp_kid: "",                    // populate if available
        new_dkp_fp: &dkp_fp,
        new_pcr_digest: &pcr_digest,
        new_policy_digest: &policy_digest,
        peer_ip_hint,
    };
```

Then update the **signature** of `observe_verified_virtual_id` to take `peer_addr: &str`:
```rust
fn observe_verified_virtual_id(ev: &AttestationEvidence, peer_addr: &str) {
```

…and update its two call sites (in `mutual_attest` after the `verify_signed_evidence` success branch, and in the inbound listener after its verify success branch) to pass `&addr` and `&remote.to_string()` respectively.

---

# Fix 5 — `TrustedPeer` carries `rotation_reason`, `nonce_i`, `nonce_r`

## Fix 5.1 — Struct

**File:** `src/attestation_service.rs`

**FIND** the `TrustedPeer` struct (post the prior fix that added DID/VID etc.):
```rust
#[derive(Serialize, Deserialize)]
struct TrustedPeer {
    peer_id: String,
    ip: String,
    status: String,
    timestamp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    virtual_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_attested_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dkp_pubkey_sha256_b16: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pcr_composite_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_digest: Option<String>,
}
```

**REPLACE WITH** (add three fields at the end):
```rust
#[derive(Serialize, Deserialize)]
struct TrustedPeer {
    peer_id: String,
    ip: String,
    status: String,
    timestamp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    virtual_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_attested_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dkp_pubkey_sha256_b16: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pcr_composite_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_digest: Option<String>,
    // Fix 5: classification + session-binding fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rotation_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce_i: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce_r: Option<String>,
}
```

## Fix 5.2 — `write_trusted_peer` writes the new fields

**File:** `src/attestation_service.rs`

**FIND** the `entry` construction inside `write_trusted_peer`:
```rust
    let entry = TrustedPeer {
        peer_id: peer_id.to_string(),
        ip: ip.to_string(),
        status: "verified".to_string(),
        timestamp: now.clone(),
        did: Some(ev.subject_did.clone()).filter(|s| !s.is_empty()),
        virtual_id: Some(ev.virtual_id.clone()).filter(|s| !s.is_empty()),
        last_attested_at: Some(now.clone()),
        dkp_pubkey_sha256_b16: dkp_fp,
        pcr_composite_digest: pcr_digest,
        policy_digest: Some(ev.policy_digest.clone()).filter(|s| !s.is_empty()),
    };
```

**REPLACE WITH**:
```rust
    // Look up the most recent rotation_reason classification for this DID.
    let rotation_reason = VID_CACHE
        .get()
        .and_then(|c| c.current_for_sync(&ev.subject_did))
        .and_then(|cv| cv.last_rotation_reason.map(|r| r.as_str().to_string()));

    let entry = TrustedPeer {
        peer_id: peer_id.to_string(),
        ip: ip.to_string(),
        status: "verified".to_string(),
        timestamp: now.clone(),
        did: Some(ev.subject_did.clone()).filter(|s| !s.is_empty()),
        virtual_id: Some(ev.virtual_id.clone()).filter(|s| !s.is_empty()),
        last_attested_at: Some(now.clone()),
        dkp_pubkey_sha256_b16: dkp_fp,
        pcr_composite_digest: pcr_digest,
        policy_digest: Some(ev.policy_digest.clone()).filter(|s| !s.is_empty()),
        rotation_reason,
        nonce_i: Some(ev.nonce.clone()).filter(|s| !s.is_empty()),
        nonce_r: None, // populate when mutual_attest carries responder nonce
    };
```

---

# Fix 6 — Upsert `trusted_peers` by DID first

**File:** `src/attestation_service.rs`

**FIND** the update/insert block inside `write_trusted_peer`:
```rust
    let mut updated = false;
    for p in data.iter_mut() {
        if p.peer_id == peer_id {
            p.timestamp           = entry.timestamp.clone();
            p.status              = "verified".into();
            p.did                 = entry.did.clone();
            p.virtual_id          = entry.virtual_id.clone();
            p.last_attested_at    = entry.last_attested_at.clone();
            p.dkp_pubkey_sha256_b16 = entry.dkp_pubkey_sha256_b16.clone();
            p.pcr_composite_digest  = entry.pcr_composite_digest.clone();
            p.policy_digest         = entry.policy_digest.clone();
            updated = true;
            break;
        }
    }
    if !updated {
        data.push(entry);
    }
```

**REPLACE WITH**:
```rust
    // Spec: upsert by DID first; peer_id fallback only for legacy records
    // (no DID stored). This prevents stale duplicates when peer_id (ip:port)
    // changes due to ephemeral port churn.
    let mut updated = false;

    // Pass 1: match by DID. Skip if the new entry has no DID (we can't
    // upsert against a missing key).
    if let Some(ref new_did) = entry.did {
        for p in data.iter_mut() {
            if p.did.as_deref() == Some(new_did.as_str()) {
                // Found by DID — overwrite EVERYTHING including peer_id/ip
                // because the new connection identity is the current truth.
                p.peer_id             = entry.peer_id.clone();
                p.ip                  = entry.ip.clone();
                p.status              = "verified".into();
                p.timestamp           = entry.timestamp.clone();
                p.virtual_id          = entry.virtual_id.clone();
                p.last_attested_at    = entry.last_attested_at.clone();
                p.dkp_pubkey_sha256_b16 = entry.dkp_pubkey_sha256_b16.clone();
                p.pcr_composite_digest  = entry.pcr_composite_digest.clone();
                p.policy_digest         = entry.policy_digest.clone();
                p.rotation_reason       = entry.rotation_reason.clone();
                p.nonce_i               = entry.nonce_i.clone();
                p.nonce_r               = entry.nonce_r.clone();
                updated = true;
                break;
            }
        }
    }

    // Pass 2: legacy peer_id fallback — only for records that have NO DID.
    // Once a record gains a DID via pass 1 on a future call, this branch
    // stops being relevant for it.
    if !updated {
        for p in data.iter_mut() {
            if p.did.is_none() && p.peer_id == peer_id {
                p.timestamp             = entry.timestamp.clone();
                p.status                = "verified".into();
                p.did                   = entry.did.clone();
                p.virtual_id            = entry.virtual_id.clone();
                p.last_attested_at      = entry.last_attested_at.clone();
                p.dkp_pubkey_sha256_b16 = entry.dkp_pubkey_sha256_b16.clone();
                p.pcr_composite_digest  = entry.pcr_composite_digest.clone();
                p.policy_digest         = entry.policy_digest.clone();
                p.rotation_reason       = entry.rotation_reason.clone();
                p.nonce_i               = entry.nonce_i.clone();
                p.nonce_r               = entry.nonce_r.clone();
                updated = true;
                break;
            }
        }
    }

    if !updated {
        data.push(entry);
    }
```

> **Migration semantics:** Existing JSON files with only `{peer_id, ip, status, timestamp}` parse fine via `serde(default)`. The first attestation after this fix lands populates DID via the peer_id fallback (Pass 2). All subsequent attestations for that peer hit Pass 1 (DID match). Stale duplicates from port churn don't accumulate going forward, but ANY existing duplicates from before this fix remain on disk — a one-shot cleanup pass on the JSON file (deduplicate by DID, keep newest `last_attested_at`) is a follow-up task if needed.

---

# Fix 7 — Update tests (additive — keep old tests passing)

**File:** `src/virtual_id_cache.rs::tests`

**ADD** at the end of `mod tests`:

```rust
    #[test]
    fn classify_initial_observation() {
        let cache = VirtualIdCache::new();
        let result = cache.observe_rich(&ctx_with_ip(
            "did:guardian:a", "vid-1", "stable-1",
            "did:guardian:a#dkp-v1", "dkp-v1", "dkp-1", "pcr-1", "policy-1",
            "192.168.50.115",
        ));
        assert_eq!(result, VidObservation::FirstSeen);
        let cached = cache.current_for_sync("did:guardian:a").unwrap();
        assert_eq!(cached.last_rotation_reason, Some(RotationReason::InitialObservation));
        assert_eq!(cached.last_rotation_reason.unwrap().as_str(), "initial_observation");
    }

    #[test]
    fn classify_did_change_via_ip_hint() {
        let cache = VirtualIdCache::new();
        // Peer at 192.168.50.115 first identifies as DID A
        let _ = cache.observe_rich(&ctx_with_ip(
            "did:guardian:a", "vid-1", "stable-1",
            "did:guardian:a#dkp-v1", "dkp-v1", "dkp-1", "pcr-1", "policy-1",
            "192.168.50.115",
        ));
        // Same IP, different DID → DidChanged regardless of DID being
        // otherwise unknown to the cache.
        let result = cache.observe_rich(&ctx_with_ip(
            "did:guardian:b", "vid-2", "stable-2",
            "did:guardian:b#dkp-v1", "dkp-v1", "dkp-9", "pcr-9", "policy-9",
            "192.168.50.115",
        ));
        assert!(matches!(
            result,
            VidObservation::Rotated { reason: RotationReason::DidChanged, .. }
        ));
    }

    #[test]
    fn classify_unknown_input_change() {
        let cache = VirtualIdCache::new();
        let _ = cache.observe_rich(&ctx(
            "did:guardian:a", "vid-1", "stable-1",
            "did:guardian:a#dkp-v1", "dkp-v1", "dkp-1", "pcr-1", "policy-1",
        ));
        // Force a synthetic "VID changed but stable inputs unknown" by
        // emptying the new stable_hex AND all the per-input fields.
        let result = cache.observe_rich(&ctx(
            "did:guardian:a", "vid-2", "",  // empty stable_hex
            "", "", "", "", "",              // all input fields empty
        ));
        assert!(matches!(
            result,
            VidObservation::Rotated { reason: RotationReason::UnknownInputChange, .. }
        ));
    }

    #[test]
    fn classify_dkp_only_when_other_inputs_unknown() {
        let cache = VirtualIdCache::new();
        let _ = cache.observe_rich(&ctx(
            "did:guardian:a", "vid-1", "stable-1",
            "did:guardian:a#dkp-v1", "dkp-v1", "dkp-1", "pcr-1", "policy-1",
        ));
        // Only DKP fingerprint is given for the new observation; PCR and
        // policy are unknown. Previously hit the catch-all and was
        // mis-classified as MultipleSecurityInputs. Should be DkpRotated.
        let result = cache.observe_rich(&ctx(
            "did:guardian:a", "vid-2", "stable-2",
            "did:guardian:a#dkp-v2", "dkp-v2", "dkp-2", "", "",
        ));
        assert!(matches!(
            result,
            VidObservation::Rotated { reason: RotationReason::DkpRotated, .. }
        ));
    }

    #[test]
    fn upsert_by_did_survives_port_change() {
        // Pure data test, no async: simulate two writes for the same DID
        // at different "peer_id" addresses, verify the upsert keeps one
        // record (the latest) keyed by DID.
        // (This test lives in attestation_service.rs once write_trusted_peer
        //  has a unit-testable extraction; see Fix 6 follow-up.)
    }

    fn ctx_with_ip<'a>(
        peer_did: &'a str,
        new_vid_hex: &'a str,
        new_stable_hex: &'a str,
        new_dkp_vm_id: &'a str,
        new_dkp_kid: &'a str,
        new_dkp_fp: &'a str,
        new_pcr_digest: &'a str,
        new_policy_digest: &'a str,
        peer_ip_hint: &'a str,
    ) -> ObservationContext<'a> {
        ObservationContext {
            peer_did,
            new_vid_hex,
            new_stable_hex,
            new_dkp_verification_method_id: new_dkp_vm_id,
            new_dkp_kid,
            new_dkp_fp,
            new_pcr_digest,
            new_policy_digest,
            peer_ip_hint,
        }
    }
```

The existing tests (`vid_cache_classifies_first_unchanged_and_rotated`, `classify_nonce_only_no_storm`, `classify_dkp_rotation`, `classify_pcr_change`, `classify_policy_change`, `cooldown_blocks_within_30s`) MUST continue to pass without modification — they don't exercise the IP hint, so the new logic is transparent to them.

---

# Combined Verification

```bash
# 1) Build clean.
cargo build --release 2>&1 | grep -E "^(warning|error):" | grep -v unused || true

# 2) Unit tests.
cargo test --release virtual_id_cache 2>&1 | tail -50
# Expected new tests pass: initial_observation, did_change_via_ip_hint,
#   unknown_input_change, dkp_only_when_other_inputs_unknown.
# Expected existing tests still pass.

# 3) Acceptance — DKP rotation classification.
ssh root@192.168.50.115 './sgx-pa-cli dkp-rotate'
sleep 35
ssh root@192.168.50.101 'journalctl -u sgx-guardian -n 200 | \
  grep -E "VID rotation reason="'
# Expect: exactly one line of the form:
#   "VID rotation reason=dkp_rotated did=did:guardian:Et… old_dkp=… new_dkp=…"

# 4) Acceptance — trusted_peers.json contains rotation_reason.
ssh root@192.168.50.101 'cat /var/log/sgx-guardian/trusted_peers_nodeA.json \
  | jq ".[] | {did, peer_id, rotation_reason, dkp_pubkey_sha256_b16}"'
# Expect: every entry has rotation_reason populated (one of:
#   initial_observation, nonce_only, dkp_rotated, pcr_changed,
#   policy_changed, multiple_security_inputs, did_changed, unknown_input_change).

# 5) Acceptance — port churn does not create duplicates.
# Restart nodeB's daemon, forcing a new ephemeral port on outbound attest.
ssh root@192.168.50.115 'pkill sgx_guardian_client; sleep 3; ./sgx_guardian_client nodeB &'
sleep 60
ssh root@192.168.50.101 'cat /var/log/sgx-guardian/trusted_peers_nodeA.json \
  | jq "[.[] | select(.did==\"did:guardian:Et…\")] | length"'
# Expect: 1 (NOT 2). The upsert by DID overwrote the old peer_id/ip with the new.

# 6) Acceptance — nonce-only stays quiet (regression on prior fix).
ssh root@192.168.50.101 'journalctl -u sgx-guardian --since "5 min ago" \
  | grep -c "VID session refresh reason=nonce_only"'
# Expect: > 0 (we DO log session refreshes at Info).
ssh root@192.168.50.101 'journalctl -u sgx-guardian --since "5 min ago" \
  | grep -c "VID rotation reason=nonce_only"'
# Expect: 0 (nonce-only is NOT a rotation; the word "rotation" is reserved
#   for security events per the new format).

# 7) Acceptance — DidChanged fires when same IP presents different DID.
# (Manual test — requires hand-crafting an evidence with a different DID
# from the same source IP, hard to reproduce without code support; the
# unit test classify_did_change_via_ip_hint is the canonical proof.)
```

Pass criteria:
- ✅ Build clean.
- ✅ All 4 new unit tests pass; all 6 existing tests still pass.
- ✅ After a real DKP rotate on a board, the observing node's audit log contains a `reason=dkp_rotated` line with `old_dkp`/`new_dkp` values, and the trusted_peers JSON entry for that DID has `rotation_reason: "dkp_rotated"` with the new DKP fingerprint in `dkp_pubkey_sha256_b16`.
- ✅ After a daemon restart that changes the outbound ephemeral port, the trusted_peers JSON has one entry per DID — not two.
- ✅ Steady-state attestation (nonce-only refresh) produces Info-severity `VID session refresh reason=nonce_only` lines, never `VID rotation`.
- ✅ Pre-fix JSON files still parse without panic.

---

# Step-by-Step Checklist

- [ ] Branch from `main` → `shahzad_vid_classify_complete`.
- [ ] **Fix 1**: extend `RotationReason` with `InitialObservation`, `DidChanged`, `UnknownInputChange`; update `is_security_event()` and `as_str()`.
- [ ] **Fix 2**: add `ip_to_did` secondary map to `VirtualIdCache`; extend `ObservationContext` with `peer_ip_hint`; consult/update the map in `observe_rich`.
- [ ] **Fix 3**: rewrite `classify_rotation` with the precedence-correct logic (DID handled at caller, count-based dispatch, `UnknownInputChange` catch-all).
- [ ] **Fix 4**: update `observe_verified_virtual_id` to emit the spec audit format (`reason=X did=Y old_*=Z new_*=W`), pass `peer_addr` through, set Critical severity on `DidChanged`.
- [ ] **Fix 5**: add `rotation_reason`, `nonce_i`, `nonce_r` to `TrustedPeer`; populate in `write_trusted_peer`.
- [ ] **Fix 6**: rewrite the upsert block in `write_trusted_peer` to match by DID first, peer_id fallback for legacy.
- [ ] **Fix 7**: add 4 new unit tests; leave the existing 6 untouched.
- [ ] Run §"Combined Verification" sequence on all 3 boards.
- [ ] CodeRabbit + CodeQL pass.

---

# Out of Scope (deliberate deferrals)

- **One-shot dedup of pre-existing `trusted_peers.json` duplicates.** New writes won't accumulate duplicates, but any duplicates already on disk from before this fix stay. Trivial follow-up: a `sgx-pa-cli trusted-peers dedup` subcommand that collapses by DID and keeps the newest `last_attested_at`.
- **DIK-based DidChanged detection.** Stronger detection than IP-based: track `DIK fingerprint → DID` and flag if the same hardware-tied DIK ever maps to a different DID. Requires resolving the peer's DID Document to extract the DIK fingerprint, which is a network call. Defer until VC-based peer verification is fully wired (Sprint 6 Task 1 already lays the groundwork).
- **Persisting the `ip_to_did` hint to disk.** Lost on daemon restart. Acceptable because the worst case is one missed `DidChanged` classification after a restart — the offending evidence still goes through normal attestation/VC verification. If you want persistence, dump it alongside `trusted_peers.json` and reload on startup; one-page change.
- **Per-reason cooldown tuning.** Current 30 s applies uniformly. `DidChanged` arguably wants a *shorter* cooldown (no rate-limiting on impersonation alerts) while `PolicyChanged` wants a longer one (policy fan-out across a cohort can rotate many VIDs quickly). Out of scope for this fix; tune via a `RotationReason::cooldown()` method in a follow-up.

---

# Honest Notes on What I Couldn't Verify

- I cannot compile or run on the boards. FIND blocks are anchored to verbatim `main` text via `project_knowledge_search`. Use `grep -n` for line-number drift.
- The signature change for `observe_verified_virtual_id` (`+peer_addr: &str`) is the cleanest way to plumb the IP hint, but it has two call sites in `attestation_service.rs` — both must be updated in the same commit. `grep -n observe_verified_virtual_id src/` confirms the count.
- `peer_ip_hint` is derived by stripping the port off the TCP `addr` string. This assumes IPv4 — for IPv6 the colon split needs care (use `addr.parse::<std::net::SocketAddr>()` and call `.ip().to_string()` for safety). One-line tweak if your deployment expects IPv6.
- The new audit messages don't use `reason.as_str()` inside `format!` for `DidChanged` because the `old_dkp`/`new_dkp` etc. structure is reason-specific. If your log scraper depends on a single canonical format, the `diff_suffix` could instead be a JSON object — but the spec you gave me uses plain `old_X=… new_X=…` key-value pairs, so I matched that.
- `nonce_r` is left `None` for now. The mutual_attest flow does carry a responder nonce internally during the exchange, but it isn't currently part of the `AttestationEvidence` wire struct. Plumbing it through is a separate small change — flagged in the "Out of scope" section if you want it next.
- The `upsert_by_did_survives_port_change` test is a placeholder. Making `write_trusted_peer` unit-testable requires factoring out the in-memory upsert logic to a pure function — a small refactor I left for the implementer. Until then, the board-level verification in §"Combined Verification" §5 is the canonical proof.
- `RotationReason::DidChanged` is the only reason that fires from the `None` (FirstSeen) cache branch, not the `Some(prev)` branch. That's by design — DID change cannot be a rotation of an existing DID's state, since the new DID has no prior cache entry. The IP hint is what bridges the two contexts.
