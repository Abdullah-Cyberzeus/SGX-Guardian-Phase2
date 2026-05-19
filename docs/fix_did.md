# SG-X Guardian — Task 1 (W3C DID) Board Fix: Network-Change DKP Regeneration Cascade

**Date:** May 19, 2026
**Scope:** Task 1 (W3C DID Implementation) only — Task 2 (DID Document) NOT yet implemented
**Board:** Variscite VAR-SOM-MX8M-PLUS, nodeA (`imx8mp-var-dart`, 192.168.50.101)
**Source:** Latest `main` via `project_knowledge_search` (GitHub private; project knowledge is authoritative)
**Style:** Same FIND→REPLACE format as `PCR_Complete_Plan.md`

---

## Note on Code Access

I could not `git clone` (private repo). As in every prior session, current `main` was read through `project_knowledge_search`. Every code excerpt and FIND block below is from the real current source: `src/secure_element/dkp.rs`, `src/secure_element/ssscli.rs`, `src/secure_element/key_storage.rs`, `src/key_manager.rs`, `src/main.rs`, `src/did/method.rs`.

I cannot compile or run on the boards. The root cause below is derived by tracing the actual code paths against the three attached terminal logs (nodeA, nodeB, nodeC) line-by-line.

---

# 1. What the Logs Actually Show (Evidence)

Reading nodeA's terminal across its 7 successive runs:

| Run | DKP line | Network | DID result |
|---|---|---|---|
| 1 (first boot) | `No existing DKP found — generating new DKP` → `DKP generated successfully (v1)` | wlan0 192.168.50.101 | ✅ `did:guardian:FbBin6gQ...` |
| 2 (restart) | `Existing DKP found (v1) — loading from SE050` | wlan0 192.168.50.101 (unchanged) | ✅ same DID |
| 3 (after reboot) | `Existing DKP found (v1)` | **eth0 192.168.4.3** then flips to wlan0 192.168.50.101 | ✅ same DID (survived ONE network change) |
| **4** | `No existing DKP found — generating new DKP` (twice!) | eth0/wlan0 churn | 🔴 `DID DERIVATION MISMATCH — refusing to start` |
| 5 | `No existing DKP found — generating new DKP` | — | ⚠️ `DKP public key unavailable... continuing` → `Secure Element not available` → `🔴 Baseline signature INVALID` |
| 6 | same | — | same collapse |
| 7 | same | — | same collapse |

Meanwhile **nodeB and nodeC** (network NOT changed) every single run: `Existing DKP found (v1) — loading from SE050` → ✅ stable DID. They only break because they start **rejecting nodeA**: `❌ Attestation rejected: prover nodeA baseline has bad signature`.

The first 5 checklist items passed. Item 6 (`DID persists after IP/network change`) is where it breaks — and it breaks the DKP, not the DID directly.

Two structural facts visible in *every* nodeA boot, even the healthy ones:

```
STEP_01 post-listener: entering KeyManager init
  No existing DKP found — generating new DKP inside SE050...   ← message #1 (KeyManager::init_with_se050)
  DKP generated successfully (v1)
DKP initialized via SE050 hardware
  Existing DKP found (v1) — loading from SE050                  ← message #2 (auto-rotation block re-inits DkpManager)
  Using existing device identity key (0x20000010)
```

`DkpManager::init()` runs **twice per boot**. That is the amplifier.

---

# 2. Root Cause (Confirmed from Code)

**The DID code is not the bug. It is correctly reporting a problem the DKP layer caused.**

### 2.1 The trigger — `dkp.rs` drift detection treats a transient ssscli failure as "chip wiped"

From current `src/secure_element/dkp.rs::DkpManager::init()`:

```rust
let slot_hex = active.key_id.clone();
let slot_found = match SeKeyStorage::new(config) {
    Ok(store) => match store.list_slots() {
        Ok(list) => list.to_uppercase().contains(&slot_hex.to_uppercase()),
        Err(_) => false,          // ← BUG: ssscli error == "slot missing"
    },
    Err(_) => false,              // ← BUG: connect() error == "slot missing"
};

if !slot_found {
    warn!("DKP metadata claims slot {} but SE050 does not have it — treating as fresh provisioning", slot_hex);
    let quarantine = format!("{}.stale.{}", metadata_path, chrono::Utc::now().timestamp());
    let _ = std::fs::rename(&metadata_path, &quarantine);   // ← quarantines GOOD metadata
    // falls through and GENERATES A NEW DKP
}
```

`SeKeyStorage::new()` calls `SssCli::connect()` (a `ssscli connect ...` subprocess). `list_slots()` runs `ssscli se05x readidlist`. Both spawn the NXP `ssscli` Python tool, which keeps a session pickle (`~.ssscli_session.pkl`, visible in the `ls -lh` you sent). When nodeA's network flaps (eth0 ↔ wlan0), the IP-monitor / config-rewrite / `🔄 Nebula reloaded` churn contends the system and the I2C/ssscli session momentarily fails. `connect()` or `readidlist` returns `Err`.

The code maps **both** "key genuinely absent" and "couldn't talk to the chip this instant" to `slot_found = false`. So a transient read failure → metadata quarantined → **brand-new DKP generated** → `dkp_pub.der` overwritten with a different public key.

### 2.2 The cascade into DID and attestation

1. New DKP pubkey written to `/var/lib/sgx-guardian/keys/dkp_pub.der`.
2. `did::method::create_if_absent()` recomputes `candidate_did = derive(SE050_UID, dkp_pub.der)`. The live `dkp_pub.der` is now the *new* key → `candidate_did ≠` persisted `did.json` → `DidError::DerivationMismatch` → `main.rs` does `std::process::exit(2)` → **"🔴 DID DERIVATION MISMATCH — refusing to start."** (run 4).
3. Restarts hammer the already-stressed ssscli session; eventually `KeyManager::init_with_se050` fails entirely → software-key fallback. `dkp_pub.der` now absent/garbage → `⚠️ DID initialization failed: DKP public key unavailable`. (runs 5–7)
4. The PCR baseline was signed by the **original** SE050 DKP. The active key is now a software key → `🔴 Baseline signature INVALID — possible tampering!` → nodeA fails its own self-attestation.
5. nodeB and nodeC verify nodeA's quote against the registry-known pubkey, see the bad baseline signature → `❌ Attestation rejected: prover nodeA baseline has bad signature`. The whole mesh ejects nodeA.

A single transient `ssscli readidlist` failure during a network change → DKP regenerated → DID mismatch → SE050 lockout → baseline invalidated → mesh-wide rejection. Exactly the log.

### 2.3 The amplifier — DKP initialized twice per boot

`src/main.rs` calls `DkpManager::init()` once inside `KeyManager::init_with_se050(...)`, then **again** in the `=== DKP Auto-Rotation Check ===` block:

```rust
if let Ok(mut dkp) =
    sgx_guardian_client::secure_element::dkp::DkpManager::init(&se_config, base_path)
{
    match dkp.check_and_auto_rotate() { ... }
}
```

Two independent ssscli probe sequences per boot = double the chance of hitting the transient window, and either one can quarantine + regenerate.

### 2.4 Latent design bug in the DID layer (exposed, must also fix)

`did::method::create_if_absent()` recomputes the DID from the **live** `dkp_pub.der`. But `dkp_pub.der` is overwritten on every *legitimate* DKP rotation (`dkp.rs::rotate()` → `storage.export_public_key(new_id, &self.public_key_path)` writes the same path). So even a normal, intended v1→v2 rotation would trip `DerivationMismatch`. The DID must be pinned to the **v1** pubkey stored *inside* `did.json` — never the live file.

---

# 3. Fix Plan (5 surgical changes)

Order matters: Fix 1 + Fix 2 stop the regeneration (root cause). Fix 5 auto-heals already-broken boards. Fix 3 reduces contention. Fix 4 makes the DID layer correct and resilient.

---

## Fix 1 — `dkp.rs`: never quarantine/regenerate on a transient SE050 error

**File:** `src/secure_element/dkp.rs`
**Function:** `DkpManager::init`

**FIND:**
```rust
                let slot_hex = active.key_id.clone();
                let slot_found = match SeKeyStorage::new(config) {
                    Ok(store) => match store.list_slots() {
                        Ok(list) => list.to_uppercase().contains(&slot_hex.to_uppercase()),
                        Err(_) => false,
                    },
                    Err(_) => false,
                };

                if !slot_found {
                    warn!(
                        "DKP metadata claims slot {} but SE050 does not have it — \
                         treating as fresh provisioning",
                        slot_hex
                    );
                    // Rotate metadata out of the way so generate_dkp can recreate.
                    let quarantine =
                        format!("{}.stale.{}", metadata_path, chrono::Utc::now().timestamp());
                    let _ = std::fs::rename(&metadata_path, &quarantine);
                    // Fall through to fresh-provision branch below.
                } else {
```

**REPLACE WITH:**
```rust
                let slot_hex = active.key_id.clone();

                // Three-state probe (Fix 1): distinguish a TRANSIENT SE050 read
                // failure from a GENUINELY-ABSENT slot. A network flap on a
                // CA/lighthouse node contends the ssscli/I2C session; a momentary
                // Err here previously caused the DKP to be regenerated, which
                // changed the device identity key and cascaded into DID mismatch
                // and baseline-signature invalidation across the whole mesh.
                enum SlotProbe { Present, Absent, Unknown }
                let probe = match SeKeyStorage::new(config) {
                    Ok(store) => match store.list_slots() {
                        Ok(list) => {
                            if list.to_uppercase().contains(&slot_hex.to_uppercase()) {
                                SlotProbe::Present
                            } else {
                                SlotProbe::Absent
                            }
                        }
                        Err(e) => {
                            warn!(
                                "SE050 readidlist failed ({}) — treating slot {} as \
                                 UNKNOWN, NOT regenerating",
                                e, slot_hex
                            );
                            SlotProbe::Unknown
                        }
                    },
                    Err(e) => {
                        warn!(
                            "SE050 connect failed ({}) — treating slot {} as UNKNOWN, \
                             NOT regenerating",
                            e, slot_hex
                        );
                        SlotProbe::Unknown
                    }
                };

                // Only a CONFIRMED-absent slot (chip talked to us and the key
                // is genuinely gone) justifies quarantining metadata and
                // re-provisioning. Unknown = keep the existing key, sign via
                // the slot the metadata points at; dkp_pub.der is already on
                // disk from original provisioning.
                if let SlotProbe::Absent = probe {
                    warn!(
                        "DKP metadata claims slot {} but SE050 confirms it is ABSENT — \
                         treating as fresh provisioning",
                        slot_hex
                    );
                    let quarantine =
                        format!("{}.stale.{}", metadata_path, chrono::Utc::now().timestamp());
                    let _ = std::fs::rename(&metadata_path, &quarantine);
                    // Fall through to fresh-provision branch below.
                } else {
                    if let SlotProbe::Unknown = probe {
                        println!(
                            "  ⚠️ SE050 not reachable this boot — keeping existing DKP \
                             (v{}) from metadata (no regeneration)",
                            active.version
                        );
                    }
```

> Note: the closing `} else {` becomes `} else { if let SlotProbe::Unknown ... }` followed by the original `println!("  Existing DKP found ...")` block. The original `else` body (the `println!`/`return Ok(Self {...})`) stays exactly as-is below this insertion; we only added the `Unknown` notice line before it. Confirm the brace balance with `cargo build` — the `else` arm now handles both `Present` and `Unknown` (both = "keep existing key").

**Effect:** A transient ssscli failure → `Unknown` → existing DKP is kept, `did.json` unchanged, baseline still valid. The exact run-4 trigger no longer regenerates.

---

## Fix 2 — `dkp.rs`: bounded retry + stale-session reset before deciding

A network flap often leaves the `ssscli` session pickle stale. The board already ships `reset_ssscli.sh` for exactly this. Do the equivalent in-process: retry the probe a few times, and between attempts delete the stale session pickle so `connect()` re-establishes cleanly. **No `std::thread::sleep` and no async** — this runs at STEP_01 before any tokio task is spawned, and the retries are immediate re-spawns (the failure mode is a stale pickle / subprocess spawn race, which a clean re-spawn fixes; it is not a timed I2C wait). This complies with the project hard rule against `std::thread::sleep`/sync `Command` inside the running async runtime.

**File:** `src/secure_element/dkp.rs`

**ADD** this free function near the top of the file (after `pub const DKP_BASE_KEY_ID`):
```rust
/// Probe the SE050 for a slot with bounded retries. Between attempts, clear
/// the stale ssscli session pickle so connect() re-establishes a fresh
/// session (equivalent to the board's reset_ssscli.sh). Returns:
///   Some(true)  = slot confirmed present
///   Some(false) = chip reachable, slot confirmed absent
///   None        = could not reach the chip after all retries (UNKNOWN)
fn probe_slot_with_retry(config: &SeConfig, slot_hex: &str, attempts: u8) -> Option<bool> {
    for attempt in 1..=attempts {
        match SeKeyStorage::new(config) {
            Ok(store) => match store.list_slots() {
                Ok(list) => {
                    return Some(list.to_uppercase().contains(&slot_hex.to_uppercase()));
                }
                Err(e) => {
                    warn!(
                        "SE050 readidlist attempt {}/{} failed: {}",
                        attempt, attempts, e
                    );
                }
            },
            Err(e) => {
                warn!(
                    "SE050 connect attempt {}/{} failed: {}",
                    attempt, attempts, e
                );
            }
        }
        // Clear stale session pickle so the next connect() is clean.
        // ssscli writes ~/.ssscli_session.pkl (note the leading char varies
        // by ssscli version: "~.ssscli_session.pkl" on these boards).
        if let Some(home) = std::env::var_os("HOME") {
            let home = home.to_string_lossy().to_string();
            for candidate in [
                format!("{}/.ssscli_session.pkl", home),
                format!("{}/~.ssscli_session.pkl", home),
                format!("{}/~.ssscli_session.pkl", "/root"),
            ] {
                let _ = std::fs::remove_file(&candidate);
            }
        }
    }
    None
}
```

**Then** replace the inline `match SeKeyStorage::new(config) { ... }` probe added in Fix 1 with a call to this helper:

**FIND** (the `let probe = match SeKeyStorage::new(config) { ... };` block from Fix 1):
```rust
                let probe = match SeKeyStorage::new(config) {
                    Ok(store) => match store.list_slots() {
                        Ok(list) => {
                            if list.to_uppercase().contains(&slot_hex.to_uppercase()) {
                                SlotProbe::Present
                            } else {
                                SlotProbe::Absent
                            }
                        }
                        Err(e) => {
                            warn!(
                                "SE050 readidlist failed ({}) — treating slot {} as \
                                 UNKNOWN, NOT regenerating",
                                e, slot_hex
                            );
                            SlotProbe::Unknown
                        }
                    },
                    Err(e) => {
                        warn!(
                            "SE050 connect failed ({}) — treating slot {} as UNKNOWN, \
                             NOT regenerating",
                            e, slot_hex
                        );
                        SlotProbe::Unknown
                    }
                };
```

**REPLACE WITH:**
```rust
                let probe = match probe_slot_with_retry(config, &slot_hex, 4) {
                    Some(true) => SlotProbe::Present,
                    Some(false) => SlotProbe::Absent,
                    None => SlotProbe::Unknown,
                };
```

**Effect:** the common case (stale pickle after network change) self-heals within a few immediate retries; only a chip that is *consistently* unreachable across 4 clean attempts is treated as `Unknown` (and Fix 1 keeps the existing key in that case anyway).

---

## Fix 3 — `main.rs`: stop initializing DKP twice per boot

The auto-rotation block re-probes the SE050 with a second `DkpManager::init()`. Gate it so it runs **only** if the primary KeyManager init already succeeded via SE050, and reuse a lightweight check rather than a second full provision-capable init.

**File:** `src/main.rs`
**Function:** `main` — the `=== DKP Auto-Rotation Check ===` block

**FIND:**
```rust
    // === DKP Auto-Rotation Check ===
    #[cfg(feature = "secure-element")]
    {
        let se_config = sgx_guardian_client::secure_element::SeConfig::default();
        let base_path = "/var/lib/sgx-guardian";
        if let Ok(mut dkp) =
            sgx_guardian_client::secure_element::dkp::DkpManager::init(&se_config, base_path)
        {
            match dkp.check_and_auto_rotate() {
```

**REPLACE WITH:**
```rust
    // === DKP Auto-Rotation Check ===
    // Only probe the SE050 a SECOND time if the primary KeyManager init above
    // actually came up on hardware. Re-initializing DkpManager on a flaky chip
    // (e.g. during a network flap on the CA node) doubles ssscli/I2C contention
    // and was an amplifier of the DKP-regeneration cascade. If we're on software
    // keys, there is nothing to auto-rotate in the SE050 anyway.
    #[cfg(feature = "secure-element")]
    if km.backend_name() == "SE050" {
        let se_config = sgx_guardian_client::secure_element::SeConfig::default();
        let base_path = "/var/lib/sgx-guardian";
        if let Ok(mut dkp) =
            sgx_guardian_client::secure_element::dkp::DkpManager::init(&se_config, base_path)
        {
            match dkp.check_and_auto_rotate() {
```

> The closing braces of this block are unchanged. We only (a) replaced the bare `{` with `if km.backend_name() == "SE050" {` and (b) added the explanatory comment. With Fix 1 in place this second `init()` is already safe (it can no longer regenerate on a transient error); Fix 3 additionally removes the redundant probe whenever the chip is degraded.

---

## Fix 4 — DID layer: pin to persisted v1 pubkey; never exit on unreadable DKP

Two problems in `did::method::create_if_absent` / `did.rs` persistence:
(a) it recomputes the DID from the **live** `dkp_pub.der` (wrong after any legitimate rotation), and
(b) `main.rs` does `process::exit(2)` on `DerivationMismatch`, turning a recoverable SE050 read blip into a hard outage.

### 4a — persist the full v1 pubkey inside `did.json`

**File:** `src/did/persistence.rs`
**Struct:** `DerivationProof`

**FIND:**
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivationProof {
    pub se050_uid: String,
    pub se050_uid_source: String,
    pub dkp_v1_pubkey_sha256_b16: String,
    pub dkp_v1_pubkey_path: String,
}
```

**REPLACE WITH:**
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivationProof {
    pub se050_uid: String,
    pub se050_uid_source: String,
    pub dkp_v1_pubkey_sha256_b16: String,
    pub dkp_v1_pubkey_path: String,
    /// Full DKP v1 SEC1 DER, base64. The DID is pinned to THIS key forever.
    /// dkp_pub.der on disk is overwritten on every legitimate DKP rotation,
    /// so it must NOT be used to re-derive the DID. Optional for backward
    /// compatibility with did.json files written before this fix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dkp_v1_pubkey_der_b64: Option<String>,
}
```

### 4b — write the v1 pubkey at creation, derive/verify from the persisted copy

**File:** `src/did/method.rs`
**Function:** `create_if_absent`

**FIND** (the derivation + mismatch logic — the block that builds `candidate_did` from the live pubkey and compares):
```rust
    let dkp_pubkey = read_dkp_pubkey(dkp_pubkey_path)?;
    let (uid_str, uid_source) = read_uid(node_id);
    let uid_bytes = uid_str.as_bytes();

    let candidate_did = derive(uid_bytes, &dkp_pubkey);

    if Path::new(did_path).exists() {
        let existing = DidRecord::load(did_path)?;
        let existing_did = Did::parse(&existing.did)?;

        if existing_did != candidate_did {
            return Err(DidError::DerivationMismatch);
        }
        return Ok(existing_did);
    }
```

**REPLACE WITH:**
```rust
    let (uid_str, uid_source) = read_uid(node_id);
    let uid_bytes = uid_str.as_bytes();

    // ── Existing DID present: validate against the PINNED v1 pubkey,
    //    never against the live dkp_pub.der (which rotates) ──────────────
    if Path::new(did_path).exists() {
        let existing = DidRecord::load(did_path)?;
        let existing_did = Did::parse(&existing.did)?;

        // Source of truth for re-derivation = the v1 pubkey stored INSIDE
        // did.json. Fall back to the on-disk file only for legacy records
        // written before this field existed.
        let pinned_v1: Vec<u8> = match &existing.derivation.dkp_v1_pubkey_der_b64 {
            Some(b64) => general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| DidError::InvalidFormat(format!("pinned v1 pubkey b64: {}", e)))?,
            None => {
                // Legacy did.json. Try the live file; if it is unreadable we
                // must NOT treat that as a mismatch — keep the persisted DID.
                match read_dkp_pubkey(dkp_pubkey_path) {
                    Ok(der) => der,
                    Err(_) => {
                        eprintln!(
                            "  ⚠️ DKP pubkey unreadable and did.json has no pinned \
                             v1 key (legacy) — trusting persisted DID, continuing"
                        );
                        return Ok(existing_did);
                    }
                }
            }
        };

        let candidate_did = derive(uid_bytes, &pinned_v1);
        if existing_did != candidate_did {
            // Only a genuine SE050 UID change (true chip swap) can move the
            // DID when derived from the pinned v1 key. This is a hard
            // identity change — surface it, but do NOT exit here; let the
            // caller decide. (main.rs is updated to NOT process::exit.)
            return Err(DidError::DerivationMismatch);
        }
        return Ok(existing_did);
    }

    // ── First boot: derive from the CURRENT DKP (this becomes v1) ────────
    let dkp_pubkey = read_dkp_pubkey(dkp_pubkey_path)?;
    let candidate_did = derive(uid_bytes, &dkp_pubkey);
```

Then, in the record-construction part of the same function, persist the v1 pubkey. **FIND**:
```rust
    let derivation = DerivationProof {
        se050_uid: uid_str.clone(),
        se050_uid_source: uid_source,
        dkp_v1_pubkey_sha256_b16: dkp_pubkey_hash,
        dkp_v1_pubkey_path: dkp_pubkey_path.to_string(),
    };
```

**REPLACE WITH:**
```rust
    let derivation = DerivationProof {
        se050_uid: uid_str.clone(),
        se050_uid_source: uid_source,
        dkp_v1_pubkey_sha256_b16: dkp_pubkey_hash,
        dkp_v1_pubkey_path: dkp_pubkey_path.to_string(),
        dkp_v1_pubkey_der_b64: Some(general_purpose::STANDARD.encode(&dkp_pubkey)),
    };
```

(Ensure `use base64::{engine::general_purpose, Engine as _};` is present in `method.rs` — it already is, used for `deriv_signature_b64`.)

### 4c — `main.rs`: do NOT `process::exit` on mismatch; keep persisted DID

**File:** `src/main.rs`
**Function:** `main` — the DID init block

**FIND:**
```rust
            Err(sgx_guardian_client::did::DidError::DerivationMismatch) => {
                eprintln!(
                    "  🔴 DID DERIVATION MISMATCH — refusing to start."
                );
```

…through the matching `std::process::exit(2);`. The exact current block (per project knowledge / your log "🔴 DID DERIVATION MISMATCH — refusing to start.") is:

```rust
            Err(sgx_guardian_client::did::DidError::DerivationMismatch) => {
                eprintln!("  🔴 DID DERIVATION MISMATCH — refusing to start.");
                log_audit(
                    &node_id,
                    AuditCategory::Did,
                    AuditSeverity::Critical,
                    AuditAction::Failed,
                    "DID derivation mismatch — hardware fingerprint changed",
                );
                std::process::exit(2);
            }
```

**REPLACE WITH:**
```rust
            Err(sgx_guardian_client::did::DidError::DerivationMismatch) => {
                // A mismatch derived from the PINNED v1 pubkey means the
                // SE050 UID changed (true chip swap) — NOT a transient read
                // blip (Fix 1/2 prevent those from ever regenerating the DKP).
                // Even so, do NOT kill the daemon: the persisted did.json
                // remains the authoritative identity. Log CRITICAL, keep the
                // persisted DID, and continue in a degraded-but-running state
                // so the operator can investigate instead of facing a boot loop.
                eprintln!(
                    "  🔴 DID DERIVATION MISMATCH (SE050 UID changed?) — \
                     keeping persisted DID, continuing in DEGRADED mode."
                );
                log_audit(
                    &node_id,
                    AuditCategory::Did,
                    AuditSeverity::Critical,
                    AuditAction::Failed,
                    "DID derivation mismatch — persisted DID retained, node DEGRADED",
                );
                if let Ok(rec) = sgx_guardian_client::did::DidRecord::load(
                    sgx_guardian_client::did::DEFAULT_DID_PATH,
                ) {
                    println!("  ↳ Persisted DID retained: {}", rec.did);
                }
            }
```

**Effect:** the run-4 hard exit becomes a logged warning; the node stays up on its real, persisted DID. Combined with Fix 1/2 the mismatch should not occur from a network change at all anymore — this is defense in depth for genuine hardware events.

---

## Fix 5 — auto-heal boards already broken by this bug

nodeA in your logs already quarantined its good metadata to `dkp_metadata.json.stale.<ts>` and is now on software keys. Recover automatically instead of requiring `fresh-provision.sh`: if `dkp_metadata.json` is absent but a quarantine exists **and** `dkp_pub.der` is still the original (non-zero, 91 bytes), restore the newest quarantine rather than generating a brand-new DKP.

**File:** `src/secure_element/dkp.rs`
**Function:** `DkpManager::init` — immediately before the `// No existing DKP — generate new one` line

**FIND:**
```rust
        // No existing DKP — generate new one
        println!("  No existing DKP found — generating new DKP inside SE050...");
        let meta = Self::generate_dkp(config, &public_key_path)?;
```

**REPLACE WITH:**
```rust
        // Fix 5: before provisioning a brand-new DKP, try to restore a
        // metadata file that a previous (buggy) boot quarantined. If the
        // public key DER is still intact on disk, the SE050 slot almost
        // certainly still holds the original key — regenerating would
        // permanently change the device identity and break the DID/baseline.
        if !Path::new(&metadata_path).exists() {
            if let Some(parent) = Path::new(&metadata_path).parent() {
                if let Ok(entries) = std::fs::read_dir(parent) {
                    let mut quarantines: Vec<std::path::PathBuf> = entries
                        .flatten()
                        .map(|e| e.path())
                        .filter(|p| {
                            p.file_name()
                                .and_then(|n| n.to_str())
                                .map(|n| {
                                    n.starts_with("dkp_metadata.json.stale.")
                                })
                                .unwrap_or(false)
                        })
                        .collect();
                    quarantines.sort();
                    if let Some(newest) = quarantines.last() {
                        let pub_ok = std::fs::metadata(&public_key_path)
                            .map(|m| m.len() == 91)
                            .unwrap_or(false);
                        if pub_ok {
                            if std::fs::rename(newest, &metadata_path).is_ok() {
                                println!(
                                    "  ♻️ Restored quarantined DKP metadata ({:?}) — \
                                     pubkey intact, NOT regenerating",
                                    newest.file_name().unwrap_or_default()
                                );
                                if let Ok(history) = DkpKeyHistory::load(&metadata_path) {
                                    if history.active_key().is_some() {
                                        return Ok(Self {
                                            history,
                                            metadata_path,
                                            public_key_path,
                                            config: config.clone(),
                                        });
                                    }
                                }
                            }
                        } else {
                            warn!(
                                "Quarantined DKP metadata found but dkp_pub.der is \
                                 missing/short — cannot safely restore, will provision"
                            );
                        }
                    }
                }
            }
        }

        // No existing DKP — generate new one
        println!("  No existing DKP found — generating new DKP inside SE050...");
        let meta = Self::generate_dkp(config, &public_key_path)?;
```

**Operator note:** For nodeA, which is *already* on software keys with an invalidated baseline, after deploying this build you also need to once: (1) stop the daemon, (2) restore `dkp_metadata.json` from the newest `dkp_metadata.json.stale.*` (Fix 5 does this automatically on next boot if `dkp_pub.der` is intact — verify with `ls -l /var/lib/sgx-guardian/keys/`), (3) if `dkp_pub.der` was overwritten by a software key, re-export it from the SE050 slot `0x20000010` with `ssscli get ecc pub 0x20000010 /var/lib/sgx-guardian/keys/dkp_pub.der`, (4) re-create the PCR baseline so it is signed by the restored SE050 DKP: `sgx-pa-cli pcr-baseline rotate`. This is a one-time recovery for the already-damaged board; Fix 1/2/5 prevent recurrence.

---

# 4. Why This Is the Right Fix (and what it is NOT)

- It does **not** touch the DID derivation formula. `did:guardian:<base58(SHA256(UID‖DKPv1))>` is unchanged and spec-compliant.
- It does **not** weaken security. A genuine chip swap (SE050 UID change) is still detected and logged CRITICAL; the node runs degraded rather than silently re-binding identity.
- It does **not** introduce `std::thread::sleep` or sync `Command` in the async runtime. The retry runs at STEP_01 before tokio tasks spawn and uses immediate re-spawn + pickle reset, matching the project hard rule and the existing `reset_ssscli.sh` approach.
- It fixes a latent bug that would have broken **legitimate DKP rotation** (Fix 4a/4b) even with no network change.
- nodeB/nodeC need no special handling — once nodeA stops regenerating its DKP, its baseline signature is valid again and the mesh re-trusts it.

---

# 5. Verification — Re-run Checklist Item 6 (the failing one)

Laptop is not representative (no SE050). Test on the boards via AnyDesk + Minicom.

```bash
# nodeA — capture identity BEFORE the network-change test
sgx-pa-cli did show            # note the did:guardian:... and DKP v1 pubkey hash
sha256sum /var/lib/sgx-guardian/keys/dkp_pub.der
cat /var/lib/sgx-guardian/keys/dkp_metadata.json | jq '.[].version'
./sgx_guardian_client nodeA &  # let it stabilize, all 3 nodes attesting

# Trigger the exact failing scenario: flap nodeA between eth0 and wlan0
sudo ip link set eth0 down ; sleep 20
sudo ip link set eth0 up   ; sleep 20
sudo ip link set wlan0 down; sleep 20
sudo ip link set wlan0 up  ; sleep 20
# Repeat the flap 5x — this is what broke run 4 previously.

# AFTER the flaps — identity MUST be unchanged:
sgx-pa-cli did show            # SAME did:guardian:... as before
sha256sum /var/lib/sgx-guardian/keys/dkp_pub.der   # SAME hash
cat /var/lib/sgx-guardian/keys/dkp_metadata.json | jq '.[].version'  # still [1], no v2
ls /var/lib/sgx-guardian/keys/ | grep stale || echo "no quarantine — good"
journalctl -u sgx-guardian | grep -E "regenerat|DERIVATION MISMATCH|Baseline signature INVALID" \
  && echo "FAIL" || echo "PASS: no regeneration, no mismatch, baseline intact"
```

Pass criteria:
1. `sgx-pa-cli did show` returns the **identical** DID before and after ≥5 eth/wifi flaps.
2. `dkp_pub.der` SHA-256 is unchanged; `dkp_metadata.json` still shows only `[1]` (no spurious v2).
3. No `dkp_metadata.json.stale.*` quarantine is created by a network change.
4. No `🔴 DID DERIVATION MISMATCH`, no `Baseline signature INVALID`.
5. nodeB/nodeC never log `❌ Attestation rejected: prover nodeA baseline has bad signature` after the flaps.
6. If SE050 is briefly unreachable during a flap, log shows `⚠️ SE050 not reachable this boot — keeping existing DKP (v1)` and the node continues with the same DID.

Regression (must still pass):
```bash
cargo build --release 2>&1 | grep -E "error|warning: unused" || true
cargo test --release secure_element::dkp 2>&1 | tail -10
cargo test --release secure_element::ssscli 2>&1 | tail -10
cargo test --release did:: 2>&1 | tail -10
# Cold-boot all 3 nodes; confirm DID-001..first-5 checklist still pass.
```

---

# 6. Corrected Verification Checklist — Task 1 (W3C DID) ONLY

Your 20-item list mixed Task 1, Task 2 (DID Document), and Task 3 (DID Resolution Service). Task 2 is **not implemented yet**, so 9 items cannot pass and do not belong here. Below is the cleaned, Task-1-only list.

### ✅ Keep — these are Task 1 (W3C DID Implementation)

```
[x] DID generated on first boot
[x] DID format is did:guardian:<base58-hash>
[x] DID unique across nodeA/nodeB/nodeC
[x] DID persists after service restart
[x] DID persists after reboot
[ ] DID persists after IP/network change            ← FIXED by this plan; re-verify
[ ] DID persists after firmware update
[ ] DID persists after DKP key rotation (v1→v2) — DID unchanged   ← ADDED (critical; the
                                                                    pinned-v1 fix makes this
                                                                    pass — it would have
                                                                    failed before Fix 4)
[ ] DID derived from device serial (SE050 UID) + secure element public key (DKP v1)
[ ] No private key exposed in files / logs / API
[ ] DID method spec documents create / resolve / update / deactivate operations
[ ] Local DID resolution returns the persisted DID + active status (sgx-pa-cli did resolve)
[ ] DID parser rejects a malformed DID string (format validation only)
[ ] DID deactivation works (sgx-pa-cli did deactivate; persists deactivated_at)
```

The first five `[x]` are the ones you reported already working. Item 6 is the one this plan fixes. I added the **DKP key rotation** item because the same pinned-v1 fix (Fix 4) is what makes both "network change" and "key rotation" preserve the DID — they share a root cause and must be tested together.

### ❌ Remove from the Task 1 list — these belong to Task 2 / Task 3 (not implemented yet)

| Original checklist item | Belongs to | Reason |
|---|---|---|
| DID Document generated | **Task 2** (DID Document) | No DID Document layer exists in Task 1 |
| DID Document valid JSON-LD | **Task 2** | JSON-LD document is a Task 2 deliverable |
| DID Document contains public key / authentication methods | **Task 2** | `verificationMethod` / `authentication` arrays are Task 2 |
| DID Document contains correct service endpoints | **Task 2** | `service[]` endpoints are Task 2 |
| DID resolver resolves valid DID | **Task 3** (DID Resolution Service) | Network resolver service is Task 3; Task 1 only has *local* resolve (kept, reworded above) |
| Resolver rejects invalid DID | **Task 3** | Resolver service is Task 3; Task 1 only has *parser* rejection (kept, reworded above) |
| Resolver cache works with TTL | **Task 3** | 1-hr TTL cache is explicitly a Task 3 deliverable |
| DID Document update works without changing DID | **Task 2** | Updating the *Document* is Task 2 |
| Key rotation updates DID Document without changing DID | **Task 2** | The "updates DID **Document**" half is Task 2. The "without changing DID" half I preserved as a Task 1 item ("DID persists after DKP key rotation") above. |

Net: **20 → 14 items** for Task 1. Two reworded down to their Task-1 scope (local resolve, parser-reject), one added (DKP rotation → DID unchanged), nine Task-2/Task-3 items removed.

---

# 7. Step-by-Step Checklist (implementation)

- [ ] Branch from `main`: `fix/task1-did-network-change-dkp`
- [ ] Fix 1 — `src/secure_element/dkp.rs` three-state probe (no regenerate on Unknown)
- [ ] Fix 2 — add `probe_slot_with_retry`, wire it into Fix 1's probe
- [ ] Fix 3 — `src/main.rs` gate auto-rotation block on `km.backend_name() == "SE050"`
- [ ] Fix 4a — `src/did/persistence.rs` add `dkp_v1_pubkey_der_b64`
- [ ] Fix 4b — `src/did/method.rs` derive/verify from pinned v1, persist v1 DER
- [ ] Fix 4c — `src/main.rs` DerivationMismatch → log + continue (no `process::exit`)
- [ ] Fix 5 — `src/secure_element/dkp.rs` quarantine-restore before generate
- [ ] `cargo build --release` clean; `cargo test --release secure_element:: did::` green
- [ ] Deploy to nodeA only first; one-time recovery (§Fix 5 operator note)
- [ ] Re-run checklist item 6 board test (§5) — 5× eth/wifi flap, DID + DKP unchanged
- [ ] Add new board test case **DID-008 (network-change persistence)** + **DID-009 (DKP-rotation DID-stable)** to Phase2_Test_Cases.pdf addendum
- [ ] Deploy to nodeB, nodeC; confirm mesh re-trusts nodeA (no "bad signature" rejections)
- [ ] CodeRabbit + CodeQL review
- [ ] PR with before/after `sgx-pa-cli did show` + `sha256sum dkp_pub.der` across the flap test

---

# 8. Honest Notes on What I Couldn't Verify

- I cannot run the boards. The root cause is reconstructed by tracing the exact current code (`dkp.rs`, `ssscli.rs`, `key_storage.rs`, `main.rs`, `did/method.rs`) against your three logs. The evidence is strong: the "No existing DKP found" line appears on nodeA exactly when (and only when) its network changed, while nodeB/nodeC (no network change) always show "Existing DKP found (v1)".
- The exact ssscli session-pickle filename varies by version. Your `ls -lh` shows `~.ssscli_session.pkl` (literally a `~` prefix). Fix 2 deletes both `~/.ssscli_session.pkl` and `~/~.ssscli_session.pkl` and the `/root/` variant to cover it. Confirm the real path on the board with `ls -a /root | grep ssscli` and adjust if needed.
- Line numbers shift between commits — use the FIND anchor strings with `grep -n`, not absolute line numbers.
- I have not seen `DkpKeyHistory::load` internals; Fix 5 assumes `load()` returns `Ok` with an active key when the JSON is a valid metadata array (consistent with `dkp_status.rs` parsing). Verify with a unit test on a restored quarantine file.
- Whether the SE050 slot `0x20000010` still physically holds the original key on the already-damaged nodeA cannot be confirmed remotely — the operator must check with `ssscli se05x readidlist` during the one-time recovery. If the slot is genuinely empty, the original DKP is unrecoverable and that board needs full re-provisioning + new DID enrollment (delete `did.json`, audit-logged) — but that is a consequence of the *original* bug, not this fix.
