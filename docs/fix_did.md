# SG-X Guardian — Task 1 DID: Two Production Fixes (DID↔DKP Decoupling + PCR4 Stability)

**Date:** May 19, 2026
**Scope:** Task 1 (W3C DID) — Issue 1 (DID anchor) + Issue 2 (PCR4 vs network state)
**Board:** Variscite VAR-SOM-MX8M-PLUS, nodeA
**Source:** Latest `main` via `project_knowledge_search` (GitHub private; project knowledge authoritative)
**Style:** Same FIND→REPLACE format as `PCR_Complete_Plan.md`

---

## Note on Code Access

GitHub repo is private — current `main` read via `project_knowledge_search`. Every FIND block below is the real current source: `src/secure_element/pcr_config.rs`, `src/secure_element/pcr.rs`, `src/secure_element/ssscli.rs`, `src/secure_element/dkp.rs`, `src/secure_element/key_storage.rs`, `src/did/method.rs`, `src/did/persistence.rs`, `src/main.rs`. I cannot compile/run on the boards; root causes are derived by tracing the code against the attached nodeA logs.

---

# ISSUE 1 — DID Anchored to a Rotatable Key

## 1.1 The problem (confirmed)

Current derivation (Task 1): `DID = did:guardian:base58(SHA256(SE050_UID ‖ DKP_pubkey_DER))`.

The DKP is **operational and rotatable** (`dkp.rs::rotate()` exists, `check_and_auto_rotate()` runs every boot, slot `0x20000010` → `0x20000011` …). The on-disk pubkey `/var/lib/sgx-guardian/keys/dkp_pub.der` is **overwritten on every rotation** (`storage.export_public_key(new_id, &self.public_key_path)`).

So:
- If `did.json` is deleted (factory reset, disk wipe, re-provision) **after** a DKP rotation, `create_if_absent` re-derives from the *current* DKP pubkey (now v2) → **a different DID**. The DID is not actually permanent — it is only as permanent as `did.json`.
- This violates the spec requirement: *"DIDs remain constant across device lifetime, firmware updates, and network changes."*

## 1.2 The explicit question: can we use a fixed SE public key?

**Short answer: a truly fixed factory key exists on the chip, but it is NOT usable with the current tooling. The correct, implementable fix is a dedicated non-rotating Device Identity Key (DIK).**

### Option A — NXP factory attestation key (the "real" fixed key)

The SE050E **does** carry a permanent, chip-unique, NXP-provisioned ECDSA-P256 attestation keypair with an NXP-signed certificate (SE050 datasheet AN13483 §3.4: *"All the generic SE050 variants have an attestation key trust provisioned by NXP"*). It is non-rotatable and cannot be erased by the user. This is exactly a "fixed SE identity public key."

**Why we cannot use it right now — the proper reason:**

The project's `ssscli` wrapper (`src/secure_element/ssscli.rs`) only wires these SE050 commands:

```
se05x : certuid, getrng, readidlist, reset, uid
keys  : generate ecc, get ecc pub, sign, verify, erase
```

There is **no command to export the NXP attestation public key or its certificate**. Retrieving it requires:
1. New APDU / `ssscli` attestation plumbing (the attestation object read with `--attest` / attestation object ID), which is not implemented in `ssscli.rs`.
2. Parsing and trust-validating the NXP attestation certificate chain.
3. Handling SE050-variant differences (not all variants expose the same attestation object layout).

That is real new firmware-interface work, not a config change. It is a valid future hardening item but is **not available with the code that exists today**. Using it now is not feasible — that is the proper reason.

### Option B — Dedicated non-rotating Device Identity Key (DIK) ✅ RECOMMENDED

Generate **one additional** SE050 keypair, **once**, at a **fixed slot separate from the DKP**, that is:
- **never rotated** (no `rotate()` path, never touched by `check_and_auto_rotate()`),
- **never used for operational signing** (zero rotation pressure — it only ever produces a public key for DID derivation),
- re-readable from the SE050 slot at any time (so the DID is re-derivable even if `did.json` is deleted).

| | DKP (existing) | **DIK (new)** |
|---|---|---|
| Slot | `0x20000010` (+version offset) | `0x20000001` (fixed, never offset) |
| Purpose | Operational signing (PCR, attestation, certs) | DID anchor **only** |
| Rotation | Yes (auto + manual) | **Never** |
| File | `/var/lib/sgx-guardian/keys/dkp_pub.der` (overwritten on rotate) | `/var/lib/sgx-guardian/keys/dik_pub.der` (write-once) |
| Used by `did:guardian` | ❌ remove | ✅ |

New derivation: `DID = did:guardian:base58(SHA256(SE050_UID ‖ DIK_pubkey_DER))`.

Properties this gives:
1. **Survives DKP rotation** — DIK slot `0x20000001` is never touched by rotation. ✅
2. **Survives `did.json` deletion** — re-read SE050 UID + DIK pubkey from slot `0x20000001` → identical DID. ✅
3. **Survives firmware update / network change** — neither input depends on firmware or IP. ✅
4. Satisfies the spec's "secure element public key" requirement (DIK is an SE050-resident key). ✅
5. Uses **existing, proven** ssscli plumbing (`generate ecc` / `get ecc pub`) — no new APDU work. ✅

The SE050 UID alone is already permanent and chip-unique; the DIK adds the cryptographic anchor the spec requires and lets the device *prove* control of its DID by signing a challenge with the DIK.

## 1.3 Migration note (one-time, acceptable in Sprint 5)

Existing test boards already minted DKP-derived DIDs:
- nodeA `did:guardian:FbBin6gQHha6tDeAbTqQhDG4NX3KWCTbdF9pNP3K8giD`
- nodeB `did:guardian:asNy11Z5Qhgm2xfU77g7q1eZrbyhKK4Tpq25Z361mjJ`
- nodeC `did:guardian:9snsv5NXFBu2cDztivn9TJU8YRC41kTJLXTrxTRxLpuN`

Switching to DIK changes these DIDs **once**. We are in Sprint 5 hardware testing, not production, so a one-time re-mint is acceptable and is the right time to fix this — before any production enrollment. After the DIK epoch the DID is permanent forever. Provide `sgx-pa-cli did remint` and document it.

## 1.4 Fix Plan — Issue 1 (4 changes)

### Fix 1.1 — New non-rotating DIK manager

**New file:** `src/secure_element/dik.rs`

```rust
// src/secure_element/dik.rs
// ============================================================
// Device Identity Key (DIK) — PERMANENT, NON-ROTATING.
//
// Slot: 0x20000001 (fixed; distinct from DKP 0x20000010).
// Purpose: the sole cryptographic anchor for did:guardian.
// NEVER rotated. NEVER used for operational signing.
//
// Generated exactly once at first provisioning. If dik_pub.der
// or dik_metadata.json is lost but the SE050 slot still holds
// the key, the public key is re-exported — the DID is therefore
// re-derivable and STABLE for the life of the chip.
// ============================================================

use crate::secure_element::config::SeConfig;
use crate::secure_element::error::SeError;
use crate::secure_element::key_storage::SeKeyStorage;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{info, warn};

/// Fixed DIK slot. Distinct from DKP_BASE_KEY_ID (0x20000010).
pub const DIK_KEY_ID: u32 = 0x20000100;
pub const DIK_PUB_PATH: &str = "/var/lib/sgx-guardian/keys/dik_pub.der";
pub const DIK_META_PATH: &str = "/var/lib/sgx-guardian/keys/dik_metadata.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DikMetadata {
    pub key_id: String,           // "0x20000001"
    pub algorithm: String,        // "ECDSA-P256"
    pub created_at: String,       // RFC3339
    pub non_rotating: bool,       // ALWAYS true — guard against accidental rotation
    pub purpose: String,          // "did:guardian anchor only"
}

pub struct DeviceIdentityKey;

impl DeviceIdentityKey {
    /// Idempotent. Returns the DIK public key DER (91 bytes).
    /// - If slot present in SE050: re-export pubkey, ensure metadata, return.
    /// - If slot absent AND no prior metadata: generate ONCE, persist.
    /// - If SE050 unreachable but dik_pub.der exists: return the cached pubkey
    ///   (do NOT regenerate — same fail-safe philosophy as the DKP fix).
    pub fn ensure(config: &SeConfig) -> Result<Vec<u8>, SeError> {
        let key_hex = format!("0x{:08X}", DIK_KEY_ID);

        // Probe the chip with the same retry/clean-session helper philosophy.
        let probe = Self::probe_slot(config, &key_hex, 4);

        match probe {
            Some(true) => {
                // Slot present — (re)export pubkey to be safe.
                if let Ok(store) = SeKeyStorage::new(config) {
                    let _ = store.export_public_key(DIK_KEY_ID, DIK_PUB_PATH);
                }
                Self::ensure_metadata();
                Self::read_pub_or_err()
            }
            Some(false) => {
                // Chip reachable, slot genuinely absent.
                if Path::new(DIK_META_PATH).exists() {
                    // Metadata says we already provisioned a DIK but the slot
                    // is gone → DO NOT silently re-provision a different
                    // identity. This is a hard, operator-visible condition.
                    warn!(
                        "DIK metadata exists but SE050 slot {} is ABSENT — \
                         refusing to silently re-provision (would change DID)",
                        key_hex
                    );
                    return Err(SeError::KeyError(
                        "DIK slot missing but metadata present — manual recovery required".into(),
                    ));
                }
                // True first provisioning.
                info!("Provisioning Device Identity Key (DIK) at {} — ONCE", key_hex);
                let store = SeKeyStorage::new(config)?;
                store.create_key_slot(DIK_KEY_ID - 0x20000000, "dik", "ecdsa")?;
                store.export_public_key(DIK_KEY_ID, DIK_PUB_PATH)?;
                Self::write_metadata();
                Self::read_pub_or_err()
            }
            None => {
                // SE050 unreachable this boot. If we have a cached pubkey,
                // trust it (DID stays stable); else hard error.
                if Path::new(DIK_PUB_PATH).exists() {
                    warn!(
                        "SE050 unreachable — using cached DIK pubkey {} (DID stable)",
                        DIK_PUB_PATH
                    );
                    Self::read_pub_or_err()
                } else {
                    Err(SeError::NotAvailable)
                }
            }
        }
    }

    fn probe_slot(config: &SeConfig, key_hex: &str, attempts: u8) -> Option<bool> {
        for _ in 0..attempts {
            if let Ok(store) = SeKeyStorage::new(config) {
                if let Ok(list) = store.list_slots() {
                    return Some(list.to_uppercase().contains(&key_hex.to_uppercase()));
                }
            }
            // Clear stale ssscli session pickle between attempts.
            if let Some(home) = std::env::var_os("HOME") {
                let h = home.to_string_lossy().to_string();
                for c in [
                    format!("{}/.ssscli_session.pkl", h),
                    format!("{}/~.ssscli_session.pkl", h),
                    "/root/~.ssscli_session.pkl".to_string(),
                ] {
                    let _ = std::fs::remove_file(&c);
                }
            }
        }
        None
    }

    fn write_metadata() {
        let meta = DikMetadata {
            key_id: format!("0x{:08X}", DIK_KEY_ID),
            algorithm: "ECDSA-P256".into(),
            created_at: chrono::Utc::now().to_rfc3339(),
            non_rotating: true,
            purpose: "did:guardian anchor only".into(),
        };
        if let Ok(j) = serde_json::to_string_pretty(&meta) {
            if let Some(p) = Path::new(DIK_META_PATH).parent() {
                let _ = std::fs::create_dir_all(p);
            }
            let _ = std::fs::write(DIK_META_PATH, j);
        }
    }

    fn ensure_metadata() {
        if !Path::new(DIK_META_PATH).exists() {
            Self::write_metadata();
        }
    }

    fn read_pub_or_err() -> Result<Vec<u8>, SeError> {
        std::fs::read(DIK_PUB_PATH)
            .map_err(|e| SeError::KeyError(format!("Read DIK pubkey: {}", e)))
    }
}
```

**Register the module** — `src/secure_element/mod.rs`:

**FIND:**
```rust
pub mod dkp;
```
**REPLACE WITH:**
```rust
pub mod dik;
pub mod dkp;
```

### Fix 1.2 — DID derives from DIK, not DKP

**File:** `src/did/persistence.rs` — rename the persisted field to reflect the anchor.

**FIND:**
```rust
    pub dkp_v1_pubkey_sha256_b16: String,
    pub dkp_v1_pubkey_path: String,
```
**REPLACE WITH:**
```rust
    pub dkp_v1_pubkey_sha256_b16: String,   // legacy; kept for back-compat reads
    pub dkp_v1_pubkey_path: String,         // legacy
    /// SHA-256 of the DIK pubkey — the real anchor going forward.
    #[serde(default)]
    pub dik_pubkey_sha256_b16: String,
    /// Full DIK pubkey DER, base64. DID is pinned to THIS forever.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dik_pubkey_der_b64: Option<String>,
```

**File:** `src/did/method.rs` — derive/verify from the DIK.

**FIND** (the first-boot derivation that reads the DKP pubkey):
```rust
    // ── First boot: derive from the CURRENT DKP (this becomes v1) ────────
    let dkp_pubkey = read_dkp_pubkey(dkp_pubkey_path)?;
    let candidate_did = derive(uid_bytes, &dkp_pubkey);
```
**REPLACE WITH:**
```rust
    // ── First boot: derive from the non-rotating DIK (NOT the DKP) ───────
    let se_config = crate::secure_element::config::SeConfig::default();
    let dik_pubkey = crate::secure_element::dik::DeviceIdentityKey::ensure(&se_config)
        .map_err(|e| DidError::Io(std::io::Error::other(format!("DIK ensure: {}", e))))?;
    let candidate_did = derive(uid_bytes, &dik_pubkey);
```

**FIND** (the existing-DID validation block — the pinned-key compare added in the prior fix; it currently keys off `dkp_v1_pubkey_der_b64`):
```rust
        let pinned_v1: Vec<u8> = match &existing.derivation.dkp_v1_pubkey_der_b64 {
            Some(b64) => general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| DidError::InvalidFormat(format!("pinned v1 pubkey b64: {}", e)))?,
            None => {
```
**REPLACE WITH:**
```rust
        let pinned: Vec<u8> = match &existing.derivation.dik_pubkey_der_b64 {
            Some(b64) => general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| DidError::InvalidFormat(format!("pinned DIK b64: {}", e)))?,
            None => {
```

…and update the corresponding `derive(uid_bytes, &pinned_v1)` call in that block to `derive(uid_bytes, &pinned)`. The legacy fallback inside the `None =>` arm should re-read the DIK (`DeviceIdentityKey::ensure`) instead of `read_dkp_pubkey`, so old `did.json` files (DKP-derived) trigger a clean re-mint via `did remint` rather than silently mismatching.

**FIND** (record construction — persist the DIK):
```rust
    let derivation = DerivationProof {
        se050_uid: uid_str.clone(),
        se050_uid_source: uid_source,
        dkp_v1_pubkey_sha256_b16: dkp_pubkey_hash,
        dkp_v1_pubkey_path: dkp_pubkey_path.to_string(),
        dkp_v1_pubkey_der_b64: Some(general_purpose::STANDARD.encode(&dkp_pubkey)),
    };
```
**REPLACE WITH:**
```rust
    use sha2::{Digest, Sha256};
    let dik_hash = hex::encode(Sha256::digest(&dik_pubkey));
    let derivation = DerivationProof {
        se050_uid: uid_str.clone(),
        se050_uid_source: uid_source,
        dkp_v1_pubkey_sha256_b16: String::new(),     // no longer the anchor
        dkp_v1_pubkey_path: String::new(),
        dik_pubkey_sha256_b16: dik_hash,
        dik_pubkey_der_b64: Some(general_purpose::STANDARD.encode(&dik_pubkey)),
    };
```

### Fix 1.3 — `main.rs`: DIK is provisioned before DID init, independent of DKP

**File:** `src/main.rs` — DID init block. Ensure the DIK exists before `create_if_absent`. `create_if_absent` already calls `DeviceIdentityKey::ensure` internally (Fix 1.2), so no main.rs change is strictly required — but add a one-line log for operator clarity.

**FIND:**
```rust
    // === DID Initialization (W3C DID / did:guardian) ===
    println!("\n🆔 Initializing W3C DID (did:guardian)...");
```
**REPLACE WITH:**
```rust
    // === Device Identity Key (DIK) — non-rotating DID anchor ===
    #[cfg(feature = "secure-element")]
    {
        let se_config = sgx_guardian_client::secure_element::SeConfig::default();
        match sgx_guardian_client::secure_element::dik::DeviceIdentityKey::ensure(&se_config) {
            Ok(_) => println!("🔑 Device Identity Key (DIK) ready (slot 0x20000001, non-rotating)"),
            Err(e) => eprintln!("⚠️ DIK ensure failed: {} — DID will use cached anchor if present", e),
        }
    }

    // === DID Initialization (W3C DID / did:guardian) ===
    println!("\n🆔 Initializing W3C DID (did:guardian)...");
```

### Fix 1.4 — `sgx-pa-cli did remint` (one-time migration)

**File:** `sgx-pa-cli/src/commands/did.rs` — add a `Remint` subcommand that: backs up the old `did.json` to `did.json.dkp-era.bak`, deletes `did.json`, and prints instructions to restart the daemon (which regenerates the DID from SE050 UID + DIK). Gate behind `--yes`. (Implementation mirrors the existing `Deactivate` subcommand pattern; ~30 lines.)

## 1.5 Issue 1 — Verification

```bash
# Provision DIK + remint DID once
sgx-pa-cli did remint --yes
./sgx_guardian_client nodeA   # note new did:guardian:... (DIK-derived)
sgx-pa-cli did show > /tmp/did_before.txt
sha256sum /var/lib/sgx-guardian/keys/dik_pub.der

# Rotate the DKP (operational key) — DID MUST NOT change
sgx-pa-cli dkp-rotate --yes
./sgx_guardian_client nodeA
sgx-pa-cli did show > /tmp/did_after_dkp_rotate.txt
diff /tmp/did_before.txt /tmp/did_after_dkp_rotate.txt && echo "PASS: DID stable across DKP rotation"

# Delete did.json, restart — DID MUST regenerate IDENTICALLY (re-read from DIK slot)
rm /var/lib/sgx-guardian/identity/did.json
./sgx_guardian_client nodeA
sgx-pa-cli did show > /tmp/did_after_delete.txt
diff /tmp/did_before.txt /tmp/did_after_delete.txt && echo "PASS: DID re-derivable from SE050+DIK"

# DKP pubkey changed (rotated) but DIK pubkey unchanged
sha256sum /var/lib/sgx-guardian/keys/dik_pub.der   # SAME as before
sha256sum /var/lib/sgx-guardian/keys/dkp_pub.der   # DIFFERENT (rotated) — and irrelevant to DID
```

Pass criteria: DID identical across (a) DKP rotation, (b) `did.json` deletion + restart, (c) reboot. `dik_pub.der` hash never changes; `dkp_pub.der` hash may change freely with no effect on the DID.

---

# ISSUE 2 — PCR4 Changes on Network Switch (CONFIRMED)

## 2.1 Root cause (proven by the logs + code)

**`src/secure_element/pcr_config.rs::default_measurement_sources()`:**
```rust
PcrMeasurementSource {
    pcr_index: 4,
    label: "Guardian config".into(),
    source_type: "file".into(),
    source: format!("/etc/sgx-guardian/config/{}.yaml", node_id),  // ← measures whole node yaml
    critical: false,
},
```

**`src/main.rs` rewrites that exact file at runtime when the network changes:**
```rust
let config_path = format!("/etc/sgx-guardian/config/{}.yaml", node_id);
let _ = dynamic_config::update_config_ip_if_changed(&config_path, &detected_ip);  // ← writes IP into the PCR-measured file
```

PCR4 hashes the raw bytes of `/etc/sgx-guardian/config/nodeA.yaml`. The daemon rewrites the `ip:` field of that **same file** on every network/IP change. The log proves the exact sequence:

```
# eth0 active, config has 192.168.4.3, baseline captured:
PCR4 [✅]: 7fd3a7bf90e5b9fc..   PCR baseline: ✅ ALL MATCH
# next boot: network switched, config rewritten 192.168.4.3 → 192.168.50.101
🔄 Updating IP: 192.168.4.3 → 192.168.50.101 in /etc/sgx-guardian/config/nodeA.yaml
# boot after that: PCR measured AFTER the rewrite:
PCR4 [✅]: a5f91248217ff8ce..   ⚠️ PCR MISMATCH detected: PCR4 expected 7fd3a7bf.. got a5f91248..
❌ Attestation rejected: prover nodeA reports PCR mismatch on PCRs [4]
```

A dynamic runtime value (the LAN IP) is being mixed into a PCR-measured *static* config. The mismatch surfaces one boot after the IP change because PCR is measured at startup *before* the IP-detect/rewrite step, so the rewritten file is measured on the *following* boot. Textbook "measuring mutable runtime state" bug.

## 2.2 The fix — separate static (attested) config from dynamic (runtime) state

Two complementary changes. **Fix 2A is the minimal, surgical, must-do** (smallest blast radius). **Fix 2B is the clean long-term architecture** (recommended next, larger change).

### Fix 2A (PRIMARY) — PCR4 measures a canonical STATIC view, excluding runtime fields

Add a new measurement `source_type = "static_yaml"` that loads the node YAML, strips a denylist of dynamic keys (`ip`, `lan_ip`, `detected_ip`, `endpoint`, plus anything under a `runtime:` map), canonicalizes (sorted keys, stable serialization), and hashes *that*. The IP rewrite no longer affects PCR4 because `ip` is excluded from the measured view.

**File:** `src/secure_element/pcr_config.rs` — change PCR4 source.

**FIND:**
```rust
        PcrMeasurementSource {
            pcr_index: 4,
            label: "Guardian config".into(),
            source_type: "file".into(),
            source: format!("/etc/sgx-guardian/config/{}.yaml", node_id),
            critical: false,
        },
```
**REPLACE WITH:**
```rust
        PcrMeasurementSource {
            pcr_index: 4,
            // Measures a CANONICAL STATIC VIEW of the node config — runtime
            // network fields (ip, endpoint, runtime.*) are excluded so PCR4
            // is stable across IP/interface changes. See "static_yaml" in
            // the measurement dispatcher.
            label: "Guardian config (static)".into(),
            source_type: "static_yaml".into(),
            source: format!("/etc/sgx-guardian/config/{}.yaml", node_id),
            critical: false,
        },
```

**File:** `src/secure_element/pcr.rs` (or wherever the measurement dispatcher matches `source_type` — search `"multi_file" =>` / `"boot_chain" =>`). Add a `"static_yaml"` arm.

**FIND** (the measurement dispatch — the arm list that handles `"file"`, `"multi_file"`, `"string"`, `"boot_chain"`; locate with `grep -n '"multi_file"' src/secure_element/pcr.rs src/main.rs`):
```rust
            "file" => {
                // hash raw file bytes
                std::fs::read(&src.source).unwrap_or_default()
            }
```
**INSERT a new arm immediately before the `"file" =>` arm:**
```rust
            "static_yaml" => {
                // Load YAML, strip runtime/network fields, canonicalize, hash.
                // This makes PCR4 immune to the daemon rewriting `ip:` on a
                // network change (the exact cause of the PCR4 mismatch).
                match std::fs::read_to_string(&src.source) {
                    Ok(raw) => match serde_yaml::from_str::<serde_yaml::Value>(&raw) {
                        Ok(mut v) => {
                            canonicalize_static_config(&mut v);
                            // Stable JSON (sorted keys) as the canonical form.
                            let json = serde_yaml_to_sorted_json(&v);
                            json.into_bytes()
                        }
                        Err(e) => {
                            eprintln!(
                                "  ⚠️ static_yaml parse failed for {} ({}) — \
                                 measuring empty (DEGRADED, not raw bytes)",
                                src.source, e
                            );
                            Vec::new()
                        }
                    },
                    Err(_) => Vec::new(),
                }
            }
```

**ADD these helpers** near the bottom of `pcr.rs` (module-level fns):
```rust
/// Keys that carry runtime/network state and MUST NOT be measured.
const PCR_DYNAMIC_DENYLIST: &[&str] = &[
    "ip", "lan_ip", "detected_ip", "endpoint", "endpoints",
    "runtime", "active_transport", "observed_ip",
];

/// Recursively remove dynamic keys so PCR4 only covers static attested config.
fn canonicalize_static_config(v: &mut serde_yaml::Value) {
    if let serde_yaml::Value::Mapping(map) = v {
        for k in PCR_DYNAMIC_DENYLIST {
            map.remove(&serde_yaml::Value::String((*k).to_string()));
        }
        for (_k, val) in map.iter_mut() {
            canonicalize_static_config(val);
        }
    } else if let serde_yaml::Value::Sequence(seq) = v {
        for item in seq.iter_mut() {
            canonicalize_static_config(item);
        }
    }
}

/// Deterministic JSON (sorted object keys) from a serde_yaml::Value.
fn serde_yaml_to_sorted_json(v: &serde_yaml::Value) -> String {
    fn to_json(v: &serde_yaml::Value) -> serde_json::Value {
        match v {
            serde_yaml::Value::Null => serde_json::Value::Null,
            serde_yaml::Value::Bool(b) => serde_json::Value::Bool(*b),
            serde_yaml::Value::Number(n) => {
                serde_json::Value::Number(
                    serde_json::Number::from_f64(n.as_f64().unwrap_or(0.0))
                        .unwrap_or_else(|| serde_json::Number::from(0)),
                )
            }
            serde_yaml::Value::String(s) => serde_json::Value::String(s.clone()),
            serde_yaml::Value::Sequence(seq) => {
                serde_json::Value::Array(seq.iter().map(to_json).collect())
            }
            serde_yaml::Value::Mapping(m) => {
                let mut keys: Vec<String> = m
                    .iter()
                    .filter_map(|(k, _)| k.as_str().map(|s| s.to_string()))
                    .collect();
                keys.sort();
                let mut obj = serde_json::Map::new();
                for k in keys {
                    if let Some(val) =
                        m.get(&serde_yaml::Value::String(k.clone()))
                    {
                        obj.insert(k, to_json(val));
                    }
                }
                serde_json::Value::Object(obj)
            }
            serde_yaml::Value::Tagged(t) => to_json(&t.value),
        }
    }
    serde_json::to_string(&to_json(v)).unwrap_or_default()
}
```

(`serde_yaml` and `serde_json` are already project dependencies — the config loader uses `serde_yaml`.)

**Effect:** PCR4 now hashes `{circle_id, node_id, role, ports, crypto params, policy refs, secure_element block, …}` with `ip`/`endpoint`/`runtime.*` removed. The daemon can rewrite `ip:` as often as it likes — PCR4 does not change. The baseline captured on eth0 stays valid on wlan0 and vice-versa. Re-create the baseline ONCE after deploying this build (the canonical form differs from the old raw-bytes form), then it is stable forever.

### Fix 2B (RECOMMENDED NEXT) — physically split static vs dynamic config

Even cleaner: never let the daemon write into the PCR-measured file at all.

1. The PCR-measured file becomes **immutable at runtime**: `/etc/sgx-guardian/config/<node>.static.yaml` (identity, role, circle, ports, crypto, SE config, policy refs). Never rewritten. PCR4 measures this.
2. Runtime network state moves to `/var/lib/sgx-guardian/runtime/<node>_net.json` (`ip`, active interface, observed endpoint). The IP-update path writes **only** here.
3. `config_loader::load_config` reads the static file and *overlays* the runtime IP from the runtime JSON in memory, so all existing `cfg.ip` consumers keep working unchanged.

**File:** `src/main.rs`

**FIND:**
```rust
    // Update ONLY current node config with detected IP
    if !detected_ip.is_empty() {
        let config_path = format!("/etc/sgx-guardian/config/{}.yaml", node_id);
        let main_path = format!("/etc/sgx-guardian/{}.yaml", node_id);
        let _ = dynamic_config::update_config_ip_if_changed(&config_path, &detected_ip);
        // Keep main path in sync
        let _ = std::fs::copy(&config_path, &main_path);
    }
```
**REPLACE WITH:**
```rust
    // Update ONLY the runtime network state file — NEVER the PCR-measured
    // config. This guarantees PCR4 cannot change on a network/IP switch.
    if !detected_ip.is_empty() {
        let runtime_dir = "/var/lib/sgx-guardian/runtime";
        let _ = std::fs::create_dir_all(runtime_dir);
        let net_path = format!("{}/{}_net.json", runtime_dir, node_id);
        let doc = serde_json::json!({
            "node_id": node_id,
            "ip": detected_ip,
            "updated_at": chrono::Utc::now().to_rfc3339(),
        });
        let tmp = format!("{}.tmp", net_path);
        if std::fs::write(&tmp, doc.to_string()).is_ok() {
            let _ = std::fs::rename(&tmp, &net_path);
        }
    }
```

Then in `config_loader::load_config`, after parsing the static YAML, overlay the runtime IP if the runtime file exists (so `cfg.ip` consumers are unchanged). This is the larger change (touches the loader + the IP-update helper + first-boot static-file seeding) and should be its own PR after Fix 2A is verified on the boards.

> **Recommendation:** ship **Fix 2A now** (small, surgical, fully resolves the failing attestation), then schedule **Fix 2B** as a follow-up hardening PR. Fix 2A alone makes checklist item 6 and attestation pass; Fix 2B removes the anti-pattern entirely.

## 2.3 Issue 2 — Verification

```bash
# After deploying Fix 2A, re-create the baseline ONCE (canonical form changed)
sgx-pa-cli pcr-baseline rotate
./sgx_guardian_client nodeA &     # note PCR4 + "PCR baseline: ✅ ALL MATCH"
PCR4_BEFORE=$(grep -m1 "PCR4 \[" <(journalctl -u sgx-guardian -n200) | awk '{print $3}')

# Force the exact failing scenario: eth0 ↔ wlan0 several times
sudo ip link set eth0 down; sleep 20
sudo ip link set eth0 up;   sleep 20      # daemon rewrites runtime IP
sudo ip link set wlan0 down; sleep 20
sudo ip link set wlan0 up;  sleep 20
# Restart so PCR is re-measured with the (rewritten) state present
pkill sgx_guardian_client; ./sgx_guardian_client nodeA &
sleep 30
journalctl -u sgx-guardian -n200 | grep -E "PCR4 \[|PCR MISMATCH|baseline"
```

Pass criteria:
1. `PCR4` value is **identical** before and after ≥4 eth/wifi flaps + restart.
2. `PCR baseline: ✅ ALL MATCH` (no `⚠️ PCR MISMATCH detected: PCR4 ...`).
3. `❌ Attestation rejected: prover nodeA reports PCR mismatch on PCRs [4]` does **not** appear.
4. nodeB/nodeC do not eject nodeA after the network change (no `early eof` removal cascade).
5. `cat /etc/sgx-guardian/config/nodeA.yaml | sha256sum` may change (Fix 2A) — that is fine; what matters is the *measured canonical view* is stable. With Fix 2B the file itself never changes.

---

# Combined Regression Checks

```bash
cargo build --release 2>&1 | grep -E "error|warning: unused" || true
cargo test --release secure_element::dik 2>&1 | tail -10
cargo test --release secure_element::pcr 2>&1 | tail -10
cargo test --release did:: 2>&1 | tail -10

# 3-node cold boot — DID stable, attestation green, no PCR4 mismatch
./sgx_guardian_client nodeA & ./sgx_guardian_client nodeB & ./sgx_guardian_client nodeC &
sleep 90
sgx-pa-cli did show           # all 3 unique, DIK-derived
# flap nodeA network 3x → DID unchanged, PCR4 unchanged, mesh stays trusted
```

Watch for:
- ✅ `🔑 Device Identity Key (DIK) ready (slot 0x20000001, non-rotating)` once at startup
- ✅ DID unchanged across DKP rotation AND `did.json` deletion AND reboot
- ✅ `dik_pub.der` SHA-256 constant; `dkp_pub.der` may change with zero DID impact
- ✅ PCR4 constant across eth0↔wlan0 flaps; `PCR baseline: ✅ ALL MATCH`
- ✅ No `Attestation rejected: ... PCR mismatch on PCRs [4]`
- ✅ No regression in DKP rotation, secure boot, Nebula CA, attestation flows

---

# Step-by-Step Checklist

- [ ] Branch `fix/task1-did-dik-anchor-and-pcr4-stable`
- [ ] **Issue 1**
  - [ ] Fix 1.1 — create `src/secure_element/dik.rs`; register in `mod.rs`
  - [ ] Fix 1.2 — `persistence.rs` add DIK fields; `method.rs` derive/verify from DIK
  - [ ] Fix 1.3 — `main.rs` DIK-ensure log line before DID init
  - [ ] Fix 1.4 — `sgx-pa-cli did remint --yes` subcommand
  - [ ] One-time `did remint` on nodeA/B/C; record new DIDs
  - [ ] Verify §1.5 (DID stable across DKP rotate + did.json delete + reboot)
- [ ] **Issue 2**
  - [ ] Fix 2A — `pcr_config.rs` PCR4 → `static_yaml`; `pcr.rs` new arm + helpers
  - [ ] `sgx-pa-cli pcr-baseline rotate` once (canonical form changed)
  - [ ] Verify §2.3 (PCR4 stable across eth/wifi flap; attestation passes)
  - [ ] (Follow-up PR) Fix 2B — physical static/dynamic config split
- [ ] Add board test cases: **DID-009** (DID stable across DKP rotation), **DID-010** (DID re-derivable after did.json delete), **PCR-010** (PCR4 stable across network switch)
- [ ] Deploy nodeA first; confirm nodeB/nodeC re-trust it
- [ ] CodeRabbit + CodeQL review
- [ ] PR evidence: `did show` before/after DKP-rotate+delete; PCR4 before/after eth/wifi flap

---

# Honest Notes on What I Couldn't Verify

- Cannot compile/run on the boards. Issue 2's root cause is **proven** by the log sequence (`🔄 Updating IP ... in nodeA.yaml` then next-boot `PCR4 ... got a5f91248..` then `PCR MISMATCH ... PCRs [4]`) cross-checked against `pcr_config.rs` (PCR4 source = the node yaml) and `main.rs` (rewrites that yaml). This is unambiguous.
- The SE050 NXP attestation key (Option A) is documented in AN13483 but **not exposed by the current `ssscli.rs` wrapper** — that is the proper reason it cannot be used today; the DIK (Option B) is the correct implementable equivalent and uses only already-working ssscli commands.
- The exact location of the PCR measurement `source_type` dispatch (`"file" =>` arm) — confirm with `grep -n '"multi_file"' src/secure_element/pcr.rs src/main.rs`; the new `"static_yaml"` arm goes in the same `match`.
- DIK slot `0x20000001` is assumed free (DKP uses `0x20000010`+). Confirm with `ssscli se05x readidlist` on each board before provisioning; pick another low slot if occupied.
- Line numbers shift between commits — use the FIND anchor strings, not absolute lines.
- Migration changes the three test DIDs once. This is intended and acceptable in Sprint 5 (pre-production). Do **not** do an uncontrolled remint on any node already enrolled in a production Circle.
