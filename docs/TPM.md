# SG-X Guardian — TPM 2.0 Backend Support — Development Plan
**Scope: Hardware Root of Trust | Deliverable: TPM 2.0 crypto backend (parallel to SE050) | Target platform: Intel NUC12WSH (x86_64) with firmware TPM 2.0 (Intel PTT) | Test tag: TPM-series (TPM-001 – TPM-014)**
**Repo:** `AsadAli-CyberZeus/SGX` | **Grounded on:** fresh indexed pull, 2026-07-14 | **Author:** Plan for Asad Ali

> **Honesty note on calibration.** This is a *hardware root-of-trust* task — much larger than the CRL additive modules. The **integration seams** below (the `SigningBackend` enum wiring, feature gating, `main.rs` boot path, the DID UID seam) are pulled **verbatim from the repo and are precise**. The **TPM command internals** (exact `tpm2-tools` flags, key templates, signature framing) are given as **complete, correct scaffolds with the real command sequences**, but they *must be iterated on the actual chip* — TPM tool behavior varies slightly across `tpm2-tools` versions and TPM firmware, and no one should claim byte-perfect final TPM code without running it on the target. Every such spot is marked **⚙️ VERIFY ON CHIP**.

---

## 0. Grounding Statement (READ FIRST)

Fresh pull taken before writing. The two facts that make this task tractable rather than a rewrite:

| Fact confirmed in the current index | Consequence |
|---|---|
| `key_manager.rs` defines a clean **`SigningBackend` enum** with three variants: `Software`, `Hardware{signer: SeSigner, key_id: u32}` (`#[cfg(feature="secure-element")]`), `Pkcs11{...}` (`#[cfg(feature="virtual-platform")]`, backed by SoftHSM2). Every crypto op — `sign`, `pubkey_der`, `runtime_public_key_export`, `backend_name`, `refresh_for_active_dkp` — matches on it. | **TPM is a 4th variant** (`#[cfg(feature="tpm")] Tpm{...}`). The abstraction already exists; we extend it, we don't invent it. |
| The DID is derived by `did::derive(uid_bytes, dik_pubkey)` = `SHA256(UID ‖ DIK_pub)` → base58 → `did:guardian:<b58>`. Confirmed generic by `did/tests.rs` (`test_derive_changes_with_uid`, `..._with_pubkey`). | The DID formula is **hardware-agnostic**. Only the *source* of the UID and the DIK/DKP keys changes. |
| The entire SE050-ness of identity funnels through **one seam**: `did::method::create_if_absent` calls `read_uid(node_id)` → `secure_element::pcr::read_device_uid()` for the UID, and consumes `dik_pub.der` / `dkp_pub.der` for the anchor/rotating pubkeys. | Preserve **three artifacts** — the UID bytes, `dik_pub.der`, `dkp_pub.der` — and DID, VirtualID, attestation, gossip, CRL all keep working unchanged. |
| A fully-worked **non-SE050 platform** already exists: `platform::virtual_hw::VirtualHardwareProvider` implements `KeyStoreProvider / MeasurementProvider / SecureBootProvider / AttestationProvider / PlatformInfoProvider` with `PlatformClass::Virtual`, backed by softhsm (PKCS#11), `vpcr`, `vboot`, `vattest`, `vinfo`. | A **template** for adding a new platform class. TPM = `PlatformClass::Tpm`. |
| `Cargo.toml` `[features]`: `default = ["secure-element"]`, plus `secure-element`, `virtual-platform` (both empty marker features). Crypto stack is `ring` + `p256` (ECDSA-P256), `sha2`. `which` crate present (tool discovery). | Add a `tpm` marker feature. **A shell-out backend (tpm2-tools) needs zero new Rust crates.** |
| SE050 access is a **`ssscli` shell-out** (`SssCli`), and `KeyManager::sign` is a **synchronous** fn (SE050's `SeSigner::sign` is sync); KeyManager init happens synchronously at boot. | A TPM `tpm2-tools` shell-out backend **mirrors the proven SE050 pattern exactly** and fits the existing sync calling convention — no async/runtime changes. |
| DID re-derivation on boot compares against the **pinned DIK pubkey** in `did.json` and only errors `DerivationMismatch` (which main.rs treats as DEGRADED, never a boot loop). `DerivationProof` stores `se050_uid`, `se050_uid_source`, `dik_pubkey_*` as **generic strings**. | The TPM anchor slots into the existing `DerivationProof` with `se050_uid_source = "tpm-ek"` — **no persistence-schema change** (see §2.4 for the honest trade-off). |

**Board dump confirms the TPM is capable** (Intel PTT firmware TPM 2.0, Alder Lake): algorithms include **ecdsa + ecc + sha256** (P-256), and the command set includes **`TPM2_CC_Sign`, `Create`, `CreatePrimary`, `Quote`, `PCR_Read`, `PCR_Extend`, `EvictControl` (persistent handles), `NV_*`, `GetRandom`, `ReadPublic`, `Certify`**. 24 SHA-256 PCRs active. → SGX's exclusive **ECDSA-P256 + SHA-256** contract is fully preservable.

**Net shape:** a new `tpm` feature + a new `src/tpm/` module (mirroring `src/secure_element/`) + a 4th `SigningBackend` variant + one UID seam dispatch + `main.rs` boot wiring. **Additive; SE050, software, and virtual backends untouched.**

---

## 1. What I Confirmed vs What's Worth Confirming (you offered more info)

**Confirmed from your board dump — no need to re-send:**
- Firmware TPM 2.0, manufacturer `INTC` (Intel PTT), Alder Lake, spec rev 1.38, over `/dev/tpmrm0`.
- ECDSA + ECC + SHA-256 supported; Sign/Create/Quote/PCR/EvictControl/NV/GetRandom present; 24 SHA-256 PCRs with real values.
- `tpm2-tools` present; `sudo tpm2_pcrread` works, non-root gets `Permission denied` on `/dev/tpmrm0` (a perms/group issue, §10).
- The NUC runs x86_64 Linux (not the aarch64 i.MX board).

**Worth a one-line answer each — they shape scope, not whether the plan works:**

| # | Question | Why it matters | Default assumed by this plan |
|---|---|---|---|
| Q1 | Is the NUC the **production** platform, the **demo cohort** host, or **both**? | Decides whether TPM is production-critical or a convenience. | **Both** — treated as a real hardware RoT for the NUC. |
| Q2 | Does the NUC have **only** a TPM (no SE050)? | If TPM-only, the NUC binary is built `--no-default-features --features tpm`. | **TPM-only** (dump shows no SE050). |
| Q3 | Will the daemon run **as root** on the NUC (or under a service user)? | `/dev/tpmrm0` access; else `tss` group / udev rule. | Runs with `/dev/tpmrm0` access (root or `tss` group). |
| Q4 | Is an **EK certificate** provisioned (`tpm2_getekcertificate`)? | If yes, the EK cert is a stronger UID anchor; if no, we use `SHA256(EK_pub)`. | **No cert assumed** — anchor on `SHA256(EK_pub)`. |
| Q5 | Do you want **native `TPM2_Quote`** attestation now, or is the existing DKP-signed evidence enough for v1? | Scope lever — native quote is a stronger, hardware-rooted attestation but more work. | **Phase 2** (v1 preserves current DKP-signed evidence; native quote added after). |

None of these block starting. If Q2 ever comes back "the NUC also has an SE050," tell me — the plan changes (you'd prefer SE050 and skip this).

---

## 2. SE050 → TPM 2.0 Concept Mapping (the heart of the plan)

### 2.1 Role mapping

| Concept | SE050 (today) | TPM 2.0 (this plan) | Artifact preserved for downstream |
|---|---|---|---|
| **Chip UID** (DID anchor, part 1) | `ssscli get_uid` (18-byte UID) | `SHA256(EK_pub)` — Endorsement Key public: per-chip, permanent, non-migratable. `uid_source="tpm-ek"`. | UID bytes fed to `did::derive` |
| **DIK** — non-rotating anchor key (DID anchor, part 2) | ECDSA-P256, SE050 slot `0x20000100`, exported `dik_pub.der` | ECDSA-P256 key persisted at TPM handle **`0x81000100`** (non-rotating), exported `dik_pub.der` | `dik_pub.der` (91-byte SPKI DER — identical framing) |
| **DKP** — rotating operational signing key | ECDSA-P256, slots `0x20000010+`, exported `dkp_pub.der` | ECDSA-P256 child under owner primary, persisted at **`0x81000010 + (v-1)`**, exported `dkp_pub.der`; rotate = new handle + evict old | `dkp_pub.der` |
| **Sign** | `SeSigner::sign(key_id, data)` (sync) | `tpm2_sign` on persistent handle, `-g sha256 -s ecdsa -f plain` → raw `r‖s` (64 B) matching `ECDSA_P256_SHA256_FIXED` (sync) | raw 64-byte signature |
| **PCR measurement** | OCOTP/HAB simulation (`secure_element::pcr`) | **Native** `tpm2_pcrread sha256:0,2,4,7` — real measured boot | pcr_material / pcr_digest for VirtualID |
| **Attestation** | DKP-signed evidence blob (VirtualID/PCR/nonce) | v1: **same** DKP-signed blob (unchanged). Phase 2: native `tpm2_quote` (hardware-rooted) | `SignedQuote` |
| **Tamper** | SE050 tamper applet | No direct TPM analog → use **PCR-change detection** + **DA lockout** status (`tpm2_getcap properties-variable`) | (difference; §13-L2) |

### 2.2 What does NOT change (the whole point)
`did::derive`, `DerivationProof`, `did.json` schema, VirtualID computation, attestation message shape, gossip, CRL, cert-bootstrap, Nebula — **untouched**. They only ever see: UID bytes, `dik_pub.der`, `dkp_pub.der`, a `km.sign()` result, and PCR material. Preserve those five and the system is oblivious to whether the root of trust is an SE050 or a TPM.

### 2.3 Identity consequence (state this to stakeholders)
DID = `SHA256(TPM_EK_hash ‖ DIK_pub)`. **A NUC/TPM node has a different `did:guardian:…` than an i.MX/SE050 node** — different hardware root of trust ⇒ different cryptographic identity. For a fresh NUC-based Circle this is a non-issue. You **cannot** "move" an SE050 node's identity onto a TPM node (or vice-versa); each is its own identity. (Same as the SE050 rule: swap the chip → `DerivationMismatch`.)

### 2.4 One honest schema trade-off
`DerivationProof` fields are named `se050_uid` / `se050_uid_source`. Two options:
- **(A, recommended for v1)** Reuse them as-is: store the EK-hash in `se050_uid`, set `se050_uid_source = "tpm-ek"`. **Zero schema change, zero test churn.** Slightly misnamed field, documented.
- **(B, cleaner, wider)** Rename to `hw_uid` / `hw_uid_source` (generic). Touches `persistence.rs`, `derivation_signing_bytes`, several tests, and would change the signed derivation bytes → not backward-compatible with existing `did.json` files. **Defer** as a separate refactor.

This plan uses **(A)**.

---

## 3. Architecture & the Access-Mechanism Decision

### 3.1 Three ways to reach the TPM — decision

| Option | What | Verdict |
|---|---|---|
| **1. `tpm2-tools` shell-out** (`tpm2_createprimary/create/load/evictcontrol/sign/pcrread/quote/readpublic/getrandom`) | Sync `Command` wrapper, exactly parallel to `SssCli` (ssscli). tpm2-tools 5.7 confirmed present. | **✅ RECOMMENDED.** Zero new Rust crates, mirrors the proven SE050 pattern, fits the sync `KeyManager::sign` convention, and native PCR/Quote come for free. The i.MX aarch64 boards don't have a TPM, so this feature is x86-only — and a runtime shell-out has **no cross-compile linkage** anyway. |
| **2. `tss-esapi` crate** (FFI → `libtss2-*`) | "Proper" in-process TSS2 ESAPI. | Defer. Adds a heavy C-FFI dep + `libtss2-dev` at build time; more integration risk. A good **production-hardening** follow-up once v1 works. |
| **3. `tpm2-pkcs11` via the existing `Pkcs11` backend** | Repoint the SoftHSM2 PKCS#11 path at `libtpm2_pkcs11.so`. | Not simpler: current `Pkcs11` code is softhsm-specific; tpm2-pkcs11 needs token/PIN provisioning; and it gives no native PCR/Quote (you'd still shell out for those). Split implementation. |

**Decision: Option 1 (tpm2-tools shell-out), new `src/tpm/` module mirroring `src/secure_element/`, new `SigningBackend::Tpm` variant.**

### 3.2 TCTI / device
Use the resource-managed device directly and pin it via env so tools don't hunt for `tabrmd`:
```
TPM2TOOLS_TCTI="device:/dev/tpmrm0"   # (the dump showed tabrmd errors; this avoids them)
```
Configurable via `SGX_TPM_DEVICE` (default `/dev/tpmrm0`).

### 3.3 Boot-path placement (mirrors SE050)
```
main.rs KeyManager init:
  #[cfg(feature="tpm")]      → KeyManager::init_with_tpm(&TpmConfig, base, fallback_key)
  #[cfg(feature="secure-element")] (existing SE050 path)
  #[cfg(feature="virtual-platform")] (existing PKCS#11 path)
  else / SGX_FORCE_SOFTWARE_KEYS → load_or_generate (software)

TPM init failure policy = mirror SE050: fail-closed on the TPM platform
  (unless SGX_FORCE_SOFTWARE_KEYS=1, which forces software — for CI/containers).
```

### 3.4 Config (env)

| Variable | Default | Meaning |
|---|---|---|
| `SGX_TPM_DEVICE` | `/dev/tpmrm0` | TCTI device (sets `TPM2TOOLS_TCTI=device:<path>`) |
| `SGX_TPM_DKP_HANDLE_BASE` | `0x81000010` | First DKP persistent handle (rotation increments) |
| `SGX_TPM_DIK_HANDLE` | `0x81000100` | Non-rotating DIK persistent handle |
| `SGX_TPM_EK_HANDLE` | `0x81010001` | EK persistent handle (UID anchor) |
| `SGX_TPM_PCR_SELECTION` | `sha256:0,2,4,7` | PCRs for measurement/quote |
| `SGX_FORCE_SOFTWARE_KEYS` | unset | Existing gate — bypass TPM, use software keys (CI/containers) |

---

## 4. Scope

### In scope (v1)
1. `tpm` Cargo feature + `src/tpm/` module (tpm2-tools shell-out wrapper, DIK, DKP, EK-UID, PCR, config, signer).
2. `SigningBackend::Tpm` variant wired into all `KeyManager` match arms + `KeyManager::init_with_tpm`.
3. UID seam: `did::method` sources the UID from the TPM EK when the TPM backend is active (preserving `did::derive`).
4. Native TPM **PCR read** feeding the existing PCR/VirtualID pipeline.
5. `main.rs` boot wiring + DIK provisioning (TPM analog of the SE050 DIK block).
6. Deployment: build flags, `/dev/tpmrm0` permissions, one-time provisioning sequence.
7. TPM-series verification (TPM-001…TPM-014).

### Phase 2 (explicitly deferred)
- Native `TPM2_Quote` attestation (stronger, hardware-rooted) — replaces/augments the DKP-signed evidence blob.
- `tss-esapi` in-process backend (remove the shell-out).
- `PlatformClass::Tpm` provider in the `platform::` trait layer (parallel to `VirtualHardwareProvider`) for the newer platform-abstraction path.
- TPM-sealed private DID-doc storage / NV-backed anti-rollback counters.

### Out of scope
- Any change to SE050, software, or virtual backends.
- Any change to `did::derive`, `did.json` schema, VirtualID, gossip, CRL, Nebula.
- aarch64/i.MX builds (TPM feature is x86/NUC-only).

---

## 5. Pre-Flight (on the NUC, before writing code)

Most is already answered by your dump. Fill the gaps:

```bash
# TCTI + capability (re-confirm on the target user context)
export TPM2TOOLS_TCTI="device:/dev/tpmrm0"
tpm2_getcap properties-fixed | grep -iE "manufacturer|vendor"     # INTC / ADL
tpm2_getcap algorithms | grep -iE "ecdsa|ecc|sha256"              # must list all three
tpm2_getcap commands | grep -iE "Sign|Quote|EvictControl|CreatePrimary|PCR_Read"
tpm2_pcrread sha256:0,2,4,7                                       # real values

# Persistent-handle headroom (we need 3 free: EK, DIK, DKP)
tpm2_getcap handles-persistent                                   # list what's already there
tpm2_getcap properties-variable | grep -iE "lockout|maxAuthFail|owner" # DA state / ownership

# EK + its (optional) certificate
tpm2_createek -c 0x81010001 -G ecc -u /tmp/ek.pub 2>&1 | head    # may already exist (that's fine)
tpm2_getekcertificate -o /tmp/ek.crt 2>&1 | head                 # Q4: present or not?

# Owner-hierarchy usable without auth? (fresh/cleared TPM usually yes)
tpm2_createprimary -C o -g sha256 -G ecc256 -c /tmp/prim.ctx 2>&1 | head

# tools + libs present
tpm2 version; which tpm2_sign tpm2_evictcontrol tpm2_readpublic
```
If `tpm2_createprimary -C o` needs owner auth, the TPM has an owner password set → note it; provisioning must supply `-P <ownerauth>`. If persistent handles are occupied, pick free ones and set the `SGX_TPM_*_HANDLE` envs.

---

## 6. File Structure

```
Cargo.toml                         MODIFIED  (add `tpm` feature)
src/key_manager.rs                 MODIFIED  (SigningBackend::Tpm + init_with_tpm + 5 match arms)
src/main.rs                        MODIFIED  (TPM boot branch + DIK provisioning block)
src/did/method.rs                  MODIFIED  (UID seam: source EK-UID when TPM backend active)
src/lib.rs                         MODIFIED  (pub mod tpm; behind cfg)
src/tpm/                           NEW MODULE (mirrors src/secure_element/)
├── mod.rs                         NEW  — TpmConfig, module wiring
├── tools.rs                       NEW  — Tpm2Cli: sync tpm2-tools shell-out wrapper (parallel to SssCli)
├── ek.rs                          NEW  — Endorsement Key → device UID (SHA256(EK_pub))
├── dik.rs                         NEW  — non-rotating DIK at 0x81000100 (parallel to secure_element::dik)
├── dkp.rs                         NEW  — rotating DKP at 0x81000010+ (parallel to secure_element::dkp)
├── signer.rs                      NEW  — TpmSigner::sign(handle, data) → raw r||s (parallel to SeSigner)
├── pcr.rs                         NEW  — native PCR read → measurement material
├── quote.rs                       NEW  — (Phase 2) native TPM2_Quote
└── tests.rs                       NEW  — parsing/format unit tests (no TPM needed)
src/secure_element/**              UNCHANGED
src/platform/**                    UNCHANGED (Phase 2 adds TpmHardwareProvider)
```

---

## 7. Implementation — `src/tpm/` (scaffolds + exact command sequences)

> These scaffolds are complete and correct in shape; the **⚙️ VERIFY ON CHIP** marks flag flags/formats to confirm against your `tpm2-tools 5.7`.

### 7.1 `src/tpm/mod.rs`

```rust
//! TPM 2.0 hardware root-of-trust backend (parallel to `secure_element`).
//!
//! Access is via a synchronous `tpm2-tools` shell-out (see `tools::Tpm2Cli`),
//! mirroring how the SE050 backend uses `ssscli`. Persistent handles hold the
//! DIK (non-rotating DID anchor) and the DKP (rotating operational key); the
//! Endorsement Key public hash provides the per-chip UID. Everything exports
//! the same `dik_pub.der` / `dkp_pub.der` (SPKI DER) artifacts the rest of the
//! pipeline already consumes, so DID/VirtualID/attestation are unchanged.

pub mod dik;
pub mod dkp;
pub mod ek;
pub mod pcr;
pub mod signer;
pub mod tools;
#[cfg(feature = "tpm")]
pub mod quote; // Phase 2 (compiles as a stub in v1)

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[derive(Debug, Clone)]
pub struct TpmConfig {
    pub device: String,          // e.g. /dev/tpmrm0
    pub dik_handle: u32,         // 0x81000100
    pub dkp_handle_base: u32,    // 0x81000010
    pub ek_handle: u32,          // 0x81010001
    pub pcr_selection: String,   // sha256:0,2,4,7
    pub owner_auth: Option<String>, // Some(pw) if owner hierarchy has auth
}

impl Default for TpmConfig {
    fn default() -> Self {
        Self {
            device: std::env::var("SGX_TPM_DEVICE")
                .unwrap_or_else(|_| "/dev/tpmrm0".to_string()),
            dik_handle: parse_handle("SGX_TPM_DIK_HANDLE", 0x8100_0100),
            dkp_handle_base: parse_handle("SGX_TPM_DKP_HANDLE_BASE", 0x8100_0010),
            ek_handle: parse_handle("SGX_TPM_EK_HANDLE", 0x8101_0001),
            pcr_selection: std::env::var("SGX_TPM_PCR_SELECTION")
                .unwrap_or_else(|_| "sha256:0,2,4,7".to_string()),
            owner_auth: std::env::var("SGX_TPM_OWNER_AUTH").ok().filter(|s| !s.is_empty()),
        }
    }
}

fn parse_handle(var: &str, default: u32) -> u32 {
    std::env::var(var)
        .ok()
        .and_then(|s| {
            let s = s.trim();
            let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
            u32::from_str_radix(s, 16).ok()
        })
        .unwrap_or(default)
}

#[derive(Debug, thiserror::Error)]
pub enum TpmError {
    #[error("tpm2 tool `{0}` failed: {1}")]
    Tool(String, String),
    #[error("tpm not available: {0}")]
    NotAvailable(String),
    #[error("tpm key error: {0}")]
    Key(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
```

### 7.2 `src/tpm/tools.rs` — the shell-out wrapper (parallel to `SssCli`)

```rust
//! Synchronous tpm2-tools wrapper. Parallels `secure_element::ssscli::SssCli`.
//! Synchronous by design: `KeyManager::sign` is sync and is called the same
//! way for SE050 today. Each call sets TPM2TOOLS_TCTI so tools never hunt for
//! a resource manager daemon.

use super::{TpmConfig, TpmError};
use std::process::Command;

pub struct Tpm2Cli {
    cfg: TpmConfig,
}

impl Tpm2Cli {
    pub fn new(cfg: TpmConfig) -> Self {
        Self { cfg }
    }

    fn tcti(&self) -> String {
        format!("device:{}", self.cfg.device)
    }

    /// Run a tpm2 tool with args; return stdout bytes on success.
    /// Stdin (optional) is used by tpm2_sign to pass the message.
    pub fn run(&self, tool: &str, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>, TpmError> {
        use std::io::Write;
        let mut cmd = Command::new(tool);
        cmd.env("TPM2TOOLS_TCTI", self.tcti());
        cmd.args(args);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        if stdin.is_some() {
            cmd.stdin(std::process::Stdio::piped());
        }
        let mut child = cmd.spawn().map_err(|e| TpmError::Tool(tool.into(), e.to_string()))?;
        if let (Some(data), Some(mut sink)) = (stdin, child.stdin.take()) {
            sink.write_all(data).map_err(|e| TpmError::Tool(tool.into(), e.to_string()))?;
        }
        let out = child.wait_with_output().map_err(|e| TpmError::Tool(tool.into(), e.to_string()))?;
        if !out.status.success() {
            return Err(TpmError::Tool(
                tool.into(),
                String::from_utf8_lossy(&out.stderr).trim().to_string(),
            ));
        }
        Ok(out.stdout)
    }

    /// `tpm2_getcap properties-fixed` smoke — is a TPM reachable?
    pub fn available(&self) -> bool {
        self.run("tpm2_getcap", &["properties-fixed"], None).is_ok()
    }

    /// List persistent handles (to check idempotency of provisioning).
    pub fn persistent_handles(&self) -> Result<String, TpmError> {
        Ok(String::from_utf8_lossy(&self.run("tpm2_getcap", &["handles-persistent"], None)?).to_string())
    }

    /// Read a persistent key's public in DER (SubjectPublicKeyInfo) to `out_path`.
    /// ⚙️ VERIFY ON CHIP: `-f der` yields SPKI DER (91 bytes for P-256), matching
    /// the SE050 export the pipeline already parses (65-byte point at offset 26).
    pub fn readpublic_der(&self, handle: u32, out_path: &str) -> Result<(), TpmError> {
        let h = format!("0x{:08X}", handle);
        self.run("tpm2_readpublic", &["-c", &h, "-f", "der", "-o", out_path], None)?;
        Ok(())
    }

    /// Whether a persistent handle already holds a key.
    pub fn handle_exists(&self, handle: u32) -> bool {
        let h = format!("0x{:08x}", handle); // getcap prints lowercase
        self.persistent_handles()
            .map(|s| s.to_lowercase().contains(&h))
            .unwrap_or(false)
    }
}
```

### 7.3 `src/tpm/ek.rs` — EK → device UID

```rust
//! Endorsement Key → per-chip UID for DID derivation.
//! UID = SHA256(EK_pub DER). Stable, non-migratable, unique per TPM.

use super::{TpmConfig, TpmError};
use super::tools::Tpm2Cli;
use sha2::{Digest, Sha256};

pub const EK_PUB_PATH: &str = "/var/lib/sgx-guardian/keys/ek_pub.der";

/// Ensure the EK exists at the configured handle and return the UID bytes
/// (32-byte SHA256 of the EK public DER). Idempotent.
pub fn ensure_uid(cfg: &TpmConfig) -> Result<Vec<u8>, TpmError> {
    let cli = Tpm2Cli::new(cfg.clone());
    if !cli.available() {
        // Fall back to a cached EK pub if the TPM is momentarily unreachable
        if let Ok(bytes) = std::fs::read(EK_PUB_PATH) {
            return Ok(Sha256::digest(&bytes).to_vec());
        }
        return Err(TpmError::NotAvailable("tpm2_getcap failed and no cached EK pub".into()));
    }

    // Create-or-reuse EK at the persistent handle. `tpm2_createek` is idempotent
    // for a given handle; if it already exists it succeeds/no-ops.
    // ⚙️ VERIFY ON CHIP: some tpm2-tools need `-t` template or accept existing handle.
    let h = format!("0x{:08X}", cfg.ek_handle);
    let _ = cli.run("tpm2_createek", &["-c", &h, "-G", "ecc", "-u", EK_PUB_PATH], None);

    // Read the EK public in DER (authoritative), then hash.
    if std::path::Path::new(EK_PUB_PATH).exists() && std::fs::metadata(EK_PUB_PATH)?.len() > 0 {
        // already written by createek -u
    } else {
        cli.readpublic_der(cfg.ek_handle, EK_PUB_PATH)?;
    }
    let der = std::fs::read(EK_PUB_PATH)?;
    Ok(Sha256::digest(&der).to_vec())
}
```

### 7.4 `src/tpm/dik.rs` — non-rotating anchor (parallel to `secure_element::dik`)

```rust
//! Device Identity Key (DIK) on TPM — PERMANENT, NON-ROTATING.
//! Persistent handle 0x81000100. Sole cryptographic anchor for did:guardian.

use super::{TpmConfig, TpmError};
use super::tools::Tpm2Cli;

pub const DIK_PUB_PATH: &str = "/var/lib/sgx-guardian/keys/dik_pub.der";

/// Idempotent. Ensures a P-256 DIK exists at cfg.dik_handle and exports its
/// public DER to DIK_PUB_PATH. Returns the DIK public DER bytes.
///
/// Provisioning sequence (⚙️ VERIFY ON CHIP — flags/templates):
///   tpm2_createprimary -C o -g sha256 -G ecc256 -c prim.ctx  [-P ownerauth]
///   tpm2_create  -C prim.ctx -g sha256 -G ecc256 -u dik.pub -r dik.priv \
///                -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign"
///   tpm2_load    -C prim.ctx -u dik.pub -r dik.priv -c dik.ctx
///   tpm2_evictcontrol -C o -c dik.ctx 0x81000100             [-P ownerauth]
///   tpm2_readpublic  -c 0x81000100 -f der -o dik_pub.der
pub fn ensure(cfg: &TpmConfig) -> Result<Vec<u8>, TpmError> {
    let cli = Tpm2Cli::new(cfg.clone());
    if cli.handle_exists(cfg.dik_handle) {
        cli.readpublic_der(cfg.dik_handle, DIK_PUB_PATH)?;
        return Ok(std::fs::read(DIK_PUB_PATH)?);
    }
    // Provision once. Use a temp workspace.
    let dir = tempfile::tempdir()?;
    let p = |name: &str| dir.path().join(name).to_string_lossy().to_string();
    let owner = cfg.owner_auth.clone();

    let mut primary = vec!["-C", "o", "-g", "sha256", "-G", "ecc256", "-c", &p("prim.ctx")];
    if let Some(pw) = owner.as_deref() { primary.extend(["-P", pw]); }
    cli.run("tpm2_createprimary", &primary, None)?;

    cli.run("tpm2_create", &[
        "-C", &p("prim.ctx"), "-g", "sha256", "-G", "ecc256",
        "-u", &p("dik.pub"), "-r", &p("dik.priv"),
        "-a", "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign",
    ], None)?;
    cli.run("tpm2_load", &[
        "-C", &p("prim.ctx"), "-u", &p("dik.pub"), "-r", &p("dik.priv"), "-c", &p("dik.ctx"),
    ], None)?;

    let h = format!("0x{:08X}", cfg.dik_handle);
    let mut evict = vec!["-C", "o", "-c", &p("dik.ctx"), &h];
    if let Some(pw) = owner.as_deref() { evict.extend(["-P", pw]); }
    cli.run("tpm2_evictcontrol", &evict, None)?;

    cli.readpublic_der(cfg.dik_handle, DIK_PUB_PATH)?;
    Ok(std::fs::read(DIK_PUB_PATH)?)
}
```

### 7.5 `src/tpm/dkp.rs` — rotating operational key (parallel to `secure_element::dkp`)

```rust
//! Device Key Pair (DKP) on TPM — ROTATING operational signing key.
//! Persistent handle base 0x81000010; version v → handle base+(v-1).
//! Reuses the existing DKP metadata/history layer for version tracking.

use super::{TpmConfig, TpmError};
use super::tools::Tpm2Cli;

pub const DKP_PUB_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_pub.der";

fn handle_for_version(cfg: &TpmConfig, version: u32) -> u32 {
    cfg.dkp_handle_base + version.saturating_sub(1)
}

/// Ensure the active DKP (version `v`) exists at its handle; export pub DER.
/// Same create→load→evict→readpublic sequence as DIK but a rotating handle
/// and NO fixedtpm/fixedparent (so it can be re-created on rotation).
pub fn ensure_active(cfg: &TpmConfig, version: u32) -> Result<u32, TpmError> {
    let cli = Tpm2Cli::new(cfg.clone());
    let handle = handle_for_version(cfg, version);
    if cli.handle_exists(handle) {
        cli.readpublic_der(handle, DKP_PUB_PATH)?;
        return Ok(handle);
    }
    let dir = tempfile::tempdir()?;
    let p = |n: &str| dir.path().join(n).to_string_lossy().to_string();
    let owner = cfg.owner_auth.clone();

    let mut primary = vec!["-C", "o", "-g", "sha256", "-G", "ecc256", "-c", &p("prim.ctx")];
    if let Some(pw) = owner.as_deref() { primary.extend(["-P", pw]); }
    cli.run("tpm2_createprimary", &primary, None)?;
    cli.run("tpm2_create", &[
        "-C", &p("prim.ctx"), "-g", "sha256", "-G", "ecc256",
        "-u", &p("dkp.pub"), "-r", &p("dkp.priv"),
        "-a", "sensitivedataorigin|userwithauth|sign",
    ], None)?;
    cli.run("tpm2_load", &[
        "-C", &p("prim.ctx"), "-u", &p("dkp.pub"), "-r", &p("dkp.priv"), "-c", &p("dkp.ctx"),
    ], None)?;
    let h = format!("0x{:08X}", handle);
    let mut evict = vec!["-C", "o", "-c", &p("dkp.ctx"), &h];
    if let Some(pw) = owner.as_deref() { evict.extend(["-P", pw]); }
    cli.run("tpm2_evictcontrol", &evict, None)?;
    cli.readpublic_der(handle, DKP_PUB_PATH)?;
    Ok(handle)
}

/// Rotate: create version v+1 at the next handle, export its pub, evict old.
/// (Mirror `secure_element::dkp::rotate`; reuse the shared DkpKeyHistory JSON.)
pub fn rotate(cfg: &TpmConfig, old_version: u32) -> Result<u32, TpmError> {
    let new_version = old_version + 1;
    let new_handle = ensure_active(cfg, new_version)?;
    // Evict the old handle so it can't sign anymore.
    let cli = Tpm2Cli::new(cfg.clone());
    let old_handle = handle_for_version(cfg, old_version);
    let oh = format!("0x{:08X}", old_handle);
    let mut evict = vec!["-C", "o", "-c", &oh]; // evict existing persistent handle = remove
    if let Some(pw) = cfg.owner_auth.as_deref() { evict.extend(["-P", pw]); }
    let _ = cli.run("tpm2_evictcontrol", &evict, None); // best-effort remove
    Ok(new_handle)
}
```

### 7.6 `src/tpm/signer.rs` — signing (parallel to `SeSigner`)

```rust
//! TPM signer. `sign(handle, data)` returns raw ECDSA r||s (64 bytes for
//! P-256), matching ring's ECDSA_P256_SHA256_FIXED so downstream verifiers
//! (verify_entry, attestation, VC) are unchanged.

use super::{TpmConfig, TpmError};
use super::tools::Tpm2Cli;

pub struct TpmSigner {
    cli: Tpm2Cli,
}

impl TpmSigner {
    pub fn new(cfg: &TpmConfig) -> Self {
        Self { cli: Tpm2Cli::new(cfg.clone()) }
    }

    /// Sign `data` with the key at persistent `handle`.
    /// tpm2_sign hashes internally (`-g sha256`) and `-f plain` emits the raw
    /// r||s bytes for ECDSA. ⚙️ VERIFY ON CHIP: confirm `-f plain` for ecdsa
    /// yields 64 bytes (r||s, 32+32). If it emits TPMT_SIGNATURE instead, parse
    /// the two TPM2B integers and concatenate to 64 bytes.
    pub fn sign(&self, handle: u32, data: &[u8]) -> Result<Vec<u8>, TpmError> {
        let h = format!("0x{:08X}", handle);
        let dir = tempfile::tempdir()?;
        let sig_path = dir.path().join("sig.bin").to_string_lossy().to_string();
        self.cli.run(
            "tpm2_sign",
            &["-c", &h, "-g", "sha256", "-s", "ecdsa", "-f", "plain", "-o", &sig_path],
            Some(data),
        )?;
        let sig = std::fs::read(&sig_path)?;
        if sig.len() != 64 {
            return Err(TpmError::Key(format!(
                "unexpected TPM signature length {} (expected 64 = r||s); check `-f plain`",
                sig.len()
            )));
        }
        Ok(sig)
    }
}
```

### 7.7 `src/tpm/pcr.rs` — native PCR read

```rust
//! Native PCR measurement. Replaces the OCOTP/HAB simulation on TPM platforms.
//! Returns the concatenated PCR digest material used by VirtualID.

use super::{TpmConfig, TpmError};
use super::tools::Tpm2Cli;
use sha2::{Digest, Sha256};

/// Read the configured PCR selection and return a stable digest over the
/// concatenated PCR values (hex-parsed). ⚙️ VERIFY ON CHIP: tpm2_pcrread text
/// format; prefer `-o <file>` binary output for stable parsing if available.
pub fn read_pcr_material(cfg: &TpmConfig) -> Result<Vec<u8>, TpmError> {
    let cli = Tpm2Cli::new(cfg.clone());
    let dir = tempfile::tempdir()?;
    let out = dir.path().join("pcr.bin").to_string_lossy().to_string();
    // Binary output is the most parse-stable across versions.
    cli.run("tpm2_pcrread", &[&cfg.pcr_selection, "-o", &out], None)?;
    let bytes = std::fs::read(&out)?;
    Ok(bytes)
}

pub fn pcr_digest(cfg: &TpmConfig) -> Result<String, TpmError> {
    Ok(hex::encode(Sha256::digest(read_pcr_material(cfg)?)))
}
```

### 7.8 `src/tpm/quote.rs` — Phase 2 stub

```rust
//! Native TPM2_Quote attestation (Phase 2). v1 keeps the DKP-signed evidence
//! blob; this module is a compiling stub until Phase 2.
//!
//! Phase 2 sequence (⚙️ VERIFY ON CHIP):
//!   tpm2_quote -c 0x81000010 -l sha256:0,2,4,7 -q <nonce_hex> \
//!              -m quote.msg -s quote.sig -o quote.pcr -g sha256
//! Verifier checks the quote signature with the DKP pubkey + PCR digest + nonce.

use super::{TpmConfig, TpmError};

pub fn generate_quote_stub(_cfg: &TpmConfig, _nonce: &str) -> Result<(), TpmError> {
    Ok(())
}
```

### 7.9 `src/tpm/tests.rs` — no-TPM unit tests

```rust
use super::{parse_handle_public_for_test as _, TpmConfig};

#[test]
fn config_defaults_and_env_handles() {
    // Defaults when env unset.
    std::env::remove_var("SGX_TPM_DIK_HANDLE");
    let cfg = TpmConfig::default();
    assert_eq!(cfg.dik_handle, 0x8100_0100);
    assert_eq!(cfg.dkp_handle_base, 0x8100_0010);
    assert_eq!(cfg.ek_handle, 0x8101_0001);
    assert!(cfg.pcr_selection.starts_with("sha256:"));
}

// Note: signer/dik/dkp/ek/pcr require a real TPM and are covered by the
// TPM-series board tests (TPM-001..TPM-014), not unit tests.
```

> Remove the `parse_handle_public_for_test` import line — it's a placeholder to force you to expose a tiny test hook or delete the line. Keep `config_defaults_and_env_handles` (uses only the public `TpmConfig::default`).

---

## 8. Integration Seams — FIND→REPLACE (verbatim anchors from the repo)

### F1 — `Cargo.toml` (add the feature)

**FIND (verbatim):**
```toml
[features]
default = ["secure-element"]
secure-element = []
virtual-platform = []
```

**REPLACE WITH:**
```toml
[features]
default = ["secure-element"]
secure-element = []
virtual-platform = []
tpm = []
```

### F2 — `src/lib.rs` (register the module)

Add near the other top-level `pub mod` declarations (pre-flight: `grep -n "pub mod secure_element;" src/lib.rs`):
```rust
#[cfg(feature = "tpm")]
pub mod tpm;
```

### F3 — `src/key_manager.rs` — the `SigningBackend` enum

**FIND (verbatim):**
```rust
pub enum SigningBackend {
    /// Software ECDSA via ring crate (Phase 1 default)
    Software,
    /// Hardware ECDSA via NXP SE050 secure element
    #[cfg(feature = "secure-element")]
    Hardware { signer: SeSigner, key_id: u32 },
    /// Virtual dev keystore with persisted ECDSA key material.
    #[cfg(feature = "virtual-platform")]
    Pkcs11 {
        node_id: String,
        raw_public_key: Vec<u8>,
        public_key_spki_der: Vec<u8>,
    },
}
```

**REPLACE WITH:**
```rust
pub enum SigningBackend {
    /// Software ECDSA via ring crate (Phase 1 default)
    Software,
    /// Hardware ECDSA via NXP SE050 secure element
    #[cfg(feature = "secure-element")]
    Hardware { signer: SeSigner, key_id: u32 },
    /// Virtual dev keystore with persisted ECDSA key material.
    #[cfg(feature = "virtual-platform")]
    Pkcs11 {
        node_id: String,
        raw_public_key: Vec<u8>,
        public_key_spki_der: Vec<u8>,
    },
    /// Hardware ECDSA via TPM 2.0 persistent handle (tpm2-tools shell-out).
    #[cfg(feature = "tpm")]
    Tpm {
        signer: crate::tpm::signer::TpmSigner,
        dkp_handle: u32,
    },
}
```

> Also add the `use` for `SeSigner`'s sibling if needed. `TpmSigner` is referenced by full path, so no new top-level `use` is required.

### F4 — `src/key_manager.rs` — `sign()` arm

**FIND (verbatim — the `virtual-platform` arm tail of `sign`):**
```rust
            #[cfg(feature = "virtual-platform")]
            SigningBackend::Pkcs11 { .. } => {
                let rng = SystemRandom::new();
                let sig = self
                    .keypair
                    .sign(&rng, data)
                    .map_err(|_| anyhow!("Failed to sign data with virtual keystore"))?;
                log_audit(
                    "system",
                    AuditCategory::Cryptography,
                    AuditSeverity::Info,
                    AuditAction::Used,
                    "Key used to sign data (virtual SoftHSM2 backend)",
                );
                Ok(sig.as_ref().to_vec())
            }
        }
    }
```

**REPLACE WITH:**
```rust
            #[cfg(feature = "virtual-platform")]
            SigningBackend::Pkcs11 { .. } => {
                let rng = SystemRandom::new();
                let sig = self
                    .keypair
                    .sign(&rng, data)
                    .map_err(|_| anyhow!("Failed to sign data with virtual keystore"))?;
                log_audit(
                    "system",
                    AuditCategory::Cryptography,
                    AuditSeverity::Info,
                    AuditAction::Used,
                    "Key used to sign data (virtual SoftHSM2 backend)",
                );
                Ok(sig.as_ref().to_vec())
            }
            #[cfg(feature = "tpm")]
            SigningBackend::Tpm { signer, dkp_handle } => {
                let sig = signer
                    .sign(*dkp_handle, data)
                    .map_err(|e| anyhow!("TPM sign failed: {}", e))?;
                log_audit(
                    "system",
                    AuditCategory::Cryptography,
                    AuditSeverity::Info,
                    AuditAction::Used,
                    "Key used to sign data (TPM 2.0 hardware)",
                );
                Ok(sig)
            }
        }
    }
```

### F5 — `src/key_manager.rs` — `pubkey_der()` arm

**FIND (verbatim — the `virtual-platform` arm tail of `pubkey_der`):**
```rust
            #[cfg(feature = "virtual-platform")]
            SigningBackend::Pkcs11 {
                raw_public_key,
                public_key_spki_der: _,
                node_id: _,
            } => Ok(raw_public_key.clone()),
        }
    }
```

**REPLACE WITH:**
```rust
            #[cfg(feature = "virtual-platform")]
            SigningBackend::Pkcs11 {
                raw_public_key,
                public_key_spki_der: _,
                node_id: _,
            } => Ok(raw_public_key.clone()),
            #[cfg(feature = "tpm")]
            SigningBackend::Tpm { .. } => {
                // Same convention as SE050: read exported DKP pubkey DER and
                // return the raw 65-byte EC point (SPKI DER: point at offset 26).
                let der = std::fs::read(crate::tpm::dkp::DKP_PUB_PATH).map_err(|e| {
                    anyhow!("TPM DKP pubkey missing at {}: {}", crate::tpm::dkp::DKP_PUB_PATH, e)
                })?;
                if der.len() == 91 {
                    Ok(der[26..].to_vec())
                } else if der.len() == 65 {
                    Ok(der)
                } else {
                    Err(anyhow!("TPM DKP pubkey unexpected length {}", der.len()))
                }
            }
        }
    }
```

### F6 — `src/key_manager.rs` — `runtime_public_key_export()` arm

**FIND (verbatim):**
```rust
            #[cfg(feature = "virtual-platform")]
            SigningBackend::Pkcs11 {
                public_key_spki_der,
                ..
            } => Ok(public_key_spki_der.clone()),
        }
    }
```

**REPLACE WITH:**
```rust
            #[cfg(feature = "virtual-platform")]
            SigningBackend::Pkcs11 {
                public_key_spki_der,
                ..
            } => Ok(public_key_spki_der.clone()),
            #[cfg(feature = "tpm")]
            SigningBackend::Tpm { .. } => std::fs::read(crate::tpm::dkp::DKP_PUB_PATH)
                .map_err(|e| anyhow!("read TPM runtime pubkey export: {}", e)),
        }
    }
```

### F7 — `src/key_manager.rs` — `backend_name()` arm

**FIND (verbatim):**
```rust
    pub fn backend_name(&self) -> &str {
        match &self.backend {
            SigningBackend::Software => "Software",
            #[cfg(feature = "secure-element")]
            SigningBackend::Hardware { .. } => "SE050",
            #[cfg(feature = "virtual-platform")]
            SigningBackend::Pkcs11 { .. } => "SoftHSM2",
        }
    }
```

**REPLACE WITH:**
```rust
    pub fn backend_name(&self) -> &str {
        match &self.backend {
            SigningBackend::Software => "Software",
            #[cfg(feature = "secure-element")]
            SigningBackend::Hardware { .. } => "SE050",
            #[cfg(feature = "virtual-platform")]
            SigningBackend::Pkcs11 { .. } => "SoftHSM2",
            #[cfg(feature = "tpm")]
            SigningBackend::Tpm { .. } => "TPM2",
        }
    }
```

### F8 — `src/key_manager.rs` — `refresh_for_active_dkp()` arm

**FIND (verbatim):**
```rust
            #[cfg(feature = "virtual-platform")]
            SigningBackend::Pkcs11 { node_id, .. } => {
                Self::init_virtual_pkcs11(node_id, &self.key_path).map(Some)
            }
        }
    }
```

**REPLACE WITH:**
```rust
            #[cfg(feature = "virtual-platform")]
            SigningBackend::Pkcs11 { node_id, .. } => {
                Self::init_virtual_pkcs11(node_id, &self.key_path).map(Some)
            }
            #[cfg(feature = "tpm")]
            SigningBackend::Tpm { .. } => {
                let cfg = crate::tpm::TpmConfig::default();
                Self::init_with_tpm(&cfg, "/var/lib/sgx-guardian", &self.key_path).map(Some)
            }
        }
    }
```

### F9 — `src/key_manager.rs` — add `init_with_tpm` (new method, place next to `init_with_se050`)

Add this method inside `impl KeyManager` (anchor: right after the `init_with_se050` method closes):

```rust
    /// Initialize KeyManager with the TPM 2.0 backend.
    /// Provisions/loads DIK (anchor) + DKP (rotating) as persistent handles,
    /// exports dik_pub.der / dkp_pub.der, and keeps a software reference key
    /// for pubkey helpers (same tolerance-to-corrupt-fallback rule as SE050).
    #[cfg(feature = "tpm")]
    pub fn init_with_tpm(
        cfg: &crate::tpm::TpmConfig,
        base_path: &str,
        fallback_key_path: &str,
    ) -> Result<Self> {
        use crate::tpm::{dik, dkp, ek, signer::TpmSigner};
        info!("Initializing KeyManager with TPM 2.0 backend...");

        // 1) Ensure EK (UID anchor) + DIK (DID anchor) exist.
        let _uid = ek::ensure_uid(cfg).map_err(|e| anyhow!("TPM EK/UID: {}", e))?;
        let _dik_pub = dik::ensure(cfg).map_err(|e| anyhow!("TPM DIK: {}", e))?;

        // 2) Determine active DKP version from the shared history JSON (default v1).
        let version = crate::secure_element::key_meta::DkpKeyHistory::load(
            &format!("{}/keys/dkp_metadata.json", base_path),
        )
        .ok()
        .and_then(|h| h.active_key().map(|k| k.version))
        .unwrap_or(1);

        // 3) Ensure the active DKP persistent handle + export dkp_pub.der.
        let dkp_handle = dkp::ensure_active(cfg, version).map_err(|e| anyhow!("TPM DKP: {}", e))?;
        let signer = TpmSigner::new(cfg);

        // 4) Keep a software reference keypair for pubkey_der() plumbing paths
        //    that expect a ring keypair present (tolerate corrupt fallback).
        let rng = SystemRandom::new();
        let fb = Path::new(fallback_key_path);
        if let Some(parent) = fb.parent() { fs::create_dir_all(parent).ok(); }
        let pkcs8 = if fb.exists() {
            let raw = fs::read(fb).unwrap_or_default();
            match EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &raw, &rng) {
                Ok(_) => raw,
                Err(_) => {
                    let q = format!("{}.corrupt.{}", fallback_key_path, chrono::Utc::now().timestamp());
                    let _ = fs::rename(fb, &q);
                    let p = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                        .map_err(|_| anyhow!("gen fallback"))?;
                    write_private_key(fallback_key_path, p.as_ref())?;
                    p.as_ref().to_vec()
                }
            }
        } else {
            let p = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .map_err(|_| anyhow!("gen fallback"))?;
            write_private_key(fallback_key_path, p.as_ref())?;
            p.as_ref().to_vec()
        };
        let keypair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8, &rng)
            .map_err(|_| anyhow!("load fallback keypair"))?;

        log_audit("system", AuditCategory::Identity, AuditSeverity::Info, AuditAction::Loaded,
            &format!("DKP initialized via TPM 2.0 (handle=0x{:08X}, v{})", dkp_handle, version));

        Ok(Self { keypair, key_path: fallback_key_path.to_string(),
                  backend: SigningBackend::Tpm { signer, dkp_handle } })
    }
```

### F10 — `src/main.rs` — TPM boot branch

The current KeyManager init is a `#[cfg(feature="secure-element")] let km = {...}` / `#[cfg(not(...))] let km = load_or_generate`. Add a TPM branch. Pre-flight: `grep -n "init_with_se050" src/main.rs`. Insert a mutually-exclusive TPM branch **above** the software fallback:

```rust
    #[cfg(feature = "tpm")]
    let km = {
        let tpm_cfg = sgx_guardian_client::tpm::TpmConfig::default();
        if GATES.force_software_keys {
            KeyManager::load_or_generate(&node_key_path)?
        } else {
            match KeyManager::init_with_tpm(&tpm_cfg, "/var/lib/sgx-guardian", &node_key_path) {
                Ok(k) => { println!("DKP initialized via TPM 2.0 hardware"); k }
                Err(e) => {
                    eprintln!("TPM init failed: {} — fail-closed on TPM platform (set \
                               SGX_FORCE_SOFTWARE_KEYS=1 to override for CI)", e);
                    return Err(e);
                }
            }
        }
    };
```
And gate the existing SE050 `let km` block so exactly one is compiled — the three hardware features (`tpm`, `secure-element`, `virtual-platform`) are mutually exclusive at build time. (⚙️ Confirm the `#[cfg]` combination compiles cleanly; if both `secure-element` and `tpm` were ever enabled together you'd get two `let km` — enforce one via a `compile_error!` guard, below.)

Optional build-time guard (top of `main.rs`):
```rust
#[cfg(all(feature = "tpm", feature = "secure-element"))]
compile_error!("Enable exactly one hardware backend: `tpm` OR `secure-element`, not both.");
```

### F11 — `src/main.rs` — DIK provisioning block (TPM analog)

Right after the existing `#[cfg(feature = "secure-element")] { ... DeviceIdentityKey::ensure ... }` block, add:
```rust
    #[cfg(feature = "tpm")]
    {
        if km.backend_name() == "TPM2" && !GATES.force_software_keys {
            let cfg = sgx_guardian_client::tpm::TpmConfig::default();
            match sgx_guardian_client::tpm::dik::ensure(&cfg) {
                Ok(_) => println!("🔑 TPM DIK ready (handle 0x81000100, non-rotating)"),
                Err(e) => eprintln!("⚠️ TPM DIK ensure failed: {} — DID uses cached anchor if present", e),
            }
        }
    }
```

### F12 — `src/did/method.rs` — UID seam

The current `read_uid(node_id)` sources the SE050 UID from `secure_element::pcr::read_device_uid`. Pre-flight to see the exact function: `grep -n "fn read_uid" src/did/method.rs` and `grep -n "read_device_uid" src/secure_element/pcr.rs`. Then make `read_uid` dispatch by active backend. The minimal change (keeps `derive()` and `DerivationProof` intact):

```rust
// Inside read_uid(...), before falling back to the SE050 UID reader:
#[cfg(feature = "tpm")]
{
    let cfg = crate::tpm::TpmConfig::default();
    if let Ok(uid_bytes) = crate::tpm::ek::ensure_uid(&cfg) {
        let uid_string = hex::encode(&uid_bytes);
        return Ok((uid_string, "tpm-ek".to_string(), uid_bytes));
    }
}
// ... existing SE050 / fallback UID path unchanged ...
```
> The exact signature of `read_uid` must be confirmed on the branch (it returns `(String, String, Vec<u8>)` = uid_string, uid_source, uid_bytes based on the call site `let (uid_string, uid_source, uid_bytes) = read_uid(node_id)?;`). Adapt the early-return to match.

---

## 9. Constraint Compliance (project hard rules)

| Rule | Compliance |
|---|---|
| No `std::thread::sleep` / sync blocking in the **tokio async** path | The TPM shell-out is **synchronous**, called from `KeyManager::sign` (already sync) and from the **synchronous** boot-init path — exactly like SE050's `SeSigner`/ssscli. No blocking call is introduced into `NebulaDaemon::start()` or any async daemon loop. |
| Don't touch `NebulaDaemon::start()` / daemon lifecycle | Untouched. |
| ECDSA-P256 + SHA-256 only | TPM keys are `ecc256` + `sha256`; signatures are raw `r‖s` matching `ECDSA_P256_SHA256_FIXED`. Confirmed available on the chip. |
| Additive; SE050 / software / virtual untouched | New feature + new module + new enum arm. All existing arms unchanged (edits only *append* arms). |
| Yocto/aarch64 boards | The `tpm` feature is **not** built for aarch64 (no TPM there). Shell-out ⇒ no cross-compile linkage. The i.MX board binary keeps building `--features secure-element`. |
| Board-freeze vectors (OCOTP mmap, etc.) | N/A on TPM; PCR comes from the TPM natively, no `/dev/mem`. |
| Secret hygiene | Private DIK/DKP never leave the TPM; only public DER is exported. Fallback software key written 0600 via `write_private_key`. |

---

## 10. Deployment Guide — NUC (TPM platform)

**Build (NUC = TPM-only, x86_64):**
```bash
cargo build --release --no-default-features --features tpm
# (NOT --features secure-element — there is no SE050 on the NUC)
```

**TPM device permissions (fixes the `Permission denied` from your dump):**
```bash
# Option A (simplest for a dedicated appliance): run the daemon as root.
# Option B (service user): add it to the tss group + udev rule:
sudo usermod -aG tss <service-user>
# /dev/tpmrm0 is typically group tss, mode 0660 by default on Ubuntu.
ls -l /dev/tpmrm0        # confirm group 'tss', mode crw-rw----
# Ensure tpm2-tools present:
sudo apt-get install -y tpm2-tools    # (already present per your dump)
```

**One-time provisioning + first run:**
```bash
export TPM2TOOLS_TCTI="device:/dev/tpmrm0"
# (If the owner hierarchy has a password, also: export SGX_TPM_OWNER_AUTH=...)
sudo -E ./sgx_guardian_client nodeA
# Expect on first boot:
#   DKP initialized via TPM 2.0 hardware
#   🔑 TPM DIK ready (handle 0x81000100, non-rotating)
#   ✅ DID active: did:guardian:...
```

**What lands on the TPM (persistent handles):**
```
0x81010001  EK        (UID anchor — SHA256(EK_pub) → did)
0x81000100  DIK       (non-rotating DID anchor key)
0x81000010  DKP v1    (rotating operational signer; v2 → 0x81000011, ...)
```
Idempotent: re-running reuses existing handles; it never re-provisions the DIK if present (identity stability — same guard philosophy as SE050's DIK).

**Multi-node on NUCs:** each NUC has its own TPM ⇒ its own EK ⇒ its own DID. Run nodeA/nodeB/nodeC on three NUCs exactly like the three i.MX boards. (For a single-NUC 3-node dev cohort, that would need software keys per the containerization discussion — a single TPM can't cleanly back three distinct node identities, same caveat as one SE050 backing three containers.)

---

## 11. Verification Plan — TPM-series

| Tag | Check | Command / expectation |
|---|---|---|
| TPM-001 | TPM reachable from the daemon's user | `TPM2TOOLS_TCTI=device:/dev/tpmrm0 tpm2_getcap properties-fixed` → INTC/ADL, no perms error |
| TPM-002 | Feature build | `cargo build --release --no-default-features --features tpm` → clean |
| TPM-003 | Unit tests | `cargo test --no-default-features --features tpm tpm::` → green |
| TPM-004 | EK/UID stable | run twice; `hex(SHA256(ek_pub.der))` identical both runs |
| TPM-005 | DIK provisioned + persistent | after boot: `tpm2_getcap handles-persistent` lists `0x81000100`; `dik_pub.der` is 91 bytes |
| TPM-006 | DKP provisioned + exports | `0x81000010` present; `dkp_pub.der` 91 bytes; `km.backend_name()=="TPM2"` in `/api/v1/dkp/status` |
| TPM-007 | Sign round-trips | daemon signs (e.g. a DID-doc publish); external `p256` verify of the 64-byte sig against `dkp_pub.der` point → OK |
| TPM-008 | DID derives + stable across reboot | `did:guardian:...` printed; reboot → same DID (pinned DIK); no `DerivationMismatch` |
| TPM-009 | PCR read | `/api/v1/pcr/status` shows values matching `tpm2_pcrread sha256:0,2,4,7` |
| TPM-010 | VirtualID computes | `/api/v1/vid/show` returns a VID; changes only on real PCR/policy/DKP change |
| TPM-011 | Attestation still works | 2-node mutual attestation passes (DKP-signed evidence path unchanged) |
| TPM-012 | Gossip/CRL unaffected | CRL revoke + gossip converge across two NUCs (reuse CRL-series smoke) |
| TPM-013 | DKP rotation | trigger rotation → `0x81000011` appears, old handle evicted, DID unchanged, new sigs verify |
| TPM-014 | Fail-closed + override | unplug/deny TPM → daemon fail-closed; `SGX_FORCE_SOFTWARE_KEYS=1` → boots on software keys |

---

## 12. Rollback

- **Instant:** build/run with SE050 or software as before — the `tpm` feature is opt-in at compile time; a non-`tpm` binary has zero TPM code.
- **On-TPM cleanup (if abandoning):** `tpm2_evictcontrol -C o -c 0x81000100`, `... 0x81000010`, `... 0x81010001` to release the persistent handles.
- **Source:** revert the branch (1 feature line + 1 lib line + `src/tpm/` + the enum/arm edits + main.rs branch). SE050/software/virtual arms were only *appended to*, so reverting is clean; no schema/data migration (TPM used the existing `did.json`/`DkpKeyHistory` shapes).

---

## 13. Known Differences & Limitations vs SE050

| # | Item | Note |
|---|---|---|
| L1 | **Identity is chip-bound** | NUC/TPM DID ≠ i.MX/SE050 DID. Can't migrate an identity between chip types. Fresh cohort = fine. |
| L2 | **No direct tamper applet** | TPM has no SE050-style tamper pin. Use PCR-change detection + DA-lockout status as the analog (Phase 2). |
| L3 | **`DerivationProof` field names** | Reused `se050_uid`/`se050_uid_source` with `"tpm-ek"` source (schema-stable). Rename to generic is a separate refactor. |
| L4 | **Shell-out latency** | tpm2-tools spawn per sign is fine for SGX's signing cadence (identical model to ssscli), but heavier than in-process. `tss-esapi` is the Phase-2 upgrade. |
| L5 | **Signature framing** | Assumes `tpm2_sign -f plain` → 64-byte r‖s. If your tools emit TPMT_SIGNATURE, add a small parser (⚙️ VERIFY ON CHIP, `signer.rs`). |
| L6 | **Owner-auth TPMs** | If the owner hierarchy has a password, set `SGX_TPM_OWNER_AUTH`; provisioning passes `-P`. A locked/owned TPM may need `tpm2_clear` (destructive) or the existing owner secret. |
| L7 | **Native quote deferred** | v1 keeps DKP-signed evidence attestation (works today). Native `TPM2_Quote` (Phase 2) is the stronger, hardware-rooted attestation the "Hardware Attestation Protocol" deliverable ideally wants. |
| L8 | **Single TPM ≠ multi-identity** | One TPM can't cleanly anchor three distinct node identities (same as one SE050 for three containers). Multi-node = multi-NUC, or software keys for a single-box cohort. |

---

## 14. Effort & Sequencing (honest)

This is **not** a one-sitting additive module. Suggested order:
1. Pre-flight §5 on the NUC (resolve Q3/Q4/owner-auth, confirm `-f der`/`-f plain` formats). *Biggest unknowns live here — do this first.*
2. `src/tpm/tools.rs` + `ek.rs` + a throwaway `main` that prints the UID → prove the shell-out + EK path on the chip.
3. `dik.rs` + `dkp.rs` + `signer.rs` → prove provisioning + a verifiable signature (TPM-004…007) **standalone**, before touching KeyManager.
4. Wire the `SigningBackend::Tpm` arms + `init_with_tpm` (F3–F9) → daemon boots on TPM (TPM-006/008).
5. UID seam (F12) + PCR (F7 module) → DID + VirtualID (TPM-008/009/010).
6. Full node bring-up + 2-NUC attestation/gossip/CRL (TPM-011/012), rotation (TPM-013), fail-closed (TPM-014).
7. Phase 2: native quote, `tss-esapi`, `PlatformClass::Tpm` provider.

Steps 2–3 are where the real hardware iteration is; once a signature verifies against `dkp_pub.der`, the rest slots into seams that are already proven by the SE050 path.
