# SG-X Guardian Calling - Technical Dependencies & Integration Checklist

**Date:** July 15, 2026  
**Purpose:** Detailed technical dependencies, Cargo.toml additions, and integration verification points  

---

## Part 1: Cargo.toml Dependencies (Phase 4 & Later)

### Phase 4 Required Additions

Add these to `Cargo.toml` dependencies section:

```toml
# WebRTC Engine (Evaluate: str0m first, fallback to webrtc or pion-webrtc-rs)
# str0m: Rust-native, actively maintained, good for real-time
str0m = "0.4"                    # [Recommended]

# Alternative if str0m has licensing/dependency issues:
# webrtc = "0.9"                 # Pure Rust, learning-friendly but evolving
# (OR) pion-webrtc-rs = "0.3"   # Pion binding, mature but external dependency

# Audio Codec (Opus)
opus = "0.3"                     # OR audiopus = "0.3" for higher-level API

# STUN (ICE connectivity check)
stun = "0.5"                     # STUN client library

# Serialization for SDP (Session Description Protocol)
serde_json = "1"                 # [Already present in Cargo.toml]

# Optional: Async utilities for concurrent media processing
futures = "0.3"                  # [Likely already present]

# Optional: FFI bindings for video codecs (Phase 5+)
# libvpx-sys = "0.1"            # (Later) FFI to libvpx (VP9 encoding)
# libaom-sys = "0.1"            # (Later) FFI to libaom (AV1 encoding)
```

### Phase 6 Additions (Dev Dependencies for Benchmarking)

```toml
[dev-dependencies]
criterion = "0.5"                # Benchmarking harness
tokio-test = "0.4"               # Test utilities for async code
proptest = "1.0"                 # Property-based testing
```

---

## Part 2: Existing Module Integration Points

### Modules Already in Codebase (Reused)

| Module | File(s) | Integration Point | Required Method |
|--------|---------|-------------------|-----------------|
| **Certificate Service** | `src/cert_service.rs` | Verify device certs in call offers | `verify_certificate()` |
| **Attestation** | `src/attestation_service.rs` | Validate SGX quotes | `verify_quote()` |
| **CRL** | `src/crl/` | Check revocation status | `is_revoked()` |
| **Policy Engine** | `src/policy_*.rs` | Load RBAC rules; check policy digest | `get_rbac_rules()`, `get_policy_digest()` |
| **Virtual ID** | `src/virtual_id*.rs` | Validate pseudo-identity tokens | `validate_virtualid()` |
| **Key Manager** | `src/key_manager.rs` | Sign/verify call offers | `sign()`, `verify_signature()` |
| **Nebula** | `src/nebula/` | Transport for signaling + ICE candidates | `send_message()`, `receive_message()` |
| **Audit** | `src/audit/` | Log all call events | `log_event()` |
| **TLS** | `src/tls.rs` | DTLS certificate/key setup | `create_certificate()` |
| **Discovery** | `src/discovery/` | Optional: resolve peer addresses | `resolve_peer()` |

### Integration Requirements Per Module

#### Certificate Service (`src/cert_service.rs`)
**Required interface:**
```rust
pub fn verify_certificate(cert: &[u8], ca_cert: &[u8]) -> Result<(), CertError> {
    // Verify cert signature, validity window, issuer
}
```
**Call flow:** Verification pipeline (Phase 2) calls this for Stage 1.

#### Attestation Service (`src/attestation_service.rs`)
**Required interface:**
```rust
pub fn verify_attestation_quote(quote: &[u8], expected_pcr: &[u8]) -> Result<(), AttestError> {
    // Validate SGX quote signature, PCR match, timestamp
}
```
**Call flow:** Verification pipeline (Phase 2) calls this for Stage 3.

#### CRL Module (`src/crl/`)
**Required interface:**
```rust
pub fn is_certificate_revoked(cert_serial: &str, local_crl: &Crl) -> Result<bool, CrlError> {
    // Check if cert is in revocation list
}
```
**Call flow:** Verification pipeline (Phase 2) calls this for Stage 2.

#### Policy Engine (`src/policy_*.rs`)
**Required interfaces:**
```rust
pub fn get_rbac_rules() -> Result<RbacRules, PolicyError> {
    // Return current RBAC table (Admin, Operator, Sensor, Camera, Robot roles)
}

pub fn get_policy_digest() -> Result<String, PolicyError> {
    // Return current policy digest (SHA-256 hash of policy document)
}

pub fn get_call_permission(caller_role: &Role, callee_role: &Role, media_type: &MediaType) -> bool {
    // Evaluate if call is permitted
}
```
**Call flow:** 
- Verification pipeline Stage 4 compares policy digests
- UEP (Phase 3) uses get_call_permission() for local gate
- Authorization (Phase 5) uses get_call_permission() for receiver-side check

#### Virtual ID Module (`src/virtual_id*.rs`)
**Required interface:**
```rust
pub fn validate_virtualid(virtualid: &str, device_cert: &DeviceCert) -> Result<(), VidError> {
    // Verify VirtualID resolves to device identity chain
}
```
**Call flow:** Verification pipeline (Phase 2) calls this for Stage 5.

#### Key Manager (`src/key_manager.rs`)
**Required interfaces:**
```rust
pub fn sign_data(data: &[u8]) -> Result<Vec<u8>, KeyError> {
    // Sign with device's ECDSA-P256 private key
}

pub fn verify_signature(data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), KeyError> {
    // Verify ECDSA-P256 signature
}
```
**Call flow:**
- Phase 1: Sign call offers
- Phase 2: Verify received offer signatures

#### Nebula Overlay (`src/nebula/`)
**Required interfaces:**
```rust
pub async fn send_message(peer_id: &str, msg: &[u8]) -> Result<(), NebulError> {
    // Send call offer/answer to peer over encrypted overlay
}

pub async fn receive_message() -> Result<(String, Vec<u8>), NebulError> {
    // Receive call offer/answer from peer
}
```
**Call flow:**
- Phase 1: Offers sent via Nebula
- Phase 4: ICE candidates exchanged via Nebula

#### Audit Module (`src/audit/`)
**Required interface:**
```rust
pub fn log_event(event: &AuditEvent) -> Result<(), AuditError> {
    // Log call initiation, verification results, auth decisions, state changes
}
```
**Call flow:** All call state transitions, auth decisions, failures logged to audit trail.

#### TLS Module (`src/tls.rs`)
**Required interfaces:**
```rust
pub fn create_self_signed_dtls_cert() -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    // Create ephemeral DTLS certificate + private key
}

pub fn derive_media_keys(dtls_secret: &[u8]) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    // Derive SRTP encryption/auth keys from DTLS secret
}
```
**Call flow:** Phase 4 (media engine) uses these for DTLS key negotiation.

---

## Part 3: New Module Dependencies (Internal)

### Phase 1: Call & Signaling

```
src/call/mod.rs
  ├─ depends on: src/key_manager.rs (sign offers)
  ├─ depends on: src/nebula/ (send/receive)
  ├─ depends on: src/audit/ (log events)
  ├─ depends on: src/virtual_id*.rs (embed VirtualID)
  └─ depends on: src/tls.rs (context for Nebula)
```

### Phase 2: Verification Pipeline

```
src/call/verify/mod.rs
  ├─ Stage 1 (cert): depends on src/cert_service.rs
  ├─ Stage 2 (CRL): depends on src/crl/
  ├─ Stage 3 (attestation): depends on src/attestation_service.rs
  ├─ Stage 4 (policy digest): depends on src/policy_*.rs
  ├─ Stage 5 (virtualid): depends on src/virtual_id*.rs
  └─ all stages: depend on src/audit/ (log failures)
```

### Phase 3: UEP Enforcement

```
src/enforcement/uep.rs
  ├─ depends on: src/policy_*.rs (get RBAC rules)
  ├─ depends on: src/key_manager.rs (extract role from cert)
  └─ depends on: src/audit/ (log UEP decisions)
```

### Phase 4: Media Engine

```
src/media/mod.rs
  ├─ depends on: WebRTC crate (str0m or webrtc)
  ├─ depends on: src/nebula/ (ICE candidate exchange)
  ├─ depends on: src/tls.rs (DTLS cert + key derivation)
  ├─ depends on: opus crate (audio codec)
  ├─ depends on: stun crate (STUN client)
  └─ depends on: src/audit/ (log media events)
```

### Phase 5: Authorization & Enforcement

```
src/call/authorize/receiver_check.rs
  ├─ depends on: src/enforcement/uep.rs (reuse RBAC logic)
  └─ depends on: src/audit/ (log authorization decisions)

src/call/enforce/media_downgrade.rs
  ├─ depends on: src/policy_*.rs (monitor for changes)
  ├─ depends on: src/media/ (stop/start streams)
  └─ depends on: src/audit/ (log downgrade events)
```

---

## Part 4: Existing Code Verification Checklist

Before Phase 1 begins, verify these existing modules:

### ✅ Check: `src/key_manager.rs`

```bash
# Does it export these functions?
grep -n "pub fn sign\|pub fn verify_signature" src/key_manager.rs

# Required: ECDSA-P256 key pair already initialized
grep -n "p256\|ECDSA" src/key_manager.rs
```

**Expected output:** Key manager uses `ring` or `p256` crate for ECDSA signing.

### ✅ Check: `src/cert_service.rs`

```bash
# Does it have cert validation?
grep -n "pub fn verify\|pub fn is_valid\|pub fn check_expired" src/cert_service.rs

# Is it using rcgen or rustls for cert handling?
grep -n "rcgen\|rustls" src/cert_service.rs
```

**Expected output:** Certificate validation functions exist.

### ✅ Check: `src/attestation_service.rs`

```bash
# Does it verify SGX quotes?
grep -n "pub fn verify.*quote\|pub fn validate.*quote" src/attestation_service.rs

# Check for PCR handling
grep -n "PCR\|pcr" src/attestation_service.rs
```

**Expected output:** Quote verification function exists.

### ✅ Check: `src/crl/` Directory

```bash
# Does CRL module exist?
ls -la src/crl/

# Does it have revocation check?
grep -n "pub fn.*revoke\|pub fn.*is_revoked" src/crl/*.rs
```

**Expected output:** CRL module with revocation check function.

### ✅ Check: `src/policy_*.rs` Files

```bash
# List policy-related files
ls -la src/policy*.rs

# Check for RBAC rules loading
grep -n "pub fn.*rbac\|pub fn.*rules\|pub fn.*permission" src/policy*.rs

# Check for policy digest
grep -n "pub fn.*digest\|pub fn.*hash" src/policy*.rs
```

**Expected output:** Policy loading and RBAC rule functions exist.

### ✅ Check: `src/nebula/` Directory

```bash
# Does Nebula overlay exist?
ls -la src/nebula/

# Check for send/receive functions
grep -n "pub.*async.*fn.*send\|pub.*async.*fn.*recv" src/nebula/*.rs
```

**Expected output:** Nebula messaging interface.

### ✅ Check: `src/audit/` Directory

```bash
# Does audit module exist?
ls -la src/audit/

# Check for event logging
grep -n "pub fn.*log\|pub fn.*record\|pub fn.*event" src/audit/*.rs
```

**Expected output:** Audit event logging interface.

### ✅ Check: `src/virtual_id*.rs` Files

```bash
# Do virtual ID functions exist?
grep -n "pub fn.*virtual\|pub fn.*virtualid\|pub fn.*validate" src/virtual_id*.rs

# Check for VirtualID structure
grep -n "struct VirtualID\|pub struct" src/virtual_id*.rs
```

**Expected output:** VirtualID types and validation functions.

---

## Part 5: Build & Compilation Verification

### Pre-Phase-1 Verification Commands

```bash
# 1. Ensure existing code compiles without calling modules
cd /home/abraam/SGX
cargo build --release 2>&1 | head -20

# 2. Run existing test suite to establish baseline
cargo test --lib 2>&1 | tail -20

# 3. Check for any breaking changes in dependencies
cargo update --dry-run 2>&1 | grep "BREAKING"

# 4. Verify key crates are available
cargo search rustls 2>&1 | head -3
cargo search ring 2>&1 | head -3

# 5. Optionally check WebRTC crate availability (Phase 4 reference)
cargo search str0m 2>&1 | head -3
cargo search opus 2>&1 | head -3
```

### Phase-by-Phase Build Checklist

| Phase | Build Command | Expected Result |
|-------|---------------|-----------------|
| Phase 1 | `cargo build --release` | Compiles; no link errors |
| Phase 1 | `cargo test --lib call::` | All call/* unit tests pass |
| Phase 2 | `cargo build --release` | Compiles; verify module passes |
| Phase 3 | `cargo build --release` | Compiles; enforcement::uep module passes |
| Phase 4 | `cargo build --release` | Compiles; webrtc crate links successfully |
| Phase 5 | `cargo build --release` | Compiles; all media modules link |
| Phase 6 | `cargo test` | All tests pass; coverage >85% |

---

## Part 6: Dependency Version Constraints

### Stable Versions (No Beta/Alpha)

```toml
# Core (already in Cargo.toml, ensure versions lock)
tokio = "~1.37"                  # No 2.0 beta
serde = "~1.0"                   # Stable
axum = "~0.7"                    # No breaking changes
rustls = "~0.23"                 # Stable TLS

# New for Phase 4
str0m = "~0.4"                   # Or webrtc "~0.9"
opus = "~0.3"                    # Stable audio codec
stun = "~0.5"                    # Stable STUN library

# Avoid:
# webrtc = "0.1-rc1"             # ❌ Pre-release
# str0m = "*"                    # ❌ Unstable wildcard
```

### License Compatibility

All new crates must have one of:
- Apache 2.0
- MIT
- GPL 3.0 (if compatible with project)
- BSD 2/3-Clause

Check before adding:
```bash
cargo add --dry-run str0m
# Review license output before confirming
```

---

## Part 7: Offline Mode Dependencies

### Cached Data Required (All Phases)

For offline calling to work, devices must cache:

| Data | Cache Location | Refresh Trigger |
|------|----------------|-----------------|
| Own device certificate | `~/.sgx-guardian/certs/device.pem` | Manual or daily |
| PA-CA public key | `~/.sgx-guardian/certs/ca-public.pem` | Manual or quarterly |
| CRL snapshot | `~/.sgx-guardian/cache/crl.json` | Hourly (if online) |
| Policy digest | `~/.sgx-guardian/cache/policy-digest` | On policy change |
| RBAC rules | `~/.sgx-guardian/cache/rbac.json` | On policy change |
| Circle of Trust | `~/.sgx-guardian/cache/peers-whitelist.json` | Manual or daily |

### Verification Pipeline Offline Capability

All five verification stages must work with cached data only:

| Stage | Offline Dependency | Fallback |
|-------|------------------|----------|
| Stage 1: Cert validity | Own CA cert (cached) | Use until cache expires |
| Stage 2: CRL check | CRL snapshot (cached) | Use; note "cache age" in audit |
| Stage 3: Attestation | Enclave measurement (cached) | Compare against expected value |
| Stage 4: Policy digest | Policy document (cached) | Detect mismatch; alert user |
| Stage 5: VirtualID | Peer identity chain (cached) | Resolve using whitelist |

**Important:** If cache is stale (e.g., CRL >24h old), call proceeds but audit logs "verification with stale data."

---

## Part 8: Testing Infrastructure Dependencies

### Test Utilities Required

```rust
// For mocking Nebula overlay
#[cfg(test)]
mod mock_nebula {
    pub async fn mock_send(msg: Vec<u8>) -> Result<(), Error> { }
    pub async fn mock_receive() -> Result<(String, Vec<u8>), Error> { }
}

// For generating test certificates
#[cfg(test)]
mod test_certs {
    pub fn create_test_cert(valid_days: u32) -> Vec<u8> { }
    pub fn create_revoked_cert() -> Vec<u8> { }
}

// For simulating policy changes
#[cfg(test)]
mod mock_policy {
    pub fn set_rbac_rules(rules: &RbacRules) { }
    pub fn set_policy_digest(digest: &str) { }
}

// For capturing audit logs in tests
#[cfg(test)]
mod audit_capture {
    pub fn capture_events() -> Vec<AuditEvent> { }
}
```

### Integration Test Framework

- Use `tokio-test` for async code testing
- Use `proptest` for property-based fuzzing (state transitions)
- Use `criterion` for benchmarking (Phase 6)

---

## Part 9: Security Review Checklist (Per Phase)

### Phase 1 Security Review

- [ ] Call offers are always signed (never sent unsigned)
- [ ] Offers are sent *only* over authenticated Nebula
- [ ] No fallback to unencrypted signaling
- [ ] Session IDs are cryptographically random

### Phase 2 Security Review

- [ ] All 5 verification stages execute in strict order
- [ ] No stage is skipped or short-circuited
- [ ] Any failure produces immediate call rejection
- [ ] Failures are audit-logged with full context

### Phase 3 Security Review

- [ ] UEP blocks unauthorized calls *before* Nebula signaling
- [ ] Policy rules are loaded from signed policy documents
- [ ] No hardcoded rules exist (all data-driven)

### Phase 4 Security Review

- [ ] Media packets never route through cloud (packet inspection)
- [ ] ICE candidates are filtered (no cloud TURN)
- [ ] DTLS uses ephemeral keys derived from DH exchange
- [ ] Codec implementations are from trusted sources

### Phase 5 Security Review

- [ ] Receiver-side authorization is independent of sender-side
- [ ] Policy changes mid-call don't create trust windows
- [ ] Downgrade logic can't be bypassed

---

## Part 10: Deployment Dependencies

### System-Level Requirements

```bash
# Linux kernel version (for netfilter / iptables if TURN needed)
uname -r                        # Kernel 5.0+ recommended

# OpenSSL libraries (for rustls if needed)
apt list --installed | grep -i openssl

# System audio libraries (for codec FFI, Phase 4+)
apt list --installed | grep -i 'libopus|libvpx|libaom'

# System build tools
rustc --version                 # 1.70+
cargo --version                 # 1.70+
```

### Docker / Container Deployment

If deploying in container:

```dockerfile
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libopus0 \
    libvpx7 \
    libaom3 \
    ca-certificates

# Build stage (separate)
FROM rust:1.75 as builder
RUN apt-get update && apt-get install -y build-essential
COPY . /build
WORKDIR /build
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim
COPY --from=builder /build/target/release/sgx_guardian /usr/local/bin/
ENTRYPOINT ["sgx_guardian"]
```

---

## Part 11: Documentation Generation

### Auto-Generated Docs

```bash
# Generate module documentation
cargo doc --no-deps --release

# View in browser
open target/doc/sgx_guardian_client/call/index.html

# Check for missing docs
cargo doc --no-deps 2>&1 | grep "missing docs"
```

### API Documentation (Swagger)

For REST endpoints, maintain:
```yaml
# docs/openapi_calling.yaml
paths:
  /api/v1/call/initiate:
    post:
      summary: "Initiate a call"
      parameters: [...]
      responses: [...]
```

---

## Part 12: Version Pinning

### Recommended: Cargo.lock

Commit `Cargo.lock` to version control to ensure reproducible builds:

```bash
git add Cargo.lock
git commit -m "Lock dependency versions for reproducibility"
```

### Minimum Version Specifications

```toml
# Allow patch updates only (most conservative)
str0m = "=0.4.0"

# Allow patch + minor updates (recommended)
str0m = "0.4"

# Allow minor + major updates (risky)
str0m = "*"
```

---

## Summary Table: All Dependencies

| Crate | Version | Purpose | Phase | Status |
|-------|---------|---------|-------|--------|
| tokio | 1.37 | Async runtime | All | ✅ Existing |
| serde | 1.0 | Serialization | All | ✅ Existing |
| axum | 0.7 | HTTP framework | All | ✅ Existing |
| rustls | 0.23 | TLS/mTLS | All | ✅ Existing |
| ring | 0.17 | Cryptography | All | ✅ Existing |
| str0m | 0.4 | WebRTC | 4 | 📋 To Add |
| opus | 0.3 | Audio codec | 4 | 📋 To Add |
| stun | 0.5 | STUN client | 4 | 📋 To Add |
| criterion | 0.5 | Benchmarking | 6 | 📋 To Add (dev-deps) |
| tokio-test | 0.4 | Test utilities | 1–6 | 📋 To Add (dev-deps) |
| proptest | 1.0 | Property testing | 6 | 📋 To Add (dev-deps) |

---

**Document Version:** 1.0  
**Last Updated:** July 15, 2026  
**Maintenance:** Update as dependencies are evaluated and added per phase.
