# SG-X Guardian Secure Calling - Quick Start & Management Guide

**Created:** July 15, 2026  
**Purpose:** High-level summary and developer onboarding for the calling feature implementation

---

## What Was Delivered?

Two comprehensive planning documents:

1. **`plan.md`** — Original architectural specification (15 sections, 500+ lines)
   - Design philosophy: zero-trust, no cloud media, fail closed
   - System components and data flow
   - Complete verification pipeline definition
   - Authorization model (RBAC)
   - Failure scenarios and offline behavior

2. **`IMPLEMENTATION_PLAN.md`** (NEW) — Detailed execution roadmap (300+ lines)
   - 6 sequential phases with timelines
   - Module structure and file manifest (~7,500 LOC to implement)
   - Dependency graph showing integration with existing code
   - Build strategy and testing approach
   - Risk mitigation and success criteria

---

## Feature Overview: Secure Voice & Video Calling

This implementation extends SG-X Guardian's existing zero-trust security model to real-time voice/video communication. Every call is treated as a brand-new transaction requiring:

✅ **Certificate validation** — is the device's cert still valid?  
✅ **Revocation check (CRL)** — has the device been revoked?  
✅ **Attestation verification** — is the SGX enclave uncompromised?  
✅ **Policy digest check** — are both devices' policies in sync?  
✅ **VirtualID validation** — does the pseudonymous ID match the device?  
✅ **Policy enforcement** — does the RBAC rules allow this call?  

**Media flows peer-to-peer only** — the cloud is never on the media path (optional push notifications only).

---

## Architecture: Key Components to Build

### New Modules (Phases 1–5)

| Component | Purpose | Phase |
|-----------|---------|-------|
| `src/call/` | Call signaling, state machine, offer/answer protocol | 1 |
| `src/call/verify/` | 5-stage verification pipeline | 2 |
| `src/enforcement/uep.rs` | Local policy gate at call initiation | 3 |
| `src/media/` | WebRTC engine, ICE, DTLS, SRTP | 4 |
| `src/call/authorize/` | Receiver-side authorization | 5 |
| `src/call/enforce/` | Mid-call policy enforcement (graceful downgrade) | 5 |

### Integration Points (Existing Modules)

| Existing Module | How It's Used |
|-----------------|---------------|
| `src/cert_service.rs` | Verify device certificates in call offers |
| `src/attestation_service.rs` | Validate SGX enclave quotes |
| `src/crl/` | Check if devices are revoked |
| `src/policy_*.rs` | Load RBAC rules, detect policy mismatch |
| `src/virtual_id*.rs` | Validate pseudonymous identity tokens |
| `src/nebula/` | Transport for call signaling + ICE candidates |
| `src/key_manager.rs` | Sign/verify call offers |
| `src/audit/` | Log all call events |

---

## Development Phases: Timeline & Milestones

### Phase 1: Foundation & Signaling (Weeks 1–2)
- **Goal:** Offer/answer protocol over Nebula overlay
- **Deliverables:** State machine, signaling data model, call session tracking
- **Exit Criteria:** Offers can be sent/received; call state transitions tracked

### Phase 2: Verification Pipeline (Weeks 3–4)
- **Goal:** Implement 5-stage authentication chain
- **Deliverables:** Cert check → CRL → Attestation → Policy digest → VirtualID
- **Exit Criteria:** All 5 stages work; any failure = immediate call reject + audit log

### Phase 3: UEP Enforcement (Weeks 5–6)
- **Goal:** Local policy gate at call origin
- **Deliverables:** RBAC rule evaluation; block unauthorized calls before signaling
- **Exit Criteria:** Unauthorized calls rejected locally; UEP decisions audit logged

### Phase 4: Media Engine (Weeks 7–10)
- **Goal:** Real-time media (voice/video)
- **Deliverables:** WebRTC integration (ICE, DTLS, SRTP); Opus audio codec
- **Exit Criteria:** Media flows peer-to-peer; no cloud on media path; <5s setup latency

### Phase 5: Authorization & Enforcement (Weeks 11–12)
- **Goal:** Receiver-side checks + policy changes mid-call
- **Deliverables:** Receiver UEP check; graceful video→voice downgrade
- **Exit Criteria:** Both sides authorize independently; downgrades work smoothly

### Phase 6: Testing & Hardening (Weeks 13–16)
- **Goal:** Production readiness
- **Deliverables:** End-to-end tests, offline scenarios, security review, docs
- **Exit Criteria:** >85% coverage; all failure modes tested; security review passed

---

## How Features Are Managed

### 1. Version Control Strategy
```bash
# Create feature branch per phase
git checkout -b feature/calling-phase1
git checkout -b feature/calling-phase2
# etc.

# Main branch always buildable; phases merge after passing all tests
```

### 2. Testing Structure
- **Unit tests** (per module): State transitions, serialization, rule evaluation
- **Integration tests** (per phase): Modules working together
- **End-to-end tests** (Phase 6): Full 2-device call scenarios
- **Regression tests** (all phases): Verify existing modules still work

### 3. Build & CI/CD
```bash
# Build (all phases)
cargo build --release

# Test (per phase; expanded in Phase 6)
cargo test

# Lint & format
cargo fmt
cargo clippy
```

### 4. Documentation Strategy
- **Code comments:** Inline explanation of verification logic, policy rules
- **Module docs:** README files per major module (call/, media/)
- **Operational guide:** `CALLING_OPERATIONS.md` (debugging, audit log interpretation)
- **API reference:** REST endpoints in Swagger/OpenAPI format

---

## Critical Design Decisions

### 1. No Implicit Trust
Every call re-runs the full 5-stage verification. No caching of "recently verified" devices. Every failure terminates the call immediately—no degraded/partial-trust modes.

### 2. Media is Peer-to-Peer Only
No media packets traverse the cloud, even if the cloud is available. If media *ever* routes through a server, that's a bug, not a feature.

### 3. Fail Closed, Not Open
Verification failures, revocation, policy mismatches, and authorization denials all end the call. The only exception is *availability* issues (cloud/internet down), which degrade gracefully because security doesn't depend on them.

### 4. Local Policy Check First
Before any signaling leaves the device, the UEP (Unified Enforcement Point) checks local RBAC rules. This prevents unauthorized call attempts from ever reaching the network.

---

## Dependency & Crate Decisions

### WebRTC Crate (Phase 4)
**Evaluate:** `str0m` (Rust-native, actively maintained)  
**Fallback:** `webrtc` or Pion binding if needed  
**Constraint:** Must support peer-operated TURN only (no cloud relay)

### Codecs (Phase 4)
**Phase 4 (MVP):** Opus audio only  
**Phase 5+:** VP9 or AV1 video codecs (via system libraries or vendored crates)

### ICE Candidate Filtering
**Allow:** Direct connectivity, peer relay (local Nebula TURN)  
**Reject:** Cloud TURN servers (AWS, Google Cloud TURN, etc.)

---

## Module Checklist: What to Build

```
✅ Phase 1: Signaling Layer
  ├─ src/call/state.rs          — FSM: 10 states + transitions
  ├─ src/call/signaling.rs      — Offer/answer protocol
  ├─ src/call/session.rs        — Session tracking + state
  ├─ src/call/nebula_signaling.rs — Nebula transport
  └─ src/call/error.rs          — Call-specific errors

✅ Phase 2: Verification Pipeline
  ├─ src/call/verify/mod.rs     — Pipeline orchestration
  ├─ src/call/verify/cert.rs    — Stage 1: cert validity
  ├─ src/call/verify/crl.rs     — Stage 2: revocation
  ├─ src/call/verify/attestation.rs — Stage 3: enclave
  ├─ src/call/verify/policy_digest.rs — Stage 4: policy sync
  ├─ src/call/verify/virtualid.rs — Stage 5: pseudo-identity
  └─ src/call/verify/media_gate.rs — Media starts after verify

✅ Phase 3: UEP Enforcement
  ├─ src/enforcement/uep.rs     — RBAC rule evaluation
  └─ src/call/uep_gate.rs       — Call initiation gate

✅ Phase 4: Media Engine
  ├─ src/media/webrtc_engine.rs — WebRTC peer connection
  ├─ src/media/ice.rs           — ICE + NAT traversal
  ├─ src/media/dtls.rs          — DTLS key derivation
  ├─ src/media/srtp.rs          — SRTP media encryption
  ├─ src/media/codecs/opus.rs   — Audio codec
  └─ src/media/codecs/vp9_av1.rs — Video codecs (later)

✅ Phase 5: Authorization & Enforcement
  ├─ src/call/authorize/receiver_check.rs — Receiver-side UEP
  └─ src/call/enforce/media_downgrade.rs — Graceful downgrade

✅ Phase 6: Testing & Docs
  ├─ tests/e2e_call_*.rs        — End-to-end scenarios
  ├─ tests/call_failure_*.rs    — Failure modes
  ├─ tests/offline_*.rs         — Offline calling
  └─ docs/CALLING_*.md          — Operational guides
```

---

## Risk Mitigation Strategies

| Risk | Mitigation |
|------|-----------|
| **WebRTC crate immaturity** | Evaluate early; spike in pre-Phase-1 if needed |
| **Media path cloud leakage** | Packet inspection testing; code review with TURN filtering focus |
| **Verification latency** | Parallelize non-dependent checks; cache carefully (re-verify still required) |
| **State machine bugs** | Exhaustive FSM testing; no dead-end states; formal verification if time permits |
| **Incomplete failure coverage** | Test all 12 failure scenarios (plan.md Section 12) |
| **Offline policy drift** | Local cache + policy digest mismatch detection; async refresh |
| **Audit log saturation** | Log rotation strategy; capacity planning |

---

## Success Criteria (Go/No-Go)

### Per Phase
- ✅ All unit tests pass
- ✅ No regressions in existing modules
- ✅ Code review approved (security team for Phases 2–4)
- ✅ Documentation updated

### Overall (Phase 6 Exit)
- ✅ >85% code coverage (call modules)
- ✅ All e2e scenarios pass (happy path + 12 failure modes)
- ✅ Offline scenario verified (calls work with cloud down)
- ✅ Security review passed (no critical issues)
- ✅ Performance acceptable (<5s setup, good MOS for media)
- ✅ Operational guide + API docs published
- ✅ Full test suite passes; zero regressions

---

## Quick Reference: Call Flow

```
┌─────────────────────────────────────────────────────────────┐
│ DEVICE A: Initiate Call                                     │
├─────────────────────────────────────────────────────────────┤
│ 1. User requests call → check local UEP rules (Phase 3)     │
│ 2. UEP allows? Yes → continue; No → reject locally          │
│ 3. Create call offer (device ID, VirtualID, nonce, etc.)    │
│ 4. Sign offer with ECDSA-P256 key                           │
│ 5. Send offer over Nebula overlay                           │
└─────────────────────────────────────────────────────────────┘
           ↓ (authenticated Nebula channel)
┌─────────────────────────────────────────────────────────────┐
│ DEVICE B: Receive Call                                      │
├─────────────────────────────────────────────────────────────┤
│ 6. Receive offer; verify signature                          │
│ 7. Run verification pipeline (Phase 2):                     │
│    a. Cert valid?     YES                                   │
│    b. CRL revoked?    NO                                    │
│    c. Attestation OK? YES                                   │
│    d. Policy digest match? YES                              │
│    e. VirtualID valid? YES                                  │
│ 8. Run receiver UEP check (Phase 5):                        │
│    a. Device A's role can call me? YES                      │
│ 9. Send accept response over Nebula                         │
└─────────────────────────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────────────────────────┐
│ BOTH DEVICES: Exchange Media                                │
├─────────────────────────────────────────────────────────────┤
│ 10. Gather ICE candidates (Phase 4)                         │
│ 11. Exchange candidates over Nebula signaling               │
│ 12. Establish direct peer connection (ICE)                 │
│ 13. Perform DTLS handshake (derive media keys)             │
│ 14. Start SRTP media flow (encrypted)                       │
│ 15. Monitor for policy changes (Phase 5):                   │
│     a. Policy forbids video? → stop video, continue audio   │
│ 16. Call ends → close connection, log event                 │
└─────────────────────────────────────────────────────────────┘
```

---

## Getting Started: Developer Onboarding

### Step 1: Read the Documents
1. Start with `plan.md` (Section 0: Design Philosophy is critical)
2. Then read `IMPLEMENTATION_PLAN.md` (Part 1–3 for context)

### Step 2: Environment Setup
```bash
# Clone repo
cd /home/abraam/SGX

# Set up Rust (if needed)
rustup update

# Build and test existing code
cargo build
cargo test

# Verify no breaking changes
```

### Step 3: Phase 1 Setup
```bash
# Create branch
git checkout -b feature/calling-phase1

# Scaffold modules
mkdir -p src/call/{verify,authorize,enforce}
touch src/call/{mod.rs,state.rs,signaling.rs,session.rs,error.rs}

# Update src/lib.rs to include calling module
echo "pub mod call;" >> src/lib.rs
```

### Step 4: Start Building (Phase 1)
- Implement `src/call/state.rs` first (FSM is foundation)
- Then `src/call/signaling.rs` (data model)
- Wire into REST API: `src/api/handlers/call.rs`
- Write unit tests as you go

---

## Communication & Status Updates

### Weekly Sync (Proposed)
- **Monday:** Review progress, blockers, plan week
- **Wednesday:** Design review / code review (if needed)
- **Friday:** Demo working features, refine Phase N timeline

### Merge Gate (All Phases)
- [ ] Code passes `cargo fmt` and `cargo clippy`
- [ ] All new tests pass; no regression in existing tests
- [ ] Documentation updated
- [ ] Code review approved (security team for crypto/auth)
- [ ] Merge to `main` after passing CI/CD

---

## Questions? Reference These Sections

| Question | Reference |
|----------|-----------|
| Why re-verify on every call? | plan.md Section 0 (Design Philosophy #1) |
| Why no cloud on media path? | plan.md Section 0 (Design Philosophy #2) |
| What's the full verification chain? | plan.md Section 6 or IMPLEMENTATION_PLAN.md Part 2 Phase 2 |
| What RBAC rules exist? | plan.md Section 11 or IMPLEMENTATION_PLAN.md Part 5 (Build & Deployment) |
| How does offline calling work? | plan.md Section 13 |
| What happens if verification fails? | plan.md Section 6 (Failure handling) |
| What's the media flow? | plan.md Section 9 |
| How is the state machine structured? | IMPLEMENTATION_PLAN.md Part 2 Phase 1 |

---

## Document Summary

| Document | Purpose | Audience | Length |
|----------|---------|----------|--------|
| `plan.md` | Architecture specification (what to build) | All | 500+ lines |
| `IMPLEMENTATION_PLAN.md` | Detailed roadmap (how to build) | Developers | 300+ lines |
| `QUICK_START.md` (this file) | High-level summary + onboarding | New devs, managers | 200+ lines |

---

**Next Steps:** Review IMPLEMENTATION_PLAN.md Part 2 (Phases 1–6); schedule kickoff sync; begin Phase 1 development.

**Version:** 1.0  
**Date:** July 15, 2026
