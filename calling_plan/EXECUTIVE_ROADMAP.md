# SG-X Guardian Calling Feature - Executive Roadmap & Status

**Date:** July 15, 2026  
**Feature:** Secure Voice & Video Calling with Zero-Trust Architecture  
**Status:** Planning Complete ✅ | Ready for Development Kickoff  

---

## What Problem Does This Solve?

SG-X Guardian currently provides:
- ✅ Secure peer-to-peer device discovery & authentication
- ✅ Attestation-based trust verification
- ✅ Policy-driven access control
- ✅ Encrypted overlay networking (Nebula)
- ✅ Verifiable credentials & digital identities

**Missing:** Real-time voice and video calling with the same zero-trust guarantees.

**This feature adds:**
- 🎤 Secure voice calls (Opus audio)
- 📹 Video conferencing (VP9/AV1, Phase 5+)
- 🔒 Call verification (5-stage auth chain)
- 📋 Policy-based call authorization (RBAC)
- 📊 Complete audit trail (all call events logged)
- 🌐 Offline operation (cloud optional, media peer-to-peer)

---

## Delivery Timeline: 16 Weeks

```
WEEK  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16
      |==|==|==|==|==|==|==|==|==|==|==|==|==|==|==|==|
PHASE 1: Signaling & State Machine
         [Foundation]

PHASE 2: Verification Pipeline (5-stage auth)
            [Auth]

PHASE 3: Local UEP Policy Enforcement
               [Local Gate]

PHASE 4: WebRTC & Media Engine
                     [ICE/DTLS/SRTP]

PHASE 5: Receiver-Side Authorization & Enforcement
                           [Complete Auth + Downgrade]

PHASE 6: Testing, Hardening & Documentation
                                   [Production Ready]
```

**Total Duration:** 4 months  
**Development Team:** 2–3 Rust developers  
**Estimated LOC:** 6,500–7,500 (call + media modules) + 2,000 tests

---

## Phase Overview

### Phase 1: Signaling Layer (Weeks 1–2)
**What:** Call initiation protocol over encrypted Nebula overlay  
**Deliverable:** Users can initiate/receive calls; call state is tracked  
**Key Decision:** Offers travel *only* over authenticated Nebula (no fallback paths)  
**Success:** Calls can be offered and answered; state transitions logged

### Phase 2: Verification Pipeline (Weeks 3–4)
**What:** 5-stage authentication chain re-runs on every call  
```
Stage 1: Certificate validity
   ↓
Stage 2: CRL (revocation) check
   ↓
Stage 3: SGX attestation verification
   ↓
Stage 4: Policy digest (sync check)
   ↓
Stage 5: VirtualID (pseudo-identity) validation
```
**Failure Mode:** Any stage fails → call rejected immediately + audit logged  
**Success:** Verification rejects untrusted devices; all failures audit-logged

### Phase 3: UEP Enforcement (Weeks 5–6)
**What:** Local policy gate at call *initiation* point  
**Rules:** Admin can call anyone; Operator can call Controllers; Sensors can't initiate calls, etc.  
**Benefit:** Unauthorized calls are blocked *before* they reach the network  
**Success:** Unauthorized call attempts rejected locally; policy rule changes take effect without restart

### Phase 4: Media Engine (Weeks 7–10)
**What:** Real-time voice (+ video scaffold)  
**Technologies:**
- **ICE:** Peer connectivity + NAT traversal (no cloud TURN)
- **DTLS:** Encryption key negotiation
- **SRTP:** Media packet encryption
- **Opus:** High-quality audio codec (minimum viable)
- **VP9/AV1:** Video codecs (later phases)

**Constraint:** Media flows **peer-to-peer only**; cloud is never on the media path  
**Success:** Audio flows securely between two devices; setup latency <5 seconds

### Phase 5: Full Authorization & Enforcement (Weeks 11–12)
**What:** 
- Receiver-side policy check (Device B validates if it can receive from Device A)
- Graceful mid-call downgrades (policy change → video stops, audio continues)
- Complete authorization on both sides

**Success:** Both sender and receiver authorize independently; policy changes don't drop calls

### Phase 6: Production Hardening (Weeks 13–16)
**What:**
- Comprehensive end-to-end testing (all scenarios + failure modes)
- Offline operation verification (calls work with cloud down)
- Security review (zero-trust guarantees verified)
- Performance benchmarks (MOS score, latency, codec efficiency)
- Documentation (operations guide, API reference, troubleshooting)

**Success:** Passes security review; >85% code coverage; all failure modes tested; operational docs complete

---

## Key Architecture Principles

### 1. Zero-Trust Calling
Every call treats the other device as untrusted initially. Re-verification happens on every call, even if you called them 5 minutes ago. This is by design.

```
Call A→B at 10:00 AM: Full verification (cert, CRL, attestation, policy, VID)
         ✅ Allowed

Call A→B at 10:05 AM: Full verification *again* (not cached)
         Device B was revoked at 10:03 AM → rejected ✅
```

### 2. No Cloud on Media Path
The cloud (optional) can:
- Push notifications ("you have an incoming call")
- Store policy & distribute updates
- Register device identities

The cloud **cannot**:
- Carry voice/video packets
- Route media through its servers
- Have access to encryption keys

This guarantee is architectural, verified by code review and packet inspection.

### 3. Fail Closed, Not Open
When anything goes wrong:
- Expired cert → call rejected
- Device revoked → call rejected
- Attestation fails → call rejected
- Policy mismatch → call rejected
- Policy denies → call rejected

There is **no** "accept with degraded trust" mode for security failures. (Network failures like internet outages *do* degrade gracefully because security doesn't depend on cloud connectivity.)

### 4. Local Policy Enforcement
Before a call offer even leaves Device A, the UEP (local policy engine) checks:
- Is Device A's role allowed to call?
- Is the destination (Device B) in the allowed set?
- Are the requested media types (voice/video) permitted?

If the answer is "no," the call is rejected *locally* — it never reaches the network. This prevents policy violations from ever happening on the wire.

---

## What Stays the Same?

These existing SG-X Guardian components are reused (not reimplemented):

| Component | How It's Used |
|-----------|---------------|
| Certificate Service | Verify device certs in call offers |
| Attestation Service | Validate SGX enclave measurements |
| CRL System | Check device revocation status |
| Policy Engine | Load RBAC rules; check policy digest |
| Virtual ID | Pseudonymous identity in offers |
| Key Manager | Sign/verify call offers (ECDSA-P256) |
| Nebula Overlay | Transport for signaling + ICE candidates |
| Audit System | Log all call events (initiation, auth, state changes) |

**Benefit:** No duplicated security logic; calling inherits all existing SG-X Guardian guarantees.

---

## Testing Strategy

### Layer 1: Unit Tests (per module)
- State machine transitions
- Offer serialization
- Verification stage logic
- RBAC rule evaluation
- Media codec operations

### Layer 2: Integration Tests (per phase)
- Modules working together
- Signaling → Verification → Authorization → Media flow
- Failure paths (cert expired → rejected)

### Layer 3: End-to-End Tests (Phase 6)
- 2-device simulation:
  - Happy path (both devices trust each other → call succeeds)
  - Device B revoked (cert valid, but on CRL → call rejected)
  - Device A unauthorized (local UEP blocks) → never reaches Device B
  - Policy mismatch → call rejected
  - Network failure (internet down) → Nebula overlay keeps calling working
  - Media quality (MOS score, latency, codec efficiency)

### Layer 4: Manual Staging (3+ devices, Phase 6)
- Real media devices (microphone, speaker, webcam)
- NAT traversal testing
- Network interruption + recovery
- Latency & jitter measurements

---

## Resource Requirements

### Team
- **2–3 Rust developers** (one lead, one/two contributors)
- **1 security engineer** (review Phases 2–4)
- **1 QA engineer** (test design, Phase 6)

### Infrastructure
- Dev environment: existing (no new hardware needed)
- Staging: 3-device cluster (can be on same network for initial testing)
- CI/CD: Use existing (GitHub Actions or similar)

### Timeline Risk Factors
- **WebRTC crate selection:** 1–2 weeks for evaluation; might reduce Phase 4 scope if immature
- **Codec performance:** If system-library bindings (libopus, libvpx) cause issues, fallback to pure-Rust codecs (adds 1–2 weeks)
- **Firewall rules / Linux kernel version:** NAT traversal (ICE) may need system-level tuning (1 week if issues arise)

---

## Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Code Coverage** | >85% for call modules | `cargo tarpaulin` or similar |
| **Call Setup Latency** | <5 seconds | Measure from offer to media flowing |
| **Media Quality (Opus)** | MOS ≥ 3.8 | Use ITU-T MOS scoring |
| **Test Coverage** | All 12 failure modes tested | Test matrix in phase 6 |
| **Offline Reliability** | Calls work with cloud down | Integration test scenario |
| **Regression Test Pass Rate** | 100% | Full suite after each phase |
| **Security Review** | Zero critical/high issues | External + internal review |
| **Documentation** | Complete API + operational guides | Docs reviewed by ops team |

---

## Go/No-Go Gates

Before each phase can proceed, the previous phase must:

| Phase | Gate | Approval Required |
|-------|------|-------------------|
| 1→2 | Signaling works; offers sent/received | Dev lead + team |
| 2→3 | Verification pipeline complete; failures logged | Security team |
| 3→4 | UEP blocks unauthorized calls | Policy team |
| 4→5 | Media flows p2p; latency <5s | Dev lead + ops |
| 5→6 | Authorization + enforcement work | Security team |
| 6→Prod | >85% coverage; security review passed | All stakeholders |

---

## Budget & Cost

### Development Cost
- 3 developers × 16 weeks × estimated velocity = ~150 story points
- Assuming 15 points/week: 10 weeks of focused dev work
- Buffer for reviews, rework: +6 weeks
- **Total effort: 16 weeks elapsed (4 months of calendar)**

### Infrastructure Cost
- Dev environment: Existing
- Staging cluster: Existing (reuse for testing)
- CI/CD: Existing
- **No new infrastructure required**

### Total: Minimal (reuse existing resources + team time)

---

## Contingency Plans

### If WebRTC crate is immature
- **Plan B:** Spike with simpler transport (Opus over UDP with manual DTLS)
- **Cost:** +1–2 weeks; reduces video feature scope (Phase 4 voice-only, video deferred)

### If codec performance is poor
- **Plan B:** Use system libraries (libopus, libvpx via FFI)
- **Cost:** +1 week; FFI bindings need security review

### If NAT traversal is unreliable
- **Plan B:** Add fallback peer relay (on Nebula overlay, not cloud)
- **Cost:** +2 weeks; extends Phase 4

### If verification latency exceeds budget
- **Plan B:** Parallelize non-dependent verification stages
- **Cost:** +1 week; careful caching (must still re-verify, not skip)

---

## Post-Launch: Future Enhancements

### Phase 5+ (Not in current roadmap)
- **Video codecs** (VP9, AV1 with hardware acceleration)
- **Screen sharing** (DLP, display capture + codec)
- **Conference bridges** (3+ participants; still peer-to-peer discovery, but relayed media if needed for N-way)
- **Call recording** (encrypted, audit-logged)
- **Real-time transcription** (with PII redaction)
- **Integration with phone systems** (SIP gateway, limited to policy-authorized calls)

---

## FAQ

### Q: Why re-verify every call? Isn't that slow?
**A:** Zero-trust principle: a device trusted 5 minutes ago might be revoked now. Re-verification is ~100–200ms; acceptable tradeoff for security. Can parallelize non-dependent stages if needed.

### Q: What if internet goes down mid-call?
**A:** Call continues via Nebula overlay (if both devices are on the same local network). Nebula works without internet. If Nebula is also unreachable, call drops gracefully.

### Q: Can the cloud access calls?
**A:** No. Cloud can send push notifications and distribute policy, but never carries media packets. Verified by code review + packet inspection in staging.

### Q: Do I need SGX for calling?
**A:** Attestation verification checks SGX, but if SGX is compromised/disabled, the call is rejected. You can't disable SGX and keep a "downgraded" call going.

### Q: What about video quality?
**A:** Phase 4 targets Opus audio + VP9 baseline. Latency <5s setup time. MOS score ≥3.8 (good voice quality). Video codec tuning in Phase 5+.

### Q: Can I use this with regular SIP phones?
**A:** Not initially. SG-X calling is proprietary (zero-trust + Nebula overlay). SIP interop is a future enhancement (Phase 6+), requires gateway with policy enforcement.

---

## Next Steps (Immediate Actions)

1. **Review & Approval** (This Week)
   - [ ] Stakeholders review IMPLEMENTATION_PLAN.md
   - [ ] Security team reviews plan.md
   - [ ] Budget/resource approval

2. **Kickoff Preparation** (Week 1)
   - [ ] Assign dev team (lead + contributors)
   - [ ] Set up dev environment & CI/CD branch
   - [ ] Create WebRTC crate evaluation spike
   - [ ] Schedule weekly sync meetings

3. **Phase 1 Start** (Week 1 End)
   - [ ] Scaffold module structure
   - [ ] Begin state machine implementation
   - [ ] Start signaling protocol design

---

## Key Contacts & Escalation

| Role | Responsibility | Contact |
|------|-----------------|---------|
| **Dev Lead** | Phase delivery, technical decisions | TBD |
| **Security Lead** | Architecture review, threat analysis | TBD |
| **Product Lead** | Feature scope, timeline, priorities | TBD |
| **Ops Lead** | Deployment, performance, stability | TBD |

---

## Documents

| Document | Audience | Purpose |
|----------|----------|---------|
| `plan.md` | Architects, security | What to build (architecture spec) |
| `IMPLEMENTATION_PLAN.md` | Developers, tech lead | How to build (6-phase roadmap + modules) |
| `QUICK_START_CALLING.md` | New developers | Onboarding + quick reference |
| `EXECUTIVE_ROADMAP.md` (this file) | Stakeholders, managers | Timeline, resources, success criteria |

---

**Prepared by:** Implementation Planning Agent  
**Date:** July 15, 2026  
**Version:** 1.0  
**Status:** Ready for Executive Review & Approval

---

## Appendix: Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Guardian Dashboard (UI)                   │
└────────────────────┬────────────────────────────────────────┘
                     │
        ┌────────────┴────────────┐
        ↓                         ↓
   ┌─────────────┐          ┌─────────────┐
   │  Device A   │          │  Device B   │
   ├─────────────┤          ├─────────────┤
   │ SGX Enclave │          │ SGX Enclave │
   │ Key Manager │          │ Key Manager │
   │ Policy (UEP)│          │ Policy (UEP)│
   │ WebRTC      │          │ WebRTC      │
   └──────┬──────┘          └──────┬──────┘
          │                        │
          │ [Signaling Plane]      │
          │ (Cert + Attestation)   │
          │ ← Nebula Overlay →     │
          │ (Authenticated)        │
          │                        │
          ├───────────────────────┤ [Media Plane]
          │                       │ (Voice/Video)
      ┌───┴───┐             ┌────┴──┐
      │ ICE   │◄────────────│ ICE   │ NAT Traversal
      ├───────┤             ├───────┤
      │ DTLS  │◄────────────│ DTLS  │ Key Negotiation
      ├───────┤             ├───────┤
      │ SRTP  │◄────────────│ SRTP  │ Encrypted Media
      └───────┘ (Peer-to-Peer, Direct Connection)
          ↓

    [Cloud Tier - Optional]
    ├─ Push notifications (incoming call alert)
    ├─ Policy distribution (update rules)
    ├─ Device registration (directory)
    └─ **NOT on media path** (never carries voice/video)
```

---

End of Executive Roadmap
