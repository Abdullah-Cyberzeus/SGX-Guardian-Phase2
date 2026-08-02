# SG-X Guardian Secure Voice & Video Calling - Implementation Plan

**Date Created:** July 15, 2026  
**Status:** Phase 1 signaling implemented; secure media, liveness, and lifecycle work pending
**Target Completion:** Multi-phase delivery  
**Repository:** /home/abraam/SGX  

---

## Executive Summary

This document provides a detailed, phased implementation roadmap for delivering the Secure Voice & Video Calling capability described in `plan.md`. The implementation is organized into **6 sequential phases** over **3 major deliverables**, with explicit module ownership, dependency mappings, and go/no-go criteria for each phase.

**Key principle:** Every phase delivers an independently testable module that integrates into the next phase without breaking existing functionality.

### Implementation Baseline — July 21, 2026

The following distinction is mandatory when reporting calling progress. An
`offer_sent` response proves only that control-plane signaling reached the
peer; it does **not** prove that an audio connection exists.

| Capability | Current state | Evidence required before it is called complete |
|---|---|---|
| Offer/answer over Nebula | Implemented | Both nodes record the same session ID and signed offer/answer |
| Receiver session registration | Implemented | Receiver stores `OfferReceived` and initiator Nebula reply address |
| Call state machine | Implemented | State transitions are audited and invalid jumps are rejected |
| Real peer connection | Pending | ICE + DTLS complete and both peers report `Connected` |
| Live audio | Pending | Microphone-to-speaker Opus audio works in both directions |
| Connection liveness | Pending | Heartbeat loss reliably detects a broken peer and ends the call |
| Coordinated hang-up | Pending | `call_end` reaches the peer and both media engines close |
| Live status/quality API | Partially implemented | Authenticated session state endpoint exists; heartbeat and media quality counters remain pending |

The implementation must not expose a call as **connected** merely because it
was accepted. `Connected` is entered only after the media transport reports a
completed DTLS/ICE connection and an authenticated media gate authorizes it.

---

## Part 1: Project Structure Mapping

### Current Codebase State

The SG-X Guardian platform currently has these functional components:

| Module | Path | Status | Purpose |
|--------|------|--------|---------|
| **Policy Authority** | `src/policy_authority.rs` | ✅ Exists | Policy signing and verification |
| **Policy Engine** | `src/policy_*.rs` | ✅ Exists | Policy state management and RBAC rules |
| **Certificate Service** | `src/cert_*.rs` | ✅ Exists | Device certificate lifecycle |
| **Attestation Service** | `src/attestation_service.rs` | ✅ Exists | Remote attestation handling |
| **Virtual ID** | `src/virtual_id*.rs` | ✅ Exists | Pseudonymous identity tokens |
| **CRL System** | `src/crl/` | ✅ Exists | Certificate revocation lists |
| **Nebula Network** | `src/nebula/` | ✅ Exists | Encrypted overlay transport |
| **DID System** | `src/did/` | ✅ Exists | Decentralized identity |
| **REST API** | `src/api/` | ✅ Exists | Admin console HTTP endpoints |
| **TLS/mTLS** | `src/tls.rs` | ✅ Exists | Mutual TLS setup |
| **Audit** | `src/audit/` | ✅ Exists | Event logging and tracking |
| **Enforcement** | `src/enforcement/` | ✅ Exists | Rule application (firewall) |
| **VC (Verifiable Credentials)** | `src/vc/` | ✅ Exists | Credential issuance/verification |
| **Discovery** | `src/discovery/` | ✅ Exists | Device discovery and inventory |
| **Call/Signaling** | N/A | ❌ **To Build** | Core calling, offer/answer, state machine |
| **Media Engine** | N/A | ❌ **To Build** | WebRTC integration, ICE, DTLS, SRTP |
| **UEP (Enforcement Point)** | N/A | ❌ **To Build** | Local policy check at call origin |
| **Call State Manager** | N/A | ❌ **To Build** | FSM, call lifecycle, state transitions |
| **Verification Pipeline** | N/A | ❌ **To Build** | 5-stage authentication chain |

**Available dependencies (from Cargo.toml):**
- Tokio (async runtime) ✅
- Axum (HTTP/REST framework) ✅
- Tonic (gRPC) ✅
- Rustls (mTLS) ✅
- Serde (serialization) ✅
- Tracing (observability) ✅
- Ring (cryptography) ✅

**Missing dependencies (to add):**
- `webrtc` or `str0m` or `pion-webrtc-rs` (WebRTC engine) — needs evaluation
- `stun` / `turn` (ICE server libraries) — embedded support only
- `dtls` or `rustls-quic` (DTLS for media) — may be built-in to WebRTC crate
- `opus` (audio codec) — via `opus` or `audiopus` crate
- `vpx` or `av1` (video codec) — via system libraries or vendored crates

---

## Part 2: Phased Implementation Roadmap

### Phase 1: Foundation & Core Signaling (Weeks 1–2)

**Objective:** Establish the call signaling layer, call state machine, and integration with existing authentication.

**Deliverables:**

| Item | File(s) | Responsibility | Success Criteria |
|------|---------|-----------------|------------------|
| Call state machine FSM | `src/call/state.rs` | New module | All 10 states defined; transitions validated; no orphaned/stuck states |
| Call offer/answer data model | `src/call/signaling.rs` | New module | Offer struct includes: device ID, VirtualID, session ID, timestamp, nonce, media type; serializable to JSON; can be signed |
| Call signaling channel (over Nebula) | `src/call/nebula_signaling.rs` | New module | Sends/receives offers over Nebula overlay; uses existing Nebula channel; no fallback to unencrypted paths |
| Call session tracker | `src/call/session.rs` | New module | Stores active call state, participants, timestamps, audit trail; integrates with existing audit module |
| REST API endpoints for call control | `src/api/handlers/call.rs` | REST layer | `/api/v1/call/initiate`, `/api/v1/call/accept`, `/api/v1/call/reject`, `/api/v1/call/end` |
| Call signing (ECDSA-P256) | Integrate with `src/key_manager.rs` | Existing module | Call offers are cryptographically signed; receiving device verifies signature |

**Module Structure:**

```
src/call/
  ├── mod.rs          # Main call module interface
  ├── state.rs        # FSM: states + transitions
  ├── signaling.rs    # Offer/answer protocol
  ├── session.rs      # Session tracking
  ├── nebula_signaling.rs # Nebula overlay integration
  └── error.rs        # Call-specific errors
```

**Dependencies on existing modules:**
- `src/key_manager.rs` → sign offers
- `src/nebula/` → transport channel
- `src/audit/` → log events
- `src/virtual_id*.rs` → embed VirtualID in offers
- `src/tls.rs` → mTLS context for Nebula

**Integration points:**
- Hook call initiation into existing device/dashboard UI (future)
- Call offer travels via Nebula overlay (reuse existing authenticated channel)

**Testing:**
- Unit tests for FSM state transitions
- Unit tests for offer serialization/deserialization
- Integration test: Device A sends offer → Device B receives (via local Nebula mock)
- Audit trail verification: ensure call events are logged

**Go/No-Go Criteria:**
- [ ] State machine has 10 states; no unreachable states
- [ ] Offer signature can be generated and verified
- [ ] Nebula channel integration compiles and doesn't break existing tests
- [ ] Call events appear in audit logs

---

### Phase 2: Verification Pipeline (Weeks 3–4)

**Objective:** Implement the 5-stage authentication chain (cert → CRL → attestation → policy digest → VirtualID).

**Deliverables:**

| Item | File(s) | Responsibility | Success Criteria |
|------|---------|-----------------|------------------|
| Certificate verification | `src/call/verify/cert.rs` | New module | Checks cert validity window, issuer signature (PA-CA), encoding; fails on expired/invalid |
| CRL check integration | `src/call/verify/crl.rs` | New module | Queries local CRL cache; attempts live CRL refresh if online; rejects if revoked |
| Attestation verification | `src/call/verify/attestation.rs` | New module | Validates quote PCR values, timestamp, enclave measurement; integrates with `src/attestation_service.rs` |
| Policy digest check | `src/call/verify/policy_digest.rs` | New module | Compares offered policy digest with local digest; rejects on mismatch (signals policy skew) |
| VirtualID validation | `src/call/verify/virtualid.rs` | New module | Validates VirtualID encoding, resolves to device identity, verifies chain to device cert |
| Unified verification pipeline | `src/call/verify/pipeline.rs` | New module | Orchestrates all 5 checks in strict sequence; any failure → `End Call` + audit log |

**Module Structure:**

```
src/call/verify/
  ├── mod.rs              # Pipeline orchestration
  ├── cert.rs             # Stage 1: cert validity
  ├── crl.rs              # Stage 2: revocation
  ├── attestation.rs      # Stage 3: enclave measurement
  ├── policy_digest.rs    # Stage 4: policy sync
  ├── virtualid.rs        # Stage 5: pseudo-identity
  └── errors.rs           # Verification-specific errors
```

**Dependencies on existing modules:**
- `src/cert_service.rs` → cert validation
- `src/crl/` → CRL data
- `src/attestation_service.rs` → quote verification
- `src/policy_*.rs` → policy digest
- `src/virtual_id*.rs` → VirtualID resolution
- `src/audit/` → audit logging

**Integration points:**
- Called by incoming call handler (Section 4 of plan.md)
- Must reject *any* failure with `End Call` + audit → no pass-through to partial trust

**Testing:**
- Unit: each stage fails independently and logs correctly
- Integration: full pipeline with mock data (cert valid, but CRL revoked) → rejects
- Integration: all stages pass → accept
- Failure path testing: ensure all 5 failure modes are distinguishable in audit logs

**Go/No-Go Criteria:**
- [ ] Each of 5 stages can fail independently
- [ ] Any failure triggers immediate `End Call` state
- [ ] All failures are audit-logged with stage name, device ID, session ID
- [ ] Happy path (all stages pass) completes successfully
- [ ] No code path bypasses any stage (e.g., re-verifying device skips a stage)

---

### Phase 3: UEP (User/Unified Enforcement Point) - Local Policy Check (Weeks 5–6)

**Objective:** Implement client-side policy check that blocks unauthorized call attempts *before* any signaling leaves the device.

**Deliverables:**

| Item | File(s) | Responsibility | Success Criteria |
|------|---------|-----------------|------------------|
| UEP core logic | `src/enforcement/uep.rs` | New module | Evaluates RBAC rules; implements role-based call allow/deny |
| Policy rule data model | `src/policy_state.rs` (extend) | Existing module | Extend to include role↔call type matrix; load from signed policy |
| UEP integration into call initiation | `src/call/uep_gate.rs` | New module | Before call offer is sent, run UEP check; block locally if denied |
| UEP audit trail | Extend `src/audit/` | Existing module | Log UEP decisions (allow/deny + reason) per call attempt |
| REST endpoint for UEP status | `src/api/handlers/call.rs` | REST layer | `/api/v1/call/policy-check` (for dashboard to show "can I call this device?") |

**Module Structure:**

```
src/enforcement/
  ├── mod.rs               # Existing: enforcement overall
  ├── executor.rs          # Existing: nftables rules
  └── uep.rs              # NEW: UEP policy evaluation

src/call/
  └── uep_gate.rs         # NEW: call initiation policy check
```

**RBAC Rule Table (from plan.md Section 11):**

```rust
enum Role {
    Admin,
    Operator,
    Sensor,
    Camera,
    Robot,
}

enum MediaType {
    Voice,
    Video,
    ScreenShare,
}

// Caller → [can call whom?]
// Admin → everyone
// Operator → Controllers (Operators + Cameras)
// Sensor → nobody (can't initiate)
// Camera → nobody (can't initiate)
// Robot → control center only (likely filtered by policy engine, role="admin")
```

**Dependencies on existing modules:**
- `src/policy_*.rs` → policy loading/state
- `src/key_manager.rs` → role identity (from cert subject)
- `src/audit/` → logging
- `src/call/state.rs` → state transitions

**Integration points:**
- Call initiation flow: UEP check is *first* gate before signaling
- Policy update flow: refresh UEP rules when policy is updated (already handled by existing policy_manager)

**Testing:**
- Unit: each role + media type combination returns correct allow/deny decision
- Integration: Admin calling Sensor → allowed; Sensor calling Admin → denied locally
- Audit trail: UEP decisions appear in audit log
- Policy update: change policy, re-query UEP, get new decision (no restart needed)

**Go/No-Go Criteria:**
- [ ] Unauthorized calls are blocked *before* Nebula signaling
- [ ] UEP decisions are logged to audit trail
- [ ] Changing policy updates UEP behavior without restart
- [ ] All roles/media type combinations are tested

---

### Phase 4: Media Engine & WebRTC Integration (Weeks 7–10)

**Objective:** Integrate WebRTC stack for ICE, DTLS, and media stream handling.

**Deliverables:**

| Item | File(s) | Responsibility | Success Criteria |
|------|---------|-----------------|------------------|
| WebRTC engine wrapper | `src/media/webrtc_engine.rs` | New module | Encapsulates WebRTC peer connection; ICE candidate gathering; no cloud TURN |
| ICE (Interactive Connectivity Establishment) | `src/media/ice.rs` | New module | Candidate gathering over Nebula overlay; STUN support for NAT traversal; no cloud relay |
| DTLS (Datagram TLS) | `src/media/dtls.rs` | New module | Key derivation for media encryption; integrates with existing TLS infrastructure |
| SRTP (Secure Real-Time Protocol) | `src/media/srtp.rs` | New module | Encrypts audio/video streams with keys from DTLS |
| Media codec support | `src/media/codecs/` | New module | Opus for audio (VP9/AV1 for video via external lib) |
| Call media state | `src/call/media_state.rs` | New module | Tracks media stream state (audio active, video active, screen share active) |
| Media path verification | `src/call/verify/media_gate.rs` | New module | Ensures media only flows after full verification + authorization |

**Module Structure:**

```
src/media/
  ├── mod.rs              # Media module interface
  ├── webrtc_engine.rs    # WebRTC peer connection wrapper
  ├── ice.rs              # ICE + NAT traversal
  ├── dtls.rs             # DTLS for key derivation
  ├── srtp.rs             # SRTP media encryption
  ├── codecs/
  │   ├── mod.rs
  │   ├── opus.rs         # Audio codec
  │   └── vp9_av1.rs      # Video codecs
  └── errors.rs

src/call/
  ├── media_state.rs      # Media stream state tracking
  └── verify/
      └── media_gate.rs   # Gate: media only starts after security passes
```

**Crate additions (Cargo.toml):**

Evaluate and add one of:
- `webrtc` (pure Rust, but immature for production; good for learning)
- `str0m` (Rust-native, actively maintained)
- `pion-webrtc-rs` (Pion ecosystem binding; mature)

Plus:
- `opus` or `audiopus` (audio codec)
- `stun` (simple STUN client)
- `ice` (ICE protocol library, if not bundled in WebRTC crate)

**Dependencies on existing modules:**
- `src/nebula/` → transport layer for ICE candidates
- `src/tls.rs` → DTLS certificate/key management
- `src/call/state.rs` → state machine integration
- `src/call/verify/` → gate: no media until verification passes

**Integration points:**
- Once call state reaches `Connected` (after accept), media engine initializes
- ICE candidates are exchanged via Nebula signaling channel (not TURN cloud)
- Media flows directly between devices (peer-to-peer)

**Testing:**
- Unit: ICE candidate parsing, filtering (no cloud TURN)
- Unit: DTLS key derivation
- Unit: SRTP frame encryption/decryption
- Integration: two devices exchange ICE candidates → establish media connection
- Integration: verify media does *not* route through cloud (observe packets on Nebula overlay)
- Codec tests: Opus encode/decode; VP9 encode/decode (system dependent)

**Go/No-Go Criteria:**
- [ ] WebRTC engine initializes without errors
- [ ] ICE candidates are exchanged and NAT traversal works (test with NAT)
- [ ] DTLS handshake completes; media encryption keys are derived
- [ ] Audio/video frames are encrypted via SRTP
- [ ] No packet inspection reveals media routing through cloud
- [ ] Media latency is acceptable for real-time use (measure and document)

---

### Phase 4A: Live Audio, Connection Health & Coordinated Teardown

**Objective:** Turn an accepted signaling session into an observable,
bidirectional voice call that detects failure without operator intervention and
closes cleanly on both boards. This subphase is a hard prerequisite for
claiming that a call is "connected" in the dashboard.

**Scope order:** audio-only first. Video and screen sharing remain disabled
until bidirectional Opus audio, liveness, and teardown pass board tests.

#### 4A.1 Signaling protocol additions

Extend `src/call/nebula_signaling.rs` with length-limited, versioned JSON
messages. Every message carries `protocol_version`, `session_id`, `timestamp`,
`nonce`, sender device ID, and an ECDSA-P256 signature. Reject messages from a
non-overlay source, stale timestamps, invalid session IDs, and replayed
nonces.

| Message | Sender → receiver | Purpose |
|---|---|---|
| `ice_candidate` | either peer | Exchange trickle ICE candidates only through the authenticated Nebula signaling channel |
| `media_ready` | either peer | Announces local DTLS/ICE readiness; does not itself mark the call connected |
| `heartbeat` | either peer | Carries monotonic sequence number and last received sequence for liveness/RTT measurement |
| `call_end` | either peer | Requests graceful end with reason code (`hangup`, `timeout`, `media_failure`, `policy_change`) |
| `call_end_ack` | receiving peer | Confirms teardown before local session cleanup |
| `media_error` | either peer | Reports a non-recoverable media failure without exposing key material |

Use a framed transport (4-byte network-order length followed by JSON) rather
than relying on TCP EOF as a message delimiter. Limit each frame to 64 KiB;
apply read/write timeouts and rate limits per peer/session.

#### 4A.2 Real WebRTC and audio pipeline

1. Evaluate `str0m` and `webrtc` in a two-board spike; select one implementation
   only after it supports ARM64 Linux, trickle ICE, DTLS-SRTP, Opus, statistics,
   and a clean close operation. Pin the selected version in `Cargo.lock`.
2. Add a `MediaPeer` trait so the call state/session code is independent of the
   selected WebRTC crate. Provide a deterministic mock for tests.
3. Gather host candidates from `nebula0` first. Reject cloud TURN URLs and
   candidates outside the policy-approved interfaces. A future relay must be a
   trusted peer inside the Nebula overlay.
4. Create an ephemeral per-call DTLS certificate/key pair. Bind its fingerprint
   to the already verified signaling session; never send private key material
   through signaling or audit logs.
5. After ICE and DTLS complete, create a single Opus audio track in each
   direction. Capture from ALSA/PipeWire through a small platform adapter,
   encode 20 ms frames, send through SRTP, decode on the peer, and play through
   the selected audio output device.
6. Enforce `MediaGate` immediately before creating/starting each track. A
   verification, authorization, policy, or attestation failure must prevent
   capture and playback.
7. Move FSM state only in this order:

```text
OfferSent/OfferReceived → Verifying → Authorizing → Accepted
→ MediaNegotiation → Connected → EndCall
```

`Connected` requires both a local WebRTC `Connected` event and a signed
`media_ready` confirmation from the peer. A signaling answer alone is not
sufficient.

#### 4A.3 Heartbeat, recovery, and teardown rules

| Rule | Required behavior |
|---|---|
| Heartbeat cadence | Send every 2 seconds while `MediaNegotiation` or `Connected` |
| Liveness timeout | After 3 missed heartbeats (6 seconds), enter `EndCall` with reason `peer_timeout` and stop capture/playback |
| RTT | Measure from heartbeat sequence/ack timestamps; do not depend on ICMP ping |
| Degraded media | Emit warning event when loss, jitter, or RTT crosses policy thresholds; retain audio unless policy requires stop |
| Graceful hang-up | `/call/end` sends `call_end`, stops new media, waits up to 3 seconds for `call_end_ack`, then closes DTLS/SRTP and releases devices |
| Abrupt peer loss | Timeout closes the local peer connection, releases audio devices, writes an audit event, and makes session terminal |
| Idempotency | Repeated `call_end`, `call_end_ack`, and late heartbeats must not resurrect a terminal session |

#### 4A.4 New modules and API surface

| File | Responsibility |
|---|---|
| `src/call/liveness.rs` | Heartbeat scheduler, timeout detector, RTT calculation, cancellation token |
| `src/call/lifecycle.rs` | Coordinates accept → media negotiation → connected → teardown without invalid FSM jumps |
| `src/media/peer.rs` | `MediaPeer` trait and real/mock implementations |
| `src/media/audio_io.rs` | Board audio capture/playback adapter; device enumeration and error mapping |
| `src/media/metrics.rs` | Normalized WebRTC/Opus counters and threshold evaluation |
| `src/api/handlers/call.rs` | Status endpoint and controlled end operation |

Add these authenticated REST routes to the node that owns the session:

| Route | Method | Request/response purpose |
|---|---|---|
| `/api/v1/call/{session_id}/status` | `GET` | FSM state, peer identity, liveness, last heartbeat, RTT, jitter, loss, bytes/packets, active media tracks; never expose keys or SDP secrets |
| `/api/v1/call/{session_id}/events` | `GET` or authenticated WebSocket/SSE | Optional ordered state/quality events for a dashboard; implement polling first if streaming adds risk |
| `/api/v1/call/end` | `POST` | Existing endpoint extended to perform remote `call_end` plus local cleanup |
| `/api/v1/call/{session_id}/media` | `GET` | Optional detailed media statistics; return `409` until `Connected` |

**Implemented increment:** `GET /api/v1/call/{session_id}/status` now returns
non-sensitive local session state, participants, negotiated media, timestamps,
duration, terminal state, and `media_connected`. It intentionally omits
nonces, Nebula addresses, signatures, SDP, and keys. `POST /call/end` now
accepts repeated local hang-up requests for an already ended session. Remote
`call_end`, heartbeat, and media statistics remain pending.

The receiver must have a secure local control path for accept/reject/status.
Do not require the nodeA-only administrative listener to manage nodeB's local
session. Prefer a separately authenticated, overlay-bound control endpoint or
a local dashboard IPC mechanism.

#### 4A.5 Board acceptance tests

1. Start nodeA and nodeB with valid Nebula addresses and audio devices.
2. Initiate and accept an audio-only call; assert both status endpoints reach
   `Connected` within 5 seconds.
3. Inject a known tone on nodeA and verify decoded audio energy on nodeB;
   repeat in the reverse direction. Do not accept a microphone-only test as
   proof of transmission.
4. Verify status reports increasing packet/byte counters and fresh heartbeat
   timestamps for at least 60 seconds.
5. Disconnect Nebula or kill nodeB; assert nodeA transitions to `EndCall`
   within 6 seconds, audio devices close, and an audit event includes
   `peer_timeout`.
6. Call `/call/end`; assert both boards receive terminal state and no UDP/RTP
   traffic or open audio device remains after teardown.
7. Capture packets on every non-Nebula interface and prove no media is routed
   through cloud or a public TURN service.

**Go/No-Go Criteria:**
- [ ] Two ARM64 boards achieve bidirectional Opus audio for 10 minutes
- [ ] Both peers report `Connected` only after ICE/DTLS/media readiness
- [ ] Heartbeat detects loss within 6 seconds and never leaves audio devices open
- [ ] Local and remote hang-up are idempotent and audited on both boards
- [ ] Status API reports current state plus non-sensitive quality counters
- [ ] Packet capture confirms no cloud media path or cloud TURN candidate

---

### Phase 5: Authorization & Policy Enforcement (Weeks 11–12)

**Objective:** Implement per-call authorization (receiver-side policy check) and mid-call policy enforcement (video → voice downgrade).

**Deliverables:**

| Item | File(s) | Responsibility | Success Criteria |
|------|---------|-----------------|------------------|
| Receiver-side authorization | `src/call/authorize/receiver_check.rs` | New module | When Device B receives an offer, it runs its own UEP check: "can I accept this call from this device?" |
| Dynamic policy enforcement | `src/call/enforce/media_downgrade.rs` | New module | If policy changes mid-call (e.g., "no video"), gracefully downgrade (stop video, continue audio) |
| Authorization audit trail | Extend `src/audit/` | Existing module | Log authorization decisions (allowed, denied, downgraded) |
| REST endpoint for authorization status | `src/api/handlers/call.rs` | REST layer | `/api/v1/call/{session_id}/authorization-status` |

**Module Structure:**

```
src/call/authorize/
  ├── mod.rs              # Authorization orchestration
  └── receiver_check.rs   # Receiver-side UEP check

src/call/enforce/
  ├── mod.rs              # Policy enforcement orchestration
  └── media_downgrade.rs  # Graceful downgrade on policy change
```

**Dependencies on existing modules:**
- `src/enforcement/uep.rs` → reuse role/permission evaluation
- `src/policy_*.rs` → fetch updated rules
- `src/media/` → control media streams
- `src/audit/` → log enforcement decisions

**Integration points:**
- Receiver-side check runs in incoming call handler (after verification, before accept)
- Dynamic enforcement runs as a background task monitoring policy changes
- If call must degrade, emit event + update call state + audit

**Testing:**
- Unit: receiver-side UEP check with various role combos
- Integration: Admin calls Sensor (Admin allowed, Sensor can't receive) → denied
- Integration: Operator calls Camera; mid-call, policy changes to forbid video → video stops, audio continues
- Audit trail: authorization decisions logged with decision reason

**Go/No-Go Criteria:**
- [ ] Receiver-side authorization check runs independently of sender-side
- [ ] Policy changes are detected mid-call
- [ ] Media downgrade is graceful (no dropped audio if video is removed)
- [ ] All authorization decisions are audit-logged

---

### Phase 6: Testing, Hardening & Documentation (Weeks 13–16)

**Objective:** Comprehensive testing, security review, offline scenarios, and operational documentation.

**Deliverables:**

| Item | File(s) | Responsibility | Success Criteria |
|------|---------|-----------------|------------------|
| End-to-end call scenario tests | `tests/e2e_call_*.rs` | New tests | Device A → Device B: full call lifecycle (initiate, verify, authorize, media, end) |
| Failure scenario tests | `tests/call_failure_*.rs` | New tests | All 12 failure modes from plan.md Section 12 are tested; correct audit trails |
| Offline calling tests | `tests/offline_*.rs` | New tests | Verify calling works with cloud fully disconnected; CRL cache used; policy cache used |
| Call state machine exhaustive tests | `tests/call_state_fsm_*.rs` | New tests | All state transitions are reachable and correct; no orphaned states |
| Security review | `docs/SECURITY_REVIEW.md` | Doc | Security assumptions, threat model, verified no-cloud-media constraint |
| Operational guide | `docs/CALLING_OPERATIONS.md` | Doc | How to troubleshoot calls, debug call logs, interpret audit trail |
| Performance benchmarks | `tests/bench_call_*.rs` | Benchmarks | Call setup latency, media encoding/decoding throughput |
| Update CONTRIBUTION.md | `CONTRIBUTION.md` | Doc | How to extend/modify calling system for future developers |

**Integration points:**
- Run all tests in CI/CD pipeline
- Verify no regressions in existing modules (attestation, cert, policy, etc.)

**Implementation note:**
- Added targeted integration tests under `tests/` for lifecycle, failure modes, offline scenarios, and benchmarks.
- Added `docs/CALLING_OPERATIONS.md`, `docs/SECURITY_REVIEW.md`, and `CONTRIBUTION.md` to complete Phase 6 documentation.

**Testing Strategy:**

```
Layer 1: Unit Tests
  ├── State machine transitions
  ├── Offer serialization/deserialization
  ├── Verification pipeline (each stage independently)
  ├── UEP rule evaluation
  ├── Media codec operations

Layer 2: Integration Tests
  ├── Signaling over Nebula (mock Nebula channel)
  ├── Full verification pipeline with real cert/CRL data
  ├── Call state transitions + audit trail
  ├── Media engine with ICE + DTLS

Layer 3: End-to-End Tests (2-device sim)
  ├── Device A calls Device B (happy path)
  ├── Device B rejects (cert invalid, CRL revoked, policy deny, etc.)
  ├── Device A initiates call blocked by local UEP
  ├── Mid-call policy change → media downgrade
  ├── Offline scenarios (cloud down, internet down)

Layer 4: Manual Testing (staging env)
  ├── 3-device test with physical media devices
  ├── NAT traversal testing
  ├── Network interruption recovery
  ├── Latency measurements (setup time, MOS score for media quality)
```

**Go/No-Go Criteria:**
- [ ] All unit tests pass; coverage >85% for new call modules
- [ ] All integration tests pass
- [ ] All e2e scenarios pass (happy + failure modes)
- [ ] Offline scenario verified (cloud down, calls still work)
- [ ] Security review document completed and approved
- [ ] Performance benchmarks documented and acceptable
- [ ] No regressions in existing modules (run full test suite)

---

## Part 3: Dependency Graph & Module Integration

### Dependency Flow

```
┌──────────────────────────────────────────────────────────┐
│                   Existing Modules                        │
├──────────────────────────────────────────────────────────┤
│ key_manager → cert_service ↔ tls.rs ↔ policy_*.rs       │
│     ↓              ↓           ↓         ↓               │
│ attestation_service   crl/   virtual_id*.rs              │
│     ↓                  ↓              ↓                   │
│ nebula/ ←────────────────────────────────────────────   │
│     ↓                                                     │
│ audit/ (logging) ← all modules report here               │
└──────────────────────────────────────────────────────────┘
         ↑
         │ (integrates into)
         │
┌──────────────────────────────────────────────────────────┐
│           NEW Call/Media Modules (Phases 1–5)            │
├──────────────────────────────────────────────────────────┤
│ call/state.rs ────────→ call/signaling.rs               │
│     ↓                        ↓                           │
│ call/session.rs ──→ call/nebula_signaling.rs            │
│     ↓                        ↓                           │
│ call/verify/ ─────────→ (5-stage pipeline)              │
│     ↓                        ↓                           │
│ enforcement/uep.rs ────→ call/uep_gate.rs               │
│     ↓                        ↓                           │
│ call/authorize/ ─→ call/media_state.rs                  │
│     ↓                        ↓                           │
│ media/webrtc_engine.rs ──→ call/verify/media_gate.rs   │
│     ↓                        ↓                           │
│ media/ice.rs, media/dtls.rs, media/srtp.rs             │
│     ↓                        ↓                           │
│ call/enforce/ ──────→ final state transitions           │
└──────────────────────────────────────────────────────────┘
         ↓
┌──────────────────────────────────────────────────────────┐
│            REST API / Dashboard Layer                     │
├──────────────────────────────────────────────────────────┤
│ src/api/handlers/call.rs ← exposes all call operations  │
└──────────────────────────────────────────────────────────┘
```

### Critical Integration Points

1. **Nebula Overlay** (existing)
   - Call offers/answers travel over authenticated Nebula channel
   - ICE candidates exchanged via Nebula signaling
   - Media packets flow peer-to-peer, not through Nebula control plane

2. **Certificate & Attestation** (existing)
   - Verification pipeline (Phase 2) depends on cert_service and attestation_service
   - Device cert must be bundled in call offer for receiver to verify

3. **Policy Engine** (existing)
   - Policy digest loaded from policy_state
   - UEP rules evaluated from RBAC table in policy
   - Policy changes trigger mid-call enforcement (Phase 5)

4. **Audit Trail** (existing)
   - All call events logged via audit/ module
   - Call state transitions, verification failures, authorization decisions, etc.

5. **Key Manager & TLS** (existing)
   - Call offers are signed with device's ECDSA-P256 key
   - DTLS certificates for media encryption reuse existing TLS infrastructure

---

## Part 4: Build & Deployment Strategy

### Build Timeline

| Phase | Weeks | Modules | Key Milestone |
|-------|-------|---------|---------------|
| 1 | 1–2 | Call signaling, state machine | Offers can be sent/received over Nebula |
| 2 | 3–4 | Verification pipeline | 5-stage check works; failures audit logged |
| 3 | 5–6 | UEP enforcement | Local policy gates call initiation |
| 4 | 7–10 | Media engine (WebRTC) | ICE + DTLS + media flowing peer-to-peer |
| 4A | 10–12 | Audio, liveness, lifecycle | Bidirectional Opus, heartbeat, remote hang-up, live status |
| 5 | 11–12 | Authorization & enforcement | Receiver-side check; mid-call downgrades |
| 6 | 13–16 | Testing & hardening | All scenarios tested; docs complete |

### Incremental Integration

**After Phase 1:** Signaling works; UI can show "call state" but no media yet.  
**After Phase 2:** Incoming offers are verified; can reject untrusted devices.  
**After Phase 3:** Callers are gated by local policy; no unauthorized attempts reach network.  
**After Phase 4:** Media flows (voice/video) securely peer-to-peer.  
**After Phase 4A:** Boards have real bidirectional audio, live liveness/quality
status, and coordinated teardown; this is the first point a call may be
presented as connected.
**After Phase 5:** Full authorization and policy enforcement on both sides.  
**After Phase 6:** Production-ready with comprehensive test coverage.

### Continuous Integration

- **Per phase:** Run full test suite + new tests for that phase
- **Regressions:** Verify existing modules (cert, policy, VC, etc.) still work
- **Coverage:** Maintain >85% code coverage for call modules
- **Documentation:** Update API docs and operational guides per phase

### Deployment Stages

1. **Development:** All phases on developer machines (local Nebula overlay)
2. **Staging:** 3-device cluster with physical media devices
3. **Canary:** Pilot with 1–2 trusted customer sites (cloud optional)
4. **Production:** Full rollout with optional cloud tier for push notifications

---

## Part 5: File Manifest & Ownership

### New Files to Create

```
src/call/
  ├── mod.rs                      (200 lines) — main interface
  ├── state.rs                    (150 lines) — FSM definition
  ├── signaling.rs                (300 lines) — offer/answer protocol
  ├── session.rs                  (250 lines) — session tracking
  ├── nebula_signaling.rs         (200 lines) — Nebula integration
  ├── liveness.rs                 (200 lines) — heartbeat, timeout, RTT
  ├── lifecycle.rs                (250 lines) — media/session orchestration
  ├── uep_gate.rs                 (150 lines) — call initiation gate
  ├── media_state.rs              (200 lines) — media stream state
  ├── error.rs                    (100 lines) — call-specific errors
  │
  ├── verify/
  │   ├── mod.rs                  (200 lines) — pipeline orchestration
  │   ├── cert.rs                 (150 lines) — stage 1: cert validity
  │   ├── crl.rs                  (150 lines) — stage 2: revocation
  │   ├── attestation.rs          (150 lines) — stage 3: enclave
  │   ├── policy_digest.rs        (100 lines) — stage 4: policy sync
  │   ├── virtualid.rs            (100 lines) — stage 5: pseudo-identity
  │   ├── media_gate.rs           (100 lines) — gate: media after verify
  │   └── errors.rs               (50 lines)  — verification errors
  │
  ├── authorize/
  │   ├── mod.rs                  (100 lines) — authorization interface
  │   └── receiver_check.rs       (150 lines) — receiver-side UEP check
  │
  └── enforce/
      ├── mod.rs                  (100 lines) — enforcement interface
      └── media_downgrade.rs      (150 lines) — graceful downgrade

src/media/
  ├── mod.rs                      (200 lines) — media module interface
  ├── webrtc_engine.rs            (400 lines) — WebRTC peer connection
  ├── peer.rs                     (250 lines) — real/mock peer abstraction
  ├── audio_io.rs                 (250 lines) — board capture/playback adapter
  ├── metrics.rs                  (150 lines) — normalized media statistics
  ├── ice.rs                      (300 lines) — ICE + NAT traversal
  ├── dtls.rs                     (200 lines) — DTLS key derivation
  ├── srtp.rs                     (250 lines) — SRTP media encryption
  ├── error.rs                    (50 lines)  — media errors
  │
  └── codecs/
      ├── mod.rs                  (100 lines) — codec interface
      ├── opus.rs                 (300 lines) — audio codec (Opus)
      └── vp9_av1.rs              (300 lines) — video codecs

src/enforcement/
  └── uep.rs                      (200 lines) — UEP policy evaluation

tests/
  ├── e2e_call_happy_path.rs      (300 lines)
  ├── e2e_call_verification_fail.rs (300 lines)
  ├── e2e_call_offline.rs         (250 lines)
  ├── call_state_fsm.rs           (200 lines)
  ├── call_media_*.rs             (500 lines) — media engine tests

docs/
  ├── CALLING_ARCHITECTURE.md     (comprehensive overview)
  ├── CALLING_OPERATIONS.md       (troubleshooting guide)
  ├── SECURITY_REVIEW.md          (security analysis)
  └── API_CALLING_ENDPOINTS.md    (REST API reference)
```

**Total new lines of code:** ~6,500–7,500 LOC (excluding tests and docs)

### Modified Files

| File | Change | Phase |
|------|--------|-------|
| `src/lib.rs` | Add `pub mod call; pub mod media;` | Phase 1 |
| `src/api/mod.rs` (already done for CORS) | Add call control endpoints | Phase 1 |
| `src/api/handlers/mod.rs` | Add `pub mod call;` | Phase 1 |
| `src/main.rs` | Spawn call/media task from main | Phase 1 |
| `Cargo.toml` | Add WebRTC, Opus crates | Phase 4 |
| `src/api/handlers/call.rs` | Add authenticated status/events endpoints and coordinated hang-up | Phase 4A |
| `src/enforcement/mod.rs` | Export `uep` submodule | Phase 3 |
| `src/audit/mod.rs` | Add call event types | Phase 1 |
| Test suite | Run regression tests per phase | All |

---

## Part 6: Key Decisions & Rationale

### Decision 1: WebRTC Crate Selection

**Options:**
- `webrtc` — pure Rust, immature, learning-friendly
- `str0m` — actively maintained, Rust-native, fast adoption
- `pion-webrtc-rs` — mature, proven, but Pion binding

**Decision:** Evaluate `str0m` first (Rust-native, good community support). Fall back to `webrtc` if licensing/dependency issues arise. Avoid Pion binding for now to reduce external dependencies.

### Decision 2: Media Codec Strategy

**Options:**
- Vendored codecs (Opus, VP9 in Rust)
- System library bindings (libopus, libvpx via FFI)
- Minimal: Opus only (voice calling first, video later)

**Decision:** Start with Opus (audio only) for Phase 4. Video codecs (VP9, AV1) deferred to Phase 5 or later. System bindings acceptable if FFI safety is reviewed.

### Decision 3: ICE Candidate Filtering

**Constraint:** No cloud TURN relay; only peer-operated or direct connectivity.

**Decision:** Filter ICE candidates to exclude cloud TURN servers. Allow:
- Direct (host candidates from local interfaces)
- Peer relay (TURN server on local Nebula peer)
Reject:
- Cloud TURN servers (AWS, Google Cloud, etc.)

### Decision 4: Call Offer Signing

**Options:**
- Sign with device's primary identity key (same as used for attestation)
- Sign with a separate call signing key
- No signature (rely on Nebula channel security)

**Decision:** Sign with device's primary ECDSA-P256 key. Offers are semi-public (shared via Nebula), so signature provides authenticity independent of transport. This aligns with zero-trust philosophy.

### Decision 5: Policy Digest Mismatch Handling

**Scenario:** Device A has updated policy; Device B has older policy. Offer contains digest A; B's local digest differs.

**Options:**
- Silently continue (assume minor drift)
- Reject call and trigger policy refresh
- Degrade to minimal permissions (voice only, no video)

**Decision:** Reject call and audit log "policy digest mismatch." Device B should trigger policy refresh from PA-CA. This enforces policy sync and prevents unintended permission drift.

### Decision 6: Offline Media Encryption

**Constraint:** Media is peer-to-peer; DTLS must work without cloud-signed certificates.

**Options:**
- Self-signed DTLS certificates per session
- Reuse device certificate for DTLS
- Ephemeral keys derived from shared secret

**Decision:** Use self-signed DTLS certificates (standard WebRTC approach). Device identity is verified in the control plane (Section 6 verification chain); media encryption is orthogonal. This avoids PKI complexity in the media path.

### Decision 7: Connection Liveness Is Application-Level

**Decision:** Use signed session heartbeats over the Nebula signaling channel
in addition to WebRTC connection-state callbacks. Send every 2 seconds and
declare a peer lost after three missed heartbeats. WebRTC callbacks alone are
not sufficient because their timing varies across NAT, driver, and network
failure modes.

### Decision 8: Audio-Only Is the First Production Media Milestone

**Decision:** Ship Opus audio before video or screen sharing. Require a
two-board, 10-minute bidirectional audio test plus loss/teardown tests before
enabling video. This limits codec, CPU, camera, and bandwidth variables while
the security and lifecycle controls are proven.

---

## Part 7: Success Criteria & Acceptance

### Phase 1 Acceptance
- [ ] State machine compiles; all 10 states reachable
- [ ] Call offers can be serialized, signed, sent over Nebula mock
- [ ] Call events logged to audit trail
- [ ] No integration test failures in existing modules

### Phase 2 Acceptance
- [ ] All 5 verification stages compile and test independently
- [ ] 5-stage pipeline runs correctly (happy path + all failure modes)
- [ ] Any failure produces audit log entry with stage name
- [ ] Verification pipeline is *not* short-circuited on re-verification

### Phase 3 Acceptance
- [ ] UEP evaluates RBAC rules correctly for all role combinations
- [ ] Local policy check blocks unauthorized calls before Nebula signaling
- [ ] UEP decisions are audit logged
- [ ] Policy reload updates UEP behavior without restart

### Phase 4 Acceptance
- [ ] WebRTC engine initializes; ICE candidates are gathered
- [ ] DTLS handshake completes; media encryption keys derived
- [ ] Opus audio frames can be encoded/decoded
- [ ] No media packets route through cloud (verified by packet inspection)
- [ ] Call setup latency <5s; MOS score acceptable for voice quality

### Phase 4A Acceptance
- [ ] Both boards transition to `Connected` only after real media readiness
- [ ] Bidirectional Opus audio is verified on physical ARM64 boards
- [ ] Signed heartbeats report RTT and identify peer loss within 6 seconds
- [ ] `/call/end` notifies the peer, closes media, and is idempotent
- [ ] `GET /api/v1/call/{session_id}/status` returns live, non-sensitive metrics
- [ ] Board tests prove no media remains after normal or timeout teardown

### Phase 5 Acceptance
- [ ] Receiver-side authorization check runs independently
- [ ] Policy changes mid-call are detected and enforced
- [ ] Media gracefully downgrades (e.g., video stops, audio continues)
- [ ] All enforcement decisions audit logged

### Phase 6 Acceptance
- [ ] All end-to-end scenarios pass (happy path + 12 failure modes)
- [ ] Offline scenario verified (calls work with cloud down)
- [ ] Code coverage >85% for call modules
- [ ] Security review completed and no critical issues found
- [ ] Performance benchmarks documented and acceptable
- [ ] Operational guide and API docs published
- [ ] Full test suite passes; no regressions in existing modules

---

## Part 8: Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| WebRTC crate immaturity | Evaluate multiple crates early; spike in Phase 0 if needed |
| Media path cloud leakage | Packet inspection testing; code review with specific focus on TURN filtering |
| Latency during verification | Parallelize non-dependent checks; cache recent verification results (carefully, respecting re-verification requirement) |
| Offline policy sync drift | Local cache always used; policy refresh triggered asynchronously; drift detected (policy digest mismatch) |
| Incomplete failure coverage | Exhaustive unit tests per phase; failure matrix testing (Section 12, plan.md) |
| State machine edge cases | Formal verification or exhaustive state transition testing; no dead-end states |
| Media codec performance | Benchmarks per phase; fallback to lower quality if needed |
| Board audio-driver incompatibility | Introduce an audio-I/O trait; validate ALSA/PipeWire devices in a board preflight test |
| Stuck call after peer crash | Signed 2-second heartbeat, 6-second timeout, idempotent terminal-state cleanup |
| Sensitive telemetry leakage | Expose only aggregated media counters; never return SDP, DTLS keys, tokens, or raw audio in APIs/logs |
| Audit log storage | Implement log rotation; audit storage capacity planning |

---

## Part 9: Next Steps (Immediately After This Plan)

1. **Spike (Week 0):** Evaluate WebRTC crates; POC single-device media encode/decode.
2. **Review:** Security team reviews plan.md + IMPLEMENTATION_PLAN.md; sign off on architecture.
3. **Setup:** Create branch `feature/calling-phase1`; scaffold module structure.
4. **Phase 1 Kickoff:** Assign developers to signaling + state machine; begin weekly syncs.

---

## Part 10: Glossary

| Term | Definition |
|------|-----------|
| **Control Plane** | Certificate exchange, verification, authorization (Section 3, plan.md) |
| **Media Plane** | WebRTC audio/video streams (Section 9, plan.md) |
| **UEP** | Unified Enforcement Point; local policy check at call origin (plan.md) |
| **Verification Pipeline** | 5-stage auth chain: cert → CRL → attestation → policy digest → VirtualID (Section 6, plan.md) |
| **VirtualID** | Pseudonymous/rotating device identity used in signaling (Section 2.2, plan.md) |
| **ICE** | Interactive Connectivity Establishment; NAT traversal protocol (Section 9, plan.md) |
| **DTLS** | Datagram TLS; key derivation for media encryption (Section 9, plan.md) |
| **SRTP** | Secure Real-Time Protocol; encrypts media streams (Section 9, plan.md) |
| **RBAC** | Role-Based Access Control; policy authorization model (Section 11, plan.md) |
| **CRL** | Certificate Revocation List; revocation status cache (Section 2.1, plan.md) |
| **Nebula** | Encrypted overlay network; transport substrate (Section 2.1, plan.md) |

---

**Document Version:** 1.1
**Last Updated:** July 21, 2026
**Author:** Implementation Planning Agent  
**Status:** Signaling baseline implemented; Phase 4/4A secure media plan ready for review
