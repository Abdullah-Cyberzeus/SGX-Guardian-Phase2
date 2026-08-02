# SG-X Guardian — Secure Voice & Video Calling Architecture

**Purpose of this document:** This is a build specification for an AI coding agent (or engineering team) implementing the Secure Voice and Video Calling capability of the SG-X Guardian Zero-Trust Platform. It expands the original design document into an implementation-oriented reference: every component, protocol step, state, and failure path is spelled out so the system can be built without ambiguity. Read this file fully before writing any code — the zero-trust guarantees only hold if every stage below is implemented, not just the "happy path."

---

## 0. Design Philosophy (read this first)

Three rules govern every decision in this system. If a proposed implementation violates any of them, it is wrong regardless of how convenient it is:

1. **No implicit trust, ever.** A device is never trusted because it was trusted a moment ago, because it's on the same network, or because a previous call with it succeeded. Every single call re-runs the full verification chain from scratch.
2. **The cloud never touches media.** The optional cloud tier may push notifications, register devices, and distribute policy — it must never be on the path that audio/video packets travel. If a code path routes RTP/media through a server, that is a bug, not a feature.
3. **Fail closed, not open.** Any failure — expired cert, revoked cert, failed attestation, policy mismatch, VirtualID mismatch — terminates the call immediately. There is no "degrade to unencrypted" or "allow with a warning" path for security failures. (Availability failures like losing internet/cloud are different — see Section 12 — those degrade gracefully because the platform doesn't depend on the cloud for security.)

---

## 1. Executive Summary

This capability extends SG-X Guardian's existing peer-to-peer, attestation-based communication model to real-time media (voice/video/screen-share), without weakening the platform's existing mutual-TLS, remote-attestation, and policy-enforcement guarantees.

Every call is treated as a brand-new zero-trust transaction. Before a single media packet moves, the system re-verifies:
- Device identity
- Certificate validity
- Attestation state (SGX enclave measurement)
- Policy digest (has the authorization policy changed since last sync?)
- VirtualID (the device's rotating/pseudonymous identity token)
- Revocation status (CRL check)

The optional cloud tier is limited strictly to: push notifications ("you have an incoming call"), device registration, and policy distribution. It is architecturally incapable of carrying voice or video — media is peer-to-peer only.

---

## 2. System Components

The platform has five functional groups. An agent implementing this should build each as a distinct module/service boundary — do not let responsibilities bleed across these groups.

### 2.1 Component Summary

| Component | Role | Build notes |
|---|---|---|
| **PA-CA** (Policy Authority / Certificate Authority) | Issues device certificates, signs policies, signs Certificate Revocation Lists (CRLs) | Acts as the root of trust. Should be an offline-capable signing service — devices only need its public key to verify, not live connectivity to it, for the security path to work. |
| **SG-X Device (A / B)** | Hosts: Intel SGX enclave, TPM identity key, attestation key, device certificate, VirtualID, UEP (User/Unified Enforcement Point), camera/mic/speaker, WebRTC engine, QUIC stack | This is the "full stack" per device — identity, enforcement, and media all live here, not on a server. |
| **Nebula overlay network** | Encrypted transport, NAT traversal, and peer discovery between devices | This is the transport substrate everything else rides on top of. Think of it as a private encrypted mesh VPN layer between all enrolled devices. |
| **Policy Engine** | Evaluates role, permission, and allowed call/video/recording/screen-share rules | Runs *locally on-device* (see UEP below) as well as being the authority that signs the policy digest devices carry. |
| **CRL system** | Maintains certificate revocation and status data | Distributed to devices so revocation checks work offline (cached CRL), and periodically refreshed when connectivity is available. |
| **Optional cloud tier** | Push notification, device registration, policy distribution | **Never** carries voice/video traffic. Treat this as a "convenience/availability" service, architecturally optional. |

### 2.2 Per-device building blocks explained

- **Intel SGX enclave** — a hardware-isolated execution environment. Sensitive operations (holding the attestation key, verifying certificates, running the local policy check) should execute inside the enclave so that even a compromised OS on the device can't tamper with the verification logic or exfiltrate keys.
- **TPM identity key** — a hardware-backed key pair unique to the device, used to prove "this is device A" independent of software state.
- **Attestation key** — used to produce a remote attestation quote proving the enclave is running genuine, unmodified code (measurement matches expected hash).
- **Device certificate** — issued by PA-CA, binds the device's public key to its identity and role. Has a validity window and can be revoked.
- **VirtualID** — a pseudonymous/rotating identifier used in signaling so that raw device identity isn't exposed on the wire more than necessary; still traceable/verifiable through the PA-CA chain.
- **UEP (Unified/User Enforcement Point)** — the local policy-decision-and-enforcement component that runs the "may this call happen?" check *before anything is sent over the network*. This is what makes unauthorized call attempts fail locally rather than being rejected by the far end.
- **WebRTC engine** — handles ICE/DTLS/SRTP and audio/video codec pipeline.
- **QUIC stack** — used for the Nebula overlay's transport and/or control-plane messaging (low-latency, connection-migration-friendly transport).

---

## 3. High-Level Architecture

Devices communicate only **after** mutual authentication and policy validation over the Nebula overlay. Once the security handshake completes, media flows **directly, peer-to-peer** — the cloud tier is never on the media path.

Two distinct planes to build:

1. **Control plane** — certificate exchange, attestation, policy digest check, VirtualID validation, CRL check. Runs over the authenticated Nebula overlay channel.
2. **Media plane** — WebRTC (ICE → DTLS → SRTP), strictly peer-to-peer, established only after the control plane succeeds.

Architecturally: draw this as two parallel paths from Device A to Device B — a "verification" path that must fully complete, gating a "media" path that only opens after a green light.

---

## 4. Call Workflow

1. Call is initiated from the **Guardian Dashboard** (the user-facing UI on the device).
2. Before any signaling leaves the device, the **UEP performs a local policy check**.
   - If the caller's role/permissions don't allow this call type (see Section 11), the call attempt is stopped **locally** — it never reaches the network.
   - This is a critical build requirement: the policy check is not merely a server-side gate, it's enforced at the point of origin.
3. Only if the local check passes does the device proceed to Section 5 (Signaling).

---

## 5. Signaling

The call offer travels **exclusively** over the already-authenticated SG-X secure channel (the Nebula overlay control-plane channel). It must **never** be sent over an unauthenticated or out-of-band path (no plain SIP, no unauthenticated WebSocket, no third-party signaling relay).

**Call offer payload — fields to implement:**

| Field | Purpose |
|---|---|
| Device identity | Identifies the calling device to the receiving device |
| VirtualID | Pseudonymous session-scoped identity token |
| Session ID | Unique identifier for this call transaction (used for audit logging and state tracking) |
| Timestamp | Used to detect replay / stale offers |
| Nonce | Anti-replay protection, should be single-use and checked against a recent-nonce cache |
| Requested media | Enumerated: voice, video, screen share |

Build note: treat the offer as a signed structure (signed with the device's key), not just a JSON blob — the receiving device needs to verify authenticity of the offer itself, separately from verifying the transport channel.

---

## 6. Device Authentication Flow (the verification chain)

Before Device B accepts the call, it runs this chain **in full, in order, on every call, with no caching/skip-on-recent-success**:

1. **Certificate validity check** — is Device A's certificate within its validity window and correctly signed by PA-CA?
2. **CRL check** — has Device A's certificate been revoked? (checked against cached CRL if offline, live CRL if online)
3. **Attestation check** — does Device A's attestation quote match the expected enclave measurement?
4. **Policy digest check** — does the policy digest presented by Device A match what Device B expects (i.e., has Device A's local policy state fallen out of sync)?
5. **VirtualID validation** — does the VirtualID in the offer correctly resolve/validate against Device A's identity chain?

**Failure handling (build this precisely):** a failure at *any* stage:
- Terminates the call immediately.
- Writes an audit record (stage that failed, timestamp, device identities, session ID).
- Does **not** fall through to a partial-trust or degraded-but-connected state. There is no such thing as "half-verified" in this system.

Suggested pseudocode structure for the agent implementing this:

```
function verifyIncomingCallOffer(offer):
    if not certificateValid(offer.deviceCert):
        return reject("CERT_EXPIRED", auditLog(offer, "cert_invalid"))
    if isRevoked(offer.deviceCert, localCRL):
        return reject("CRL_REVOKED", auditLog(offer, "crl_match"))
    if not attestationValid(offer.attestationQuote):
        return reject("ATTESTATION_FAILED", auditLog(offer, "attestation_fail"))
    if offer.policyDigest != expectedPolicyDigest():
        return reject("POLICY_DIGEST_MISMATCH", auditLog(offer, "policy_mismatch"))
    if not virtualIdValid(offer.virtualId, offer.deviceCert):
        return reject("VIRTUALID_MISMATCH", auditLog(offer, "vid_mismatch"))
    return accept(offer)  # proceed to authorization model (Section 11), then media (Section 9)
```

---

## 7. Security Workflow and Layered Defense

Every call transaction passes through the **full** SG-X Guardian security stack — application layer down to the physical network. No layer is bypassed for real-time media, even though media is latency-sensitive. Build this as a strict pipeline, not an optional set of checks that can be short-circuited "for performance":

```
Application layer  →  Policy/Authorization layer  →  Identity/Attestation layer
      →  Transport security (mutual TLS / Nebula overlay encryption)
      →  Network layer (NAT traversal, routing)
      →  Physical network
```

---

## 8. Sequence Diagram (build reference)

Full call transaction, participants: **Device A, Policy Engine, Nebula overlay, Device B, PA-CA.**

1. Device A: local UEP policy check (Section 4).
2. Device A → Nebula overlay: signed call offer (Section 5).
3. Nebula overlay: routes to Device B (encrypted transport, no cloud involvement).
4. Device B: runs full verification chain against PA-CA-issued material (Section 6) — this includes round-trip checks against PA-CA/CRL data as needed (live or cached).
5. Device B: runs authorization check against Policy Engine rules (Section 11).
6. Device B → Device A: accept/reject response over the same authenticated channel.
7. On accept: both devices proceed to direct peer-to-peer WebRTC media negotiation (Section 9) — PA-CA and the overlay's control-plane role end here; media does not route through them.

Build note: steps 1–6 (verification) must **fully complete** before step 7 (media negotiation) begins. Do not parallelize media setup with verification to save latency — that reintroduces implicit trust.

---

## 9. Media Flow

Once authentication, attestation, and authorization all succeed:

1. **ICE** (Interactive Connectivity Establishment) — connectivity negotiation across the Nebula overlay (candidate gathering, NAT traversal).
2. **DTLS** — derives session encryption keys for the media channel (DTLS handshake over the negotiated ICE path).
3. **SRTP** — carries the actual encrypted media, using the keys derived from DTLS.
4. **Codecs:** Opus for audio; VP9 or AV1 for video.

The cloud is not involved at any point in this path — build this as a hard architectural constraint (e.g., no cloud-facing media relay/TURN-via-cloud-server should be permitted; if TURN-like relay is ever needed for NAT traversal, it must be a peer-operated relay within the Nebula overlay, not a cloud service, to preserve the "cloud never carries media" guarantee).

---

## 10. Call State Machine

A call session moves through a strict, auditable sequence of states. Implement this as an explicit finite state machine (not implicit/ad-hoc state tracking):

**States to implement:**
- `Idle`
- `Local Policy Check`
- `Offer Sent` (Device A) / `Offer Received` (Device B)
- `Verifying` (running the Section 6 chain)
- `Authorizing` (Section 11 role/permission check)
- `Accepted` → proceeds to `Media Negotiation` → `Connected`
- `Rejected` → `End Call`
- `On Hold` / `Resume` (mid-call states, must return to `Connected`)
- `End Call` (terminal state — reachable directly from *any* verification/authentication/policy failure, not only from a normal hangup)

**Critical build rule:** any authentication, attestation, or policy failure transitions **directly** to `End Call`. There must be no intermediate "connected but downgraded trust" state — the only exception to this is the *explicit, policy-driven* video→voice downgrade described in Section 12 (which is a policy decision, not a trust failure).

---

## 11. Authorization Model (RBAC)

Enforced by the Policy Engine at **both** call initiation (caller side, via UEP) and call acceptance (receiver side).

| Role | Calling permission |
|---|---|
| Admin | Can call everyone |
| Operator | Can call controllers |
| Sensor | Cannot initiate calls |
| Camera | Can only receive calls |
| Robot | Can only call the control center |

Build note: this table should be data-driven (a policy document signed by PA-CA and distributed to devices), not hardcoded per-device — that's what "policy digest" in Section 6 refers to: devices need a way to detect when their local copy of this table is stale relative to what the PA-CA currently considers authoritative.

---

## 12. Failure Scenarios

| Condition | Outcome |
|---|---|
| Certificate expired | Reject |
| CRL match (revoked) | Reject |
| Attestation failed | Reject |
| policy_digest mismatch | Reject |
| VirtualID mismatch | Reject |
| Policy denies video | Downgrade to voice only |
| Policy denies call | Call blocked |
| Cloud offline | Continue peer-to-peer call |
| Internet lost | Continue via Nebula overlay |

Two categories to build distinctly:
- **Security-relevant failures** (first five rows) → hard reject, always, no exceptions.
- **Availability-related conditions** (cloud/internet loss) → degrade gracefully, because the platform's security and media path never depended on the cloud or general internet in the first place — only on the Nebula overlay operating between devices (which can function on a local/private network).

---

## 13. Offline Calling

Because certificates, policy, and the **Circle of Trust** (the set of devices/identities a given device is configured to trust) are already cached on-device, calling continues to function with the cloud entirely unavailable.

Build implications:
- Devices must locally cache: their own certificate, the PA-CA public key/root of trust, the current CRL snapshot, the current policy digest and rules, and the Circle of Trust membership list.
- All of Section 6's verification chain must be executable using **only** locally cached data — no step in that chain should have a hard runtime dependency on reaching the cloud.
- The cloud is a convenience tier (push notifications so a receiving device wakes up / gets notified faster) — not a dependency of the security or media path.

---

## 14. Summary / Non-Negotiable Guarantees

This design applies SG-X Guardian's existing zero-trust primitives — mutual TLS, remote attestation, policy digests, VirtualID, and CRL checks — to real-time voice and video calling without exception:

- No device is trusted by default.
- No media traverses the cloud.
- Every failure mode degrades toward rejection, never toward implicit trust.

The result should have the same security posture as the rest of the SG-X Guardian platform, suitable for deployment in high-assurance and regulated environments.

---

## 15. Build Checklist for the Implementing Agent

Use this as a go/no-go checklist before considering any milestone "done":

- [ ] Local UEP policy check blocks unauthorized calls **before** any network I/O.
- [ ] Call offer is signed and carries: device identity, VirtualID, session ID, timestamp, nonce, requested media type.
- [ ] Offer is sent only over the authenticated Nebula overlay channel — no fallback signaling path exists in code.
- [ ] Full 5-stage verification chain (cert → CRL → attestation → policy digest → VirtualID) runs on **every** call, with no short-circuit/caching of "recently verified."
- [ ] Any verification failure produces an audit record and an immediate `End Call` transition — verified this can't be bypassed.
- [ ] Media (ICE/DTLS/SRTP) only initializes after verification **and** authorization both succeed — never in parallel with them.
- [ ] No code path routes RTP/media packets through a cloud service, under any configuration flag.
- [ ] RBAC table (Section 11) is loaded from a signed, versioned policy document, not hardcoded.
- [ ] State machine has an explicit `End Call` terminal state reachable from every failure branch — no orphaned "stuck" states.
- [ ] All security-path data (own cert, PA-CA root, CRL snapshot, policy, Circle of Trust) is cached locally and the app functions with cloud/internet fully disconnected.
- [ ] Cloud/internet loss is handled as a distinct, non-fatal code path separate from security failures (Section 12).