# Secure Calling: Implemented Work and Complete Remaining Plan

**Repository snapshot reviewed:** 2026-07-21  
**Document purpose:** Provide a source-backed status audit and an implementation plan for production WebRTC calling and its frontend integration, especially the Network page and the requested `/pictures` frontend area.

> Important scope note: this repository currently contains the Rust Guardian backend only. No HTML, CSS, JavaScript, TypeScript, React, Vue, or other frontend source—and no `/pictures` directory or route—exists in this checkout. The frontend sections below are therefore a proposed implementation contract. If `/pictures` refers to a separate repository or supplied mockups, that source must be added or linked before pixel-accurate implementation begins.

## 1. Executive status

The project has a useful **call-control foundation**, but it does not yet provide a real audio/video call.

| Area | Status | What that means |
|---|---|---|
| Call data model and finite-state machine | Implemented foundation | Offer/answer models, session records, lifecycle states, and transition checks exist. |
| Signed offer/answer creation | Partially implemented | ECDSA signatures are created, but received signatures are not cryptographically verified yet. |
| Nebula signaling | Partially implemented | Offer/answer TCP transport and inbound listener exist on the Nebula address. It has no SDP, trickle ICE, heartbeat, or hang-up signaling messages yet. |
| REST call-control API | Implemented foundation | Initiate, accept, reject, end, status, and policy-check routes exist. The API lacks inbox/list/event/media-control endpoints. |
| Policy and verification gates | Partially implemented | State and policy abstractions exist, but the complete certificate/VC/CRL/attestation verification chain is not wired into the live handler path. |
| ICE / DTLS / SRTP / codecs | Scaffold only | These modules simulate behavior or store metadata; they are not protocol implementations. |
| WebRTC media | Not implemented | No WebRTC library dependency, peer connection, SDP exchange, RTP, real encryption, capture, playback, or media flow exists. |
| Frontend | Not present | Network and calling screens must be created in the frontend repository/application. |

**Current usable outcome:** two Guardians can exchange signed-looking call offers and answers through the Nebula control plane and expose local session state through REST.  
**Not yet usable:** a user cannot complete a real voice/video WebRTC call.

## 2. Source-backed implementation inventory

### 2.1 Implemented call foundation

1. **Call lifecycle state machine** — `src/call/state.rs`
   - States: `Idle`, `LocalPolicyCheck`, `OfferSent`, `OfferReceived`, `Verifying`, `Authorizing`, `Accepted`, `MediaNegotiation`, `Connected`, and `EndCall`.
   - Valid transition enforcement and terminal-state detection are implemented.
   - Both outbound and inbound call paths are represented.

2. **Offer and answer models** — `src/call/signaling.rs`
   - Device ID, VirtualID, session ID, timestamp, nonce, requested/accepted media, and signature fields exist.
   - Audio and video media types exist.
   - Offer and answer construction signs the serialized payload with the Guardian key manager.
   - Required-field and empty-media validation exists.

3. **Session management** — `src/call/session.rs`
   - Creates and stores active sessions behind an async `RwLock`.
   - Tracks participants, state changes, start/end times, nonce use, Nebula endpoints, and audit history.
   - Registers incoming offers and provides a dashboard-safe status snapshot.
   - Uses a policy-enforcer abstraction before acceptance.

4. **Nebula signaling transport** — `src/call/nebula_signaling.rs`
   - Listens on TCP port `50063`, bound to the local Nebula overlay IP.
   - Rejects source addresses outside the configured `192.168.100.0/24` assumption.
   - Enforces a 5-second I/O timeout, 64 KiB message limit, and 5-minute offer-age limit.
   - Sends and receives `call_offer` and `call_answer` JSON messages.
   - The listener is started by `src/main.rs`.

5. **REST call routes** — `src/api/handlers/call.rs`, registered in `src/api/mod.rs`
   - `POST /api/v1/call/initiate`
   - `POST /api/v1/call/accept`
   - `POST /api/v1/call/reject`
   - `POST /api/v1/call/end`
   - `GET /api/v1/call/:session_id/status`
   - `POST /api/v1/call/policy-check`
   - Routes are behind the existing authentication middleware.

6. **Policy-related components**
   - UEP role/media authorization model exists in `src/enforcement/uep.rs`.
   - A call policy adapter exists in `src/call/policy.rs`.
   - A pre-media gate abstraction exists in `src/call/verify/media_gate.rs`.
   - Call decisions and lifecycle changes have audit hooks.

7. **Tests currently present**
   - State-machine tests.
   - Offer/answer serialization and validation tests.
   - Offline signaling parsing tests.
   - Policy-denial and invalid-transition tests.
   - A lifecycle test that manually advances states.
   - These validate control logic; they do not prove networked WebRTC media.

### 2.2 Present but only simulated or incomplete

1. **`src/media/webrtc_engine.rs`**
   - Stores configuration, strings representing candidates, stream metadata, and manually assigned state.
   - Does not instantiate an actual WebRTC peer connection.
   - Does not generate or process SDP.
   - Does not gather network candidates, perform connectivity checks, or send RTP.

2. **`src/media/ice.rs`**
   - Generates a fabricated host candidate containing the peer ID.
   - Marks connectivity successful whenever local and remote candidate collections are non-empty.
   - Does not perform STUN transactions, candidate pairing, consent checks, nomination, or ICE restarts.

3. **`src/media/dtls.rs`**
   - Advances a simulated handshake state.
   - Derives bytes by hashing identifiers/fingerprints.
   - Does not perform DTLS packets, certificate exchange, authenticated handshake, or RFC-compliant key export.

4. **`src/media/srtp.rs`**
   - Encrypts with reversible XOR.
   - This is not SRTP and must never be treated as production media protection.

5. **`src/media/codecs.rs` and `src/call/media_state.rs`**
   - Define capability and statistics data structures.
   - Do not encode/decode, capture, render, play, or transmit media.

6. **Signature verification**
   - `CallOffer::verify_signature` currently checks only whether the signature string is empty.
   - The inbound signaling listener likewise checks presence rather than verifying the signature against the resolved peer identity key.
   - Answers need the same full verification.

7. **Verification modules**
   - Certificate/CRL work is present or in progress in the working tree, but `src/call/verify/mod.rs` currently exports only the media gate.
   - The REST accept flow advances through `Verifying` and `Authorizing`; it does not prove completion of the full intended trust chain.

8. **Session semantics**
   - Sessions are in-memory and are lost on restart.
   - The status API is per-session only.
   - There is no incoming-call inbox, active-session list, missed-call history, server event stream, or cross-device state reconciliation.
   - Ending locally does not currently send a hang-up message to the remote Guardian.

## 3. Target architecture and ownership decision

The cleanest architecture for the requested browser frontend is:

```text
Browser frontend
  | HTTPS REST + authenticated WebSocket/SSE
  v
Local Guardian API
  | Nebula-only signed signaling
  v
Remote Guardian API

Browser A  <========== WebRTC media ==========>  Browser B
               direct route where possible
```

The browser should own `RTCPeerConnection`, `getUserMedia`, audio/video elements, device selection, mute, camera, and screen sharing. The Guardian backend should own authentication, identity resolution, policy decisions, trust verification, audit, Nebula-only signaling, and the authorization token that permits a browser media session.

This avoids trying to capture desktop browser media inside the Rust daemon and uses the browser's mature WebRTC stack. If the actual deployment requires cameras/microphones physically attached to the Guardian board with no browser media access, replace this decision with a native Rust WebRTC engine (`str0m` or another evaluated implementation). That is a separate media topology and must be confirmed before implementation.

### Security boundary

- The browser must not receive Guardian private keys.
- Guardian-to-Guardian control messages must remain on the authenticated Nebula interface.
- The backend must cryptographically verify the caller before it tells the frontend that a call is safe to answer.
- SDP and ICE candidates may be exchanged as signaling payloads, but must be session-bound, size-limited, authenticated, replay-protected, and audited without logging sensitive SDP details.
- `Connected` must mean a real peer connection is connected and both endpoints have confirmed media readiness—not merely that an answer was accepted.

## 4. Required backend completion

### Phase B1 — Freeze protocol and resolve security blockers

1. Define a versioned signaling envelope:

```json
{
  "version": 1,
  "type": "offer|answer|ice_candidate|ice_complete|media_ready|hangup|heartbeat|error",
  "session_id": "uuid",
  "sender_device_id": "...",
  "sender_virtual_id": "...",
  "sequence": 1,
  "timestamp": "RFC3339",
  "nonce": "...",
  "payload": {},
  "signature": "hex-or-base64"
}
```

2. Sign a canonical byte representation; do not rely on arbitrary JSON property ordering.
3. Resolve the sender's trusted public key from the verified DID/device certificate chain.
4. Verify every message signature, timestamp, session binding, sender role, sequence number, and nonce before processing.
5. Add replay storage scoped by sender/session and reject duplicate or out-of-window messages.
6. Replace the hard-coded prefix check with validation against the configured Nebula CIDR/interface.
7. Add per-peer rate limits and concurrent-call limits.
8. Redact signatures, SDP, ICE addresses, and device secrets from logs.

**Exit criteria:** modified, forged, stale, replayed, oversized, wrong-peer, and non-Nebula messages all fail closed in automated tests.

### Phase B2 — Complete event and session APIs for the frontend

Add the following authenticated APIs:

| Method and route | Purpose |
|---|---|
| `GET /api/v1/calls?state=&direction=&cursor=` | List incoming, outgoing, active, ended, and missed sessions. |
| `GET /api/v1/calls/active` | Return the one active call or all active calls according to concurrency policy. |
| `GET /api/v1/calls/events` | Authenticated SSE stream for call state/events; WebSocket is acceptable if two-way transport is needed. |
| `GET /api/v1/call/:id` | Full frontend-safe detail, including peer display data and allowed actions. |
| `POST /api/v1/call/:id/accept` | Path-oriented replacement/alias for accept. |
| `POST /api/v1/call/:id/reject` | Reject with a bounded reason code. |
| `POST /api/v1/call/:id/end` | End locally and send a signed remote hang-up. |
| `POST /api/v1/call/:id/signal` | Submit browser SDP/candidate messages after authorization. |
| `GET /api/v1/call/:id/signals?after=` | Fetch pending browser signals if WebSocket delivery is not used. |
| `POST /api/v1/call/:id/media-ready` | Confirm local WebRTC connected state. |
| `POST /api/v1/call/:id/quality` | Submit normalized `getStats()` quality data, sampled/rate-limited. |

Do not make the frontend send authoritative `initiator_device_id`, `initiator_virtual_id`, or caller role. Derive them from the authenticated session and bound Guardian identity. The frontend should send a target peer ID, requested media, and optional UI metadata only.

Recommended initiate request:

```json
{
  "target_peer_id": "guardian-b",
  "media": ["audio", "video"]
}
```

Recommended frontend-safe session response:

```json
{
  "session_id": "uuid",
  "direction": "outgoing",
  "state": "offer_sent",
  "peer": {
    "id": "guardian-b",
    "display_name": "Entrance Camera",
    "nebula_reachable": true,
    "trust": "verified"
  },
  "requested_media": ["audio", "video"],
  "accepted_media": [],
  "allowed_actions": ["cancel"],
  "created_at": "...",
  "updated_at": "...",
  "reason_code": null
}
```

Use stable, lowercase wire states even if Rust enum display labels remain PascalCase.

### Phase B3 — Browser WebRTC signaling relay

1. Extend Nebula signaling with SDP offer, SDP answer, trickle ICE, end-of-candidates, media-ready, hang-up, and heartbeat messages.
2. Bind signaling messages to the already-authorized call session.
3. Buffer short-lived messages for reconnecting frontends with strict TTL and count/size limits.
4. Deliver remote messages to the browser over authenticated SSE/WebSocket.
5. Enforce direction and state: only the initiator may send the first SDP offer; candidates are accepted only after authorization; media-ready is accepted only during negotiation.
6. Add timeouts:
   - ringing/answer timeout: configurable, default 30 seconds;
   - negotiation timeout: 15 seconds;
   - heartbeat interval: 2 seconds;
   - peer-lost threshold: 3 missed heartbeats;
   - stale session cleanup and browser disconnect grace period.
7. Add glare handling if simultaneous calling is supported. A deterministic tie-breaker can use device ID plus session ID.

### Phase B4 — Real media and connection proof

For the recommended browser-owned approach:

1. Browser creates `RTCPeerConnection` only after the backend returns an authorized session.
2. Use Nebula host candidates where browser routing permits them. Decide whether public STUN is forbidden; current planning says no cloud TURN.
3. Determine a supported NAT policy:
   - preferred: direct host candidates across the Nebula-reachable topology;
   - optional: organization-owned STUN/TURN only;
   - fail clearly when no route exists rather than silently using public infrastructure.
4. Verify that the selected browser can route media to the remote endpoint. A browser cannot automatically bind media to an arbitrary daemon-only tunnel without OS routing support.
5. Move session state `Accepted -> MediaNegotiation` when SDP exchange begins.
6. Move to `Connected` only after:
   - browser reports `RTCPeerConnection.connectionState === "connected"`;
   - remote sends signed `media_ready`;
   - the media gate remains authorized.
7. On failure/disconnect, expose a reason code and attempt one bounded ICE restart before ending.

If native board media is required instead, first run a two-board spike comparing `str0m` and suitable Rust alternatives. Replace the simulated modules, integrate actual capture/playback and codecs, and never ship the XOR SRTP code.

### Phase B5 — Persistence, observability, and cleanup

- Persist call summaries and terminal reason codes; do not persist raw SDP or candidates.
- Keep active negotiation state ephemeral and reconstruct safely after restart as ended/interrupted.
- Add metrics: attempts, policy denial, verification failure, setup time, connected duration, packet loss, RTT, jitter, ICE failures, and reason-coded termination.
- Audit: initiation, verified peer identity, policy result, accept/reject, media-ready, ICE failure, hang-up, and timeout.
- Add structured reason codes such as `busy`, `declined`, `policy_denied`, `identity_failed`, `unreachable`, `ring_timeout`, `media_timeout`, `permission_denied`, and `network_lost`.

## 5. Frontend implementation plan

### 5.1 Frontend project boundary

Because no frontend exists here, add or identify a separate frontend package. A recommended structure for a React + TypeScript application is:

```text
frontend/
  src/
    app/router.tsx
    api/http.ts
    api/calls.ts
    api/network.ts
    features/calls/
      call.types.ts
      call.store.ts
      call.events.ts
      webrtc.service.ts
      media-devices.ts
      IncomingCallDialog.tsx
      OutgoingCallDialog.tsx
      CallingScreen.tsx
      CallControls.tsx
      ConnectionStatus.tsx
      DevicePicker.tsx
    pages/
      NetworkPage.tsx
      PicturesPage.tsx
      CallPage.tsx
```

If the real frontend uses another framework, preserve the state/API design below and adapt only the file/component syntax.

### 5.2 Global call coordinator

Calling cannot live only inside the Network page because incoming calls must appear regardless of the current route.

At application startup, after authentication:

1. Connect to `/api/v1/calls/events`.
2. Hydrate `/api/v1/calls/active` after login, refresh, and event-stream reconnect.
3. Store only serializable call metadata in the global store.
4. Keep `RTCPeerConnection`, `MediaStream`, and device handles inside a dedicated service, not Redux/local-storage state.
5. Mount one global incoming-call dialog and one global active-call overlay.
6. Never persist bearer tokens, raw SDP, ICE candidates, or media streams in local storage.

Suggested client states:

```text
idle
preparing_media
authorizing
ringing_outgoing
ringing_incoming
verifying
negotiating
connected
reconnecting
ending
ended
failed
```

Map backend states into user language; do not expose internal enum names directly.

| Backend state | Frontend text/action |
|---|---|
| `LocalPolicyCheck` | “Checking call policy…”; cancel only. |
| `OfferSent` | “Ringing…”; cancel. |
| `OfferReceived` | Incoming call dialog; accept or decline. |
| `Verifying` | “Verifying Guardian identity…”; controls disabled except decline/end. |
| `Authorizing` | “Checking permissions…” |
| `Accepted` | “Preparing secure media…” |
| `MediaNegotiation` | “Establishing encrypted connection…” |
| `Connected` | Full call controls and duration. |
| `EndCall` | End reason, cleanup, return to previous page. |

### 5.3 Network page integration

The Network page is the primary call-entry surface.

#### Peer/device list changes

Use `/api/v1/peers` for trusted Guardian peers and discovery inventory only for network inventory. Do not show a call action for arbitrary scanned devices unless they are mapped to an authenticated Guardian identity.

Each trusted peer row/card should show:

- display name and peer ID;
- online/reachable status and last seen;
- trust/attestation status;
- Nebula address only in an expandable technical detail area;
- audio-call button;
- video-call button;
- disabled state with a tooltip when offline, unverified, blocked by policy, missing media capability, or already busy.

The row action sequence is:

```text
Click audio/video
  -> validate peer and local active-call state
  -> request microphone/camera permission
  -> show local preview for video
  -> POST call initiation
  -> open outgoing calling screen
  -> receive events
  -> exchange SDP/ICE after acceptance
  -> connected screen
```

Permission can be requested just before initiation so the remote peer is not rung when local media is unavailable. The UI must clearly handle denied browser permission and provide browser-specific recovery instructions.

#### Calling screen on the Network page

Implement the calling screen as a route-backed modal/overlay, for example `/network/call/:sessionId`, so refresh and browser navigation can restore the active session. The underlying Network page remains visible but inert while a call is active.

Layout:

- top bar: peer name, verified shield, connection label, duration;
- center: remote video; avatar/identity fallback for audio-only or video unavailable;
- small movable local preview, mirrored visually but not transmitted mirrored;
- pre-connect panel showing policy, identity, and secure-media progress;
- bottom controls: microphone, camera, speaker/output where supported, screen share if authorized, device menu, and red end button;
- quality popover: route type, RTT, packet loss, jitter, resolution, codec—no sensitive addresses by default;
- error banner with a human-readable reason and retry action only where retry is safe.

Incoming calls should appear globally and, on Network page, also highlight the calling peer row. The dialog shows peer identity, verified state, requested media, accept, decline, and “accept audio only” when policy and offer permit it.

#### Network page concurrency rules

- One active/ringing call per browser and per Guardian initially.
- A second incoming call receives `busy` automatically after backend confirmation.
- Disable scan/peer mutations that could disrupt the overlay during an active call, or warn before executing them.
- Network transport changes should trigger `reconnecting`, then an ICE restart; do not immediately mark the call ended.

### 5.4 `/pictures` page integration

Since `/pictures` does not exist in this checkout, this plan assumes it is a gallery/live-camera page represented by external designs.

Implement `/pictures` with these call-related behaviors:

1. A picture/camera tile that is associated with a trusted Guardian shows “Call device” actions.
2. Clicking the phone icon starts audio; clicking the camera icon starts video.
3. The target peer must come from trusted backend data attached to the picture record—never from a user-editable URL/IP field.
4. Reuse the exact same global call coordinator and `CallingScreen`; do not build a second WebRTC implementation for this page.
5. Navigate to `/pictures/call/:sessionId` or open the shared route-backed overlay while retaining gallery context.
6. If a tile represents a still image without an authenticated Guardian mapping, no call button is displayed.
7. For a camera-type peer, the frontend can request video by default; microphone transmission must still be explicit and visible.
8. On call completion, return to the same gallery position/filter and show a short non-sensitive result toast.

Before implementation, obtain the `/pictures` page source or mockups and document:

- exact tile/card layout and responsive breakpoints;
- where peer/device identity is stored;
- whether “pictures” means still-image gallery, camera devices, or a route name only;
- expected desktop/tablet/mobile behavior;
- approved icons, colors, and accessibility requirements.

### 5.5 WebRTC client service

`webrtc.service.ts` should expose a small controlled API:

```ts
prepareMedia(options)
startAsCaller(sessionId)
acceptAsCallee(sessionId)
applyRemoteDescription(description)
addRemoteCandidate(candidate)
setMuted(value)
setCameraEnabled(value)
startScreenShare()
stopScreenShare()
restartIce()
getQualitySnapshot()
close()
```

Implementation rules:

- Use one `RTCPeerConnection` per session.
- Register all event handlers before setting descriptions.
- Queue remote ICE candidates until `remoteDescription` is set.
- Send trickle candidates through the authenticated backend channel.
- Use `srcObject` for media elements; never create object URLs for streams.
- Stop every local track and close the peer connection on end, failure, logout, or terminal event.
- Listen for device removal and renegotiate/fallback appropriately.
- Use `replaceTrack` for camera switching and screen share where possible.
- Sample `getStats()` every 2–5 seconds while connected; do not render-update on every raw report.
- Treat `failed` differently from temporary `disconnected`.

Initial media constraints:

- audio: echo cancellation, noise suppression, and auto gain enabled;
- video: ideal 1280×720 at 30 fps with graceful fallback;
- no screen capture until an explicit user gesture;
- no automatic unmute when reconnecting.

### 5.6 Frontend API and error handling

- Centralize HTTPS calls and auth refresh/logout behavior.
- Generate an idempotency key for call initiation to prevent double-click duplicate calls.
- Disable call buttons while a request is pending.
- Reconcile state from the server after event gaps; events are notifications, server state is authoritative.
- Show friendly messages while logging only a correlation ID and safe reason code.
- On tab refresh during ringing/connected state, fetch active state and attempt controlled media recovery. Do not claim the media remained connected.
- On logout, end or detach according to explicit product policy; default to ending the call.

### 5.7 Accessibility and responsive behavior

- All controls need accessible names, keyboard operation, visible focus, and pressed/muted state announcements.
- Incoming dialog must trap focus and announce caller and requested media.
- Never rely on red/green color alone for call or trust status.
- Respect reduced motion.
- On narrow screens, remote video fills the viewport and controls remain reachable without hover.
- Prevent screen sleep during active calls where browser support allows, with graceful fallback.

## 6. End-to-end flows

### 6.1 Outgoing video call

1. User selects Video Call on Network or `/pictures`.
2. Frontend checks that no call is active and requests mic/camera access.
3. Frontend calls the simplified initiate endpoint with target peer and media.
4. Backend derives local identity, applies UEP policy, creates a session, signs an offer, and sends it through Nebula.
5. Caller UI displays Ringing and subscribes to session events.
6. Receiver backend verifies signature, trust chain, freshness, replay state, peer mapping, and local policy.
7. Receiver frontend gets a verified incoming-call event.
8. Receiver accepts; backend sends a signed answer.
9. Caller browser creates SDP offer; SDP and trickle candidates transit through the two local backends over Nebula signaling.
10. Receiver creates SDP answer and both browsers perform ICE/DTLS-SRTP through native WebRTC.
11. Each browser reports media-ready; Guardians exchange signed readiness.
12. Backend marks `Connected`; both UIs expose controls and duration.
13. Either side ends; a signed hang-up is propagated, media tracks stop, session becomes terminal, and audit/summary are written.

### 6.2 Incoming rejected/denied call

- Verification or policy failure: do not show an actionable incoming dialog; send a generic signed rejection and audit the detailed local reason.
- User decline: send `declined`, terminate both sessions, clean UI.
- Busy: backend rejects automatically with `busy` and does not interrupt the active call.

### 6.3 Connection loss

1. UI shows Reconnecting after a short debounce.
2. Client requests an ICE restart once.
3. Backend and remote maintain heartbeat/grace timeout.
4. On recovery, return to Connected without unmuting tracks.
5. On timeout, both sides end with `network_lost` and release all resources.

## 7. Testing plan

### Backend unit and integration tests

- Canonical signature verification for every message type.
- Wrong key, altered field, stale timestamp, replayed sequence/nonce, wrong session, and oversized payload rejection.
- Full inbound/outbound FSM including hang-up and timeout.
- Policy and trust verification fail-closed behavior.
- Event-stream reconnect and event ordering.
- Session list/inbox authorization and pagination.
- Remote hang-up propagation.
- Simultaneous calls, busy response, double initiation, and restart recovery.
- Two real Guardian processes bound to test overlay addresses where CI permits.

### Frontend tests

- Component tests for peer actions, incoming dialog, calling screen, controls, and all error states.
- Store/reducer tests for out-of-order and duplicate events.
- WebRTC service tests using a mock peer-connection adapter.
- Permission denied, no device, device removed, failed ICE, reconnect, remote hang-up, refresh, and logout cleanup.
- Accessibility scans and keyboard-only call flow.

### Real end-to-end acceptance matrix

Test with two physical boards and two supported browsers:

| Scenario | Required result |
|---|---|
| Audio call on same LAN/Nebula circle | Bidirectional audio; mute/end work. |
| Video call | Bidirectional video/audio at negotiated fallback quality. |
| Incoming call while viewing another route | Global dialog appears and routes correctly after accept. |
| Network page call | Peer row and shared calling screen stay synchronized. |
| `/pictures` call | Correct trusted tile maps to the correct Guardian; shared calling screen works. |
| Unauthorized peer | No media/signaling beyond safe rejection; clear UI reason. |
| Tampered signaling | Rejected and audited; no incoming prompt. |
| Browser permission denied | Remote is not rung, or initiation is canceled deterministically. |
| Link interruption | Reconnect once or end cleanly within timeout. |
| No permitted direct route | Clear connection failure; no unauthorized public relay fallback. |

Measure setup time, RTT, packet loss, audio continuity, CPU/memory, and thermal behavior on target hardware.

## 8. Delivery order and milestones

### Milestone 0 — Product/topology confirmation (1–2 days)

- Locate the actual frontend and `/pictures` designs/source.
- Confirm browser-owned media versus board-native media.
- Confirm supported browsers, one-call concurrency, screen sharing, and STUN/TURN policy.
- Freeze wire state names and end-reason codes.

### Milestone 1 — Secure signaling completion (1–2 weeks)

- Canonical envelopes and real signature verification.
- Full trust-chain/policy wiring.
- Replay, bounds, rate limits, hang-up, heartbeat, SDP, and ICE messages.
- Security and negative tests.

### Milestone 2 — Frontend-ready call API (1 week)

- Session list/detail/active APIs.
- SSE/WebSocket events and recovery.
- Safe identity-derived initiation contract.
- Remote end, timeouts, reason codes, and persistence summary.

### Milestone 3 — Shared frontend call foundation (1–2 weeks)

- API client, global call coordinator, event reconciliation, WebRTC service, device permissions, incoming/outgoing dialogs, and shared Calling Screen.
- Mock-backend component and browser tests.

### Milestone 4 — Network and `/pictures` integration (1 week after designs exist)

- Trusted-peer call buttons and status on Network page.
- Route-backed calling overlay.
- Trusted picture/camera tile mapping and shared call entry.
- Responsive and accessibility work.

### Milestone 5 — Two-device media hardening (1–2 weeks)

- Physical-board/browser testing.
- ICE/reconnect behavior, quality telemetry, constrained-network testing, and performance tuning.
- Security review and removal/feature-gating of all simulated media code.

### Milestone 6 — Release gate

- No simulated DTLS/SRTP/ICE code is reachable in production.
- No call reaches `Connected` without real WebRTC plus remote media-ready proof.
- All negative security tests and two-device E2E tests pass.
- Operational documentation, browser support, firewall/overlay requirements, and troubleshooting are published.

## 9. Definition of done

Calling is complete only when all of the following are true:

- A trusted user can start audio/video from both Network and `/pictures` surfaces.
- A verified receiver gets a global incoming prompt and can accept or decline.
- Real media flows bidirectionally using standards-compliant browser WebRTC.
- Every control-plane message is authenticated, replay-protected, session-bound, and transported only through the intended Guardian/Nebula path.
- Unauthorized, unverified, stale, forged, and busy calls fail closed.
- `Connected` reflects real local and remote media readiness.
- Mute, camera, device switching, end, remote end, timeout, and one bounded reconnect behave consistently.
- Refresh, logout, device removal, and daemon restart do not leak media tracks or leave false active state.
- The UI is responsive, keyboard accessible, and uses stable server-authoritative state.
- Automated unit, integration, security, frontend, and two-device tests pass.
- Simulated XOR “SRTP,” simulated DTLS, and simulated ICE are removed from production paths.

## 10. Immediate next actions

1. Provide or add the frontend repository and `/pictures` mockups/source.
2. Decide whether browsers or Guardian boards own media capture and `RTCPeerConnection`.
3. Implement real signature verification before expanding signaling.
4. Agree on the event/API contracts in Phase B2.
5. Build a minimal two-browser, two-Guardian audio-call spike through Nebula signaling.
6. Only after the spike proves routing and media ownership, implement the full Network and `/pictures` UI.
