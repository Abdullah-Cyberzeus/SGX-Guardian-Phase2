# SG-X Guardian PWA — Complete Implementation Plan

**Document status:** Implementation roadmap  
**Created:** August 12, 2026  
**Scope:** Guardian-hosted member PWA and Internet-independent local Admin Console  
**Source requirements:** `Guardian_PWA_Complete_Design_Document.pdf` and `Guardian_PWA_User_Guide.pdf`  
**Repository:** `/home/kali/Documents/SGX`  

---

## 1. Purpose

This plan defines the work required to complete Guardian PWA using the current SG-X Guardian repository as the implementation baseline.

The target product has two experiences served by the same Guardian binary:

1. **Member PWA** — a restricted, installable browser experience for messaging, calls, contacts, files, and personal settings.
2. **Admin Console** — the existing Guardian-management experience, available without public Internet whenever the administrator can reach the Guardian over its local LAN or Guardian Wi-Fi.

The work is divided into phases with explicit dependencies, deliverables, acceptance criteria, and test requirements. A phase is not complete merely because the screen exists; its backend enforcement, persistence, offline behavior, and security checks must also work.

---

## 2. Scope Boundaries

### 2.1 Included

- Guardian-hosted PWA served from the embedded Rust web server.
- Local access through Guardian Wi-Fi/LAN and `https://guardian.local`.
- Local onboarding and Guardian fingerprint verification.
- Guardian-issued browser membership/session credentials.
- Member-only navigation and authorization.
- Messages, calls, contacts, files, settings, and notifications.
- IndexedDB caching and encrypted pending-message storage.
- Offline application shell and cached read-only data.
- Automatic synchronization when Guardian connectivity returns.
- Internet-independent Admin Console access through local Guardian APIs.
- Browser security, Guardian API authorization, audit events, testing, packaging, and documentation.
- Alignment of the existing API with the PWA PDF contract.

### 2.2 Explicitly excluded

- Cross-network Guardian communication.
- Public Nebula lighthouse or relay deployment.
- NAT traversal, router port forwarding, TURN over the Internet, or cloud relay.
- Native-to-container or cross-site deployment matrices.
- Remote PWA access outside the Guardian's reachable local network.
- Guardian Mobile App implementation.
- A new browser User DID.
- A browser acting as a Guardian mesh node.
- Browser hardware attestation.

Existing Guardian-to-Guardian LAN discovery, attestation, Circle formation, and Nebula communication remain dependencies, but this plan does not redesign them.

---

## 3. Locked Architecture Decisions

These decisions must remain stable unless a formal decision record changes them.

### 3.1 Identity model

- The **Guardian DID** remains the Circle and mesh identity.
- The browser does not generate a new DID.
- The browser does not receive the Guardian private key.
- The browser does not become a mesh node.
- Guardian-to-Guardian messages, calls, and files continue to be performed by the Guardian backend using the Guardian identity.
- Human accountability is represented by a local Guardian account/session identifier in addition to the Guardian DID.

Example audit identity:

```text
guardian_did: did:guardian:node-a
local_actor: member-42
browser_credential_id: pwa-session-7f2...
action: chat.message.send
```

### 3.2 Browser credential model

The phrase “membership credentials stored on your device” in the User Guide will be implemented as a Guardian-issued, revocable PWA credential/session—not as a DID or Membership VC.

The credential must bind at least:

- Credential ID.
- Guardian ID.
- Circle ID or allowed Circle IDs.
- Local actor/account ID.
- Role: `member` or `admin`.
- Permissions/scopes.
- Issued-at and expiry timestamps.
- Browser/device registration identifier.
- Guardian signature or server-verifiable opaque token.
- Revocation state.

Long-lived secrets must not be stored as unprotected plaintext in localStorage. IndexedDB can store a credential only after the security design defines its wrapping and recovery behavior. Short-lived access tokens may be held in memory where practical.

### 3.3 Application model

- One React application may serve both member and admin roles.
- Routes, navigation, and actions are selected by the authenticated role.
- Backend authorization is authoritative. Hiding an admin button is not authorization.
- The member PWA has five primary destinations: Messages, Calls, Contacts, Files, Settings.
- The Admin Console retains Guardian-management routes.

### 3.4 Meaning of “offline”

Two states must be distinguished:

| State | Internet | Guardian | Expected behavior |
|---|---:|---:|---|
| Local offline operation | Unavailable | Reachable | Member PWA and Admin Console use full local Guardian functionality |
| Disconnected PWA | Unavailable or irrelevant | Unreachable | Cached member data remains readable; messages can be queued; live calls/downloads/admin actions are unavailable |

Connectivity must be measured against the Guardian health endpoint, not `navigator.onLine`, because the browser may reach the Guardian while having no public Internet.

### 3.5 Cryptographic boundary

The current Guardian chat path relies on the Nebula-secured Guardian-to-Guardian channel. The PDFs additionally state that messages are encrypted on the user's device. Phase 0 must resolve this wording before implementation:

- **Preferred fit for the locked identity model:** Browser-to-Guardian uses HTTPS; the Guardian performs message encryption and signing with Guardian-controlled keys before persistence/forwarding.
- If literal browser-side end-to-end encryption is retained, a separate browser cryptographic key lifecycle is required. Such a key would be a content-encryption key, not a DID or mesh identity.

No implementation may claim client-side E2EE while the production path stores plaintext message content under a field named `encrypted_payload`.

---

## 4. Current Repository Baseline

### 4.1 Implemented foundations to retain

| Capability | Current location | Baseline assessment |
|---|---|---|
| Embedded frontend | `src/api/frontend.rs`, `build.rs` | Implemented; React assets are embedded in the Guardian binary |
| PWA manifest | `frontend/public/manifest.json` | Foundation exists |
| Service worker | `frontend/public/sw.js`, `frontend/src/app/App.tsx` | Basic shell caching and registration exist |
| Guardian local domain | `src/netbridge/`, `config/dnsmasq/dnsmasq.conf.template` | `guardian.local` and local DHCP/DNS foundations exist |
| Authentication | `src/api/auth/`, `frontend/src/app/contexts/AuthContext.tsx` | Local auth/session foundations exist; role integration must be completed |
| Circle lifecycle | `src/circle/`, Circle API routes and frontend services | Circle, invites, join, members, and revocation foundations exist |
| Messaging | `src/chat/`, chat handlers, `chatService.ts`, conversation screens | Direct/group chat, persistence, receipts, sync, and WebSocket foundations exist |
| Calls | `src/call/`, `src/media/`, `frontend/src/features/calls/` | Signaling and WebRTC UI/service foundations exist; production media assurance remains |
| Files/vault | `src/vault/`, `src/xfer/`, chat attachments, storage screens | Strong backend foundation; member PWA ownership/access features incomplete |
| Notifications | `src/notify/`, notification API/context/screens | History, preferences, and live stream foundations exist |
| Audit | `src/audit/` | Tamper-evident audit foundation exists |
| Responsive routes | `frontend/src/app/routes.ts` | Current application supports mobile and desktop layouts |

### 4.2 Known gaps that this plan must close

- Current application is primarily an Admin Console, not a restricted five-tab member PWA.
- No complete fingerprint-verification member onboarding flow.
- No complete Guardian-issued browser membership credential lifecycle.
- No complete IndexedDB stores for membership, messages, contacts, files, calls, pending items, and settings.
- No durable browser-side offline message queue.
- Cached member data is not the canonical fallback when the Guardian is unreachable.
- Current service worker precaches only the root shell and does not use Workbox.
- PWA manifest references icon/screenshot assets that are absent under the expected names.
- Chat UI sends directly to the Guardian and reports failure when unreachable.
- Production chat handling currently persists plaintext JSON in `encrypted_payload`.
- The Files view is mainly derived from chat attachments and lacks the full owner control contract.
- Contacts, last-seen, and presence behavior need a dedicated member interface.
- PWA-specific offline, mobile-browser, security, and coverage tests are missing.
- Some UI areas still contain mock fallbacks; member and admin acceptance paths must fail truthfully rather than display simulated success.
- The PWA PDF API names and the current `/api/v1/...` routes are not fully aligned.
- The design document specifies SQLite while several current subsystems use durable JSON/JSONL storage; the authoritative persistence contract must be recorded.

---

## 5. Target Architecture

```text
Phone / Tablet / Desktop Browser
             |
             | HTTPS to guardian.local
             v
Embedded React Application
  +-------------------+---------------------+
  | Member PWA        | Admin Console       |
  | 5-tab navigation  | Management routes   |
  +-------------------+---------------------+
             |
             | Authenticated /api/v1 requests + WebSocket/SSE
             v
SG-X Guardian Rust Backend
  +----------+----------+----------+----------+
  | Auth/RBAC| Circle   | Chat     | Calls    |
  | Files    | Notify   | Audit    | Sync     |
  +----------+----------+----------+----------+
             |
             | Existing trusted LAN/Nebula path
             v
Other locally reachable Guardians in the Circle
```

Browser persistence:

```text
Service Worker Cache
  - versioned application shell
  - static assets only

IndexedDB
  - membership/session metadata
  - encrypted/cached messages
  - contacts and presence snapshot
  - file metadata
  - call history
  - encrypted pending queue
  - member settings
  - synchronization cursors
```

---

## 6. Phase Overview

| Phase | Name | Primary outcome |
|---:|---|---|
| 0 | Requirements and security decisions | Ambiguities resolved; API/security/storage contracts locked |
| 1 | Role and authorization foundation | Member and admin experiences securely separated |
| 2 | Local access and member onboarding | `guardian.local`, fingerprint verification, and browser credential lifecycle complete |
| 3 | PWA shell and offline infrastructure | Installable application shell and IndexedDB repositories complete |
| 4 | Connectivity and synchronization engine | Guardian-aware online/offline state and deterministic sync complete |
| 5 | Messaging and offline queue | Cached messaging and durable `Pending → Sent → Delivered` workflow complete |
| 6 | Contacts and presence | Member roster, profile, presence, and quick actions complete |
| 7 | Files | Encrypted sharing, metadata, ownership, revoke, expiry, and offline listing complete |
| 8 | Voice and video | Production local calls, controls, quality, recovery, and history complete |
| 9 | Settings and notifications | Required preferences, storage controls, and missed-activity delivery complete |
| 10 | Offline Admin Console hardening | All supported admin workflows operate without public Internet |
| 11 | Security, reliability, and performance | Threat model controls and recovery behavior verified |
| 12 | Device QA, packaging, and release | Supported-browser evidence and production release artifacts complete |

Phases may overlap only where their dependencies allow. Phase 5 must not begin its final integration before Phases 2–4 define credentials, IndexedDB, and synchronization.

---

## 7. Detailed Phased Plan

## Phase 0 — Requirements, Contracts, and Decision Records

### Objective

Turn ambiguous PDF statements into implementable, testable contracts before expanding the codebase.

### Tasks

1. Create architecture decision records for:
   - Guardian DID as the only Circle/mesh identity.
   - Browser as an authenticated Guardian client.
   - Browser credential/session format and revocation behavior.
   - Member versus admin roles and scopes.
   - Browser-to-Guardian and Guardian-to-Guardian encryption boundaries.
   - SQLite requirement versus current durable file storage.
   - API compatibility strategy.
   - Local TLS trust and fingerprint derivation.
   - PWA cache policy for sensitive data.
2. Define a permission matrix.
3. Define canonical message states and their acknowledgements:
   - `pending_local`
   - `accepted_by_guardian`
   - `delivered_to_remote_guardian`
   - `read`
   - `failed_retryable`
   - `failed_permanent`
4. Define canonical connectivity states:
   - `guardian_connected`
   - `guardian_degraded`
   - `guardian_reconnecting`
   - `guardian_offline`
5. Define data retention and cache-clearing behavior.
6. Define supported browser/device versions from the User Guide.
7. Map PDF endpoints to current APIs and identify aliases or migrations.
8. Define PWA release version linkage to Guardian firmware.

### Required permission matrix

| Capability | Member | Admin |
|---|---:|---:|
| Read own allowed Circles | Yes | Yes |
| Message/call Circle members | Yes | Yes |
| Upload/download allowed files | Yes | Yes |
| Change personal settings | Yes | Yes |
| Create/delete Circle | No | Yes |
| Add/remove/revoke members | No | Yes |
| Manage Guardian peers | No | Yes |
| Manage devices/firewall/policies | No | Yes |
| View administrative audit/security data | No | Yes |
| Restart/reconfigure Guardian | No | Yes |

### Deliverables

- `docs/decisions/` ADRs for the decisions above.
- PWA API contract document.
- Browser storage schema document.
- Permission matrix used by both frontend and backend.
- Requirements traceability table linking each PDF requirement to a phase and test.

### Exit criteria

- No unresolved identity, encryption, role, storage, or TLS question blocks implementation.
- Each PWA PDF requirement has an owner, implementation phase, and acceptance test.
- Product owner approves the browser-as-interface model.

---

## Phase 1 — Role Separation and Authorization Foundation

### Objective

Create a secure member experience without weakening the existing Admin Console.

### Implementation status — 2026-08-12

Phase 1 is implemented in source with the following boundaries:

- The product exposes two account roles: `admin` and `member`; persisted accounts and signed sessions carry server-authoritative scopes. Legacy `owner` records remain compatible as administrators, while a role or scoped-permission change invalidates a scoped token immediately.
- The backend uses a default-deny member permission map. Owner/admin behavior remains allowed so certificate assignment, Circle policy operations, attestation, discovery, transport, and Nebula administration keep their existing paths.
- Role enforcement applies when local login is enabled. The pre-existing explicit login-disabled deployment gate remains an owner/admin appliance mode for compatibility and does not create a member session.
- Member communication is limited to active DIDs that share an existing Circle with the hosting Guardian DID. The browser is not assigned a DID and is not introduced as another mesh device.
- Group message access verifies active local Guardian membership. Member notification history, unread state, and live events exclude device/security/admin events. Member contacts omit IP addresses, ports, topology, policies, and attestation internals.
- Login and Circle join/preview attempts use the existing bounded rate limiter. Fingerprint-confirmation and browser-credential issuance limits will be attached when those endpoints are introduced in Phase 2; no placeholder public endpoint was added.
- Logout, revoke-all-sessions, expiry enforcement, inactive-account checks, and immediate role/scope-change rejection are implemented. Removal of a named browser registration remains Phase 2 work because browser registrations do not exist before the credential flow is implemented.
- The frontend now has backend-backed role guards, a safe access-restricted screen, session-expiry handling, and a member shell with Messages, Calls, Contacts, Files, and Settings. Admin navigation is preserved.
- One-time local account setup now presents Admin and Member roles. The backend validates and persists the selected role, derives its fixed scopes, and returns the authoritative role so signup/login route to the appropriate shell. Caller-provided scopes are never accepted.
- Member runtime composition does not mount certificate approval or daemon-restart providers and does not prefetch administrative peer/DID endpoints. Member Vault UI hides management mutations not granted to the member role.

Validation for this implementation is deliberately source-level only at the owner's request. No build, Docker, Cargo check, or other heavy command was run. `git diff --check` passes; the optional Rust formatting component is not installed and was not installed as part of this work.

### Backend tasks

1. Extend local account/session records with role and scopes.
2. Add reusable authorization middleware for member/admin scopes.
3. Protect every PWA and admin endpoint; remove unauthenticated administrative gaps.
4. Add Circle-level authorization checks to messages, calls, files, roster, and notifications.
5. Record successful and denied authorization decisions in the audit system.
6. Add session logout, revoke-all, expire, and browser-registration removal operations.
7. Rate-limit login, join, fingerprint confirmation, and credential issuance.

### Frontend tasks

1. Create route guards for unauthenticated, member, and admin states.
2. Create a member application shell with five primary tabs:
   - Messages
   - Calls
   - Contacts
   - Files
   - Settings
3. Preserve the Admin Console navigation for admin sessions.
4. Remove admin links, data prefetches, and management actions from the member shell.
5. Add a safe `403` screen and session-expired workflow.
6. Remove reliance on mock fallback in member-critical screens.

### Suggested code areas

- `src/api/auth/`
- `src/api/auth/middleware.rs`
- `src/api/handlers/`
- `frontend/src/app/contexts/AuthContext.tsx`
- `frontend/src/app/routes.ts`
- New `frontend/src/app/layouts/MemberLayout.tsx`
- New shared permission definitions in backend and frontend types

### Tests

- Member cannot call any admin endpoint.
- Direct URL navigation cannot bypass role restrictions.
- Admin retains access to approved management endpoints.
- Revoked/expired sessions fail immediately.
- Session role changes take effect without browser cache bypass.
- Denied operations generate audit records without leaking sensitive details.

### Exit criteria

- Backend—not the UI—enforces every protected operation.
- A member can use only the five PWA functional areas.
- Existing admin functionality remains reachable for admin sessions.

---

## Phase 2 — Local Access, Fingerprint Verification, and Membership Session

**Implementation status (August 12, 2026):** Implemented in source. Static/source-level
verification is complete; build, container, and runtime test commands were intentionally not
run on the development laptop. Device validation on a clean phone remains a release check.

Implemented contract:

- `guardian.local` receives an explicit dnsmasq gateway record, and common captive-network
  probes redirect to `/join`.
- `GET /api/v1/pwa/onboarding` is the minimal unauthenticated Guardian summary. The invite
  preview and member join routes are also public, narrowly rate-limited onboarding operations;
  other APIs remain authenticated.
- The fingerprint is the first 80 bits of SHA-256 over the Guardian device signing public key,
  encoded as 16 unambiguous Crockford Base32 characters and displayed `XXXX-XXXX-XXXX-XXXX`.
  It identifies the Guardian public identity, not the browser and not a new user DID.
- The user must type the independently obtained physical-Guardian fingerprint and explicitly
  confirm it. A mismatch blocks joining. Shared-LAN `guardian.local` ambiguity therefore cannot
  silently select a different Guardian.
- A PWA member invitation reuses the existing signed, expiring, max-use Circle invitation
  format, but enters a separate local-browser registration path. It never executes the existing
  Guardian-to-Guardian join/attestation/certificate/Nebula flow.
- Only a `member` invitation issued by this Guardian for one of its Circles may create a browser
  member. Redemption is replay-protected and compensated if the local account write fails.
- The persisted member record and signed session bind local actor ID, role, fixed server-derived
  scopes, Circle ID, browser registration ID, Guardian fingerprint, invite ID, and expiration.
- Member login, middleware, and refresh reject inactive/expired registrations and fingerprint
  rotation. Rotation requires a new verified invitation/rejoin; it is never silently accepted.
- Refresh rotates the session token; logout, revoke-all, and remove-browser workflows are
  available. Rejoin invalidates earlier sessions. Registration validity defaults to 30 days and
  can be configured with `SGX_PWA_REGISTRATION_DAYS`.
- Member resource handlers derive contacts, chats, calls, transfers, and Circle visibility from
  the account's Circle scope. Admin/legacy-owner behavior and existing device invitation flows
  are retained.
- The browser receives only its bearer session material. Member tokens are kept in per-tab
  `sessionStorage` (and memory in the API client), not durable `localStorage`; closing the browser
  requires login again while the server-side registration remains valid. The browser receives no
  Guardian private key, creates no DID, and does not become a mesh member.
- Fingerprint confirmation, credential issue/rejection/expiry/rotation/revocation, session
  refresh, and member authorization decisions emit audit events.

Deployment note: the captive-probe handlers are present on the Guardian web router. Automatic
OS captive-window launch also depends on the deployed hotspot forwarding HTTP probe traffic to
that listener; this must be confirmed during device validation. The same fingerprint must be
printed on or independently displayed by the physical Guardian during provisioning.

### Objective

Implement the User Guide’s complete local joining experience.

### Local network tasks

1. Verify `guardian.local` resolves to the Guardian hotspot/LAN address.
2. Add the required local DNS host record if `domain=guardian.local` alone is insufficient.
3. Implement captive-portal detection endpoints and redirect behavior for supported platforms.
4. Ensure the welcome page is reachable before authentication without exposing other APIs.
5. Define behavior when multiple Guardians advertise `guardian.local` on one LAN.

### TLS and fingerprint tasks

1. Define the Guardian fingerprint as a stable representation of the Guardian TLS/public identity.
2. Produce a human-readable 16-character format with collision and display rules documented.
3. Expose the fingerprint and Guardian/Circle summary through a minimal public onboarding endpoint.
4. Display a strong mismatch warning.
5. Require explicit “I verify the fingerprint” confirmation before join.
6. Bind the accepted fingerprint to the issued browser credential.
7. Handle Guardian certificate rotation without silently trusting a new fingerprint.

### Membership/session tasks

1. Implement a `POST` join/credential issuance flow.
2. Require a valid local invitation or administrator-authorized onboarding policy.
3. Create a local member/account record.
4. Issue the browser credential with role, Circle scope, expiry, and browser registration ID.
5. Store only the required credential material securely on the browser.
6. Add credential refresh, expiry, logout, revoke, and rejoin workflows.
7. Audit fingerprint confirmation, credential issuance, rejection, expiry, and revocation.

### Frontend flow

```text
Welcome
  → Guardian and Circle information
  → Fingerprint verification
  → Invitation/member details
  → Join confirmation
  → Credential created
  → Optional Add to Home Screen
  → Member dashboard
```

### Tests

- Correct Guardian fingerprint allows join.
- Unchecked verification cannot proceed.
- Expired/invalid/replayed invitation fails with no partial member record.
- Revoked browser credential loses access.
- Refresh/restart preserves valid membership.
- Fingerprint change produces an explicit re-verification block.
- Join works with upstream Internet physically unavailable.

### Exit criteria

- The exact User Guide steps can be completed on a clean supported phone.
- No Supabase, cloud identity provider, public DNS, CDN, or email/SMS dependency is required.
- The browser receives no Guardian private key and no new DID.

---

## Phase 3 — Installable PWA Shell and IndexedDB Foundation

### Objective

Make the member application reliably installable and able to load without Guardian connectivity.

### PWA shell tasks

1. Introduce Workbox through Vite configuration or document an approved equivalent.
2. Precache all application-shell assets required for startup.
3. Add versioned cache names tied to application version.
4. Add activation/migration behavior and safe cleanup of older caches.
5. Implement navigation fallback for member routes.
6. Never cache authenticated API responses in the generic Cache API.
7. Add required 192x192 and 512x512 icons and valid screenshots.
8. Validate manifest fields, installability, theme, start URL, and display mode.
9. Add an update-available prompt so a service-worker update does not corrupt active state.

### IndexedDB tasks

Create a typed database with schema versioning and these stores:

| Store | Purpose | Sensitive |
|---|---|---:|
| `membership` | Guardian, Circle, role, credential metadata | Yes |
| `messages` | Locally available message history | Yes |
| `contacts` | Roster and last known presence | Moderate |
| `files` | File metadata and optional encrypted cached blobs | Yes |
| `calls` | Call history | Moderate |
| `pending` | Durable outbound operation queue | Yes |
| `settings` | Member preferences | Moderate |
| `sync_state` | Cursors, sequence IDs, and last successful sync | Moderate |

Implement:

1. Typed repository interfaces.
2. Atomic transactions for message/queue state transitions.
3. Schema migrations and rollback/recovery policy.
4. Storage quota monitoring.
5. Encrypted sensitive records using the approved browser-storage key design.
6. Corruption detection and safe reset/export flow.
7. Cache clearing that preserves or removes membership according to the selected user action.
8. Data export with explicit warning and encrypted archive format where sensitive data is included.

### Suggested frontend structure

```text
frontend/src/pwa/
  db/
    schema.ts
    migrations.ts
    membershipRepository.ts
    messageRepository.ts
    contactRepository.ts
    fileRepository.ts
    callRepository.ts
    pendingRepository.ts
    settingsRepository.ts
    syncStateRepository.ts
  crypto/
  connectivity/
  sync/
  service-worker/
```

### Tests

- Clean install and upgrade from each supported schema version.
- Application loads after Guardian becomes unreachable.
- Sensitive API responses are absent from generic service-worker cache.
- IndexedDB transactions survive refresh and browser restart.
- Quota and corruption errors show recoverable UI.
- Installability checks pass on supported browsers.

### Exit criteria

- Member PWA shell opens with Guardian unavailable after at least one successful installation/load.
- IndexedDB repositories are the single browser persistence interface.
- No feature writes sensitive records directly to localStorage.

---

## Phase 4 — Guardian Connectivity and Synchronization Engine

### Objective

Provide one reliable mechanism for connectivity state, reconnection, synchronization, and conflict handling.

### Tasks

1. Add or designate a lightweight authenticated Guardian health endpoint.
2. Implement a connectivity service using:
   - Page visibility events.
   - WebSocket/SSE state.
   - Timed Guardian health probes.
   - Request failure classification.
3. Do not use public Internet reachability as the online test.
4. Store `last_guardian_seen_at` after successful local responses.
5. Implement exponential backoff with jitter and a maximum retry interval.
6. Implement a single synchronization coordinator to prevent duplicate concurrent syncs.
7. Define sync order:
   1. Validate/refresh local credential.
   2. Send pending operations.
   3. Pull new messages and receipts.
   4. Pull contacts/presence.
   5. Pull file metadata.
   6. Pull call history.
   7. Pull notifications.
   8. Commit new sync cursors.
8. Use server sequence/cursor values rather than client clock alone.
9. Add idempotency keys to all replayable writes.
10. Implement conflict policies for edited settings, revoked membership, deleted files, and duplicate messages.
11. Stop synchronization immediately if membership/session is revoked.

### UI tasks

- Global connected/offline indicator.
- Accurate last-seen time.
- Reconnecting state.
- Pending operation count.
- Manual retry action for recoverable failures.
- Clear messaging for credential revocation versus network loss.

### Tests

- Internet unavailable while Guardian reachable remains `guardian_connected`.
- Guardian unreachable becomes offline within the defined threshold.
- Reconnect triggers exactly one sync coordinator.
- Duplicate reconnect events do not duplicate writes.
- Revocation during offline time blocks queue replay.
- Sync cursor commits only after all required writes succeed.

### Exit criteria

- Every PWA feature consumes the shared connectivity state.
- Reconnection produces deterministic, idempotent synchronization.
- UI never calls a user “online” solely because public Internet exists.

---

## Phase 5 — Messaging, Local Search, and Durable Offline Queue

### Objective

Deliver the complete message experience described in the PDFs, including disconnected composition and automatic delivery.

### Backend tasks

1. Define canonical message IDs generated before first send.
2. Accept an idempotency key and return the existing result on replay.
3. Return explicit Guardian-accepted, remote-delivered, and read states.
4. Enforce Circle membership and local role on every send/history/read operation.
5. Add cursor-based history and receipt synchronization.
6. Resolve the current plaintext `encrypted_payload` path according to the Phase 0 encryption decision.
7. Sign/audit message state changes as required.
8. Define retention, deletion, and maximum message/queue sizes.

### Frontend tasks

1. Persist downloaded messages to IndexedDB.
2. Render cached conversation lists and threads before network refresh.
3. When Guardian is unreachable:
   - Generate the canonical message ID.
   - Encrypt/wrap the pending payload as designed.
   - Write it to `pending` and `messages` atomically.
   - Display `Pending` immediately.
4. On reconnect:
   - Replay by sequence and creation order.
   - Include idempotency key.
   - Transition to `Sent` only after Guardian acceptance.
   - Transition to `Delivered` only after remote acknowledgement.
   - Transition to `Read` after receipt.
5. Add retry, cancel, and permanent-failure actions.
6. Prevent edits after Guardian acceptance unless message editing becomes an explicit feature.
7. Implement local IndexedDB search by keyword, member name, and phrase.
8. Support direct and Circle/group conversations.
9. Respect read-receipt and typing-indicator privacy settings.

### Required state transition

```text
pending_local
    → accepted_by_guardian
    → delivered_to_remote_guardian
    → read

pending_local
    → failed_retryable
    → pending_local

pending_local
    → cancelled | failed_permanent
```

### Tests

- Compose multiple messages while Guardian is unreachable.
- Refresh/close/reopen browser; pending messages remain.
- Reconnect; each message is accepted exactly once.
- Interrupted sync resumes without duplication.
- Local search works with Guardian unreachable.
- Removed/revoked member cannot replay queued messages.
- Read receipt privacy setting is enforced by backend and frontend.
- Message content follows the approved encryption-at-rest and transport model.

### Exit criteria

- Required `Pending → Sent → Delivered` behavior is observable and durable.
- Cached history and local search work without Guardian connectivity.
- No duplicate message appears after repeated reconnections.

---

## Phase 6 — Contacts, Roster, Profiles, and Presence

### Objective

Deliver the PDF-defined Contacts experience using Circle membership and live/local presence.

### Backend tasks

1. Provide a member-safe roster response containing only approved fields.
2. Return full name/display name, device/browser name, join date, role, status, and last seen.
3. Define presence heartbeat and expiry thresholds.
4. Enforce privacy preferences for online status and last-seen visibility.
5. Emit member-joined and status-update events.
6. Exclude revoked or unauthorized members.

### Frontend tasks

1. Add dedicated Contacts tab.
2. Cache roster snapshots in IndexedDB.
3. Show green online and gray offline indicators.
4. Show last-seen time where allowed.
5. Implement local contact search.
6. Add member profile with:
   - Full/display name.
   - Device name.
   - Join date.
   - Status.
   - Message action.
   - Voice-call action.
   - Video-call action.
7. Mark cached presence as stale when offline rather than presenting it as current.

### Tests

- Roster converges after member join/removal.
- Revoked member disappears or is marked according to policy.
- Presence changes propagate in real time.
- Offline roster remains visible and is clearly stale.
- Privacy settings remove hidden presence fields.
- Quick actions navigate to the correct authorized member.

### Exit criteria

- Contacts meets every field and quick-action requirement in the User Guide.
- No member can enumerate Circles or people outside their authorization.

---

## Phase 7 — Files and File Access Control

### Objective

Complete both chat attachment sharing and the independent Files-tab workflow.

### Backend tasks

1. Normalize chat attachments and Files-tab uploads onto one file metadata/access model.
2. Enforce allowed MIME types, sizes, quotas, and Circle authorization.
3. Encrypt file content according to the approved AES-256-GCM key model.
4. Store integrity hash and verify it on download.
5. Add owner metadata and download audit records.
6. Implement:
   - List files.
   - Upload.
   - Download.
   - View download history.
   - Revoke future access.
   - Set/update expiration.
   - Automatic expiry cleanup.
7. Prevent partial or failed uploads from becoming visible.
8. Use idempotency and resumable/chunked transfer where required by supported file sizes.

### Frontend tasks

1. Complete independent Files-tab upload with optional description.
2. Retain attachment sharing inside conversations.
3. Show upload progress, retry, cancel, completion, and failure.
4. Show file name, type, size, owner, shared time, expiry, and availability.
5. Add image preview and general download behavior.
6. Add owner-only download-history, revoke, and expiry controls.
7. Cache file metadata in IndexedDB.
8. Optionally cache encrypted blobs only if storage and security policy permit.
9. When Guardian is offline:
   - Show cached metadata.
   - Disable downloads not already cached.
   - Explain why the action is unavailable.

### Tests

- Upload from chat and Files tab produces consistent metadata.
- Unauthorized/revoked user cannot download.
- Hash matches after download/decryption.
- Duplicate filename behavior is deterministic.
- Expired/revoked file becomes unavailable.
- Partial, oversized, disallowed, and quota-exceeding files are rejected safely.
- Offline file list remains visible; uncached download is disabled.

### Exit criteria

- Every file action from both PDFs is available and backend-enforced.
- Owner control and audit history are real, not UI-only state.

---

## Phase 8 — Voice and Video Calls

### Objective

Finish production-quality local voice/video functionality through reachable Guardians.

### Backend/signaling tasks

1. Complete authorization before call signaling is accepted.
2. Complete real certificate signature verification; remove non-empty-signature placeholders.
3. Replace simulated DTLS fingerprint behavior with actual certificate/media fingerprint verification.
4. Maintain one-to-one and group session state consistently.
5. Persist call history with participants, media type, start/end, duration, and result.
6. Deliver call-ended and participant-state updates to all participants.
7. Reject calls immediately when membership is revoked.

### Frontend/WebRTC tasks

1. Complete Calling, Ringing, Connected, Reconnecting, Ended, Rejected, and Failed states.
2. Handle microphone permission denial with recovery instructions.
3. Handle camera permission denial while allowing audio where authorized.
4. Support mute/unmute and camera on/off.
5. Add accurate call timer.
6. Add Excellent/Good/Fair/Poor quality indicator derived from WebRTC stats.
7. Implement adaptive bitrate behavior.
8. Handle network interruption and bounded reconnection.
9. Persist/synchronize call history.
10. Disable initiation while Guardian is unreachable.
11. Verify audio/video encryption claims through browser and transport evidence.

### Tests

- One-to-one voice and video on supported phones.
- Group voice and video with join/leave.
- Microphone/camera denial.
- Mute/camera state agreement across participants.
- Link interruption and reconnection.
- Membership revocation during active call.
- Call history survives refresh and restart.
- Quality labels match defined WebRTC statistic thresholds.

### Exit criteria

- “Connected” is shown only after real media connectivity.
- Actual intelligible audio and video are demonstrated between supported devices.
- No simulated fingerprint or placeholder verification remains in production call paths.

---

## Phase 9 — Settings, Notifications, and Local Data Management

### Objective

Implement all personal PWA preferences and missed-activity behavior.

### Settings tasks

Implement and persist:

- Device/browser display name.
- Notifications enabled/disabled.
- Sound.
- Vibration.
- Do Not Disturb schedule.
- Show/hide online status.
- Show/hide read receipts.
- Show/hide typing indicators.
- Storage-used display.
- Clear cache.
- Export data.
- App version.
- Guardian fingerprint.
- Support links available without Internet where appropriate.

Separate settings into:

- **Local-only:** sound, vibration, DND UI behavior, local cache controls.
- **Guardian-enforced:** presence, receipts, typing indicators, display name, notification delivery preferences.

### Notification tasks

1. Implement in-app notifications for messages, calls, files, member joins, and status updates.
2. Request browser notification permission only after user explanation/interaction.
3. Apply preference and DND filters.
4. Persist missed notification cursor/state.
5. Deliver missed activity after reconnect.
6. Suppress duplicate notifications by event ID.
7. Define behavior when background push is unavailable without Internet.
8. Add unread counts and mark-read synchronization.

### Tests

- Every preference survives restart.
- Guardian-enforced privacy is honored by another client.
- DND suppresses sound/vibration according to schedule.
- Offline missed activity appears exactly once after reconnect.
- Clear cache accurately reports what will be removed.
- Export contains the selected data and protects sensitive content.

### Exit criteria

- Every Settings item in the User Guide is functional.
- Notifications are preference-aware, durable, and duplicate-safe.

---

## Phase 10 — Internet-Independent Admin Console Hardening

### Objective

Ensure the Admin Console works through local Guardian services with no public Internet dependency.

### Tasks

1. Remove or isolate Supabase/cloud authentication dependencies from the local admin path.
2. Ensure all required frontend assets are embedded; remove CDN dependencies.
3. Implement/document local admin bootstrap, login, logout, recovery, and session expiry.
4. Confirm local Admin Console URL and TLS trust workflow.
5. Ensure admin API base URLs remain same-origin/local.
6. Remove mock fallback from acceptance-critical admin screens.
7. Ensure admin actions modify real Guardian state and produce audit events.
8. Add an explicit cloud-unavailable state for optional integrations rather than failing the whole console.
9. Define disconnected-from-Guardian behavior:
   - Cached read-only status may be displayed as stale.
   - State-changing admin controls must be disabled.
   - No admin operation may be queued unless a separate approved design explicitly makes it safe.
10. Verify member and admin shells coexist without route or service-worker cache leakage.

### Tests

- Disconnect upstream Internet before browser startup.
- Load `guardian.local`, log in locally, refresh, and navigate all supported admin functions.
- Confirm no public DNS/API/CDN/auth requests are necessary.
- Invalid credentials fail and are audited.
- State-changing actions persist through refresh and Guardian restart where required.
- Member credential cannot access Admin Console endpoints.

### Exit criteria

- Admin Console requires Guardian reachability but not Internet connectivity.
- Optional cloud failures do not break local management.
- UI state is corroborated by backend state and audit records.

---

## Phase 11 — Security, Reliability, Persistence, and Performance

### Objective

Harden the combined member/admin application for production use.

### Security tasks

1. Update threat model for:
   - Malicious local Wi-Fi participant.
   - Stolen browser credential.
   - XSS stealing cached content.
   - Service-worker cache poisoning.
   - Replay of join/message/file operations.
   - Guardian fingerprint substitution.
   - Role escalation.
   - Revoked member reconnecting with pending data.
2. Apply strict CSP compatible with the PWA/WebRTC implementation.
3. Apply secure headers: HSTS where operationally safe, `X-Content-Type-Options`, frame policy, referrer policy, and permissions policy.
4. Restrict camera/microphone permissions to call routes and user gestures.
5. Audit dependencies and remove unused Supabase/client libraries from the local PWA path where possible.
6. Verify secrets do not appear in logs, URLs, analytics, or exported diagnostics.
7. Add CSRF protections appropriate to the credential transport mechanism.
8. Rotate/revoke credentials and storage keys safely.

### Reliability tasks

1. Test browser crash during each IndexedDB transaction.
2. Test Guardian restart during message, file, and credential operations.
3. Test service-worker upgrade with pending messages.
4. Test abrupt device power loss and browser process termination.
5. Test full storage quota.
6. Test clock skew between browser and Guardian.
7. Test duplicate, delayed, and reordered WebSocket events.
8. Test member removal while offline and during active sessions.

### Performance tasks

1. Keep production bundle below the PDF target of 5 MB or document an approved exception.
2. Define and measure:
   - Cold and warm startup.
   - Cached offline startup.
   - Message sync latency.
   - Search performance for realistic history sizes.
   - IndexedDB storage footprint.
   - File transfer throughput.
   - Call setup time and media recovery.
3. Use pagination/virtualization for large conversations, rosters, files, and call history.

### Exit criteria

- OWASP Top 10 assessment is complete.
- No high/critical unresolved security issue remains.
- Pending data survives defined crash/restart scenarios without duplication or silent loss.
- Performance thresholds are documented and met.

---

## Phase 12 — Automated Testing, Device QA, Packaging, and Release

### Objective

Produce a repeatable release with evidence against both PWA PDFs.

### Automated test layers

1. **Unit tests (Vitest):**
   - IndexedDB repositories.
   - Migrations.
   - Encryption/wrapping.
   - Queue state machine.
   - Synchronization conflict logic.
   - Validation.
   - Permission helpers.
   - Search.
   - Settings and notification filters.
2. **Backend unit/integration tests:**
   - Credential issuance/revocation.
   - Role middleware.
   - Idempotent messages/files.
   - Roster privacy.
   - Call/file/message authorization.
   - Audit generation.
3. **Playwright tests:**
   - Welcome and fingerprint join.
   - Member five-tab navigation.
   - Admin/member authorization boundaries.
   - Direct/group messages.
   - Offline queue and reconnect.
   - Cached history/search.
   - Contacts.
   - Files.
   - Settings.
   - Notification preferences.
4. **Real device tests:**
   - iOS 15+ Safari on supported hardware.
   - Android 11+ Chrome and Firefox on supported hardware.
   - Tablet layout.
   - Desktop Chrome, Safari, Firefox, and Edge where available.
5. **Security tests:**
   - CSP and headers.
   - Credential theft/replay simulation.
   - Cross-role API access.
   - Stored/reflected XSS attempts.
   - Malformed IndexedDB and sync payloads.

### Coverage and CI

- Enforce greater than 85% unit coverage for the PDF-listed crypto, validation, messaging, and file modules.
- Add test, build, security scan, bundle-size, and artifact stages to GitHub Actions.
- Version service-worker caches automatically from the application version/build digest.
- Publish frontend artifact digest with Guardian binary/firmware version.
- Fail release when manifest assets are missing or service-worker precache references are invalid.

### Release evidence

Create a release evidence package containing:

- Guardian binary/image/configuration versions.
- PWA semantic version and service-worker cache version.
- Supported browser/device matrix.
- Automated test report.
- Offline test recordings.
- Network capture proving no Internet requirement for local flows.
- Audit excerpts for join, message, file, call, revoke, and admin actions.
- Security scan results.
- Known limitations and deferred items.
- Upgrade and rollback instructions.

### Exit criteria

- Every requirement in the traceability matrix has passing evidence.
- PWA installs, upgrades, runs offline, and synchronizes on supported devices.
- Guardian binary includes the exact tested frontend artifact.
- Documentation and rollback procedure are complete.

---

## 8. API Work Plan

The PDFs use simplified endpoints while the repository generally uses `/api/v1/...`. Preserve one internal implementation and add aliases only when required.

| PDF API | Proposed current/target mapping | Work |
|---|---|---|
| `GET /guardian/info` | `GET /api/v1/node/status` plus onboarding-safe summary | Add required Circle/fingerprint fields or a dedicated public summary |
| `POST /guardian/join` | Circle join plus local browser credential issuance | Create member-PWA onboarding endpoint |
| `GET /guardian/roster` | Circle member APIs | Add member-safe normalized response and presence fields |
| `GET /messages` | `GET /api/v1/chat/history` | Add cursor-based member contract |
| `POST /messages` | `POST /api/v1/chat/send` | Add idempotency and explicit delivery states |
| `GET /messages/search` | Browser-local IndexedDB search | Prefer local search; server search optional while connected |
| `GET /files` | Vault/chat file listing | Normalize member file metadata |
| `POST /files` | Vault/chat uploads | Normalize upload and ownership controls |
| `GET /files/{id}/download` | Existing vault/chat download routes | Normalize authorization and integrity response |

Required new or normalized capabilities:

- Onboarding summary/fingerprint.
- Browser credential issue/refresh/revoke.
- Member-safe roster with presence.
- Message cursor sync and idempotency.
- Receipt synchronization.
- File owner/download/expiry metadata.
- Call history sync.
- Unified PWA synchronization cursor or coordinated resource cursors.

---

## 9. Browser Storage and Synchronization Rules

### 9.1 Source of truth

- Guardian storage is authoritative for membership, authorization, delivered messages, file access, and call records.
- IndexedDB is authoritative only for unsent local pending operations and local-only preferences.
- Cached Guardian records must retain server IDs, versions, and sync cursors.

### 9.2 Conflict priorities

1. Revocation and authorization denial always override cached access.
2. Guardian deletion/expiry overrides cached file availability.
3. Server delivery/read state advances local state; local state cannot regress it.
4. Local-only pending messages remain until accepted, cancelled, expired, or permanently rejected.
5. Privacy settings use version/timestamp conflict rules defined in Phase 0.

### 9.3 Sensitive data rules

- Do not place membership credentials or message bodies in service-worker Cache API.
- Avoid sensitive query-string tokens because URLs enter history and logs.
- Encrypt sensitive IndexedDB records under the approved key model.
- Clear decrypted buffers/object URLs when no longer needed where browser APIs allow.
- Exports must be explicit, authenticated, and clearly labeled sensitive.

---

## 10. User Experience States Required for Every Member Screen

Each member feature must implement:

- Loading.
- Populated.
- Empty.
- Recoverable error.
- Permanent/authorization error.
- Guardian offline with cached data.
- Reconnecting/synchronizing.
- Stale data indicator.

Action rules while Guardian is unreachable:

| Action | Allowed |
|---|---:|
| Read cached messages | Yes |
| Search cached messages | Yes |
| Compose/queue message | Yes |
| View cached contacts | Yes |
| View cached file metadata | Yes |
| View call history | Yes |
| Start voice/video call | No |
| Download uncached file | No |
| Perform live admin action | No |
| Refresh live presence | No |

---

## 11. Migration Strategy for the Current Frontend

1. Do not rewrite the entire Admin Console.
2. Extract common primitives first:
   - API client.
   - Auth/session state.
   - Connectivity state.
   - Circle/member types.
   - Chat/call/file services.
3. Introduce `MemberLayout` and role-aware route trees.
4. Move member-capable screens behind member-safe service interfaces.
5. Replace mock fallback only within the paths being migrated, then remove remaining acceptance-path mocks.
6. Introduce IndexedDB repositories without changing visual behavior initially.
7. Change reads to cache-first/network-refresh.
8. Add queued writes after idempotent backend endpoints exist.
9. Keep admin mutations online-to-Guardian only.
10. Remove obsolete Supabase-dependent local paths after local authentication parity is established.

This incremental approach reduces regression risk while reusing the implemented Circle, chat, call, vault, notification, and admin functionality.

---

## 12. Definition of Done

A feature is complete only when all applicable conditions are true:

- UI exists for supported layouts.
- Backend endpoint and authorization exist.
- State is durable where required.
- Offline behavior matches the allowed-action table.
- Reconnection is idempotent.
- Audit evidence exists for security-relevant actions.
- No mock fallback or simulated success is used in the production path.
- Error, empty, loading, stale, and revoked states are implemented.
- Unit and integration tests pass.
- Real supported-device test evidence exists where browser/hardware behavior matters.
- Documentation and requirements traceability are updated.

The complete PWA release is done when:

1. A new local user can connect to Guardian Wi-Fi, open `guardian.local`, verify the 16-character fingerprint, join, install the PWA, and reach the five-tab member dashboard without Internet.
2. The user can message, call, view contacts, share files, and manage required settings while the Guardian is reachable.
3. After losing Guardian connectivity, the user can read cached data and create durable pending messages.
4. After reconnecting, the PWA synchronizes exactly once without duplicate messages or notifications.
5. A revoked user or browser credential cannot regain access or replay queued operations.
6. An administrator can reach and use the supported Admin Console locally without public Internet.
7. Member credentials cannot access administrative APIs.
8. The exact tested PWA is embedded in the released Guardian binary.

---

## 13. Immediate Next Actions

Start with these tasks in order:

1. Approve and record the locked architecture decisions in Phase 0.
2. Create the requirements traceability matrix from both PDFs.
3. Inventory all current endpoints by required member/admin scope.
4. Close unauthenticated administrative endpoint gaps.
5. Implement role-aware backend middleware and the member route shell.
6. Define the 16-character fingerprint and local TLS verification behavior.
7. Implement the Guardian-issued browser credential lifecycle.
8. Add the typed IndexedDB schema and migrations.
9. Replace the basic service worker with the complete versioned PWA shell strategy.
10. Implement Guardian-aware connectivity and sync coordination.
11. Add message idempotency, then implement the durable offline queue.

Cross-network work remains outside this sequence and should not be introduced into PWA phase acceptance criteria.
