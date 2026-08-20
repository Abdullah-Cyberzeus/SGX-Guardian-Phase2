# Guardian PWA Phase 11 Verification Log

**Phase:** Security, Reliability, Persistence, and Performance
**Date:** 2026-08-20
**Scope:** Embedded member PWA and local Admin Console served by the Guardian binary.

## Security Assessment

### Threat Model Updates

| Threat | Control implemented or verified |
|---|---|
| Malicious local Wi-Fi participant | Auth middleware requires signed bearer sessions for non-public API routes; member sessions are bound to role, scopes, Circle IDs, browser registration, and Guardian fingerprint. |
| Stolen browser credential | Member tokens are stored in `sessionStorage`, sessions are checked against the server-side session store on every request, and revoked/expired sessions are rejected. |
| XSS stealing cached content | Static HTML now avoids inline script requirements, CSP blocks third-party script/object/frame execution, API data is not service-worker cached, and the topology log no longer renders event text as HTML. |
| Service-worker cache poisoning | Service worker only handles same-origin non-API GET requests, refuses opaque/missing shell assets during install, versions cache names by app version, and deletes previous shell caches on activate. |
| Replay of join/message/file operations | Frontend mutation/upload calls attach `Idempotency-Key`; backend handlers already use idempotency in PWA/chat/file paths where supported. |
| Guardian fingerprint substitution | Member auth rejects sessions whose embedded Guardian fingerprint no longer matches the current Guardian public key fingerprint. |
| Role escalation | Backend authorization checks current user role/scopes and rejects tokens whose role/scope snapshot no longer matches the account record. |
| Revoked member reconnecting with pending data | Revoked/inactive sessions are rejected before authorization; offline membership metadata does not grant write access while Guardian is unreachable. |

### OWASP Top 10 Pass

| Category | Result |
|---|---|
| A01 Broken Access Control | Backend route authorization and member/admin scope checks are enforced server-side. |
| A02 Cryptographic Failures | Browser-to-Guardian requires trusted HTTPS for PWA install/media; Guardian-to-Guardian crypto remains backend-owned. |
| A03 Injection | Removed direct HTML rendering in topology logs; CSP blocks script injection from external origins. |
| A04 Insecure Design | Local-only model, fingerprint verification, revocable sessions, and offline/read-only boundaries are documented in the PWA plan. |
| A05 Security Misconfiguration | Added CSP, `nosniff`, frame denial, referrer policy, permissions policy, COOP, and CORP. HSTS is opt-in with `SGX_ENABLE_HSTS=1` because local self-signed deployments can otherwise become unrecoverable in browsers. |
| A06 Vulnerable Components | No Supabase/client libraries are referenced in the local PWA path. Full dependency CVE audit remains a release-gate task for Phase 12 CI. |
| A07 Identification and Authentication Failures | JWT signatures, issuer, expiry, server-side session state, role/scope drift, and member registration bindings are verified on each request. |
| A08 Software and Data Integrity Failures | Service worker update flow requires explicit client activation for controlled pages; old shell caches are pruned. |
| A09 Logging and Monitoring Failures | Authz denials and member-sensitive access decisions generate audit events. Secret-bearing auth failures are logged without token values. |
| A10 SSRF | Browser PWA APIs use same-origin Guardian endpoints; no user-controlled server fetch path was introduced in this phase. |

### Implemented Hardening

- Added global security headers in `src/api/mod.rs`.
- Added fetch-metadata/origin checks for unsafe authenticated API requests in `src/api/auth/middleware.rs`.
- Added the `X-SGX-Client: guardian-pwa` header to frontend fetch/XHR mutation paths.
- Moved theme bootstrapping out of inline HTML so CSP can disallow inline scripts.
- Added a runtime media permission guard that limits camera/microphone/screen capture to call routes and camera-only onboarding routes, requiring the tab to be visible and a recent user action.
- Replaced topology log `dangerouslySetInnerHTML` with normal text rendering.

## Reliability Coverage

Heavy crash/power-loss testing was intentionally not run in this pass to avoid destabilizing the development machine.

| Scenario | Current handling | Release-gate verification |
|---|---|---|
| Browser crash during IndexedDB transaction | IndexedDB repositories use transactional writes and pending item states. | Lightweight fake-indexeddb/Vitest crash simulation in Phase 12. |
| Guardian restart during message/file/credential operations | Pending queue and idempotency keys prevent duplicate client mutations; Guardian reachability gates sync. | Targeted backend integration tests, not full Playwright matrix. |
| Service-worker upgrade with pending messages | Worker update waits for explicit activation and does not cache authenticated API data. | Single Playwright upgrade test with a seeded pending queue. |
| Abrupt device power loss/browser termination | Pending writes are durable once committed; in-flight writes must be retried by operation id. | Manual device QA plus focused repository tests. |
| Full storage quota | Storage persist request is best effort; quota failure paths need targeted unit tests. | Add quota-exceeded IndexedDB tests before release. |
| Clock skew | Backend token expiry is authoritative. | Add browser skew simulation around session refresh and pending replay. |
| Duplicate/delayed/reordered WebSocket events | Existing sync/event code uses identifiers and local repositories. | Add small event-ordering tests around sync coordinator. |
| Member removal while offline/active | Server rejects inactive/revoked sessions on reconnect; offline mode remains read-only for Guardian actions. | Add reconnect-after-removal test. |

## Performance Status

| Metric | Status |
|---|---|
| Production bundle below 5 MB | Met after switching self-hosted fonts to latin-only imports. `npm run build` produced `frontend/dist` at 4,968 KiB total; JS/CSS assets total 2,828 KiB. |
| Cold/warm/offline startup | Service worker caches the shell and static assets only; measurement remains a Phase 12 CI/device step. |
| Message sync latency | Pending replay emits deterministic mutation requests with idempotency keys; timing threshold still needs release hardware data. |
| Search performance | Vault uses virtual rows; broad message/contact/file search thresholds remain to be measured with seeded data. |
| IndexedDB footprint | Repositories are separated by domain and can be measured per object store in a focused browser test. |
| File transfer throughput | Existing upload path preserves progress callbacks and idempotency; hardware throughput needs device QA. |
| Call setup/media recovery | Media access is route/gesture-gated; call setup timing must be measured on supported browsers/devices. |

## Residual Risks

- Full dependency CVE audit and bundle-size enforcement should run in Phase 12 CI, not as an ad hoc heavy local test.
- HSTS is intentionally opt-in for local self-signed deployments.
- Some large-list virtualization remains uneven outside the vault file browser and should be completed where seeded data shows slow rendering.
