# 0002 — Admin REST API authentication dependency (S1 security override)

- **Date:** 2026-07-13
- **Category:** Security (sensitive) — authentication dependency
- **Issue:** Cyber-review gate Round 2, finding S1 (CRITICAL)
- **PR:** feat/62-CRL

## Context

The cybersecurity review gate flags the admin REST API
(`0.0.0.0:8443`) as unauthenticated. This is accurate for the code on
this branch: `require_localhost()` in `src/api/handlers/vc.rs` is a
placeholder that does not actually check the caller.

JWT bearer token authentication is implemented as part of the
Login/Onboarding deliverable, in a separate feature branch not yet
merged into `feat/62-CRL` or `main`. That branch adds:
- JWT token generation on login
- Bearer token validation middleware on all mutating endpoints
- Token expiry and refresh flow
- Role-based access control (Owner vs Member)

## Decision

This PR merges CRL functionality without inline auth. The auth branch
merges immediately after (or is rebased onto this branch before final
release). The `0.0.0.0` binding is required for the Lightning Leap
Analytics frontend console, which connects from a separate host.

## Compensating controls (until auth merges)

1. Boards are on an isolated LAN during development/testing.
2. nftables rules restrict port 8443 to known peer IPs (see
   `src/enforcement/executor.rs`).
3. No production deployment occurs until the auth branch is merged.
4. The cyber-review gate re-runs on the auth-merge PR and must pass
   clean — this override does not carry forward past that merge.

## Risk acceptance

- **Accepted by:** Asad Ali — *(please confirm/adjust; PR73_Round2 also names Pouya Barrach-Yousefi as a stakeholder)*
- **Date:** 2026-07-13
- **Scope:** Development/testing only — NOT production.

## Consequences

- Any caller that can reach port 8443 on the LAN can invoke every admin
  endpoint (DKP rotate/revoke, policy sign, CRL revoke, threat config)
  without authentication until the auth branch merges.
- This ADR alone does not stop the cyber-review gate from flagging S1
  again — it is the artifact the `security-override` label policy
  requires. The label must still be applied to the actual PR for the
  gate to pass (see `.github/cyber-review/README.md`); this record is
  what makes that use of the label auditable.
