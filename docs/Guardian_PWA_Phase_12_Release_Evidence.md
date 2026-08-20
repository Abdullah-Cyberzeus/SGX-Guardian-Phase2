# Guardian PWA Phase 12 Release Evidence

Generated 2026-08-20T08:19:37Z by `scripts/generate-release-evidence.sh`. Re-run after a
real release build + CI pass to refresh — do not hand-edit the automated
sections below; edit the manual QA section as sign-offs land.

## Versions

| Component | Value |
|---|---|
| Git commit | `fd8b47511f3aee604b641060f3ac30fa209eb93f` |
| Git branch | `phase_8` |
| Guardian binary version (Cargo.toml) | 0.1.0 |
| Guardian binary SHA-256 | `not available in this run (cargo build --release first)` |
| PWA semantic version (frontend/package.json) | 3.0.1-phase3 |
| PWA service-worker cache version | `sgx-guardian-shell-${FRONTEND_VERSION}` — see `frontend/public/sw.js`, derived from `__APP_VERSION__` (frontend/vite.config.ts) at build time |
| Frontend `dist/` digest (sha256 of sorted file digests) | `4f43eb73833681d6c83c76c4878196a8c98807dcc67672a2baf2f59d6bae51da` |
| Frontend `dist/` size | 4.9M (budget: 5 MiB, enforced by `frontend/scripts/check-bundle-size.mjs`) |

## Automated test evidence

| Layer | Status |
|---|---|
| Backend coverage (scoped: vc::issue, vc::status_list, api::idempotency, circle::members, circle::invite; 85% gate) | not available in this run (run the CI coverage step, or cargo tarpaulin locally) |
| Frontend unit-test coverage (pwa/db, pwa/crypto, pwa/sync, app/utils/authorization; 85% gate) | lines 99.53%, functions 86.58%, branches 77.08%, statements 94.44% |
| Frontend precache validation (`frontend/scripts/validate-precache.mjs`) | Run as part of `npm run build` + CI; fails the build if a service-worker-precached asset is missing from `dist/` |
| Bundle size gate (`frontend/scripts/check-bundle-size.mjs`) | Run as part of CI; fails the build over 5 MiB |
| Playwright E2E (Admin Console) | See CI job `frontend-build-test` artifact `playwright-report` for the authoritative pass/fail |
| Playwright E2E (Member PWA: join, five-tab nav, authz boundaries, direct/group messages, offline queue, cached search, contacts, files, settings, notification prefs) | **Not yet implemented** — tracked as a Phase 12 follow-up; the backend test harness (`src/bin/test_guardian_server.rs`, `src/testkit.rs`) and admin-console E2E coverage are in place, the member-role login fixture and the 10 member-flow specs are not |

## Security scan tooling

- cargo-audit: not installed in this environment — see CI job `build-test-audit` for the authoritative result
- cargo-deny: not installed in this environment — see CI job `build-test-audit` for the authoritative result
- semgrep: not installed in this environment — see CI job `build-test-audit` for the authoritative result
Authoritative pass/fail for all three lives in the `build-test-audit` CI job — this section only reports whether the tooling is present in the environment that generated this document, not a live scan result.

## Known limitations and deferred items

- Real device/browser matrix (iOS Safari, Android Chrome/Firefox, tablet, desktop Safari/Firefox/Edge) has no CI equivalent — see the manual QA section below.
- Member-role Playwright coverage is not yet implemented (see above).
- The backend coverage gate is intentionally scoped to 5 modules with confirmed dedicated tests, not the whole crate — widen as more modules earn coverage.
- Network-capture-proves-no-Internet-requirement is a manual check (see below); no automated equivalent exists.

## Upgrade and rollback

- The Guardian binary and its `frontend/dist` are versioned and built together in the same CI run (see the artifact digests above) — do not deploy a binary and frontend build from different commits.
- Rollback: redeploy the previous release's signed binary + frontend digest pair together; the service worker's cache name is version-scoped (`sgx-guardian-shell-${VERSION}`), so an older client falling back to a previous binary will not serve a stale/mismatched shell.

---

## Manual QA — not automatable

These cannot be produced by CI or this script; a human tester fills in the
Result/Date/Tester columns. Leave rows blank (not "pass") until actually run
— an unfilled row means "not yet verified," not "assumed fine."

| Check | Result | Date | Tester |
|---|---|---|---|
| iOS 15+ Safari — install, offline reload, core member flows | | | |
| Android 11+ Chrome — install, offline reload, core member flows | | | |
| Android 11+ Firefox — install, offline reload, core member flows | | | |
| Tablet layout (iPad / Android tablet) | | | |
| Desktop Chrome | | | |
| Desktop Safari | | | |
| Desktop Firefox | | | |
| Desktop Edge | | | |
| Network capture proving no Internet requirement for local flows (e.g. Wireshark/tcpdump during offline-capable use, filtered to non-LAN destinations) | | | |
| Offline test recording (PWA install → kill network → core flows still work → reconnect → queue drains) | | | |
