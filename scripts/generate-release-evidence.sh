#!/bin/bash
# Phase 12 release evidence package generator.
#
# Assembles docs/Guardian_PWA_Phase_12_Release_Evidence.md from what this
# checkout / the CI run actually produced: binary and PWA versions, coverage
# and security-scan results, bundle size. Two things in the plan's evidence
# list cannot be produced by this script and are never fabricated — the
# real device/browser matrix and a live network capture — those stay as an
# explicit manual sign-off checklist at the bottom of the generated doc.
#
# Usage: scripts/generate-release-evidence.sh
# Run from the repo root, ideally after `cargo build --release`,
# `cargo tarpaulin --out Json`, and `cd frontend && npm run build`, so the
# real artifacts/reports it reads actually exist. Missing inputs are
# reported as "not available in this run" rather than skipped silently.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

OUT="docs/Guardian_PWA_Phase_12_Release_Evidence.md"
NOW_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
GIT_COMMIT="$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
GIT_BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")"
BACKEND_VERSION="$(grep -m1 '^version' Cargo.toml | sed -E 's/version *= *"(.*)"/\1/')"
FRONTEND_VERSION="$(node -p "require('./frontend/package.json').version" 2>/dev/null || echo "unknown")"

value_or() { [ -n "${1:-}" ] && echo "$1" || echo "$2"; }

# --- Frontend bundle digest / size ---------------------------------------
FRONTEND_DIGEST="not available in this run (build frontend/dist first)"
FRONTEND_SIZE="not available in this run (build frontend/dist first)"
if [ -d frontend/dist ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    FRONTEND_DIGEST="$(find frontend/dist -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')"
  fi
  FRONTEND_SIZE="$(du -sh frontend/dist 2>/dev/null | awk '{print $1}')"
fi

# --- Backend release binary digest ---------------------------------------
BACKEND_DIGEST="not available in this run (cargo build --release first)"
if [ -f target/release/sgx_guardian_client ] && command -v sha256sum >/dev/null 2>&1; then
  BACKEND_DIGEST="$(sha256sum target/release/sgx_guardian_client | awk '{print $1}')"
fi

# --- Backend coverage (scoped modules, matching the CI gate) -------------
BACKEND_COVERAGE="not available in this run (run the CI coverage step, or cargo tarpaulin locally)"
if [ -f cobertura.xml ]; then
  BACKEND_COVERAGE="cobertura.xml present — see CI job summary for the enforced-module percentage"
fi

# --- Frontend unit-test coverage ------------------------------------------
FRONTEND_COVERAGE="not available in this run (run: cd frontend && npm run test:unit -- --coverage)"
if [ -f frontend/coverage/coverage-summary.json ]; then
  FRONTEND_COVERAGE="$(node -p "
    const s = require('./frontend/coverage/coverage-summary.json').total;
    \`lines \${s.lines.pct}%, functions \${s.functions.pct}%, branches \${s.branches.pct}%, statements \${s.statements.pct}%\`
  " 2>/dev/null || echo "coverage-summary.json present but unparsable")"
fi

# --- Security scan tool availability (pass/fail comes from the CI job) ---
SECURITY_TOOLS=""
for tool in cargo-audit cargo-deny semgrep; do
  if command -v "$tool" >/dev/null 2>&1; then
    SECURITY_TOOLS="${SECURITY_TOOLS}- ${tool}: installed locally (\`${tool} --version\`: $(${tool} --version 2>/dev/null | head -1))\n"
  else
    SECURITY_TOOLS="${SECURITY_TOOLS}- ${tool}: not installed in this environment — see CI job \`build-test-audit\` for the authoritative result\n"
  fi
done

mkdir -p docs
cat > "$OUT" <<EOF
# Guardian PWA Phase 12 Release Evidence

Generated $NOW_UTC by \`scripts/generate-release-evidence.sh\`. Re-run after a
real release build + CI pass to refresh — do not hand-edit the automated
sections below; edit the manual QA section as sign-offs land.

## Versions

| Component | Value |
|---|---|
| Git commit | \`$GIT_COMMIT\` |
| Git branch | \`$GIT_BRANCH\` |
| Guardian binary version (Cargo.toml) | $BACKEND_VERSION |
| Guardian binary SHA-256 | \`$BACKEND_DIGEST\` |
| PWA semantic version (frontend/package.json) | $FRONTEND_VERSION |
| PWA service-worker cache version | \`sgx-guardian-shell-\${FRONTEND_VERSION}\` — see \`frontend/public/sw.js\`, derived from \`__APP_VERSION__\` (frontend/vite.config.ts) at build time |
| Frontend \`dist/\` digest (sha256 of sorted file digests) | \`$FRONTEND_DIGEST\` |
| Frontend \`dist/\` size | $FRONTEND_SIZE (budget: 5 MiB, enforced by \`frontend/scripts/check-bundle-size.mjs\`) |

## Automated test evidence

| Layer | Status |
|---|---|
| Backend coverage (scoped: vc::issue, vc::status_list, api::idempotency, circle::members, circle::invite; 85% gate) | $BACKEND_COVERAGE |
| Frontend unit-test coverage (pwa/db, pwa/crypto, pwa/sync, app/utils/authorization; 85% gate) | $FRONTEND_COVERAGE |
| Frontend precache validation (\`frontend/scripts/validate-precache.mjs\`) | Run as part of \`npm run build\` + CI; fails the build if a service-worker-precached asset is missing from \`dist/\` |
| Bundle size gate (\`frontend/scripts/check-bundle-size.mjs\`) | Run as part of CI; fails the build over 5 MiB |
| Playwright E2E (Admin Console) | See CI job \`frontend-build-test\` artifact \`playwright-report\` for the authoritative pass/fail |
| Playwright E2E (Member PWA: join, five-tab nav, authz boundaries, direct/group messages, offline queue, cached search, contacts, files, settings, notification prefs) | **Not yet implemented** — tracked as a Phase 12 follow-up; the backend test harness (\`src/bin/test_guardian_server.rs\`, \`src/testkit.rs\`) and admin-console E2E coverage are in place, the member-role login fixture and the 10 member-flow specs are not |

## Security scan tooling

$(echo -e "$SECURITY_TOOLS")
Authoritative pass/fail for all three lives in the \`build-test-audit\` CI job — this section only reports whether the tooling is present in the environment that generated this document, not a live scan result.

## Known limitations and deferred items

- Real device/browser matrix (iOS Safari, Android Chrome/Firefox, tablet, desktop Safari/Firefox/Edge) has no CI equivalent — see the manual QA section below.
- Member-role Playwright coverage is not yet implemented (see above).
- The backend coverage gate is intentionally scoped to 5 modules with confirmed dedicated tests, not the whole crate — widen as more modules earn coverage.
- Network-capture-proves-no-Internet-requirement is a manual check (see below); no automated equivalent exists.

## Upgrade and rollback

- The Guardian binary and its \`frontend/dist\` are versioned and built together in the same CI run (see the artifact digests above) — do not deploy a binary and frontend build from different commits.
- Rollback: redeploy the previous release's signed binary + frontend digest pair together; the service worker's cache name is version-scoped (\`sgx-guardian-shell-\${VERSION}\`), so an older client falling back to a previous binary will not serve a stale/mismatched shell.

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
EOF

echo "Wrote $OUT"
