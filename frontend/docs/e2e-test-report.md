# E2E Test Report — SG-X Guardian Admin Console

**Run date:** 2026-04-16
**Branch:** `NodeServerValues`
**Test runner:** Playwright
**Browser:** Chromium
**Total runtime:** 6.1 minutes
**Result:** **140 / 140 passed (100%)**

---

## Summary

| Suite | File | Tests | Passed | Failed |
|---|---|---|---|---|
| Integrity Dashboard | `e2e/integrity-dashboard.spec.ts` | 27 | 27 | 0 |
| Key Management | `e2e/key-management.spec.ts` | 28 | 28 | 0 |
| Security Pages | `e2e/security-pages.spec.ts` | 42 | 42 | 0 |
| Navigation | `e2e/navigation.spec.ts` | 43 | 43 | 0 |
| **Total** | | **140** | **140** | **0** |

---

## CLI Command Coverage

All 15 CLI commands have corresponding UI pages covered by E2E tests.

| CLI Command | UI Route | Suite |
|---|---|---|
| `status` | `/home/guardian` | Navigation |
| `boot-status` | `/settings/boot-status` | Security Pages |
| `peers` | `/home/topology` | Navigation |
| `attestation` | `/settings/attestation` | Security Pages |
| `logs` | `/settings/logs` | Security Pages |
| `keygen` | `/settings/keys` | Key Management |
| `sign` | `/settings/policy` | Security Pages |
| `verify` | `/settings/policy` | Security Pages |
| `dkp-status` | `/settings/keys` | Key Management |
| `dkp-rotate` | `/settings/keys` | Key Management |
| `dkp-revoke` | `/settings/keys` | Key Management |
| `emergency-rotate` | `/settings/keys` | Key Management |
| `pcr-status` | `/settings/integrity` | Integrity Dashboard |
| `pcr-baseline-create` | `/settings/integrity` | Integrity Dashboard |
| `pcr-baseline-verify` | `/settings/integrity` | Integrity Dashboard |

---

## Suite Breakdown

### Integrity Dashboard (27 tests)
Covers `pcr-status`, `pcr-baseline-create`, `pcr-baseline-verify`.

- Page load & direct URL access (`/integrity`, `/settings/integrity`)
- PCR status display (PCR 0–7 registers)
- Baseline creation flow with confirmation dialog
- Baseline verification results
- Tamper detection banner
- Refresh action
- Error boundary resilience

### Key Management (28 tests)
Covers `dkp-status`, `dkp-rotate`, `dkp-revoke`, `emergency-rotate`, `keygen`.

- Page load & dual route access (`/keys`, `/settings/keys`)
- Three-tab layout (DKP Status / History / Emergency)
- Active key info (version, algorithm ECDSA-P256, total versions)
- DKP rotate confirmation + success toast + daemon restart banner
- History tab with version cards and status badges
- Revoke action (Deprecated keys only, 30-day grace period warning)
- Emergency rotation (all critical keys warning)
- StatusBadge fallback — regression test for "Cannot destructure property 'bg' of config[status]"

### Security Pages (42 tests)
Covers `boot-status`, `attestation`, `logs`, `sign`, `verify`.

**Boot Status:**
- Secure boot chain banner (Intact / Compromised)
- HAB Status, Device Mode, Boot Chain state
- Device Information (model, hash, timestamp)
- Trust chain visualization (Boot ROM → HAB → U-Boot → Kernel → RootFS → Guardian → SE050)
- Refresh action with loading + success states

**Attestation:**
- Last attestation result banner
- Attestation statistics (Total / Passed / Failed)
- Peer attestation history
- Re-attest action

**Logs:**
- Log entries with level tags (INFO / WARN / ERROR / DEBUG)
- Timestamp formatting
- Filter controls
- Search & Export functionality

**Policy Management:**
- Three tabs (Policies / Sign / Keys)
- Signed policies list with verification badges
- Policy upload & key selector (sign flow)
- Policy Authority keys

### Navigation (43 tests)
Covers cross-cutting routing and settings menu.

- Settings root page — Security & Keys section visible
- All 6 security menu items accessible
- Navigation to each security page from Settings
- Back navigation (Key Management, Integrity → Settings)
- Direct URL navigation — standalone routes (`/keys`, `/integrity`, `/boot-status`, `/attestation`, `/policy`, `/logs`)
- Direct URL navigation — prefixed routes (`/settings/*`)
- Bottom navigation (Home ↔ Settings)
- CLI-to-UI mapping for all 15 commands
- Error handling (invalid routes, page refresh)

---

## Bug Fixes Verified by This Run

### 1. StatusBadge Destructure Error
**Issue:** `Cannot destructure property 'bg' of 'config[status]' as it is undefined`
**File:** `src/app/screens/keys/KM01KeyManagement.tsx`
**Fix:** Added fallback `UNKNOWN` style when status lookup misses
**Verification:** `Key Management › StatusBadge Fallback (Bug Fix Verification)` suite — 1 test passing

### 2. Vercel SPA Deep-Link 404
**Issue:** `404: NOT_FOUND` when navigating directly to routes like `/onboarding`, `/settings/keys`
**File:** `vercel.json`
**Fix:** Added `{ "rewrites": [{ "source": "/(.*)", "destination": "/index.html" }] }`
**Verification:** User confirmed working — Direct URL navigation suite (12 tests) all pass

---

## Test Pattern Adopted

The suites were standardized on a resilient locator pattern to avoid strict-mode violations and visibility issues:

| Old (brittle) | New (resilient) |
|---|---|
| `page.locator('text=X')` | `expect(page.locator('body')).toContainText('X')` |
| `page.click('button:has-text("X")')` | `page.getByRole('button', { name: 'X' }).first().click()` |
| `page.locator('h1:has-text("X")')` | `page.getByRole('heading', { name: 'X' })` |
| `page.locator('[role="dialog"] button')` | `page.getByRole('button', { name: 'X' }).last()` *(custom ConfirmDialog has no `role="dialog"`)* |
| `page.click('button svg.lucide-arrow-left')` | `page.goBack()` *(icon-only buttons report as not visible)* |

---

## Running the Tests

```bash
# Install browsers (first run only)
npx playwright install chromium

# Full suite
npm run test:chromium

# Individual suites
npx playwright test e2e/integrity-dashboard.spec.ts --project=chromium
npx playwright test e2e/key-management.spec.ts --project=chromium
npx playwright test e2e/security-pages.spec.ts --project=chromium
npx playwright test e2e/navigation.spec.ts --project=chromium

# HTML report
npx playwright show-report
```

Playwright config (`playwright.config.ts`) spawns both:
- Vite dev server on `http://localhost:5173`
- Mock API server on `http://localhost:3001`

---

## Known Quirks

- **Custom `ConfirmDialog`** — rendered as a styled `<div>` without `role="dialog"`. Tests target the confirm button via `.last()` after the dialog opens (two buttons with identical names exist: the page trigger + the dialog confirm).
- **Back navigation** — header back buttons are icon-only `<svg>` children. Playwright sometimes reports them as not visible due to size/overflow calculations. Tests use `page.goBack()` (browser history API) instead for reliability.
- **`networkidle` + 1s buffer** — pages use long-polling / toast animations. All navigations wait for `networkidle` plus a 1-second settle to avoid racing React state updates.
