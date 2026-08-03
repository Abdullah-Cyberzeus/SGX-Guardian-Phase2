# NMAP Network Discovery — Frontend Implementation

Frontend integration for the backend's NMAP-based network discovery subsystem
(Sprint 6, NMP-series — 14 REST endpoints). Backend handlers live on branch
`feat/60_nmap` of `new-guardian`; this document covers the frontend work and how
to run the full stack locally.

Spec source of truth: `new-guardian/docs/REST API Details.md` (§3.50–3.63, §4),
branch `feat/60_nmap`.

---

## 1. The 14 endpoints

| # | Method | Path | UI surface |
|---|--------|------|------------|
| 1 | GET | `/discovery/devices` | Inventory tab — device list |
| 2 | GET | `/discovery/list` | service alias of #1 |
| 3 | GET | `/discovery/inventory/list` | service alias of #1 |
| 4 | GET | `/discovery/devices/unauthorized` | `useUnauthorizedDevices` hook |
| 5 | GET | `/discovery/unauthorized` | service alias of #4 |
| 6 | POST | `/discovery/scan` | Inventory → **Default** button |
| 7 | POST | `/discovery/scan/stealth` | Inventory → **Stealth** button |
| 8 | POST | `/discovery/scan/standard` | Inventory → **Standard** button |
| 9 | POST | `/discovery/scan/aggressive` | Inventory → **Aggressive** button |
| 10 | POST | `/discovery/approve` | Approve dialog |
| 11 | GET | `/discovery/whitelist` | Whitelist tab |
| 12 | PUT | `/discovery/whitelist` | Whitelist → **Save** |
| 13 | GET | `/discovery/schedule` | Schedule tab |
| 14 | PUT | `/discovery/schedule` | Schedule → **Save** |

The three GET aliases (#2, #3, #5) return data identical to their canonical
endpoints, so they exist as service methods but are not given redundant UI.

---

## 2. Architecture

The feature follows the existing service → hook → screen pattern (no react-query;
data fetching via the custom `useApiData` hook).

| Layer | File |
|-------|------|
| Service + types | `src/app/services/discoveryService.ts` |
| Service/type exports | `src/app/services/index.ts` |
| Data hooks | `src/app/hooks/useApiData.ts` |
| Screen | `src/app/screens/network/NW07Discovery.tsx` |
| Routes | `src/app/routes.ts` |
| Navigation entry | `src/app/screens/settings/ST01SettingsRoot.tsx` |
| E2E tests | `e2e/discovery.spec.ts` |

**Types** (`discoveryService.ts`): `OpenPort`, `ConnectedDevice`,
`DiscoveryIntensity`, `DiscoveryScanResponse`, `ApproveDeviceRequest`,
`ApproveDeviceResponse`, `WhitelistDevice`, `WhitelistDoc`, `ScheduleEntry`,
`DiscoverySchedule`.

**Hooks** (`useApiData.ts`): `useDiscoveryDevices` (30s poll),
`useUnauthorizedDevices` (30s poll), `useDiscoveryWhitelist`,
`useDiscoverySchedule`. Mutations (scan / approve / PUT whitelist / PUT schedule)
call the service directly then `refetch()`.

---

## 3. Screen (`/network/discovery`)

Reachable at `/network/discovery`, `/discovery`, and `/settings/discovery`, plus
**Settings → Network → Network Discovery**. Three tabs:

- **Inventory** — device cards with status badges (`approved` / `unauthorized` /
  `drifted`), OS + open-port chips, a "flagged only" filter, summary stats, the
  four scan-intensity buttons (toast shows the scan's `stdout` summary), and an
  **Approve** dialog (MAC prefilled + optional label).
- **Whitelist** — a `Table ⇄ JSON` toggle:
  - *Table view* (default): one card per whitelisted device (MAC, label, expected
    OS/ports/IPs chips) with a per-entry **Remove**.
  - *JSON view*: the raw whitelist document editor.
  - Both are backed by the same editable string — edits/removals in one reflect in
    the other; `Reset` / `Save whitelist` apply to either.
- **Schedule** — config form (enabled, target CIDR [blank = auto-detect LAN],
  timeout, comma-separated excludes, hourly/daily intensity). If the current
  config can't be loaded it falls back to defaults with an inline warning so the
  form stays usable.

---

## 4. Tests

`e2e/discovery.spec.ts` — 11 Playwright tests covering page load, the three route
aliases, the tab controls, the four scan buttons, inventory stat cards, and the
Whitelist/Schedule tab content. Structural assertions, so they pass with or
without backend data.

```bash
npx playwright test e2e/discovery.spec.ts --project=chromium
```

---

## 5. Running the full stack locally

### Frontend

```bash
# from SGX-gaurdian-admin-console-FE/
VITE_API_URL=http://localhost:8443/api/v1 npm run dev    # http://localhost:5173
```

### Backend (`new-guardian`, branch `feat/60_nmap`)

The backend binds the REST API to `0.0.0.0:8443`. The clean `feat/60_nmap` branch
reads/writes **hardcoded system paths** (`/etc/sgx-guardian`,
`/var/lib/sgx-guardian`, `/var/log/sgx-guardian`) — it does **not** honor the
`SGX_RUNTIME_BASE`/`SGX_CONFIG_DIR` testdata-redirect env vars. So local setup is:

```bash
# 1. Build (branch feat/60_nmap)
cargo build

# 2. Create runtime dirs and hand ownership to your user (one-time, needs sudo)
sudo mkdir -p /etc/sgx-guardian/{config,discovery} \
  /var/lib/sgx-guardian/{boot,keys,pcr,sgx-agent,nebula,discovery} \
  /var/log/sgx-guardian
sudo chown -R "$(id -un):$(id -gn)" /etc/sgx-guardian /var/lib/sgx-guardian /var/log/sgx-guardian

# 3. Seed from testdata/ so it doesn't run empty
cp testdata/config/nodeA.yaml          /etc/sgx-guardian/config/
cp testdata/keys/dkp_metadata.json     /var/lib/sgx-guardian/keys/
cp testdata/pcr/nodeA_current.json     /var/lib/sgx-guardian/pcr/
cp testdata/sgx-agent/device_nodeA.*   /var/lib/sgx-guardian/sgx-agent/

# 4. (optional) seed a discovery inventory so the Inventory tab shows devices
#    -> /var/lib/sgx-guardian/discovery/inventory.json  (JSON array of ConnectedDevice)

# 5. Launch with hardware subsystems disabled
testdata/start-test-backend.sh
```

`start-test-backend.sh` exports the `SGX_DISABLE_*` flags (honored — keep Nebula,
gRPC, attestation, secure-element, etc. off) and `SGX_FORCE_SOFTWARE_KEYS=1`. Its
path-redirect env vars are ignored by the clean branch, which is why step 2 is
required.

Stop the backend: `fuser -k 8443/tcp 50051/tcp`.

### Verify

```bash
curl -s http://localhost:8443/api/v1/discovery/devices            # inventory array
curl -s http://localhost:8443/api/v1/discovery/whitelist          # {version, devices:[]}
curl -s http://localhost:8443/api/v1/discovery/schedule           # schedule config
```

---

## 6. Known limitations

- **Live scans need `nmap`.** `/discovery/scan*` invoke `sgx-pa-cli discovery scan`;
  the testdata `sgx-pa-cli` is a stub that returns canned output without running a
  real sweep or updating the inventory. Real scans require `nmap` installed and the
  real CLI (and root for some scan types).
- **Run-only path patch.** Pointing the backend at `testdata/` instead of system
  paths requires a local ~17-line patch to `state.rs`/`main.rs` (env-configurable
  paths). It is intentionally **not** part of the clean `feat/60_nmap` branch; the
  system-dir setup above is used instead.
