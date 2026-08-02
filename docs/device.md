# Connected Devices Management & Security / Privacy Scoring — Complete Development Plan
### Base branch: `feat/62-CRL` · Module: `src/devices/` (over `src/discovery/`) · **No new port**

---

## 0. Grounding note + what already exists

Written against the **actual indexed repo state**, not memory.

**The finding: far more exists than the feature title suggests — this is an enrichment layer, not a new subsystem.** The NMAP discovery module is live and rich:

```rust
pub struct ConnectedDevice {
    device_id, ip, mac, vendor, hostname,
    os_fingerprint, os_cpe,
    open_ports: Vec<OpenPort>,      // port, protocol, service, product_version, cpe,
                                    // scripts  ← includes `vulners` NSE = real CVEs + CVSS
    host_scripts,                   // e.g. fcrdns, dns-blacklist
    status: DeviceStatus,           // Approved | Unauthorized | Drifted | Stale
    first_seen, last_seen, vuln_triaged, last_scan_intensity,
}
```

Already shipped and live:

| Capability | Where |
|---|---|
| **Categorical** risk classifier `risk_level(&device) -> (level, reasons, flagged_ports)` → `critical\|high\|medium\|low\|unknown` | `src/api/handlers/discovery.rs` |
| Real CVE data with CVSS (e.g. `CVE-2023-38408 9.8`) via the `vulners` NSE script | `open_ports[].scripts` |
| Inventory + summary + per-device detail | `/discovery/devices`, `/discovery/summary`, `/discovery/devices/{id}` |
| Whitelist classify/approve (Approved / Drifted / Unauthorized) | `src/discovery/whitelist.rs`, `/discovery/approve`, `/discovery/whitelist` |
| Scans: stealth / standard / aggressive, ad-hoc + scheduled, raw XML archive (last 10) | `/discovery/scan/*`, `/discovery/schedule`, `/discovery/runs` |
| IP blocking with TTL, persistence, **self-protection** | `src/threat/blocker.rs`, `/threat/blocks` |

**So the genuine gaps are only these six:**

1. **Numeric Security Score (0–100)** — the FE renders score *rings*; the backend has only a categorical level.
2. **Privacy Score (0–100)** — **entirely absent.** No privacy dimension exists anywhere.
3. **Per-device on-demand scan** with the FE's five-step sequence — today only whole-network scans exist.
4. **Block / remove device enforcement** — `Blocker` blocks IPs from *threat alerts*; it is not wired to the device inventory.
5. **Manual device add** (name / IP / MAC / manufacturer) — whitelist accepts entries but there is no inventory-level manual add.
6. **User-editable device name** — the whitelist has `label`; the inventory doesn't surface an editable name.

**Could not verify:** GitHub live PR/diff (private repo → 404, then rate-limited). Anchors from the project-knowledge index — re-verify against the tip of `feat/62-CRL`. Confirm `risk_level()`'s exact signature/visibility (it lives in the discovery handler and may need to move to a shared module) and the `blocker.rs` exemption helper's visibility before reuse.

---

## 1. Two design decisions that matter

### 1.1 Scores must be deterministic and explainable — and must not contradict `risk_level`

The existing classifier already returns **`risk_reasons`** — the codebase's precedent is *explainable* risk, not an opaque number. So:

- The Security Score is computed by a **published, deterministic rubric** from signals that already exist (CVSS from `vulners`, risky open ports, whitelist status, OS/service exposure), and it returns **`score_reasons`** — every deduction is attributable.
- **Score and level stay consistent:** `risk_level` remains the source of the band, and the score is bucketed to agree with it (critical ≤ 20, high 21–50, medium 51–75, low 76–100). A device must never show "score 92" next to "risk: critical". If they ever disagree, the **level wins** and the discrepancy is audited — one truth, two presentations.
- **No invented numbers.** Where a signal is missing (stealth scan → no OS, no ports), the score is reported as **`null` with `"insufficient data"`**, mapping to the existing `unknown` band — not a misleading 50.

### 1.2 Privacy Score is genuinely new — and must be honest about its limits

There is no privacy data model today, and **a network scan can only see network-observable privacy signals.** It cannot know a vendor's data-sharing policy. So the Privacy Score is scoped and labelled as *network-observable privacy exposure*, built from:

| Signal | Privacy impact |
|---|---|
| **Cleartext protocols** exposed (telnet 23, ftp 21, http 80, snmp 161) | credentials/content observable on the LAN |
| **Device class inference** (camera / microphone / NAS / voice assistant, from vendor + service + OS fingerprint) | sensitive-data-capable device |
| **Discovery/broadcast chattiness** (UPnP 1900, mDNS 5353, SSDP) | advertises itself + its services to the whole LAN |
| **Cloud-reachable services** / remote-admin exposure | data leaves the local network |
| **Unknown vendor / no fingerprint** | unattributable device on the network |

The response includes `privacy_reasons` and an explicit `basis: "network-observable"` field. **This must be surfaced to the FE and to Cervais** so the score is never read as a vendor-privacy rating (§11).

---

## 2. Architecture

```
   EXISTING (live)                      NEW — enrichment layer (this plan)
   ┌───────────────────────┐            ┌──────────────────────────────────────────┐
   │ NMAP discovery        │  inventory │ scoring/security.rs  → score + reasons     │
   │  inventory.json       │───────────►│ scoring/privacy.rs   → score + reasons     │
   │  risk_level()         │            │ (bucketed to agree with risk_level)        │
   │  whitelist classify   │            └──────────────────┬───────────────────────┘
   │  scan (net-wide)      │                               │
   └───────────────────────┘            ┌──────────────────▼───────────────────────┐
   ┌───────────────────────┐            │ devices/registry.rs — user layer:         │
   │ Blocker (IP + TTL,    │◄───────────│  manual add · editable name · block/remove│
   │  self-protection)     │  block      │  (MAC-aware; self-protection inherited)   │
   └───────────────────────┘            └──────────────────┬───────────────────────┘
                                        ┌──────────────────▼───────────────────────┐
                                        │ devices/scan.rs — per-device 5-step scan  │
                                        │  (targeted NMAP, progress-tracked)        │
                                        └──────────────────────────────────────────┘
```

The inventory stays the source of truth; this layer **enriches** (scores), **augments** (manual/user data in a sidecar registry), and **acts** (per-device scan, block/remove). Discovery is not rewritten.

---

## 3. Data model

```rust
pub struct DeviceScores {
    pub security_score: Option<u8>,     // 0-100; None = insufficient data
    pub security_reasons: Vec<String>,  // every deduction, attributable
    pub privacy_score: Option<u8>,
    pub privacy_reasons: Vec<String>,
    pub privacy_basis: String,          // "network-observable"
    pub risk_level: String,             // from the EXISTING classifier — authoritative band
    pub computed_at: String,
}

// Sidecar user layer (never mutates inventory.json)
pub struct DeviceRecord {
    pub device_id: String,
    pub display_name: Option<String>,   // user-editable
    pub manual: bool,                   // manually added, not scan-discovered
    pub ip: Option<String>, pub mac: Option<String>,
    pub manufacturer: Option<String>,
    pub monitoring_enabled: bool,       // FE "Guardian Monitoring" toggle
    pub blocked: bool,
    pub notes: Option<String>,
    pub created_at: String, pub updated_at: String,
}

pub struct DeviceScanRun {              // per-device 5-step scan
    pub scan_id: String, pub device_id: String,
    pub step: u8,                       // 1..5
    pub step_label: String,             // firmware / open ports / encryption / known vulns / report
    pub state: String,                  // running | complete | failed
    pub started_at: String, pub finished_at: Option<String>,
    pub findings: Vec<String>, pub recommendations: Vec<String>,
}
```

**The sidecar is deliberate:** `inventory.json` is rewritten by every scan. User data (name, manual devices, monitoring flag) must live in a **separate** signed registry keyed by `device_id`, or a scan would erase it.

---

## 4. Deliverables

Each independently reviewable/testable; tree stays green (`cargo build && cargo test && cargo clippy -- -D warnings`); no existing behaviour changes.

| # | Deliverable | Files | Acceptance test |
|---|---|---|---|
| **S1** | **Security scoring rubric** (pure, no network) | `src/devices/{mod,errors,model}.rs`, `src/devices/scoring/security.rs`, `src/lib.rs` | Unit: fixture devices → expected scores; **CVSS 9.8 from `vulners` drives a critical score**; every deduction appears in `security_reasons`; **score band agrees with `risk_level`** for all fixtures; stealth-only device → `None` + "insufficient data" (never a fake 50). |
| **S2** | **Privacy scoring rubric** (pure, no network) | `src/devices/scoring/privacy.rs` | Unit: cleartext-protocol device (telnet/ftp/http) scores low; camera-class device flagged; UPnP/mDNS chattiness deducted; `privacy_basis = "network-observable"` always present; reasons attributable. |
| **S3** | **Score enrichment + REST** | `src/api/handlers/devices.rs`, `routes.rs`, `mod.rs` | Board: `GET /devices` returns inventory **plus** both scores + reasons per device; `GET /devices/:id` full detail; `GET /devices/summary` adds score distribution to the existing risk counts. Existing `/discovery/*` endpoints **unchanged**. |
| **S4** | **Device registry: manual add + editable name + monitoring toggle** | `src/devices/registry.rs` | Board: `POST /devices` adds a manual device (name/IP/MAC/manufacturer); `PATCH /devices/:id` renames + toggles monitoring; **run a discovery scan → user data survives** (sidecar not overwritten); registry signed + atomic; tampered registry rejected. |
| **S5** | **Per-device on-demand scan (5-step)** | `src/devices/scan.rs`, `handlers/devices.rs` | Board: `POST /devices/:id/scan` runs a **targeted** NMAP against that device; `GET /devices/:id/scan/:scan_id` reports step 1–5 progress and a findings/recommendations summary; scan is **async** (`tokio::process`, never a sync `Command`); a running scan survives leaving the screen (shared state, mirroring the existing discovery-scan lifecycle). |
| **S6** | **Block / remove enforcement** ⚠ | `src/devices/enforce.rs` | Board: `POST /devices/:id/block` blocks via **`Blocker`** (TTL + persistence + `inet sgx_threat`); **self-protection inherited** — blocking the gateway / management LAN / overlay is **refused and audited**; `POST /devices/:id/unblock` reverses it; **MAC-aware re-apply**: if the device's IP changes (DHCP), the block follows the MAC on the next scan; `DELETE /devices/:id` removes it from the sidecar (and whitelist if present) without breaking inventory. |
| **S7** | **Board validation + regression** | `tests/devices_*.sh` | 3-node/board run: scores stable across two scans of an unchanged device (deterministic); discovery/threat/gossip/CRL regression green; no watchdog reset; targeted scan does not disturb the scheduled scan lifecycle. |

**Sequencing:** S1 → S2 (pure rubrics, fully unit-testable) → S3 (surface them). S4 → S5 in parallel with each other. **S6 is the risk-sensitive one** (enforcement) and lands after S4. S7 closes.
**Two devs:** Dev A → S1/S2/S3 (scoring — analytic, no hardware risk); Dev B → S4/S5/S6 (registry, scan, enforcement). Meet at S7.

> **Hard rule:** device blocking is **not** exposed live until **S6's self-protection test passes on the board** — a device-block that catches the gateway locks the operator out.

---

## 5. File structure (all new — strictly additive)

```
src/devices/
├── mod.rs             # DevicesConfig::from_env(), re-exports              [S1]
├── errors.rs          # DevicesError                                       [S1]
├── model.rs           # DeviceScores, DeviceRecord, DeviceScanRun          [S1]
├── scoring/
│   ├── mod.rs         # combine + band-consistency check vs risk_level     [S1]
│   ├── security.rs    # PURE rubric (CVSS, ports, status, exposure)        [S1]
│   └── privacy.rs     # PURE rubric (cleartext, class, chattiness)         [S2]
├── registry.rs        # sidecar: manual add, name, monitoring (signed)     [S4]
├── scan.rs            # per-device targeted 5-step scan + progress         [S5]
├── enforce.rs         # block/unblock via Blocker (self-protection)        [S6]
└── tests/mod.rs                                                            [S1/S2]

src/api/handlers/devices.rs   # list / detail / summary / CRUD / scan / block [S3-S6]
```

Storage:
```
/var/lib/sgx-guardian/devices/
├── registry.json      # signed sidecar (user data — survives scans)
├── scores.json        # cached computed scores (recomputed after each scan)
└── scans.jsonl        # per-device scan runs (capped ring)
```

Env: `SGX_GUARDIAN_DEVICES_BASE`, `SGX_DEVICES_SCAN_TIMEOUT_SECS` (default 120). No new port, no `main.rs` spawn (scores compute on read/after-scan; scans are on-demand).

---

## 6. Exact FIND → REPLACE

### 6.1 `src/api/routes.rs` — add the router

**FIND** (closing lines of `crl_router()` — the shared anchor):
```rust
        .route(
            "/api/v1/crl/gossip/trigger",
            post(handlers::crl::gossip_trigger),
        )
}
```
> ⚠️ Sibling parallel plans append routers here too. Add `devices_router()` after the last one.

**REPLACE:**
```rust
        .route(
            "/api/v1/crl/gossip/trigger",
            post(handlers::crl::gossip_trigger),
        )
}

pub fn devices_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/devices", get(handlers::devices::list).post(handlers::devices::add_manual))
        .route("/api/v1/devices/summary", get(handlers::devices::summary))
        .route(
            "/api/v1/devices/:id",
            get(handlers::devices::detail)
                .patch(handlers::devices::edit)
                .delete(handlers::devices::remove),
        )
        .route("/api/v1/devices/:id/scan", post(handlers::devices::start_scan))
        .route("/api/v1/devices/:id/scan/:scan_id", get(handlers::devices::scan_status))
        .route("/api/v1/devices/:id/block", post(handlers::devices::block))
        .route("/api/v1/devices/:id/unblock", post(handlers::devices::unblock))
}
```
Extend the import if `patch` isn't present: `use axum::{routing::{get, patch, post}, Router};`

### 6.2 `src/api/mod.rs` — merge (⚠️ verify anchor)
```rust
        .merge(routes::crl_router())
        .merge(routes::devices_router())   // ← add
```

### 6.3 `src/main.rs` / `src/enforcement/executor.rs` — **no change**
No background task and no new port. Blocking reuses the existing `inet sgx_threat` chain via `Blocker`.

### 6.4 ⚠️ `risk_level()` may need to move
It currently lives in `src/api/handlers/discovery.rs`. The scoring module must call it to enforce band consistency (§1.1). Either make it `pub(crate)` and import it, or move it to `src/discovery/risk.rs` and re-export — **a pure move, no behaviour change**, and `/discovery/*` responses must be byte-identical afterwards (S3 acceptance).

---

## 7. Implementation contracts

**Reuse, don't reinvent:**
- **`risk_level()`** stays the authoritative band; scoring is bucketed to agree with it (§1.1).
- **Blocking** always via `Blocker` — it owns exemptions, TTL, `blocked_ips.json`, and the `inet sgx_threat` chain. **Never** shell out to `nft` from `src/devices/`.
- **Scanning** reuses the discovery scan entry points (targeted at one IP/host) — do not spawn a second NMAP subsystem; reuse intensity semantics (`stealth|standard|aggressive`).
- **Whitelist** remains the approve/authorise mechanism; `remove` cleans the sidecar and, when present, the whitelist entry.
- **Persistence/signing:** `write_atomic`, `sign_in_place_generic`, cached `load_runtime_key_manager(node_id)`; `AuditCategory` (add `Devices`).

**Async safety (board freeze):**
- Per-device NMAP via **`tokio::process::Command`** or `spawn_blocking` — **never** a synchronous `Command::new().output()` in the runtime.
- Inventory/registry reads via `tokio::fs`.
- Scoring is pure CPU over a small struct — fine inline; if inventory grows large, batch-score in `spawn_blocking`.
- Never hold the registry write lock across an `.await`.
- Do **not** touch `NebulaDaemon::start()` / `resolve_ca_ip_from_config_inner()`.

**Determinism:** scoring must be a pure function of the device record — two runs over unchanged input give identical scores (S7 asserts this).

---

## 8. Regression checks

```bash
cargo build --release && cargo test && cargo clippy -- -D warnings
cargo build --release --target aarch64-unknown-linux-gnu
cargo test --package sgx-guardian-client discovery::   # whitelist/classify untouched
cargo test --package sgx-guardian-client threat::      # blocker untouched
```

On the boards (binaries direct — **not** `systemctl`/`journalctl`):
```bash
API=http://localhost:8443/api/v1
./sgx_guardian_client nodeA

# Ensure inventory exists
curl -s -X POST "$API/discovery/scan/standard" >/dev/null; sleep 30

# Scores present, explainable, band-consistent
curl -s "$API/devices" | python3 -c "
import sys,json
for d in json.load(sys.stdin)[:5]:
    print(d['device_id'], 'sec=',d.get('security_score'), 'priv=',d.get('privacy_score'), 'level=',d.get('risk_level'))
    print('   reasons:', d.get('security_reasons')[:2])"

# Existing discovery endpoints byte-identical (risk_level move must not change them)
curl -s "$API/discovery/summary" | python3 -m json.tool
DID=$(curl -s "$API/discovery/devices" | python3 -c "import sys,json;print(json.load(sys.stdin)[0]['device_id'])")
curl -s "$API/discovery/devices/$DID" | python3 -c "import sys,json;d=json.load(sys.stdin);print('risk:',d['risk_level'],d['risk_reasons'])"

# Manual add + rename SURVIVES a rescan (sidecar proof)
curl -s -X POST "$API/devices" -H 'content-type: application/json' \
  -d '{"display_name":"Lab Printer","ip":"192.168.50.77","mac":"AA:BB:CC:11:22:33","manufacturer":"Acme"}' | python3 -m json.tool
curl -s -X POST "$API/discovery/scan/standard" >/dev/null; sleep 30
curl -s "$API/devices" | python3 -c "import sys,json;print('named devices:',[d.get('display_name') for d in json.load(sys.stdin) if d.get('display_name')])"

# Per-device 5-step scan
SID=$(curl -s -X POST "$API/devices/$DID/scan" | python3 -c "import sys,json;print(json.load(sys.stdin)['scan_id'])")
sleep 20; curl -s "$API/devices/$DID/scan/$SID" | python3 -m json.tool

# ⚠ SELF-PROTECTION (S6): blocking the gateway must be REFUSED
GW=$(ip route | awk '/default/{print $3; exit}')
GWID=$(curl -s "$API/devices" | python3 -c "import sys,json,os;print(next((d['device_id'] for d in json.load(sys.stdin) if d.get('ip')==os.environ.get('GW')),''))" GW="$GW")
curl -s -o /dev/null -w 'block gateway HTTP %{http_code}\n' -X POST "$API/devices/$GWID/block"   # expect 4xx refusal
curl -s "$API/threat/blocks" | python3 -c "import sys,json;print('blocked:',json.load(sys.stdin)['blocked'])"   # gateway MUST NOT appear
grep -a "exempt\|refused to block" /var/log/sgx-guardian/audit-nodeA.log | tail -3

# Determinism: same device, two reads → same score
A=$(curl -s "$API/devices/$DID" | python3 -c "import sys,json;print(json.load(sys.stdin)['security_score'])")
B=$(curl -s "$API/devices/$DID" | python3 -c "import sys,json;print(json.load(sys.stdin)['security_score'])")
echo "score A=$A B=$B (must match)"

curl -s "$API/health" >/dev/null && echo "API alive"
pkill -f sgx_guardian_client
```

---

## 9. Step-by-step checklist

**S1 — security rubric**
- [ ] `scoring/security.rs` pure; CVSS parsed from `vulners` script output
- [ ] `security_reasons` for every deduction; `None` + "insufficient data" when signals absent
- [ ] **Band agrees with `risk_level`** for all fixtures (level wins on conflict + audit)

**S2 — privacy rubric**
- [ ] `scoring/privacy.rs` pure; cleartext protocols, device class, chattiness, unknown vendor
- [ ] `privacy_basis: "network-observable"` always set; reasons attributable

**S3 — enrichment + REST**
- [ ] `risk_level()` visibility/move (§6.4) — `/discovery/*` responses byte-identical
- [ ] `GET /devices`, `/devices/:id`, `/devices/summary`; routes.rs + mod.rs

**S4 — registry (sidecar)**
- [ ] Signed `registry.json`; manual add, display_name, monitoring toggle
- [ ] **Survives a discovery rescan** (inventory rewrite does not clobber it)

**S5 — per-device scan**
- [ ] Targeted NMAP via `tokio::process`; 5 steps with progress + findings/recommendations
- [ ] Shared state so a running scan survives navigation

**S6 — block / remove** ⚠
- [ ] Block via `Blocker`; **self-protection inherited** (gateway/LAN/overlay refused + audited)
- [ ] MAC-aware re-apply on IP change; unblock; remove cleans sidecar (+ whitelist)

**S7 — board + regression**
- [ ] Deterministic scores across repeated scans
- [ ] discovery/threat/gossip/CRL green; no watchdog reset

---

## 10. Risks

| Risk | Mitigation |
|---|---|
| **Blocking a device blocks the gateway / management LAN → operator locked out** | All blocking via `Blocker`'s inherited exemption (live local subnets + gateway + `block_exempt`); S6 board test asserts refusal; not live until verified |
| **Score contradicts `risk_level`** in the UI | Score bucketed to the existing band; level authoritative on conflict + audited (§1.1) |
| **Invented/misleading scores** on thin data (stealth scan) | `None` + "insufficient data" → existing `unknown` band; never a fake midpoint |
| **User data wiped by the next scan** | Sidecar registry keyed by `device_id`; inventory never mutated (S4 asserts survival) |
| **Privacy score over-read as a vendor-privacy rating** | `privacy_basis: "network-observable"` + reasons; flagged to FE/Cervais (§11) |
| **DHCP: blocked IP reassigned to an innocent device** | MAC-aware block re-apply; TTL from `Blocker`; re-evaluate on each scan |
| **Board freeze** from a sync NMAP call | `tokio::process`/`spawn_blocking`; `tokio::fs`; no daemon-lifecycle edits |
| **`risk_level()` move changes discovery output** | Pure move; S3 asserts `/discovery/*` responses byte-identical |
| Branch drift | Re-verify anchors; confirm `risk_level()` and the blocker exemption helper visibility |

---

## 11. Decisions for Cervais / FE

1. **Privacy Score scope.** It can only measure **network-observable** exposure (cleartext protocols, device class, chattiness) — not vendor data practices. Confirm this framing, and that the FE labels it accordingly rather than as a general "privacy rating".
2. **Scoring rubric sign-off.** The security rubric and its weights should be reviewed and agreed (it drives an operator-visible number). Recommend publishing the rubric in the user guide so scores are defensible.
3. **Should device block be available at all in this cut?** Blocking is the only destructive action here. Alert-and-recommend is the safe default; confirm whether operators should be able to block a device directly from the inventory.
4. **`unknown` presentation.** Stealth scans yield no OS/ports → no score. Confirm the FE shows "insufficient data — run a deeper scan" rather than an empty ring.
