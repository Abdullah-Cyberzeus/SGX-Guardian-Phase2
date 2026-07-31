# Geofencing — Location-Based Alerts + Automation Integration
### The two modules the Geofencing plan left as *seams* — now made self-contained
### Base branch: `feat/62-CRL` · Module: `src/geofence/` (extends) · **No new port**

---

## 0. Grounding note + what these modules replace

Written against the **actual indexed repo state**, not memory.

**The gap being closed.** The Geofencing plan implemented zones, sources, and the enter/exit engine, but left **"location-based alerts"** and **"automation integration"** as *seams* — a `notify::publish(...)` call (depends on the separate Notification feature) and a "rules-engine event schema" (depends on the unbuilt Alert Rules engine #12). Neither was self-contained. This plan makes both **real and self-contained on capabilities that are already live in `feat/62-CRL`.**

**What I confirmed is live (so we don't wait on other features):**

| Capability | Where | Used for |
|---|---|---|
| `ThreatAlert` struct + `AlertInventory` (capped ring, `ingest`, `save_atomic`, `load_from_path`) | `src/threat/{threat_alert,inventory}.rs` | **Location-based alerts** — geofence emits real, persisted, user-visible alerts in the same shape the Alerts UI already renders (`GET /threat/alerts`) |
| `forward_to_ai(node_id, &alert)` broadcast tap (non-blocking) | `src/threat/ai_bridge.rs` | Feed geofence events to the anomaly engine for correlation |
| Transport lock (`/transport/lock`), nftables `sgx_guardian` enforcement | `src/enforcement/`, transport handlers | **Automation** — network-lock action |
| DKP emergency rotation (`/dkp/emergency-rotate`) | `src/api/handlers/dkp.rs` | **Automation** — anti-theft key rotation |
| NMAP discovery scan (`/discovery/*`) | `src/discovery/` | **Automation** — run-scan action |
| `notify::publish` bus | Notification plan (sibling) | **Automation** — notify action (seam; optional) |

**Could not verify:** GitHub live PR/diff (private repo → 404, then rate-limited). Anchors from the project-knowledge index — re-verify against the tip of `feat/62-CRL`. Depends on the base Geofencing module (`src/geofence/`, plan `Geofencing_Location_Zones_Complete_Plan.md`) — if not yet built, land that first (G1–G4).

---

## 1. The design decision that matters most: automation is a loaded gun

Geofence-triggered automation is genuinely powerful for a physical-security appliance — *"the Guardian left the Control Room → assume theft → rotate keys, lock the network, raise a critical alert."* It is also **the most dangerous feature in the whole backlog**: a false positive (and RF-signature location is noisy) could make the appliance **lock itself out or rotate its own keys** with no attacker present.

So the automation module is built **safe-by-default and defence-in-depth:**

1. **Alert-only by default.** A new zone's automation is `RaiseAlert` + (optional) `Notify` only. Nothing destructive unless explicitly configured.
2. **Destructive actions are double-gated.** `LockNetwork` and `EmergencyKeyRotation` require (a) an explicit `allow_destructive: true` on the zone **and** (b) a high **confidence/dwell** threshold — a single noisy evaluation can never trigger them; the breach must persist.
3. **Dry-run is the default execution mode.** `SGX_GEOFENCE_ACTIONS_DRYRUN=1` (default) logs and audits what *would* run without running it. Execution is an explicit opt-in.
4. **Fail-safe.** An action executor error is caught, audited, and never crashes the eval loop or wedges the daemon.
5. **Debounced.** Each action fires at most once per confirmed transition, not repeatedly while outside.

> These are not optional polish — for this feature they are the feature. The plan treats them as first-class deliverables (B3).

---

## 2. Architecture (extends the geofence eval loop)

```
   GEOFENCE EVAL LOOP (from base plan)
   confirmed entry/exit transition (already hysteresis-gated)
                    │
        ┌───────────┴─────────────────────────────────┐
        ▼                                               ▼
  MODULE A — Location-Based Alerts            MODULE B — Automation Integration
  ┌────────────────────────────┐             ┌──────────────────────────────────────┐
  │ build a ThreatAlert-shaped  │             │ look up zone.automation[on_entry|exit]│
  │ record (geofence sid range) │             │ dispatch each Action on a SEPARATE    │
  │  → geofence AlertInventory  │             │ task (never blocks the eval loop):    │
  │  → /geofence/alerts         │             │   RaiseAlert    → Module A            │
  │  → notify::publish (seam)   │             │   Notify        → notify bus (seam)   │
  │  → forward_to_ai (correlate)│             │   RunScan       → discovery           │
  └────────────────────────────┘             │   LockNetwork   *destructive, gated*  │
                                              │   EmergencyKeyRotation *destructive*  │
   RULES-ENGINE SEAM (#12, later):            │ dry-run default · fail-safe · debounce│
   geofence.entry / geofence.exit             └──────────────────────────────────────┘
   become triggers when #12 lands
```

**Module A is also Module B's `RaiseAlert` action** — one implementation, two entry points (the eval loop always alerts; the action engine can also alert as a configured action).

---

## 3. Module A — Location-Based Alerts

### Data & storage

Geofence alerts reuse the **exact `ThreatAlert` shape** so the Alerts UI needs no new schema — but live in a **geofence-owned** store so they never race the Suricata inventory writer:

```
/var/lib/sgx-guardian/geofence/alerts.jsonl   # AlertInventory of ThreatAlert, geofence-owned
```

Field mapping for a geofence event:

| ThreatAlert field | Geofence value |
|---|---|
| `signature_id` | dedicated range **10000900–10000999** (fits the existing SGX custom-rule range: e.g. 10000131, 10000201) |
| `signature` | `"SGX GEOFENCE {zone_name} {ENTRY|EXIT}"` |
| `category` | `ThreatCategory::PolicyViolation` (a zone breach is a policy event) |
| `severity` | the zone's configured severity (`Info`..`Critical`) |
| `src_ip` | `"geofence:local"` (synthetic marker — this is not a network flow) |
| `dst_ip` | `zone_id` |
| `event_type` | `"alert"` |
| `alert_id` | **must include the transition timestamp** (see the dedup subtlety below) |

> **Dedup subtlety (important):** `AlertInventory` dedups by `alert_id = SHA256(sid‖src‖dst)`. If geofence used a fixed sid+src+dst per zone, **repeated entry/exit of the same zone would collapse into one alert.** So the geofence `alert_id` must incorporate the transition timestamp (e.g. `SHA256(sid‖zone_id‖transition‖ts)[..16]`) so **every transition is a distinct alert**, not merged like a recurring network flow.

### Surfacing in the main Alerts UI

Because the records are the same `ThreatAlert` shape, the FE Alerts tab can merge two sources trivially: `GET /threat/alerts` (Suricata) + `GET /geofence/alerts` (geofence). No new alert model, no threat-pipeline change (we do **not** write into the Suricata inventory — that would race its writer). *(A future thin aggregator endpoint could merge them server-side; not required for this cut. Flag to FE.)*

### Also fires (non-blocking seams)
- `notify::publish(...)` — if the Notification feature is present, the alert reaches the console live over SSE.
- `forward_to_ai(node_id, &alert)` — existing, non-blocking; lets the anomaly engine correlate a geofence breach with network events.

---

## 4. Module B — Automation Integration

### Action catalog (fixed, safe enum — each maps to an existing live capability)

```rust
pub enum GeofenceAction {
    RaiseAlert { severity: String },      // Module A (always safe)
    Notify     { severity: String },      // notify bus seam (safe)
    RunScan,                              // NMAP discovery (safe, read-only-ish)
    LockNetwork,                          // transport lock / enforcement   ⚠ DESTRUCTIVE
    EmergencyKeyRotation,                 // /dkp/emergency-rotate           ⚠ DESTRUCTIVE
}
```

### Per-zone automation config (default alert-only)

```rust
pub struct ZoneAutomation {
    pub on_entry: Vec<GeofenceAction>,    // default: []
    pub on_exit:  Vec<GeofenceAction>,    // default: [RaiseAlert{severity:"high"}]
    pub allow_destructive: bool,          // default: false — gate for Lock/KeyRotation
    pub min_confidence: f64,              // default: 0.9 — dwell/score required for destructive
}
```

Stored inside the zone record (extends `GeofenceZone` from the base plan) or a sibling `actions.json`. Signed with the rest of the registry.

### Dispatch (never blocks the eval loop)

On a confirmed transition, the eval loop **hands the action list to a separate dispatch task** (`tokio::spawn`) and returns immediately. Each action runs via async / `spawn_blocking` as appropriate (key rotation touches the SE050; scans shell out). An action failure is caught + audited; the loop is never stalled or crashed.

### Safeguards (deliverable B3 — the heart of this module)

- **Dry-run default** (`SGX_GEOFENCE_ACTIONS_DRYRUN=1`): every action is audited as `would-run` but not executed. Execution requires explicitly setting it to `0`.
- **Destructive double-gate:** `LockNetwork` / `EmergencyKeyRotation` execute only if `zone.allow_destructive == true` **and** the transition confidence ≥ `zone.min_confidence`. Otherwise they are **downgraded to a critical alert** ("would have locked network — confidence too low / not allowed") and audited.
- **Debounce:** an action fires once per transition; re-entering the "outside" state does not re-fire until an entry→exit cycle completes.
- **Fail-safe:** executor errors are isolated per action; one failing action does not block the others or the loop.

### Rules-engine seam (#12) stays
When the general Alert Rules engine lands, `geofence.entry` / `geofence.exit` are exposed as triggers there too (broader cross-feature automation). The geofence-local action engine is the **immediate, self-contained** capability; the seam is the **future, general** one. No coupling either way.

---

## 5. Deliverables

Each independently reviewable/testable; tree stays green (`cargo build && cargo test && cargo clippy -- -D warnings`); no existing behaviour changes.

| # | Deliverable | Files | Acceptance test |
|---|---|---|---|
| **A1** | **Geofence alert store + model** (no network) | `src/geofence/alerts.rs` | Unit: builds a `ThreatAlert` with a geofence sid (10000900+), category=PolicyViolation; **two transitions of the same zone produce two distinct alerts** (timestamped `alert_id`, not deduped); own `alerts.jsonl` ring + `save_atomic` round-trips; never opens the Suricata inventory. |
| **A2** | **Alert emission + endpoint + seams** | `src/geofence/{alerts,eval}.rs`, `src/api/handlers/geofence.rs` | Board: a confirmed exit writes a geofence alert; `GET /geofence/alerts` returns it (same shape as `/threat/alerts`); `notify::publish` fires (if Notification present); `forward_to_ai` called (non-blocking). Suricata `/threat/alerts` **unchanged** (no race). |
| **B1** | **Action catalog + per-zone config** (no network) | `src/geofence/actions/{mod,catalog,config}.rs` | Unit: `GeofenceAction` enum; `ZoneAutomation` defaults (on_exit=[RaiseAlert high], allow_destructive=false, min_confidence=0.9); config signs/persists with the registry; unknown/malformed action rejected (fail-closed). |
| **B2** | **Action executor + async dispatch + fail-safe** | `src/geofence/actions/executor.rs`, `eval.rs` | Board (**non-destructive only**): configure on_exit=[RunScan, Notify]; a confirmed exit dispatches both on a **separate task** (eval loop not blocked); a deliberately-failing action is caught + audited, others still run. |
| **B3** | **Safeguards** (dry-run, destructive gate, debounce) | `src/geofence/actions/executor.rs` | Board: with dry-run **on** (default), a zone configured with `EmergencyKeyRotation` **does not rotate** — only audits "would-run"; with `allow_destructive=false`, a destructive action is **downgraded to a critical alert**; debounce — repeated evals outside fire the action once. **Verify DKP version is unchanged after a dry-run.** |
| **B4** | **Action-config REST + rules-engine seam + regression** | `src/api/handlers/geofence.rs`, `routes.rs`, `tests/geofence_actions_*.sh` | `GET/PUT /geofence/zones/:id/actions`; `POST /geofence/actions/test` (dry-run a zone's actions on demand); geofence event schema exposed for #12. 3-node/board run; threat/gossip/CRL/DKP regression green; no watchdog reset. |

**Sequencing:** A1 → A2 (Module A, self-contained, ships first — real alerts with zero risk). Then B1 → B2 → **B3 (safeguards before any destructive action is ever wired live)** → B4. **Two devs:** Dev A → Module A + B1/B4 (config + REST); Dev B → B2/B3 (executor + safeguards — the risk-sensitive core, one careful owner).

> **Hard rule:** destructive actions (`LockNetwork`, `EmergencyKeyRotation`) are **not enabled for live execution until B3 (safeguards) is complete and board-verified.** Until then they exist only in dry-run.

---

## 6. File structure (extends the geofence module — additive)

```
src/geofence/
├── alerts.rs                 # Module A: ThreatAlert-shaped store + emit        [A1/A2]
├── actions/
│   ├── mod.rs                # ZoneAutomation, re-exports                       [B1]
│   ├── catalog.rs            # GeofenceAction enum                              [B1]
│   ├── config.rs             # per-zone config, signed persistence             [B1]
│   └── executor.rs           # async dispatch, safeguards, fail-safe            [B2/B3]
├── (eval.rs)                 # + on-transition: emit alert + dispatch actions   [A2/B2]
└── (model.rs)                # + ZoneAutomation on GeofenceZone                 [B1]

src/api/handlers/geofence.rs  # + /geofence/alerts, /zones/:id/actions, /actions/test  [A2/B4]
```

Storage (extends geofence base):

```
/var/lib/sgx-guardian/geofence/
├── alerts.jsonl        # geofence AlertInventory (ThreatAlert shape)   (NEW, Module A)
├── zones.json          # + per-zone `automation` config                (extended)
├── location.json       # latest valid active-provider fix
├── reported_location.json # latest admin/API reported coordinate input
├── status.json         # latest evaluated ZoneStatus vector
├── source_selection.json # active auto/forced source and selection reason
└── events.jsonl
```

Source selection env:
- `SGX_GEOFENCE_SOURCE=auto` or unset: production auto mode. Priority is fresh valid GNSS, then RF signature, then fresh reported location. Manual coordinates are not used as an auto fallback.
- Forced test/admin modes remain: `manual`, `reported`, `rf`, `gnss`.
- Auto stability knobs: `SGX_GEOFENCE_SOURCE_FRESHNESS_SECS` (default 120), `SGX_GEOFENCE_SOURCE_CONFIRM_SUCCESSES` (default 3), `SGX_GEOFENCE_SOURCE_FAILURE_THRESHOLD` (default 3), `SGX_GEOFENCE_SOURCE_HOLD_DOWN_SECS` (default 60).

Action env: `SGX_GEOFENCE_ACTIONS_DRYRUN` (**default `1` = safe**), `SGX_GEOFENCE_ACTION_CONFIDENCE` (destructive floor, default 0.9). No new port. No new `main.rs` line — this rides the base plan's existing `geofence::spawn` eval loop.

---

## 7. Exact FIND → REPLACE

### 7.1 `src/api/routes.rs` — extend the geofence router

Add to the existing `geofence_router()` (from the base plan):

**FIND** (the base geofence router's events route):
```rust
        .route("/api/v1/geofence/events", get(handlers::geofence::events))
```

**REPLACE:**
```rust
        .route("/api/v1/geofence/events", get(handlers::geofence::events))
        // Location-based alerts (Module A)
        .route("/api/v1/geofence/alerts", get(handlers::geofence::alerts))
        // Automation config (Module B)
        .route(
            "/api/v1/geofence/zones/:id/actions",
            get(handlers::geofence::get_actions).put(handlers::geofence::put_actions),
        )
        .route("/api/v1/geofence/actions/test", post(handlers::geofence::test_actions))
```

### 7.2 `src/geofence/eval.rs` — emit alert + dispatch actions on a confirmed transition

In the base plan's transition handler, **after** a transition is confirmed (post-hysteresis):

```rust
// Module A — always raise a location-based alert (self-contained, zero risk):
crate::geofence::alerts::emit_transition_alert(node_id, &zone, transition, &fix_summary).await;

// Module B — dispatch configured actions on a SEPARATE task (never block the loop):
let zone_cloned = zone.clone();
let node = node_id.to_string();
tokio::spawn(async move {
    crate::geofence::actions::executor::dispatch(&node, &zone_cloned, transition, confidence).await;
});
```

`dispatch` internally honours dry-run, the destructive double-gate, debounce, and fail-safe (B3). The eval loop returns immediately either way.

---

## 8. Implementation contracts

**Reuse, don't reinvent:**
- **Alerts (Module A):** reuse `crate::threat::threat_alert::ThreatAlert` and the `AlertInventory` ring/`save_atomic` pattern — **but a geofence-owned instance and path.** Do **not** call the threat subsystem's writer (race). `ThreatAlert::compute_id` takes `(sid, src, dst)` — for geofence, extend the input with the transition timestamp so each event is unique.
- **Actions (Module B):** each action calls the **same internal function the corresponding REST handler calls** — not the HTTP endpoint. E.g. `RunScan` → the discovery scan entry point; `LockNetwork` → the transport-lock function; `EmergencyKeyRotation` → the DKP emergency-rotate function; `Notify` → `notify::publish`. This avoids an internal HTTP round-trip and keeps it in-process.
- **Signing** the zone/action config — the registry pattern (`sign_in_place_generic`, cached `load_runtime_key_manager(node_id)`).
- **Audit** — extend `AuditCategory::Geofence`: alert-raised, action-would-run (dry-run), action-executed, action-downgraded (gate), action-failed.

**Async safety (board freeze):**
- **Actions dispatch on a separate `tokio::spawn`** — the eval loop never blocks on an action.
- **Key rotation / scans that touch SE050 or shell out run via `spawn_blocking` / async** — never a synchronous `Command::new().output()` in the runtime.
- Alert `save_atomic` is a small write; keep it off the loop's critical section (do it in the emit helper, not while holding a lock across `.await`).
- Do **not** touch `NebulaDaemon::start()` / `resolve_ca_ip_from_config_inner()`.

**Fail-safe contract:** `dispatch` wraps each action in a `Result` guard; a panic/error is logged + audited and **swallowed** — a misbehaving action can degrade automation but must never take down the daemon or the eval loop.

---

## 9. Regression checks

```bash
cargo build --release
cargo test
cargo clippy -- -D warnings
cargo build --release --target aarch64-unknown-linux-gnu

# Untouched — must still pass (we read their entry points, we don't modify them)
cargo test --package sgx-guardian-client threat::
cargo test --package sgx-guardian-client geofence::
cargo test --package sgx-guardian-client crl::
```

On the boards (binaries direct — **not** `systemctl`/`journalctl`):

```bash
API=http://localhost:8443/api/v1
./sgx_guardian_client nodeA

# --- Module A: location-based alerts ---
# Drive a transition (Manual source: inside → outside), then check the geofence alert:
curl -s -X POST "$API/geofence/location" -d '{"lat":24.90,"lng":67.10}' >/dev/null   # outside
sleep 35
curl -s "$API/geofence/alerts" | python3 -c "import sys,json;a=json.load(sys.stdin);print('geofence alerts:',len(a));[print(x['signature'],x['severity']) for x in a[-3:]]"
# Same shape as Suricata alerts (FE can merge):
curl -s "$API/threat/alerts?limit=1" | python3 -c "import sys,json;print('threat alert keys:',sorted(json.load(sys.stdin)[0].keys()) if json.load.__self__ else '')" 2>/dev/null
# Suricata inventory UNCHANGED (no race):
curl -s "$API/threat/alerts" | python3 -c "import sys,json;print('threat count:',len(json.load(sys.stdin)))"

# --- Module B: dry-run is the default (DESTRUCTIVE MUST NOT RUN) ---
echo "DRYRUN=$SGX_GEOFENCE_ACTIONS_DRYRUN (expect 1/unset = safe)"
# Configure a zone with EmergencyKeyRotation on exit:
curl -s -X PUT "$API/geofence/zones/$CID/actions" -H 'content-type: application/json' \
  -d '{"on_exit":[{"EmergencyKeyRotation":null}],"allow_destructive":true,"min_confidence":0.9}' | python3 -m json.tool
# Record DKP version BEFORE:
DKP_BEFORE=$(curl -s "$API/dkp/status" | python3 -c "import sys,json;print(json.load(sys.stdin).get('version'))")
# Trigger an exit:
curl -s -X POST "$API/geofence/location" -d '{"lat":25.0,"lng":67.5}' >/dev/null
sleep 35
# DKP version AFTER — MUST equal BEFORE (dry-run did not rotate):
DKP_AFTER=$(curl -s "$API/dkp/status" | python3 -c "import sys,json;print(json.load(sys.stdin).get('version'))")
echo "DKP BEFORE=$DKP_BEFORE AFTER=$DKP_AFTER (must be equal in dry-run)"
grep -a "would-run\|action-would" /var/log/sgx-guardian/audit-nodeA.log | tail -3

# --- Fail-safe / no freeze ---
tail -f /var/log/sgx-guardian/*.log | grep -iE "geofence|action|panic|watchdog"
pkill -f sgx_guardian_client
```

---

## 10. Step-by-step checklist

**A1 — alert store + model**
- [ ] `src/geofence/alerts.rs`: geofence `AlertInventory` (own path), `ThreatAlert` builder, geofence sid range
- [ ] `alert_id` includes transition timestamp (two transitions → two alerts)
- [ ] Unit: distinct-per-transition, ring round-trip, does not touch Suricata inventory

**A2 — emission + endpoint + seams**
- [ ] `emit_transition_alert()` called from `eval.rs` on confirmed transition
- [ ] `GET /geofence/alerts`; `notify::publish` + `forward_to_ai` (non-blocking) fired
- [ ] Board: exit → geofence alert present; `/threat/alerts` unchanged

**B1 — catalog + config**
- [ ] `GeofenceAction` enum; `ZoneAutomation` defaults (alert-only, allow_destructive=false, min_confidence=0.9)
- [ ] Signed persistence; unknown action rejected
- [ ] Unit: defaults, sign/verify, fail-closed on malformed

**B2 — executor + dispatch**
- [ ] `dispatch()` on a separate `tokio::spawn`; actions call internal entry points (not HTTP)
- [ ] Non-destructive board test (RunScan + Notify); failing action isolated + audited

**B3 — safeguards** *(before any live destructive action)*
- [ ] Dry-run default; destructive double-gate (allow_destructive + confidence); debounce
- [ ] Board: EmergencyKeyRotation in dry-run → **DKP version unchanged**; destructive w/o allow → downgraded to critical alert
- [ ] Audit: would-run / downgraded / executed distinguished

**B4 — REST + seam + regression**
- [ ] `GET/PUT /geofence/zones/:id/actions`, `POST /geofence/actions/test`
- [ ] rules-engine event schema (`geofence.entry`/`exit`) exposed for #12
- [ ] 3-node; threat/gossip/CRL/DKP regression green; no watchdog reset

---

## 11. Risks

| Risk | Mitigation |
|---|---|
| **False-positive destructive action** (self-lock / self key-rotation) | **The whole safety design (§1, B3):** alert-only default, dry-run default, destructive double-gate (allow_destructive + confidence), debounce. Destructive not live until B3 verified. |
| **Racing the Suricata inventory writer** (lost geofence alerts) | Geofence uses its **own** `alerts.jsonl`; never writes the threat inventory. FE merges the two same-shape sources. |
| **Dedup collapsing repeated transitions** into one alert | `alert_id` includes the transition timestamp — each transition is distinct (§3) |
| **Blocking the eval loop** on a slow action (scan / key rotation) | Actions dispatch on a separate `tokio::spawn`; SE050/shell work via `spawn_blocking`; no lock across await; no daemon-lifecycle edits |
| **An action crashes the daemon** | Fail-safe: per-action error isolation, audited + swallowed |
| **Emergency rotation triggered in error is irreversible-ish** | Default off; opt-in + high confidence; recommend the client keep destructive actions disabled unless the anti-theft use-case is explicit (§12) |
| Branch drift | Re-verify anchors against the tip of `feat/62-CRL` |

---

## 12. Decisions for Cervais

1. **Do you want destructive automation at all?** Alert-only (raise + notify) covers "tell me the appliance moved." `LockNetwork` / `EmergencyKeyRotation` are the anti-theft response — powerful, but a false positive disrupts operations. **Recommend: ship alert-only; enable destructive only for a confirmed high-value anti-theft requirement, per zone.**
2. **If destructive is wanted, which source feeds confidence?** GNSS gives high-confidence position; RF-signature is noisier — destructive actions on RF alone need a conservative confidence floor and dwell.
3. **Should geofence alerts appear in the main Alerts tab now** (FE merges `/geofence/alerts`) or is a separate geofence view acceptable for the first cut?

## 13. Out of scope (flag to FE / #12)

- **Server-side alert aggregation** (one endpoint merging Suricata + geofence) — a thin later addition; for now the FE reads both same-shape sources.
- **General Alert Rules engine (#12).** This module is geofence-scoped automation; #12 is the cross-feature rules engine. Geofence events are exposed as triggers for it via the seam.
- **Reversal/auto-recovery of a triggered lock/rotation** (e.g. auto-unlock on return to zone) — a deliberate follow-up; destructive recovery must be its own carefully-designed flow, not a reflex.
