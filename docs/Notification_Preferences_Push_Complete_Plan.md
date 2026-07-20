# Notification Preferences + Push — Complete Development Plan
### Base branch: `feat/62-CRL` · Module: `src/notify/` · **No new port** · Channel: **SSE**

---

## 0. Grounding note + why this is low-risk

Written against the **actual indexed repo state**, not memory.

**Two existing, tested patterns make this feature mostly a clone, not new invention:**

1. **`src/threat/ai_bridge.rs`** already implements exactly the bus this feature needs — a process-wide broadcast tap:
   ```rust
   static FEATURE_TAP: OnceLock<broadcast::Sender<AlertFeature>> = OnceLock::new();
   fn tap() -> &'static broadcast::Sender<AlertFeature> { FEATURE_TAP.get_or_init(|| broadcast::channel(1024).0) }
   pub fn subscribe() -> broadcast::Receiver<AlertFeature> { tap().subscribe() }
   pub fn forward_to_ai(node_id: &str, alert: &ThreatAlert) { … let _ = tap().send(feature); … }  // non-blocking
   ```
   And it is **already called from the eve-alert loop** for every High/Critical Suricata alert. That call site is the exact place to wire the "Alerts" notification category.

2. **`src/threat/inventory.rs`** already implements the store this feature needs — a capped ring buffer (`MAX_ALERTS = 10_000`) with atomic JSONL persistence (`save_atomic`, `load_from_path`, dedup). The notification store mirrors it.

The notification bus mirrors #1; the notification store mirrors #2. This is the safest of the feature plans.

**Independence (your constraint).** Vault and In-Circle File Transfer are being built **in parallel and are not in the branch**. This feature does **not** depend on either. Its only touchpoint is the **threat pipeline**, which is in `feat/62-CRL`. Events those other features will emit (file shared, new message, incoming call, member joined) are defined here as **published-when-they-exist seams** — the enum variants exist, but nothing fires them until those features land and call `notify::publish(...)`. Zero coupling.

**Could not verify:** GitHub live PR/diff (private repo → 404). Anchors from the project-knowledge index — re-verify against the tip of `feat/62-CRL`. The exact **`forward_to_ai(...)` call site** and the `src/api/mod.rs` merge line each need a one-second eyeball.

---

## 1. The channel decision (WebSocket / SSE / FCM)

**Recommendation: SSE (Server-Sent Events) as the primary channel.** Reasoning specific to this product:

| Option | Fit for this system | Verdict |
|---|---|---|
| **FCM / APNs** (mobile push via Google/Apple) | Requires a mobile app **and** internet reachability to Google/Apple servers. This is a **zero-trust edge appliance** whose whole ethos is *"no cloud required" / "Rules run on your Guardian"*. Routing notifications through Google/Apple **breaks offline operation** and adds a cloud dependency to a product that markets *not* needing one. | ❌ **Not the primary path.** Optional opt-in only, for a future mobile app when the device has internet (§13). |
| **WebSocket** | Bidirectional, persistent. Works on LAN/offline, rides `:8443`. But notifications are **one-way** (Guardian → console) — the bidirectional channel and its upgrade/connection-management complexity are unneeded here. | 🟡 Alternative if a future feature needs client→server streaming. Overkill for notifications. |
| **SSE** | One-way server→client over a long-lived HTTP response — the **exact shape of a push notification**. Rides the existing `:8443`, works fully offline/on-LAN, browsers auto-reconnect via `EventSource`, and support **`Last-Event-ID` replay** for missed events. No new port, no upgrade handshake. | ✅ **Primary.** |

**The one thing SSE alone doesn't give — durability — the store provides.** The AI FeatureTap drops lagging subscribers (fine for a feature stream); **notifications must not be lost**. So: the **broadcast bus** delivers live to connected consoles, and the **persisted store** guarantees nothing is lost — on (re)connect, SSE first **replays missed notifications** from the store (via `Last-Event-ID`), then switches to live. Best of both.

> "Push" in the FE = the notification *concept* delivered live to the console over SSE, plus a persisted history/badge. It does **not** mean FCM.

---

## 2. Architecture

```
   EVENT SOURCES (publish — non-blocking)                 CONSUMERS
   ┌───────────────────────────────┐
   │ Suricata alerts  ── EXISTS ──► │
   │  (next to forward_to_ai)       │              ┌──────────────────────────┐
   │ Device discovered ─ EXISTS ──► │  notify::    │ persistence task (spawn) │
   │ Guardian offline ── EXISTS ──► │  publish() ──►   subscribes → STORE     │  durability
   │ ─────────────────────────────  │   (bus)      └──────────────────────────┘
   │ file shared      ─ FUTURE ───► │                          │
   │ new message      ─ FUTURE ───► │              ┌──────────────────────────┐
   │ incoming call    ─ FUTURE ───► │              │ SSE /notifications/stream│
   │ member joined    ─ FUTURE ───► │ ────────────►│  replay(Last-Event-ID)   │──► Admin
   └───────────────────────────────┘              │  → live from bus         │    Console
                                                   │  filtered by PREFERENCES │    (EventSource)
   BUS  = OnceLock<broadcast::Sender>              └──────────────────────────┘
          (clone of ai_bridge.rs)
   STORE = capped ring + atomic JSONL              PREFERENCES = signed, persisted
          (clone of inventory.rs)                   3 categories (Alerts/Devices/Circles)
```

Live delivery, durability, and preference-filtering are three separate concerns, cleanly split — exactly like the existing threat + AI split.

---

## 3. Data model (matches the FE Notification Preferences screen exactly)

```rust
pub enum NotificationCategory { Alerts, Devices, Circles }

pub enum NotificationKind {
    // Alerts (source EXISTS — Suricata)
    AlertHigh, AlertMedium, AlertLow,
    // Devices (source EXISTS — NMAP discovery / health)
    DeviceDiscovered, DevicePendingApproval, GuardianOffline,
    // Circles (sources FUTURE — fired by transfer/chat/calls/circle when they land)
    CircleNewMessage, CircleIncomingCall, CircleMemberJoined, CircleFileShared,
}

pub struct NotificationEvent {
    pub id: String,            // monotonic — the SSE event id / Last-Event-ID cursor
    pub kind: NotificationKind,
    pub title: String,
    pub body: String,
    pub severity: String,      // info|low|medium|high|critical
    pub ref_id: Option<String>,// alert_id / device_id / circle_id — deep-link target
    pub created_at: String,    // RFC3339
    pub read: bool,
}

// Persisted, signed. Defaults all-on. Mirrors the FE's three grouped cards.
pub struct NotificationPrefs {
    pub alerts:  AlertPrefs,   // { high, medium, low }
    pub devices: DevicePrefs,  // { new_device, pending_approval, guardian_offline }
    pub circles: CirclePrefs,  // { new_message, incoming_call, member_joined }
    pub sequence: u64,
    pub proof: Proof,          // ECDSA-P256, owner DKP — same as every registry
}
```

**Filtering rule:** an event is delivered to a console only if its `kind`'s matching preference toggle is `true`. The Circle toggles exist and persist now; their events simply never fire until those features are built.

---

## 4. Deliverables

Each independently reviewable/testable; tree stays green (`cargo build && cargo test && cargo clippy -- -D warnings`); no existing behaviour changes.

| # | Deliverable | Files | Acceptance test |
|---|---|---|---|
| **D1** | **Event model + bus + preferences model** (no network) | `src/notify/{mod,errors,model,bus,prefs}.rs`, `src/lib.rs` | Unit: bus is a `OnceLock<broadcast::Sender>` clone of `ai_bridge` — `publish()` is non-blocking and a no-op with no subscribers; `subscribe()` receives; `NotificationPrefs` signs/verifies, defaults all-on, tampered prefs rejected; `kind → toggle` filter mapping correct. |
| **D2** | **Notification store** (no network) | `src/notify/store.rs` | Unit (mirror `inventory.rs` tests): capped ring evicts oldest; `save_atomic` JSONL round-trips; `replay_after(id)` returns only newer events; `unread_count()` correct; monotonic ids survive reload. |
| **D3** | **Persistence task + spawn** | `src/notify/mod.rs`, `src/main.rs` | Board: `notify::spawn(node_id)` subscribes to the bus and appends every published event to the store; a published event is durable across restart. **This is the only `main.rs` change** — one line, beside `crl::gossip::spawn`. |
| **D4** | **Preferences REST + filtering** | `src/api/handlers/notify.rs`, `routes.rs`, `mod.rs` | `GET /notifications/prefs` returns current toggles; `PUT /notifications/prefs` persists (signed); filtering verified — an event whose toggle is off is not delivered over the stream. |
| **D5** | **SSE stream** | `src/api/handlers/notify.rs` | Browser/`curl`: `GET /notifications/stream` streams live events as SSE; on connect with `Last-Event-ID`, missed events replay from the store first, then live; prefs-filtered; keep-alive heartbeat holds the connection; auto-reconnect resumes without loss. |
| **D6** | **Wire sources + history REST + 3-node** | `src/api/handlers/notify.rs`, alert/discovery call sites, `tests/notify_*.sh` | Board: a real Suricata High alert produces a notification on the stream + in history; `GET /notifications` (history), `POST /notifications/:id/read`, `GET /notifications/unread-count` work; Device + Guardian-offline seams wired at their event sites; Circle seams defined (unfired). 3-node run; threat/gossip/CRL regression green. |

**Sequencing:** D1 → D2 one dev (both are clones of existing modules). D3 spawns the persistence task. D4/D5 are the REST + SSE surface. D6 wires sources. **Two devs:** Dev A → D1→D2→D3; Dev B → D4→D5 (REST/SSE) as soon as D1's bus + model exist; meet at D6.

---

## 5. File structure (all new — strictly additive)

```
src/notify/
├── mod.rs        # NotifyConfig, spawn(node_id), re-exports              [D1/D3]
├── errors.rs     # NotifyError                                           [D1]
├── model.rs      # NotificationEvent, NotificationKind, Category         [D1]
├── bus.rs        # OnceLock<broadcast::Sender> — clone of ai_bridge.rs   [D1]
├── prefs.rs      # NotificationPrefs (signed, persisted) + filter()      [D1]
├── store.rs      # capped ring + save_atomic JSONL — clone of inventory  [D2]
└── tests/mod.rs  # unit tests                                            [D1/D2]

src/api/handlers/notify.rs   # prefs GET/PUT, SSE stream, history, read   [D4/D5/D6]
```

Storage:

```
/var/lib/sgx-guardian/notify/
├── events.jsonl        # capped ring of NotificationEvent (atomic)
└── prefs.json          # signed NotificationPrefs
```

Env: `SGX_GUARDIAN_NOTIFY_BASE` (mirrors `SGX_GUARDIAN_VC_BASE`), `SGX_NOTIFY_MAX_EVENTS` (default 2000).

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

> ⚠️ Other parallel plans append their routers here too. Add `notify_router()` after the last existing one.

**REPLACE:**

```rust
        .route(
            "/api/v1/crl/gossip/trigger",
            post(handlers::crl::gossip_trigger),
        )
}

pub fn notify_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/notifications/stream", get(handlers::notify::stream))
        .route("/api/v1/notifications", get(handlers::notify::history))
        .route("/api/v1/notifications/unread-count", get(handlers::notify::unread_count))
        .route("/api/v1/notifications/:id/read", post(handlers::notify::mark_read))
        .route("/api/v1/notifications/read-all", post(handlers::notify::mark_all_read))
        .route(
            "/api/v1/notifications/prefs",
            get(handlers::notify::get_prefs).put(handlers::notify::put_prefs),
        )
}
```

Extend the `routes.rs` import if `put` isn't present (it uses `.put(...)`):

**FIND:** `use axum::{ routing::{get, post}, Router };`
**REPLACE:** `use axum::{ routing::{get, post, put}, Router };`
*(If a prior plan already added `patch`, just add `put` to the same list.)*

### 6.2 `src/api/mod.rs` — merge (⚠️ verify anchor)

```rust
        .merge(routes::crl_router())
        .merge(routes::notify_router())   // ← add
```

### 6.3 `src/main.rs` — spawn the persistence task (the ONE main.rs line)

**FIND** (verbatim):

```rust
    sgx_guardian_client::crl::gossip::spawn(node_id.clone(), did_resolver.clone());
```

**REPLACE:**

```rust
    sgx_guardian_client::crl::gossip::spawn(node_id.clone(), did_resolver.clone());

    // === Notification persistence ===
    // Subscribes to the notification bus and durably appends events to the
    // store (so nothing is lost when no console is connected). One background
    // tokio task; returns immediately; runs on every node role.
    sgx_guardian_client::notify::spawn(node_id.clone());
```

### 6.4 Wire the "Alerts" source (⚠️ verify the `forward_to_ai` call site)

Find where `ai_bridge::forward_to_ai(` is called on the eve-alert path and add a parallel publish beside it — same argument, same non-blocking contract:

```rust
    crate::threat::ai_bridge::forward_to_ai(node_id, &alert);
    // NEW — surface High/Medium/Low Suricata alerts as user notifications
    crate::notify::publish_alert(node_id, &alert);
```

`publish_alert` maps `ThreatAlert::severity` → `AlertHigh/Medium/Low`, builds a `NotificationEvent`, and calls `notify::publish()` (non-blocking). This is the single concrete source wiring for D6; Device / Guardian-offline follow the same one-line `notify::publish(...)` pattern at their event sites.

---

## 7. Implementation contracts (clone the existing modules)

**Bus** — copy `ai_bridge.rs` structure exactly:
```rust
static NOTIFY_BUS: OnceLock<broadcast::Sender<NotificationEvent>> = OnceLock::new();
fn bus() -> &'static broadcast::Sender<NotificationEvent> {
    NOTIFY_BUS.get_or_init(|| broadcast::channel(1024).0)
}
pub fn subscribe() -> broadcast::Receiver<NotificationEvent> { bus().subscribe() }
pub fn publish(ev: NotificationEvent) { let _ = bus().send(ev); }   // non-blocking, drop-if-no-subscriber
```

**Store** — copy `inventory.rs`: `VecDeque` ring capped at `SGX_NOTIFY_MAX_EVENTS`, `save_atomic` (tmp + `sync_all` + `rename`), `load_from_path`. Add `replay_after(id)` and `unread_count()`. Guard mutations with `NOTIFY_WRITE_LOCK: Lazy<Mutex<()>>` (the `CRL_WRITE_LOCK` discipline).

**SSE** — axum's native type:
```rust
use axum::response::sse::{Sse, Event, KeepAlive};
// on connect: read Last-Event-ID header → store.replay_after(id) as the first events,
// then map the broadcast Receiver into SSE Events, each with .id(ev.id) for resume.
Sse::new(stream).keep_alive(KeepAlive::default())
```

**Signing** prefs — identical to every registry: `sign_in_place_generic(&mut prefs.proof, &canonical, km, &vm_ref)`, `vm_ref = "{did}#dkp-v{n}"`, `km = load_runtime_key_manager(node_id)` (cached — never re-init `DkpManager`).

**Async safety (board freeze):**
- `publish()` is non-blocking (in-memory broadcast) — safe to call from the async eve-loop, exactly like `forward_to_ai`.
- **All disk writes live in the spawned persistence task and the REST handlers**, via `tokio::fs` / short `save_atomic`; never on the publish hot path.
- The SSE handler must **not** block — it returns a stream; keep-alive prevents idle timeouts.
- Never hold `NOTIFY_WRITE_LOCK` across an `.await`.
- No `std::thread::sleep`; no synchronous `Command::new().output()` in the runtime.
- The spawn mirrors `crl::gossip::spawn` and returns immediately — it does **not** touch `NebulaDaemon::start()` or daemon lifecycle.

**Audit** — add `AuditCategory::Notify`: prefs updated; (optionally) high-severity notification raised.

---

## 8. Regression checks

```bash
cargo build --release
cargo test
cargo clippy -- -D warnings
cargo build --release --target aarch64-unknown-linux-gnu

# Untouched — must still pass (we wired next to, not into, the threat path)
cargo test --package sgx-guardian-client threat::
cargo test --package sgx-guardian-client crl::
```

On the boards (binaries direct — **not** `systemctl`/`journalctl`):

```bash
./sgx_guardian_client nodeA

# Stream is live (leave it open in one shell)
curl -N "http://127.0.0.1:8443/api/v1/notifications/stream"

# Trigger a real Suricata alert (or inject a test EVE line) → a notification appears on the stream
# History + unread reflect it
curl -s "http://127.0.0.1:8443/api/v1/notifications" | jq '. | length'
curl -s "http://127.0.0.1:8443/api/v1/notifications/unread-count" | jq .

# Preferences persist and filter
curl -s "http://127.0.0.1:8443/api/v1/notifications/prefs" | jq .
curl -s -X PUT "http://127.0.0.1:8443/api/v1/notifications/prefs" \
  -H 'content-type: application/json' -d '{"alerts":{"high":true,"medium":false,"low":false}}'
#   → a Medium alert should NOT appear on the stream after this

# Durability: notifications survive restart
pkill -f sgx_guardian_client && ./sgx_guardian_client nodeA
curl -s "http://127.0.0.1:8443/api/v1/notifications" | jq '. | length'   # non-zero

# No watchdog reset; threat pipeline unharmed
curl -s "http://127.0.0.1:8443/api/v1/threat/alerts?limit=5" | jq '. | length'
tail -f /var/log/sgx-guardian/*.log | grep -iE "notify|panic|watchdog"
pkill -f sgx_guardian_client
```

---

## 9. Step-by-step checklist

**D1 — model + bus + prefs**
- [ ] `src/notify/{mod,errors,model,bus,prefs}.rs`; `pub mod notify;` in `src/lib.rs`
- [ ] `bus.rs` = `OnceLock<broadcast::Sender>` clone of `ai_bridge.rs`; `publish`/`subscribe`
- [ ] `NotificationEvent` + `NotificationKind` (Alerts/Devices/Circles)
- [ ] `NotificationPrefs` signed + persisted, all-on default, `filter(kind) -> bool`
- [ ] Unit: non-blocking publish, filter mapping, tampered prefs rejected

**D2 — store**
- [ ] `store.rs` = capped ring + `save_atomic` clone of `inventory.rs`
- [ ] `replay_after(id)`, `unread_count()`, monotonic ids; `NOTIFY_WRITE_LOCK`
- [ ] Unit (mirror `threat_inventory_test.rs`): eviction, round-trip, replay

**D3 — persistence task + spawn**
- [ ] `notify::spawn(node_id)` subscribes → appends to store
- [ ] `main.rs` one-line spawn beside gossip (§6.3)
- [ ] Board: published event durable across restart

**D4 — prefs REST + filter**
- [ ] `get_prefs` / `put_prefs` (signed); routes.rs + mod.rs (§6.1, §6.2)
- [ ] Filtering verified — off-toggle event not delivered

**D5 — SSE**
- [ ] `stream` handler: `Last-Event-ID` replay → live from bus, prefs-filtered
- [ ] `KeepAlive`; auto-reconnect resumes without loss

**D6 — sources + history + 3-node**
- [ ] Wire `publish_alert` beside `forward_to_ai` (§6.4)
- [ ] Device + Guardian-offline seams at their event sites; Circle seams defined (unfired)
- [ ] `history`, `mark_read`, `mark_all_read`, `unread_count`
- [ ] 3-node; threat/gossip/CRL regression green; no watchdog reset

---

## 10. Risks

| Risk | Mitigation |
|---|---|
| **Blocking the eve-loop** on publish | `publish()` is in-memory broadcast (clone of `forward_to_ai`); all disk I/O is in the spawned task / handlers |
| **Board freeze** | No blocking in runtime; `tokio::fs`; no lock across await; spawn mirrors gossip; no daemon-lifecycle edits |
| **Lost notifications** when no console connected | Store persists every event; SSE replays via `Last-Event-ID` on reconnect |
| **Unbounded growth** on flash | Capped ring (`SGX_NOTIFY_MAX_EVENTS`) + atomic rewrite, exactly like `inventory.rs` |
| **Wrong channel choice** (FCM breaking offline) | SSE primary — offline/LAN, no cloud; FCM is opt-in future only (§1, §13) |
| **Coupling to unbuilt features** | Circle/transfer/chat/call variants are defined-but-unfired seams; only the in-branch threat source is wired |
| **`forward_to_ai` call site drift** | Verify that anchor (§6.4) before wiring; the publish call is additive beside it |
| Branch drift | Re-verify anchors against the tip of `feat/62-CRL` |

---

## 11. Parallel-development notes (Vault / File Transfer running separately)

- **No shared files** with the Vault or File-Transfer tracks. This feature touches `src/notify/` (new), `src/api/handlers/notify.rs` (new), and three shared edit points: `routes.rs`, `mod.rs`, `main.rs`.
- **Merge-conflict surface = the three shared files.** All three are append-style: a new `notify_router()`, a new `.merge(...)` line, a new `spawn(...)` line. If Vault/Transfer touch the same three, resolution is trivial (each adds its own router / merge / spawn line). Agree an ordering with those devs for `routes.rs` to minimise churn.
- **When File Transfer / Chat / Calls / Circle land**, they enable their notifications by calling `crate::notify::publish(NotificationEvent{ kind: CircleFileShared, … })` at their event sites — no change to this module. The seam is already here.

---

## 12. Out of scope (flag to Cervais / other tracks)

- **Mobile push (FCM / APNs).** Optional future opt-in for a mobile app when the device has internet — explicitly secondary, never the primary path, to preserve offline/zero-trust operation. Would add an outbound push adapter behind a feature flag.
- **Per-user notification routing.** Single-owner console assumed; multi-user fan-out is a later concern.
- **Notification actions** (act on a notification inline, e.g. "approve device" from the toast). This cut delivers + deep-links (`ref_id`); acting is the target feature's endpoint.
- **Email / webhook delivery.** Not in the FE; add later as additional `notify::publish` subscribers if requested.
