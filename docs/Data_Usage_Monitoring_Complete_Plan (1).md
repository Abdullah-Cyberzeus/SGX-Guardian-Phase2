# Data Usage Monitoring — Complete Development Plan
### Base branch: `feat/62-CRL` · Module: `src/dusage/` · **No new port**

---

## 0. Grounding note + an honest correction

Written against the **actual indexed repo state**, not memory.

**The "nftables counters already hain" assumption is wrong — verified.** `build_nft_ruleset()` in `src/enforcement/executor.rs` emits every rule as a plain `accept` / `drop` with **no `counter` statement**:
```rust
out.push_str("    tcp dport 50063 accept\n");   // no counter
```
`render_rule()` likewise joins parts ending in `accept`/`drop` — no counter. (The `counter accept` in `docs/architecture/README.md` is an *illustrative* example, not the shipped code.) **So there are no per-rule byte counters to read today.**

**The genuinely zero-change source is `/sys/class/net/<iface>/statistics/{rx_bytes,tx_bytes,rx_packets,tx_packets}`** (equivalently `/proc/net/dev`) — per-interface counters, always present, no `nft` subprocess, no enforcement edit. This is the real "easy" path and it is the durable one: **eBPF enforcement is a Sprint-9 item that will replace user-space nftables** (`SGX Phase 2.docx`), so building on nftables counters has a shelf-life; `/sys` interface stats survive that migration.

**Three honest scope notes:**
1. **Per-interface / overall usage = easy** (`/sys`). This is the core and matches what the FE Data Usage screen actually shows (aggregate bars + breakdown).
2. **Per-category = moderate** — requires **adding `counter name "<cat>"` statements** to the enforcement ruleset (additive, non-behavioural) and reading them via async `nft`. Delivered as D5.
3. **Per-device (per-IP) = the hard part** — needs conntrack accounting (`nf_conntrack_acct`) or an nftables IP-keyed counter map. Not "easy". Delivered as optional D6, clearly scoped.
4. **Some FE categories are not network-measurable.** The FE shows "AI analysis cache" and local "device telemetry" under data usage — **that is local storage/compute, not network bytes.** The backend measures real *network* usage; those categories need a different source (disk/subsystem accounting) or should be re-scoped. Flag to FE.

**Could not verify:** GitHub live PR/diff (private repo → 404, then rate-limited). Anchors from the project-knowledge index — re-verify against the tip of `feat/62-CRL`. The `src/api/mod.rs` merge line needs a one-second eyeball.

---

## 1. The one correctness subtlety: cumulative counters reset

`/sys` (and nftables) counters are **cumulative since boot** and **reset to zero on reboot / counter flush**. So "usage this period" is **not** the raw counter — it is `current − period_baseline`, and the sampler must handle the counter going **backwards**:

- On each sample, if `current_raw < baseline` → the counter reset (reboot / nft flush) → **re-baseline** (set baseline to the current raw value; treat the pre-reset bytes as already counted for the period, or 0). Never report a negative or a giant spurious spike.
- Interface add/remove: an interface that disappears (e.g. `nebula0` down) keeps its last period contribution; a new interface starts a fresh baseline.

This is the whole trick. Everything else is aggregation + REST.

---

## 2. Architecture

```
   SAMPLER LOOP (spawned, tokio::time::interval)
   every SGX_DUSAGE_SAMPLE_SECS:
     • read /sys/class/net/*/statistics/{rx,tx}_bytes   (tokio::fs — no subprocess)     ── per-interface  (D1/D2)
     • [D5] read `nft -j list counters` (async)         (tokio::process)                 ── per-category   (D5)
     • [D6] read conntrack / nft IP-keyed map (async)                                     ── per-device     (D6)
     • period usage = current − baseline (reset/wraparound handled)
     • detect period rollover → snapshot completed period → history, re-baseline
                    │
        ┌───────────┴────────────┐
        ▼                        ▼
   STATE (signed baselines)   HISTORY (capped ring)      QUOTA (signed)
   dusage/state.json          dusage/history.jsonl        dusage/quota.json
                    │
                    ▼
   REST (:8443, no new port):
   GET /dusage/current · GET /dusage/history · GET/PUT /dusage/quota · POST /dusage/reset
```

No boot-critical work, no daemon-lifecycle touch — the sampler mirrors `crl::gossip::spawn` (one `main.rs` line) and returns immediately.

---

## 3. Data model

```rust
pub struct InterfaceUsage {
    pub iface: String,          // wlan0 / nebula0 / uap0 / eth0
    pub rx_bytes: u64,          // THIS PERIOD  (current − baseline)
    pub tx_bytes: u64,
    pub rx_total: u64,          // raw cumulative counter (since boot)
    pub tx_total: u64,
}
pub struct CategoryUsage {      // per-port-group (D5)
    pub category: String,       // gossip / registry / cert-bootstrap / api / nebula / discovery
    pub bytes: u64,             // this period
}
pub struct DeviceUsage {        // per-IP (D6, optional)
    pub ip: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}
pub struct UsageSnapshot {
    pub period: String,         // daily | weekly | monthly
    pub period_start: String,   // RFC3339
    pub interfaces: Vec<InterfaceUsage>,
    pub categories: Vec<CategoryUsage>,     // empty unless D5
    pub devices: Vec<DeviceUsage>,          // empty unless D6
    pub total_bytes: u64,       // this period (Σ interface rx+tx)
    pub quota_bytes: Option<u64>,
    pub used_pct: Option<f64>,  // total/quota — drives the FE bar colour
    pub sampled_at: String,
}
// Persisted, signed:
pub struct DusageState {
    pub period: String,
    pub period_start: String,
    pub iface_baselines: BTreeMap<String, (u64, u64)>,   // iface -> (rx,tx) at period start
    pub category_baselines: BTreeMap<String, u64>,
    pub sequence: u64,
    pub proof: Proof,
}
pub struct DusageQuota {
    pub quota_bytes: u64,
    pub period: String,         // reset cadence
    pub sequence: u64,
    pub proof: Proof,           // ECDSA-P256, owner DKP
}
```

**Bar colour** (matches the FE): `used_pct > 80` → red, `> 50` → amber, else green — computed server-side so every client is consistent.

---

## 4. Deliverables

Each independently reviewable/testable; tree stays green (`cargo build && cargo test && cargo clippy -- -D warnings`); no existing behaviour changes.

| # | Deliverable | Files | Acceptance test |
|---|---|---|---|
| **D1** | **Per-interface counter reader (`/sys`) + reset/wraparound + model** (no network) | `src/dusage/{mod,errors,model,counters}.rs`, `src/lib.rs` | Unit: parses `/sys/class/net/*/statistics/*` (fixture dir via env); `period = current − baseline`; **counter-went-backwards → re-baseline, never negative/spurious-spike**; new/removed iface handled. |
| **D2** | **Sampler loop + spawn + period state** | `src/dusage/{sampler,state}.rs`, `src/main.rs` | Board: `dusage::spawn(node_id)` samples every `SGX_DUSAGE_SAMPLE_SECS`; `state.json` (signed baselines) written atomically; transferring data moves the counters (verify `rx_bytes` grows). **One `main.rs` line**, beside `crl::gossip::spawn`. Uses `tokio::time::interval` + `tokio::fs`. |
| **D3** | **Quota + reset scheduling + thresholds** | `src/dusage/quota.rs`, `sampler.rs` | Unit + board: `used_pct` = total/quota, colour thresholds (>80/>50); **period rollover** (daily/weekly/monthly) snapshots the completed period to history and re-baselines; a low quota → `used_pct` crosses thresholds correctly. |
| **D4** | **REST + history + analytics** | `src/api/handlers/dusage.rs`, `routes.rs`, `mod.rs` | `GET /dusage/current` (per-interface + totals + quota + pct); `GET /dusage/history` (completed periods); `GET/PUT /dusage/quota` (signed); `POST /dusage/reset` (manual re-baseline). |
| **D5** | **Per-category via nftables named counters** (additive enforcement edit) | `src/enforcement/executor.rs`, `src/dusage/counters.rs` | Board: `build_nft_ruleset` gets `counter name "<cat>"` on port-group rules (gossip/registry/cert-bootstrap/api/nebula) — **accept/drop behaviour unchanged**; `nft -j list counters` read **async** (`tokio::process`); `/dusage/current` shows per-category bytes. |
| **D6** | *(optional — the hard one)* **Per-device (per-IP)** | `src/dusage/devices.rs` | Board **only if conntrack available**: per-IP rx/tx via conntrack accounting (`nf_conntrack_acct=1` → `/proc/net/nf_conntrack`) or an nftables IP-keyed counter map; `/dusage/current` shows `devices[]`. Clearly gated + documented as harder. |
| **D7** | **Board validation + regression** | `tests/dusage_*.sh` | 3-node/board run; enforcement/gossip/CRL regression green; no watchdog reset; counter reads never block the loop. |

**Sequencing:** D1 → D2 → D3 → D4 is the **easy core** (one dev, ships real per-interface usage with quota/history/reset — zero enforcement change). **D5 (per-category)** is the one additive enforcement touch. **D6 (per-device)** is optional and harder. **Two devs:** Dev A → D1–D4 + D7; Dev B → D5 (and D6 if per-device is required).

---

## 5. File structure (all new except the D5 enforcement edit)

```
src/dusage/
├── mod.rs        # DusageConfig::from_env(), spawn(node_id)               [D1/D2]
├── errors.rs     # DusageError                                           [D1]
├── model.rs      # InterfaceUsage, CategoryUsage, UsageSnapshot, state   [D1]
├── counters.rs   # /sys reader (D1) + async nft counter reader (D5)      [D1/D5]
├── state.rs      # signed baselines, atomic persistence                  [D2]
├── sampler.rs    # interval loop, period rollover, reset detection       [D2/D3]
├── quota.rs      # DusageQuota, used_pct, thresholds                     [D3]
├── devices.rs    # per-IP via conntrack / nft map (optional)             [D6]
└── tests/mod.rs                                                          [D1/D3]

src/api/handlers/dusage.rs   # current / history / quota / reset          [D4]
src/enforcement/executor.rs  # + counter statements on port-group rules   [D5, additive]
```

Storage:
```
/var/lib/sgx-guardian/dusage/
├── state.json        # signed baselines + current period
├── history.jsonl     # completed-period snapshots (capped ring)
└── quota.json        # signed quota + reset cadence
```

Env: `SGX_GUARDIAN_DUSAGE_BASE`, `SGX_DUSAGE_SAMPLE_SECS` (default 60), `SGX_DUSAGE_PERIOD` (`daily|weekly|monthly`, default `monthly`), `SGX_DUSAGE_QUOTA_BYTES` (0 = no quota). No new port.

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
> ⚠️ Sibling parallel plans append routers here too. Add `dusage_router()` after the last one.

**REPLACE:**
```rust
        .route(
            "/api/v1/crl/gossip/trigger",
            post(handlers::crl::gossip_trigger),
        )
}

pub fn dusage_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/dusage/current", get(handlers::dusage::current))
        .route("/api/v1/dusage/history", get(handlers::dusage::history))
        .route(
            "/api/v1/dusage/quota",
            get(handlers::dusage::get_quota).put(handlers::dusage::put_quota),
        )
        .route("/api/v1/dusage/reset", post(handlers::dusage::reset))
}
```

### 6.2 `src/api/mod.rs` — merge (⚠️ verify anchor)
```rust
        .merge(routes::crl_router())
        .merge(routes::dusage_router())   // ← add
```

### 6.3 `src/main.rs` — spawn the sampler (one line)
**FIND** (verbatim):
```rust
    sgx_guardian_client::crl::gossip::spawn(node_id.clone(), did_resolver.clone());
```
**REPLACE:**
```rust
    sgx_guardian_client::crl::gossip::spawn(node_id.clone(), did_resolver.clone());

    // === Data-usage sampler ===
    // Periodically snapshots per-interface byte counters, computes per-period
    // usage (baseline-relative, reset-safe), and rolls history. One background
    // tokio task; returns immediately; runs on every node role.
    sgx_guardian_client::dusage::spawn(node_id.clone());
```

### 6.4 `src/enforcement/executor.rs` — add counters (D5 only, additive)
Add `counter name "<cat>"` to the port-group allow rules so the accept/drop behaviour is **unchanged** but bytes are counted. Example:

**FIND:**
```rust
    // Allow CRL gossip exchange for decentralized revocation propagation
    out.push_str("    tcp dport 50063 accept\n");
```
**REPLACE:**
```rust
    // Allow CRL gossip exchange for decentralized revocation propagation
    out.push_str("    tcp dport 50063 counter name \"gossip\" accept\n");
```
> Repeat for the other categories (registry 50062 → `"registry"`, cert-bootstrap 50061 → `"cert-bootstrap"`, Nebula 4242 → `"nebula"`, etc.). Named counters must be **declared** in the table (`counter gossip {}` …). **`counter` never changes accept/drop** — purely additive. D5 acceptance re-verifies the ruleset still applies and the firewall behaves identically.

---

## 7. Implementation contracts

**Reuse, don't reinvent:** `/sys`/`/proc` reads follow `src/network_selector.rs` (but via **`tokio::fs`** on this periodic path); the signed-config + `write_atomic` pattern from `vc/persistence.rs`; the capped-ring + atomic-JSONL history from `threat/inventory.rs`; `AuditCategory` (add `Dusage`).

**Async safety (board freeze):**
- Sampler uses **`tokio::time::interval`** — never `std::thread::sleep`.
- **`/sys`/`/proc` reads via `tokio::fs`** (periodic path).
- **The `nft -j list counters` read (D5) is async** (`tokio::process::Command`), **never** a synchronous `Command::new().output()` in the runtime. (The enforcement `apply_rules` shells out synchronously, but that is a one-shot apply, not our periodic sampler.)
- Never hold a write lock across `.await`; `state.json` writes are small.
- Do **not** touch `NebulaDaemon::start()` / `resolve_ca_ip_from_config_inner()`.

**Correctness:** period usage = `current.saturating_sub(baseline)`; on `current < baseline` re-baseline + audit; period rollover snapshots then re-baselines to the current raw values.

---

## 8. Regression checks

```bash
cargo build --release
cargo test
cargo clippy -- -D warnings
cargo build --release --target aarch64-unknown-linux-gnu

# Untouched — must still pass (D5 touches enforcement additively → re-run it)
cargo test --package sgx-guardian-client enforcement::
cargo test --package sgx-guardian-client crl::
```

On the boards (binaries direct — **not** `systemctl`/`journalctl`):

```bash
API=http://localhost:8443/api/v1
./sgx_guardian_client nodeA

# Sampler started
grep -a "Data-usage\|dusage" /var/log/sgx-guardian/audit-nodeA.log | tail -1

# Current usage — per interface, totals, quota %:
curl -s "$API/dusage/current" | python3 -m json.tool

# Generate traffic, then confirm counters moved:
B=$(curl -s "$API/dusage/current" | python3 -c "import sys,json;print(json.load(sys.stdin)['total_bytes'])")
curl -s http://127.0.0.1:8443/api/v1/health >/dev/null; dd if=/dev/zero bs=1M count=20 2>/dev/null | nc -w1 192.168.50.248 50063 || true
sleep 70   # > sample interval
A=$(curl -s "$API/dusage/current" | python3 -c "import sys,json;print(json.load(sys.stdin)['total_bytes'])")
echo "total BEFORE=$B AFTER=$A  (AFTER should be >= BEFORE)"

# Quota threshold: set a small quota, check used_pct colour band:
curl -s -X PUT "$API/dusage/quota" -H 'content-type: application/json' -d '{"quota_bytes":1048576,"period":"monthly"}' >/dev/null
curl -s "$API/dusage/current" | python3 -c "import sys,json;d=json.load(sys.stdin);print('used_pct:',d.get('used_pct'))"

# Reboot-safe: reboot (or flush nft counters), confirm no negative/huge spike:
#   ssh reboot ... then:
curl -s "$API/dusage/current" | python3 -c "import sys,json;print([ (i['iface'],i['rx_bytes']) for i in json.load(sys.stdin)['interfaces']])"   # non-negative, sane

# History + manual reset:
curl -s "$API/dusage/history" | python3 -c "import sys,json;print('periods:',len(json.load(sys.stdin)))"
curl -s -X POST "$API/dusage/reset" | python3 -m json.tool

# Enforcement unharmed (esp. after D5):
nft list ruleset | grep -E "policy drop|dport 50063"      # chain intact, gossip still allowed
curl -s "$API/crl/gossip/status" | python3 -c "import sys,json;print(json.load(sys.stdin).get('merkle_root'))"
pkill -f sgx_guardian_client
```

---

## 9. Step-by-step checklist

**D1 — /sys reader + reset/wraparound**
- [ ] `src/dusage/{mod,errors,model,counters}.rs`; `pub mod dusage;`
- [ ] Parse `/sys/class/net/*/statistics/{rx,tx}_bytes` (env-overridable root for tests)
- [ ] `period = current.saturating_sub(baseline)`; backwards → re-baseline
- [ ] Unit: reset-safe, new/removed iface

**D2 — sampler + spawn + state**
- [ ] `dusage::spawn(node_id)` + one-line `main.rs` (§6.3); `tokio::time::interval`, `tokio::fs`
- [ ] `state.json` signed + atomic
- [ ] Board: counters grow with traffic

**D3 — quota + reset scheduling**
- [ ] `used_pct` + colour thresholds; daily/weekly/monthly rollover → history + re-baseline
- [ ] Unit + board

**D4 — REST + history**
- [ ] `current` / `history` / `quota` (GET/PUT) / `reset`; routes.rs + mod.rs (§6.1, §6.2)

**D5 — per-category counters** *(additive enforcement)*
- [ ] `counter name` on port-group rules (§6.4) + declare counters; behaviour unchanged
- [ ] async `nft -j list counters` read; `/dusage/current` shows categories
- [ ] Re-run enforcement regression

**D6 — per-device** *(optional, harder)*
- [ ] conntrack accounting or nft IP-keyed map; gated on availability
- [ ] `/dusage/current` shows `devices[]`

**D7 — board + regression**
- [ ] 3-node; enforcement/gossip/CRL green; no watchdog reset

---

## 10. Risks

| Risk | Mitigation |
|---|---|
| **Assuming nftables counters exist** (they don't) | Core uses `/sys` interface stats (zero enforcement change); counters are *added* in D5 |
| **Cumulative-counter reset → negative / spurious spike** | `saturating_sub` + backwards-detection → re-baseline + audit (§1) |
| **eBPF migration (Sprint 9) removes nftables counters** | `/sys` interface stats are the durable primary source; D5 (nft counters) is the optional layer |
| **Board freeze** from a synchronous `nft`/`/sys` read | `tokio::fs` for `/sys`; async `tokio::process` for `nft`; `tokio::time::interval`; no daemon-lifecycle edits |
| **D5 enforcement edit breaks the firewall** | `counter` is non-behavioural; D5 acceptance re-verifies accept/drop + gossip still works |
| **Per-device is treated as easy** (it isn't) | D6 is optional + clearly scoped (conntrack/IP-keyed map) |
| Branch drift | Re-verify anchors against the tip of `feat/62-CRL` |

---

## 11. Decisions for Cervais / FE

1. **Which breakdown does the FE actually need?** Per-**interface** + per-**category** (port-group) is the easy, real set and matches the current screen. **Per-device (per-IP)** is a harder add — confirm if it's in scope.
2. **The FE's non-network categories** ("AI analysis cache", local "device telemetry") are **not network bytes** — either re-scope those labels to real network categories, or add a separate disk/subsystem-accounting source (not this feature).
3. **Reset cadence** — daily / weekly / monthly, and the default quota (0 = monitor only, no cap).
