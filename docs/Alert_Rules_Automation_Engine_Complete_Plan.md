# Custom Alert Rules / Automation Engine — Complete Development Plan
### Base branch: `feat/62-CRL` · Module: `src/rules/` · **No new port**

---

## 0. Grounding note + the finding that shapes the design

Written against the **actual indexed repo state**, not memory.

**The finding: a single-purpose rules engine already exists and works — we are generalising it, not inventing it.** `src/threat/blocker.rs` contains:

```rust
/// Pure decision function - safe to unit test without nftables.
pub fn should_block(cfg: &SuricataConfig, alert: &ThreatAlert) -> bool {
    if !cfg.enabled { return false; }
    if !matches!(cfg.block_mode, BlockMode::InlineBlock) { return false; }
    if !matches!(alert.severity, Severity::High | Severity::Critical) { return false; }
    for exempt in &cfg.block_exempt { /* CIDR / IP exemption */ }
    true
}
```

That **is** an event→condition→action rule, hardcoded: *event* = ThreatAlert, *condition* = enabled + inline mode + severity ≥ High + not exempt, *action* = nftables drop + persist + audit. The generalised engine follows this exact shape — **pure, side-effect-free condition evaluation** (unit-testable without nftables), then a separate executor.

**Executors already exist and are live** — the engine calls internal entry points, never HTTP:

| Action | Backing capability (live) |
|---|---|
| Block / unblock IP | `Blocker` + `inet sgx_threat` chain (`POST /threat/blocks`) |
| Raise alert | `ThreatAlert` + `AlertInventory` |
| Notify | notify bus (`notify::publish`) — seam |
| Run discovery scan | `/discovery/scan/{stealth,standard,aggressive}` |
| Revoke DID | `/crl/revoke` ⚠ destructive |
| Lock transport | transport lock ⚠ destructive |
| Emergency key rotation | `/dkp/emergency-rotate` ⚠ destructive |
| Patch threat config | `/threat/config` |

**The critical safety inheritance.** `Blocker` protects the device from itself: `block_exempt` in `config/threat/config.yaml` lists `127.0.0.0/8` and `192.168.100.0/24` (Nebula overlay), **and** the code enumerates *"every local interface subnet and the default-route gateway … derived live from `ip addr show` so DHCP renewals and interface changes are handled automatically."* A user-authored rule such as *"on any alert → block source IP"* would otherwise be able to **block the management LAN or the gateway and lock the operator out of the box.** The engine **must** route every block through the same self-protection helper — this is non-negotiable (§3).

**Could not verify:** GitHub live PR/diff (private repo → 404, then rate-limited). Anchors from the project-knowledge index — re-verify against the tip of `feat/62-CRL`. The `src/api/mod.rs` merge line needs a one-second eyeball. Confirm the exact name/visibility of the local-subnet exemption helper in `blocker.rs` before reusing it (it may need to be made `pub(crate)`).

---

## 1. Design principles

1. **Pure evaluation, separate execution.** `evaluate(rule, event) -> bool` has no side effects and is unit-testable without nftables, SE050, or a network — exactly like `should_block`. Execution is a separate, spawned step.
2. **Fixed action catalog, not arbitrary code.** Rules select from a closed enum. No shell, no scripting, no user-supplied commands — that would be a remote-code-execution surface on a security appliance.
3. **Safe by default.** New rules are alert/notify only. Destructive actions require explicit opt-in per rule **and** survive the safeguards in §3.
4. **Never block the producing loop.** Rule evaluation and action dispatch run off the event-producing path (the eve-alert loop must not stall).
5. **Self-protection is inherited, not re-implemented.** All blocking goes through `Blocker`'s exemption logic.

---

## 2. Architecture

```
   EVENT SOURCES (already live)                RULES ENGINE                    EXECUTORS (internal calls)
   ┌──────────────────────────┐        ┌───────────────────────────┐
   │ Suricata alert           │  Event │  for each enabled rule:   │  Action  ┌────────────────────────┐
   │  (next to forward_to_ai) │───────►│   trigger matches?        │─────────►│ RaiseAlert / Notify    │
   │ Discovery: device found  │        │   conditions match? (pure)│          │ BlockIp  (via Blocker) │
   │ Geofence entry/exit      │        │   cooldown / rate ok?     │          │ RunScan                │
   │ Peer attest failed       │        │   dry-run? destructive?   │          │ RevokeDid   ⚠          │
   │ CRL revocation           │        └────────────┬──────────────┘          │ LockTransport ⚠        │
   └──────────────────────────┘                     │ tokio::spawn            │ EmergencyKeyRotation ⚠ │
                                                     ▼                         └────────────────────────┘
   RULES (signed registry)                  EXECUTION LOG (capped ring)
   rules/rules.json                         rules/executions.jsonl
```

Events reach the engine the same way notifications do — a **non-blocking publish** at each existing event site (`rules::publish(event)`), mirroring `forward_to_ai`. The engine subscribes; producers never wait.

---

## 3. Safeguards (the heart of the module)

| Safeguard | Behaviour |
|---|---|
| **Self-protection (inherited)** | Every `BlockIp` goes through `Blocker`'s exemption path: `block_exempt` config **plus** live-derived local interface subnets and the default gateway. A rule can never block the management LAN, the overlay, loopback, or the gateway. |
| **Dry-run default** | `SGX_RULES_DRYRUN=1` (default). Actions are audited as `would-run` and not executed. Execution is an explicit opt-in. |
| **Destructive opt-in** | `RevokeDid`, `LockTransport`, `EmergencyKeyRotation` require `allow_destructive: true` on the rule; otherwise they are **downgraded to a critical alert** and audited. |
| **Cooldown per rule** | `cooldown_secs` (default 300). A rule cannot re-fire for the same target within its cooldown — stops an alert storm from firing hundreds of actions. |
| **Rate cap per rule** | `max_actions_per_hour` (default 20). Exceeding it disables the rule's actions for the window and raises an alert — a runaway rule degrades to alerting, it does not run wild. |
| **Fail-safe** | Each action is isolated; an error is audited and swallowed. One bad rule never stalls the engine or the daemon. |
| **Signed rules** | `rules.json` is signed with the owner DKP; a tampered rule set is rejected on load (fail-closed → no rules run). |

---

## 4. Data model

```rust
pub enum RuleTrigger {
    ThreatAlert,          // Suricata
    DeviceDiscovered,     // NMAP discovery
    DeviceUnauthorized,
    GeofenceEntry, GeofenceExit,
    AttestationFailed,
    CrlRevocation,
}

pub enum Condition {                       // pure predicates over the event
    SeverityAtLeast(String),               // info|low|medium|high|critical
    CategoryIs(String),
    SignatureIdIn(Vec<u32>),
    SrcIpInCidr(String),
    PortIn(Vec<u16>),
    DeviceStatusIs(String),                // approved|unauthorized|drifted|stale
    ZoneIs(String),
    All(Vec<Condition>), Any(Vec<Condition>), Not(Box<Condition>),
}

pub enum RuleAction {
    RaiseAlert { severity: String },
    Notify     { severity: String },
    BlockIp    { ttl_secs: Option<u64> },  // via Blocker — self-protection applies
    RunScan    { intensity: String },
    RevokeDid,                             // ⚠ destructive
    LockTransport,                         // ⚠ destructive
    EmergencyKeyRotation,                  // ⚠ destructive
}

pub struct Rule {
    pub rule_id: String,          // urn:uuid
    pub name: String,             // FE: "Rule Name"
    pub enabled: bool,
    pub trigger: RuleTrigger,     // FE: "When"
    pub condition: Condition,     // FE: "If"
    pub actions: Vec<RuleAction>, // FE: "Then"
    pub notify: bool,             // FE: "Notify" toggle
    pub allow_destructive: bool,  // default false
    pub cooldown_secs: u64,       // default 300
    pub max_actions_per_hour: u32,// default 20
    pub created_at: String, pub updated_at: String,
}

pub struct RuleRegistry { pub rules: Vec<Rule>, pub sequence: u64, pub proof: Proof }

pub struct RuleExecution {     // audit/history for the FE
    pub id: String, pub rule_id: String, pub rule_name: String,
    pub trigger_summary: String, pub actions: Vec<String>,
    pub outcome: String,       // executed | dry-run | downgraded | rate-limited | failed
    pub at: String,
}
```

This maps 1:1 onto the FE Custom Alert Rules screen (Rule Name, Event Trigger, Condition, Action, Notify, enable switch, delete).

---

## 5. Deliverables

Each independently reviewable/testable; tree stays green (`cargo build && cargo test && cargo clippy -- -D warnings`); no existing behaviour changes.

| # | Deliverable | Files | Acceptance test |
|---|---|---|---|
| **E1** | **Rule model + pure condition evaluator** (no network, no side effects) | `src/rules/{mod,errors,model,eval}.rs`, `src/lib.rs` | Unit (mirroring `threat_blocker_logic_test.rs`): a matrix of (rule, event) → expected bool; `All/Any/Not` nesting; `SrcIpInCidr` boundary cases; **evaluator touches no nftables/network/SE050** (runs in a plain unit test). |
| **E2** | **Signed rule registry + CRUD REST** | `src/rules/{store,persistence}.rs`, `src/api/handlers/rules.rs`, `routes.rs`, `mod.rs` | Board: `POST /rules` creates (defaults: enabled, alert-only, `allow_destructive=false`, cooldown 300); `GET/PATCH/DELETE`; `rules.json` signed + atomic; **tampered registry rejected on load (no rules run)**. |
| **E3** | **Event ingestion (bus + source wiring)** | `src/rules/bus.rs`, event call sites | Board: a Suricata alert reaches the engine (publish next to `forward_to_ai`, non-blocking); discovery + geofence + attestation seams wired the same way; the producing loop is **not** blocked (API stays responsive under alert load). |
| **E4** | **Executors + self-protection inheritance** ⚠ | `src/rules/exec/{mod,actions}.rs` | Board (non-destructive): a rule with `BlockIp` on a **LAN/gateway/overlay** source is **refused by the inherited exemption** and audited — the operator is never locked out; `RaiseAlert`/`Notify`/`RunScan` execute via internal entry points (no HTTP round-trip). |
| **E5** | **Safeguards: dry-run, cooldown, rate cap, destructive gate** ⚠ | `src/rules/exec/guards.rs` | Board: with dry-run **on** (default), a rule with `EmergencyKeyRotation` **does not rotate** — **DKP version unchanged**, audited `would-run`; `allow_destructive=false` → **downgraded to critical alert**; 50 rapid alerts → cooldown/rate cap holds actions to the configured ceiling. |
| **E6** | **Dispatch wiring + execution history** | `src/rules/exec/mod.rs`, `handlers/rules.rs` | Board: matching event → `tokio::spawn` dispatch (engine never blocks); `GET /rules/executions` shows outcome per run (`executed`/`dry-run`/`downgraded`/`rate-limited`/`failed`); a deliberately failing action is isolated and audited, others still run. |
| **E7** | **Rule test endpoint + 3-node regression** | `handlers/rules.rs`, `tests/rules_*.sh` | `POST /rules/:id/test` evaluates a rule against a **sample event** in dry-run and returns the would-fire plan (no side effects). 3-node run; threat/discovery/gossip/CRL/DKP regression green; no watchdog reset. |

**Sequencing:** E1 → E2 → E3 (model, storage, events — all safe). Then **E4 → E5 (the security-critical pair)**, then E6 → E7.
**Two devs:** Dev A → E1/E2/E3/E7 (model, CRUD, ingestion, test endpoint); Dev B → **E4/E5/E6** (executors + safeguards — one careful owner).

> **Hard rule:** destructive actions are **not** enabled for live execution until **E4 (self-protection) and E5 (safeguards)** are board-verified. Until then the engine runs dry-run only.

---

## 6. File structure (all new — strictly additive)

```
src/rules/
├── mod.rs          # RulesConfig::from_env(), spawn(node_id), re-exports   [E1/E6]
├── errors.rs       # RulesError                                           [E1]
├── model.rs        # Rule, RuleTrigger, Condition, RuleAction, Execution  [E1]
├── eval.rs         # PURE evaluate(rule, event) -> bool                    [E1]
├── bus.rs          # OnceLock<broadcast::Sender<RuleEvent>> (ai_bridge clone)[E3]
├── store.rs        # RULES_WRITE_LOCK, signed registry CRUD               [E2]
├── persistence.rs  # paths + write_atomic                                 [E2]
└── exec/
    ├── mod.rs      # dispatch (spawned), execution log                     [E6]
    ├── actions.rs  # executors → internal entry points                     [E4]
    └── guards.rs   # dry-run, cooldown, rate cap, destructive gate         [E5]

src/api/handlers/rules.rs   # CRUD, test, executions                        [E2/E7]
```

Storage:
```
/var/lib/sgx-guardian/rules/
├── rules.json         # signed RuleRegistry
├── executions.jsonl   # capped ring of RuleExecution
└── state.json         # cooldown / rate-limit counters
```

Env: `SGX_GUARDIAN_RULES_BASE`, `SGX_RULES_DRYRUN` (**default `1` = safe**), `SGX_RULES_MAX_EXECUTIONS` (ring cap, default 2000).

---

## 7. Exact FIND → REPLACE

### 7.1 `src/api/routes.rs` — add the router

**FIND** (closing lines of `crl_router()` — the shared anchor):
```rust
        .route(
            "/api/v1/crl/gossip/trigger",
            post(handlers::crl::gossip_trigger),
        )
}
```
> ⚠️ Sibling parallel plans append routers here too. Add `rules_router()` after the last one.

**REPLACE:**
```rust
        .route(
            "/api/v1/crl/gossip/trigger",
            post(handlers::crl::gossip_trigger),
        )
}

pub fn rules_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/rules", get(handlers::rules::list).post(handlers::rules::create))
        .route(
            "/api/v1/rules/:id",
            get(handlers::rules::detail)
                .patch(handlers::rules::edit)
                .delete(handlers::rules::delete),
        )
        .route("/api/v1/rules/:id/enable", post(handlers::rules::set_enabled))
        .route("/api/v1/rules/:id/test", post(handlers::rules::test))
        .route("/api/v1/rules/executions", get(handlers::rules::executions))
}
```
Extend the import if `patch` isn't present: `use axum::{routing::{get, patch, post}, Router};`

### 7.2 `src/api/mod.rs` — merge (⚠️ verify anchor)
```rust
        .merge(routes::crl_router())
        .merge(routes::rules_router())   // ← add
```

### 7.3 `src/main.rs` — spawn the engine (one line)

**FIND** (verbatim):
```rust
    sgx_guardian_client::crl::gossip::spawn(node_id.clone(), did_resolver.clone());
```
**REPLACE:**
```rust
    sgx_guardian_client::crl::gossip::spawn(node_id.clone(), did_resolver.clone());

    // === Alert-rules automation engine ===
    // Subscribes to the rule event bus, evaluates enabled rules (pure predicates),
    // and dispatches actions on separate tasks under dry-run/cooldown/rate guards.
    // One background tokio task; returns immediately; runs on every node role.
    sgx_guardian_client::rules::spawn(node_id.clone());
```

### 7.4 Event source wiring (E3) — publish beside the existing tap

At the eve-alert site, next to `forward_to_ai` (⚠️ verify this call site):
```rust
    crate::threat::ai_bridge::forward_to_ai(node_id, &alert);
    // NEW — feed the rules engine (non-blocking)
    crate::rules::publish(RuleEvent::from_threat_alert(node_id, &alert));
```
Discovery / geofence / attestation / CRL sites follow the same one-line pattern.

---

## 8. Implementation contracts

**Reuse, don't reinvent:**
- **Evaluator shape:** copy `Blocker::should_block`'s purity discipline — no I/O inside `eval.rs`.
- **Blocking:** call `Blocker`'s block path (which owns exemption + TTL + `blocked_ips.json` + `inet sgx_threat`). **Never** shell out to `nft` from the rules module.
- **Bus:** `OnceLock<broadcast::Sender>` clone of `ai_bridge.rs`; `publish()` non-blocking.
- **Execution log:** capped ring + atomic JSONL, `threat/inventory.rs` pattern.
- **Signing/persistence:** `write_atomic`, `sign_in_place_generic`, cached `load_runtime_key_manager(node_id)`; `AuditCategory` (add `Rules`).

**Async safety (board freeze):**
- `publish()` is in-memory and non-blocking — safe from the eve-loop.
- Action dispatch on a **separate `tokio::spawn`**; scans/SE050 work via async or `spawn_blocking`; **never** a synchronous `Command::new().output()` in the runtime.
- Never hold `RULES_WRITE_LOCK` across an `.await`.
- Do **not** touch `NebulaDaemon::start()` / `resolve_ca_ip_from_config_inner()`.

---

## 9. Regression checks

```bash
cargo build --release && cargo test && cargo clippy -- -D warnings
cargo build --release --target aarch64-unknown-linux-gnu
cargo test --package sgx-guardian-client threat::     # blocker untouched
cargo test --package sgx-guardian-client discovery::
cargo test --package sgx-guardian-client crl::
```

On the boards (binaries direct — **not** `systemctl`/`journalctl`):
```bash
API=http://localhost:8443/api/v1
./sgx_guardian_client nodeA
grep -a "rules engine\|Rules" /var/log/sgx-guardian/audit-nodeA.log | tail -1

# Create an alert-only rule (safe default)
RID=$(curl -s -X POST "$API/rules" -H 'content-type: application/json' -d '{
  "name":"High alerts → notify","trigger":"ThreatAlert",
  "condition":{"SeverityAtLeast":"high"},
  "actions":[{"RaiseAlert":{"severity":"high"}}],"notify":true}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['rule_id'])")

# Dry-run a rule against a sample event (no side effects)
curl -s -X POST "$API/rules/$RID/test" | python3 -m json.tool

# SELF-PROTECTION (E4): a rule that would block the management LAN must be refused
curl -s -X PATCH "$API/rules/$RID" -H 'content-type: application/json' \
  -d '{"actions":[{"BlockIp":{"ttl_secs":600}}]}' >/dev/null
#   trigger an alert whose src_ip is on 192.168.50.0/24, then:
curl -s "$API/threat/blocks" | python3 -c "import sys,json;print('blocked:',json.load(sys.stdin)['blocked'])"
#   → management LAN / gateway MUST NOT appear
grep -a "exempt\|refused to block" /var/log/sgx-guardian/audit-nodeA.log | tail -3

# DESTRUCTIVE DRY-RUN (E5): DKP must not rotate
DKP_BEFORE=$(curl -s "$API/dkp/status" | python3 -c "import sys,json;print(json.load(sys.stdin).get('version'))")
#   (configure a rule with EmergencyKeyRotation + allow_destructive, fire it)
DKP_AFTER=$(curl -s "$API/dkp/status" | python3 -c "import sys,json;print(json.load(sys.stdin).get('version'))")
echo "DKP BEFORE=$DKP_BEFORE AFTER=$DKP_AFTER (must be equal in dry-run)"

# Cooldown / rate cap (E5): burst alerts, count executions
curl -s "$API/rules/executions" | python3 -c "import sys,json;d=json.load(sys.stdin);print('executions:',len(d));print([e['outcome'] for e in d[-5:]])"

# Connectivity + mesh unharmed
curl -s "$API/health" >/dev/null && echo "API alive"
nft list ruleset | grep -E "policy drop"
pkill -f sgx_guardian_client
```

---

## 10. Step-by-step checklist

**E1 — model + pure evaluator**
- [ ] `Rule`, `RuleTrigger`, `Condition`, `RuleAction`, `RuleExecution`
- [ ] `eval.rs` pure — no I/O; `All/Any/Not`; CIDR predicate
- [ ] Unit matrix mirroring `threat_blocker_logic_test.rs`

**E2 — registry + CRUD**
- [ ] Signed `rules.json` + `RULES_WRITE_LOCK` + atomic write
- [ ] `POST/GET/PATCH/DELETE /rules`, `:id/enable`; safe defaults
- [ ] Tampered registry → rejected, **no rules run**

**E3 — event ingestion**
- [ ] `bus.rs` (ai_bridge clone); `publish()` beside `forward_to_ai` (§7.4)
- [ ] Discovery / geofence / attestation / CRL seams
- [ ] Producing loop not blocked under alert load

**E4 — executors + self-protection** ⚠
- [ ] Actions call internal entry points (no HTTP)
- [ ] **All blocking via `Blocker`** (exemption inherited; confirm helper visibility)
- [ ] Board: LAN/gateway/overlay block refused + audited

**E5 — safeguards** ⚠
- [ ] Dry-run default; destructive opt-in → else downgrade to critical alert
- [ ] Cooldown + rate cap with persisted counters
- [ ] Board: DKP version unchanged in dry-run; burst capped

**E6 — dispatch + history**
- [ ] `tokio::spawn` dispatch; per-action isolation
- [ ] `executions.jsonl` ring; `GET /rules/executions`

**E7 — test endpoint + regression**
- [ ] `POST /rules/:id/test` (dry-run, no side effects)
- [ ] 3-node; threat/discovery/gossip/CRL/DKP green; no watchdog reset

---

## 11. Risks

| Risk | Mitigation |
|---|---|
| **A rule blocks the management LAN / gateway → operator locked out** | All blocking inherits `Blocker`'s live-derived local-subnet + gateway + `block_exempt` protection (§0, E4). Board test asserts refusal. |
| **Alert storm → hundreds of actions** | Cooldown + per-rule hourly rate cap; exceeding degrades to alerting (E5) |
| **False-positive destructive action** (revoke / rotate / lock) | Dry-run default + per-rule `allow_destructive` + downgrade-to-alert; not live until E4/E5 verified |
| **Arbitrary code execution via rules** | Fixed action enum — no shell, no scripts, no user commands (§1) |
| **Tampered rules file changes behaviour** | Signed registry; fail-closed (no rules run) on invalid signature |
| **Blocking the eve-loop** | Non-blocking `publish()`; dispatch on separate tasks; no sync `Command` in runtime |
| **Rule storm wedges the daemon** | Per-action isolation + fail-safe swallow; engine never panics the loop |
| Branch drift | Re-verify anchors; confirm the `blocker.rs` exemption helper's name/visibility |

---

## 12. Decisions for Cervais

1. **Which destructive actions should be available at all?** Recommend shipping with `RaiseAlert`, `Notify`, `RunScan`, `BlockIp` only; `RevokeDid` / `LockTransport` / `EmergencyKeyRotation` enabled per-deployment on request.
2. **Default dry-run.** Recommend keeping dry-run on until the operator has reviewed a rule's execution history, then flipping it per deployment.
3. **Rule authorship authority.** Should any authenticated operator be able to create a blocking rule, or should destructive rules require circle-owner authority (as VC admin actions do)?
