# AI Alert Recommendation — Complete Development Plan
### Base branch: `feat/62-CRL` · Module: `src/advisory/` · **No new port**

---

## 0. Grounding note + what already exists

Written against the **actual indexed repo state**, not memory.

**The finding: the hard inputs already exist — this is an advisory layer that maps existing signals to human-readable remediation.** Confirmed in the codebase:

| Existing input | Where | What it gives us |
|---|---|---|
| **Anomaly engine** `AnomalyModel::score(fv) -> Score` | `src/anomaly.rs` | `Score { value: f32 (0..1), topk: Vec<(String,f32)>, model_version }` — **`topk` is explainable feature contributions** (e.g. `[("flow_rate",0.42),("cmd_entropy",0.31)]`) |
| **Feature vector** `FeatureVec` / `FeatureTap` | `src/features.rs` | `flow_rate, cmd_entropy, peer_diversity, attest_jitter, modbus_fc_mix` |
| **`forward_to_ai` broadcast tap** | `src/threat/ai_bridge.rs` | non-blocking stream of alerts to the AI layer |
| **`ThreatAlert`** | `src/threat/threat_alert.rs` | `signature, signature_id, category (ThreatCategory), severity, risk_reasons` |
| **Device context** `ConnectedDevice` | `src/discovery/` | per-IP CVEs (from `vulners`), CVSS, `risk_reasons`, flagged ports |
| **Alert inventory** | `/threat/alerts` | where a recommendation is surfaced next to its alert |

So the **"anomaly detection engine integration" already has a defined API** (`Score.topk`), and the alert + device context are live. The only new thing is the **recommendation generator** and its **advisory service**.

**Could not verify:** GitHub live PR/diff (private repo → 404, then rate-limited). Anchors from the project-knowledge index — re-verify against the tip of `feat/62-CRL`. Confirm the exact `forward_to_ai` / anomaly `Score` call sites and visibility before wiring. Confirm whether `src/anomaly.rs` is compiled in the default build or behind a feature flag (an ONNX backend is behind `ai-onnx`; the `EwmaZ` z-score baseline is not).

---

## 1. The one design decision that defines this feature

**"AI-generated" here does NOT mean a runtime cloud LLM.** This is a **zero-trust, offline-capable appliance** — it cannot and must not call an external model at alert time (no cloud dependency, no data egress, works air-gapped). So the recommendation is generated **deterministically, on-device, from real signals**:

- the alert's **signature / category / severity / reasons**,
- the anomaly engine's **explainability** (`Score.topk` — *what* was abnormal),
- the affected device's **CVEs / risk** (from discovery).

These map through a **config-driven knowledge base** to a structured remediation recommendation. This is defensible, offline, reproducible, and — like the Device Scoring rubric — **explainable**: every recommendation traces to the signals that produced it. `RECOMMENDED`.

> Optional, deliberately out of scope for the first cut: a **local** small model or a pre-generated advisory library. Not a cloud LLM. See §12.

**This feature is read-only.** It gives *advice*. It does **not** execute actions (that is the Alert Rules engine, #12) and does **not** change policy (that is Automated Policy Adaptation, Milestone 10). Keeping it read-only is what makes it low-risk.

---

## 2. Architecture

```
   INPUTS (all live)                         GENERATOR (pure, deterministic)          OUTPUT
   ┌──────────────────────────┐        ┌──────────────────────────────────┐
   │ ThreatAlert              │        │ 1. match signature/category to a  │   RemediationRecommendation
   │  (sig, category, sev,    │───────►│    KB entry (recommendation_rules)│──► • attached to the alert
   │   risk_reasons)          │        │ 2. fold in anomaly Score.topk as  │    • /threat/alerts/:id/recommendation
   │ Anomaly Score.topk       │───────►│    "why / what was abnormal"      │    • /advisory/recommendations
   │  (explainable contribs)  │        │ 3. enrich with device CVEs/risk   │    • persisted sidecar (capped ring)
   │ Device CVEs / risk       │───────►│ 4. emit summary + ranked steps +  │
   │  (discovery, per-IP)     │        │    context + references + source  │
   └──────────────────────────┘        └──────────────────────────────────┘
                                        Config-driven KB: recommendation_rules.json
                                        (built-in fallback if no rule matches)
```

Generation runs **off the alert-producing path** (non-blocking, like `forward_to_ai`); the KB mapping is pure CPU; the recommendation is written to an **advisory-owned** store (never the threat inventory writer — no race), and surfaced next to its alert.

---

## 3. Data model

```rust
pub struct RemediationRecommendation {
    pub rec_id: String,              // urn:uuid
    pub alert_id: String,            // links to the ThreatAlert
    pub title: String,               // "Possible C2 beacon on 192.168.50.42"
    pub summary: String,             // plain-language "what this is"
    pub severity: String,            // info|low|medium|high|critical (from the alert)
    pub confidence: f32,             // 0..1 (signature certainty x anomaly score)
    pub steps: Vec<RemediationStep>, // prioritized "what to do"
    pub context: Vec<String>,        // WHY: anomaly top-contributors, CVEs, alert reasons
    pub references: Vec<String>,     // CVE links, signature/rule references
    pub source: String,              // "signature-kb" | "anomaly-kb" | "device-cve" | "fallback"
    pub generated_at: String,
}
pub struct RemediationStep {
    pub order: u8,
    pub action: String,              // e.g. "Isolate the device from the Circle network"
    pub rationale: String,           // why this step, tied to a signal
    pub automatable: bool,           // HINT only: could Alert Rules (#12) do this? (never executed here)
}
```

`context` is the explainability bridge: e.g. `["Anomaly: flow_rate contribution 0.42 (traffic spike)", "Device has CVE-2023-38408 (CVSS 9.8)", "Signature: ET MALWARE C2 checkin"]`. Every recommendation shows its evidence.

**Knowledge base** (`recommendation_rules.json`, config-driven, signed for integrity):

```jsonc
{
  "rules": [
    {
      "match": { "category": "Malware", "severity_at_least": "high" },
      "title": "Suspected malware / command-and-control activity",
      "summary": "A device is communicating in a pattern associated with malware control channels.",
      "steps": [
        { "action": "Isolate the affected device from the Circle network", "rationale": "Contain potential C2", "automatable": true },
        { "action": "Run a full device scan", "rationale": "Identify the malware", "automatable": true },
        { "action": "Rotate credentials that touched this device", "rationale": "Limit blast radius", "automatable": false }
      ],
      "references": ["signature", "cve"]
    }
    // ... reconnaissance, exploit, policy-violation, anomaly-only, etc.
  ],
  "fallback": { "title": "Security alert requires review", "summary": "...", "steps": [ ... ] }
}
```

Config-driven so remediation advice can be **updated without recompiling**; the built-in `fallback` guarantees every alert gets *some* advice.

---

## 4. Deliverables

Each independently reviewable/testable; tree stays green (`cargo build && cargo test && cargo clippy -- -D warnings`); no existing behaviour changes.

| # | Deliverable | Files | Acceptance test |
|---|---|---|---|
| **R1** | **Recommendation model + KB + pure generator** (no network) | `src/advisory/{mod,errors,model,kb,generate}.rs`, `src/lib.rs` | Unit: a fixture `ThreatAlert` → a recommendation via a matched KB rule; **no rule → the `fallback`** (every alert gets advice); generator is **pure** (no I/O, no network); `recommendation_rules.json` loads + signature-verifies (tampered → rejected, falls back to built-in). |
| **R2** | **Anomaly-engine integration (contextual)** | `src/advisory/context.rs` | Unit: given an anomaly `Score { topk }`, the recommendation's `context` includes the **top contributors** as plain-language lines (e.g. `flow_rate 0.42 → traffic spike`); `confidence` combines signature certainty × anomaly score. **This is the "integrating anomaly detection engines" requirement.** |
| **R3** | **Device-context enrichment** | `src/advisory/context.rs` | Board: for an alert whose `src_ip`/`dst_ip` matches a discovered device with CVEs, the recommendation `context` + `references` include the **CVE(s) + CVSS**; missing device → recommendation still generated (context just omits CVEs). |
| **R4** | **Generation on alert + advisory store** | `src/advisory/{mod,store}.rs`, alert/anomaly call site | Board: a High Suricata alert (or anomaly detection) produces a recommendation, stored in an **advisory-owned** `recommendations.jsonl` (capped ring, atomic) — **the threat inventory is untouched** (no race); generation is **non-blocking** (alert loop stays responsive). |
| **R5** | **Advisory REST + FE contract + regression** | `src/api/handlers/advisory.rs`, `routes.rs`, `mod.rs`, `tests/advisory_*.sh` | `GET /threat/alerts/:id/recommendation` returns the advice for one alert; `GET /advisory/recommendations` lists recent; `GET/PUT /advisory/rules` reads/updates the KB (owner). **Deterministic:** same alert twice → identical recommendation. 3-node/board; threat/anomaly/discovery regression green; no watchdog reset. |

**Sequencing:** R1 → R2 → R3 (model + the two context sources — all pure/unit-testable) → R4 (wire + store) → R5 (REST + regression). **Two devs:** Dev A → R1/R2 (generator + anomaly context); Dev B → R3/R4/R5 (device context, wiring, REST).

---

## 5. File structure (all new — strictly additive)

```
src/advisory/
├── mod.rs        # AdvisoryConfig::from_env(), re-exports              [R1/R4]
├── errors.rs     # AdvisoryError                                      [R1]
├── model.rs      # RemediationRecommendation, RemediationStep         [R1]
├── kb.rs         # recommendation_rules.json load + verify + fallback [R1]
├── context.rs    # anomaly topk + device CVE enrichment               [R2/R3]
├── generate.rs   # PURE generate(alert, score, device) -> Recommendation [R1]
├── store.rs      # capped ring + atomic JSONL (advisory-owned)        [R4]
└── tests/mod.rs                                                       [R1/R2]

src/api/handlers/advisory.rs   # per-alert / list / rules             [R5]
```

Storage:
```
/var/lib/sgx-guardian/advisory/
├── recommendations.jsonl   # capped ring of RemediationRecommendation (atomic)
└── recommendation_rules.json   # the knowledge base (config, signed)
```

Env: `SGX_GUARDIAN_ADVISORY_BASE`, `SGX_ADVISORY_MAX_RECS` (ring cap, default 2000). No new port, no `main.rs` spawn required if generation hooks the existing alert/anomaly tap (see §6.3).

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
> ⚠️ Sibling parallel plans append routers here too. Add `advisory_router()` after the last one.

**REPLACE:**
```rust
        .route(
            "/api/v1/crl/gossip/trigger",
            post(handlers::crl::gossip_trigger),
        )
}

pub fn advisory_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/advisory/recommendations", get(handlers::advisory::list))
        .route("/api/v1/threat/alerts/:id/recommendation", get(handlers::advisory::for_alert))
        .route(
            "/api/v1/advisory/rules",
            get(handlers::advisory::get_rules).put(handlers::advisory::put_rules),
        )
}
```
Extend the import if `put` isn't present: `use axum::{routing::{get, post, put}, Router};`

### 6.2 `src/api/mod.rs` — merge (⚠️ verify anchor)
```rust
        .merge(routes::crl_router())
        .merge(routes::advisory_router())   // ← add
```

### 6.3 Generation hook (R4) — beside the existing AI tap (⚠️ verify the call site)

At the alert site where `forward_to_ai` is called (and/or where the anomaly `Score` is produced), add a non-blocking generate+store:

```rust
    crate::threat::ai_bridge::forward_to_ai(node_id, &alert);
    // NEW — generate a remediation recommendation (non-blocking, read-only)
    crate::advisory::generate_for_alert(node_id, &alert);   // pulls anomaly topk + device context, stores it
```

`generate_for_alert` looks up the latest anomaly `Score` and the device for the alert's IP, runs the **pure** generator, and appends to the advisory store. If any input is missing, it still produces a recommendation (fallback + whatever context is available). No blocking, no daemon-lifecycle touch.

---

## 7. Implementation contracts

**Reuse, don't reinvent:**
- **Anomaly `Score.topk`** is the explainability source — do not re-derive feature importance; consume what `src/anomaly.rs` already returns.
- **Device context** via the existing discovery `ConnectedDevice` (CVEs from `vulners`, `risk_reasons`) — same source the Device Scoring plan uses.
- **Store** = capped ring + atomic JSONL, `threat/inventory.rs` pattern, but an **advisory-owned** file (never the threat inventory — avoids the writer race).
- **KB signing/persistence:** `write_atomic`, `sign_in_place_generic`, cached `load_runtime_key_manager(node_id)`; `AuditCategory` (add `Advisory`).

**Async / board-freeze safety:**
- `generate_for_alert` is **non-blocking** and **pure-CPU** (KB mapping over small structs) — safe from the alert loop, like `forward_to_ai`.
- Advisory store append via `tokio::fs` / short atomic write; never hold a lock across `.await`.
- **No network calls, ever** — the whole point (§1). No `reqwest`, no outbound socket at generation time. This is a hard rule (and a test — R5/API 4).
- No `std::thread::sleep`; no synchronous `Command::new().output()` in the runtime.
- Do **not** touch `NebulaDaemon::start()` / `resolve_ca_ip_from_config_inner()`.

**Determinism:** `generate()` is a pure function of `(alert, score, device, kb)` — the same inputs always yield the same recommendation (R5 asserts this). No randomness, no time-varying output except `generated_at`.

---

## 8. Regression checks

```bash
cargo build --release && cargo test && cargo clippy -- -D warnings
cargo build --release --target aarch64-unknown-linux-gnu
cargo test --package sgx-guardian-client threat::      # inventory/blocker untouched
cargo test --package sgx-guardian-client anomaly::     # anomaly engine untouched
cargo test --package sgx-guardian-client discovery::
```

On the boards (binaries direct — **not** `systemctl`/`journalctl`):
```bash
API=http://localhost:8443/api/v1
./sgx_guardian_client nodeA

# Generate an alert, then read its recommendation:
#   (inject an EVE alert or trigger a Suricata rule)
sleep 3
AID=$(curl -s "$API/threat/alerts?limit=1" | python3 -c "import sys,json;print(json.load(sys.stdin)[0]['alert_id'])")
curl -s "$API/threat/alerts/$AID/recommendation" | python3 -m json.tool

# Anomaly context present (topk contributors as plain-language "why"):
curl -s "$API/threat/alerts/$AID/recommendation" | python3 -c "import sys,json;r=json.load(sys.stdin);print('context:',r['context']);print('steps:',[s['action'] for s in r['steps']])"

# Deterministic: same alert twice → identical recommendation (minus timestamp)
curl -s "$API/threat/alerts/$AID/recommendation" | python3 -c "import sys,json;r=json.load(sys.stdin);r.pop('generated_at',None);r.pop('rec_id',None);import hashlib;print(hashlib.sha256(json.dumps(r,sort_keys=True).encode()).hexdigest()[:16])"

# List recent advisories:
curl -s "$API/advisory/recommendations" | python3 -c "import sys,json;print('recommendations:',len(json.load(sys.stdin)))"

# OFFLINE PROOF — no outbound connections during generation:
#   (in another shell before injecting the alert) ss -tnp | grep sgx_guardian ; then inject; then re-check — no new external sockets
ss -tnp 2>/dev/null | grep sgx_guardian_client || echo "no external connections (offline advisory)"

# Threat inventory untouched (no race):
curl -s "$API/threat/alerts" | python3 -c "import sys,json;print('threat alerts:',len(json.load(sys.stdin)))"
pkill -f sgx_guardian_client
```

---

## 9. Step-by-step checklist

**R1 — model + KB + generator**
- [ ] `src/advisory/{mod,errors,model,kb,generate}.rs`; `pub mod advisory;`
- [ ] `RemediationRecommendation` + `RemediationStep`
- [ ] `recommendation_rules.json` load + verify + built-in fallback
- [ ] `generate()` pure; unit: matched rule + fallback + tampered KB rejected

**R2 — anomaly integration**
- [ ] Consume `Score.topk` → plain-language `context` lines
- [ ] `confidence` = signature certainty × anomaly score
- [ ] Unit: top contributors present in context

**R3 — device context**
- [ ] Enrich from discovery `ConnectedDevice` (CVE/CVSS/risk) by alert IP
- [ ] Board: CVE appears in context/references; missing device → still generates

**R4 — generation + store**
- [ ] `generate_for_alert` beside `forward_to_ai` (§6.3), non-blocking
- [ ] Advisory-owned `recommendations.jsonl` (capped ring, atomic); threat inventory untouched
- [ ] Board: High alert → recommendation stored

**R5 — REST + regression**
- [ ] `for_alert` / `list` / `rules` (GET/PUT); routes.rs + mod.rs
- [ ] Deterministic (same alert → same rec); **no outbound network**
- [ ] 3-node; threat/anomaly/discovery green; no watchdog reset

---

## 10. Risks

| Risk | Mitigation |
|---|---|
| **Treating "AI" as a cloud LLM** → breaks offline/zero-trust + leaks data | Deterministic on-device KB generation; **no network at generation time** (hard rule + test) (§1) |
| **Advisory misread as an action** (executes something) | Read-only by design; `automatable` is a *hint*, never executed here; execution is Alert Rules (#12) |
| **Confused with Policy Adaptation** (changes policy) | This produces advice only; policy changes are Milestone 10 |
| **Racing the threat inventory writer** | Advisory-owned store; never writes the threat inventory |
| **Blocking the alert loop** | `generate_for_alert` non-blocking + pure CPU, like `forward_to_ai` |
| **Stale/unhelpful advice** | Config-driven KB updatable without recompile; fallback guarantees coverage; context shows evidence |
| **Anomaly engine behind a feature flag / not compiled** | Degrade gracefully — if no `Score` is available, generate from signature + device context only |
| Branch drift | Re-verify anchors; confirm anomaly `Score` + `forward_to_ai` call sites |

---

## 11. Decisions for Cervais / FE

1. **Confirm "AI-generated" = on-device deterministic advisory** (recommended), not a runtime cloud model — this is the only option compatible with offline/zero-trust operation.
2. **Knowledge-base ownership.** The remediation content (per category/signature) should be reviewed and signed off — it is operator-facing advice. Recommend curating it with the Cervais security team.
3. **Where the FE shows it** — inline under each alert (recommended) and/or a dedicated advisory list.

## 12. Out of scope (flag)

- **Runtime cloud LLM** — incompatible with the appliance's offline/zero-trust design.
- **A local small model / pre-generated advisory library** — a possible future enhancement *behind a feature flag* (like the existing `ai-onnx` anomaly backend); the deterministic KB ships first.
- **Executing remediation** — that is the Alert Rules engine (#12); this feature only advises.
- **Changing policy from a recommendation** — that is Automated Policy Adaptation (Milestone 10).
- **Attack-timeline correlation across members** — that is a separate Milestone 12 forensics deliverable.
