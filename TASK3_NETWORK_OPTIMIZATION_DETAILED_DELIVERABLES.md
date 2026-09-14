# Task 3 AI Network Optimization - Detailed Deliverables and Implementation Flow

## Purpose

Task 3 ka objective AI-based route optimizer banana hai jo Guardian network traffic ke liye best eligible route choose kare.

Ye optimizer sirf ek fixed demo ya sirf telemetry ke liye nahi hoga. Senior clarification ke according Task 3 ko dono traffic types support karne hain:

1. Normal operational traffic
2. High-priority security/control traffic

Important rule:

```text
Trust / eligibility filtering first.
AI route optimization second.
```

Yani AI low-latency route choose kar sakta hai, lekin agar route untrusted, quarantined, prohibited, ya policy ke against hai to woh route candidate list me hi nahi jana chahiye.

---

## Final Scope Confirmed by Senior

Task 3 route optimizer in traffic classes ke liye kaam karega.

### High Priority - Security / Control Traffic

Used for:

- `VSHIFT_ALERT`
- signed policy delivery
- policy verification messages
- attestation challenge/response
- revocation / CRL messages
- trust-state updates
- Virtual Shift control messages

Security/control traffic ke liye route choose karne se pehle latest trust state read hogi. Fastest route ka matlab trusted route nahi hota. Isliye untrusted route kabhi auto-select nahi hoga.

### Normal Priority - Operational Traffic

Used for:

- Guardian telemetry
- heartbeat messages
- runtime metrics
- health/status updates
- network statistics
- normal operational data

Normal traffic ke routes latency, packet loss, bandwidth utilization, throughput, relay hops, aur route availability ke basis par optimize honge.

---

## Task 1 and Task 2 Link

### Local Implementation Progress

```text
Done locally:
- D1 network telemetry schema + Task1-compatible metric adapter
- D2 route candidate inventory + trust eligibility filter
- D3 route history store
- D4 route quality predictor
- D5 degradation predictor
- D6 reward + contextual bandit/RL policy
- D7 safety guard + hysteresis/cooldown + safe switch result
- D8 multi-relay load balancing
- D9 first Task1/Task2 integration bridge:
  Task1 recommendation JSON is read as a route-risk signal.
  Task2 routing trust summary JSON is read before AI route scoring.
  Integration audit is saved read-only without mutating Task1/Task2 state.

Not pushed yet: Task3 stays local until full Task3 completion.
```

### Task 1 Role

Task 1 anomaly engine abnormal behavior detect karta hai.

Task 3 Task 1 se ye cheezein reuse karega:

- live/runtime network metrics
- anomaly score
- anomaly confidence
- contributing features
- node-level model metadata
- baseline/per-node scoring context
- network-related fields like `conn_rate`, `relay_ratio`, `nebula_mbps`, latency-related metrics

Task 3 ka kaam anomaly detect karna nahi hai. Task 3 ka kaam route optimize karna hai.

### Task 2 Role

Task 2 Virtual Shift policy lifecycle sensitive policy/control actions ko safely handle karta hai.

Task 3 Task 2 se ye consume karega:

- latest active policy
- latest trust/eligibility state
- applied/quarantined route/member state
- policy verification result
- attestation/trust result
- routing trust summary

Task 3 trust state khud modify nahi karega.

Task 2 policy apply hone ke baad trust state update karega. Task 3 next decision cycle me latest state read karega aur uske according eligible route choose karega.

---

## High-Level Runtime Flow

```text
Incoming Guardian message
        |
        v
Traffic classification
        |
        v
Priority assignment
        |
        v
Latest Task 2 trust / policy state read
        |
        v
Remove untrusted / quarantined / prohibited routes
        |
        v
Eligible route candidates
        |
        v
Task 1 anomaly/risk enrichment
        |
        v
AI route prediction and degradation scoring
        |
        v
RL / reward-aware route decision
        |
        v
Safety guard / hysteresis / cooldown
        |
        +-----------------------------+
        |                             |
        v                             v
Safe existing route apply       Sensitive policy change
        |                             |
        v                             v
Runtime route controller        Task 2 Virtual Shift lifecycle
        |
        v
Persist decision, reason, confidence, reward, and outcome
```

---

## Core Implementation Rule

Task 3 must be flexible.

Do not hardcode it for only one traffic type or one route type.

The route decision input should include:

```text
source_node
destination_node
traffic_class
priority
required_trust_level
current_route
candidate_routes
latency / RTT
packet_loss
throughput
bandwidth_utilization
relay_hops
route_health
Task 1 anomaly/risk signal
latest Task 2 trust eligibility
```

---

# Deliverables

## Deliverable 1 - Network Telemetry Schema and Shared Adapter

### Goal

Task 3 ke liye clean network observation schema banana hai jo existing Guardian/Task1 metrics ko reuse kare.

### Work

- RTT / latency collect karna
- packet loss collect karna
- bandwidth utilization collect karna
- throughput collect karna
- relay hop count collect karna
- current route identify karna
- route availability identify karna
- Task1-compatible metrics reuse karna
- timestamped observation persist karna

### Files

```text
crates/sgx-network-optimizer/src/metrics.rs
crates/sgx-network-optimizer/src/features.rs
src/network_ai/telemetry_adapter.rs
```

### Acceptance

- real/synthetic observation object create ho
- observation me route ID ho
- peer/source/destination info ho
- traffic class included ho
- no live attestation dependency in telemetry adapter
- observation JSON/log persist ho

---

## Deliverable 2 - Traffic Classification and Priority Classes

### Goal

Senior clarification ke according normal aur security/control traffic separate priority classes me handle karna.

### Work

- `TrafficClass` enum banana
- `PriorityClass` enum banana
- normal operational traffic identify karna
- security/control traffic identify karna
- message type ke basis par class assign karna
- policy/control messages ko high priority dena

### Suggested Classes

```text
SecurityControl
Operational
Heartbeat
Telemetry
Attestation
PolicyControl
SecurityAlert
BulkSync
```

### Acceptance

- `VSHIFT_ALERT` high priority classify ho
- attestation high priority classify ho
- telemetry normal priority classify ho
- heartbeat normal priority classify ho
- unknown traffic safe default me jaye
- classification output route decision me visible ho

---

## Deliverable 3 - Route Candidate Inventory

### Goal

System ko available route options ka deterministic inventory dena.

### Work

- direct P2P candidate build karna
- relay route candidate build karna
- multi-hop relay route candidate build karna
- deterministic route IDs generate karna
- candidate route health attach karna
- candidate trust fields attach karna

### Files

```text
crates/sgx-network-optimizer/src/candidates.rs
src/network_ai/route_adapter.rs
```

### Acceptance

- direct route candidate visible ho
- relay route candidate visible ho
- multi-hop route candidate visible ho
- route IDs repeatable hon
- route candidate me hop count ho
- route candidate me current health/trust metadata ho

---

## Deliverable 4 - Trust Eligibility Filter

### Goal

AI optimizer ko sirf trusted/eligible route candidates milen.

### Work

- latest Task2 trust state read karna
- active policy state read karna
- quarantined/untrusted routes remove karna
- prohibited route remove karna
- stale trust state detect karna
- eligible candidate list produce karna

### Files

```text
crates/sgx-network-optimizer/src/eligibility.rs
src/network_ai/virtual_shift_bridge.rs
```

### Acceptance

- trust filtering AI scoring se pehle run ho
- untrusted route AI selected route nahi ban sake
- quarantined relay candidate list se remove ho
- missing/stale state safe fallback trigger kare
- decision record me eligibility reason saved ho

---

## Deliverable 5 - Historical Route Performance Store

### Goal

Route performance history persist karni hai taake model past behavior se better decision le.

### Work

- per-route history store
- EWMA latency
- EWMA packet loss
- EWMA throughput
- route failure count
- route success rate
- route switch count
- bounded retention
- restart-safe state

### Files

```text
crates/sgx-network-optimizer/src/history.rs
crates/sgx-network-optimizer/src/persistence.rs
```

### Acceptance

- history restart ke baad load ho
- per-route stats available hon
- old entries retention policy ke according trim hon
- decision ke baad observed outcome history me save ho

---

## Deliverable 6 - Feature Builder

### Goal

Route prediction ke liye stable feature vector banana.

### Work

- current route metrics normalize karna
- historical stats include karna
- traffic priority encode karna
- Task1 anomaly score include karna
- route age include karna
- route failure/success rate include karna
- feature schema version define karna

### Suggested Feature Schema

```text
network-ai-v1
```

### Acceptance

- feature vector stable ho
- version persisted ho
- top contributors/reasons explainable hon
- missing values safe defaults se handle hon

---

## Deliverable 7 - Route Quality Prediction Model

### Goal

Eligible candidates me best quality route predict karna.

### Work

- expected latency predict karna
- expected packet loss predict karna
- expected throughput predict karna
- route quality score calculate karna
- confidence calculate karna
- model metadata persist karna

### Files

```text
crates/sgx-network-optimizer/src/predictor.rs
crates/sgx-network-optimizer/tests/predictor_test.rs
```

### Acceptance

- same input par deterministic prediction ho
- all eligible candidates score hon
- output me latency/loss/throughput/confidence ho
- opaque score ke sath component breakdown bhi save ho
- heuristic ko false ML claim na kiya jaye

---

## Deliverable 8 - Degradation Predictor

### Goal

Current route kharab hone se pehle risk predict karna.

### Work

- rising RTT trend detect karna
- rising loss detect karna
- falling throughput detect karna
- high relay utilization detect karna
- repeated failure pattern detect karna
- degradation probability emit karna
- contributors save karna

### Files

```text
crates/sgx-network-optimizer/src/degradation.rs
crates/sgx-network-optimizer/tests/degradation_test.rs
```

### Acceptance

- probability output ho
- reason/contributors output hon
- synthetic test me hard failure se pehle warning aaye
- decision JSON me degradation info saved ho

---

## Deliverable 9 - Reinforcement Learning / Contextual Bandit Policy

### Goal

Route decisions ko observed outcome se improve karna.

### V1 Approach

Contextual bandit / Q-value policy use karna.

Neural DQN abhi required nahi. V1 lightweight, deterministic, edge-friendly aur auditable hona chahiye.

### Work

- discrete route actions define karna
- reward function build karna
- reward components persist karna
- exploration bounded rakhna
- policy state save/load karna
- reproducible exploitation decisions support karna

### Files

```text
crates/sgx-network-optimizer/src/reward.rs
crates/sgx-network-optimizer/src/rl.rs
crates/sgx-network-optimizer/tests/rl_policy_test.rs
```

### Acceptance

- low latency reward ho
- high throughput reward ho
- packet loss penalty ho
- congestion penalty ho
- route switching penalty ho
- failure penalty ho
- saved policy restart ke baad same decision de

---

## Deliverable 10 - Safety Guard, Hysteresis, and Cooldown

### Goal

Route flapping aur unsafe switching prevent karna.

### Work

- minimum improvement threshold
- minimum hold time
- switch cooldown
- max switches per window
- immediate failover only for hard failure
- rollback/fallback if route apply fails

### Files

```text
crates/sgx-network-optimizer/src/safety.rs
crates/sgx-network-optimizer/src/decision.rs
```

### Acceptance

- AI cannot switch on tiny improvement
- cooldown enforce ho
- no route flapping in stability test
- failed apply rollback/fallback kare
- safety result decision JSON me visible ho

---

## Deliverable 11 - Safe Runtime Route Controller

### Goal

Already trusted/allowed route changes ko guarded runtime controller se apply karna.

### Work

- direct P2P to relay switch
- relay to direct switch
- relay A to relay B switch
- current route state update
- apply result persist
- actual outcome observe karna

### Files

```text
src/network_ai/route_adapter.rs
crates/sgx-network-optimizer/src/engine.rs
```

### Acceptance

- safe route change owner approval ke bina apply ho sakta hai
- only already eligible route apply ho
- apply result saved ho
- route transition audit record saved ho
- observed outcome reward system ko feed ho

---

## Deliverable 12 - Sensitive Route / Policy Handoff to Task 2

### Goal

Agar route change security/policy-sensitive ho to Task3 direct apply na kare. Task2 lifecycle me handoff kare.

### Sensitive Cases

- new untrusted relay
- policy rule change needed
- cross-boundary route
- quarantined member recovery
- route requires security exception
- trust-state mutation needed

### Files

```text
src/network_ai/virtual_shift_bridge.rs
src/network_ai/audit.rs
```

### Acceptance

- sensitive route action Task2 recommendation/policy handoff me jaye
- AI justification preserved ho
- owner/admin approval required ho
- direct apply blocked ho
- Task2 audit chain linked ho

---

## Deliverable 13 - Multi-Relay Load Balancing

### Goal

Multiple healthy relays ke beech traffic weights decide karna.

### Work

- multiple relay candidates rank karna
- route quality se weights calculate karna
- weights normalize karna
- overloaded route ka weight reduce karna
- failed relay remove karna
- recovered relay ko gradually weight wapas dena

### Files

```text
crates/sgx-network-optimizer/src/load_balancer.rs
```

### Acceptance

- relay weights sum stable hon
- high priority traffic best trusted route prefer kare
- overloaded/failed relay down-weight/remove ho
- recovery ke baad route eligible ho sakta hai

---

## Deliverable 14 - Decision Persistence and Audit Evidence

### Goal

Har AI decision explainable aur auditable ho.

### Work

- decision JSON persist karna
- route history JSONL persist karna
- reward JSONL persist karna
- degradation events persist karna
- model metadata persist karna
- confidence/reason save karna
- selected vs rejected candidates save karna

### State Layout

```text
data/network_ai/
  runtime.json
  current_decision.json
  route_history.jsonl
  decisions.jsonl
  rewards.jsonl
  degradation_events.jsonl
  benchmark.json
  models/
    route_predictor.json
    degradation_model.json
    rl_policy.json
```

### Acceptance

- latest decision easy to inspect ho
- decision me selected route aur reason ho
- rejected candidates ke reasons ho
- reward/outcome linked ho
- Task1/Task2 trace IDs saved hon

---

## Deliverable 15 - Runtime Modes

### Goal

Task3 ko safe rollout modes me chalana.

### Modes

```text
Shadow   = observe + predict only
Advisory = recommend route, no apply
Active   = safe eligible route apply with guard
```

### Acceptance

- [x] default mode shadow ho
- [x] runtime `--mode shadow|advisory|active` se mode change ho
- [x] active mode existing D10/D11 safety path ke bina apply na kare
- [x] terminal aur `runtime_mode_decision.json` me current mode visible ho
- [x] shadow/advisory route change apply na kare

---

## Deliverable 16 - Configurable Admin Settings

### Goal

Thresholds, weights, cooldowns, aur mode hardcoded na hon.

### Config File

```text
config/network_ai.example.json
```

### Configurable Values

- enabled/disabled
- mode
- sample interval
- history window
- min improvement percent
- switch cooldown
- min route hold seconds
- max switches per window
- degradation probability threshold
- RL epsilon
- learning rate
- reward weights

### Acceptance

- [x] `config/network_ai.example.json` load ho
- [x] invalid config safe error de
- [x] config version visible ho
- [x] effective admin values runtime evidence me traceable hon

---

## Deliverable 17 - Production Runtime Integration

### Goal

Optimizer Guardian runtime ke sath integrate ho.

### Work

- [x] Guardian-facing runtime module add karna
- [x] configured periodic bounded engine ticks
- [x] current mode decision/runtime state update
- [x] start/stop support + restart-safe `runtime.json`
- no secret leakage
- restart-safe load

### Files

```text
src/network_ai/mod.rs
src/network_ai/runtime.rs
src/main.rs
```

### Acceptance

- runtime start ho
- restart ke baad state load ho
- mode visible ho
- runtime Task1/Task2 ko break na kare

---

## Deliverable 18 - Client-Facing API

### Goal

Admin/client route optimizer state inspect kar sake.

### APIs

```text
GET /api/v1/network-ai/status
GET /api/v1/network-ai/candidates
GET /api/v1/network-ai/decision/current
GET /api/v1/network-ai/history
GET /api/v1/network-ai/rewards
POST /api/v1/network-ai/mode
```

### Files

```text
src/api/handlers/network_ai.rs
src/api/routes.rs
```

### Acceptance

- [x] authenticated endpoints hon
- [x] status me mode/model/version ho
- [x] candidates me eligibility reason ho
- [x] decision endpoint me selected route + reason ho
- [x] no secret/model key leakage ho

---

## Deliverable 19 - Task 1 Bridge

### Goal

Task1 anomaly/risk output ko Task3 route optimization me safely use karna.

### Work

- Task1 recommendation/anomaly signal read karna
- anomaly score as feature use karna
- model metadata preserve karna
- Task1 source record link karna

### Files

```text
src/network_ai/task1_bridge.rs
```

### Acceptance

- [x] Task1 signal optional ho
- [x] missing/malformed Task1 signal route optimizer ko crash na kare
- [x] Task1 metadata/run/recommendation trace decision audit me ho
- [x] Task3 anomaly engine ka duplicate version na banaye

---

## Deliverable 20 - Task 2 Trust/Policy Bridge

### Goal

Task2 ke latest trust/policy state se route eligibility decide karna.

### Work

- active policy read karna
- latest apply result read karna
- attestation/trust result read karna
- routing trust summary read karna
- quarantined/untrusted state use karna
- security-sensitive action Task2 lifecycle me bhejna

### Files

```text
src/network_ai/virtual_shift_bridge.rs
```

### Acceptance

- [x] Task3 trust state modify na kare
- [x] latest authoritative routing summary, active-policy/apply/identity source traces consume kare
- [x] stale/missing/malformed state safe fallback kare
- [x] sensitive-route Task2 handoff reason saved ho (existing D12 handoff service)

---

## Deliverable 21 - Demo 1: Shadow Route Decision

### Goal

First demo me AI route choose kare but apply na kare.

### Output

- traffic class
- priority
- latest trust state used
- eligible candidates
- rejected candidates with reason
- predicted latency/loss/throughput
- degradation probability
- selected best eligible route
- shadow mode: no apply
- JSON evidence saved

### Acceptance

- [x] terminal readable table ho
- [x] `shadow_route_decision.json` simple ho
- [x] senior ko selected route, metrics, confidence, rejection aur reason samajh aaye

---

## Deliverable 22 - Demo 2: Advisory Route Recommendation

### Goal

AI recommendation generate kare, but route apply na ho.

### Output

- recommended route
- expected improvement
- confidence
- reason
- safety guard result
- operator next step

### Acceptance

- [x] advisory decision saved ho
- [x] no active route change
- [x] operator/admin ko route, improvement, confidence aur read-only safety verdict clear mile

---

## Deliverable 23 - Demo 3: Active Safe Route Switch

### Goal

Already trusted/eligible route pe safe switch apply karna.

### Output

- old route
- selected route
- improvement percent
- safety guard PASS
- apply result
- fallback/rollback readiness
- observed outcome
- reward calculation

### Acceptance

- direct to relay switch demo
- relay to relay switch demo
- active policy/trust restriction respected ho
- route history updated ho

---

## Deliverable 24 - Demo 4: Task2 Handoff for Sensitive Route Change

### Goal

Sensitive route/policy change direct apply na ho, Task2 Virtual Shift lifecycle me jaye.

### Output

- reason direct apply blocked
- Task2 handoff created
- owner/admin review required
- linked recommendation/policy ID

### Acceptance

- unsafe/new route direct apply nahi hota
- Task2 flow reuse hota hai
- audit chain linked hoti hai

---

## Deliverable 25 - Demo 5: Static vs AI Benchmark

### Goal

Static routing baseline aur AI routing result compare karna.

### Work

- same topology
- same workload
- static routing run
- AI routing run
- avg/p50/p95/p99 latency compare
- packet loss compare
- throughput compare
- route switch count compare
- benchmark JSON save

### Acceptance

- benchmark repeatable ho
- 20-40% latency target measured ho
- PASS/FAIL honestly reported ho
- unit test se performance claim na kiya jaye

---

# Suggested Patch Order

Implementation ko is order me karna best hai:

```text
1. Create sgx-network-optimizer crate/module
2. Add core types and config
3. Add traffic class + priority classification
4. Add telemetry observation schema
5. Add feature builder
6. Add route candidate inventory
7. Add Task2 trust eligibility filter
8. Add route history persistence
9. Add route quality predictor
10. Add degradation predictor
11. Add reward function
12. Add contextual bandit / RL policy
13. Add safety guard and hysteresis
14. Add route decision engine
15. Add safe route controller
16. Add multi-relay load balancer
17. Add Task1 bridge
18. Add Task2 Virtual Shift bridge
19. Add audit persistence
20. Add runtime modes
21. Add client-facing APIs
22. Add shadow demo
23. Add advisory demo
24. Add active route switch demo
25. Add Task2 handoff demo
26. Add static vs AI benchmark
27. Run tests and verification
```

---

# Definition of Done

Task3 complete tab hoga jab ye sab prove ho:

- [ ] normal operational traffic classify hota hai
- [ ] security/control traffic high priority classify hota hai
- [ ] latest Task2 trust state read hoti hai
- [ ] untrusted/quarantined routes AI candidate list se pehle remove hote hain
- [ ] direct P2P route candidate available hota hai
- [ ] relay route candidate available hota hai
- [ ] multi-hop relay candidate available hota hai
- [ ] Task1 anomaly/risk signal route feature me use hota hai
- [ ] predictor latency/loss/throughput/confidence emit karta hai
- [ ] degradation predictor probability + contributors emit karta hai
- [ ] RL reward persist hota hai
- [ ] policy state restart ke baad survive karti hai
- [ ] safety guard route apply se pehle run hota hai
- [ ] hysteresis/cooldown route flapping prevent karta hai
- [ ] safe route switch apply hota hai
- [ ] sensitive route/policy change Task2 lifecycle me jata hai
- [ ] decision JSON me reason/confidence/selected route/rejected route saved hota hai
- [ ] runtime shadow/advisory/active modes support karta hai
- [ ] API current status/candidates/decision/history/reward expose karti hai
- [ ] static vs AI benchmark repeatable hai
- [ ] 20-40% latency improvement only measured evidence se claim hota hai
- [ ] Task1 and Task2 verified flows break nahi hote

---

# What We Will Tell Senior

```text
Task3 will be implemented as a flexible traffic-class based AI route optimizer. It will support both normal operational traffic and high-priority security/control traffic. Every routing decision will first read the latest Task2 trust/policy state and remove untrusted or quarantined routes before AI scoring. The AI will then rank only eligible routes using latency, packet loss, throughput, bandwidth utilization, relay hops, route health, traffic priority, historical performance, and Task1 anomaly/risk signals. Safe existing-route changes can be applied through a guarded runtime controller, while security/policy-sensitive changes will be handed to the Task2 Virtual Shift lifecycle for owner/admin approval. All predictions, decisions, reasons, confidence, rewards, transitions, and benchmark results will be persisted for audit.
```
