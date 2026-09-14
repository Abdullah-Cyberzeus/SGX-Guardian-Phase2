# AI Network Optimization — Implementation Deliverable


## 1. Objective

Implement an AI-driven routing optimizer that continuously evaluates real network conditions and selects the best available route for each peer/traffic class.

The module must monitor:

- Peer latency / RTT
- Packet loss
- Bandwidth utilization / throughput
- Relay hop count
- Direct P2P availability
- Relay path health
- Connection growth / congestion indicators
- Existing Task 1 anomaly signals
- Historical performance of each route

The optimizer will:

1. Predict the expected quality of available routes.
2. Select between direct P2P and relay paths.
3. Balance high-priority traffic across healthy relay paths.
4. Predict likely degradation before the current route becomes unusable.
5. Use reinforcement learning to improve route selection from observed outcomes.
6. Apply route changes through a guarded runtime controller.
7. Persist every AI decision, reason, confidence, reward, and route transition.
8. Benchmark against the existing static-routing baseline.

**Performance target:** demonstrate a measurable reduction in average latency against static routing, with **20–40% latency reduction as the project target**, not as a guaranteed result. Final acceptance must be based on repeatable benchmark evidence.

---

# 2. Link With Previous AI Tasks

## Task 1 → AI Anomaly Engine

Task 1 already provides the foundation for network-aware AI:

- Full ML runtime
- Tier-1 baseline + Tier-2 Isolation Forest
- Per-node model selection
- Live telemetry ingestion
- Network-related contributors such as:
  - `conn_rate`
  - `relay_ratio`
  - `nebula_mbps`
  - latency-related metrics
- Structured score, confidence, evidence, and model metadata
- Runtime APIs and persisted AI records

### Reuse in Task 3

Task 3 must **not create a second competing telemetry stack**.

Instead, the network optimizer will consume shared/raw runtime metrics through a dedicated adapter and may also consume Task 1 anomaly/degradation signals.

Flow:

```text
Existing Guardian Metrics
        |
        +--------------------+
        |                    |
        v                    v
Task 1 Anomaly Engine   Task 3 Network Optimizer
        |                    |
 anomaly/risk signal         |
        +-----------> feature enrichment
                             |
                             v
                    AI Route Decision
```

Task 1 remains responsible for **detecting abnormal behavior**.

Task 3 becomes responsible for **choosing a better network route**.

---

## Task 2 → Virtual Shift / Controlled AI Action Lifecycle

Task 2 already provides:

- AI recommendation persistence
- Human review for sensitive actions
- Signed lifecycle artifacts
- Gossip / member verification
- Atomic apply / rollback
- Virtual ID rotation
- Re-attestation lifecycle
- Audit trails
- False-positive override
- Final lifecycle verification

### Reuse in Task 3

Normal route optimization must remain fast and should not require a full owner approval for every transient route change.

Therefore Task 3 uses two action classes:

### Class A — Safe Runtime Route Optimization

Examples:

- direct P2P → existing trusted relay
- relay A → relay B
- weighted load balancing between already eligible relays

These can be applied automatically when:

- route is already known/allowed,
- peer/relay is eligible,
- safety guard passes,
- hysteresis/cooldown allows switching.

Every action is still persisted to the AI audit log.

### Class B — Security/Policy-Sensitive Change

Examples:

- route requires a new policy rule,
- new untrusted relay,
- cross-boundary routing,
- security policy mutation.

These must be handed to the existing Task 2 controlled lifecycle instead of being applied directly.

```text
Task 3 route decision
        |
        +---- safe existing route ----> guarded runtime apply
        |
        +---- policy/security change -> Task 2 Virtual Shift lifecycle
```

---

# 3. Attestation Dependency

The AI prediction engine itself must **not depend on live attestation**.

This keeps AI verification possible even when attestation services are temporarily unavailable.

Routing has a separate eligibility layer:

```text
AI scoring
    |
    v
Candidate route ranking
    |
    v
Eligibility / trust filter
    |
    v
Safe route apply
```

Rules:

- AI model can score all observed candidates.
- Automatic application can only use routes allowed by the current trust/eligibility state.
- If attestation is temporarily unavailable, existing established/approved routes may continue according to current Guardian policy.
- A new untrusted route must never be silently activated by the AI.
- Tests for prediction, RL reward, degradation detection, and route ranking can run independently of attestation.
- Full security-sensitive E2E tests may include attestation once the existing service is available.

---

# 4. Proposed Architecture

```text
                         +----------------------+
                         | Existing SG-X Metrics|
                         +----------+-----------+
                                    |
                                    v
                         +----------------------+
                         | Telemetry Adapter    |
                         +----------+-----------+
                                    |
                   +----------------+----------------+
                   |                                 |
                   v                                 v
        +----------------------+        +----------------------+
        | Historical Store     |        | Task 1 Risk Adapter  |
        +----------+-----------+        +----------+-----------+
                   |                               |
                   +---------------+---------------+
                                   |
                                   v
                         +----------------------+
                         | Feature Builder      |
                         +----------+-----------+
                                    |
                +-------------------+-------------------+
                |                                       |
                v                                       v
     +----------------------+              +----------------------+
     | Route Quality Model  |              | Degradation Model    |
     +----------+-----------+              +----------+-----------+
                |                                       |
                +-------------------+-------------------+
                                    |
                                    v
                         +----------------------+
                         | RL Policy Engine     |
                         +----------+-----------+
                                    |
                                    v
                         +----------------------+
                         | Safety Guard         |
                         +----------+-----------+
                                    |
                                    v
                         +----------------------+
                         | Route Controller     |
                         +----------+-----------+
                                    |
             +----------------------+----------------------+
             |                                             |
             v                                             v
   Direct P2P / Relay Apply                    Task 2 Virtual Shift
                                                when required
```

---

# 5. Proposed Repository Structure

The core AI logic should live in a new crate so that it remains testable without launching the full Guardian daemon.

```text
SGX/
├── crates/
│   ├── sgx-anomaly-engine/
│   │   └── ... existing Task 1 / Task 2 AI code
│   │
│   └── sgx-network-optimizer/
│       ├── Cargo.toml
│       ├── src/
│       │   ├── lib.rs
│       │   ├── config.rs
│       │   ├── types.rs
│       │   ├── metrics.rs
│       │   ├── features.rs
│       │   ├── history.rs
│       │   ├── candidates.rs
│       │   ├── eligibility.rs
│       │   ├── predictor.rs
│       │   ├── degradation.rs
│       │   ├── reward.rs
│       │   ├── rl.rs
│       │   ├── decision.rs
│       │   ├── load_balancer.rs
│       │   ├── safety.rs
│       │   ├── engine.rs
│       │   └── persistence.rs
│       └── tests/
│           ├── predictor_test.rs
│           ├── degradation_test.rs
│           ├── rl_policy_test.rs
│           ├── safety_test.rs
│           └── optimizer_e2e.rs
│
├── src/
│   ├── network_ai/
│   │   ├── mod.rs
│   │   ├── runtime.rs
│   │   ├── telemetry_adapter.rs
│   │   ├── task1_bridge.rs
│   │   ├── route_adapter.rs
│   │   ├── virtual_shift_bridge.rs
│   │   └── audit.rs
│   │
│   ├── api/
│   │   ├── handlers/
│   │   │   └── network_ai.rs
│   │   └── routes.rs                 # existing file: add Task 3 routes
│   │
│   ├── main.rs                       # existing file: spawn Task 3 runtime
│   └── lib.rs                        # export network_ai module if required
│
├── config/
│   └── network_ai.example.json
│
└── docs/
    └── ai-network-optimization.md
```

> The exact adapter calls into the existing Nebula/relay implementation should be bound to the current repository functions during the patch phase. The AI crate itself should stay independent of those implementation details.

---

# 6. Runtime State Layout

Use a separate state root:

```text
/var/lib/sgx-guardian/network-ai/
├── runtime.json
├── current_decision.json
├── route_history.jsonl
├── decisions.jsonl
├── rewards.jsonl
├── degradation_events.jsonl
├── benchmark.json
└── models/
    ├── route_predictor.json
    ├── degradation_model.json
    └── rl_policy.json
```

Configuration:

```text
/etc/sgx-guardian/network-ai/config.json
```

---

# 7. Core Data Structures

## 7.1 Route Candidate

**File:** `crates/sgx-network-optimizer/src/types.rs`

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum RouteKind {
    DirectP2p,
    Relay,
    MultiHopRelay,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RouteCandidate {
    pub route_id: String,
    pub peer_id: String,
    pub kind: RouteKind,
    pub relay_ids: Vec<String>,
    pub hop_count: u8,
    pub trusted: bool,
}
```

---

## 7.2 Network Observation

**File:** `crates/sgx-network-optimizer/src/metrics.rs`

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkObservation {
    pub ts_ms: u64,
    pub peer_id: String,
    pub route_id: String,

    pub rtt_ms: f64,
    pub packet_loss_pct: f64,
    pub throughput_mbps: f64,
    pub bandwidth_utilization_pct: f64,
    pub relay_hops: u8,

    pub conn_rate: f64,
    pub relay_ratio: f64,
    pub anomaly_score: Option<f64>,
}
```

---

## 7.3 Route Prediction

**File:** `crates/sgx-network-optimizer/src/predictor.rs`

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RoutePrediction {
    pub route_id: String,
    pub expected_latency_ms: f64,
    pub expected_loss_pct: f64,
    pub expected_throughput_mbps: f64,
    pub degradation_probability: f64,
    pub confidence: f64,
}
```

---

## 7.4 AI Decision

**File:** `crates/sgx-network-optimizer/src/decision.rs`

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RouteDecision {
    pub decision_id: String,
    pub ts_ms: u64,
    pub peer_id: String,

    pub previous_route: Option<String>,
    pub selected_route: String,

    pub predicted_latency_ms: f64,
    pub predicted_loss_pct: f64,
    pub predicted_throughput_mbps: f64,

    pub model_confidence: f64,
    pub degradation_probability: f64,

    pub reason: String,
    pub mode: DecisionMode,
}
```

Modes:

```rust
pub enum DecisionMode {
    Shadow,
    Advisory,
    Active,
}
```

---

# 8. Feature Vector

The model should build route-specific feature vectors from current and historical data.

Suggested features:

```text
1. current_rtt_ms
2. rtt_ewma_30s
3. rtt_p95_5m
4. packet_loss_pct
5. loss_ewma_30s
6. throughput_mbps
7. throughput_ewma_30s
8. bandwidth_utilization_pct
9. relay_hop_count
10. relay_load
11. route_switches_5m
12. route_failure_rate
13. connection_rate
14. relay_ratio
15. Task1 anomaly_score
16. degradation_trend
17. historical_route_success_rate
18. traffic_priority
19. route_age_seconds
```

The first implementation should keep the vector stable and version it.

Example:

```rust
pub const NETWORK_FEATURE_SCHEMA_VERSION: &str = "network-ai-v1";
```

---

# 9. Prediction Model

## Goal

Estimate expected quality for every eligible candidate route.

A candidate quality score can combine:

- expected latency
- expected packet loss
- expected throughput
- degradation risk

Conceptually:

```text
higher score = better route

route_score =
    latency_component
  + throughput_component
  - loss_penalty
  - congestion_penalty
  - hop_penalty
  - degradation_penalty
```

The implementation should persist all component values rather than exposing only one opaque score.

## Recommended V1

Use an interpretable lightweight predictor first:

- exponentially weighted historical statistics,
- normalized feature scoring,
- optional trained regression model loaded from JSON.

This provides deterministic behavior and easy Rust deployment.

A learned model can later replace the predictor behind the same trait.

```rust
pub trait RoutePredictor: Send + Sync {
    fn predict(
        &self,
        candidate: &RouteCandidate,
        features: &RouteFeatures,
    ) -> anyhow::Result<RoutePrediction>;
}
```

---

# 10. Network Degradation Prediction

**File:** `crates/sgx-network-optimizer/src/degradation.rs`

The degradation model predicts whether the current route is likely to worsen before a hard failure.

Inputs include:

- rising RTT trend,
- packet loss trend,
- falling throughput,
- increasing relay utilization,
- repeated route failures,
- Task 1 anomaly score,
- environment-specific metrics if available.

The core model must remain generic.

Satellite-weather or cellular-specific signals should be added only when those telemetry sources actually exist.

```rust
pub struct DegradationPrediction {
    pub probability: f64,
    pub horizon_seconds: u64,
    pub contributors: Vec<String>,
}
```

Example behavior:

```text
Current route is still usable
RTT trend rising
Loss rising
Relay utilization > threshold
Predicted degradation probability = 0.87

=> proactively prepare/switch to next safe route
```

---

# 11. Reinforcement Learning Design

## V1 Strategy

Use a safe, lightweight reinforcement-learning policy over discrete route candidates.

A **contextual bandit / Q-value policy** is recommended before introducing a neural DQN.

Reasons:

- small action space,
- easy to test,
- deterministic persistence,
- low compute cost,
- suitable for edge hardware,
- safer to roll out.

Actions:

```text
A0 = keep current route
A1 = direct P2P
A2 = relay path A
A3 = relay path B
A4 = multi-hop route C
```

---

## Reward Function

**File:** `crates/sgx-network-optimizer/src/reward.rs`

Example normalized reward:

```text
reward =
    + throughput_reward
    - latency_penalty
    - packet_loss_penalty
    - congestion_penalty
    - hop_penalty
    - route_switch_penalty
    - failed_route_penalty
```

Rust structure:

```rust
pub struct RewardComponents {
    pub latency: f64,
    pub throughput: f64,
    pub packet_loss: f64,
    pub congestion: f64,
    pub hop_count: f64,
    pub route_switch: f64,
    pub failure: f64,
}

impl RewardComponents {
    pub fn total(&self) -> f64 {
        self.throughput
            - self.latency
            - self.packet_loss
            - self.congestion
            - self.hop_count
            - self.route_switch
            - self.failure
    }
}
```

Every reward must be persisted so that an operator can explain why the policy learned a preference.

---

# 12. RL Safety Rules

The RL agent must **never directly control an unrestricted route space**.

Before an action is eligible:

```text
candidate route
      |
      v
is known?
      |
      v
is allowed?
      |
      v
is trust state acceptable?
      |
      v
is route healthy?
      |
      v
is switch cooldown satisfied?
      |
      v
eligible action
```

RL cannot override the safety guard.

---

# 13. Route Switch Hysteresis

Without hysteresis, small metric fluctuations can cause route flapping.

**File:** `crates/sgx-network-optimizer/src/safety.rs`

Required controls:

- minimum improvement before switching,
- minimum route hold time,
- cooldown after a route change,
- maximum switches per time window,
- immediate failover only for hard failure.

Example config:

```json
{
  "min_improvement_pct": 10.0,
  "min_route_hold_seconds": 30,
  "switch_cooldown_seconds": 20,
  "max_switches_per_5m": 6
}
```

---

# 14. Direct P2P vs Relay Selection

Example decision:

```text
Direct P2P
RTT: 82 ms
Loss: 4.1%
Throughput: 18 Mbps

Relay A
RTT: 59 ms
Loss: 0.8%
Throughput: 31 Mbps
Hop count: 1

AI prediction:
Relay A expected quality better by 26%

Safety guard:
PASS

Decision:
switch direct -> relay A
```

A route change must record both the predicted improvement and the actual observed result.

---

# 15. Multi-Relay Load Balancing

**File:** `crates/sgx-network-optimizer/src/load_balancer.rs`

High-priority traffic can be distributed among healthy relay routes.

Do not split traffic blindly.

Use route weights derived from predicted quality:

```rust
pub struct RelayWeight {
    pub route_id: String,
    pub weight: f64,
}
```

Possible result:

```text
relay-A = 0.55
relay-B = 0.30
relay-C = 0.15
```

High-priority traffic should prefer:

- lower latency,
- lower loss,
- adequate bandwidth,
- fewer hops,
- healthy/trusted routes.

---

# 16. Engine Loop

**File:** `crates/sgx-network-optimizer/src/engine.rs`

```rust
pub struct NetworkOptimizerEngine<P> {
    predictor: P,
    mode: DecisionMode,
}

impl<P: RoutePredictor> NetworkOptimizerEngine<P> {
    pub async fn tick(&mut self) -> anyhow::Result<()> {
        // 1. collect observation
        // 2. discover candidate routes
        // 3. build features
        // 4. predict route quality
        // 5. predict degradation
        // 6. obtain RL recommendation
        // 7. run eligibility + safety guard
        // 8. persist decision
        // 9. apply only in Active mode
        // 10. observe outcome and calculate reward
        Ok(())
    }
}
```

---

# 17. Guardian Runtime Integration

**File:** `src/network_ai/runtime.rs`

Responsibilities:

- load Task 3 configuration,
- create optimizer,
- attach shared telemetry adapter,
- attach Task 1 signal adapter,
- attach route controller,
- periodically execute inference,
- persist runtime metadata.

Suggested startup:

```rust
pub fn spawn_network_ai_runtime(
    node_id: String,
    metrics: Arc<Mutex<Metrics>>,
    state_dir: PathBuf,
) -> anyhow::Result<()> {
    // construct adapters
    // construct optimizer
    // spawn async runtime
    Ok(())
}
```

Then add startup wiring to existing:

```text
src/main.rs
```

near the existing Task 1 AI runtime initialization.

---

# 18. Telemetry Adapter

**File:** `src/network_ai/telemetry_adapter.rs`

This bridges existing Guardian metrics into `NetworkObservation`.

It should reuse existing counters wherever possible.

Do not create duplicate counters for metrics already collected by the daemon.

Responsibilities:

- RTT
- loss
- throughput
- relay usage
- connection rate
- current route
- relay hop count
- route-specific health

---

# 19. Task 1 Bridge

**File:** `src/network_ai/task1_bridge.rs`

Purpose:

- read latest Task 1 runtime risk/anomaly information,
- enrich route features,
- never treat anomaly score as the sole routing decision.

Example:

```rust
pub struct Task1RiskSignal {
    pub score: f64,
    pub contributors: Vec<String>,
    pub model_version: String,
}
```

---

# 20. Existing Routing Adapter

**File:** `src/network_ai/route_adapter.rs`

This is the only layer allowed to know the exact existing Nebula/relay implementation.

Trait:

```rust
#[async_trait::async_trait]
pub trait RouteController {
    async fn candidates(&self, peer_id: &str)
        -> anyhow::Result<Vec<RouteCandidate>>;

    async fn current_route(&self, peer_id: &str)
        -> anyhow::Result<Option<RouteCandidate>>;

    async fn apply_route(&self, decision: &RouteDecision)
        -> anyhow::Result<()>;
}
```

This separation prevents the AI crate from becoming tightly coupled to the network stack.

---

# 21. Task 2 Bridge

**File:** `src/network_ai/virtual_shift_bridge.rs`

Use this only when the requested route action is outside the safe runtime route set.

```rust
pub enum RouteActionClass {
    SafeRuntime,
    RequiresVirtualShift,
}
```

Decision:

```text
safe runtime action
    -> RouteController

policy/security-sensitive action
    -> Task 2 Virtual Shift recommendation/handoff
```

---

# 22. Audit Record

**File:** `src/network_ai/audit.rs`

Each AI decision should persist:

```json
{
  "decision_id": "netai-nodeA-...",
  "node_id": "nodeA",
  "peer_id": "nodeB",
  "previous_route": "direct-nodeB",
  "selected_route": "relayA-nodeB",
  "mode": "active",
  "predicted_latency_ms": 51.2,
  "previous_latency_ms": 79.5,
  "predicted_improvement_pct": 35.6,
  "model_confidence": 0.88,
  "degradation_probability": 0.73,
  "reward": 0.64,
  "reason": [
    "lower predicted RTT",
    "lower packet loss",
    "current route degrading"
  ],
  "model_version": "network-ai-v1"
}
```

---

# 23. API Deliverables

**New file:**

```text
src/api/handlers/network_ai.rs
```

**Existing file to update:**

```text
src/api/routes.rs
```

Suggested authenticated routes:

```text
GET  /api/v1/network-ai/runtime
GET  /api/v1/network-ai/current
GET  /api/v1/network-ai/candidates
GET  /api/v1/network-ai/decisions?limit=50
GET  /api/v1/network-ai/rewards?limit=50
GET  /api/v1/network-ai/benchmark
POST /api/v1/network-ai/mode
```

Example runtime response:

```json
{
  "engine_source": "sgx_network_optimizer",
  "mode": "shadow",
  "predictor": "route_quality_v1",
  "rl_policy": "contextual_bandit_v1",
  "feature_schema": "network-ai-v1",
  "model_version": "sha256:...",
  "current_peer_count": 2,
  "last_decision_ts": 0
}
```

---

# 24. Rollout Modes

Task 3 must be deployed progressively.

## Mode 1 — Shadow

AI observes and predicts but never changes a route.

```text
prediction -> persisted only
```

## Mode 2 — Advisory

AI generates a recommended route.

```text
prediction -> recommendation -> operator/API visibility
```

## Mode 3 — Active

AI may apply safe route changes through the safety guard.

```text
prediction -> safety -> apply -> reward
```

A configuration change is required to move into Active mode.

---

# 25. Task Breakdown / Issues

## Task 3 — Issue #1
### Network Telemetry Schema and Shared Adapter

**Files**

```text
crates/sgx-network-optimizer/src/metrics.rs
crates/sgx-network-optimizer/src/features.rs
src/network_ai/telemetry_adapter.rs
```

**Acceptance**

- RTT collected
- packet loss collected
- bandwidth/throughput collected
- relay hops collected
- current route identified
- Task 1-compatible metrics reused
- timestamped observations persisted
- no dependency on live attestation

---

## Task 3 — Issue #2
### Route Candidate Inventory and Eligibility

**Files**

```text
crates/sgx-network-optimizer/src/candidates.rs
crates/sgx-network-optimizer/src/eligibility.rs
src/network_ai/route_adapter.rs
```

**Acceptance**

- direct route candidate
- single relay candidate
- multi-hop candidate
- route IDs deterministic
- unhealthy routes excluded
- prohibited/untrusted routes cannot auto-apply

---

## Task 3 — Issue #3
### Historical Route Performance Store

**Files**

```text
crates/sgx-network-optimizer/src/history.rs
crates/sgx-network-optimizer/src/persistence.rs
```

**Acceptance**

- per-route history persisted
- EWMA latency
- EWMA loss
- EWMA throughput
- failure count
- success rate
- bounded retention
- restart-safe state

---

## Task 3 — Issue #4
### Route Quality Prediction Model

**Files**

```text
crates/sgx-network-optimizer/src/predictor.rs
crates/sgx-network-optimizer/tests/predictor_test.rs
```

**Acceptance**

- scores all candidates
- predicts latency
- predicts loss
- predicts throughput
- returns confidence
- deterministic with same input/model
- model/version metadata persisted
- no hidden heuristic presented as ML model

---

## Task 3 — Issue #5
### Network Degradation Predictor

**Files**

```text
crates/sgx-network-optimizer/src/degradation.rs
crates/sgx-network-optimizer/tests/degradation_test.rs
```

**Acceptance**

- rising RTT detected
- rising loss detected
- falling throughput detected
- degradation probability emitted
- contributors emitted
- prediction occurs before configured hard-failure threshold in synthetic tests

---

## Task 3 — Issue #6
### Reinforcement Learning Routing Policy

**Files**

```text
crates/sgx-network-optimizer/src/reward.rs
crates/sgx-network-optimizer/src/rl.rs
crates/sgx-network-optimizer/tests/rl_policy_test.rs
```

**Acceptance**

- discrete route actions
- reward persisted
- low latency rewarded
- high throughput rewarded
- loss/congestion penalized
- excessive switching penalized
- exploration bounded
- policy state survives restart
- same saved policy produces reproducible exploitation decisions

---

## Task 3 — Issue #7
### Safe Direct / Relay Route Switching

**Files**

```text
crates/sgx-network-optimizer/src/safety.rs
crates/sgx-network-optimizer/src/decision.rs
src/network_ai/route_adapter.rs
```

**Acceptance**

- direct → relay switch
- relay → direct switch
- relay A → relay B switch
- hysteresis
- cooldown
- minimum improvement requirement
- rollback/fallback when apply fails
- no route flapping in stability test

---

## Task 3 — Issue #8
### Multi-Relay Load Balancing

**Files**

```text
crates/sgx-network-optimizer/src/load_balancer.rs
```

**Acceptance**

- multiple eligible relay paths ranked
- route weights normalized
- high-priority traffic favors best route
- overloaded route loses weight
- failed relay removed
- weights automatically recover when route health recovers

---

## Task 3 — Issue #9
### Task 1 + Task 2 AI Integration

**Files**

```text
src/network_ai/task1_bridge.rs
src/network_ai/virtual_shift_bridge.rs
src/network_ai/audit.rs
```

**Acceptance**

- Task 1 anomaly signal can enrich route decision
- safe route optimization does not require Virtual Shift approval
- sensitive route/policy action enters Task 2 handoff
- AI justification preserved
- previous Task 1 model metadata traceable
- Task 3 model metadata traceable
- action audit linked across modules

---

## Task 3 — Issue #10
### Production Runtime + Client-Facing API

**Files**

```text
src/network_ai/mod.rs
src/network_ai/runtime.rs
src/api/handlers/network_ai.rs
src/api/routes.rs
src/main.rs
```

**Acceptance**

- runtime starts with Guardian
- restart-safe
- shadow/advisory/active modes
- runtime API
- candidate API
- current decision API
- history API
- reward API
- authenticated routes
- no secret/model key leakage

---

## Task 3 — Issue #11
### Full E2E Benchmark and Optimization Verification

**Files**

```text
crates/sgx-network-optimizer/tests/optimizer_e2e.rs
crates/sgx-network-optimizer/examples/run_network_ai_demo.rs
docs/ai-network-optimization.md
```

**Acceptance**

- static-routing baseline recorded
- identical workload replayed for AI routing
- average latency compared
- p50/p95/p99 latency compared
- packet loss compared
- throughput compared
- route-switch count compared
- convergence/reward trend recorded
- degradation reroute demonstrated
- direct/relay transition demonstrated
- multi-relay balancing demonstrated
- results persisted in benchmark artifact
- target evaluation explicitly reports whether 20–40% latency reduction was achieved

---

# 26. Benchmark Method

Never claim the 20–40% improvement from a unit test.

Use the same topology and workload for both runs.

## Baseline A

```text
static/current routing
AI disabled
same traffic
same duration
same topology
```

Measure:

```text
avg RTT
p50 RTT
p95 RTT
p99 RTT
loss
throughput
relay utilization
route failures
```

## Experiment B

```text
AI routing active
same traffic
same duration
same topology
```

Calculate:

```text
latency_improvement_pct =
    ((static_avg_latency - ai_avg_latency) / static_avg_latency) * 100
```

Final benchmark artifact:

```text
/var/lib/sgx-guardian/network-ai/benchmark.json
```

Example:

```json
{
  "static_avg_latency_ms": 82.4,
  "ai_avg_latency_ms": 58.9,
  "latency_improvement_pct": 28.52,
  "target_20_to_40_percent": "PASS",
  "static_packet_loss_pct": 3.1,
  "ai_packet_loss_pct": 1.2
}
```

---

# 27. Test Strategy

Only Task 3 AI-related tests should be required for this deliverable.

## Core tests

```bash
cargo test -p sgx-network-optimizer
```

## Targeted tests

```bash
cargo test -p sgx-network-optimizer predictor
cargo test -p sgx-network-optimizer degradation
cargo test -p sgx-network-optimizer rl
cargo test -p sgx-network-optimizer safety
cargo test -p sgx-network-optimizer optimizer_e2e
```

## Guardian integration tests

Target only the new module/API filters after implementation.

Do not require unrelated CRL or non-AI regression suites for Task 3 verification.

---

# 28. Configuration Example

**File:** `config/network_ai.example.json`

```json
{
  "enabled": true,
  "mode": "shadow",
  "sample_interval_seconds": 5,
  "history_window_seconds": 300,

  "min_improvement_pct": 10.0,
  "switch_cooldown_seconds": 20,
  "min_route_hold_seconds": 30,
  "max_switches_per_5m": 6,

  "degradation_probability_threshold": 0.75,

  "rl": {
    "enabled": true,
    "algorithm": "contextual_bandit_v1",
    "epsilon": 0.05,
    "learning_rate": 0.10
  },

  "reward": {
    "latency_weight": 0.35,
    "throughput_weight": 0.30,
    "loss_weight": 0.20,
    "congestion_weight": 0.10,
    "hop_weight": 0.03,
    "switch_weight": 0.02
  }
}
```

Weights are initial configuration values and must be tuned with benchmark evidence rather than treated as final constants.

---

# 29. Cargo Integration

New workspace member:

```toml
crates/sgx-network-optimizer
```

Suggested crate dependencies:

```toml
[dependencies]
anyhow = "1"
async-trait = "0.1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["sync", "time", "rt"] }
tracing = "0.1"
```

Prefer a small dependency footprint for edge deployment.

---

# 30. Patch Order

When implementation starts, patch in this order:

```text
1. Create sgx-network-optimizer crate
2. Add core types/config
3. Add telemetry + feature builder
4. Add candidate inventory
5. Add history store
6. Add predictor
7. Add degradation predictor
8. Add reward + RL policy
9. Add safety/hysteresis
10. Add decision engine
11. Add relay load balancing
12. Add Guardian telemetry adapter
13. Add existing-route adapter
14. Add Task 1 bridge
15. Add Task 2 bridge
16. Add audit persistence
17. Add runtime spawn
18. Add APIs
19. Wire src/main.rs
20. Build/recreate all three containers
21. Run Task 3 AI-only tests
22. Run live shadow-mode verification
23. Run advisory-mode verification
24. Enable active mode only after safety proof
25. Run controlled benchmark
```

---

# 31. Container Rollout

After any deployable code change:

```bash
docker compose -f docker-compose.dev.yml -p sgx-guardian-dev build nodeA nodeB nodeC

docker compose -f docker-compose.dev.yml -p sgx-guardian-dev up -d \
  --force-recreate --no-deps nodeA nodeB nodeC
```

Start Task 3 in:

```text
shadow
```

mode.

Do not start directly in active route-switching mode.

---

# 32. Definition of Done

Task 3 is complete only when all of the following are proven:

- [ ] Real network telemetry enters the optimizer.
- [ ] Direct and relay candidates are discovered.
- [ ] Route history survives restart.
- [ ] Route predictor produces structured predictions.
- [ ] Degradation predictor produces probability + contributors.
- [ ] RL policy learns/persists rewards.
- [ ] Safety filter always runs before route application.
- [ ] Route flapping protection works.
- [ ] Direct ↔ relay switching works.
- [ ] Relay ↔ relay switching works.
- [ ] Multi-relay weighting works.
- [ ] Task 1 risk signal is integrated.
- [ ] Task 2 handoff is used only when security/policy scope requires it.
- [ ] Runtime API exposes model/mode/version.
- [ ] Decision API exposes reason/confidence.
- [ ] Every applied route change is auditable.
- [ ] Static vs AI benchmark is repeatable.
- [ ] Benchmark explicitly reports achieved latency improvement.
- [ ] No claim of 20–40% improvement is made unless measurement proves it.
- [ ] All Task 3 AI-focused tests pass.
- [ ] Live three-container verification passes.

---

# 33. Final Module Flow

```text
REAL NETWORK METRICS
        |
        v
TELEMETRY ADAPTER
        |
        v
FEATURE BUILDER <----- TASK 1 ANOMALY/RISK SIGNAL
        |
        +---------------------------+
        |                           |
        v                           v
ROUTE QUALITY MODEL       DEGRADATION PREDICTOR
        |                           |
        +-------------+-------------+
                      |
                      v
             RL ROUTING POLICY
                      |
                      v
              ELIGIBILITY FILTER
                      |
                      v
                SAFETY GUARD
                      |
          +-----------+-----------+
          |                       |
          v                       v
 SAFE EXISTING ROUTE      SECURITY/POLICY CHANGE
          |                       |
          v                       v
  ROUTE CONTROLLER        TASK 2 VIRTUAL SHIFT
          |
          v
 OBSERVE REAL OUTCOME
          |
          v
 CALCULATE RL REWARD
          |
          v
 UPDATE HISTORY/POLICY
```

---

# 34. Deliverables Summary

The implementation deliverable will consist of:

1. `crates/sgx-network-optimizer` — isolated AI routing engine.
2. `src/network_ai` — Guardian runtime integration.
3. `src/api/handlers/network_ai.rs` — Client-Facing API.
4. `src/api/routes.rs` updates.
5. `src/main.rs` runtime startup wiring.
6. Persistent AI decision/reward/history artifacts.
7. Task 1 anomaly bridge.
8. Task 2 controlled-action bridge.
9. Shadow → advisory → active rollout modes.
10. AI-only unit/integration/E2E tests.
11. Static-vs-AI network benchmark evidence.
12. Final documented result stating whether the 20–40% latency target was actually achieved.

---

## Implementation Rule

Before patching this plan into the repository, inspect the current exact Nebula/relay routing functions and bind only `src/network_ai/route_adapter.rs` to them. The new AI crate should remain independent, testable, and reusable.

This prevents the new optimizer from breaking the already verified Task 1 and Task 2 AI modules.
