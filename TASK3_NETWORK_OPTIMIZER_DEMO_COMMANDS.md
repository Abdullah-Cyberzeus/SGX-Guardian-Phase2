# Task 3 Network Optimizer Demo Commands

Run one PowerShell block at a time.

Current status:

```text
Deliverable 1 complete locally: Network telemetry schema + shared adapter
Deliverable 2 complete locally: Route candidates + trust eligibility filter
Deliverable 3 complete locally: Historical route performance store
Deliverable 4 complete locally: Route quality prediction model
Deliverable 5 complete locally: Network degradation predictor
Deliverable 6 complete locally: RL / contextual bandit policy
Deliverable 7 complete locally: Safety guard, hysteresis, cooldown, safe route switching
Deliverable 8 complete locally: Multi-relay load balancing
Deliverable 9 complete locally: Task1 recommendation + Task2 routing trust integration bridge
Deliverable 10 complete locally: Official safety guard, hysteresis, cooldown, hard-failure failover, rollback/fallback
Deliverable 11 complete locally: Guarded runtime route controller, state, transition audit, observed outcome
Deliverable 12 complete locally: Sensitive route changes hand off to Task2 pending owner review
Deliverable 13 complete locally: Multi-relay ranking, stable weights, overload reduction and recovery ramp
Deliverable 14 complete locally: Linked decision, reward, degradation, Task1 and Task2 audit evidence
Deliverable 15 complete locally: Shadow/Advisory/Active safe runtime modes
Deliverable 16 complete locally: Versioned validated admin configuration with effective-value evidence
Deliverable 17 complete locally: Guardian-facing bounded periodic runtime with restart-safe state
Deliverable 18 complete locally: Authenticated Task3 client API with safe bounded audit responses
Deliverable 19 complete locally: Optional read-only Task1 anomaly/risk bridge with trace evidence
Deliverable 20 complete locally: Read-only latest Task2 trust/policy bridge with safe fallback and source trace
Deliverable 21 complete locally: Shadow route decision with simple readable evidence and no apply
Deliverable 22 complete locally: Advisory route recommendation with read-only safety verdict and no apply
```

No commit/push until full Task3 is complete.

---

## Demo 10 - Deliverable 21: Shadow route decision

```powershell
Set-Location "C:\Users\Hp\Desktop\Task1-2_AnomalydetectionEngine\sgx-anomaly-engine"

cargo run --example run_task3_network_optimizer_demo -- `
  --mode shadow `
  --traffic-class operational `
  --source-node nodeA `
  --destination-node nodeB `
  --task2-trust-state data\virtual_shift\15_ROUTING_TRUST_STATE\nodeB\routing_trust_summary.json `
  --out-dir data\network_ai\d21_shadow_demo
```

It prints trusted/rejected routes, predicted metrics, degradation and selected
route, but writes no runtime apply result. Read the short decision here:

```text
data\network_ai\d21_shadow_demo\shadow_route_decision.json
```

---

## Demo 11 - Deliverable 22: Advisory route recommendation

```powershell
Set-Location "C:\Users\Hp\Desktop\Task1-2_AnomalydetectionEngine\sgx-anomaly-engine"

cargo run --example run_task3_network_optimizer_demo -- `
  --mode advisory `
  --traffic-class operational `
  --source-node nodeA `
  --destination-node nodeB `
  --task2-trust-state data\virtual_shift\15_ROUTING_TRUST_STATE\nodeB\routing_trust_summary.json `
  --out-dir data\network_ai\d22_advisory_demo
```

No active route changes. The saved recommendation contains expected improvement,
confidence, reason, read-only safety verdict and the operator next step:

```text
data\network_ai\d22_advisory_demo\advisory_route_recommendation.json
```

---

## Demo 1 - Deliverable 1 to 11: Telemetry to Task1/Task2-Linked Route Decision

This demo uses synthetic Task1-compatible network telemetry, and if Task1/Task2 evidence exists it also reads the latest Task1 recommendation JSON and Task2 routing trust summary JSON.

It proves:

- traffic class selection
- normal vs high priority
- RTT / latency collection
- packet loss collection
- throughput collection
- bandwidth utilization collection
- relay hop count
- current route ID
- direct/relay/multihop candidate inventory
- trust eligibility filter before AI scoring
- rejected route reason
- per-route historical performance store
- EWMA latency/loss/throughput
- success/failure count
- restart-safe history JSON
- route quality prediction
- expected latency/loss/throughput
- model confidence
- selected best eligible route
- degradation probability
- degradation contributors
- route reward components
- contextual bandit Q-value policy
- reproducible RL selected route
- safety guard
- minimum improvement check
- cooldown / hold-time protection
- max-switch window protection
- hard-failure failover option
- safe route apply result
- rollback route kept
- runtime direct/relay route transition controller
- current active route state + transition audit
- observed outcome persisted with reward for learning
- relay weight calculation
- overloaded/failed/non-eligible relays excluded from weights
- Task1 recommendation signal bridge
- Task2 routing trust-state bridge
- read-only integration audit
- JSON evidence saved

### Security/control traffic run

Use this for policy/control traffic style messages like `VSHIFT_ALERT`, signed policy delivery, verification, attestation, and trust updates.

```powershell
Set-Location "C:\Users\Hp\Desktop\Task1-2_AnomalydetectionEngine\sgx-anomaly-engine"

cargo run --example run_task3_network_optimizer_demo -- `
  --traffic-class security-control `
  --source-node nodeA `
  --destination-node nodeB `
  --task1-recommendation data\recommendation_records\nodeA\run_012\recommendations.json `
  --task2-trust-state data\virtual_shift\15_ROUTING_TRUST_STATE\nodeB\routing_trust_summary.json
```

Expected terminal sections:

```text
TASK 3 - NETWORK OPTIMIZER DEMO (DELIVERABLE 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9 + 10 + 11)
1. TRAFFIC CLASSIFICATION
2. NETWORK OBSERVATION - Task1-compatible metrics reused
3. ROUTE CANDIDATE INVENTORY
4. TRUST ELIGIBILITY FILTER - runs before AI scoring
5. HISTORICAL ROUTE PERFORMANCE STORE
6. ROUTE QUALITY PREDICTION MODEL
7. NETWORK DEGRADATION PREDICTOR
8. REWARD + CONTEXTUAL BANDIT POLICY
9. SAFETY GUARD AND SAFE ROUTE SWITCHING
10. MULTI-RELAY LOAD BALANCING
11. TASK1 + TASK2 INTEGRATION BRIDGES
12. GUARDED RUNTIME ROUTE CONTROLLER
SAVED EVIDENCE
```

Expected evidence:

```text
data\network_ai\task3_deliverable_1_2_demo\current_observation.json
data\network_ai\task3_deliverable_1_2_demo\route_observations.jsonl
data\network_ai\task3_deliverable_1_2_demo\candidate_inventory.json
data\network_ai\task3_deliverable_1_2_demo\eligible_routes.json
data\network_ai\task3_deliverable_1_2_demo\route_history_store.json
data\network_ai\task3_deliverable_1_2_demo\route_predictions.json
data\network_ai\task3_deliverable_1_2_demo\degradation_predictions.json
data\network_ai\task3_deliverable_1_2_demo\route_rewards.json
data\network_ai\task3_deliverable_1_2_demo\rl_policy.json
data\network_ai\task3_deliverable_1_2_demo\rl_decision.json
data\network_ai\task3_deliverable_1_2_demo\route_safety_decision.json
data\network_ai\task3_deliverable_1_2_demo\route_apply_result.json
data\network_ai\task3_deliverable_1_2_demo\current_route_state.json
data\network_ai\task3_deliverable_1_2_demo\runtime_route_apply_result.json
data\network_ai\task3_deliverable_1_2_demo\route_transition_audit.jsonl
data\network_ai\task3_deliverable_1_2_demo\relay_weights.json
data\network_ai\task3_deliverable_1_2_demo\task1_route_signal.json
data\network_ai\task3_deliverable_1_2_demo\task2_trust_summary.json
data\network_ai\task3_deliverable_1_2_demo\task3_integration_audit.json
```

If you do not pass `--task1-recommendation` or `--task2-trust-state`, the demo tries latest local defaults. If no files exist, it safely falls back to synthetic demo state.

---

### Hard-failure failover safety proof

Use this when the current route is actually failed. In this case only, D10 allows immediate failover even if hold time or cooldown would normally block switching.

```powershell
Set-Location "C:\Users\Hp\Desktop\Task1-2_AnomalydetectionEngine\sgx-anomaly-engine"

cargo run --example run_task3_network_optimizer_demo -- `
  --traffic-class security-control `
  --source-node nodeA `
  --destination-node nodeB `
  --task1-recommendation data\recommendation_records\nodeA\run_012\recommendations.json `
  --task2-trust-state data\virtual_shift\15_ROUTING_TRUST_STATE\nodeB\routing_trust_summary.json `
  --current-route-failed `
  --out-dir data\network_ai\task3_deliverable_10_failover_demo
```

Expected terminal proof:

```text
Safety verdict: Allow
Hard failover: true
Reason: hard failure failover
Route apply result saved with rollback/fallback route
```

Expected evidence:

```text
data\network_ai\task3_deliverable_10_failover_demo\route_safety_decision.json
data\network_ai\task3_deliverable_10_failover_demo\route_apply_result.json
data\network_ai\task3_deliverable_10_failover_demo\current_route_state.json
data\network_ai\task3_deliverable_10_failover_demo\route_transition_audit.jsonl
```

---

### Normal operational traffic run

Use this for telemetry, heartbeat, runtime metrics, health/status, and network stats.

```powershell
Set-Location "C:\Users\Hp\Desktop\Task1-2_AnomalydetectionEngine\sgx-anomaly-engine"

cargo run --example run_task3_network_optimizer_demo -- `
  --traffic-class operational `
  --source-node nodeA `
  --destination-node nodeB `
  --out-dir data\network_ai\task3_deliverable_1_2_demo_operational
```

Expected evidence:

```text
data\network_ai\task3_deliverable_1_2_demo_operational\current_observation.json
data\network_ai\task3_deliverable_1_2_demo_operational\route_observations.jsonl
data\network_ai\task3_deliverable_1_2_demo_operational\candidate_inventory.json
data\network_ai\task3_deliverable_1_2_demo_operational\eligible_routes.json
data\network_ai\task3_deliverable_1_2_demo_operational\route_history_store.json
data\network_ai\task3_deliverable_1_2_demo_operational\route_predictions.json
data\network_ai\task3_deliverable_1_2_demo_operational\degradation_predictions.json
data\network_ai\task3_deliverable_1_2_demo_operational\route_rewards.json
data\network_ai\task3_deliverable_1_2_demo_operational\rl_policy.json
data\network_ai\task3_deliverable_1_2_demo_operational\rl_decision.json
data\network_ai\task3_deliverable_1_2_demo_operational\route_safety_decision.json
data\network_ai\task3_deliverable_1_2_demo_operational\route_apply_result.json
data\network_ai\task3_deliverable_1_2_demo_operational\relay_weights.json
data\network_ai\task3_deliverable_1_2_demo_operational\task3_integration_audit.json
```

---

## Verification Commands

Run after Task3 changes to ensure Task3 and existing Task1/Task2 demos are still okay.

```powershell
Set-Location "C:\Users\Hp\Desktop\Task1-2_AnomalydetectionEngine\sgx-anomaly-engine"

cargo test network_ai --lib
cargo check --example run_task3_network_optimizer_demo
cargo check --example run_live_stream_demo
cargo check --example run_policy_recommendation_groups_demo
cargo check --example run_virtual_shift_after_approval_demo
```

Expected:

```text
network_ai tests pass
Task3 demo compiles
Task1 live demo compiles
Task2 grouping demo compiles
Task2 after-approval lifecycle demo compiles
```

---

## Future Demo Sections To Add

As we implement the next deliverables, add commands below:

```text
Deliverable 11: complete - guarded runtime controller
Deliverable 14: Decision persistence and audit evidence
```

---

## Demo 2 - Deliverable 12: Sensitive route handoff to Task2

Use this only for a route that needs a trust/policy/security exception. It does **not** use the runtime route controller. Instead, it saves the exact Task3 reason in the existing Task2 owner-review queue as `PendingReview`.

```powershell
Set-Location "C:\Users\Hp\Desktop\Task1-2_AnomalydetectionEngine\sgx-anomaly-engine"

cargo run --example run_task3_sensitive_route_handoff_demo -- `
  --source-node nodeA `
  --destination-node nodeB `
  --route-id relay-nodeA-via-nodeZ-nodeB `
  --reason new-untrusted-relay `
  --out-dir data\network_ai\task3_deliverable_12_demo
```

Accepted `--reason` values:

```text
new-untrusted-relay
policy-rule-change-needed
cross-boundary-route
quarantined-member-recovery
security-exception-required
```

Expected proof:

```text
Direct route apply: BLOCKED
Owner/admin approval: REQUIRED
Task2 review status: PendingReview
Task2 pending review: data/virtual_shift/02_OWNER_REVIEW_DECISIONS/<plan-id>/review.json
```

Evidence:

```text
data\network_ai\task3_deliverable_12_demo\task3_sensitive_route_handoff_audit.json
data\virtual_shift\02_OWNER_REVIEW_DECISIONS\<plan-id>\review.json
```

### D12 end-to-end proof: later Task3 cycle reads fresh Task2 state

This focused proof runs both branches in isolated local evidence: Task3 handoff, Task2 approval/rejection, a new Task2 routing-summary version, then a new Task3 eligibility/apply cycle.

```powershell
Set-Location "C:\Users\Hp\Desktop\Task1-2_AnomalydetectionEngine\sgx-anomaly-engine"

cargo run --example run_task3_d12_lifecycle_proof_demo
```

Expected proof:

```text
Approved route eligible/applied: true/true
Rejected route eligible/applied: false/false
```

Each branch saves `task3_handoff.json`, Task2 `review.json`, fresh `task2_routing_trust_summary.json`, runtime apply/audit files, and `later_task3_decision.json` carrying all three linked IDs.

---

## Demo 3 - Deliverable 13: Multi-relay balancing

This shows only Task2-trusted candidate routes. Security/control traffic gives the top trusted route preference; overloaded routes are down-weighted, and a newly recovered relay returns gradually instead of receiving full traffic immediately.

```powershell
Set-Location "C:\Users\Hp\Desktop\Task1-2_AnomalydetectionEngine\sgx-anomaly-engine"

cargo run --example run_task3_multi_relay_balancing_demo
```

Expected proof:

```text
Total stable weight: 1.0000
overload_factor < 1.00 for overloaded relay
recovery_factor < 1.00 for recently recovered relay
rank 1 receives high-priority preference
```

---

## Demo 4 - Deliverable 14: Decision audit evidence chain

Runs the existing real optimizer path and writes one simple latest decision
plus append-only linked decision, reward, and degradation histories.

```powershell
Set-Location "C:\Users\Hp\Desktop\Task1-2_AnomalydetectionEngine\sgx-anomaly-engine"

cargo run --example run_task3_network_optimizer_demo -- `
  --out-dir data\network_ai\d14_audit_demo `
  --traffic-class operational `
  --source-node nodeA `
  --destination-node nodeB
```

Inspect these D14 files:

```text
data\network_ai\d14_audit_demo\current_decision.json
data\network_ai\d14_audit_demo\decisions.jsonl
data\network_ai\d14_audit_demo\rewards.jsonl
data\network_ai\d14_audit_demo\degradation_events.jsonl
```

`current_decision.json` links selected route/reason/confidence, rejected
routes/reasons, model versions, Task1/Task2 traces, route history, observed
outcomes, selected reward, and degradation predictions.

---

## Demo 5 - Deliverable 15: Runtime modes

`--mode` is the runtime configuration. If it is omitted, Task3 defaults to
`shadow`. Shadow and Advisory generate evidence/recommendations only; only
Active can call the existing D10/D11 guarded controller.

### Shadow (default, no route apply)

```powershell
Set-Location "C:\Users\Hp\Desktop\Task1-2_AnomalydetectionEngine\sgx-anomaly-engine"

cargo run --example run_task3_network_optimizer_demo -- `
  --out-dir data\network_ai\d15_shadow_demo `
  --mode shadow `
  --traffic-class operational `
  --source-node nodeA `
  --destination-node nodeB
```

### Advisory (recommend only, no route apply)

```powershell
cargo run --example run_task3_network_optimizer_demo -- `
  --out-dir data\network_ai\d15_advisory_demo `
  --mode advisory `
  --traffic-class operational `
  --source-node nodeA `
  --destination-node nodeB
```

### Active (only Task2-trusted route + D10/D11 safety path)

```powershell
cargo run --example run_task3_network_optimizer_demo -- `
  --out-dir data\network_ai\d15_active_demo `
  --mode active `
  --traffic-class operational `
  --source-node nodeA `
  --destination-node nodeB
```

Each run saves `runtime_mode_decision.json`. Shadow/Advisory show
`Applied: false`; Active saves D10 safety and D11 apply evidence only when
the selected route is already Task2-eligible.

---

## Demo 6 - Deliverable 16: Versioned admin configuration

The config is validated before the engine uses it. It controls enabled/mode,
sampling/history retention, D10 safety settings, degradation threshold, RL
epsilon/learning rate, and reward weights.

```powershell
Set-Location "C:\Users\Hp\Desktop\Task1-2_AnomalydetectionEngine\sgx-anomaly-engine"

cargo run --example run_task3_network_optimizer_demo -- `
  --config config\network_ai.example.json `
  --out-dir data\network_ai\d16_config_demo `
  --traffic-class operational `
  --source-node nodeA `
  --destination-node nodeB
```

Evidence:

```text
config\network_ai.example.json
data\network_ai\d16_config_demo\effective_network_ai_config.json
```

---

## Demo 7 - Deliverable 17: Bounded production-runtime integration

This runs two periodic Task3 ticks through the Guardian-facing runtime module,
using fresh Task2-filtered inputs per tick. It exits automatically after two
ticks; it does not start an endless background process.

```powershell
Set-Location "C:\Users\Hp\Desktop\Task1-2_AnomalydetectionEngine\sgx-anomaly-engine"

cargo run --example run_task3_runtime_demo -- `
  --config config\network_ai.example.json
```

Evidence:

```text
data\network_ai\d17_runtime_demo\runtime.json
```

---

## Demo 8 - Deliverable 18: Authenticated client API

Start this in one PowerShell terminal:

```powershell
Set-Location "C:\Users\Hp\Desktop\Task1-2_AnomalydetectionEngine\sgx-anomaly-engine"
cargo run --example run_task3_network_ai_api
```

In a second terminal, authenticated read example:

```powershell
Invoke-RestMethod http://127.0.0.1:8093/api/v1/network-ai/status `
  -Headers @{ "x-operator-id" = "nodeA" }
```

Endpoints: `status`, `candidates`, `decision/current`, `history`, `rewards`,
and authenticated `POST /api/v1/network-ai/mode`. No private keys, tokens, or
Task2 credentials are exposed.

---

## Demo 9 - Deliverable 19: Task1 anomaly/risk bridge

```powershell
Set-Location "C:\Users\Hp\Desktop\Task1-2_AnomalydetectionEngine\sgx-anomaly-engine"

cargo run --example run_task3_network_optimizer_demo -- `
  --task1-recommendation data\recommendation_records\nodeA\run_012\recommendations.json `
  --out-dir data\network_ai\d19_task1_bridge_demo `
  --traffic-class operational `
  --source-node nodeA `
  --destination-node nodeB
```

Task3 reads the existing Task1 JSON only. It stores source path, run ID,
recommendation IDs, anomaly score and evidence features in
`task1_route_signal.json`; missing/malformed optional input safely becomes no
Task1 signal rather than crashing the optimizer.

---

## Demo 10 - Deliverable 23: Active safe route switch

This uses real Task2-backed eligibility, deterministic route prediction,
reward/Q-value selection, D10 safety, and D11 apply. It proves trusted
direct -> relay and relay -> relay changes only when both safety verdicts pass.

```powershell
Set-Location "C:\Users\Hp\Desktop\Task1-2_AnomalydetectionEngine\sgx-anomaly-engine"

cargo run --example run_task3_active_safe_switch_demo
```

Evidence:

```text
data\network_ai\d23_active_safe_switch_demo\d23_evidence.json
data\network_ai\d23_active_safe_switch_demo\apply1.json
data\network_ai\d23_active_safe_switch_demo\apply2.json
data\network_ai\d23_active_safe_switch_demo\state.json
data\network_ai\d23_active_safe_switch_demo\transitions.jsonl
data\network_ai\d23_active_safe_switch_demo\outcomes.jsonl
data\network_ai\d23_active_safe_switch_demo\predictions.json
data\network_ai\d23_active_safe_switch_demo\rewards.json
data\network_ai\d23_active_safe_switch_demo\rl_decision.json
```

---

## Demo 11 - Deliverable 24: Task2 handoff for a sensitive route

An untrusted/new relay is never applied directly. Task3 creates an existing
Task2 owner-review record and keeps Task2 trust/policy unchanged.

```powershell
Set-Location "C:\Users\Hp\Desktop\Task1-2_AnomalydetectionEngine\sgx-anomaly-engine"

cargo run --example run_task3_d24_task2_handoff_demo
```

Expected: `DIRECT_APPLY_BLOCKED: true`, `PendingReview`, linked Task3 handoff
ID, Task2 review JSON, and audit evidence at:

```text
data\network_ai\d24_task2_handoff_demo\task3_task2_handoff_audit.json
data\virtual_shift\02_OWNER_REVIEW_DECISIONS\<task3-handoff-id>\review.json
```

---

## Demo 12 - Deliverable 25: Static versus AI benchmark

Runs the identical fixed laptop/synthetic topology and operational workload for
static direct routing and Task3 AI routing. Task2 filtering happens before AI
selection; D10/D11 must allow the selected trusted route. The target is judged
from the measured output, not unit-test success.

```powershell
Set-Location "C:\Users\Hp\Desktop\Task1-2_AnomalydetectionEngine\sgx-anomaly-engine"

cargo run --example run_task3_static_vs_ai_benchmark
```

Evidence:

```text
data\network_ai\d25_static_vs_ai_benchmark\benchmark.json
```

It records average/p50/p95/p99 latency, loss, throughput, switch count,
measured latency improvement, D10/D11 state, and an honest 20–40% target verdict.
