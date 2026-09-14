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
```

No commit/push until full Task3 is complete.

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
