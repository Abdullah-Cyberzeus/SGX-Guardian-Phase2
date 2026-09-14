# SGX Task 3 --- Production Wiring Plan

## 1. Scope

Wire the existing `sgx-anomaly-engine::network_ai` Task 3 subsystem into
the real SGX Guardian production runtime.

This phase is **production integration only**. It must **not redesign or
fix AI algorithms**. The AI crate remains the decision engine, while SGX
production code owns runtime orchestration, real networking state, trust
enforcement, route application, rollback, and operational lifecycle.

The integration must be designed around stable adapter boundaries so
that later AI-side fixes can be merged without rewriting the production
networking layer.

---

## 2. Core Architecture

The target production flow is:

```text
SGX Guardian Startup
        |
        v
NetworkAiRuntimeService
        |
        +--> Real Telemetry Adapter
        |
        +--> Nebula / CoT Topology Adapter
        |
        +--> Task2 Trust Adapter
        |
        +--> Route Observation / History Adapter
        |
        v
sgx-anomaly-engine::network_ai
        |
        v
AI Route Recommendation
        |
        v
Production Safety + Task2 Validation
        |
        v
Transport / Relay Control Adapter
        |
        +--> Apply succeeds --> Commit active route
        |
        +--> Apply fails ----> Retain/rollback previous route
        |
        v
Persistence + D14 Audit + Runtime Status
```

**Security rule:** an AI recommendation is not proof that a route was
applied. Production state may report a new active route only after the
real transport layer confirms successful application.

---

## 3. Wiring Item 1 --- Production Runtime Entry Point

### Objective

Start Task 3 automatically as part of the normal SGX Guardian lifecycle.

### Required Work

- Locate the real Guardian startup/runtime path, such as `src/main.rs`
  and its service initialization modules.
- Add a dedicated production Task 3 runtime service rather than
  invoking example/demo binaries.
- Start the service after required SGX networking, identity,
  CoT/Nebula, and Task2 dependencies are available.
- Ensure Task 3 shutdown follows the Guardian shutdown lifecycle.
- Prevent duplicate Task 3 runtime instances.
- Make enable/disable behavior configurable where appropriate.

### Acceptance Criteria

Task 3 starts automatically with Guardian and does not require manually
executing `run_task3_network_optimizer_demo` or another example binary.

---

## 4. Wiring Item 2 --- Stable Production Adapter Layer

### Objective

Prevent production SGX networking code from becoming tightly coupled to
current AI implementation details.

### Required Interfaces

Create or reuse production abstractions equivalent to:

```rust
trait NetworkTelemetryProvider {
    fn collect(&self) -> anyhow::Result<ProductionTelemetry>;
}

trait RouteTopologyProvider {
    fn discover_routes(&self) -> anyhow::Result<ProductionRouteTopology>;
}

trait Task2TrustProvider {
    fn current_trust_state(&self) -> anyhow::Result<ProductionTrustState>;
}

trait RouteObservationProvider {
    fn current_route(&self) -> anyhow::Result<ObservedRouteState>;
}

trait RouteTransport {
    fn apply_route(&self, request: &RouteApplyRequest)
        -> anyhow::Result<RouteApplyResult>;

    fn rollback(&self, request: &RouteRollbackRequest)
        -> anyhow::Result<RouteApplyResult>;
}

trait RelayHealthProvider {
    fn relay_health(&self) -> anyhow::Result<Vec<ProductionRelayHealth>>;
}

trait RelayControl {
    fn apply_weights(&self, request: &RelayWeightApplyRequest)
        -> anyhow::Result<RelayWeightApplyResult>;
}
```

Exact names may follow existing SGX conventions. Do not create duplicate
abstractions if suitable production interfaces already exist.

### Boundary Rule

Conversion from SGX production types to `network_ai` types should happen
in an integration/adapter layer. Avoid spreading AI-specific types
throughout unrelated Guardian modules.

---

## 5. Wiring Item 3 --- Real Telemetry Integration

### Objective

Replace demo/synthetic production inputs with measurements obtained from
the actual Guardian runtime.

### Required Work

Inspect existing SGX sources for:

- interface state;
- RTT/latency;
- packet loss;
- throughput;
- bandwidth utilization;
- interface availability;
- route health;
- Nebula tunnel state;
- transport state;
- historical observations.

Use existing SGX collectors first. Add production collection only where
a required metric has no existing source.

### Requirements

- No hardcoded latency/loss/throughput values.
- No hardcoded success state.
- Missing measurements must be represented explicitly.
- Collection failure must not be converted into fake healthy metrics.
- Telemetry timestamps must come from the real runtime clock.

---

## 6. Wiring Item 4 --- Real Nebula / Circle Route Discovery

### Objective

Build Task 3 candidate routes from real SGX topology instead of
hardcoded node lists.

### Candidate Sources

Inspect and integrate the authoritative runtime sources, including where
applicable:

```text
overlay_registry.json
lighthouse_registry.json
relay_registry.json
Nebula runtime/config state
Circle membership
CoT peer state
live transport/interface state
```

### Required Work

- Determine local node dynamically.
- Determine destination dynamically.
- Discover direct route availability.
- Discover actual eligible relay nodes/topology.
- Map physical endpoints and overlay identities safely.
- Exclude stale/unavailable topology entries.
- Avoid inventing multi-hop paths that the production transport cannot
  actually realize.

### Forbidden

Production code must not assume:

```text
nodeA
nodeB
nodeC
nodeD
nodeE
192.168.100.x
172.31.250.x
```

Those values may remain in tests/fixtures only.

---

## 7. Wiring Item 5 --- Task 2 Trust Authority

### Objective

Ensure Task 3 never bypasses Task 2 security/trust decisions.

### Required Work

- Locate the authoritative Task2 trust state produced by the
  production runtime.
- Read current trust state/version through the adapter.
- Validate freshness/version where the existing Task2 model supports
  it.
- Feed the state into Task 3 eligibility filtering.
- Revalidate trust before transport application if the decision/apply
  boundary can race with trust updates.

### Fail-Closed Cases

Do not apply a new route when:

- Task2 trust state is unavailable;
- trust state cannot be parsed/validated;
- required peer trust is absent;
- a candidate contains a quarantined/rejected peer;
- the trust state is known to be stale;
- the candidate is no longer in the trusted eligible set.

Task2 remains authoritative over AI optimization.

---

## 8. Wiring Item 6 --- Periodic Task 3 Runtime Cycle

### Objective

Execute Task 3 continuously as a production service rather than only
through demos.

### Runtime Flow

```text
collect real telemetry
        |
discover current topology
        |
read Task2 trust state
        |
observe current transport route
        |
update route observations/history
        |
construct AI candidates
        |
Task2 eligibility filtering
        |
prediction / optimization
        |
production safety validation
        |
apply through transport adapter if required
        |
verify result
        |
persist state and audit
```

### Requirements

- Runtime interval must be configurable.
- Prevent overlapping cycles unless explicitly designed for
  concurrency.
- One failed cycle must not crash the entire Guardian.
- Record cycle failures.
- Missing security-critical inputs must cause a safe no-change result.
- Graceful shutdown must stop the loop.

---

## 9. Wiring Item 7 --- Real Transport Apply Boundary

### Objective

Ensure an AI-selected route becomes active only through real production
networking control.

### Required Sequence

```text
AI recommends candidate
        |
Task2 candidate still eligible?
        |
production safety checks pass?
        |
RouteTransport::apply_route(...)
        |
     +-- success --> verify/observe --> commit
     |
     +-- failure --> retain previous route / rollback
```

### Critical Requirements

Never implement production behavior equivalent to:

```rust
let transport_apply_succeeds = true;
```

or:

```rust
active_route = ai_selected_route;
```

without transport confirmation.

`RouteApplyResult` should provide enough evidence to distinguish at
minimum:

- requested route;
- previous route;
- transport operation attempted;
- success/failure;
- resulting observed route where available;
- failure reason;
- rollback result where applicable.

---

## 10. Wiring Item 8 --- Rollback and State Consistency

### Objective

Prevent Task 3 internal state from diverging from the actual network.

### Required Work

- Capture previous active route before switching.
- Attempt real transport change.
- Verify resulting transport state when technically possible.
- Commit Task 3 route state only after successful application.
- On failure, retain the old route.
- If a partial change occurred, invoke rollback.
- Record rollback success/failure.
- On restart, reconcile persisted state against observed network
  state.

### Important Invariant

```text
Task3 active_route == verified/observed production route
```

If verification is unavailable, status must explicitly represent
uncertainty rather than claiming successful application.

---

## 11. Wiring Item 9 --- Real Relay Health Integration

### Objective

Supply Task 3 relay balancing with actual relay health/runtime
information.

### Potential Inputs

Use authoritative available SGX/Nebula state such as:

```text
relay_registry.json
relay_stats.json
lighthouse_registry.json
Nebula process/tunnel state
current bandwidth/utilization
peer/tunnel health
```

### Required Work

Map real state into the AI relay-health input boundary.

Do not synthesize:

- `available=true`;
- `healthy=true`;
- utilization;
- recovery timestamps.

Unknown health must remain unknown/unavailable according to the safest
supported integration behavior.

---

## 12. Wiring Item 10 --- Relay Control Boundary

### Objective

Keep relay enforcement outside the AI crate.

AI may calculate relay preferences/weights, but production SGX must own
enforcement.

### Required Flow

```text
AI RelayWeightSet
      |
Production validation
      |
RelayControl adapter
      |
actual supported Nebula/SGX mechanism
      |
verification
      |
audit/result
```

If the current Nebula deployment cannot enforce weighted relay selection
directly, do **not** falsely mark weights as applied. Record them as
recommendations/pending enforcement until a real supported control
mechanism exists.

---

## 13. Wiring Item 11 --- Production Persistence

### Objective

Give the production Task 3 service restart-safe, inspectable storage
independent of demo directories.

Use an SGX-configured data root. A target layout may be:

```text
/var/lib/sgx-guardian/data/network_ai/runtime/
├── runtime_status.json
├── current_route_state.json
├── route_history.jsonl
├── observed_outcomes.jsonl
├── route_transition_audit.jsonl
├── current_decision.json
├── decisions.jsonl
├── rewards.jsonl
├── degradation_events.jsonl
└── relay_weights.json
```

The final path must follow existing Guardian configuration/storage
conventions.

### Requirements

- No demo directory dependency.
- Atomic replacement for current-state files where required.
- Append-only audit/history where appropriate.
- Safe directory creation and permissions.
- Restart-safe loading.
- Corrupt critical state must not silently become trusted state.
- Persistence errors affecting safety state must fail safely.

Do not redesign known AI persistence algorithms in this wiring phase.

---

## 14. Wiring Item 12 --- D14 Automatic Decision Audit

### Objective

Make D14 evidence generation part of the real runtime cycle.

### Required Work

Automatically persist/link:

- decision ID;
- real timestamp;
- selected route;
- confidence/reason;
- model/schema version;
- rejected candidates;
- Task1 evidence reference;
- Task2 trust evidence/version;
- reward evidence where produced by the AI engine;
- degradation evidence;
- route history evidence;
- actual transport application result;
- rollback/transition evidence.

Artifacts must update because the Guardian runtime executes Task 3, not
because a demo command was manually run.

---

## 15. Wiring Item 13 --- Production Runtime Status

### Objective

Expose enough state to diagnose Task 3 without reading arbitrary demo
output.

A status representation should include equivalent information to:

```json
{
  "running": true,
  "last_cycle_ms": 0,
  "last_success_ms": 0,
  "trust_state_available": false,
  "candidate_count": 0,
  "eligible_count": 0,
  "recommended_route": null,
  "active_route": null,
  "transport_apply_attempted": false,
  "last_transport_result": null,
  "last_error": null
}
```

Use existing SGX API/status infrastructure if available rather than
introducing a parallel control plane unnecessarily.

---

## 16. Wiring Item 14 --- Configuration

### Objective

Remove environment-specific assumptions from production Task 3 wiring.

Configuration should cover applicable values such as:

- enable/disable Task 3;
- cycle interval;
- production persistence root;
- Nebula/CoT state locations where they are not already centrally
  configured;
- trust state source;
- safety/reconciliation behavior supported by production code.

Reuse existing SGX configuration mechanisms.

Do not hardcode container-specific paths if Guardian already has
canonical path configuration.

---

## 17. Wiring Item 15 --- Startup Dependency Ordering

### Objective

Ensure Task 3 does not begin optimizing before its security/network
dependencies are usable.

Expected dependency order:

```text
Guardian base initialization
        |
identity/security initialization
        |
network / Nebula / CoT initialization
        |
Task2 trust/policy availability
        |
Task3 production runtime start
```

If dependencies temporarily disappear after startup, Task 3 must move
into a safe degraded/no-change state rather than bypassing them.

---

## 18. Wiring Item 16 --- Error Handling and Fail-Closed Behavior

Production wiring must explicitly test these conditions:

  Condition                                     Required behavior

---

  Task2 state missing                           No new route apply
  Task2 state invalid                           No new route apply
  Trusted candidate disappears                  No unsafe switch
  No eligible candidate                         Retain safe current route
  Telemetry unavailable                         Do not invent measurements
  Relay health unavailable                      Do not claim healthy relay
  Transport apply fails                         Do not commit requested route
  Verification disagrees with requested route   Do not claim success
  Rollback required                             Attempt and audit rollback
  Persistence of safety-critical state fails    Fail safely
  AI cycle errors                               Guardian remains running; record error
  Restart                                       Reconcile persisted route with actual network

---

## 19. Wiring Item 17 --- Concurrency and Runtime Safety

### Required Work

- Avoid concurrent route switches.
- Serialize or otherwise protect transport mutations.
- Prevent stale AI decisions from applying after topology/trust
  changes.
- Ensure decision IDs/cycle IDs can correlate telemetry, trust,
  decision, apply, and audit records.
- Avoid holding blocking filesystem/network operations across
  inappropriate async locks.
- Follow the existing Guardian async/runtime architecture.

---

## 20. Wiring Item 18 --- Production Verification

Verification must prove behavior, not merely compilation.

### A. Automatic Startup

Start Guardian normally.

Confirm Task 3 runtime starts without manually invoking any Task 3
example.

### B. Automatic Cycles

Observe at least two production cycles.

Verify timestamps/status/audit artifacts update automatically.

### C. Real Input Proof

Show that:

- local/destination identity comes from runtime state;
- candidate topology comes from real Nebula/CoT state;
- telemetry comes from actual collectors;
- Task2 trust version/state comes from production Task2.

### D. Trust Gate Test

Make a controlled candidate untrusted/quarantined through the legitimate
Task2 test/administrative path.

Verify Task 3 cannot apply it.

### E. Transport Success Test

Where a real supported route transition exists:

```text
AI recommendation
→ production validation
→ transport apply
→ observed network confirmation
→ internal state commit
```

Capture evidence for each stage.

### F. Transport Failure Test

Force or simulate failure at the production transport adapter boundary
using a legitimate test mechanism.

Verify:

```text
apply fails
→ active route is not falsely changed
→ previous route retained/rollback attempted
→ failure audited
```

### G. Restart Test

Restart Guardian/container.

Verify persisted Task 3 state is loaded and reconciled against actual
network state.

### H. D14 Runtime Test

Without executing a demo binary, confirm:

```text
current_decision.json
decisions.jsonl
rewards.jsonl (when AI emits rewards)
degradation_events.jsonl (when applicable)
route_transition_audit.jsonl
```

are generated/updated by production cycles.

---

## 21. AI-Side Work Explicitly Out of Scope

Do **not** use this wiring task to redesign/fix:

- AI scoring algorithms;
- contextual bandit/RL algorithms;
- reward formulas;
- predictor formulas;
- degradation algorithms;
- AI-side persistence semantics already tracked as AI issues;
- current algorithm-specific load-balancing behavior;
- model tuning.

If an AI bug prevents a specific wiring test, document it against its AI
issue and keep the production adapter correct.

Production integration gaps discovered during implementation **are in
scope** and should be fixed.

---

## 22. Merge-Safety Requirement

The production wiring must tolerate a later merge of the corrected
`sgx-anomaly-engine`.

Prefer:

```text
SGX runtime types
      ↓
production adapters
      ↓
small network_ai integration boundary
      ↓
AI crate
```

Avoid:

```text
AI internals spread across main.rs,
Nebula modules,
Task2 modules,
API modules,
and transport implementation
```

This separation is required so later AI fixes do not force a production
networking rewrite.

---

## 23. Definition of Done

Production wiring is complete only when all of the following are true:

- Task 3 starts automatically with Guardian.
- No demo binary is required for normal operation.
- Real telemetry feeds the production cycle.
- Real Nebula/CoT topology feeds route discovery.
- Real Task2 state controls route eligibility.
- Runtime relay health comes from real state.
- AI decisions execute periodically.
- Production persistence updates automatically.
- D14 evidence is produced automatically.
- AI recommendations cannot directly mutate network state.
- Route application occurs only through the transport adapter.
- Successful application is confirmed before internal route commit.
- Failed application does not produce false success.
- Rollback/retention behavior is auditable.
- Restart reconciliation works.
- Missing trust/security-critical state fails closed.
- No production node names, IP addresses, measurements, timestamps,
  trust results, or success results are hardcoded.
- Existing SGX security boundaries remain authoritative.
- Later AI fixes can be merged without rewriting the production
  integration architecture.

---

## 24. Final Implementation Report Required

After wiring is complete, produce a concise report containing:

1. production files added/changed;
2. existing SGX modules reused;
3. adapters implemented;
4. startup integration point;
5. real telemetry sources;
6. real topology sources;
7. Task2 trust source and freshness handling;
8. transport application mechanism;
9. rollback mechanism;
10. persistence paths;
11. D14 automatic audit flow;
12. tests added;
13. commands/tests executed and results;
14. any production wiring gap discovered beyond this plan and how it was
    fixed;
15. any remaining blocker caused specifically by an AI-side issue.
