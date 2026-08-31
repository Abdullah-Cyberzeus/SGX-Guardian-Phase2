# Workspace Coverage Plan: 51.29% to 90%+

## Objective

Raise workspace-wide Rust line coverage from the current baseline to at least 90% without changing application behavior or removing features.

Current baseline from `coverage.txt`:

- Covered lines: 26,906
- Total executable lines: 52,456
- Current coverage: 51.29%
- Covered lines required for 90%: 47,211
- Additional covered lines required: 20,305
- Final working target: 91–92%, providing a buffer for small instrumentation changes

The first 28 high-priority files can raise overall coverage to approximately 70.62% if every one reaches 90%. Workspace-wide 90% will require covering the longer tail of approximately 150–200 files as well.

## Expected checkpoints

These estimates assume that each ranked target is brought to approximately 90% file coverage.

| Ranked targets completed | Estimated workspace coverage |
|---:|---:|
| Top 20 files | 68.01% |
| Top 40 files | 74.40% |
| Top 60 files | 79.02% |
| Top 80 files | 82.16% |
| Top 100 files | 84.62% |
| Top 150 files | 88.67% |
| Top 200 files | 90.51% |

## Test placement rules

### Add tests inside `src` files when testing

- Private functions and internal types
- Parsing, validation and normalization helpers
- Internal state transitions
- Error conversion and formatting
- Environment and configuration handling
- Cryptographic payload construction and verification helpers
- Command construction before an operating-system process is invoked

Use this structure:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Focused unit tests for private behavior.
}
```

### Add tests under `tests/` when testing

- HTTP routes and complete request/response behavior
- Authentication and authorization middleware
- Public workflows spanning multiple modules
- CLI executable behavior and exit codes
- Interactions between independently public components

Consolidate related integration tests into domain-level files. Do not create a separate integration-test binary for every source file because that increases compilation time and disk usage.

### Isolation requirements

- Do not access real TPM, secure-element or networking hardware.
- Do not modify real firewall, routing, Wi-Fi or system-service state.
- Do not require root privileges or internet access.
- Use temporary directories for persistence tests.
- Mock process results, network responses and external providers.
- Serialize tests that mutate process-wide environment variables.
- Avoid timing-dependent sleeps; use paused time, channels or deterministic synchronization where possible.

## Wave 0 — Baseline and coverage controls

- [ ] Preserve the current `coverage.txt` as the 51.29% baseline.
- [ ] Generate a machine-readable JSON or LCOV report at every major checkpoint.
- [ ] Rank files by the number of lines needed to reach 90%, not only by current percentage.
- [ ] Keep production code and generated files in the report consistently between runs.
- [ ] Confirm that every newly added test passes alone before running full coverage.

Acceptance criteria:

- The test suite has a reproducible baseline.
- Coverage runs use the same workspace, features and engine.
- Coverage changes can be attributed to each wave.

## Wave A — Startup and application assembly

Primary target:

- `src/main.rs` — 10/1,974 lines, 0.51%

Placement: primarily in-file unit tests.

Cover:

- [ ] Environment-variable defaults and overrides
- [ ] Configuration construction
- [ ] Address and port parsing
- [ ] Feature enable/disable branches
- [ ] Router and application-state construction
- [ ] Invalid configuration paths
- [ ] Startup validation before services bind
- [ ] Graceful-shutdown helpers
- [ ] Error formatting and propagation
- [ ] Command-line mode selection
- [ ] Disabled-service and optional-component branches

Do not launch real long-running servers or system daemons. If startup code is monolithic, test private helpers directly and use test-only service substitutes where existing abstractions permit them.

Target:

- Initial file target: 70–80%
- Final file target: at least 90% where startup-only operating-system branches are testable

## Wave B — Large API handlers

Targets:

- `src/api/handlers/call.rs`
- `src/api/handlers/circle.rs`
- `src/api/handlers/pwa.rs`
- `src/api/handlers/group_call.rs`
- `src/api/handlers/vault.rs`
- `src/api/handlers/devices.rs`
- `src/api/handlers/crl.rs`
- `src/api/handlers/xfer.rs`
- `src/api/handlers/chat.rs`
- `src/api/handlers/auth.rs`
- `src/api/handlers/ha_integrations.rs`

Placement: in-file tests for private helpers and consolidated integration tests for routes.

Suggested integration files:

```text
tests/cov_api_call_circle_test.rs
tests/cov_api_storage_transfer_test.rs
tests/cov_api_security_test.rs
tests/cov_api_homeassistant_test.rs
```

In-file coverage:

- [ ] Private request validation
- [ ] Identifier parsing and normalization
- [ ] Permission and policy decisions
- [ ] Internal state conversion
- [ ] Invalid transition handling
- [ ] Error-to-response mapping
- [ ] Serialization and response helpers

Router coverage:

- [ ] Successful requests
- [ ] Missing and malformed request bodies
- [ ] Authentication failures
- [ ] Insufficient permissions
- [ ] Missing records
- [ ] Duplicate and conflicting requests
- [ ] Invalid state transitions
- [ ] Storage failures
- [ ] Correct status codes and JSON bodies
- [ ] Idempotency behavior

Use Axum router requests through `tower::ServiceExt::oneshot`; do not start a TCP listener.

Expected workspace checkpoint: approximately 61–66%.

## Wave C — Attestation, certificates, CRL and transfers

Targets:

- [x] `src/attestation_service.rs`
- [x] `src/crl/gossip/engine.rs`
- [x] `src/crl/gossip/emergency.rs`
- [x] `src/crl/gossip/store.rs`
- [x] `src/crl/offline/sync.rs`
- [x] `src/cert_client.rs`
- [x] `src/xfer/engine.rs` (already had adequate coverage, no gaps found)
- [x] `src/xfer/store.rs`
- [x] `src/nebula/registry_sync.rs`
- [x] `src/nebula/overlay_registry.rs`

Placement: in-file tests for private state machines and integration tests for public workflows.

Cover:

- [ ] Valid, expired and malformed attestations
- [ ] Signature and certificate verification failures
- [ ] PCR mismatch paths
- [ ] Missing keys and corrupted persisted state
- [ ] CRL merge, duplicate and stale-entry handling
- [ ] Gossip request and response variants
- [ ] Empty peer lists and unreachable peers
- [ ] Emergency propagation
- [ ] Offline queue recovery
- [ ] Transfer creation, resume, failure and cancellation
- [ ] Transfer cleanup and persistence errors
- [ ] Registry conflict resolution
- [ ] Network timeout and malformed-response handling

Expected workspace checkpoint: approximately 68–72%.

## Wave D — Network bridge, automation and runtime

Targets:

- [x] `src/netbridge/mod.rs`
- [x] `src/netbridge/routing.rs`
- [x] `src/netbridge/uplink_monitor.rs`
- [x] `src/netbridge/dhcp_client.rs`
- [x] `src/netbridge/process.rs`
- [x] `src/netbridge/nat.rs`
- [x] `src/netbridge/wifi_client.rs`
- [x] `src/netbridge/validator.rs`
- [x] `src/runtime/runtime_manager.rs`
- [x] `src/automation/engine.rs`
- [x] `src/rules/exec/actions.rs`
- [x] `src/rules/exec/mod.rs`
- [x] `src/device/manager.rs`
- [x] `src/discovery/scheduler.rs`

Placement: primarily in-file unit tests with mocked command and provider results.

Cover:

- [ ] Generated executable names and command arguments
- [ ] Interface and network validation
- [ ] Routing and NAT decisions
- [ ] Process success, failure and signal interpretation
- [ ] DHCP lease variants
- [ ] Uplink state transitions
- [ ] Automation matching, suppression and conflicts
- [ ] Rule action dispatch and guard failures
- [ ] Runtime start, stop and restart transitions
- [ ] Duplicate operations
- [ ] Partial failures and rollback
- [ ] Scheduler boundaries, cancellation and retry

Expected workspace checkpoint: approximately 76–80%.

## Wave E — Home Assistant, integrations and threat services

Targets:

- `src/nest/ha_config_flow.rs`
- `src/kasa/ha_config_flow.rs`
- `src/homeassistant/websocket.rs`
- `src/integration/manager.rs`
- `src/integration/refresh_worker.rs`
- `src/notify/mod.rs`
- `src/api/handlers/ha_automations.rs`
- `src/api/handlers/ha_devices.rs`
- `src/api/handlers/ha_notifications.rs`
- `src/api/handlers/ha_telemetry.rs`
- `src/api/handlers/ha_websocket.rs`
- `src/api/handlers/notify.rs`
- `src/api/handlers/geofence.rs`
- `src/api/handlers/threat.rs`
- `src/threat/service.rs`
- `src/threat/blocker.rs`
- `src/threat/rule_manager.rs`

Placement: in-file tests for private provider logic and router tests for public endpoints.

Cover:

- [ ] Configuration-flow success and rejection
- [ ] Missing and invalid credentials
- [ ] Token refresh and expiry
- [ ] Retry and circuit-breaker behavior
- [ ] WebSocket connect, message, parse-error and disconnect paths
- [ ] Provider lookup and disabled-provider failures
- [ ] Notification preferences, filtering and missing subscribers
- [ ] Threat-rule matching
- [ ] Duplicate and expired alerts
- [ ] Block and unblock behavior
- [ ] Mocked operating-system command failures
- [ ] API response mappings

Expected workspace checkpoint: approximately 82–85%.

## Wave F — CLI workspace package

First-priority CLI files:

- `sgx-pa-cli/src/commands/attest_quote.rs`
- `sgx-pa-cli/src/commands/vc.rs`
- `sgx-pa-cli/src/commands/crl.rs`
- `sgx-pa-cli/src/commands/did.rs`
- `sgx-pa-cli/src/commands/emergency_rotate.rs`
- `sgx-pa-cli/src/commands/pcr_baseline.rs`
- `sgx-pa-cli/src/commands/transport.rs`
- `sgx-pa-cli/src/commands/threat.rs`

Second-priority CLI files:

- `sgx-pa-cli/src/commands/audit_logs.rs`
- `sgx-pa-cli/src/commands/diddoc.rs`
- `sgx-pa-cli/src/commands/dkp_rotate.rs`
- `sgx-pa-cli/src/commands/audit_verify.rs`
- `sgx-pa-cli/src/commands/attestation.rs`
- `sgx-pa-cli/src/main.rs`
- All remaining CLI command files below 90%

Placement: in-command unit tests plus a small number of consolidated binary integration tests.

Unit coverage:

- [ ] Argument conversion
- [ ] Input validation
- [ ] Output formatting
- [ ] JSON and table rendering
- [ ] File loading and parsing
- [ ] Invalid identifiers
- [ ] Missing arguments
- [ ] Service-response interpretation
- [ ] Error conversion

Executable coverage:

- [ ] `--help` and version behavior
- [ ] Invalid subcommands and arguments
- [ ] Missing input files
- [ ] Exit codes
- [ ] Machine-readable output
- [ ] Server-unavailable responses

The original first eight CLI targets combined with the first 20 source targets can bring estimated workspace coverage to approximately 70.62%. The later waves must also be completed to reach 90%.

## Wave G — Hardware and secure-element boundaries

Targets:

- `src/tpm/tools.rs`
- `src/tpm/dkp.rs`
- `src/tpm/dik.rs`
- `src/tpm/ek.rs`
- `src/tpm/pcr.rs`
- `src/tpm/signer.rs`
- `src/secure_element/dkp.rs`
- `src/secure_element/se050.rs`
- `src/secure_element/sign.rs`
- `src/secure_element/key_storage.rs`
- `src/secure_element/secure_boot.rs`

Placement: in-file tests using existing traits, fake implementations and deterministic command-output fixtures.

Cover:

- [ ] Command construction without executing hardware tools
- [ ] Successful and failed command-output parsing
- [ ] Missing-device behavior
- [ ] Malformed key, PCR and certificate data
- [ ] Key lifecycle state transitions
- [ ] Secure-boot validation branches
- [ ] Unsupported-operation errors
- [ ] Timeout and process-failure conversion

Real hardware tests must remain separate and ignored unless explicitly run in a suitable environment.

## Wave H — Remaining high-gain files

Continue in descending order of lines required to bring each file to 90%. Important remaining groups include:

- API handlers below 90%
- Netbridge services below 90%
- Rules execution
- Chat gRPC client/server
- Circle snapshot and invitation handling
- Discovery scheduler and runner
- Vault ingest, wrapper, persistence and quota
- Backup handlers and restore branches
- CoT transports and failover
- Nebula lifecycle, daemon, lighthouse and registry modules
- Notification and policy management
- Server and client startup modules

For each file:

- [ ] Record current covered/total lines.
- [ ] Read its exact uncovered-line list.
- [ ] Test pure and private branches in-file first.
- [ ] Add integration coverage only for cross-module behavior.
- [ ] Run the narrow test target.
- [ ] Regenerate coverage after each logical group.
- [ ] Stop adding tests once the file exceeds 90%, unless uncovered security-critical behavior remains.

Expected workspace checkpoint after approximately 150 ranked files reach 90%: about 88.67%.

## Wave I — Final 90% closure

- [ ] Regenerate the complete workspace coverage report.
- [ ] Re-rank every file still below 90%.
- [ ] Target the largest remaining uncovered-line contributions.
- [ ] Cover missed error paths and boundary branches.
- [ ] Check that test-only code is not counted as production coverage.
- [ ] Investigate files showing zero coverage despite passing tests.
- [ ] Remove test flakiness and shared-state dependencies.
- [ ] Run the complete suite more than once.
- [ ] Reach at least 91–92% before declaring completion.

Expected checkpoint after approximately 200 ranked files reach 90%: about 90.51%.

## Test commands

### Run all library unit tests

```bash
CARGO_PROFILE_TEST_DEBUG=0 \
CARGO_BUILD_JOBS=4 \
cargo test --lib -- --test-threads=4
```

### Run a particular in-file test module

```bash
CARGO_PROFILE_TEST_DEBUG=0 \
cargo test --lib api::handlers::call::tests -- --test-threads=1
```

### Run one integration-test file

```bash
CARGO_PROFILE_TEST_DEBUG=0 \
cargo test --test TEST_FILE_NAME -- --test-threads=1
```

### Run the CLI package tests

```bash
CARGO_PROFILE_TEST_DEBUG=0 \
CARGO_BUILD_JOBS=4 \
cargo test -p sgx-pa-cli -- --test-threads=4
```

### Generate full LLVM coverage

```bash
CARGO_INCREMENTAL=0 \
CARGO_PROFILE_TEST_DEBUG=0 \
CARGO_PROFILE_DEV_DEBUG=0 \
CARGO_BUILD_JOBS=4 \
RUST_TEST_THREADS=4 \
cargo tarpaulin \
  --workspace \
  --locked \
  --jobs 4 \
  --engine llvm \
  --skip-clean \
  --out stdout \
  --timeout 120 \
  -- --test-threads=4
```

## Completion criteria

- [ ] Workspace line coverage is at least 90%.
- [ ] Preferred final coverage is 91–92%.
- [ ] Production logic and externally visible behavior remain unchanged.
- [ ] All new tests pass individually and in the complete suite.
- [ ] No default test requires root, internet or real hardware.
- [ ] Files and environment variables are isolated between tests.
- [ ] Coverage uses the same workspace scope and feature set as the baseline.
- [ ] The final report and validation commands are documented.

## Progress log

### Wave 1 / Wave A — first test batch added

- [x] Added in-source `src/main.rs` coverage for environment truth parsing.
- [x] Added semantic JSON comparison and plain-text fallback coverage.
- [x] Added isolated fake-`nebula-cert` success, failure and private-IP parsing coverage.
- [x] Added missing runtime PCR snapshot coverage.
- [x] Added the admin TLS alias occupied-bind error path.
- [ ] Continue through the large startup and application-assembly body.

### Wave 2 / Wave B — first test batch added

- [x] Added call request defaults and cursor deserialization coverage.
- [x] Added invalid caller-role, target-role and media policy responses.
- [x] Added missing, malformed, incomplete TURN and valid ICE-server configuration coverage.
- [x] Added PWA enrollment claim parsing and lookup coverage.
- [x] Added PWA enrollment expiry and view-state coverage.
- [x] Added PWA secret, hash, display-name, role, presence and registration-duration coverage.
- [ ] Continue with state-backed call, circle, group-call, vault, device, CRL, transfer, chat, auth and Home Assistant handler branches.

### Wave 3 / Wave C — completed

- [x] `attestation_service.rs`: 12 new tests on `SignedQuote::verify` and `AttestationQuote::sign` — signature failures, wrong-key rejection, nonce replay, expiry/staleness, PCR-mismatch-vs-baseline, boot-chain failure, malformed-JSON parse failure. `compute_local_baseline_status` left untested (hardcoded `/var/lib` and `/etc` paths, no override point — would need a refactor).
- [x] `crl/gossip/store.rs`: 20 new tests — merge conflict resolution (entry vs entry, entry vs tombstone, tombstone vs tombstone), duplicate/stale handling, peer-notified threshold logic, corrupted-persisted-state error surfacing. Full checklist covered (pure/filesystem-only file, no network needed).
- [x] `crl/gossip/engine.rs`: 15 new tests — peer filtering matrix, threshold math, round counters, audit helpers, batch verification rejection paths. Network round-trip functions (`round_task`, `exchange_with_peer`, `listener_task`, `handle_inbound`) intentionally skipped (need live TCP).
- [x] `crl/gossip/emergency.rs`: 10 new tests — dedup fingerprint set, DID-to-device-id resolution, identity loading, notice counters, broadcast pure gate conditions. Live UDP paths (`listener_task`, `handle_notice`, `rebroadcast`, `broadcast_once`) intentionally skipped.
- [x] `crl/offline/sync.rs`, `cert_client.rs`, `xfer/store.rs`: tests added in an earlier session pass (sync-state persistence, pending/settlement, cert marker/write/membership-VC flows, receiver/outbox/inbox lifecycle).
- [x] `xfer/engine.rs`: already had ~1029 lines of tests from a prior session; reviewed against the checklist, no gaps found.
- [x] `nebula/registry_sync.rs`: 27 new tests — snapshot payload parsing, atomic writes, overlay/lighthouse/relay snapshot application, conflict handling. Live-socket functions and hardcoded `/var/lib` cache paths intentionally skipped.
- [x] `nebula/overlay_registry.rs`: 27 new tests — IP/CIDR validation matrix, conflict resolution, corrupted/missing persisted state. Full checklist covered.
- Note: full combined workspace `cargo test` was not re-run after Wave C (each file verified with its own narrow test target) because the machine's root filesystem was at 100% disk usage at the time.

### Wave 4 / Wave D — completed

- [x] All 14 targets covered: 216 tests passing (0 failed) across `netbridge::` (81), `runtime::runtime_manager` (20), `automation::engine` (34), `rules::exec::` (49), `device::manager` (21), `discovery::scheduler` (11).
- [x] netbridge cluster: command/parse logic for routing, NAT policy merge, DHCP/Wi-Fi/uplink orchestrators, process lifecycle (start/stop/restart/signals/duplicate calls), interface/port validation — all via mocked commands and fixture interfaces, no real network/firewall/root touched.
- [x] `runtime_manager.rs`: mode transitions, interface fallback/dedup, supervised-transition abort-on-duplicate.
- [x] `automation::engine`: rule CRUD + persistence, condition/trigger matching, action dispatch (delay/notification/command), failure-policy handling (abort/continue/log/retry), conflict resolution, pending-timer restore.
- [x] `rules::exec`: action dispatch for every `RuleAction` variant via safe/mocked paths, guard cooldown/rate-cap, outcome aggregation, execution log append/list with cap and corruption handling.
- [x] `device::manager`: Nest/Ecobee entity classification, state reconciliation, command dispatch against a mocked HA server, unit-system caching/fallback.
- [x] `discovery::scheduler`: nmap run success/failure/parse-failure via a fixture-XML hook (no real scans), schedule period/name mapping, config/whitelist seeding.
- Verified with the full narrow-module `cargo test` run across all six module groups — 216 passed, 0 failed.
