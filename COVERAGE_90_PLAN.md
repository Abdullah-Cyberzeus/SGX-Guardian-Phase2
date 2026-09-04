# 90% Test Coverage Plan

## Objective

Raise whole-workspace line coverage from **74.81% (39,241/52,457)** to at least **90% (47,212/52,457)**, then prevent it from dropping below 90%.

The current gap is **7,971 newly covered lines**, based on `coverage.txt`. Because the denominator changes as production code is added or removed, every wave must recalculate the gap from a fresh report rather than treating 7,971 as fixed.

## Definition of done

- The canonical full-workspace Tarpaulin run reports at least 90% line coverage.
- CI fails when full-workspace line coverage is below 90%.
- New and changed production logic includes tests for success, error, boundary, and authorization/security paths where applicable.
- Coverage is generated with the same features, exclusions, and test-thread settings locally and in CI.
- Tests are deterministic and do not require real TPM/SE050 hardware, root network changes, or public network access.
- Any excluded generated, platform-only, or harness code is documented and narrowly scoped; exclusions are not used merely to improve the number.

## Baseline findings

The report shows that the gap is concentrated in orchestration, CLI, network/device integration, and large API handlers. The leading per-file gaps to 90% are:

| Priority | File | Current | Lines needed for that file to reach 90% |
|---:|---|---:|---:|
| 1 | `src/main.rs` | 5.88% (116/1,974) | 1,661 |
| 2 | `src/attestation_service.rs` | 66.80% (992/1,485) | 345 |
| 3 | `src/api/handlers/circle.rs` | 64.14% (737/1,149) | 298 |
| 4 | `src/api/handlers/call.rs` | 62.19% (630/1,013) | 282 |
| 5 | `src/crl/gossip/engine.rs` | 40.14% (173/431) | 215 |
| 6 | `src/api/handlers/group_call.rs` | 54.03% (315/583) | 210 |
| 7 | `src/xfer/engine.rs` | 62.13% (461/742) | 207 |
| 8 | `src/netbridge/mod.rs` | 36.56% (121/331) | 177 |
| 9 | `sgx-pa-cli/src/commands/discovery.rs` | 46.31% (163/352) | 154 |
| 10 | `sgx-pa-cli/src/commands/pcr_baseline.rs` | 27.00% (54/200) | 126 |

The existing CI job generates a full report but only enforces **85% on five selected modules**. That scoped gate should remain while coverage is being raised, but it does not protect the workspace-wide target.

## Execution strategy

### Wave 0 — Make measurement reproducible

- Pin the Tarpaulin version used by CI instead of installing an unbounded latest release.
- Add one canonical script or task for the full report, using the current test serialization requirement:

  ```bash
  cargo tarpaulin --workspace --out Stdout --out Xml -- --test-threads 1
  ```

- Confirm whether `--workspace` changes the present denominator; adopt the verified command in both local instructions and CI.
- Archive the text/XML result as a CI artifact and print the workspace total in the job summary.
- Use `scripts/coverage-rank.sh coverage.txt 90` after each run to refresh priorities.
- Classify non-testable lines before excluding anything: generated code, test binaries, OS/hardware adapters, and process entry points. Record each approved exclusion with a reason and owner.

Exit criterion: two clean runs on the same commit produce the same total, apart from an explicitly documented tolerance.

### Wave 1 — Extract and test the process entry points (target: 80%)

The single largest opportunity is `src/main.rs`. Move behavior into library-level functions with injected dependencies, leaving `main()` responsible only for parsing, wiring, and exit status.

- Extract configuration validation, command dispatch, startup decisions, and shutdown handling from `src/main.rs`.
- Introduce small traits/fakes for filesystem, process execution, clock, network, TPM, and secure-element boundaries.
- Add table-driven tests for configuration combinations, invalid inputs, service-selection branches, and startup failures.
- Apply the same pattern to `src/server.rs`, `src/node_listener.rs`, and `src/bin/test_guardian_server.rs` where those files contain real logic.
- Cover inexpensive pure-code gaps in pagination, configuration, policy validation, parsers, and error mapping alongside the refactor.

Milestone: at least **80% (41,966/52,457 at the current denominator)**, requiring about **2,725** additional covered lines.

### Wave 2 — High-value service and API behavior (target: 85%)

- Prioritize `attestation_service`, Circle, call/group-call, CRL gossip, transfer engine, and API CRL handlers.
- Test handlers through in-process routers/services, asserting status, response body, persisted state, and emitted events.
- For every endpoint/service operation, cover: valid request, malformed request, unauthenticated/unauthorized request, missing resource, conflict/idempotent retry, dependency failure, and success.
- Add reusable fixture builders for identities, attestations, circles, calls, CRLs, and transfers to keep tests readable.
- Use deterministic fake clocks and seeded IDs/keys; do not rely on sleeps or random external state.

Milestone: at least **85% (44,589/52,457)**, about **5,348** additional covered lines from the baseline.

### Wave 3 — CLI commands and platform adapters (target: 88%)

- Test CLI parsing and dispatch with process tests only for the thin binary boundary; test command behavior through callable functions.
- Prioritize discovery, PCR baseline, emergency rotation, DKP rotation/revocation, CRL, DID, VC, and attestation commands.
- Replace direct command execution in network, Nebula, TPM, SE050, Wi-Fi, and certificate code with injected runners; assert command arguments and map stdout/stderr fixtures into outcomes.
- Add contract tests for adapter error mapping and fixture-backed parsers. Keep a small, separately labelled hardware integration suite for real-device validation.

Milestone: at least **88% (46,163/52,457)**, about **6,922** additional covered lines from the baseline.

### Wave 4 — Close the residual gap and enable the 90% gate

- Regenerate the ranked report and select remaining files by a combination of uncovered-line count and risk.
- Fill branch/error gaps in security-sensitive areas first: authentication/authorization, attestation, key lifecycle, secure boot, CRL, vault crypto, and transfer verification.
- Review uncovered lines that remain. Test reachable behavior; remove dead code; document only legitimate platform/generated-code exclusions.
- Run the entire suite repeatedly to identify flaky tests before making the gate mandatory.
- Change the full-workspace CI coverage command to include `--fail-under 90`. Retain the scoped module gate if it provides a stricter or faster signal.

Milestone: at least **90%**, with a preferred merge buffer of **90.5% or higher** so small denominator changes do not immediately break the build.

## Maintaining 90%

Once the target is reached:

1. Make the full-workspace `--fail-under 90` job required by branch protection.
2. Run the coverage gate on every pull request that changes Rust source, manifests, build scripts, fixtures, or tests, and on the default branch.
3. Require tests in the same pull request as behavior changes. Bug fixes should include a regression test that fails before the fix.
4. Report both total coverage and changed-line coverage. Use changed-line coverage as a review signal (recommended target: 95%), while the workspace-wide 90% gate remains authoritative.
5. Do not lower the threshold to merge a change. If an exceptional exclusion is necessary, require a written rationale and follow-up issue.
6. Re-run and archive a scheduled weekly coverage report to catch toolchain, feature, or platform drift.
7. Review the ten largest coverage deficits monthly and remove stale/dead code before writing tests solely for coverage.

## Per-wave test checklist

- Happy path and all meaningful result/error variants
- Boundary values, empty values, malformed input, and size limits
- Authentication, authorization, ownership, and tenant/circle isolation
- Persistence success, rollback, retry, conflict, and idempotency
- Timeout/cancellation and dependency-unavailable behavior
- Serialization/deserialization and backward-compatible fixtures
- No real network, privileged host mutation, hardware dependency, wall-clock sleep, or nondeterministic randomness in unit tests
- `cargo fmt -- --check`, `cargo clippy -- -D warnings`, `cargo test --workspace`, and the canonical coverage command pass

## Tracking template

Update this table after each merged wave using a newly generated `coverage.txt`.

| Wave | Date/commit | Covered/total | Coverage | Gap to 90% | Largest remaining hotspot | Status |
|---|---|---:|---:|---:|---|---|
| Baseline | Current report | 39,241/52,457 | 74.81% | 7,971 | `src/main.rs` | Recorded |
| 1 | | | ≥80% | | | Planned |
| 2 | | | ≥85% | | | Planned |
| 3 | | | ≥88% | | | Planned |
| 4 | | | ≥90% | 0 | | Planned |

## Immediate next actions

1. Complete Wave 0 and commit the canonical coverage command/configuration.
2. Open the first implementation slice for extracting testable startup/configuration logic from `src/main.rs`; keep each slice small enough to review independently.
3. Add the reusable fake clock, command runner, and fixture builders needed by later waves.
4. Regenerate `coverage.txt` after every slice and choose the next slice from the ranked report.
5. Enable the workspace-wide 90% CI gate only after the report reaches 90%; until then, ratchet an interim workspace threshold upward at each milestone so coverage cannot regress.
