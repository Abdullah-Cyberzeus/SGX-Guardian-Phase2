# CI benchmarks

This document records measured GitHub Actions timings for the required Rust CI
pipeline. Estimates are not recorded as measurements.

## Pre-change baseline

Recent successful runs of the serial `Build, Test & Security Checks` job took
32–37 minutes. PR #118 retry attempt 2 completed in **36m50s**.

| Step | Measured duration |
|---|---:|
| Coverage | 12m05s |
| `cargo-audit` install and scan | 5m36s |
| `cargo-deny` install and checks | 5m13s |
| Release build | 4m45s |
| Tarpaulin install | 3m55s |
| Unit tests | 2m56s |
| Clippy | 1m21s |

The old combined Cargo cache attempted to archive registry data together with
instrumented, debug, and release targets. Its save step exhausted runner disk,
so these baseline runs rebuilt from scratch.

## Post-change measured results

Source: [PR #125 workflow run 30289251043](https://github.com/Cervais/new-guardian/actions/runs/30289251043).

### Cold full-CI attempt

[Attempt 1](https://github.com/Cervais/new-guardian/actions/runs/30289251043/attempts/1)
started `Classify Changes` at `17:26:34Z` and completed `CI Required` at
`17:40:31Z`: **13m57s measured wall time**.

| Job | Measured duration |
|---|---:|
| Classify Changes | 13s |
| Semgrep | 32s |
| Dependency Policy | 32s |
| Unit Tests | 3m55s |
| Format & Clippy | 1m47s |
| Release Build | 5m32s |
| Coverage | 13m18s |
| CodeQL (separate workflow) | 3m04s |

### Warm full-CI attempt

[Attempt 2](https://github.com/Cervais/new-guardian/actions/runs/30289251043/attempts/2)
started `Classify Changes` at `17:41:20Z` and completed `CI Required` at
`17:51:35Z`: **10m15s measured wall time**.

| Job | Measured duration |
|---|---:|
| Classify Changes | 10s |
| Semgrep | 30s |
| Dependency Policy | 30s |
| Unit Tests | 2m41s |
| Format & Clippy | 46s |
| Release Build | 2m13s |
| Coverage | 9m45s |
| CI Required | 8s |

### Final warning-free setup revision

The final repository-owned protoc installer revision ran without the Node.js
runtime deprecation warning. [CI run 30291436566](https://github.com/Cervais/new-guardian/actions/runs/30291436566)
started `Classify Changes` at `2026-07-27T17:55:31Z` and completed
`CI Required` at `2026-07-27T18:08:57Z`: **13m26s measured wall time**.

| Job | Measured duration |
|---|---:|
| Classify Changes | 10s |
| Semgrep | 31s |
| Dependency Policy | 26s |
| Unit Tests | 3m46s |
| Format & Clippy | 36s |
| Release Build | 2m21s |
| Coverage | 13m05s (`17:55:44Z`–`18:08:49Z`) |
| CI Required | 5s |

The separate [CodeQL run 30291436634](https://github.com/Cervais/new-guardian/actions/runs/30291436634)
completed in **2m32s**, from `2026-07-27T17:55:38Z` to
`2026-07-27T17:58:10Z`.

### Comparison

- The cold 13m57s result has 62.1% lower wall time than PR #118's measured
  36m50s retry and 56.4–62.3% lower wall time than the 32–37 minute baseline range.
- The warm 10m15s result has 72.2% lower wall time than PR #118's measured
  retry and 68.0–72.3% lower wall time than the baseline range.
- The warm attempt has 26.5% lower wall time than the cold attempt, a
  reduction of 3m42s.
- The final warning-free 13m26s result has 63.5% lower wall time than PR #118's
  measured retry and 58.0–63.7% lower wall time than the baseline range.
- All three measured full-CI runs are below the 15-minute target. Their
  nearest-rank sample p95 is 13m57s; more runs are needed for a stable p95.

## Remaining measurements

Documentation-only timing and Actions cache API evidence remain pending.
Additional final-revision full-CI runs are needed to make the sample p95
representative; do not substitute estimates for those measurements.

## Trusted gate overhead

The final PR-local summary in run
[30291436566](https://github.com/Cervais/new-guardian/actions/runs/30291436566)
took 5s and completed 8s after Coverage. That summary was removed because its
logic came from the PR checkout.

The replacement `CI Required` status is evaluated by a base-owned workflow. It
polls every 10s. The first live measurement is final PR #131 head
`84380fb5ea243fb5c3888001e2532c9103ec19a9`:

- [CI run 30298348187](https://github.com/Cervais/new-guardian/actions/runs/30298348187)
  started `Classify Changes` at `2026-07-27T19:32:56Z`, completed Coverage at
  `19:45:24Z`, and completed the pipeline at `19:45:25Z`.
- [Trusted-gate run 30298346665](https://github.com/Cervais/new-guardian/actions/runs/30298346665)
  completed its exact-head evaluation and published `CI Required` at
  `19:45:33Z`; the job completed at `19:45:35Z`.

This is **12m29s measured CI execution wall time** from classification start to
pipeline completion. The trusted gate detected completed CI in **8s**, or 9s
after Coverage, within one configured polling interval. The trusted workflow
started earlier while prior head activity was being cancelled/queued; that
pre-CI wait is separate from the 12m29s execution measurement.

Repeated Rust/protoc/cache setup remains inside the parallel jobs by design;
factoring it into a shared preparation job would serialize the fan-out.
Coverage still repeats the unit suite and owns the approximately 13-minute
critical path. Moving coverage off the PR-required path could reduce latency
but would weaken per-PR evidence, so it remains a documented follow-up rather
than part of this change.
