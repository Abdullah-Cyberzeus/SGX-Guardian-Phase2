# Cyber-review benchmarks

This document separates measured GitHub Actions durations from expected effects.
Do not treat removed steps or configured polling intervals as measured runtime
until a post-merge AI-lane run exercises the default-branch workflow.

## Previous design

Source: [PR #125 Cybersecurity Review Gate run 30296576083](https://github.com/Cervais/new-guardian/actions/runs/30296576083),
started `2026-07-27T19:03:42Z` and completed `2026-07-27T19:12:58Z`.

| Scope | Measured duration |
|---|---:|
| Whole workflow | 9m16s |
| Cyber-review gate job | 8m39s |
| Rust + protoc setup | 16s |
| Model review step | 8m02s |
| Merge job | 13s |
| Broad pre-review result poll | 3s |

The result poll happened after CI was already green, so the 3s measurement does
not expose its former 30-second polling lag under load. The merge job's single
combined polling-and-merge step took 9s in that run.

### Observed merge-before-CI-failure race

[PR #127](https://github.com/Cervais/new-guardian/pull/127) demonstrates the
failure mode that broad old-gate polling allowed. GitHub records the PR merge
at `2026-07-27T19:25:48Z`; the old
[cyber-review run 30297047535](https://github.com/Cervais/new-guardian/actions/runs/30297047535)
completed its merge job at `19:25:51Z`. The old monolithic
[CI run 30297047466](https://github.com/Cervais/new-guardian/actions/runs/30297047466)
was still active and failed with `No space left on device` at `19:33:24Z`.

The deterministic CI failure therefore arrived **7m36s after GitHub's recorded
merge** and **7m33s after the merge job completed**. This is direct evidence
that the old gate could merge without waiting for the actual build result.

## Redesigned workflow

No post-change AI-lane runtime is measured yet. GitHub evaluates
`pull_request` workflow definitions from the base branch, so the implementing
PR cannot exercise its redesigned cyber-review workflow before merge.

| Scope | Current measurement |
|---|---:|
| Whole workflow | Not yet measured |
| Cyber-review gate job | Not yet measured |
| Rust + protoc setup | Removed (16s measured previously) |
| Model review step | Not yet measured |
| Exact-SHA CI query/poll | Not yet measured |
| Upstream `CI Required` publication after CI completed | 8s |
| Merge job | Not yet measured |

The redesign removes prompt-driven Clippy, check, test, audit, and deny reruns;
the already-green `CI Required` status is now the build/test/dependency evidence.
It also replaces each pair of broad REST calls with one narrow GraphQL query
that projects only PR head identity plus status/check names and conclusions.
The review context reuses the checked-out diff instead of downloading the PR
file list a second time.
The shared poll interval is 10 seconds instead of 30 seconds, but the resulting
latency reduction is not a measurement.

The 8s value above measures the base-owned producer of `CI Required`, not the
redesigned model workflow. On final PR #131 head
`84380fb5ea243fb5c3888001e2532c9103ec19a9`,
[CI run 30298348187](https://github.com/Cervais/new-guardian/actions/runs/30298348187)
completed at `19:45:25Z` and
[trusted-gate run 30298346665](https://github.com/Cervais/new-guardian/actions/runs/30298346665)
completed evaluation/published the result at `19:45:33Z`. Coverage had
completed at `19:45:24Z`, making publication 9s after the critical-path job and
within the producer's configured 10-second polling interval.

### Failed output-path trial (not a successful current benchmark)

[Run 30304269615](https://github.com/Cervais/new-guardian/actions/runs/30304269615)
exercised the proposed AI lane on PR #131 head
`a16142b145c9a29f88d469ccc22702ba67462bfd`. The cyber-review job ran from
`20:50:28Z` to `20:56:04Z` (**5m36s**) and the Claude action step ran from
`20:50:43Z` to `20:56:00Z` (**5m17s**). The action reported a successful
296.622-second, 20-turn model session costing **$0.76082905**, but also reported
two permission denials and produced no `.github/cyber-review/findings.json`.
The base-owned severity gate correctly failed closed.

This run measures a failed file-output contract, not successful redesigned
cyber-review latency. The fix consumes the action's schema-validated
`structured_output` and materializes it under `RUNNER_TEMP` without granting
the model Bash or filesystem-write tools. Keep the current successful benchmark
fields marked “Not yet measured” until that complete path passes.

### Successful output, security-blocked trial (not a successful current benchmark)

[Run 30306455829](https://github.com/Cervais/new-guardian/actions/runs/30306455829)
exercised the structured-output path on PR #131 head
`8a7e305754beffaa8dba8461aef37e80a88c19b6`. The workflow ran from
`21:20:40Z` to `21:26:03Z` (**5m23s**), the cyber-review gate job ran from
`21:21:01Z` to `21:26:02Z` (**5m01s**), and the model step ran from
`21:21:12Z` to `21:26:00Z` (**4m48s**). The action returned schema-valid
structured findings, the workflow materialized them, and the base-owned
severity gate correctly blocked one critical and one high security finding.

This proves the structured-output handoff, but it is not a successful current
benchmark: the workflow was manually dispatched from the PR branch and failed
its security policy. The fix removes manual dispatch, changes the trigger to
base-owned `pull_request_target`, and explicitly allowlists only `Read`, `Grep`,
and `Glob`. Measure the first complete held-PR review after this policy reaches
`main`; keep the current successful benchmark fields marked “Not yet measured”
until then.

## Next benchmark

On the first post-merge, non-fast-lane PR:

1. Record the workflow, cyber-review job, model step, exact-SHA wait, and merge
   job timestamps from `gh run view <run-id> --json jobs`.
2. Compare model duration separately from deterministic wait and setup so model
   variability does not hide workflow overhead.
3. Add the measured values above; retain this baseline for before/after review.
