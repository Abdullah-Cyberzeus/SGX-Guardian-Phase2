# 0004 — Base-owned required CI status gate

- **Date:** 2026-07-27
- **Category:** CI / branch-protection (sensitive)
- **Issue:** [#119](https://github.com/Cervais/new-guardian/issues/119)
- **PR:** [#125](https://github.com/Cervais/new-guardian/pull/125)

## Context

PR #125 originally computed `CI Required` in `.github/workflows/ci.yml` and
executed its decision script from the pull request checkout. A contributor
could therefore change the gate in the same PR it judged, while still
publishing the trusted-looking required check name.

The parallel build jobs should remain on the ordinary `pull_request` event:
they intentionally execute PR code with a restricted token. Only the final
required-status decision needs elevated trust.

## Decision

1. Remove the PR-local `CI Required` job and reserve that exact context for a
   `pull_request_target` workflow loaded from the default branch.
2. The trusted workflow checks out only the default branch, with persisted
   credentials disabled, and never downloads or executes PR code or artifacts.
3. It classifies changed filenames from the pull request API, finds the
   `CI Pipeline` workflow run for the exact PR head SHA and workflow ID, and
   fails closed on missing, duplicate, skipped, cancelled, or failed required
   jobs. Documentation-only changes may have heavy jobs skipped; workflow,
   configuration, script, and runtime changes require every heavy job to pass.
4. The trusted workflow publishes the `CI Required` commit status on the exact
   PR head SHA with least-privilege `statuses: write`; its own job has a
   different name to avoid duplicate required-check contexts.

## Consequences

- Pull request changes cannot replace the required-status decision logic or
  satisfy it with a stale workflow run from another SHA.
- The gate adds at most one polling interval after the slowest CI job and uses
  one base checkout. The old PR-local summary checkout/job is removed.
- The first landing is a bootstrap exception: GitHub runs
  `pull_request_target` workflows only when their workflow file exists on the
  default branch. PR #125 must therefore be reviewed and landed using the
  existing administrative path; `CI Required` should be required for
  subsequent PRs after this workflow reaches `main`.
- The parallel jobs keep repeated setup intentionally. A shared preparation
  job would serialize the fan-out and lengthen the critical path.

## Supersedes

This narrows ADR 0001's required-check design: the deterministic CI context is
now emitted only by base-owned policy rather than PR-owned workflow code.
