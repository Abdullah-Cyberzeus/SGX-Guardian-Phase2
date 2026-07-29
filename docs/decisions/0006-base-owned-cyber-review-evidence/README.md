# 0006 — Base-owned exact-SHA evidence for privileged cyber-review

- **Date:** 2026-07-27
- **Category:** CI / trust boundary (sensitive)
- **Issue:** [#121](https://github.com/Cervais/new-guardian/issues/121)
- **PR:** [#131](https://github.com/Cervais/new-guardian/pull/131)

## Context

The cost-lane workflow from ADR 0003 waited for every visible check and commit
status twice: once before model review and again before merge. Both inline loops
downloaded broad result sets, carried a stale exclusion for the retired
`Build, Test & Security Checks` context, and accepted whatever check set happened
to be visible rather than a stable policy contract.

The privileged AI job then installed Rust and protoc and prompted the model to
rerun Clippy, check, tests, audit, and deny after deterministic CI had already
performed those jobs. The checkout also supplied `gate.py` and
`file_findings.py`, so a PR could propose the policy code later executed by a
job with write permissions. The merge job exposed the organization admin token
while it polled for up to 40 minutes.

## Decision

1. Run the secret-bearing workflow only from the base branch through
   `pull_request_target`. Remove `workflow_dispatch`, because its caller can
   select a PR branch's workflow definition. Check out the exact PR head only
   as non-executable review data, with persisted Git credentials disabled.
2. Treat two contexts as the complete deterministic evidence contract:
   `CI Required` and `Static Analysis (CodeQL)`. Both must be successful on the
   exact classified PR head SHA. Missing results remain pending; failed,
   cancelled, neutral, duplicate, malformed, stale-SHA, and moved-head results
   fail closed.
3. Centralize that policy in tested `.github/cyber-review/ci-gate.sh`. The
   workflow loads it from the exact base commit and uses its narrow GraphQL
   projection before model review and immediately before merge.
4. Deterministic CI owns builds, lint, tests, dependency policy, and CodeQL.
   The model reviews their adequacy and the patch but does not rerun
   PR-controlled commands. Rust/protoc setup is removed, and the model tool set
   is explicitly allowlisted to `Read`, `Grep`, and `Glob`, with shell and
   mutation tools also denied. The Claude action enforces a findings JSON
   schema; trusted workflow steps materialize and gate that structured action
   output rather than asking the model to write a file.
5. Load the deterministic severity and issue-filing scripts from the exact base
   commit as well. PR content remains the subject of review, never the source of
   privileged policy.
6. Expose the organization admin token only in the final opt-out/head recheck
   and exact-SHA merge step, after required CI has passed under the ordinary
   read-only workflow token.
7. Require `CI Required`, `Static Analysis (CodeQL)`, and `Cyber-review gate`
   in ruleset `18809646`. Because ruleset mutation takes effect immediately and
   is not reviewable in this pull request, adding the currently absent
   `CI Required` context is an explicit post-merge administrator gate.

## Consequences

- The independent LLM security review and workflow-driven merge semantics from
  ADR 0003 remain, but their trust boundary is explicit and base-owned.
- Manual dispatch is removed; applying `re-review` is the sole rerun mechanism
  and keeps the privileged workflow definition on the base branch.
- One minimal GraphQL response replaces two REST result collections per poll,
  and the duplicated polling implementation is eliminated.
- The model no longer spends time or tokens repeating deterministic build
  evidence. Its review duration remains variable and must be measured after
  this workflow reaches the default branch.
- A future required deterministic check must first be incorporated into either
  the trusted `CI Required` policy or this exact evidence contract; unrelated
  optional checks do not stall cyber-review.
- Until the post-merge ruleset update is applied, workflow-driven merges still
  fail closed on `CI Required`, but the GitHub ruleset itself does not enforce
  that context for other merge paths.

## Supersedes

This narrows ADR 0003's broad “all other checks are green” polling design and
ADR 0001's retired `Build, Test & Security Checks` context.
