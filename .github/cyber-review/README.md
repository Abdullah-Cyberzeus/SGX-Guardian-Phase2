# Cybersecurity Review Gate

A security-first LLM review of each PR to `main` that blocks merge on
high-confidence critical findings (pre-GA posture, ADR 0002) and drives the
merge itself on pass (ADR 0003).

## Cadence & cost lanes (ADR 0003)

- The review runs **once per ready PR** (`opened`/`reopened`/`ready_for_review`),
  not on every push. Re-run it with the **`re-review`** label (auto-removed).
- The secret-bearing workflow uses `pull_request_target`, so its definition
  comes from the base branch. Manual dispatch is intentionally unavailable
  because GitHub permits selecting a PR branch's workflow definition.
- Docs-only PRs are **fast-laned**: no model call; they merge on green CI with
  an audit comment. (Deletions-only diffs get full review — removing code can
  remove a security control.)
- **CI-first:** the model only runs after the exact head SHA has successful
  `CI Required` and `Static Analysis (CodeQL)` contexts — red PRs cost nothing.
- **Model tiering:** Haiku for routine diffs; Sonnet for security-relevant paths.
- On gate pass + green CI the workflow **squash-merges** (org `TOKEN`, admin
  bypass) and deletes the branch. Opt out per PR with the **`hold`** label, a
  "DO NOT MERGE" title marker, or draft status — re-checked at merge time.

## What "passing" means

Merge is gated by two tiers of check. **All required checks must be green** for
auto-merge to fire.

### Tier 1 — deterministic (the reliable gates)
Run by `CI Pipeline` (`.github/workflows/ci.yml`) and `CodeQL Analysis`:
- `cargo fmt --check`, `cargo clippy -- -D warnings`
- `cargo test`
- `cargo audit`, `cargo deny check`, Semgrep
- `cargo build --release`
- CodeQL static analysis

The cyber-review waits for exactly two base-owned result contexts on the
classified PR head SHA:

- `CI Required`, published by `.github/workflows/trusted-ci-required.yml` only
  after the required `CI Pipeline` jobs pass.
- `Static Analysis (CodeQL)`, published by `.github/workflows/codeql.yml`.

The base-owned `CI Required` gate compares the exact base/head Git blobs for
the CI and CodeQL workflows, repository helpers, and policy-bearing tool
configuration; otherwise a contributor could preserve required job names while
replacing commands or helpers. Legitimate changes to that trusted surface
require review and a restricted ruleset bypass (ADR 0007). Stale base SHAs
fail closed.

Missing contexts remain pending, failed/cancelled/neutral contexts fail closed,
and a moved head or duplicate required context fails closed. The same tested
`.github/cyber-review/ci-gate.sh` policy is used before review and immediately
before merge.

The repository ruleset must also require branches to be up to date
(`strict_required_status_checks_policy: true`). The runtime check cannot revoke
an already-successful commit status if `main` advances later.

The live `Cyber-review required checks` ruleset (ID `18809646`) must require
`CI Required`, `Static Analysis (CodeQL)`, and `Cyber-review gate`. At the time
of this change it still lists only the latter two; a repository administrator
must add `CI Required` after this base-owned policy reaches `main`. The workflow
fails closed on `CI Required` independently, so the admin update strengthens
manual/ruleset enforcement rather than creating the workflow gate.

### Manual and admin delivery precondition

Prefer the workflow-owned merge step. If that step is broken and a manual or
admin merge is proposed, delivery automation must first pin the current PR head
SHA and inspect only checks and statuses attached to that SHA. It must refuse
the merge while any required context is pending, missing, failed, stale, or
belongs to a different head.

Immediately before merging, re-fetch the PR head and require it to match the
pinned SHA. The current head must have successful `CI Required` and
`Static Analysis (CodeQL)` evidence plus a successful exact-head
`Cyber-review gate` for an AI-lane review. A docs fast lane must instead have a
successful current-head classification from the base-owned cyber-review
workflow. Adding or rebasing a commit invalidates the evidence and requires a
fresh run.

Admin capability is not approval to bypass these preconditions. Trusted CI
definition changes that intentionally fail the base-owned manifest comparison
require explicit authorization for the restricted ruleset-bypass path described
by ADR 0007; delivery automation must stop and request that authorization.

### Tier 2 — LLM cyber-review (this workflow)
`.github/workflows/cyber-review.yml` runs a multi-dimension review (security,
static evidence, test adequacy, architecture, simplification) and **ingests
CodeRabbit's findings as an additional input**. The action requires the model
to return schema-validated structured findings, which the workflow materializes
under `RUNNER_TEMP`; the model does **not** write repository files or decide
merge-ability.

Deterministic CI owns compilation, lint, tests, dependency checks, and CodeQL.
The privileged AI job does not install Rust or protoc and does not execute
pull-request-controlled build, test, package, dependency, generator, or policy
scripts. It checks out the exact PR head only as review data, without persisted
Git credentials, and receives a non-executable diff/context bundle. The Claude
action explicitly allows only `Read`, `Grep`, and `Glob` while also denying
shell and mutation tools. Severity and issue-filing policy scripts are loaded
from the exact base commit rather than the PR checkout.

`.github/cyber-review/gate.py` applies a fixed, phase-dependent policy (ADR 0002):

> **Pre-GA** (`PRE_GA: "true"` in the workflow, current setting): **block** iff
> `severity = critical` **and** `confidence ∈ {high, medium}`.
> **Release/hardening posture** (`PRE_GA` unset): **block** iff
> `severity ∈ {critical, high}` **and** `confidence ∈ {high, medium}`.

Rationale: the LLM is non-deterministic, so only *high-confidence, high-severity*
findings gate. During feature buildout, blocking on every high produced an
open-ended fix/rescan loop; instead, highs and below are converted into tracked
debt (below) and one dedicated hardening pass closes the backlog before release.

### Non-blocking findings become tracked issues

When the gate passes, `.github/cyber-review/file_findings.py` auto-files each
surviving high/medium/low finding as a GitHub issue labelled
`security-debt` + `severity:<sev>` on the **"Pre-release security hardening"**
milestone (deduped by title against open `security-debt` issues). It runs only
on green runs, so intermediate pushes don't spam the tracker. Nothing the gate
waves through goes invisible — the milestone must be empty before GA.

## Break-glass override

Apply the **`security-override`** label to a PR to make the gate advisory for that
PR (it still reports what it *would* have blocked). Every use must be paired with
an ADR under `docs/decisions/` recording who/why. Intended for false positives and
genuine emergencies only.

## Fail-closed

A missing/malformed findings file fails the gate (a review that produced no
parseable output must not silently pass). Re-run the job; if infra is flaky, use
the override label with an ADR.

## Enabling / configuration

- Requires an org/repo secret **`ANTHROPIC_API_KEY`**. If it is missing the AI
  lane **fails closed** — no review is possible, so nothing auto-merges (the
  ADR 0001 "pass as not configured" behavior became fail-open once the merge
  turned workflow-driven, ADR 0003).
- Cost/latency control: the CI review runs the five review lenses in a single
  read-only agent pass (not five subagents per push) and consumes deterministic
  CI evidence instead of rerunning it. The full 5-subagent fan-out is the local
  / on-demand `cybersecurity-code-review` flow.
- The workflow already omits `synchronize`; the `re-review` label is the only
  way to re-run on new pushes.
