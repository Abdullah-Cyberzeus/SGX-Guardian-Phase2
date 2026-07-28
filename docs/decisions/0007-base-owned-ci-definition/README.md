# 0007 — Keep the required CI definition base-owned

- **Date:** 2026-07-27
- **Category:** CI / branch-protection (sensitive)
- **Issue:** [#129](https://github.com/Cervais/new-guardian/issues/129)
- **PR:** [#139](https://github.com/Cervais/new-guardian/pull/139)

## Context

ADR 0004 moved the `CI Required` decision into a base-owned
`pull_request_target` workflow, but that gate still trusted job names and
conclusions from `.github/workflows/ci.yml`. GitHub evaluates that ordinary
`pull_request` workflow with the pull request's changes, so a contributor could
replace a required command with a no-op while retaining the expected job name.

Executing the pull request checkout from `pull_request_target` would expose an
untrusted build to a privileged event and is not an acceptable repair.

## Decision

1. The base-owned gate resolves the pull request event's exact base and head
   commit SHAs to their validated tree SHAs, then loads those recursive Git
   trees, using the head repository for fork pull requests. It compares a fixed
   manifest of every policy-bearing workflow, repository helper, and optional
   tool configuration consumed by required CI.
2. The trusted manifest covers `ci.yml`, `codeql.yml`, the base-owned
   `trusted-ci-required.yml`, every `.github/scripts` helper that CI executes,
   `deny.toml`, `.gitignore`, and optional Cargo, audit, Rust toolchain,
   rustfmt, Clippy, tarpaulin, and Semgrep configuration paths. This also
   prevents a pull request from spoofing the separately required
   `Static Analysis (CodeQL)` check or weakening the future gate.
3. Missing optional paths are part of the manifest, so adding one is a
   definition change. Mismatched/malformed commit responses and modified,
   deleted, renamed, symlinked, duplicated, malformed, or truncated tree
   entries fail closed.
4. Before comparing definitions, the gate verifies that the event base SHA is
   still the current default-branch head. A stale pull request must update
   before it can receive a trusted status.
5. Documentation/full-CI classification is derived from those same immutable
   base and head trees rather than the pull request's mutable files endpoint.
6. Ordinary `pull_request` CI remains the only workflow that executes pull
   request code. The privileged gate continues to inspect API metadata and
   publish a status for the exact head SHA without checking out the head.
7. A legitimate trusted-definition change requires explicit review and a
   restricted ruleset bypass to merge it into the default branch. The bypass
   is the trust decision; a contributor-controlled run cannot satisfy
   `CI Required` for that change.

Cargo manifests, lockfiles, build scripts, tests, and source remain untrusted
product inputs because CI exists to evaluate changes to them. They are not
trusted command definitions and are not added to the manifest. Required jobs
remain isolated, use fresh checkouts, and execute fixed commands from the
protected surface.

## Consequences

- A pull request cannot weaken CI commands, helpers, or policy configuration
  and reuse trusted-looking job names to obtain a green `CI Required` status.
- The definition check is bound to the same immutable head SHA as the workflow
  run and a current base SHA, rather than the pull request's mutable files list.
- Reusing the fetched trees for path classification removes one API request
  and keeps docs/full mode bound to the evaluated commit pair.
- CI-definition changes intentionally fail the required status until a trusted
  maintainer uses the audited administrative path.
- Repository rules must require the exact `CI Required` context, restrict
  bypass permission to trusted maintainers, and protect `main` against direct
  pushes and force-pushes.
- The runtime base check prevents trusting a run that is already stale when the
  gate evaluates it, but a successful commit status cannot be revoked
  automatically if `main` advances afterward. Repository ruleset `18809646`
  currently has `strict_required_status_checks_policy: false`; deployment is
  incomplete until an administrator sets it to `true` and requires
  `CI Required` after the #131 bootstrap lands.
- This supersedes ADR 0004's claim that validating job names and conclusions
  alone makes the required status base-owned.
