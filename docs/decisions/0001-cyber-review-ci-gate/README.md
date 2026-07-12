# 0001 — Cybersecurity review gate as a required check + full auto-merge

- **Date:** 2026-07-11
- **Category:** CI / branch-protection (sensitive)
- **Issue:** CRL review follow-up (see #74–#87)
- **PR:** #88

## Context

The multi-agent cybersecurity review of PR #73 found a CRITICAL trust-model flaw
(#74) that **compiled and passed the existing deterministic CI** — clippy, tests,
Semgrep, cargo-audit/deny, and CodeQL were all green. Deterministic tooling does
not catch logic/trust-boundary flaws. We want an automated security gate that
does, and we want green PRs to merge without manual clicks.

The user explicitly chose (over the recommended safer defaults):
- **Gate strictness:** LLM cyber-review **blocks** on high-confidence Critical/High.
- **Auto-merge scope:** **full auto-merge on green for all PRs**, including
  security-sensitive paths (declined the CODEOWNERS/sensitive-gated option).
- **Rollout:** build and enable end-to-end.

## Decision

1. Add `.github/workflows/cyber-review.yml` — a security-first LLM review that
   emits structured findings; a deterministic script
   (`.github/cyber-review/gate.py`) blocks merge iff a finding is
   `severity ∈ {critical,high}` ∧ `confidence ∈ {high,medium}`. Break-glass via
   the `security-override` label (must be paired with an ADR). The model never
   decides merge-ability (prompt-injection defense); the gate is a fixed policy.
2. Add an **additive** branch ruleset "Cyber-review required checks" (ruleset id
   18809646) on the default branch, leaving the existing "Basic" ruleset — signed
   commits, 1 approval, no force-push/deletion — untouched. **Currently required:**
   - `Static Analysis (CodeQL)`
   - `Cyber-review gate` (this workflow)

   **Deferred:** `Build, Test & Security Checks` is **not yet required** because it
   is red on `main` — `cargo audit` reports 9 dependency advisories (see #89,
   incl. a CRL-parsing panic in `rustls-webpki`). Requiring it now would wedge all
   merges. Add its context to the ruleset once #89 is resolved (or the audit step
   is made non-blocking / split from build+test).
3. Rely on the repo's already-enabled **auto-merge**; PRs use
   `gh pr merge --auto --squash --delete-branch` to merge the moment all required
   checks pass.

### Deliberately NOT changed (flagged risks)
- The existing **1-approval** requirement is **kept**. "Full auto-merge" was
  interpreted as *checks-driven*; removing the human approval entirely is a
  larger, hard-to-reverse reduction in oversight and was **not** done here. It can
  be removed on explicit request (one ruleset edit).
- **Admin bypass** ("always") on the branch is preserved to avoid lockout.
- The LLM gate is **non-deterministic**; only high-confidence Critical/High
  blocks, and the deterministic Tier-1 checks remain the backbone of "green".

## Consequences

- Security-relevant logic flaws can now block merge automatically; CodeRabbit
  findings feed the same review.
- **Requires an `ANTHROPIC_API_KEY` secret.** Until it is set, the gate passes as
  *not configured* (does not wedge merges) and auto-activates once added.
- Full auto-merge means a green PR (incl. sensitive paths) merges without a human
  click once its one approval + checks are satisfied — accepted per the decision
  above.

## Sensitive change — effective before → current (branch ruleset on default branch)

```diff
 Ruleset "Basic" (unchanged):
   - block deletion
   - block non-fast-forward (force-push)
   - require signed commits
   - pull_request: 1 required approval
+
+New additive ruleset "Cyber-review required checks":
+  required_status_checks:
+    - "Build, Test & Security Checks"
+    - "Static Analysis (CodeQL)"
+    - "Cyber-review gate"
+    strict_required_status_checks_policy: false
+  enforcement: active   (admin bypass: always, to match "Basic")
```

Full change in PR #88.
