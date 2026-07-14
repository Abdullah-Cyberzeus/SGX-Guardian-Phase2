# 0002 — Pre-GA cyber-review gate: block on critical only, track high and below as security debt

- **Date:** 2026-07-13
- **Category:** CI / merge policy (sensitive)
- **Issue:** dev-team escalation on PR #73 review loop
- **PR:** #92

## Context

The gate from ADR 0001 blocks on high-confidence Critical/High findings and
re-reviews the full diff on every push. On PR #73 (54 commits: CRL, gossip,
admin API, DID distribution, SE050) this produced three-plus rounds of
fix → fresh review → new/deeper findings, and 19 fix commits. The dev team
escalated, proposing a 1–2 iteration cap per PR.

The system is **pre-production** — nothing is deployed, so the requirement at
this phase is that security debt is *visible and tracked*, not that `main` is
vulnerability-free at every commit. Blocking on every high is a production
posture applied during feature buildout.

## Decision

1. `gate.py` gains a `PRE_GA` env toggle. With `PRE_GA=true` (set in
   `cyber-review.yml` today) only `severity=critical ∧ confidence∈{high,medium}`
   blocks. Unset, the ADR 0001 policy (critical+high) applies — flip the one
   workflow env line back at the release-hardening milestone.
2. New `file_findings.py` step, run **only on green gate runs**: auto-files each
   surviving high/medium/low finding as an issue labelled
   `security-debt` + `severity:<sev>` on the **"Pre-release security hardening"**
   milestone (title-deduped against open `security-debt` issues). The milestone
   must be cleared before GA — that hardening pass is where the strict posture
   returns.
3. The workflow gains `issues: write` permission for the filing step.
4. Break-glass (`security-override` label + ADR) is unchanged.

## Consequences

- With full auto-merge on green (ADR 0001), PRs carrying known **high** findings
  now merge without a human click. Accepted for the pre-GA phase because every
  such finding is auto-filed as tracked debt; the trade is velocity now, one
  dedicated hardening pass later.
- Criticals still block, so the floor (unauthenticated destructive surfaces,
  trust-model breaks) is kept.
- Risk: "temporary" becomes permanent if the milestone is ignored. Mitigation:
  GA checklist requires the milestone empty and `PRE_GA` removed.

## Sensitive change — effective before → current (merge-blocking policy)

```diff
 Gate blocks a PR iff a finding has confidence ∈ {high, medium} AND:
-  severity ∈ {critical, high}
+  severity ∈ {critical}                        # while PRE_GA=true in cyber-review.yml
+
+Non-blocking high/medium/low findings on a green run:
+  auto-filed as `security-debt` issues on the
+  "Pre-release security hardening" milestone (must be empty before GA)
+
+Workflow permissions: + issues: write
```
