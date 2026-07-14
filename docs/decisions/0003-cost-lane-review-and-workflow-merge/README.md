# 0003 — Cost-lane cyber-review cadence + workflow-driven auto-merge (org-wide verjson approach)

- **Date:** 2026-07-13
- **Category:** CI / merge policy (sensitive)
- **Issue:** dev-team escalation on PR #73; owner directive to adopt the Verjson org's `ai-review-merge` approach
- **PR:** #92 (this repo) · Cervais/.github#2 (org reusable workflow)

## Context

ADR 0001's gate re-ran a fresh full-depth LLM review on **every push**, which
(a) cost tokens on red or still-churning pushes and (b) produced the open-ended
fix/rescan loop the dev team escalated on PR #73. The Verjson org solved the
same problem with a cost-lane review-and-merge workflow
(`Verjson/.github/.github/workflows/ai-review-merge.yml`, their viager-docs
ADR-018). Owner directed adopting that approach for the Cervais org.

## Decision

1. **Org level:** `Cervais/.github` gains a reusable (`workflow_call`)
   `ai-review-merge.yml` (Cervais/.github#2) any org repo can adopt via a thin
   stub: free deterministic fast lanes (deletions-only, docs-only, bot
   non-major dep bumps), CI-first model invocation, Haiku/Sonnet tiering,
   once-per-ready-PR cadence with a `re-review` label, and squash-merge on
   green via the org `TOKEN` secret with `hold` / "DO NOT MERGE" / draft
   opt-outs re-checked at merge time.
2. **new-guardian** keeps its specialized security review but is restructured
   onto the same lanes (`cyber-review.yml`):
   - Review runs **once per ready PR** (`opened`/`reopened`/`ready_for_review`),
     not on `synchronize`. Re-run via the `re-review` label (auto-removed) or
     `workflow_dispatch`. The review prompt now verifies prior findings and
     focuses on the delta instead of re-deep-diving reviewed code.
   - `classify` fast-lanes deletions-only and docs-only PRs (no model call).
   - CI-first: the model runs only after all other checks are green — red
     PRs cost $0.
   - Model tiering: Haiku default; Sonnet for security-relevant paths
     (`.github/`, `src/api|crl|did|secure_element`, key/crypto/auth).
   - The PRE_GA severity gate and security-debt issue filing (ADR 0002) are
     unchanged and run inside the AI lane.
   - **Merge is workflow-driven:** after gate pass + green CI (and fast lane
     directly on green CI, with an audit comment), the workflow squash-merges
     with `--admin` using the org `TOKEN` secret and deletes the branch.
     Fail-closed: missing secret or red CI leaves the PR open.

## Consequences

- **The one-human-approval requirement is now bypassed by the workflow merge**
  (`--admin` through the ruleset's admin bypass), and the "Cyber-review gate"
  required check no longer exists on SHAs pushed after the review. The ruleset
  itself is unchanged: it still blocks *manual/auto* merges without a review-run
  SHA, while the workflow merge is the sanctioned path — the AI gate replaces
  the human approval, mirroring verjson ADR-018. Per-PR human control returns
  via `hold` / "DO NOT MERGE" / draft.
- The dev team's iteration concern is structurally resolved: a PR is reviewed
  when ready and re-reviewed only when they ask (`re-review`), so review rounds
  are opt-in rather than per-push.
- Cost drops: no review on red CI, no review per push, no review on
  docs/deletions-only PRs, Haiku for routine diffs.
- Risk: `TOKEN` is an org-admin credential used by CI to merge. Its scope and
  rotation are org-level concerns; if it leaks, branch protection is moot.
  Accepted as the same mechanism verjson uses; revisit at GA.

## Sensitive change — effective before → current (merge path)

```diff
-Review: fresh full-depth LLM review on EVERY push (synchronize)
+Review: once per ready PR (+ `re-review` label / workflow_dispatch);
+        fast lanes (docs-only, deletions-only) skip the model entirely;
+        model runs only after the rest of CI is green; Haiku/Sonnet tiering
-Merge:  gh pr merge --auto (requires 1 human approval + required checks
-        on head SHA)
+Merge:  workflow squash-merges with --admin (org TOKEN) after gate pass +
+        green CI — bypasses the 1-approval requirement and check staleness;
+        `hold` label / "DO NOT MERGE" title / draft opt out, re-checked at
+        merge time
 Ruleset "Basic" + "Cyber-review required checks": unchanged
```
