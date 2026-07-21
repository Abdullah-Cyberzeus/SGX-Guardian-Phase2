# AI review and merge pipeline handoff

> Snapshot (2026-07-14): AI review/merge pipeline live (ADR 0002/0003); PR #73 waiting on dev-team fixes; 13 security-debt issues on the hardening milestone.

**Status:** The cyber-review process was overhauled across two days. new-guardian PR #92 (2026-07-13) landed the PRE_GA critical-only gate + cost-lane cadence + SHA-pinned workflow merge (ADRs 0002/0003); PR #106 (2026-07-14) synced applicable upstream improvements from `Verjson/.github` (turn budget 60, named pending diagnostics). The org-level reusable twin lives in `Cervais/.github/.github/workflows/ai-review-merge.yml` (their PRs #2–#7). The pipeline has merged its own PRs twice end-to-end, and its self-review caught and we fixed three real criticals (deletions-only lane, unpinned merge SHA, fail-open on missing API key).

**Open items:**

- **new-guardian#73** (CRL Data Structure & Gossip, AsadAli-CyberZeus) — OPEN. Waiting on the dev team to: fix #94 (DID key-binding version bypass) and #95 (second SE050 key-write path without 0600) in-branch, add an interim mitigation for #93 (bind admin API to 127.0.0.1 or make `require_localhost` real — the critical still blocks the gate), then apply the `re-review` label. Process comment with all of this is on the PR.
- **Security-debt backlog** — 13 issues (#93–#105) on the "Pre-release security hardening" milestone (milestone #1). Must be empty, and `PRE_GA` removed from `cyber-review.yml`, before GA.
- **new-guardian#89** — cargo-audit red on main (9 advisories). Until fixed, "Build, Test & Security Checks" is excluded from the gate's CI-wait polls and not a required check; fixing #89 should also remove that exclusion in `.github/workflows/cyber-review.yml` and re-require the check.

**Blocked/held:** nothing held by us; #73 is in the dev team's court.

**Watch/verify:**

- Next PR to main will exercise the gate automatically; check with `gh run list --workflow "Cybersecurity Review Gate"`. Re-run a stale PR with the `re-review` label.
- Verify the org `TOKEN` secret is a tightly-scoped PAT (it is now the merge credential for the whole org) — flagged to Pouya in the 2026-07-13 session report, not yet confirmed.
- Periodically re-sync from `Verjson/.github` (last synced through their #16 on 2026-07-14). Do NOT port their `synchronize` trigger into this repo (ADR 0003 divergence).

**Gotchas:**

- Polling checks from Actions: use REST (`/commits/<sha>/check-runs` + `/commits/<sha>/status`), not GraphQL `statusCheckRollup` (403s on other apps' suites); jobs need `checks: read`, `actions: read`, `statuses: read`.
- The workflow merge bypasses the 1-human-approval rule via org `TOKEN` admin bypass; per-PR human control = `hold` label / "DO NOT MERGE" title / draft.
- Gate fails closed if `ANTHROPIC_API_KEY` is missing (org secret; visibility "private").
- Backticks in `git commit -m "…"` double-quoted strings execute — escape or use heredocs.
