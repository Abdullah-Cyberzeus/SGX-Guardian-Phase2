# Architecture Decision Records

Reverse-chronological index of decisions. Sensitive-class changes (branch
protection, auth, secrets, anything destructive) must have a record here.

| # | Date | Category | Decision | PR |
| --- | --- | --- | --- | --- |
| [0003](0003-cost-lane-review-and-workflow-merge/README.md) | 2026-07-13 | CI / merge policy | Cost-lane review cadence (once per ready PR, fast lanes, CI-first, model tiering) + workflow-driven auto-merge; org reusable workflow in Cervais/.github | #92 |
| [0002](0002-pre-ga-gate-critical-only/README.md) | 2026-07-13 | CI / merge policy | Pre-GA gate blocks on critical only; high/medium/low auto-filed as tracked security debt | #92 |
| [0001](0001-cyber-review-ci-gate/README.md) | 2026-07-11 | CI / branch-protection | Add cybersecurity review gate as a required check + full auto-merge on green | #88 |
