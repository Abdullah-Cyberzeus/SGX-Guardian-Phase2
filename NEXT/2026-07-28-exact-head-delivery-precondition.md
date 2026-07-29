# Document exact-head delivery preconditions

- Require delivery automation to pin and re-fetch the pull request head immediately before any manual or admin merge.
- Refuse merge when required CI or review evidence is pending, missing, failed, stale, or attached to another SHA.
- Distinguish full cyber-review evidence from the docs-only fast lane without treating admin capability as bypass authorization.
- Track the premature PR #139 merge and operational safeguard in issue #148.
