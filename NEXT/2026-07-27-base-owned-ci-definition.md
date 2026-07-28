# Keep required CI commands base-owned

## Security

- Compare a fixed manifest of the workflow, repository helpers, and
  policy-bearing tool configuration at the pull request event's exact base and
  head SHAs before trusting required job conclusions.
- Reject stale base SHAs and changed, added, missing, renamed, symlinked,
  malformed, or truncated trusted-definition entries.
- Classify documentation versus full CI from the same immutable trees, removing
  the mutable pull-request-files query.
- Record the remaining administrator gate: ruleset `18809646` must enable
  strict required-status checks and require `CI Required` after #131 lands.
- Keep pull request execution in the unprivileged `pull_request` workflow; the
  base-owned status publisher continues to validate the exact head SHA without
  checking out or executing pull request code.
- Document the restricted ruleset bypass required for legitimate CI Pipeline
  definition updates.
