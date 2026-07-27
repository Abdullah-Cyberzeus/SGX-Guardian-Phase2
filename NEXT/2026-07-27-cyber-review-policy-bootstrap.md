# Bootstrap the base-owned cyber-review policy

- Land the inert exact-SHA CI gate helper and its fixtures on `main` before
  #121 changes the privileged cyber-review workflow to load that policy from
  the pull request's base commit.
- Do not activate or alter cyber-review behavior in this bootstrap; PR #131
  remains the reviewed workflow change.
