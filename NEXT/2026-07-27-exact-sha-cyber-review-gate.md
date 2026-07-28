# Trust and streamline the cyber-review gate

- Replace duplicated broad status polling with one base-owned, tested helper
  that requires successful `CI Required` and `Static Analysis (CodeQL)` results
  on the exact PR head SHA.
- Remove redundant Rust/protoc setup and prompt-driven build, lint, test, and
  dependency reruns after deterministic CI has passed.
- Load severity and issue-filing policy from the base commit and expose the
  admin merge token only for the final exact-SHA merge.
- Document the trust-boundary decision and measured before/current benchmark
  status.
- Post-merge administrator gate: add `CI Required` to required-check ruleset
  `18809646`; the workflow already fails closed on that context.
