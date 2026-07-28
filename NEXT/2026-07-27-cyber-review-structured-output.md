# Wire structured cyber-review output

- Consume the Claude action's schema-validated `structured_output` instead of
  asking a read-only model session to write findings into the PR checkout.
- Keep Bash and filesystem mutation tools denied, materialize findings under
  `RUNNER_TEMP`, and retain the base-owned fail-closed severity policy.
- Run the exact-SHA gate fixtures and workflow output-contract fixture in the
  normal CI helper-test step.
- Record run 30304269615 as a failed output-path trial, not a successful
  post-redesign cyber-review benchmark.
