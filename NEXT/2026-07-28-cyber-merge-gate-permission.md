# Restore exact-SHA verification in the cyber-review merge job

- Grant the merge job read-only access to pull request metadata so its base-owned GraphQL snapshot can verify the reviewed head SHA.
- Keep the permission scoped to the merge job and preserve the fail-closed CI gate.
- Add a workflow-contract regression test for the merge job's exact least-privilege permission set.
- Track the production failure and fix in issue #143.
