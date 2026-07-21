# Make the privileged cyber-review caller base-owned

- Run the secret-bearing review only from `pull_request_target`; remove manual
  dispatch because it can select a PR branch's workflow definition.
- Check out the exact PR head as non-executable review data without persisted
  Git credentials, and retain base-owned policy scripts.
- Explicitly allow only Claude's `Read`, `Grep`, and `Glob` tools while also
  denying shell, mutation, and MCP tools.
- Contract-test the trigger, event fields, top-level permissions, checkout, and
  tool restrictions in normal CI.
- Record run 30306455829 as a successful-output but security-blocked trial, not
  a successful current benchmark.
