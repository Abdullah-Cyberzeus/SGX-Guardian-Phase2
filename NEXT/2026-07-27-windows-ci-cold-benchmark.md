# Record the first Windows CI benchmark

- Record the first GitHub-hosted cold `Windows Workspace Tests` measurement: 11m07s total, including 8m24s for workspace tests and 2m00s to save the target cache.
- Confirm the Windows job completed 1m02s before Coverage and did not extend the full-CI critical path.
- Defer cache changes until a comparable warm GitHub Actions measurement exists.
