# Record the warm Windows CI benchmark

- Record the first warm GitHub-hosted `Windows Workspace Tests` measurement: 6m46s total, 4m21s (39.1%) faster than cold.
- Measure workspace tests at 5m30s, a 2m54s (34.5%) reduction, with a 34s target-cache restore and 3s post-run cache save.
- Retain the Windows target cache because measured warm performance improved while the job still completed 1m18s before Coverage.
