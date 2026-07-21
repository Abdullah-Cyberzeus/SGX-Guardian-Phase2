# Parallel, cacheable CI

- Split Rust validation into parallel lint, test, coverage, dependency-policy, Semgrep, and release-build jobs behind one stable `CI Required` check.
- Skip heavy jobs for documentation, `NEXT/`, Markdown, and `.gitignore`-only changes while treating every other path as runtime-affecting.
- Pin the Rust toolchain, protoc, audit tools, coverage tooling, actions, and Semgrep image; cache Cargo registries and job-specific targets without caching Tarpaulin output.
- Cancel superseded PR runs and use CodeQL's Rust `build-mode: none` to remove redundant builds.
- Keep Tarpaulin tests serialized because they share process and environment state; benchmark concurrency only after those tests are isolated.
- Record the measured 32–37 minute serial baseline and the procedure for capturing post-change full-CI, docs-only, and cache timings in `docs/ci-benchmarks.md`.
