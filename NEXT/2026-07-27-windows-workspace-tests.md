# Restore Windows workspace tests

- Make DID document verification parse into an explicit `DidDocument`.
- Replace Unix shell fixtures in guardian-key handler tests with a platform-neutral key-generator test double while preserving the production process runner.
- Add a required Windows workspace test job with pinned Rust and a checksum-verified protoc installer, without duplicating lint, coverage, release, or security jobs.
- Record the before/after Windows workspace test evidence in `docs/ci-benchmarks.md`.
