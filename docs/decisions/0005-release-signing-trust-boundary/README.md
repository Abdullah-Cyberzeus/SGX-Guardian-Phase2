# 0005 — Isolate release signing from pull-request execution

- **Date:** 2026-07-27
- **Category:** release signing / secrets (sensitive)
- **Issue:** [#120](https://github.com/Cervais/new-guardian/issues/120)
- **PR:** [#133](https://github.com/Cervais/new-guardian/pull/133)

## Context

The general CI workflow imported the package-signing key after executing
repository-controlled build steps on both pull requests and `main`. It then
looked for Debian and RPM files that the workflow never produced, so successful
runs expanded the secret exposure boundary without signing a release artifact.

The Debian and RPM inputs also duplicated service and configuration files and
declared package versions independently of the release being built.

## Decision

1. Pull-request CI remains secret-free and only proves that the Rust release
   profile compiles.
2. Package creation and signing run only for a published, stable semantic
   version tag in a job gated by the protected `release-signing` environment.
3. The trusted job requires the stable tag to resolve to the release event SHA,
   checks out that exact SHA, verifies it is an ancestor of fetched
   `origin/main`, and rebuilds it without consuming pull-request artifacts or
   caches. Immutable tag creation/update/deletion rules remain an explicit
   repository-administration control.
4. The distinctly named release signing key, passphrase, and exact signing
   fingerprint are environment secrets scoped only to the signing step. The
   helper rejects missing/mismatched/ambiguous keys and verifies every detached
   signature. The workflow keeps `contents: read` and publishes a workflow
   artifact rather than writing to the repository or release.
5. One helper builds both package formats from the same binary, shared service
   and configuration inputs, trusted tag version, and commit timestamp. It and
   the signer both fail closed on absent or ambiguous package outputs.
6. The canonical service unit retains only `CAP_NET_RAW` and `CAP_NET_ADMIN`;
   all configured listeners use unprivileged ports, so the duplicated
   `CAP_NET_BIND_SERVICE` grant is removed.
7. Generated package staging trees and binaries are no longer versioned; the
   trusted helper reconstructs every package from source.
8. Package assembly runs in a digest-pinned Rust image with pinned RPM and
   checksum-verified protoc inputs. Repeated assembly is byte-identical for the
   same binary, source, epoch, and tool versions; it is not declared hermetic
   because apt dependencies, Cargo downloads, and the runner runtime remain
   external. A signed manifest records the exact provenance and tool versions.
9. Debian maintainer scripts do not grant file capabilities to system-wide
   `nmap`; systemd supplies service-scoped capabilities and upgrade/removal
   clears capabilities left by older packages.

## Consequences

- Pull-request code cannot access or invoke the package-signing key.
- A release requires an environment approval and protected immutable tag rules
  configured by a repository administrator.
- Administrators must migrate to the `RELEASE_GPG_*` environment secrets and
  delete the old repository-level GPG secrets; no compatibility fallback
  exists.
- Signed packages are not automatically attached to the GitHub release; doing
  that later would require a separate decision to grant `contents: write`.
- Both formats now contain the same runtime configuration and service unit,
  eliminating divergent per-format copies from the package build path.
- Full hermeticity remains future infrastructure work; the manifest makes the
  current repeatability boundary auditable rather than overstating it.
