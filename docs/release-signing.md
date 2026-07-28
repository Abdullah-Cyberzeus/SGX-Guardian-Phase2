# Release package signing

Release package signing is isolated from pull-request CI. Pull requests compile
the optimized release profile without receiving signing secrets. Publishing a
stable release such as `v1.2.3` starts the `Release Packages` workflow from that
tag, rebuilds the binary and both package formats, then unlocks the signing key
only through the `release-signing` GitHub Environment.

## Repository setup

An administrator must configure the `release-signing` environment before the
workflow can sign a release:

1. Require at least one reviewer and disable administrator bypass.
2. Restrict deployments to protected stable release tags matching `vX.Y.Z`.
3. Store `RELEASE_GPG_PRIVATE_KEY`, `RELEASE_GPG_PASSPHRASE`, and the
   canonical uppercase 40-character `RELEASE_GPG_FINGERPRINT` as environment
   secrets, not repository-level secrets.
4. Add a tag ruleset for stable `v*` tags that restricts creation to release
   managers and prevents tag update or deletion.
5. After the environment secrets are verified, delete the legacy
   repository-level `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` secrets. They are
   intentionally not accepted as fallbacks.

The environment and tag ruleset are administrative controls and cannot be
enforced by workflow YAML alone. Do not publish a release until both are
active.

At runtime the workflow checks that the tag resolves to the event's full
commit SHA, that the checkout is exactly that SHA, and that the commit is an
ancestor of fetched `origin/main`. The workflow has only `contents: read`. It
does not upload to the release record; the signed `.deb`, `.rpm`, provenance
manifest, SHA-256 manifests, and detached ASCII signatures are retained as one
workflow artifact for 90 days.

## Package repeatability boundary

`.github/scripts/build-release-packages.sh` requires a version, a freshly built
executable, an empty output directory, and the trusted commit timestamp. It
uses the shared assets under `packaging/common`, normalizes file timestamps,
builds one package with `dpkg-deb` and one with `rpmbuild`, and fails unless
both outputs exist. With identical binary, source tree, commit timestamp, and
tool versions, repeated package assembly produces byte-identical `.deb` and
`.rpm` files. Versions come from the stable release tag rather than package
templates.

The release job runs in a digest-pinned Rust 1.97.1 Debian image, installs the
exact RPM package version, and installs protoc from a checksum-verified
archive. The artifact manifest records the tag, full commit SHA, container
digest, source epoch, package hashes, and actual Rust, Cargo, protoc,
`dpkg-deb`, `rpmbuild`, and GnuPG versions.

This is a repeatable package assembly process, not a fully hermetic toolchain.
The RPM package and its transitive Debian dependencies still come from live
Debian repositories, Cargo dependencies are locked and checksummed but not
vendored, and the GitHub runner/container runtime remains external. A
fully-hermetic claim would require a maintained organization-owned build image
and vendored dependency inputs.

The signing helper imports the private key into an ephemeral GnuPG home,
requires exactly one primary secret key, selects the configured signing
fingerprint with GnuPG's exact-key syntax, and verifies each detached signature
before upload. The three release secrets are scoped to that step and are never
available to pull-request workflows.

Debian installation no longer grants persistent file capabilities to the
system-wide `nmap` binary. The service receives `CAP_NET_RAW` and
`CAP_NET_ADMIN` only through systemd, and upgrade/removal scripts clear legacy
`nmap` file capabilities left by older packages.

## Local unsigned verification

On Debian or Ubuntu with `rpm` installed:

```bash
cargo build --release --locked
bash .github/scripts/build-release-packages.sh \
  0.1.0 target/release/sgx_guardian_client dist "$(git show -s --format=%ct HEAD)"
```

Signing is intentionally unavailable through the local verification path.
