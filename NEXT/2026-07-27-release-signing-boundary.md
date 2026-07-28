# Isolate package signing from pull-request CI

- Removed GPG secret access and the no-op package-signing loop from general CI.
- Added a protected, least-privilege release workflow that rebuilds stable
  tagged commits already contained in `main`, creates Debian and RPM packages,
  records provenance, and signs exactly one of each plus the manifest with an
  explicitly configured signing fingerprint.
- Added deterministic package and signing helpers with fail-closed tests.
- Consolidated duplicated package configuration and service inputs, including
  removal of an unused privileged-port capability and stale generated package
  artifacts.
- Removed persistent capabilities from the system-wide `nmap` binary and added
  upgrade/uninstall cleanup for legacy grants.
- Pinned the packaging container by digest and documented the exact
  byte-repeatability boundary and remaining non-hermetic dependencies.
- Documented the release environment setup and signing trust boundary in ADR
  0005.
