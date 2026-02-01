## Addressing CodeRabbit Review Comments

### 1. Placeholder Public Key Validation in nodeB.yaml / nodeC.yaml

The `public_key` values defined in `nodeB.yaml` and `nodeC.yaml` are intentional non-production placeholders used exclusively for local multi-node simulation and documentation purposes.

In the SG-X Guardian architecture, node identity and trust are established through runtime-generated cryptographic keys and mutual attestation flows. Static YAML configuration values are not used as trust anchors during runtime operation.

As such, additional placeholder-pattern validation is not required at this stage.

---

### 2. IPAddressDeny=any blocks peer discovery and gRPC attestation.

The network restrictions defined in the systemd service file (`IPAddressDeny=any`, `IPAddressAllow=localhost`) are intentional and aligned with Phase-1 security and deployment requirements.

Phase-1 of the SG-X Guardian project focuses on controlled LAN-based demonstrations, trust flow validation, policy enforcement, and secure packaging with hardened defaults. The systemd service is configured to run a single local Guardian instance (nodeA) and is not intended to expose full peer-to-peer networking capabilities at the system service level.

Distributed mesh networking, multi-transport peer communication, and unrestricted inter-node connectivity are explicitly defined as Phase-2 deliverables (e.g., Nebula mesh, CRL gossip, multi-interface CoT). As such, relaxing systemd-level network isolation in Phase-1 would be premature and contrary to the intended security posture.

The current configuration ensures least-privilege execution and prevents unintended network exposure during early deployments. Network permissions will be expanded in Phase-2 via updated service profiles once full mesh networking is introduced.

---

### 3. build/ and packaging/ Directory Responsibilities

The `packaging/` directory is the authoritative source of truth for all packaging definitions, including install scripts, systemd units, configuration templates, and policies.

The `build/` directory is created from the `packaging/` directory to represent the filesystem layout after installation. It is used to observe and verify how the system will look and behave once installed.

Any runtime effects, side effects, or issues manifest only in the `build/` directory. The `build/` directory does not contain authoritative sources and can be safely removed at any time. If required, it can be recreated again from the updated `packaging/` directory.

All changes and fixes are applied only in the `packaging/` directory, after which the `build/` directory is regenerated as needed.

---

### 4. tonic / rustls Dependency Versions

No change is required for this item.

The current dependency set has been built and tested repeatedly using `cargo clean` and `cargo build`, and the system remains stable and fully functional. No build-time or runtime incompatibilities have been observed, and the resolved dependency graph is locked via `Cargo.lock`, ensuring reproducible builds.

Downgrading to `tonic 0.10.x` is explicitly rejected. That version line is affected by a known remotely exploitable Denial of Service vulnerability (CVE-2024-47609), where a malicious client can cause the server to exit by triggering a TCP/TLS accept condition. Using an affected version would introduce a confirmed security risk rather than improving stability.

Upgrading the TLS stack (`rustls 0.22` / `tokio-rustls 0.25`) would require changes to core security-critical code paths (TLS, mTLS, certificate handling, and gRPC transport). Introducing such changes in Phase-1 would add unnecessary regression risk while the current implementation is already stable and operational.

Given that the system is working correctly, reproducible, and avoids known vulnerable versions, no dependency changes are required at this stage.

---

### 5. systemd WorkingDirectory Configuration

The SG-X Guardian systemd service does not perform runtime key generation or write to relative filesystem paths. All required keys and artifacts are generated ahead of time via administrative tooling and placed into their final absolute locations before the service is started.

At runtime, the service only reads existing files and writes to explicitly permitted absolute paths (`/var/lib/sgx-guardian` and `/var/log/sgx-guardian`), which are already allowed via `ReadWritePaths`.

Since no relative-path writes occur during service execution, the absence of `WorkingDirectory` does not cause any functional or security issues. Adding it would be unnecessary and is therefore intentionally omitted.

