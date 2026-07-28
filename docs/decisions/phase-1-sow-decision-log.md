# SG-X Guardian - Decision Log

**Project**: SG-X Guardian Client (On-Premise Core)

**Phase**: Phase 1 - Circle of Trust & Policy Automation MVP

**Document Date**: November 12, 2025

## Overview

This decision log tracks all significant architectural, tactical, and procedural decisions made during the development of the SG-X Guardian system. Each decision is documented with context, rationale, alternatives considered, and implications for future development.

---

## Decision Summary

### Quick Reference Table

| ID | Decision | Category | Status | Sprint |
| -- | -------- | -------- | ------ | ------ |
| D001 | Core Programming Language - Rust | Architecture - Core Technology | Accepted | Sprint 1 |
| D002 | Inter-Service Communication - gRPC over mTLS | Architecture - Communication | Accepted | Sprint 1 |
| D003 | Cryptographic Algorithm - ECDSA P-256 | Architecture - Security | Accepted | Sprint 1 |
| D004 | Peer Discovery Mechanism - mDNS | Architecture - Networking | Accepted | Sprint 2 |
| D005 | Policy Enforcement Layer - nftables | Architecture - Security Enforcement | Accepted | Sprint 1 |
| D006 | Virtual Identity Derivation | Architecture - Security Model | Accepted | Sprint 2 |
| D007 | Attestation Model - Software-based (Phase 1) | Architecture - Security | Accepted | Sprint 2 |
| D008 | Service Architecture - Monolithic Daemon | Architecture - System Design | Accepted | Sprint 1 |
| D009 | Service Management - systemd | Deployment - Service Management | Accepted | Sprint 1 |
| D010 | Package Distribution - .deb and .rpm | Deployment - Packaging | Accepted | Sprint 4 |
| D011 | Error Handling Strategy - Result Types with Context | Implementation - Code Quality | Accepted | Sprint 1 |
| D012 | Logging and Observability Strategy | Implementation - Observability | Accepted | Sprint 4 |
| D013 | Policy Schema - YAML-based UEP v1.0 | Architecture - Policy | Accepted | Sprint 1 |
| D014 | Atomic Policy Updates with Rollback | Architecture - Policy Management | Accepted | Sprint 3 |
| D015 | Metrics and Telemetry - Prometheus Format | Implementation - Observability | Accepted | Sprint 4 |
| D016 | Cloud Integration - Outbound-Only Mock (Phase 1) | Architecture - Cloud Integration | Accepted | Sprint 4 |
| D017 | CI/CD Pipeline - GitHub Actions | DevOps - Continuous Integration | Accepted | Sprint 1 |
| D018 | Branch Protection and Development Workflow | Process - Development Workflow | Accepted | Sprint 1 |
| D019 | Test Strategy - Unit, Integration, and E2E | Quality - Testing | Accepted | Sprint 1 |
| D020 | Feature Deferrals to Phase 2+ | Scope - Prioritization | Accepted | Sprint 1 |

### Decisions by Category

| Category | Count | Decisions |
| -------- | ----- | --------- |
| **Architecture** | 9 | D001, D002, D003, D004, D005, D006, D007, D008, D013, D014, D016 |
| **Implementation** | 3 | D011, D012, D015 |
| **Deployment** | 2 | D009, D010 |
| **DevOps** | 1 | D017 |
| **Process** | 1 | D018 |
| **Quality** | 1 | D019 |
| **Scope** | 1 | D020 |

### Technology Stack Decisions

| Component | Technology | Decision ID | Justification |
| --------- | --------- | ----------- | ------------- |
| **Core Language** | Rust | D001 | Memory safety, fearless concurrency, and high performance are non-negotiable for security |
| **P2P Communication** | gRPC over mTLS | D002 | High-performance, strongly-typed RPC framework. mTLS ensures mutual authentication and encryption with forward secrecy |
| **Cryptography** | ECDSA P-256 | D003 | Standardized, efficient elliptic curve algorithm for FIPS-compliant device identity and policy signing |
| **Peer Discovery** | mDNS | D004 | Zero-configuration discovery on local networks without central infrastructure |
| **Enforcement** | nftables | D005 | Modern, kernel-level successor to iptables for deterministic, high-performance L3/L4 policy enforcement |
| **Service Management** | systemd | D009 | Standard for enterprise Linux deployments, providing robust service lifecycle management |
| **Packaging** | .deb/.rpm | D010 | Native integration with enterprise Linux package managers |
| **Error Handling** | Result + anyhow/thiserror | D011 | Explicit error handling with context preservation |
| **Logging** | tracing + journald | D012 | Structured logging with systemd integration |
| **Policy Format** | YAML | D013 | Human-readable, machine-parseable policy definitions |
| **Metrics** | Prometheus | D015 | Industry-standard metrics format for monitoring |
| **CI/CD** | GitHub Actions | D017 | Native GitHub integration with comprehensive quality gates |

---

## Detailed Decisions

### D001: Core Programming Language - Rust

**Date**: October 2025
**Status**: Accepted
**Category**: Architecture - Core Technology

**Context**:
The SG-X Guardian is a security-critical system that will run on edge devices with limited resources. The system requires high performance, memory safety, and the ability to handle concurrent operations safely. The core daemon will manage cryptographic operations, network communications, and system-level policy enforcement.

**Decision**:
Use Rust as the primary programming language for both `sgx-guardian` daemon and `sgx-pa-cli` tool.

**Rationale**:

| Criterion | Why Rust |
| --------- | -------- |
| **Memory Safety** | Ownership system eliminates entire classes of security vulnerabilities (buffer overflows, use-after-free, data races) at compile time |
| **Performance** | Zero-cost abstractions and no garbage collector provide performance comparable to C/C++ |
| **Concurrency** | Fearless concurrency model prevents race conditions and deadlocks at compile time |
| **Security Focus** | For security-critical software, these guarantees are non-negotiable |
| **Modern Ecosystem** | Excellent cryptography libraries, networking frameworks, and tooling |

**Alternatives Considered**:

| Alternative | Pros | Cons | Why Not Chosen |
| ----------- | ---- | ---- | -------------- |
| **Go** | Simple to learn, good concurrency, fast compilation | Garbage collector (non-deterministic latency), lacks compile-time memory safety | Insufficient memory safety guarantees for security-critical code |
| **C/C++** | Maximum performance and control, mature ecosystem | Manual memory management, prone to security vulnerabilities | Too high risk of memory safety issues |
| **Python** | Rapid development, excellent libraries | Slow performance, GIL limitations, dynamic typing | Insufficient performance and security guarantees |

**Implications**:

- Team requires Rust expertise or training
- Longer initial development time due to Rust's learning curve
- Higher code quality and fewer runtime errors
- Better long-term maintainability and security posture

**Related Decisions**: D002, D003, D011

---

### D002: Inter-Service Communication Protocol - gRPC over mTLS

**Date**: October 2025
**Status**: Accepted
**Category**: Architecture - Communication

**Context**:
The Circle of Trust requires secure, authenticated, and encrypted peer-to-peer communication between edge nodes. The protocol must support strong typing, efficient serialization, and bi-directional streaming for real-time policy synchronization.

**Decision**:
Use gRPC with mutual TLS (mTLS) for all P2P communication between guardian nodes.

**Rationale**:

| Feature | Benefit |
| ------- | ------- |
| **Strongly Typed** | Protocol Buffers provide language-agnostic, versioned API contracts |
| **High Performance** | Binary serialization is more efficient than JSON/XML |
| **Built-in Security** | Native support for TLS/mTLS enables mutual authentication |
| **Streaming Support** | Bi-directional streaming for real-time policy updates |
| **Forward Secrecy** | Ephemeral key exchange in TLS 1.3 ensures forward secrecy |
| **Cross-Platform** | Excellent Rust support via `tonic` crate |
| **HTTP/2 Foundation** | Multiplexing, flow control, and header compression |

**Alternatives Considered**:

| Alternative | Pros | Cons | Why Not Chosen |
| ----------- | ---- | ---- | -------------- |
| **REST over HTTPS** | Simple, well-understood, widespread adoption | Lacks strong typing, no streaming, inefficient text-based serialization | Insufficient for real-time policy synchronization |
| **Custom Protocol** | Maximum control, optimized for specific use case | Significant engineering effort, security auditing required, no ecosystem | Too much development overhead for MVP |
| **MQTT** | Lightweight, good pub/sub support | Not ideal for request/response, lacks strong typing, requires broker | Doesn't fit P2P architecture without broker |

**Implications**:

- All API contracts must be defined in Protocol Buffers
- Certificate management infrastructure required for mTLS
- Protobuf schema versioning strategy needed
- Network must support HTTP/2

**Related Decisions**: D001, D004, D005

---

### D003: Cryptographic Algorithm - ECDSA P-256

**Date**: October 2025
**Status**: Accepted
**Category**: Architecture - Security

**Context**:
The system requires a digital signature algorithm for device identity, policy signing, and attestation. The algorithm must be secure, efficient (suitable for edge devices), and widely recognized for compliance purposes.

**Decision**:
Use ECDSA (Elliptic Curve Digital Signature Algorithm) with the P-256 curve for all digital signatures.

**Rationale**:

- **FIPS Compliance**: P-256 (also known as secp256r1) is FIPS 186-4 approved
- **Efficiency**: Smaller key sizes (256 bits) compared to RSA (2048+ bits) for equivalent security
- **Performance**: Faster signature generation and verification on resource-constrained devices
- **Industry Standard**: Widely adopted and well-vetted by cryptographic community
- **Library Support**: Excellent support in Rust ecosystem (`ring`, `p256` crates)

**Alternatives Considered**:

- **RSA-2048/4096**: Larger keys, slower operations, higher resource usage
- **Ed25519**: Faster and more secure, but not FIPS-approved (compliance requirement)
- **P-384/P-521**: Higher security margins but unnecessary for this threat model and slower

**Implications**:

- All signing and verification operations use P-256
- Key generation must use cryptographically secure random number generators
- Private keys require secure storage (filesystem permissions, future TPM integration)
- Future migration to post-quantum cryptography will require protocol versioning

**Related Decisions**: D001, D007

---

### D004: Peer Discovery Mechanism - mDNS

**Date**: October 2025
**Status**: Accepted
**Category**: Architecture - Networking

**Context**:
The Circle of Trust requires zero-configuration peer discovery on local networks. Nodes must automatically discover each other without manual configuration or central registry. The mechanism must work on standard enterprise networks without requiring special infrastructure.

**Decision**:
Use mDNS (Multicast DNS) with service type `_sgx-guardian._tcp` for peer discovery.

**Rationale**:

- **Zero Configuration**: No DNS servers or manual configuration required
- **Standard Protocol**: RFC 6762, widely supported across operating systems
- **Local Network Scope**: Multicast packets stay within local subnet (security boundary)
- **Service Discovery**: Built-in service type advertisement and discovery
- **Nonce Exchange**: Can include random nonce in TXT records for freshness
- **Library Support**: Good Rust support via `mdns-sd` and similar crates

**Alternatives Considered**:

- **Consul/etcd**: Requires additional infrastructure and central coordination
- **Static Configuration**: Eliminates auto-discovery; brittle and error-prone
- **Broadcast UDP**: Non-standard, less efficient, no service typing
- **DHT (Distributed Hash Table)**: Overly complex for local network discovery

**Implications**:

- Nodes must be on same subnet or have multicast routing configured
- Firewall rules must allow mDNS (UDP port 5353, multicast 224.0.0.251)
- Discovery announcement frequency must balance responsiveness vs. network overhead
- Future WAN deployments will require alternative discovery mechanism

**Related Decisions**: D002, D006

---

### D005: Policy Enforcement Layer - nftables

**Date**: October 2025
**Status**: Accepted
**Category**: Architecture - Security Enforcement

**Context**:
The Universal Edge Processing (UEP) policy must be enforced at the network layer (L3/L4) with deterministic, high-performance packet filtering. The enforcement mechanism must integrate with the Linux kernel and support atomic rule updates.

**Decision**:
Use nftables as the policy enforcement engine for L3/L4 network filtering.

**Rationale**:

- **Modern Framework**: Successor to iptables with cleaner syntax and better performance
- **Kernel Integration**: Direct netfilter subsystem integration for maximum performance
- **Atomic Operations**: Supports atomic ruleset replacement (critical for policy updates)
- **Flexibility**: Single framework for IPv4, IPv6, ARP, and bridge filtering
- **Performance**: Optimized packet classification and reduced kernel-userspace transitions
- **Deterministic**: No race conditions during rule updates
- **Standard**: Default firewall in modern Linux distributions (Debian 10+, RHEL 8+)

**Alternatives Considered**:

- **iptables**: Legacy tool, less efficient, more complex rule management
- **eBPF/XDP**: Higher performance but significantly more complex, requires newer kernels
- **DPDK**: Maximum performance but bypasses kernel, requires dedicated NICs
- **User-space Firewall**: Higher latency, less secure (can be bypassed)

**Implications**:

- Requires Linux kernel 3.13+ with nftables support
- UEP-to-nftables translation layer needed in enforcement engine
- Policy rollback requires maintaining previous nftables ruleset
- Future L7 protocol inspection will require different approach (eBPF)

**Related Decisions**: D001, D014

---

### D006: Virtual Identity Derivation

**Date**: October 2025
**Status**: Accepted
**Category**: Architecture - Security Model

**Context**:
The Circle of Trust must detect when a node's state changes (policy update, key rotation, compromise). A static identity would not reflect current operational state. The system needs a way to bind device identity to its current security posture.

**Decision**:
Derive a Virtual Identity (VirtualID) by hashing the device's public key, current policy digest, and session nonces. This VirtualID changes whenever any component of the security state changes.

**Rationale**:

- **State Binding**: Identity is cryptographically bound to current policy and session
- **Automatic Re-attestation**: Policy changes force new VirtualID, triggering re-attestation
- **Replay Prevention**: Nonces prevent replay of old attestation evidence
- **Liveness Proof**: Demonstrates that node is active with current policy
- **Tamper Detection**: Any modification to policy or keys invalidates VirtualID
- **Zero Trust**: Continuous verification rather than one-time authentication

**Alternatives Considered**:

- **Static Device ID**: Simpler but doesn't reflect current state; can't detect policy drift
- **Certificate-based**: Requires PKI infrastructure and doesn't bind to runtime state
- **Periodic Re-attestation**: Requires timers and doesn't immediately detect changes

**Implications**:

- Every policy update triggers re-attestation across the cohort
- Hash function must be cryptographically secure (SHA-256 or better)
- VirtualID must be included in all P2P communications
- Nodes must maintain mapping of peer public keys to current VirtualIDs

**Related Decisions**: D003, D007

---

### D007: Attestation Model - Software-based (Phase 1)

**Date**: October 2025
**Status**: Accepted
**Category**: Architecture - Security

**Context**:
The system requires a mechanism to verify that peer nodes are running authentic, unmodified software. Hardware-based attestation (TPM) provides stronger guarantees but adds complexity and hardware dependencies. Phase 1 must establish the attestation protocol that can later be enhanced with hardware roots of trust.

**Decision**:
Implement software-based attestation in Phase 1, with architecture designed to support future TPM integration.

**Rationale**:

- **MVP Focus**: Validates the attestation protocol flow without hardware dependencies
- **Development Velocity**: Simpler to implement and test in development environment
- **Platform Independence**: Works on any Linux system without TPM requirements
- **Proof of Concept**: Demonstrates the attestation exchange before adding hardware complexity
- **Incremental Security**: Provides defense against casual tampering and network MITM

**Software Attestation Mechanism**:

- Node signs a message containing: peer nonce + self nonce + current policy digest
- Signature uses the node's persistent ECDSA P-256 identity key
- Receiving node verifies signature and checks that policy digest matches expected value

**Alternatives Considered**:

- **TPM-based attestation (Phase 1)**: Stronger security but adds hardware requirements and complexity
- **Remote Attestation Service**: Requires external infrastructure and internet connectivity
- **No attestation**: Unacceptable for security-critical system

**Implications**:

- Attestation provides authentication and liveness but not software integrity guarantees
- Private keys stored in filesystem with strict permissions (future: TPM)
- Protocol must be designed to accommodate future TPM evidence format
- Security model acknowledges software attestation limitations in threat model documentation

**Future Enhancement** (Phase 2+):

- Integrate TPM 2.0 for hardware-rooted attestation
- Generate and store identity keys in TPM
- Use TPM Quote operation for attestation evidence
- Implement measured boot and runtime integrity measurement

**Related Decisions**: D003, D006, D013

---

### D008: Service Architecture - Monolithic Daemon

**Date**: October 2025
**Status**: Accepted
**Category**: Architecture - System Design

**Context**:
The guardian system consists of multiple logical services (discovery, attestation, policy management, enforcement, telemetry, audit). These services need to be deployed, managed, and operated as a cohesive unit. The choice is between a single binary with all services or a microservices architecture.

**Decision**:
Implement all core services as modules within a single `sgx-guardian` daemon binary.

**Rationale**:

- **Operational Simplicity**: Single binary to deploy, update, and monitor
- **Resource Efficiency**: No IPC overhead, shared memory space, single process
- **Atomic Updates**: Single binary update ensures all components are version-matched
- **Tight Integration**: Direct function calls instead of network/IPC communication
- **Easier Debugging**: Single process space simplifies debugging and logging
- **Rust Module System**: Excellent support for modular code organization within single binary
- **Edge Device Constraints**: Minimal resource footprint for edge deployments

**Service Modules**:

- `p2p_discovery`: mDNS peer discovery
- `key_manager`: Identity key management
- `attestation_service`: Mutual attestation
- `policy_manager`: Policy signature verification and loading
- `enforcement_engine`: nftables rule translation
- `telemetry_service`: Prometheus metrics
- `audit_logger`: Tamper-evident logging

**Alternatives Considered**:

- **Microservices**: Better isolation but higher complexity, resource usage, and operational overhead
- **Separate Processes with IPC**: More fault isolation but adds IPC complexity and latency

**Implications**:

- Code organized as Rust modules with clear internal boundaries
- Shared state managed through Rust's ownership and concurrency primitives
- Crash in any service brings down entire daemon (requires robust error handling)
- Future: Could split out specific services if operational requirements change

**Related Decisions**: D001, D009

---

### D009: Service Management - systemd

**Date**: October 2025
**Status**: Accepted
**Category**: Deployment - Service Management

**Context**:
The `sgx-guardian` daemon must start automatically on boot, restart on failure, and integrate with system logging and monitoring. A service management solution is required for production deployments.

**Decision**:
Use systemd for service lifecycle management on all supported Linux distributions.

**Rationale**:

- **Standard**: Default init system on all major enterprise Linux distributions (RHEL 7+, Debian 8+, Ubuntu 15.04+)
- **Robust Features**: Automatic restart, dependency management, resource limits
- **Security Hardening**: Supports capabilities, namespaces, seccomp, and other hardening features
- **Logging Integration**: Automatic integration with journald for structured logging
- **Socket Activation**: Potential future use for on-demand service activation
- **Monitoring**: Native integration with monitoring tools

**systemd Hardening Applied**:

- `PrivateTmp=yes`: Isolated /tmp directory
- `NoNewPrivileges=yes`: Prevent privilege escalation
- `ProtectSystem=strict`: Read-only /usr and /boot
- `ProtectHome=yes`: Deny access to /home
- `CapabilityBoundingSet`: Minimal capabilities (CAP_NET_ADMIN for nftables)
- `RestrictNamespaces=yes`: Restrict namespace creation
- `SystemCallFilter`: Whitelist allowed syscalls

**Alternatives Considered**:

- **Docker/Container**: Adds unnecessary complexity for system-level security daemon
- **Custom init script**: Less robust, more maintenance burden
- **supervisord**: Additional dependency, not standard on enterprise Linux

**Implications**:

- Service unit file must be included in .deb/.rpm packages
- Installation scripts must enable and start service
- Documentation must include systemd management commands
- Logging must integrate with journald

**Related Decisions**: D010, D015

---

### D010: Package Distribution - .deb and .rpm

**Date**: October 2025
**Status**: Accepted
**Category**: Deployment - Packaging

**Context**:
The guardian system must be easily installable on enterprise Linux distributions. A standard packaging format is required that integrates with native package managers and handles dependencies, service setup, and upgrades.

**Decision**:
Build and distribute native .deb packages (Debian/Ubuntu) and .rpm packages (RHEL/Fedora/CentOS).

**Rationale**:

- **Native Integration**: Works with apt/yum/dnf package managers
- **Dependency Management**: Automatic handling of system dependencies
- **Upgrade Path**: Built-in support for package upgrades and rollbacks
- **Enterprise Standard**: Expected format for enterprise Linux deployments
- **Installation Hooks**: Pre/post-install scripts for service setup
- **Signature Verification**: Package signing for authenticity verification

**Package Contents**:

- `/usr/bin/sgx-guardian`: Main daemon binary
- `/usr/bin/sgx-pa-cli`: Policy authority CLI tool
- `/etc/sgx-guardian/`: Configuration directory
- `/etc/systemd/system/sgx-guardian.service`: systemd unit file
- `/var/lib/sgx-guardian/`: State directory (keys, policies)
- `/var/log/sgx-guardian/`: Log directory

**Alternatives Considered**:

- **Tarball**: No dependency management or integration with package managers
- **Docker Container**: Not appropriate for system-level security daemon
- **Snap/Flatpak**: Less common in enterprise environments, additional abstraction layer
- **AppImage**: Single-file deployment but no system integration

**Implications**:

- Build pipeline must support multi-format packaging
- Packages must be signed with GPG keys
- Repository hosting required for package distribution
- Installation documentation for both package formats
- Pre/post-install scripts must handle service enablement

**Related Decisions**: D009, D017

---

### D011: Error Handling Strategy - Result Types with Context

**Date**: October 2025
**Status**: Accepted
**Category**: Implementation - Code Quality

**Context**:
As a security-critical system, error handling must be explicit, comprehensive, and informative. Rust's Result type provides compile-time guarantees that errors are handled, but a strategy is needed for error propagation, context addition, and error types.

**Decision**:
Use Rust's `Result<T, E>` types with the `anyhow` crate for application errors and `thiserror` crate for library-style error types with context preservation.

**Rationale**:

- **Explicit Error Handling**: Rust's Result forces explicit error handling at compile time
- **Context Preservation**: `anyhow::Context` adds context as errors propagate up the stack
- **No Exceptions**: No hidden control flow or uncaught exceptions
- **Type Safety**: Error types are part of function signatures
- **Debugging**: Full error chains with context for troubleshooting
- **Pattern Matching**: Allows structured error handling based on error type

**Error Handling Patterns**:

```rust
// Library code (reusable modules) uses thiserror
#[derive(Error, Debug)]
pub enum AttestationError {
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Nonce mismatch")]
    NonceMismatch,
}

// Application code uses anyhow with context
fn attest_peer(peer: &Peer) -> Result<VirtualId> {
    let evidence = peer.get_evidence()
        .context("Failed to retrieve attestation evidence")?;

    verify_signature(evidence)
        .context("Signature verification failed")?;

    Ok(derive_virtual_id(evidence))
}
```

**Alternatives Considered**:

- **Panic on Error**: Unacceptable for production security software
- **Error Codes**: Less type-safe, easy to ignore, no context preservation
- **Custom Error Type Hierarchy**: More boilerplate, reinventing existing solutions

**Implications**:

- All fallible operations return Result types
- Errors must include context about what operation failed
- Logging must include full error chains
- No use of `.unwrap()` or `.expect()` in production code paths
- Unit tests should verify error conditions

**Related Decisions**: D001, D012

---

### D012: Logging and Observability Strategy

**Date**: October 2025
**Status**: Accepted
**Category**: Implementation - Observability

**Context**:
The guardian system requires comprehensive logging for security auditing, operational troubleshooting, and compliance. The logging approach must distinguish between security audit events and operational logs, with appropriate structure and tamper-evidence.

**Decision**:
Implement a dual logging strategy:

1. **Audit Log**: Structured, tamper-evident log for security events using custom audit logger
2. **Operational Log**: Structured application logs using `tracing` crate with journald integration

**Audit Logger**:

- **Format**: JSON Lines with cryptographic hash chain
- **Events**: Authentication, attestation, policy changes, enforcement actions
- **Tamper Evidence**: Each entry includes hash of previous entry
- **Storage**: Append-only file with strict permissions
- **Rotation**: Size-based rotation with retention policy

**Operational Logging**:

- **Framework**: `tracing` crate for structured, leveled logging
- **Levels**: ERROR, WARN, INFO, DEBUG, TRACE
- **Fields**: Structured key-value pairs (peer_id, policy_version, etc.)
- **Output**: journald for systemd integration
- **Format**: JSON for machine readability

**Rationale**:

- **Separation of Concerns**: Audit vs. operational logs have different requirements
- **Tamper Evidence**: Hash chain prevents undetected log modification
- **Structured Data**: JSON enables log analysis and correlation
- **Performance**: `tracing` is zero-cost when disabled, minimal overhead when enabled
- **Integration**: journald integration for system-level log management

**Alternatives Considered**:

- **syslog**: Less structured, no native tamper-evidence
- **Single log file**: Mixes audit and operational concerns
- **Log aggregation service**: Adds external dependency for MVP

**Implications**:

- Two separate log subsystems to maintain
- Log rotation and retention policies needed
- Audit log verification tool needed (for hash chain validation)
- Sensitive data (keys, credentials) must never be logged

**Related Decisions**: D011, D013

---

### D013: Policy Schema - YAML-based UEP v1.0

**Date**: October 2025
**Status**: Accepted
**Category**: Architecture - Policy

**Context**:
The Universal Edge Processing (UEP) policy defines L3/L4 network filtering rules that are synchronized across the Circle of Trust. The schema must be human-readable for administrators, machine-parseable for enforcement, and support digital signatures.

**Decision**:
Define UEP Policy Schema v1.0 in YAML format with support for L3/L4 network filtering rules, structured for translation to nftables.

**Policy Structure**:

```yaml
version: "1.0"
metadata:
  policy_id: "uuid"
  created_at: "ISO8601 timestamp"
  description: "Human-readable description"

signature:
  algorithm: "ECDSA-P256-SHA256"
  public_key_id: "Policy Authority key ID"
  signature: "base64-encoded signature"

rules:
  - name: "Allow SSH from management network"
    action: accept
    protocol: tcp
    source_ip: "10.0.1.0/24"
    destination_port: 22

  - name: "Block all other inbound"
    action: drop
    direction: inbound
```

**Rationale**:

- **Human Readable**: YAML is more readable than JSON for manual policy authoring
- **Validation**: Can use JSON Schema validation after parsing
- **Versioning**: Explicit version field for future schema evolution
- **Signature**: Detached signature over canonical representation
- **L3/L4 Focus**: Sufficient for Phase 1; extensible for L7 in future
- **nftables Mapping**: Structure designed for straightforward translation

**Alternatives Considered**:

- **JSON**: Less human-friendly, more verbose
- **TOML**: Good readability but less common for complex nested structures
- **Custom DSL**: Maximum flexibility but requires parser development and user learning
- **Rego (Open Policy Agent)**: Overly complex for L3/L4 rules

**Implications**:

- YAML parser must handle untrusted input safely
- Canonical form needed for signature verification (ordered keys, normalized whitespace)
- Schema validation required before policy installation
- Policy migration strategy needed for future versions
- Documentation and examples required for administrators

**Related Decisions**: D003, D005, D014

---

### D014: Atomic Policy Updates with Rollback

**Date**: October 2025
**Status**: Accepted
**Category**: Architecture - Policy Management

**Context**:
Policy updates must be applied atomically across the cohort to prevent split-brain scenarios where nodes enforce different policies. Additionally, failed policy updates must be automatically rolled back to prevent service disruption.

**Decision**:
Implement atomic policy updates with automatic rollback using nftables' atomic replacement feature and maintaining the previous policy version.

**Update Procedure**:

1. Receive new policy over secure gRPC channel
2. Verify Policy Authority signature
3. Validate policy schema and rules
4. Store new policy to disk
5. Translate to nftables ruleset
6. Test new ruleset (connectivity check)
7. Atomically swap nftables ruleset
8. If swap fails or connectivity lost: restore previous ruleset
9. Update policy_digest and VirtualID
10. Broadcast new VirtualID to peers

**Rationale**:

- **Atomicity**: nftables supports atomic ruleset replacement (all-or-nothing)
- **Safety**: Automatic rollback prevents enforcement disruption
- **Consistency**: All nodes enforce policy before updating VirtualID
- **Verification**: Connectivity check ensures policy doesn't lock out management
- **Auditability**: All steps logged to audit log

**Alternatives Considered**:

- **Incremental Updates**: Risk of partial application and inconsistent state
- **Manual Rollback**: Requires operator intervention; too slow for edge deployment
- **Two-Phase Commit**: Overly complex for this use case; network partitions cause issues

**Implications**:

- Must maintain previous policy version on disk for rollback
- Rollback timeout must be configurable (default: 30 seconds)
- Connectivity check must verify critical management paths
- Policy storage must handle atomic writes (write-to-temp, rename)
- Update failures must emit alerts/notifications

**Related Decisions**: D005, D013

---

### D015: Metrics and Telemetry - Prometheus Format

**Date**: October 2025
**Status**: Accepted
**Category**: Implementation - Observability

**Context**:
The system requires operational visibility for monitoring health, performance, and security posture. Metrics must be machine-readable, standardized, and compatible with common monitoring tools.

**Decision**:
Expose Prometheus-style metrics via HTTP endpoint on localhost.

**Metrics Categories**:

- **System Health**: Uptime, service status, error rates
- **Circle of Trust**: Peer count, attestation success/failure, trust state
- **Policy**: Active policy version, last update time, enforcement stats
- **Network**: Packet counts, bytes filtered, rule match rates
- **Performance**: Request latency, processing time, queue depths

**Metric Examples**:

```sh
# HELP sgx_guardian_peers_total Total number of discovered peers
# TYPE sgx_guardian_peers_total gauge
sgx_guardian_peers_total 3

# HELP sgx_guardian_attestations_total Attestation attempts
# TYPE sgx_guardian_attestations_total counter
sgx_guardian_attestations_total{result="success"} 45
sgx_guardian_attestations_total{result="failure"} 2

# HELP sgx_guardian_policy_version Currently active policy version
# TYPE sgx_guardian_policy_version gauge
sgx_guardian_policy_version{policy_id="uuid"} 5
```

**Rationale**:

- **Industry Standard**: Prometheus is de facto standard for metrics
- **Tool Compatibility**: Works with Grafana, Prometheus, VictoriaMetrics, etc.
- **Simple Format**: Text-based, easy to parse and debug
- **Pull Model**: Monitoring scrapes metrics; no outbound connections required
- **Cardinality**: Careful label design prevents cardinality explosion

**Alternatives Considered**:

- **StatsD**: Push-based, requires aggregation service
- **Custom JSON API**: Reinventing the wheel; poor tool compatibility
- **CloudWatch/Datadog SDK**: Vendor lock-in, requires outbound connectivity

**Implications**:

- Metrics endpoint on localhost:9090/metrics (configurable)
- Firewall must allow access from monitoring system
- Metric names follow Prometheus naming conventions
- Sensitive information must not be exposed in metrics
- Documentation must include metric catalog

**Related Decisions**: D012, D016

---

### D016: Cloud Integration - Outbound-Only Mock (Phase 1)

**Date**: October 2025
**Status**: Accepted
**Category**: Architecture - Cloud Integration

**Context**:
Phase 1 is "Self-Hosted First" but must establish the architectural foundation for future cloud-based management. The cloud integration path must be validated without implementing full bi-directional control in Phase 1.

**Decision**:
Implement a secure, outbound-only cloud uplink mock that establishes the connection pattern and data flow for future cloud integration, without enabling inbound control commands.

**Mock Implementation**:

- **Connection**: Outbound-only mTLS connection to mock cloud endpoint
- **Heartbeat**: Periodic status updates (node health, policy version, peer count)
- **Telemetry**: Optional metric upload to mock cloud collector
- **Authentication**: Certificate-based authentication for cloud endpoint
- **No Inbound Control**: Cloud cannot send policy updates or commands in Phase 1

**Rationale**:

- **Architectural Validation**: Proves the integration pattern works
- **Security Posture**: Outbound-only minimizes attack surface
- **Self-Hosted First**: Keeps core functionality independent of cloud
- **Future Readiness**: Establishes integration point for Phase 2
- **Testing**: Allows testing of cloud connectivity and authentication

**Alternatives Considered**:

- **No Cloud Integration**: Simpler but defers critical architectural decisions
- **Full Bi-directional**: Out of scope for Phase 1; adds complexity
- **Webhook Only**: Less secure; doesn't validate mTLS pattern

**Implications**:

- Cloud endpoint URL must be configurable
- Certificate management for cloud authentication
- Telemetry data must be carefully filtered (no secrets)
- Mock cloud service needed for testing
- Documentation must clarify Phase 1 limitations

**Related Decisions**: D002, D018

---

### D017: CI/CD Pipeline - GitHub Actions

**Date**: October 2025
**Status**: Accepted
**Category**: DevOps - Continuous Integration

**Context**:
The project requires automated build, test, and security scanning on every commit and pull request. The CI/CD system must integrate with the GitHub repository, support multi-architecture builds, and enforce quality gates.

**Decision**:
Implement CI/CD pipeline using GitHub Actions with comprehensive quality gates and automated deployment to test environment.

**Pipeline Stages**:

**1. Build**:

- Rust compilation (debug and release)
- Dependency caching
- Multi-architecture builds (x86_64, ARM64)

**2. Test**:

- Unit tests (`cargo test`)
- Integration tests
- Code coverage (target: 80%)
- Coverage reporting to PR comments

**3. Quality Gates**:

- `cargo clippy` (linting) - zero warnings
- `cargo fmt` (formatting) - must be formatted
- `cargo audit` (dependency vulnerabilities) - zero HIGH/CRITICAL
- `cargo deny` (license/security policy) - all checks pass
- SAST (Semgrep, CodeQL) - zero critical findings

**4. Security**:

- Dependency scanning
- Secret scanning
- Container scanning (if using containers)
- Security policy enforcement

**5. Package**:

- Build .deb packages
- Build .rpm packages
- Sign packages with GPG

**6. Deploy (Test Environment)**:

- Automated deployment to 3-node test LAN
- Deployment verification tests
- Rollback on failure

**Rationale**:

- **Native Integration**: GitHub Actions native to GitHub repository
- **Cost**: Free for public repos, included with GitHub Enterprise
- **Flexibility**: Supports custom workflows and matrix builds
- **Marketplace**: Large ecosystem of pre-built actions
- **Artifact Storage**: Built-in artifact and package storage

**Alternatives Considered**:

- **Jenkins**: More powerful but requires self-hosting and maintenance
- **GitLab CI**: Would require moving repository
- **CircleCI/Travis**: Additional service dependency

**Implications**:

- Workflow files in `.github/workflows/`
- Runner requirements for ARM64 builds (if needed)
- Secret management for signing keys
- Artifact retention policy
- Notification configuration for build failures

**Related Decisions**: D010, D018

---

### D018: Branch Protection and Development Workflow

**Date**: October 2025
**Status**: Accepted
**Category**: Process - Development Workflow

**Context**:
The project requires a development workflow that ensures code quality, enables collaboration, and maintains a stable main branch. The workflow must support trunk-based development while enforcing quality standards.

**Decision**:
Implement trunk-based development with protected main branch, required pull requests, and comprehensive status checks.

**Branch Protection Rules**:

- **Main branch protected**: Cannot push directly
- **Pull requests required**: All changes via PR
- **Required approvals**: Minimum 1 reviewer
- **Status checks**: All CI/CD checks must pass
  - `test` job
  - `security` job
  - `status-check` job
- **Up-to-date requirement**: Branch must be current with main
- **Conversation resolution**: All PR comments resolved
- **Linear history**: Squash or rebase merges
- **Signed commits**: GPG signature required
- **Admin bypass**: Repository admins can bypass for emergencies

**Development Workflow**:

1. Create feature branch from main
2. Develop and commit changes (signed commits)
3. Push branch and create pull request
4. CI/CD runs automatically
5. Code review and approval
6. Squash merge to main
7. Automatic deployment to test environment

**Rationale**:

- **Code Quality**: Automated checks enforce standards
- **Collaboration**: Pull requests enable code review
- **Stability**: Protected main branch prevents broken builds
- **Auditability**: All changes reviewed and approved
- **Security**: Signed commits verify author identity
- **Flexibility**: Admin bypass for emergencies

**Alternatives Considered**:

- **Git Flow**: Too complex for small team and rapid iteration
- **Unprotected Main**: Risks broken builds and security issues
- **Direct Commits**: No code review; single points of failure

**Implications**:

- All team members need GPG keys for signed commits
- PR template should guide reviewers
- Status check names must match workflow job names
- Emergency procedure documented for admin bypass
- Branch cleanup after merge

**Related Decisions**: D017

---

### D019: Test Strategy - Unit, Integration, and E2E

**Date**: October 2025
**Status**: Accepted
**Category**: Quality - Testing

**Context**:
As security-critical software, comprehensive testing is essential. The test strategy must provide confidence in correctness while supporting rapid development velocity.

**Decision**:
Implement a three-tier testing strategy: unit tests, integration tests, and end-to-end tests with 80% code coverage target.

**Test Tiers**:

**1. Unit Tests** (Target: 90% coverage):

- Test individual functions and modules in isolation
- Mock external dependencies (filesystem, network, crypto)
- Fast execution (<1 second total)
- Run on every file save (watch mode)
- Framework: `cargo test` with `mockall` for mocking

**2. Integration Tests** (Target: 70% coverage):

- Test interactions between modules
- Real filesystem, in-memory networking
- Moderate execution time (<30 seconds)
- Run in CI/CD pipeline
- Framework: `cargo test --test integration_tests`

**3. End-to-End Tests** (Scenario-based):

- Full system tests on 3-node test LAN
- Real networking, real attestation, real enforcement
- Automated via test scripts
- Run before each milestone demo
- Scenarios:
  - Circle of Trust formation
  - Policy distribution and enforcement
  - Node failure and recovery
  - Policy rollback
  - Attestation failure handling

**Test Organization**:

```sh
tests/
├── unit/          # Unit tests (in src/ alongside code)
├── integration/   # Integration tests
└── e2e/          # End-to-end test scripts
```

**Rationale**:

- **Fast Feedback**: Unit tests provide immediate feedback
- **Confidence**: Integration tests verify module interactions
- **Realism**: E2E tests prove system works end-to-end
- **Coverage**: 80% target balances thoroughness and pragmatism
- **Automation**: All tests automated in CI/CD

**Alternatives Considered**:

- **Manual Testing Only**: Insufficient for security-critical code
- **100% Coverage**: Diminishing returns; testing test code
- **Property-based Testing**: Valuable but requires significant effort

**Implications**:

- Test code is first-class code (must be maintained)
- Tests must be deterministic (no flaky tests)
- Test fixtures and utilities need development
- CI/CD pipeline runs all automated tests
- Coverage reports generated and tracked
- Failed tests block merge

**Related Decisions**: D011, D017

---

### D020: Feature Deferrals to Phase 2+

**Date**: October 2025
**Status**: Accepted
**Category**: Scope - Prioritization

**Context**:
To deliver Phase 1 within 8 weeks with 3 FTE, scope must be carefully managed. Several valuable features are deferred to future phases to maintain focus on core Circle of Trust functionality.

**Decision**:
Defer the following features to Phase 2 and beyond:

**1. Virtual Shift (AI/ML) - Phase 3+**:

- Requires significant R&D
- Circle of Trust must be stable first
- Machine learning for anomaly detection

**2. Protocol Connectors (L7) - Phase 2**:

- L7 protocol parsing (Modbus, OPC-UA, BACnet)
- Substantial engineering effort
- Requires eBPF integration

**3. Hardware TPM Attestation - Phase 2**:

- Software attestation validates protocol in Phase 1
- TPM integration adds hardware complexity
- Requires TPM-capable hardware for testing

**4. Advanced Enforcement (eBPF/DPDK) - Phase 3**:

- nftables sufficient for MVP
- eBPF/DPDK is performance optimization
- Requires kernel expertise and extensive testing

**5. CRL Gossip Protocol - Phase 2**:

- Certificate Revocation List distribution
- Complex distributed systems problem
- Simple revocation sufficient for Phase 1

**6. Bi-directional Cloud Control - Phase 2**:

- Phase 1 is Self-Hosted First
- Outbound-only channel validates architecture
- Full cloud control requires additional security review

**Rationale**:

- **Focus**: Concentrate on core trust fabric and policy enforcement
- **Risk Reduction**: Deliver working foundation before advanced features
- **Learning**: Phase 1 experience informs Phase 2 design
- **Value**: Core features provide immediate security value

**Phase 1 Success Criteria**:

- Circle of Trust formation and maintenance
- Cryptographic policy distribution
- L3/L4 network enforcement
- Operational observability
- Production-ready packaging

**Implications**:

- Architecture must support future feature addition
- APIs designed for extensibility
- Documentation notes future capabilities
- Client expectations managed regarding scope

**Deferred Features Summary**:

| Feature | Target Phase | Reason for Deferral | Dependency |
| ------- | ----------- | ------------------- | ---------- |
| **Virtual Shift (AI/ML)** | Phase 3+ | Requires significant R&D; Circle of Trust must be stable first | D001, D008 |
| **Protocol Connectors (L7)** | Phase 2 | Substantial engineering effort; requires eBPF integration | D005 |
| **Hardware TPM Attestation** | Phase 2 | Adds hardware complexity; software attestation validates protocol | D007 |
| **Advanced Enforcement (eBPF/DPDK)** | Phase 3 | Performance optimization; nftables sufficient for MVP | D005 |
| **CRL Gossip Protocol** | Phase 2 | Complex distributed systems problem | D002, D003 |
| **Bi-directional Cloud Control** | Phase 2 | Requires additional security review; outbound validates architecture | D016 |

**Related Decisions**: D007, D013, D016

---

## Decision Status Types

- **Proposed**: Under consideration, not yet accepted
- **Accepted**: Decision made and currently in effect
- **Deprecated**: No longer recommended, but may still be in use
- **Superseded**: Replaced by a newer decision

## Decision Categories

- **Architecture**: Fundamental system design and structure
- **Security**: Cryptography, authentication, authorization
- **Implementation**: Code-level technical choices
- **Deployment**: Packaging, distribution, and operations
- **DevOps**: CI/CD, automation, and infrastructure
- **Process**: Development workflow and procedures
- **Quality**: Testing, monitoring, and observability
- **Scope**: Feature prioritization and deferrals

## Contributing to Decision Log

When making significant architectural or technical decisions:

1. Document the decision using the template below
2. Assign a unique decision ID (D###)
3. Include context, rationale, alternatives, and implications
4. Reference related decisions
5. Update this README with the new decision

### Decision Template

```markdown
### D###: Decision Title

**Date**: Month Year
**Status**: Proposed | Accepted | Deprecated | Superseded
**Category**: Architecture | Security | Implementation | etc.

**Context**:
What is the issue we're addressing? What constraints exist?

**Decision**:
What are we deciding? Be specific and concrete.

**Rationale**:
Why this decision? What are the key benefits?

**Alternatives Considered**:
- **Alternative 1**: Why not chosen
- **Alternative 2**: Why not chosen

**Implications**:
What are the consequences? What must change as a result?

**Related Decisions**: D###, D###
```

---

## References

- [Project README](../../README.md)
- [Deliverables Tracking](../deliverables/README.md)
- [Branch Protection Setup](../../BRANCH_PROTECTION_SETUP.md)
