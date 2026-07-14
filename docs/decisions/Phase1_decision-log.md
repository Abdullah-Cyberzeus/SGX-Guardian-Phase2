# SG-X Guardian - Decision Log

**Project**: SG-X Guardian Client  
**Phase**: Phase 1 - Circle of Trust & Policy Automation MVP  
**Document Date**: November 2025  

---

## Overview

This decision log tracks all significant **architectural, tactical and procedural decisions** made during Sprint 1 and Sprint 2 of the SG-X Guardian Client development lifecycle.  
It ensures traceability, justification and long-term maintainability of core design choices.

---

# Decision Summary

## Quick Reference Table

| ID | Decision | Category | Status | Sprint |
|----|----------|----------|--------|--------|
| D001 | Programming Language – Rust | Architecture – Core Technology | Accepted | Sprint 1 |
| D002 | Communication Protocol – gRPC + Protobuf | Architecture – Communication | Accepted | Sprint 1 |
| D003 | Cryptography – mTLS 1.3 + Ed25519/X25519 | Architecture – Security | Accepted | Sprint 1 |
| D004 | Policy Schema – UEP Policy v1 (YAML) | Architecture – Policy | Accepted | Sprint 1 |
| D005 | Data Storage – YAML Node Configs | Architecture – Config Management | Accepted | Sprint 1 |
| D006 | Logging Framework – tracing + JSON logs | Implementation – Observability | Accepted | Sprint 1 |
| D007 | Metrics Engine – Custom async metrics.rs | Implementation – Observability | Accepted | Sprint 1 |
| D008 | Security Model – Zero-Trust Edge | Architecture – Security Model | Accepted | Sprint 1 |
| D009 | Modular Architecture Structure | Architecture – System Design | Accepted | Sprint 1 |
| D010 | CI/CD – GitHub Actions + Security Gates | DevOps – CI/CD | Accepted | Sprint 1 |
| D011 | Deployment Automation – GPG Artifact Signing | DevOps – Release Management | Accepted | Sprint 1 |
| D012 | Policy Authority CLI – keygen + sign | Architecture – Tooling | Accepted | Sprint 1 |
| D013 | Static Analysis – Semgrep + CodeQL | Quality – SAST | Accepted | Sprint 1 |
| D014 | API Spec v1.0 – Protobuf Definitions | Architecture – API | Accepted | Sprint 1 |
| D015 | Code Quality Tools – fmt, clippy, audit, deny | Quality – Code Hygiene | Accepted | Sprint 1 |
| D016 | Feature Deferral – PQC + AI/ML | Scope – Prioritization | Accepted | Sprint 1 |
| D017 | Node Identity – ECDSA P-256 Key Manager | Architecture – Identity | Accepted | Sprint 2 |
| D018 | Peer Discovery – mDNS | Architecture – Networking | Accepted | Sprint 2 |
| D019 | Attestation Service – Evidence Signing | Architecture – Security | Accepted | Sprint 2 |
| D020 | Discovery + Attestation Integration | Architecture – Integration | Accepted | Sprint 2 |
| D021 | Background Task Runtime – Tokio | Implementation – Runtime | Accepted | Sprint 2 |
| D022 | CLI Enhancements – peers + attestation | Architecture – Tooling | Accepted | Sprint 2 |
| D023 | CLI Data Source – Structured JSON Logs | Architecture – Observability | Accepted | Sprint 2 |
| D024 | Enhanced Logging for Discovery & Attestation | Implementation – Logging | Accepted | Sprint 2 |
| D025 | Unit & Integration Testing | Quality – Testing | Accepted | Sprint 2 |
| D026 | Multi-Node Simulation (Node A/B/C) | Quality – Distributed Testing | Accepted | Sprint 2 |
| D027 | TCP Attestation Listener | Architecture – Networking | Accepted | Sprint 2 |
| D028 | Trusted Peer + Evidence Logs | Architecture – Trust | Accepted | Sprint 2 |
| D029 | Re-Attestation Timer (60 Seconds) | Architecture – Trust Refresh | Accepted | Sprint 2 |
| D030 | Auto Re-Attest on Startup | Architecture – Resilience | Accepted | Sprint 2 |
| D031 | Trusted Peer Timestamp Refresh | Architecture – Trust Health | Accepted | Sprint 2 |
| D032 | Failure Handling – Retry Logic | Implementation – Reliability | Accepted | Sprint 2 |
| D033 | CLI Sync Validation | Quality – Verification | Accepted | Sprint 2 |
| D034 | Autonomous Circle-of-Trust Demo | Architecture – Distributed System | Accepted | Sprint 2 |
| D035 | Multi-Node Automation Script | Process – Testing Automation | Accepted | Sprint 2 |
| D036 | Peer Log Merging – jq Consolidation | Architecture – Observability | Accepted | Sprint 2 |
| D037 | TLS Module – mTLS Foundation | Architecture – Security | Accepted | Sprint 3 |
| D038 | Certificate Lifecycle – Persistent Identity | Architecture – Identity | Accepted | Sprint 3 |
| D039 | Secure gRPC mTLS Channel Integration | Architecture – Communication Security | Accepted | Sprint 3 |
| D040 | Policy Signing Capability (sgx-pa-cli) | Architecture – Policy Security | Accepted | Sprint 3 |
| D041 | Signed Policy Envelope (JSON + Base64 + Digest) | Architecture – Policy Distribution | Accepted | Sprint 3 |
| D042 | Policy Signature Verification at Node Startup | Architecture – Policy Enforcement | Accepted | Sprint 3 |
| D043 | Atomic Policy Activation (Active / Pending / Backup) | Architecture – Configuration Safety | Accepted | Sprint 3 |
| D044 | Policy Rollback Strategy on Verification Failure | Architecture – Resilience | Accepted | Sprint 3 |
| D045 | Fail-Closed Policy Enforcement Model | Architecture – Zero Trust | Accepted | Sprint 3 |
| D046 | Milestone Demo 2 – Admin-Signed Policy Propagation | Process – Demonstration | Accepted | Sprint 3 |
| D047 | Secure Element as Hardware Root of Trust | Architecture – Hardware Security | Accepted | Sprint 1 |
| D048 | Secure Element Driver and Cryptographic Subsystem Initialization | Implementation – Secure Element | Accepted | Sprint 1 |
| D049 | Secure Element Protected Key Storage | Implementation – Secure Element | Accepted | Sprint 1 |
| D050 | Hardware Key Manager for DKP Lifecycle | Architecture – Identity | Accepted | Sprint 1 |
| D051 | Non-Exportable DKP Private Key Model | Architecture – Identity | Accepted | Sprint 1 |
| D052 | Secure Element Signing Boundary | Implementation – Secure Element | Accepted | Sprint 1 |
| D053 | DKP Rotation and Revocation Workflow | Architecture – Identity | Accepted | Sprint 1 |
| D054 | Nebula Mesh as Circle Transport Layer | Architecture – Mesh Networking | Accepted | Sprint 1 |
| D055 | Nebula CA Operations for Circle Certificates | Architecture – Mesh Networking | Accepted | Sprint 1 |
| D056 | DID-to-Overlay-IP Certificate Binding | Architecture – Identity | Accepted | Sprint 1 |
| D057 | Verifiable Credential Validation Before Certificate Issuance | Architecture – Identity | Accepted | Sprint 1 |
| D058 | Time-Limited Nebula Certificates | Architecture – Identity | Accepted | Sprint 1 |
| D059 | PCR Measurement Collection | Architecture – Hardware Security | Accepted | Sprint 2 |
| D060 | Golden PCR Baseline Storage | Architecture – Hardware Security | Accepted | Sprint 2 |
| D061 | PCR Mismatch as Attestation Failure | Architecture – Attestation | Accepted | Sprint 2 |
| D062 | Secure Boot Chain Validation | Architecture – Hardware Security | Accepted | Sprint 2 |
| D063 | Fail-Closed Boot Integrity Model | Security – Fail-Closed Enforcement | Accepted | Sprint 2 |
| D064 | Transport-Agnostic Circle of Trust | Architecture – Multi-Transport CoT | Accepted | Sprint 2 |
| D065 | LAN and WiFi Auto-Detection | Architecture – Multi-Transport CoT | Accepted | Sprint 2 |
| D066 | Transport Preference and Failover Model | Architecture – Multi-Transport CoT | Accepted | Sprint 2 |
| D067 | Nebula Overlay Network CIDR 192.168.100.0/24 | Architecture – Mesh Networking | Accepted | Sprint 3 |
| D068 | nebula0 Virtual Interface Creation | Architecture – Mesh Networking | Accepted | Sprint 3 |
| D069 | Overlay IP Allocation Tracking | Architecture – Mesh Networking | Accepted | Sprint 3 |
| D070 | Lighthouse-Based Peer Discovery | Architecture – Mesh Networking | Accepted | Sprint 3 |
| D071 | Lighthouse Registry and Endpoint Updates | Architecture – Mesh Networking | Accepted | Sprint 3 |
| D072 | Redundant Lighthouse Support | Architecture – Mesh Networking | Accepted | Sprint 3 |
| D073 | Cellular CoT Extension | Architecture – Multi-Transport CoT | Accepted | Sprint 3 |
| D074 | Bluetooth CoT Extension | Architecture – Multi-Transport CoT | Accepted | Sprint 3 |
| D075 | Multi-Hop Relay Routing | Architecture – Mesh Networking | Accepted | Sprint 4 |

---

# Decisions by Category

| Category | Count | Decisions |
|---------|--------|----------|
| **Architecture** | 51 | D001, D002, D003, D004, D005, D008, D009, D012, D014, D016, D017, D018, D019, D020, D027, D028, D029, D030, D031, D034, D037, D038, D039, D040, D041, D042, D043, D044, D046,D047, D059, D060, D062 ,D050, D051, D053, D056, D057, D058 ,D054, D055 , D061 ,D064, D065 , D067, D068, D069, D070, D071, D072, D075, |
| **Implementation** | 8 | D006, D007, D021, D024, D032, D048, D049, D052 |
| **DevOps** | 2 | D010, D011 |
| **Quality** | 5 | D013, D015, D025, D026, D033 |
| **Process** | 1 | D035 |
| **Scope** | 1 | D016 |
| **Security – Fail-Closed Enforcement** | 1 | D063 |

---

# Technology Stack Decisions

| Component | Technology | Decision ID | Justification |
|----------|------------|-------------|---------------|
| Core Language | Rust | D001 | Memory safety, performance, secure concurrency |
| Networking | gRPC + Protobuf | D002 | Typed, efficient, cross-platform |
| Cryptography | mTLS, Ed25519/X25519 | D003 | High-security identity & transport |
| Policy Format | YAML UEP v1 | D004 | Human-readable, schema-friendly |
| Logging | tracing + JSON | D006 | Structured log processing |
| Metrics | Custom metrics.rs | D007 | Prometheus-style extension path |
| Node Identity | ECDSA P-256 | D017 | Durable persistent identity |
| Peer Discovery | mDNS | D018 | Zero-config LAN peer discovery |
| Attestation | Signed Evidence | D019 | Foundation of Circle-of-Trust |
| Transport Security | rustls + tonic mTLS | D037, D039 | Secure gRPC channels with mutual authentication |
| Node Certificates | X.509 (DER/PEM) | D038 | Persistent cryptographic identity for each node |
| Policy Distribution | Signed JSON Envelope (Base64 + SHA-256) | D040, D041 | Portable, verifiable policy delivery across nodes |
| Hardware Root of Trust | Secure Element / SE050 abstraction | D047 | Establishes tamper-resistant device trust anchor |
| Secure Element Driver | Rust wrapper over secure element access layer | D048 | Isolates hardware communication from business logic |
| Protected Key Storage | Secure element-backed key slots | D049 | Prevents private key exposure to operating system |
| Hardware Key Manager | DKP lifecycle manager | D050 | Controls generation, rotation and revocation of device keys |
| Device Key Pair | Secure element-backed DKP | D050, D051 | Ensures device identity is hardware-bound and non-exportable |
| Signing Boundary | Hardware-backed signing operation | D052 | Keeps private key operations inside secure hardware boundary |
| PCR Measurement | Platform Configuration Register collection | D059 | Provides integrity fingerprint for firmware, bootloader, kernel and config |
| Golden Baseline | Known-good PCR reference set | D060 | Enables trusted comparison during attestation |
| Secure Boot Chain | Verified boot sequence | D062 | Prevents tampered firmware or bootloader execution |
| Hardware Attestation | Secure element challenge-response protocol | D079 | Provides cryptographic proof of hardware and firmware state |
| Attestation Quote | Nonce-bound signed quote | D080 | Prevents replay and proves freshness |
| Nebula Mesh | Encrypted overlay networking | D054 | Provides resilient Circle transport layer |
| Nebula CA | Circle certificate authority | D055 | Enables certificate-based mesh membership |
| Overlay Addressing | 192.168.100.0/24 per Circle | D067 | Provides predictable private mesh addressing |
| Virtual Interface | nebula0 | D068 | Routes peer traffic through encrypted overlay tunnels |
| Lighthouse | Nebula lighthouse peer discovery | D070, D071 | Enables NAT traversal and endpoint discovery |
| Redundant Lighthouse | Multiple lighthouse nodes | D072 | Improves availability and failover |
| Relay Routing | Nebula multi-hop relay | D075 | Maintains connectivity when direct UDP fails |
| Relay Controls | Bandwidth and usage limits | D076 | Prevents uncontrolled relay resource usage |
| Multi-Transport CoT | LAN, WiFi, Bluetooth, Cellular, Satellite | D064, D073, D074, D077, D078 | Makes trust independent of physical transport |
| Runtime Integration | Rust + Tokio-compatible modules | D048, D064, D079 | Preserves existing async architecture |
| Configuration | YAML / JSON config extensions | D067, D070, D076 | Keeps deployment human-readable and auditable |
| Logging | Structured logs | D061, D082, D084 | Supports audit, debugging and CLI visibility |
| Test Environment | 3-node hardware and network test setup | D083, D085 | Validates end-to-end trust behavior |
---

# Detailed Decisions

---

### D001: Programming Language – Rust

**Date:** Sprint 1  
**Status:** Accepted  
**Category:** Architecture – Core Technology  

**Context:**  
SG-X Guardian requires a highly secure, memory-safe and concurrent runtime for cryptographic operations, distributed networking and real time policy enforcement. The language must prevent buffer overflows and race conditions by design.

**Decision:**  
Use **Rust** for both `sgx-guardian` daemon and `sgx-pa-cli`.

**Rationale:**

| Criterion | Why Rust |
|----------|-----------|
| Memory Safety | Eliminates buffer overflows + data races through ownership model |
| Performance | C/C++-level speed with zero-cost abstractions |
| Concurrency | Fearless concurrency prevents deadlocks and race conditions |
| Cryptography | Strong RustCrypto ecosystem |
| Reliability | Compiler ensures correctness before runtime |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Go | Easy concurrency | GC pauses, weaker memory safety |
| C++ | High performance | Manual memory -> dangerous for security |
| Python | Easy scripting | Too slow & unsafe for edge workloads |

**Implications:**  
- Slightly higher learning curve  
- Much stronger long-term stability  
- Fewer memory related vulnerabilities  

**Related Decisions:** D002, D003, D011  

---

### D002: Communication Protocol – gRPC + Protobuf

**Status:** Accepted  
**Category:** Architecture – Communication  

**Context:**  
Nodes need a secure, typed, efficient communication layer for attestation, policy sync and health checking. Protocol must support mTLS and real time streaming.

**Decision:**  
Adopt **gRPC** with **Protobuf** schemas.

**Rationale:**

| Feature | Benefit |
|--------|----------|
| Strong typing | Strict API contracts |
| HTTP/2 | Multiplexing & header compression |
| Binary encoding | Fast + compact |
| Streaming | Real-time policy & trust updates |
| TLS integration | Native mTLS support |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|-------------|------|------|
| REST/HTTPS | Simple | No streaming, slower, text-based |
| Custom TCP protocol | Flexible | Costly to design + insecure |
| MQTT | Lightweight | Requires broker -> not P2P |

**Implications:**  
- All RPC interfaces defined via `.proto`  
- Requires certificate lifecycle management  

**Related Decisions:** D001, D004, D005  

---

### D003: Cryptographic Algorithm – mTLS + Ed25519/X25519

**Status:** Accepted  
**Category:** Architecture – Security  

**Context:**  
Guardian nodes exchange sensitive attestation and policy data. Requires modern, secure and light cryptography.

**Decision:**  
Use **Ed25519** for signatures and **X25519** for key exchange under **TLS 1.3 mTLS**.

**Rationale:**

| Benefit | Description |
|---------|-------------|
| Fast verification | Perfect for repeated attestation cycles |
| Small keys | Ideal for edge systems |
| Strong security | Trusted modern curves |
| Rust support | Available in rustls/RustCrypto |

**Alternatives Considered:**

| Option | Reason Not Chosen |
|--------|--------------------|
| RSA-2048 | Too slow, large keys |
| P-256 | Good but slower than Ed25519 |
| Custom crypto | Security risk |

**Implications:**  
- Efficient crypto at scale  
- Reduced CPU load during attestation  

**Related Decisions:** D017, D019  

---

### D004: Policy Schema – UEP v1 (YAML)

**Status:** Accepted  
**Category:** Architecture – Policy  

**Context:**  
Policy must be human-readable, easy to sign and translate into nftables rules.

**Decision:**  
Define **UEP Policy Schema v1** in **YAML**.

**Rationale:**

| Feature | Benefit |
|---------|---------|
| Human-readable | Admin-friendly |
| Supports structure | Nested L3/L4 rules |
| Extendable | Future L7 features |
| Simple validation | YAML schema + Rust structs |

**Alternatives Considered:**

| Option | Cons |
|--------|------|
| JSON | Less readable |
| TOML | Not suitable for complex rule trees |

**Implications:**  
- YAML -> canonical form required for policy signing  
- Must validate input to prevent malformed policies  

**Related Decisions:** D014, D015  

---

### D005: Data Storage – YAML Config Files

**Status:** Accepted  
**Context:**  
Nodes must boot with minimal configuration on LAN.

**Decision:**  
Store per-node configurations in `nodeA.yaml`, `nodeB.yaml`, `nodeC.yaml`.

**Rationale:**  
Simple, human-readable and no DB required.

**Alternatives Considered:**  
Database -> too heavy for Phase 1.

**Implications:**  
Easy simulation and testing.

---

### D006: Logging Framework – tracing + JSON Logs

**Status:** Accepted  
**Category:** Implementation – Observability

**Context:**  
Guardian must produce tamper-evident logs and structured telemetry.

**Decision:**  
Use **tracing** + JSON with structured fields.

**Rationale:**

| Benefit | Details |
|---------|---------|
| Structured | Machine parsable |
| Async friendly | Works with Tokio |
| Integrates with CLI | CLI can parse logs easily |

**Alternatives:** syslog -> unstructured.

**Implications:**  
- Enables CLI commands like `peers` & `attestation`.

---

### D007: Metrics Engine – Custom Async Collector

**Status:** Accepted  
**Category:** Implementation – Observability  

**Context:**  
Need lightweight internal metrics.

**Decision:**  
Implement custom `metrics.rs`.

**Rationale:**  
Small footprint, Prometheus-ready formatting.

**Implications:**  
Supports uptime, event counts, errors.

---

### D008: Zero-Trust Edge Security Model

**Status:** Accepted  
**Category:** Architecture – Security Model  

**Context:**  
Nodes must not trust each other by default.

**Decision:**  
All trust derived from cryptographic attestation and live verification.

**Rationale:**  
Zero external trust dependencies.

**Implications:**  
Every node verifies every peer.

---

### D009: Modular Architecture Structure

**Status:** Accepted  
**Category:** Architecture – System Design  

**Context:**  
Guardian daemon contains multiple subsystems.

**Decision:**  
Organize code into modules: discovery, attestation, policy, enforcement, logging, metrics.

**Rationale:**  
Improves maintainability and testing.

**Implications:**  
Scalable design for future features.

---

### D010: CI/CD – GitHub Actions with Security Gates

**Status:** Accepted  
**Category:** DevOps – CI/CD  

**Decision:**  
Use GitHub Actions for build, lint, audit, test, SAST, package signing.

**Rationale:**

| Gate | Purpose |
|------|---------|
| fmt/clippy | Code quality |
| audit/deny | Dependency & license safety |
| CodeQL/Semgrep | SAST scanning |
| Tests | Prevent regressions |

**Implications:**  
Only secure, clean code enters main.

---

### D011: Deployment Automation – GPG Signed Artifacts

**Status:** Accepted  
**Category:** DevOps – Release  

**Decision:**  
Sign `.deb` and `.rpm` with GPG during CI.

**Rationale:**  
Integrity & tamper protection.

**Implications:**  
Requires secure CI secrets.

---

### D012: Policy Authority CLI – keygen + sign

**Status:** Accepted  
**Category:** Architecture – Tooling  

**Decision:**  
CLI provides:  
- `keygen` -> generate P256 keypairs  
- `sign` -> sign YAML UEP policies  

**Rationale:**

| Benefit | Detail |
|---------|--------|
| Offline trust root | Admin can sign policies securely |
| Simplicity | No external systems needed |

**Implications:**  
Central to policy lifecycle.

---

### D013: Static Analysis – Semgrep + CodeQL

**Date:** Sprint 1  
**Status:** Accepted  
**Category:** Quality – SAST  

**Context:**  
Security-critical Rust code must be continuously scanned for vulnerabilities, insecure patterns, dependency issues and logic flaws. Manual reviews alone are insufficient.

**Decision:**  
Integrate **Semgrep** + **GitHub CodeQL** in CI/CD for automated static analysis.

**Rationale:**

| Feature | Why Needed |
|---------|------------|
| Semgrep rules | Fast pattern-based detection |
| CodeQL security queries | Deep semantic detection of Rust vulnerabilities |
| Automated CI | Prevents insecure merges |
| Low false-positives | Stable Rust rulesets |

**Alternatives Considered:**

| Tool | Cons |
|------|------|
| Only Clippy | Lints but no security scanning |
| SonarQube | Heavy + needs server |
| Manual review | High risk of human error |

**Implications:**  
- Blocks insecure PRs  
- Ensures ongoing compliance  
- Early detection of insecure dependencies  

**Related Decisions:** D010, D015  

---

### D014: API Specification v1.0 – Protobuf Schemas

**Date:** Sprint 1  
**Status:** Accepted  
**Category:** Architecture – API  

**Context:**  
Guardian nodes must use a consistent, versioned API for P2P communication: peer discovery, ping, attestation, policy sync.

**Decision:**  
Define complete **Protobuf v1.0 API** covering:  
- `peer.proto`  
- `ping.proto`  
- `policy.proto`

**Rationale:**

| Benefit | Description |
|---------|-------------|
| Strong typing | Prevents breaking changes |
| Backward compatible | Proto fields can evolve safely |
| Auto-generated code | Reduces errors |
| Cross-platform | Future support for other languages |

**Alternatives Considered:**  
REST JSON -> too slow, no typing.  
Custom binary -> insecure, heavy engineering.

**Implications:**  
- Every change requires versioning  
- Ensures clean communication contracts  

**Related Decisions:** D002, D004  

---

### D015: Code Quality Tools – fmt, clippy, audit, deny

**Date:** Sprint 1  
**Status:** Accepted  
**Category:** Quality – Code Hygiene  

**Context:**  
Large distributed system requires strict coding standards to avoid drift, bugs and unsafe code patterns.

**Decision:**  
Enforce:  
- `cargo fmt`  
- `cargo clippy`  
- `cargo audit`  
- `cargo deny`  

**Rationale:**

| Tool | Purpose |
|------|---------|
| fmt | Formatting consistency |
| clippy | Catch logic bugs |
| audit | Detect vulnerable crates |
| deny | License & version compliance |

**Alternatives Considered:**  
No enforcement -> inconsistent, unsafe code.

**Implications:**  
- All PRs must pass quality gates  
- Reduces tech debt  

---

### D016: Feature Deferrals – PQC & AI/ML

**Date:** Sprint 1  
**Status:** Accepted  
**Category:** Scope – Prioritization  

**Context:**  
PQC & anomaly-detection ML are future capabilities but not required for Phase 1 MVP.

**Decision:**  
Defer PQC algorithms, AI inference and behavioral ML models.

**Rationale:**

| Reason | Explanation |
|--------|-------------|
| Complexity | PQC not stable yet (NIST finalization) |
| Time constraint | Phase 1 limited to 8 weeks |
| Dependencies | AI requires stable metrics + audit pipeline |

**Implications:**  
- Architecture must remain PQC-ready  
- Policy engine must allow future ML hooks  

**Related Decisions:** D003, D007  

---

### D017: Node Identity – ECDSA P-256 Key Manager

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Architecture – Identity  

**Context:**  
Each node must maintain a durable cryptographic identity for attestation and mTLS sessions.

**Decision:**  
Implement `key_manager.rs` storing persistent **ECDSA P-256** keypairs.

**Rationale:**

| Benefit | Detail |
|---------|--------|
| Durable | Identity remains across reboots |
| Secure | Industry-standard curve |
| Compatible | Works with future TPM integration |

**Alternatives Considered:**  
Ephemeral keys -> breaks Circle-of-Trust.

**Implications:**  
- Nodes must protect private key files  
- All trust decisions bind to this identity  

---

### D018: Peer Discovery – mDNS

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Architecture – Networking  

**Context:**  
Nodes must automatically find peers without manual config.

**Decision:**  
Use **mDNS** broadcasting `_sgx-guardian._tcp` with nonce exchange.

**Rationale:**

| Feature | Benefit |
|---------|---------|
| Zero-config | Ideal for LAN deployments |
| Nonce in TXT | Prevents replay |
| Standard protocol | Works across systems |

**Alternatives Considered:**  
Static IP lists -> brittle.  
Consul -> too heavy.

**Implications:**  
- Requires mDNS-open networks  
- Part of Circle-of-Trust boot sequence  

---

### D019: Attestation Service – Evidence Signing

**Status:** Accepted  
**Category:** Architecture – Security  

**Context:**  
Nodes must prove they are alive and enforcing same policy.

**Decision:**  
Attestation evidence = signature over:  
`(peer nonce + self nonce + policy digest)`

**Rationale:**

| Benefit | Description |
|---------|-------------|
| Liveness check | Peer nonce prevents replay |
| Policy binding | Digest ties identity to active rules |
| Lightweight | Works even on small devices |

**Alternatives:** TPM attestation now -> too complex for Phase 1.

**Implications:**  
- Foundation for VirtualID  
- Enables mutual verification  

---

### D020: Discovery + Attestation Integration

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Architecture – Integration  

**Context:**  
Discovery alone is useless unless trust handshake begins immediately.

**Decision:**  
Automatically start attestation upon peer discovery event.

**Rationale:**

| Benefit | Detail |
|---------|--------|
| Autonomous | No admin input required |
| Fast | Trust formation within seconds |
| Consistent | Every peer validates every peer |

**Alternatives:** Manual trigger -> slow.

**Implications:**  
- Needs async concurrency management (Tokio)  

---

### D021: Background Task Model – Tokio Runtime

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Implementation – Runtime  

**Context:**  
Guardian daemon must run discovery, attestation, timers, TCP listeners, log writers, all in parallel.

**Decision:**  
Use **Tokio**'s async scheduler for tasks.

**Rationale:**

| Benefit | Description |
|---------|-------------|
| Scalable | Handles many tasks efficiently |
| Async I/O | Ideal for network-heavy workloads |
| Stable | Industry-trusted runtime |

**Alternatives:**  
Threads -> too heavy; no structured async.

**Implications:**  
- Requires structured cancellation on shutdown  

---

### D022: CLI Enhancements – peers + attestation

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Architecture – Tooling  

**Context:**  
Admins need visibility into real-time trust status.

**Decision:**  
Add commands:  
- `sgx-pa-cli peers`  
- `sgx-pa-cli attestation`

**Rationale:**

| Feature | Benefit |
|---------|---------|
| Live data | Reads JSON logs directly |
| Helpful | Shows trusted peers & last attestation |
| Zero dependency | CLI works without daemon RPC |

**Alternatives:**  
Direct gRPC -> adds complexity for Phase 1.

**Implications:**  
- Log formats must remain stable  

---

### D023: CLI Data Source – Structured JSON Logs

**Status:** Accepted  
**Category:** Architecture – Observability  

**Context:**  
CLI must not block daemon operations.

**Decision:**  
Use JSON files (`trusted_peers.json`, `last_attestation.json`) as data sources.

**Rationale:**

| Benefit | Detail |
|---------|--------|
| Decoupled design | CLI reads logs, not memory |
| Reliable | Safe during daemon restarts |
| Simple parsing | JSON maps cleanly to Rust structs |

**Alternatives:**  
Direct socket -> risk of blocking daemon.

**Implications:**  
- Log writers must guarantee atomic writes  

---

### D024: Enhanced Logging for Discovery & Attestation

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Implementation – Logging  

**Context:**  
Need complete traceability of discovery events and attestation flows.

**Decision:**  
Add structured JSON logs for:  
- discovery results  
- attestation success/failure  
- timestamps  
- peer VirtualID  

**Rationale:**

| Benefit | Description |
|---------|-------------|
| Forensics | Audit chain for trust issues |
| CLI visibility | Live consumption |
| Monitoring | Helps detect unstable peers |

**Alternatives:**  
Plain text logs -> unreadable for tools.

**Implications:**  
- Must define stable JSON schema  

---

### D025: Unit & Integration Testing Framework

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Quality – Testing  

**Context:**  
Guardian must operate reliably across multiple async subsystems. Tests must cover CLI, discovery, attestation and basic policy loading.

**Decision:**  
Implement full suite of:  
- **Unit Tests** (Rust modules)  
- **Integration Tests** (`tests/`)  
- **CLI Output Tests** (`cli_output.rs`)  

**Rationale:**

| Benefit | Explanation |
|---------|-------------|
| Early bug detection | Catch logic issues before deployment |
| Stability | Prevent regressions in trust formation |
| Realistic behavior | Integration tests simulate multi-node workflow |

**Alternatives Considered:**  
Manual testing -> unreliable, slow.

**Implications:**  
- All features require test coverage  
- CI runs tests on PR automatically  

**Related Decisions:** D010, D026  

---

### D026: Multi-Node Simulation – Node A/B/C

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Quality – Distributed Testing  

**Context:**  
Trust formation is a distributed process. Must verify behavior across multiple nodes on a LAN.

**Decision:**  
Create **3-node LAN simulation** (A, B, C) with discovery, attestation and timestamp tracking.

**Rationale:**

| Benefit | Explanation |
|---------|-------------|
| Realistic test | Simulates real deployment environment |
| Validates flow | Discovery -> Attestation -> Trust storage |
| Stability check | Peer flapping detection |

**Alternatives:**  
Single-node mock -> cannot validate Circle-of-Trust.

**Implications:**  
- Requires orchestration script (`run_three_nodes.sh`)  
- Essential for milestone demos  

---

### D027: TCP Attestation Listener

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Architecture – Networking  

**Context:**  
Attestation must be bidirectional; nodes must receive inbound attestation as well as initiate outbound.

**Decision:**  
Implement `start_attestation_listener` on **dynamic port = base_port + 100**.

**Rationale:**

| Benefit | Detail |
|---------|-------|
| Bidirectional trust | Both peers validate each other |
| Flexibility | Avoids port conflicts |
| Async friendly | Clean handling in Tokio |

**Alternatives:**  
HTTP-based endpoint -> slower, heavier.

**Implications:**  
- Must update firewall rules if required  
- Part of core trust handshake  

**Related Decisions:** D019, D021  

---

### D028: Trusted Peer + Evidence Logs

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Architecture – Trust  

**Context:**  
Trust decisions must persist across restarts and provide transparency to administrators.

**Decision:**  
Write structured logs:  
- `trusted_peers.json`  
- `last_attestation.json`

**Rationale:**

| Feature | Benefit |
|---------|---------|
| Durability | Survives reboot |
| Transparency | CLI uses logs directly |
| Forensics | Allows replay & debugging |

**Alternatives:**  
In-memory state -> lost on restart.

**Implications:**  
- Must guarantee atomic writes  
- JSON schema must stay backward-compatible  

---

### D029: Re-Attestation Timer (60 Seconds)

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Architecture – Trust Refresh  

**Context:**  
Trust must be continuously renewed to maintain zero-trust posture.

**Decision:**  
Every node re-attests peers every **60 seconds**.

**Rationale:**

| Benefit | Explanation |
|---------|------------|
| Fresh trust | Detects stale/compromised peers |
| Automatic | No operator action required |
| Consistent | Works across entire cluster |

**Alternatives:**  
Manual re-attest -> unreliable.

**Implications:**  
- Increased periodic network traffic (minimal)  
- Logs updated every cycle  

---

### D030: Auto Re-Attest on Startup

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Architecture – Resilience  

**Context:**  
If node restarts, it must quickly rejoin Circle-of-Trust without manual intervention.

**Decision:**  
On startup, verify all peers in `trusted_peers.json`.

**Rationale:**

| Benefit | Detail |
|---------|--------|
| Seamless recovery | No trust downtime |
| Fast convergence | Node joins existing trust mesh quickly |

**Alternatives:**  
Wait for next timer -> delayed trust restoration.

**Implications:**  
- Startup includes trust-refresh operations  
- Requires stable log state  

---

### D031: Timestamp Refresh on Successful Re-Attestation

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Architecture – Trust Health  

**Context:**  
Admins must see accurate, up-to-date trust timestamps.

**Decision:**  
Every successful attestation updates `last_seen` timestamp in `trusted_peers.json`.

**Rationale:**

| Feature | Benefit |
|---------|---------|
| Real-time monitoring | Admin sees active peers |
| Accuracy | Prevents stale peer entries |

**Alternatives:**  
Static timestamps -> misleading trust state.

**Implications:**  
- CLI displays live trust health  
- Timestamp must use consistent ISO format  

---

### D032: Failure Handling – Retry Loop + NetworkError Logs

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Implementation – Reliability  

**Context:**  
Network instability can temporarily break trust handshakes.

**Decision:**  
Add retry loop (3 attempts) + structured `[NetworkError]` logs.

**Rationale:**

| Benefit | Detail |
|---------|--------|
| Resilience | Recovers from transient issues |
| Clarity | Clean logging supports debugging |

**Alternatives:**  
Immediate failure -> too fragile.

**Implications:**  
- Improves reliability in unstable networks  
- Clear error patterns for monitoring systems  

---

### D033: CLI Sync Validation

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Quality – Verification  

**Context:**  
CLI output must always match real trust state in logs.

**Decision:**  
Validate that `peers` and `attestation` commands reflect updated timestamps and evidence.

**Rationale:**

| Benefit | Detail |
|---------|--------|
| Consistency | CLI always matches daemon output |
| Transparency | Admins rely on accurate trust data |

**Alternatives:**  
No validation -> risk of stale results.

**Implications:**  
- CLI must parse logs correctly  
- Schema changes must sync with CLI  

---

### D034: Autonomous Circle-of-Trust Demo

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Architecture – Distributed System  

**Context:**  
Client demo requires showing automatic peer discovery + mutual attestation forming trust mesh.

**Decision:**  
Demonstrate nodes A, B, C boot -> discover each other  ->  mutually attest -> form stable mesh.

**Rationale:**

| Benefit | Explanation |
|---------|------------|
| Proof of capability | Validates end-to-end trust flow |
| Realistic | Matches production topology |

**Alternatives:**  
Manual scripts -> less convincing, less realistic.

**Implications:**  
- Demo scripts must reflect real system behavior  

---

### D035: Multi-Node Automation Script

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Process – Automation  

**Context:**  
Manually starting 3 nodes is error prone.

**Decision:**  
Enhance `run_three_nodes.sh` to auto-start, wait, verify, summarize logs.

**Rationale:**

| Benefit | Detail |
|---------|--------|
| Reproducibility | Same test every time |
| Speed | Instant multi-node setup |
| Validation | Script checks trust mesh formation |

**Alternatives:**  
Manual start -> slow & inconsistent.

**Implications:**  
- Script becomes mandatory for demo/testing  

---

### D036: Peer Log Merging – jq Consolidation

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Architecture – Observability  

**Context:**  
Each node logs trusted peers separately; admin needs unified view.

**Decision:**  
Use:  
```
jq -s 'add | unique_by(.peer_id)'
```
to merge all node logs into one consolidated file.

**Rationale:**

| Feature | Benefit |
|---------|---------|
| Unified trust map | Full network-wide peer view |
| Deduplication | Removes repeated entries |
| Scriptable | Easy integration into tools |

**Alternatives:**  
Custom merger -> requires more code.

**Implications:**  
- Enables centralized trust visualization  
- Requires consistent JSON schemas  

---

### D037: TLS Module – mTLS Foundation

**Date:** Sprint 3  
**Status:** Accepted  
**Category:** Architecture – Security  

**Context:**  
System required a transport security layer for encrypted gRPC communication.  
No centralized TLS module existed in Sprint 1–2.

**Decision:**  
Create `src/tls.rs` implementing:  
- Rustls server/client builders  
- Certificate + key loaders  
- Mutual-auth enforcement  
- TLS configuration tests using rcgen  

**Rationale:**  
Centralizing TLS prevents duplication and ensures consistent Zero-Trust defaults.

**Implications:**  
All gRPC layers now depend on this TLS foundation.

---

### D038: Certificate Lifecycle – Persistent Node Identity

**Date:** Sprint 3  
**Status:** Accepted  
**Category:** Architecture – Identity  

**Context:**  
Nodes had persistent keys but no certificates for mTLS.  
Tonic required PEM, but project assets were DER formatted.

**Decision:**  
Implement certificate lifecycle:  
- Generate or load `sgx-agent/device_cert.der`  
- Bind certificate to device.key  
- Convert DER -> PEM at runtime  
- Include SAN hostname + 127.0.0.1  
- Expose `ensure_node_certificate_or_generate()`  

**Rationale:**  
Node must have a stable, durable identity for secure channels.

**Implications:**  
Same identity persists across restarts and forms basis for authentication.

---

### D039: Secure gRPC mTLS Channel Integration

**Date:** Sprint 3  
**Status:** Accepted  
**Category:** Architecture – Communication Security  

**Context:**    
Next step was to fully secure server.rs & client.rs with mTLS.

**Decision:**  
Integrate mTLS into gRPC transport layer:  
- Use ServerTlsConfig + ClientTlsConfig  
- DER -> PEM conversion for Identity  
- TLS server starts before attestation  
- Secure Ping/Pong RPC implemented  
- Add audit-proof logs  

**Rationale:**  
Meets Sprint-3 deliverable: secure communication between nodes.

**Implications:**  
All cross-node communication is now encrypted & authenticated.

---

### D040: Policy Signing Engine – Deterministic Digest & Signature Core

**Date:** Sprint 3  
**Status:** Accepted  
**Category:** Architecture – Policy Security  

**Context:**  
SG-X Guardian requires that administrative policies be cryptographically signed before distribution.  
Policy signatures must remain stable across platforms and formatting differences.

**Decision:**  
Implement a dedicated policy signing engine in `sgx-pa-cli` that:
- Normalizes YAML input
- Computes SHA-256 policy digest
- Signs digest using ECDSA P-256
- Produces a signed policy envelope

**Rationale:**

| Requirement | Implementation |
|------------|----------------|
| Deterministic digest | YAML normalization + CRLF handling |
| Strong cryptography | SHA-256 + ECDSA P-256 |
| Portability | Base64 encoding |
| Auditability | Explicit digest + public key |

**Alternatives Considered:**  
Raw file signing (breaks on whitespace), binary formats (not admin-friendly).

**Implications:**  
Establishes cryptographic root-of-trust for policy lifecycle.

**Related Decisions:** D004, D012, D041

---

### D041: Signed Policy Envelope – JSON + Base64 Format

**Date:** Sprint 3  
**Status:** Accepted  
**Category:** Architecture – Policy Distribution  

**Context:**  
Signed policies must be portable, inspectable and self-contained.

**Decision:**  
Define a JSON-based signed policy envelope containing:
- version
- policy_b64
- digest_hex
- signature_b64
- signing_pubkey_b64

**Rationale:**

| Feature | Benefit |
|-------|---------|
| JSON | Human-readable |
| Base64 | Binary-safe |
| Embedded pubkey | Self verifying artifact |
| Versioning | Forward compatibility |

**Alternatives Considered:**  
Detached signatures, ASN.1 blobs, YAML based signing.

**Implications:**  
Policy and signature travel as a single trust artifact.

**Related Decisions:** D040, D042

---

### D042: Policy Verification CLI – Offline Trust Validation

**Date:** Sprint 3  
**Status:** Accepted  
**Category:** Architecture – Tooling  

**Context:**  
Administrators must verify policy integrity without running Guardian nodes.

**Decision:**  
Add `verify` command to `sgx-pa-cli` that:
- Validates envelope version
- Recomputes digest
- Verifies ECDSA signature
- Rejects tampered policies

**Rationale:**

| Benefit | Explanation |
|-------|-------------|
| Offline verification | No daemon dependency |
| Fail-fast | Immediate rejection |
| Transparency | Clear CLI output |

**Implications:**  
Improves admin confidence and operational safety.

**Related Decisions:** D041, D043

---

### D043: Policy Manager – Cryptographic Verification in Guardian

**Date:** Sprint 3  
**Status:** Accepted  
**Category:** Architecture – Policy Enforcement  

**Context:**  
Guardian nodes must never load untrusted or tampered policy data.

**Decision:**  
Implement `policy_manager.rs` to:
- Parse signed policy envelope
- Verify digest and signature
- Reject invalid policies at startup

**Rationale:**

| Principle | Enforcement |
|---------|-------------|
| Zero-Trust | No implicit trust |
| Fail-closed | Exit on invalid policy |
| Consistency | Same verification logic as CLI |

**Implications:**  
Policy trust boundary enforced inside daemon.

**Related Decisions:** D040, D042, D044

---

### D044: Atomic Policy Activation with Rollback

**Date:** Sprint 3  
**Status:** Accepted  
**Category:** Architecture – Reliability  

**Context:**  
Policy updates must never leave system in partial or corrupted state.

**Decision:**  
Use atomic filesystem-based policy activation:
- pending_policy.yaml
- active_policy.yaml
- backup_policy.yaml

Rollback occurs automatically on failure.

**Rationale:**

| Feature | Benefit |
|-------|---------|
| Atomic rename | Crash-safe |
| Backup policy | Guaranteed rollback |
| No database | Lightweight edge design |

**Implications:**  
Policy updates are safe and reversible.

**Related Decisions:** D043, D045

---

### D045: Runtime Policy Cache – once_cell + RwLock

**Date:** Sprint 3  
**Status:** Accepted  
**Category:** Implementation – Runtime  

**Context:**  
Activated policies must be efficiently accessible by runtime subsystems.

**Decision:**  
Store active policy in memory using:
- once_cell::Lazy
- Arc<RwLock<Option<Policy>>>

**Rationale:**

| Benefit | Explanation |
|-------|-------------|
| Fast access | No repeated file reads |
| Thread-safe | Async compatible |
| Extensible | Supports future hot-reload |

**Implications:**  
Runtime always enforces verified policy.

**Related Decisions:** D044, D047

---

### D046: End-to-End Policy Lifecycle Demonstration (Milestone Demo 2)

**Date:** Sprint 3  
**Status:** Accepted  
**Category:** Process – Milestone Validation  

**Context:**  
Sprint 3 required a complete, demonstrable policy trust workflow.

**Decision:**  
Demonstrate full lifecycle:
1. Admin signs policy via CLI
2. Policy distributed to nodes
3. Nodes verify signature
4. Policy activates atomically
5. Runtime enforces policy

**Rationale:**

| Goal | Outcome |
|----|--------|
| Trust proof | Cryptographically verifiable |
| Realism | Matches production workflow |
| Confidence | Visible security guarantees |

**Implications:**  
Sprint 3 policy automation is fully complete.

**Related Decisions:** D040–D046

---

### D047: Secure Element as Hardware Root of Trust

**Date:** Sprint 1  
**Status:** Accepted  
**Category:** Architecture – Hardware Security  

**Context:**  
Phase 1 used software-based identity and software attestation to validate the Circle of Trust workflow. Phase 2 required stronger device assurance by anchoring identity and cryptographic operations in hardware instead of relying only on operating system protected files.

**Decision:**  
Use an embedded secure element as the hardware root of trust for SG-X Guardian devices.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Security | Private keys and sensitive cryptographic operations are isolated from the main processor |
| Tamper resistance | Secure element storage is harder to extract or modify than filesystem keys |
| Trust foundation | Provides a hardware backed identity anchor for attestation and DKP lifecycle |
| Phase 2 alignment | Directly supports hardware attestation, PCR validation and secure boot trust chain |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Software-only keys | Simple and fast to implement | Private keys remain exposed to OS compromise risk |
| TPM-only design | Strong hardware trust model | Less aligned with current secure element integration work |
| External HSM | Very secure | Not practical for embedded edge deployment |
| Cloud key custody | Centralized control | Breaks edge-first and offline trust requirements |

**Implications:**  
- Device identity becomes hardware-backed instead of software-only.  
- Signing and attestation workflows must integrate with secure element APIs.  
- Future compromise of the host OS should not directly expose device private keys.  
- Testing must include secure element availability, initialization and failure handling.

**Related Decisions:** D048, D049, D050, D079  

---

### D048: Secure Element Driver and Cryptographic Subsystem Initialization

**Date:** Sprint 1  
**Status:** Accepted  
**Category:** Implementation – Secure Element  

**Context:**  
The secure element cannot be safely used by the Guardian runtime unless communication, initialization and error handling are isolated behind a stable software abstraction. Direct hardware access scattered across the codebase would increase maintenance and security risk.

**Decision:**  
Implement a dedicated secure element driver layer and initialize the cryptographic subsystem during Guardian startup.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Modularity | Keeps hardware access isolated from attestation and key management logic |
| Reliability | Centralized initialization allows clear startup validation |
| Maintainability | Future secure element models can be supported behind the same abstraction |
| Security | Reduces accidental misuse of low-level secure element commands |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Direct calls from attestation code | Fast initial implementation | Creates tight coupling and fragile code |
| Shelling out to vendor CLI everywhere | Easy for testing | Hard to secure, parse and control in production |
| No abstraction layer | Less code initially | Long-term maintenance risk |

**Implications:**  
- Secure element setup becomes part of the boot/startup path.  
- Initialization failure must produce clear logs and fail safely.  
- Higher-level modules should depend on the secure element abstraction, not vendor-specific details.  
- Enables clean testing with mock secure element behavior.

**Related Decisions:** D047, D049, D052, D079  

---

### D049: Secure Element Protected Key Storage

**Date:** Sprint 1  
**Status:** Accepted  
**Category:** Implementation – Secure Element  

**Context:**  
Phase 2 required moving sensitive device identity material away from plain filesystem storage. The private portion of the Device Key Pair must remain protected even if the Linux userspace is compromised.

**Decision:**  
Store Guardian device private keys inside secure element protected key slots.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Key protection | Private key material is not written to disk |
| Attack reduction | Filesystem theft no longer directly exposes the DKP private key |
| Hardware trust | Key storage becomes bound to the device hardware |
| Attestation readiness | Hardware-backed keys can sign attestation evidence without export |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Filesystem key files | Easy backup and debugging | High exposure risk if OS is compromised |
| Encrypted key file | Better than plaintext | Decryption still occurs in software memory |
| Remote key server | Centralized control | Breaks offline edge operation |
| Secure element storage | Strong protection | Requires hardware integration and lifecycle tooling |

**Implications:**  
- Key backup and migration require explicit lifecycle design.  
- Signing operations must use key handles instead of raw private keys.  
- Provisioning must verify key slot creation and access permissions.  
- Hardware failure handling must be documented.

**Related Decisions:** D047, D050, D051, D052  

---

### D050: Hardware Key Manager for DKP Lifecycle

**Date:** Sprint 1  
**Status:** Accepted  
**Category:** Architecture – Identity  

**Context:**  
The Device Key Pair is central to Guardian identity, attestation signing and trust establishment. Phase 2 required lifecycle management beyond simple generation, including rotation and revocation.

**Decision:**  
Implement a Hardware Key Manager responsible for secure element backed DKP generation, metadata tracking, rotation and revocation.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Identity lifecycle | DKP operations need one controlled authority inside the daemon |
| Security | Prevents unmanaged key creation and accidental key reuse |
| Operations | Enables admin-visible key state and rotation readiness |
| Future readiness | Supports DID, certificate and hardware attestation integration |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Ad hoc key commands | Simple for prototypes | No lifecycle consistency |
| Manual vendor CLI use | Useful during bring up | Not production grade |
| Software key manager only | Reuses Phase 1 pattern | Does not satisfy hardware backed identity requirement |
| Hardware Key Manager | Structured and secure | Requires additional implementation and testing |

**Implications:**  
- DKP status becomes a first-class operational state.  
- Rotation and revocation workflows can be tested independently.  
- CLI and logs should expose key status without exposing secret material.  
- Future DID and certificate binding can reference DKP public identity.

**Related Decisions:** D049, D051, D053, D056  

---

### D051: Non-Exportable DKP Private Key Model

**Date:** Sprint 1  
**Status:** Accepted  
**Category:** Architecture – Identity  

**Context:**  
A hardware-backed key loses much of its security value if the private key can be exported into software memory. The DKP private key must remain inside the secure element for all lifecycle stages.

**Decision:**  
Adopt a non-exportable private key model for the Device Key Pair.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Confidentiality | Private key never leaves secure hardware |
| Compromise resistance | Malware cannot simply read key bytes from disk or process memory |
| Trust binding | Identity becomes tied to the physical device |
| Compliance posture | Better aligns with hardware-rooted trust expectations |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Exportable private key | Easier backup and migration | Weakens the root of trust |
| Encrypted export | Supports recovery | Still creates key material outside hardware boundary |
| Software-only rotation | Simple | Does not prove hardware possession |
| Non-exportable DKP | Strong trust model | Requires key handle-based APIs |

**Implications:**  
- All signing must be performed by requesting the secure element to sign.  
- Recovery and replacement workflows must use rotation, not private key export.  
- Device identity becomes strongly bound to hardware presence.  
- Attestation can prove possession without exposing the key.

**Related Decisions:** D049, D050, D052, D079  

---

### D052: Secure Element Signing Boundary

**Date:** Sprint 1  
**Status:** Accepted  
**Category:** Implementation – Secure Element  

**Context:**  
The Guardian must use private keys for signing attestation quotes, DKP proof and security events. Allowing software to handle raw private keys would violate the Phase 2 hardware security model.

**Decision:**  
Keep all private-key signing operations inside the secure element boundary.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Security | Prevents private key extraction during signing |
| Consistency | All DKP signatures follow the same hardware backed path |
| Auditability | Signing requests can be logged without exposing key material |
| Attestation strength | Quote signatures prove hardware backed possession |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Software signing | Fast and easy | Private key must exist in software memory |
| Hybrid software/hardware signing | Flexible | Creates inconsistent trust guarantees |
| Secure element only signing | Strongest protection | Requires robust error handling and test coverage |

**Implications:**  
- Signing APIs must accept payloads and return signatures, not keys.  
- Secure element failure blocks hardware backed attestation.  
- Signature logs must include key IDs and operation status only.  
- Performance testing must confirm signing latency is acceptable.

**Related Decisions:** D048, D049, D051, D080  

---

### D053: DKP Rotation and Revocation Workflow

**Date:** Sprint 1  
**Status:** Accepted  
**Category:** Architecture – Identity  

**Context:**  
A production identity system must support key rotation and revocation. If a DKP is suspected stale, compromised, or replaced during maintenance, the system must update trust state without breaking the entire Circle permanently.

**Decision:**  
Implement DKP lifecycle support for generation, rotation and revocation.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Security hygiene | Keys should not remain valid forever |
| Incident response | Suspected identity compromise must be recoverable |
| Operational continuity | Rotation allows controlled transition to a new DKP |
| Future compatibility | Supports DID document updates and certificate renewal |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Static DKP forever | Simple | Poor security lifecycle |
| Manual reprovision only | Clean reset | Operationally disruptive |
| Rotation without revocation | Easier | Does not handle compromise |
| Full lifecycle workflow | Secure and maintainable | Requires metadata and state tracking |

**Implications:**  
- DKP metadata must track active, rotated and revoked states.  
- Certificates and DID bindings must update after rotation.  
- Revoked keys must not be accepted during attestation.  
- Tests must verify generation, rotation and revocation behavior.

**Related Decisions:** D050, D051, D056, D058  

---

### D054: Nebula Mesh as Circle Transport Layer

**Date:** Sprint 1  
**Status:** Accepted  
**Category:** Architecture – Mesh Networking  

**Context:**  
Phase 1 focused on Circle of Trust concepts and secure peer communication. Phase 2 required a practical encrypted overlay layer to support real peer-to-peer networking across local and remote environments.

**Decision:**  
Use Nebula mesh networking as the Circle transport layer for Guardian-to-Guardian communication.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Mesh networking | Supports peer-to-peer encrypted overlay communication |
| Certificate model | Aligns with Circle membership and CA-based authorization |
| NAT traversal | Supports lighthouse-assisted peer discovery |
| Relay support | Enables connectivity when direct peer paths fail |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Static WireGuard tunnels | Secure and fast | Less flexible for dynamic Circle membership |
| Plain gRPC over public IP | Simple | Weak NAT traversal and network abstraction |
| Custom overlay protocol | Full control | High engineering and security risk |
| Nebula mesh | Proven and flexible | Requires config generation and lifecycle management |

**Implications:**  
- Guardian must generate and manage Nebula configuration.  
- Circle certificates become part of networking trust.  
- Overlay IP assignment is required.  
- Lighthouse and relay features can extend connectivity.

**Related Decisions:** D055, D067, D070, D075  

---

### D055: Nebula CA Operations for Circle Certificates

**Date:** Sprint 1  
**Status:** Accepted  
**Category:** Architecture – Mesh Networking  

**Context:**  
Nebula requires certificate based trust. A Circle owner must be able to issue certificates to approved members and revoke or rotate them when required.

**Decision:**  
Implement Nebula Certificate Authority operations for Circle-based mesh certificates.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Circle ownership | Circle owner controls certificate issuance |
| Membership enforcement | Only approved members receive validmesh certificates |
| Operational control | Certificates can include groups, permissions and expiry |
| Mesh security | Peers authenticate before joining overlay communication |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Pre-shared static certificates | Simple | Poor lifecycle and poor scalability |
| Cloud-only CA | Centralized management | Breaks offline Circle operation |
| Manual certificate generation | Good for lab | Error-prone for production |
| Nebula CA operations | Aligned with Circle model | Requires secure CA key handling |

**Implications:**  

- Circle owner must protect CA material.  
- Certificate issuance becomes part of member onboarding.  
- Certificate renewal and revocation workflows are required.  
- Mesh trust depends on certificate validity.

**Related Decisions:** D054, D056, D057, D058  

---

### D056: DID to Overlay IP Certificate Binding

**Date:** Sprint 1  
**Status:** Accepted  
**Category:** Architecture – Identity  

**Context:**  
A Nebula certificate must identify not just an IP address but the trusted Guardian identity behind that address. Without identity binding, overlay IPs could become detached from long-term trust anchors.

**Decision:**  
Bind Guardian identity information, including DID or DID-derived identity metadata, to the assigned Nebula overlay IP in Circle certificates.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Identity continuity | Overlay IP maps back to a known Guardian identity |
| Auditability | Logs can correlate peer activity with DID and overlay IP |
| Trust enforcement | Prevents unauthenticated IP-only membership |
| Future compatibility | Supports DID/VC workflows in later identity phases |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| IP-only certificate | Simple | Weak identity traceability |
| Hostname only binding | Human readable | Not globally unique enough |
| DID to IP binding | Strong identity mapping | Requires identity metadata management |
| Runtime only mapping | Flexible | Easier to desync from certificate state |

**Implications:**  
- Certificate metadata must include or reference Guardian identity.  
- Overlay IP allocation must be recorded with identity state.  
- Certificate renewal must preserve identity mapping.  
- Trust logs can reference both DID and overlay IP.

**Related Decisions:** D050, D055, D057, D067, D069  

---

### D057: Verifiable Credential Validation Before Certificate Issuance

**Date:** Sprint 1  
**Status:** Accepted  
**Category:** Architecture – Identity  

**Context:**  
Certificate issuance must not rely only on a manual request. A Guardian requesting a Circle certificate should prove membership authorization before receiving mesh access.

**Decision:**  
Validate Circle membership through Verifiable Credential evidence before issuing Nebula member certificates.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Authorization | Certificate issuance depends on cryptographic membership proof |
| Decentralization | Membership can be verified without a central online service |
| Security | Reduces risk of unauthorized certificate issuance |
| Auditability | Issuance decision can record VC subject, issuer and validity |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Manual approval only | Simple | Human error risk |
| Static allowlist | Easy to inspect | Hard to scale and maintain |
| Cloud approval | Centralized control | Breaks offline operation |
| VC validation | Strong decentralized proof | Requires credential parsing and validation |

**Implications:**  
- Certificate issuance flow must validate VC issuer and subject.  
- Expired or revoked credentials must be rejected.  
- CA logs should record credential validation result.  
- Future DID/VC work can build on this trust path.

**Related Decisions:** D055, D056, D058  

---

### D058: Time-Limited Nebula Certificates

**Date:** Sprint 1  
**Status:** Accepted  
**Category:** Architecture – Identity  

**Context:**  
Long lived certificates increase the risk window if a device is lost, compromised, or removed from a Circle. Phase 2 required stronger membership hygiene.

**Decision:**  
Issue time limited Nebula certificates for Circle members.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Reduced exposure | Expired certificates automatically stop being trusted |
| Lifecycle control | Renewal becomes a natural revalidation point |
| Incident safety | Limits damage from forgotten or stale certificates |
| Operational fit | Supports planned renewal and key rotation |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Permanent certificates | No renewal burden | High long term compromise risk |
| Manual revocation only | Direct control | Depends on operator action |
| Very short certificates | Strong security | Operationally noisy |
| Time limited certificates | Balanced security and usability | Requires renewal workflow |

**Implications:**  
- Certificate renewal must be supported.  
- Expiry monitoring should be visible in logs or CLI.  
- Expired certificates must fail mesh authentication.  
- Key rotation and DID binding must coordinate with certificate updates.

**Related Decisions:** D053, D055, D056, D057  

---

### D059: PCR Measurement Collection

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Architecture – Hardware Security  

**Context:**  
Hardware attestation requires a measurable device state. The Guardian must collect boot and platform measurements that represent firmware, bootloader, kernel and configuration integrity.

**Decision:**  
Implement PCR measurement collection during boot and runtime integrity validation.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Integrity evidence | PCRs represent measured platform state |
| Attestation input | PCR values can be signed in hardware attestation quotes |
| Tamper detection | Firmware or bootloader changes produce different measurements |
| Trust binding | PCR values can contribute to VirtualID and attestation decisions |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| No PCR collection | Simpler | Cannot prove platform state |
| Hash only application binary | Lightweight | Ignores boot chain and firmware |
| Manual version checks | Easy to read | Not cryptographically strong |
| PCR measurement | Strong integrity signal | Requires baseline and comparison logic |

**Implications:**  
- PCR values must be collected consistently.  
- PCR semantics must be documented.  
- Attestation depends on PCR availability.  
- Testing must include known-good and mismatched PCR scenarios.

**Related Decisions:** D060, D061, D062, D081  

---

### D060: Golden PCR Baseline Storage

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Architecture – Hardware Security  

**Context:**  
PCR values alone are not useful unless the verifier has a known good reference. The system needs a baseline to compare measured device state against expected trusted state.

**Decision:**  
Store golden reference PCR baselines for known good Guardian firmware, bootloader, kernel and configuration states.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Verification | Baseline enables pass/fail comparison |
| Repeatability | Same known-good state can be validated repeatedly |
| Auditability | Baseline record documents trusted configuration |
| Security | Unexpected platform changes can be detected |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Trust any PCR value | Simple | No integrity protection |
| Manual visual comparison | Easy in lab | Not scalable or reliable |
| Cloud only baseline | Centralized | Weak offline support |
| Local golden baseline | Works offline and supports deterministic validation | Requires secure storage and update control |

**Implications:**  
- Baseline updates must be controlled and auditable.  
- Different firmware versions may require different baselines.  
- PCR mismatch must trigger attestation failure.  
- Baseline files must be protected from unauthorized modification.

**Related Decisions:** D059, D061, D081, D084  

---

### D061: PCR Mismatch as Attestation Failure

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Architecture – Attestation  

**Context:**  
If measured PCR values do not match the known good baseline, the device state cannot be considered trusted. Allowing a peer with mismatched PCRs would weaken the entire Circle.

**Decision:**  
Treat PCR mismatch as hardware attestation failure.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Zero Trust | Trust must be earned through measured evidence |
| Tamper detection | Modified firmware or bootloader should fail validation |
| Safety | Prevents compromised nodes from joining trusted state |
| Clarity | Produces deterministic pass/fail behavior |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Warn only | Less disruptive | Allows potentially compromised peer |
| Manual override by default | Flexible | Weakens trust model |
| Ignore selected PCRs | Easier compatibility | Reduces measurement value |
| Fail attestation on mismatch | Secure and deterministic | Requires correct baseline management |

**Implications:**  
- Mismatched PCR devices are not trusted.  
- Logs must show which PCR failed.  
- CLI and demo output should clearly show attestation failure reason.  
- Baseline management becomes operationally important.

**Related Decisions:** D059, D060, D081, D082, D084  

---

### D062: Secure Boot Chain Validation

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Architecture – Hardware Security  

**Context:**  
PCR measurement detects state, but secure boot prevents unauthorized components from executing in the first place. Phase 2 required a boot chain that validates each stage before handing control forward.

**Decision:**  
Implement secure boot chain validation where each boot stage verifies the next stage before execution.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Boot integrity | Prevents tampered bootloader or firmware execution |
| Chain of trust | Establishes continuity from hardware root to software runtime |
| PCR reliability | Measurements become meaningful when tied to verified boot stages |
| Attack resistance | Reduces risk of persistent firmware level compromise |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Runtime-only validation | Easier | Too late if boot chain is compromised |
| Manual boot checks | Simple for demos | Not secure or automated |
| Secure boot validation | Strong protection | Requires platform specific integration |
| Trust firmware version string | Easy | Not cryptographic proof |

**Implications:**  
- Boot failure must halt or enter safe mode.  
- PCR measurements should reflect secure boot stages.  
- Firmware signing and verification procedures must be managed carefully.  
- Secure boot status becomes part of trust evaluation.

**Related Decisions:** D059, D060, D063, D079  

---

### D063: Fail-Closed Boot Integrity Model

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Security – Fail-Closed Enforcement  

**Context:**  
A security device must not continue operating as trusted if boot integrity cannot be verified. If boot verification fails, allowing normal operation would contradict the Zero Trust model.

**Decision:**  
Adopt a fail closed boot integrity model for secure boot and PCR validation failures.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Security | Unknown boot state is treated as untrusted |
| Determinism | Failure behavior is predictable |
| Trust protection | Prevents compromised devices from silently operating |
| Operational clarity | Operators receive clear failure state instead of hidden risk |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Fail-open | Keeps device online | Unsafe for security critical deployment |
| Warning-only mode | Less disruptive | Allows untrusted operation |
| Manual decision every time | Flexible | Slow and inconsistent |
| Fail-closed | Strongest security posture | Requires recovery workflow |

**Implications:**  
- Devices with failed boot integrity cannot be treated as trusted peers.  
- Recovery process must be documented.  
- Logs must distinguish secure boot failure from network failure.  
- Demo and tests must validate failure behavior.

**Related Decisions:** D061, D062, D082, D084  

---

### D064: Transport Agnostic Circle of Trust

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Architecture – Multi-Transport CoT  

**Context:**  
The Circle of Trust should not depend on a single physical network type. Guardian deployments may use Ethernet, WiFi, Bluetooth, cellular, or satellite depending on environment.

**Decision:**  
Design Circle of Trust membership, trust establishment and policy enforcement to be independent of the underlying transport.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Deployment flexibility | Works across LAN, wireless, remote and mobile environments |
| Trust consistency | Same trust rules apply regardless of transport |
| Resilience | Transport changes do not invalidate Circle membership |
| Future readiness | Supports additional transport types without redesigning trust logic |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| LAN-only CoT | Simple and fast | Not sufficient for real deployments |
| Separate trust per transport | Flexible | Duplicates logic and increases risk |
| Manual transport configuration | Predictable | Operationally fragile |
| Transport-agnostic CoT | Clean architecture | Requires interface detection and failover logic |

**Implications:**  
- Trust state must be bound to identity, not interface.  
- Transport modules must feed a common CoT layer.  
- Failover should preserve peer trust where possible.  
- Testing must include multiple interface conditions.

**Related Decisions:** D065, D066, D073, D074, D077, D078  

---

### D065: LAN and WiFi Auto-Detection

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Architecture – Multi-Transport CoT  

**Context:**  
Initial multi-transport work required automatic detection of common local connectivity paths. LAN and WiFi are primary deployment paths for Guardian lab and office setups.

**Decision:**  
Implement automatic interface detection and adaptation for LAN and WiFi connectivity.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Usability | Reduces manual setup for field users |
| Reliability | Detects available network paths at runtime |
| Demo readiness | Supports real 3-node office and lab testing |
| Foundation | Establishes pattern for cellular, Bluetooth and satellite extensions |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Manual interface selection | Simple implementation | Error-prone for users |
| LAN only detection | Easier | Ignores WiFi fallback |
| WiFi-only mode | Useful for mobile | Weak for wired deployments |
| LAN + WiFi auto detection | Balanced and practical | Requires interface monitoring |

**Implications:**  
- Runtime must monitor interface availability.  
- Logs should show selected transport.  
- Failover logic can build on detection results.  
- Tests MT-001 to MT-003 validate expected behavior.

**Related Decisions:** D064, D066, D078  

---

### D066: Transport Preference and Failover Model

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Architecture – Multi-Transport CoT  

**Context:**  
When multiple transports are available, Guardian needs a deterministic selection model. Without preference and failover rules, nodes may choose unstable or expensive paths unpredictably.

**Decision:**  
Implement a transport preference and failover model for available network interfaces.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Predictability | Operators can understand why a transport was selected |
| Resilience | Automatic failover keeps Circle connectivity alive |
| Cost control | Lower-cost and lower-latency transports can be preferred |
| Operational clarity | Logs can explain transport transitions |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Random available transport | Simple | Unpredictable behavior |
| Manual failover only | Operator control | Slow during outages |
| Always prefer latest connected | Simple | Can flap frequently |
| Defined preference model | Stable and explainable | Requires monitoring and state logic |

**Implications:**  
- Transport state must be tracked continuously.  
- Failover events must be logged.  
- Connection recovery should not reset trust unnecessarily.  
- Future AI routing can use this baseline.

**Related Decisions:** D064, D065, D073, D077, D078  

---

### D067: Nebula Overlay Network CIDR 192.168.100.0/24

**Date:** Sprint 3  
**Status:** Accepted  
**Category:** Architecture – Mesh Networking  

**Context:**  
Nebula mesh requires a predictable private overlay address range per Circle. Phase 2 required a standard CIDR for local testing and consistent configuration.

**Decision:**  
Use `192.168.100.0/24` as the default Nebula overlay network CIDR per Circle.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Simplicity | Easy to understand and configure |
| Lab consistency | Supports repeatable 3-node testing |
| Routing clarity | Separates overlay traffic from physical network addresses |
| Operational fit | Matches planned node overlay IP assignments |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Random CIDR per Circle | Reduces conflicts | Harder to debug |
| Use physical LAN IPs | No overlay mapping | Breaks mesh abstraction |
| Large `/16` overlay | More capacity | Overkill for Phase 2 |
| `192.168.100.0/24` | Simple and sufficient | Requires conflict awareness |

**Implications:**  
- Node overlay IPs can follow predictable patterns.  
- Circle owner must track assigned addresses.  
- Future deployments may override CIDR if conflicts exist.  
- Documentation and scripts can use consistent examples.

**Related Decisions:** D054, D056, D068, D069  

---

### D068: nebula0 Virtual Interface Creation

**Date:** Sprint 3  
**Status:** Accepted  
**Category:** Architecture – Mesh Networking  

**Context:**  
Nebula routes encrypted overlay traffic through a virtual network interface. Guardian needs a consistent interface target for peer communication, routing, monitoring, and troubleshooting.

**Decision:**  
Create and use the `nebula0` virtual interface for Circle overlay communication.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Isolation | Overlay traffic is separated from physical network interfaces |
| Observability | Operators can inspect a known interface |
| Routing | Peer-to-peer traffic can be routed consistently |
| Integration | Firewall and monitoring rules can target `nebula0` |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Use physical interface directly | Simpler | No overlay isolation |
| Dynamic interface names | Flexible | Hard to script and troubleshoot |
| Multiple interfaces per peer | Granular | Too complex for Phase 2 |
| Standard `nebula0` | Clear and operationally simple | Requires name consistency |

**Implications:**  
- Startup scripts must verify `nebula0` creation.  
- Troubleshooting commands can check `nebula0` status.  
- Logs and metrics can report overlay interface health.  
- Firewall rules can separate overlay and physical traffic.

**Related Decisions:** D054, D067, D069  

---

### D069: Overlay IP Allocation Tracking

**Date:** Sprint 3  
**Status:** Accepted  
**Category:** Architecture – Mesh Networking  

**Context:**  
Every Guardian in a Circle requires a unique overlay IP. Manual assignment risks collisions, inconsistent certificates, and broken peer routing.

**Decision:**  
Track overlay IP allocations in Circle state using a next-overlay-IP counter and member assignment records.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Collision prevention | Ensures each Guardian receives a unique overlay IP |
| Certificate consistency | Assigned IP can be embedded in member certificate |
| Auditability | Circle owner can trace which device received which IP |
| Automation | Supports repeatable onboarding and renewal |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Manual IP assignment | Simple in small labs | Error-prone |
| Random IP assignment | Easy automation | Collision handling required |
| DHCP inside overlay | Familiar model | Adds moving parts |
| Tracked allocation counter | Deterministic and simple | Requires persistent Circle state |

**Implications:**  
- Circle state must persist overlay allocation data.  
- Certificate issuance depends on allocation state.  
- Revoked or removed members require IP reuse policy.  
- Tests should verify no duplicate overlay IP assignment.

**Related Decisions:** D056, D067, D068  

---

### D070: Lighthouse-Based Peer Discovery

**Date:** Sprint 3  
**Status:** Accepted  
**Category:** Architecture – Mesh Networking  

**Context:**  
Guardians may run behind NAT, cellular networks, or restrictive firewalls. Direct peer discovery may fail without a stable discovery point.

**Decision:**  
Use Nebula lighthouse nodes for peer discovery and NAT traversal support.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| NAT traversal | Helps peers discover reachable endpoints |
| Mesh scalability | Reduces need for static peer configuration |
| Dynamic networks | Supports endpoint changes over time |
| Operational fit | Aligns with Nebula mesh design |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Static peer IPs | Simple in lab | Breaks with NAT and mobile networks |
| Central cloud broker | Easy coordination | Weakens self-hosted/offline model |
| Broadcast discovery only | Works on LAN | Not enough across WAN/cellular |
| Nebula lighthouse | Built for this use case | Requires lighthouse deployment and monitoring |

**Implications:**  
- At least one reachable lighthouse is needed for non-LAN peer discovery.  
- Lighthouse configuration must be generated and distributed.  
- Endpoint registration must update on network changes.  
- Lighthouse health affects mesh convergence.

**Related Decisions:** D054, D071, D072, D075  

---

### D071: Lighthouse Registry and Endpoint Updates

**Date:** Sprint 3  
**Status:** Accepted  
**Category:** Architecture – Mesh Networking  

**Context:**  
A lighthouse is only useful if it maintains current peer endpoint information. Guardians may change IP addresses when switching Wi-Fi, cellular, or satellite links.

**Decision:**  
Maintain lighthouse registry updates for peer public endpoint mappings during startup and network changes.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Freshness | Peers receive current public IP and port mappings |
| Failover support | Endpoint changes can be reflected after transport switch |
| NAT traversal | UDP hole punching depends on accurate endpoint data |
| Reliability | Reduces stale connection attempts |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Register once at install | Simple | Stale after network changes |
| Manual endpoint updates | Operator control | Not practical |
| Polling-only discovery | Simple | Slower convergence |
| Automatic registry updates | Accurate and resilient | Requires network event handling |

**Implications:**  
- Transport changes must trigger endpoint update logic.  
- Logs should capture registration and update status.  
- Lighthouse state must reject malformed or unauthorized updates.  
- Peer connection reliability improves across dynamic networks.

**Related Decisions:** D070, D072, D078  

---

### D072: Redundant Lighthouse Support

**Date:** Sprint 3  
**Status:** Accepted  
**Category:** Architecture – Mesh Networking  

**Context:**  
A single lighthouse can become a discovery bottleneck or availability risk. Circle connectivity should continue even if one lighthouse is unavailable.

**Decision:**  
Support multiple redundant lighthouses per Circle.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Availability | Peer discovery survives lighthouse failure |
| Resilience | Multiple lighthouses reduce single point of failure |
| Geographic flexibility | Different deployments can place lighthouses near peers |
| Operational safety | Maintenance can occur without full discovery outage |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Single lighthouse | Simple | Single point of failure |
| No lighthouse | Fully peer-based | Weak NAT traversal |
| Cloud-only discovery | Reliable if cloud available | Not self-hosted-first |
| Redundant lighthouses | Robust and aligned with mesh | Requires configuration management |

**Implications:**  
- Config must support multiple lighthouse entries.  
- Health checks should identify unreachable lighthouses.  
- Peer startup should try alternatives if primary fails.  
- Circle deployment docs must define lighthouse selection criteria.

**Related Decisions:** D070, D071, D075  

---

### D073: Cellular CoT Extension

**Date:** Sprint 3  
**Status:** Accepted  
**Category:** Architecture – Multi-Transport CoT  

**Context:**  
Guardian devices may operate in mobile or remote environments where Ethernet and Wi-Fi are unavailable. Cellular LTE/5G support is required for resilient field connectivity.

**Decision:**  
Extend Circle of Trust transport support to cellular LTE/5G interfaces.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Mobility | Supports moving or remote Guardian devices |
| Resilience | Provides fallback when LAN/Wi-Fi is unavailable |
| Deployment reach | Enables wider field and tactical usage |
| Mesh continuity | CoT trust can remain active across cellular paths |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| LAN/Wi-Fi only | Simpler | Not enough for remote deployment |
| Manual cellular VPN | Familiar | Adds external dependency and config overhead |
| Cellular as separate trust mode | Isolated | Duplicates CoT logic |
| Cellular CoT extension | Unified trust model | Requires transport detection and cost awareness |

**Implications:**  
- Cellular transport may need different timeout and retry behavior.  
- Bandwidth and latency should be monitored.  
- Lighthouse and relay support become more important.  
- Logs must show cellular transport selection.

**Related Decisions:** D064, D066, D071, D075, D078  

---

### D074: Bluetooth CoT Extension

**Date:** Sprint 3  
**Status:** Accepted  
**Category:** Architecture – Multi-Transport CoT  

**Context:**  
Certain local or constrained deployments may require short-range peer connectivity without relying on LAN or Wi-Fi infrastructure.

**Decision:**  
Extend Circle of Trust transport support to Bluetooth interfaces where applicable.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Local fallback | Supports short-range trusted communication |
| Infrastructure independence | Useful when LAN/Wi-Fi is unavailable |
| Device onboarding | Can support nearby-device workflows |
| Transport diversity | Expands CoT beyond IP-first assumptions |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Ignore Bluetooth | Simpler | Reduces local fallback options |
| Bluetooth-only trust flow | Specific optimization | Duplicates trust logic |
| Manual pairing only | Familiar | Weak automation |
| Bluetooth CoT extension | Adds local resilience | Requires careful pairing and interface handling |

**Implications:**  
- Bluetooth should use same identity and trust validation model.  
- Range and bandwidth limitations must be considered.  
- Logs should clearly identify Bluetooth transport use.  
- Security must avoid trusting Bluetooth pairing alone.

**Related Decisions:** D064, D066, D078  

---

### D075: Multi-Hop Relay Routing

**Date:** Sprint 4  
**Status:** Accepted  
**Category:** Architecture – Mesh Networking  

**Context:**  
Some Guardians cannot establish direct UDP connections because of symmetric NAT, restrictive firewalls, cellular carrier NAT, or satellite constraints. Mesh connectivity must still function when direct paths fail.

**Decision:**  
Enable Nebula multi-hop relay routing through trusted intermediate peers.

**Rationale:**

| Criterion | Explanation |
|----------|-------------|
| Connectivity | Maintains peer communication when direct UDP fails |
| Resilience | Supports restrictive networks and remote deployments |
| Privacy | Relay forwards encrypted packets without decrypting content |
| Mesh continuity | Keeps Circle communication alive under network constraints |

**Alternatives Considered:**

| Alternative | Pros | Cons |
|------------|------|------|
| Direct-only connections | Lowest latency | Fails behind restrictive NAT |
| Central relay server only | Predictable | Adds central dependency |
| Manual SSH tunnels | Useful for debugging | Not production-grade |
| Multi-hop relay | Mesh-native and resilient | Adds latency and resource usage |

**Implications:**  
- Relay-capable peers must be configured and monitored.  
- Relay path selection must avoid loops and excessive hops.  
- Relay metadata and bandwidth use should be logged.  
- Relay traffic remains encrypted end-to-end.

**Related Decisions:** D054, D070, D072, D076, D077  

---
