# SG-X Guardian - Decision Log

**Project**: SG-X Guardian Client  
**Phase**: Phase 1 - Circle of Trust & Policy Automation MVP  
**Document Date**: November 2025  

---

## Overview

This decision log tracks all significant **architectural, tactical, and procedural decisions** made during Sprint 1 and Sprint 2 of the SG-X Guardian Client development lifecycle.  
It ensures traceability, justification, and long-term maintainability of core design choices.

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

---

# Decisions by Category

| Category | Count | Decisions |
|---------|--------|----------|
| **Architecture** | 27 | D001, D002, D003, D004, D005, D008, D009, D012, D014, D016, D017, D018, D019, D020, D027, D028, D029, D030, D031, D034, D037, D038, D039, D040, D041, D042, D043, D044, D046 |
| **Implementation** | 5 | D006, D007, D021, D024, D032 |
| **DevOps** | 2 | D010, D011 |
| **Quality** | 5 | D013, D015, D025, D026, D033 |
| **Process** | 2 | D035, D047 |
| **Scope** | 1 | D016 |

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

---

# Detailed Decisions

---

### D001: Programming Language – Rust

**Date:** Sprint 1  
**Status:** Accepted  
**Category:** Architecture – Core Technology  

**Context:**  
SG-X Guardian requires a highly secure, memory-safe, and concurrent runtime for cryptographic operations, distributed networking, and real-time policy enforcement. The language must prevent buffer overflows and race conditions by design.

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
| C++ | High performance | Manual memory → dangerous for security |
| Python | Easy scripting | Too slow & unsafe for edge workloads |

**Implications:**  
- Slightly higher learning curve  
- Much stronger long-term stability  
- Fewer memory-related vulnerabilities  

**Related Decisions:** D002, D003, D011  

---

### D002: Communication Protocol – gRPC + Protobuf

**Status:** Accepted  
**Category:** Architecture – Communication  

**Context:**  
Nodes need a secure, typed, efficient communication layer for attestation, policy sync, and health checking. Protocol must support mTLS and real-time streaming.

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
| MQTT | Lightweight | Requires broker → not P2P |

**Implications:**  
- All RPC interfaces defined via `.proto`  
- Requires certificate lifecycle management  

**Related Decisions:** D001, D004, D005  

---

### D003: Cryptographic Algorithm – mTLS + Ed25519/X25519

**Status:** Accepted  
**Category:** Architecture – Security  

**Context:**  
Guardian nodes exchange sensitive attestation and policy data. Requires modern, secure, and light cryptography.

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
Policy must be human-readable, easy to sign, and translate into nftables rules.

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
- YAML → canonical form required for policy signing  
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
Simple, human-readable, and no DB required.

**Alternatives Considered:**  
Database → too heavy for Phase 1.

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

**Alternatives:** syslog → unstructured.

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
- `keygen` → generate P256 keypairs  
- `sign` → sign YAML UEP policies  

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
Security-critical Rust code must be continuously scanned for vulnerabilities, insecure patterns, dependency issues, and logic flaws. Manual reviews alone are insufficient.

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
REST JSON → too slow, no typing.  
Custom binary → insecure, heavy engineering.

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
Large distributed system requires strict coding standards to avoid drift, bugs, and unsafe code patterns.

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
No enforcement → inconsistent, unsafe code.

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
Defer PQC algorithms, AI inference, and behavioral ML models.

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
Ephemeral keys → breaks Circle-of-Trust.

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
Static IP lists → brittle.  
Consul → too heavy.

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

**Alternatives:** TPM attestation now → too complex for Phase 1.

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

**Alternatives:** Manual trigger → slow.

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
Threads → too heavy; no structured async.

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
Direct gRPC → adds complexity for Phase 1.

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
Direct socket → risk of blocking daemon.

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
Plain text logs → unreadable for tools.

**Implications:**  
- Must define stable JSON schema  

---

### D025: Unit & Integration Testing Framework

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Quality – Testing  

**Context:**  
Guardian must operate reliably across multiple async subsystems. Tests must cover CLI, discovery, attestation, and basic policy loading.

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
Manual testing → unreliable, slow.

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
Create **3-node LAN simulation** (A, B, C) with discovery, attestation, and timestamp tracking.

**Rationale:**

| Benefit | Explanation |
|---------|-------------|
| Realistic test | Simulates real deployment environment |
| Validates flow | Discovery → Attestation → Trust storage |
| Stability check | Peer flapping detection |

**Alternatives:**  
Single-node mock → cannot validate Circle-of-Trust.

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
HTTP-based endpoint → slower, heavier.

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
In-memory state → lost on restart.

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
Manual re-attest → unreliable.

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
Wait for next timer → delayed trust restoration.

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
Static timestamps → misleading trust state.

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
Immediate failure → too fragile.

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
No validation → risk of stale results.

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
Demonstrate nodes A, B, C boot → discover each other → mutually attest → form stable mesh.

**Rationale:**

| Benefit | Explanation |
|---------|------------|
| Proof of capability | Validates end-to-end trust flow |
| Realistic | Matches production topology |

**Alternatives:**  
Manual scripts → less convincing, less realistic.

**Implications:**  
- Demo scripts must reflect real system behavior  

---

### D035: Multi-Node Automation Script

**Date:** Sprint 2  
**Status:** Accepted  
**Category:** Process – Automation  

**Context:**  
Manually starting 3 nodes is error-prone.

**Decision:**  
Enhance `run_three_nodes.sh` to auto-start, wait, verify, summarize logs.

**Rationale:**

| Benefit | Detail |
|---------|--------|
| Reproducibility | Same test every time |
| Speed | Instant multi-node setup |
| Validation | Script checks trust mesh formation |

**Alternatives:**  
Manual start → slow & inconsistent.

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
Custom merger → requires more code.

**Implications:**  
- Enables centralized trust visualization  
- Requires consistent JSON schemas  

---

### D037: TLS Module – mTLS Foundation

**Date:** Sprint 3  
**Status:** Accepted  
**Category:** Architecture – Security  

**Context:**  
System required a transport-security layer for encrypted gRPC communication.  
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
- Convert DER → PEM at runtime  
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
- DER → PEM conversion for Identity  
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
Signed policies must be portable, inspectable, and self-contained.

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
| Embedded pubkey | Self-verifying artifact |
| Versioning | Forward compatibility |

**Alternatives Considered:**  
Detached signatures, ASN.1 blobs, YAML-based signing.

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

# Decision Template

```markdown
### D###: Decision Title

**Date**: Month Year  
**Status**: Proposed | Accepted | Deprecated | Superseded  
**Category**: Architecture | Security | Implementation | etc.

**Context**:  
Description of the problem.

**Decision**:  
The chosen solution.

**Rationale**:  
Why this option was selected.

**Alternatives Considered**:  
- Alternative A  
- Alternative B  

**Implications**:  
Consequences of the decision.

**Related Decisions**:  
D###, D###
```

---
