# Phase 1: Circle of Trust & Policy Automation MVP

**Document Date:** October 8, 2025
**Project Name:** SG-X Guardian Client (On-Premise Core)
**Phase Duration:** 8 Weeks
**Team Size:** 3 FTE
**Status:** CONFIDENTIAL

**Related record:** [Phase 1 deliverable tracking](deliverables/README.md)

## Executive Summary

The objective of Phase 1 is to deliver a **Minimal Viable Product (MVP)** that establishes the foundational security architecture for the SG-X Guardian Client. This 8-week effort will build a cryptographically secure, self-hosted system where a cohort of devices can autonomously form a "Circle of Trust," synchronize a digitally signed security policy, and enforce it deterministically at the network layer.

The architecture is explicitly **Self-Hosted First**, with clear provisions for future **Cloud-Optional** integration.

## Value Delivered in Phase 1

| Area | Value Proposition |
| ---- | ----------------- |
| **Trust Fabric** | **Autonomous, Zero-Trust Fabric:** Devices automatically discover peers, perform mutual software-based attestation, and establish secure mTLS channels. |
| **Policy Control** | **Deterministic Policy Enforcement:** A signed Universal Edge Processing (UEP) policy is atomically synchronized and enforced across the cohort using nftables for immediate L3/L4 security control. |
| **Operational Readiness** | **Production-Readiness & Observability:** System includes essential operational components: a tamper-evident audit log, Prometheus-style metrics, and a CLI status dashboard. |
| **Future Path** | **Cloud-Optional Pathway:** Implementation of a secure, outbound-only cloud uplink mock to validate the integration path for future cloud-based management. |

---

## Technical Architecture & Core Stack

The system comprises the core daemon, an administrative CLI tool, and internal microservices.

### System Components

#### 1. `sgx-guardian` Daemon (Core Service)

Built in **Rust** and runs on every edge node. It contains the following logical services:

- **`p2p_discovery`** - Uses mDNS for zero-configuration peer discovery
- **`key_manager`** - Manages the node's persistent ECDSA P-256 identity key pair
- **`attestation_service`** - Facilitates mutual software-based attestation
- **`policy_manager`** - Verifies policy digital signatures and manages atomic installation/rollback
- **`enforcement_engine`** - Translates UEP policy rules into concrete nftables commands
- **`telemetry_service`** - Collects and exposes Prometheus-style system metrics
- **`audit_logger`** - Writes a structured, tamper-evident log of all critical security events

#### 2. `sgx-pa-cli` Tool (Policy Authority CLI)

The on-premise command-line tool used by administrators for:

- Key pair generation
- Policy signing
- Viewing local node status

### Core Technical Stack & Justification

| Component | Technology Choice | Justification |
| --------- | ----------------- | ------------- |
| **Core Language** | Rust | Memory safety, fearless concurrency, and high performance are non-negotiable for security. |
| **P2P Communication** | gRPC over mTLS | High-performance, strongly-typed RPC framework. mTLS ensures mutual authentication and encryption with forward secrecy. |
| **Cryptography** | ECDSA P-256 | Standardized, efficient elliptic curve algorithm for FIPS-compliant device identity and policy signing. |
| **Enforcement** | nftables | Modern, kernel-level successor to iptables for deterministic, high-performance L3/L4 policy enforcement. |
| **Packaging/Init** | .deb/.rpm & systemd | Standard for enterprise Linux deployments, providing robust service lifecycle management. |

### Detailed P2P Trust Establishment Protocol

1. **Discovery:** Nodes use mDNS to broadcast a service type (`_sgx-guardian._tcp`) and a random nonce.

2. **Authentication:** Peers initiate a gRPC connection with a mutual TLS (mTLS) handshake, presenting a certificate signed by their persistent identity key.

3. **Attestation:** Nodes exchange an `AttestationEvidence` (a cryptographic signature over combined nonces and the active policy digest), proving liveness and binding identity to operational state.

4. **Virtual Identity:** The session's unique ID (`VirtualID`) is derived from a hash incorporating the device's public key, the policy digest, and the nonces, forcing re-attestation upon any state change.

5. **Policy Sync:** Policies are distributed via the secure gRPC channel. Receiving nodes verify the Policy Authority's signature before atomically installing the new policy and updating their `policy_digest`.

---

## 8-Week Implementation Plan: Sprint Breakdown

The project is structured into four 2-week sprints, each with defined objectives and tangible, demonstrable deliverables.

### Sprint 1 (Week 1-2): Foundation & Bootstrap

**Objective:** Establish project backbone and finalize core specifications.

**Key Tasks:**

- Setup CI/CD pipeline and 3-node test LAN
- Define all Protobuf API Schemas
- Design the minimal UEP Policy Schema v1 (L3/L4 rules)
- Build `sgx-pa-cli` skeleton

**Milestone Demo/Deliverable:**

- API Spec v1.0
- UEP Schema v1.0
- Configured dev environment

### Sprint 2 (Week 3-4): Identity & Discovery

**Objective:** Enable autonomous peer discovery and verifiable identity.

**Key Tasks:**

- Implement mDNS `p2p_discovery`
- Implement persistent `key_manager` (ECDSA P-256)
- Implement software `attestation_service`

**Milestone Demo 1:**

3 nodes boot, discover each other, and successfully complete a mutual attestation handshake.

### Sprint 3 (Week 5-6): Secure Channels & Policy Sync

**Objective:** Establish encrypted communication and secure policy distribution.

**Key Tasks:**

- Implement mTLS over gRPC for secure channels
- Complete `sgx-pa-cli` policy signing capability
- Implement `policy_manager` for signature verification and atomic loading

**Milestone Demo 2:**

An admin signs a policy; it is securely distributed and verified by all peers in the cohort.

### Sprint 4 (Week 7-8): Enforcement, Observability & Handoff

**Objective:** Activate enforcement, implement operational visibility, and finalize artifacts.

**Key Tasks:**

- Implement `enforcement_engine` (UEP v1 to nftables translator)
- Implement `telemetry_service` (metrics) and `audit_logger` (tamper-evident log)
- Implement Cloud Uplink Mock (secure outbound-only channel)
- Create .deb/.rpm packages and final documentation

**Final Demo:**

Full E2E script proving trust formation, policy sync, and active L3/L4 enforcement, with status visibility via the CLI.

---

## Team Structure & Responsibilities (3 FTE)

| Role | Key Responsibilities |
| ---- | -------------------- |
| **Rust Backend Engineer** | P2P protocol state machine, gRPC/mTLS, cryptographic routines, core daemon architecture, and identity management. |
| **Linux Systems Engineer** | nftables integration, policy engine logic, OS packaging (.deb/.rpm), systemd hardening, and telemetry/audit pipeline. |
| **Project Lead / DevOps Engineer** | Project management, sprint coordination, CI/CD, comprehensive integration testing, documentation synthesis, and client demonstration. |

---

## Phase 1 Deliverables (Tangible Outcomes)

### 1. Source Code

A complete, modular, and documented Rust codebase for `sgx-guardian` and `sgx-pa-cli`.

### 2. Design Artifacts

- `API_Specification_v1.0.pdf` (Protobuf schemas & sequence diagrams)
- `UEP_Policy_Schema_v1.0.pdf` (YAML/JSON structure)

### 3. Working Software & Artifacts

- `sgx-guardian` daemon binary
- `sgx-pa-cli` administration tool
- `.deb` and `.rpm` installation packages with systemd configuration

### 4. Documentation

- `Administrator_Guide_v0.5.pdf` (Installation, configuration, key management, and operational procedures)
- `Test_Report.pdf` (Summary of all unit and integration test results)
- `CI/CD_Pipeline_Documentation.md` (Pipeline architecture, quality gates, workflow procedures, troubleshooting guide)

### 5. Demonstration

A repeatable, scripted demo proving the core value proposition on a 3-node cohort.

---

## Scope Exclusions: Deferral for Phase 2+

To ensure timely delivery of a robust foundation, the following complex features are explicitly deferred to subsequent phases:

| Feature | Status in Phase 1 | Justification for Deferral |
| ------- | ----------------- | -------------------------- |
| **Virtual Shift (AI/ML)** | ❌ Deferred | Requires significant R&D; the Circle of Trust plane must be stable first. |
| **Protocol Connectors** | ❌ Deferred | L7 protocol parsing (Modbus, OPC-UA) is a substantial, separate engineering effort. |
| **Hardware TPM Attestation** | ❌ Deferred | Software attestation validates the protocol flow. TPM integration adds hardware-specific complexity. |
| **Advanced Enforcement** | ❌ Deferred | nftables is sufficient for the MVP. eBPF/DPDK is a performance optimization for later. |
| **CRL Gossip & Advanced Audit** | ❌ Deferred | A full Certificate Revocation List (CRL) gossip protocol is a complex distributed systems problem. |
| **Bi-directional Cloud Control** | ❌ Deferred | Phase 1 is Self-Hosted First. Only a secure, outbound-only channel is implemented for future readiness. |

---

## Development Requirements & Standards

### Project Management

1. **Repository:** Use Cervais organization GitHub
2. **Branch Protection:**
   - Main branch: Protected, requires PR approval
   - Commit signing: Required (GPG)
   - Status checks: All CI/CD checks must pass
3. **Project Tracking:** GitHub Projects hosted in Cervais
   - All work tracked as GitHub Issues
   - Code-to-Ticket Traceability - All commits must reference an issue number
4. **Sprint Ceremonies:**
   - Daily stand-up
   - Sprint review
   - Demo (weekly or end of sprint)
5. **Decision Log:** Track all architectural, tactical, and procedural decisions in a markdown document
   - Strategic decisions with long-term impact on system structure
   - Programming language and framework choices
   - Communication protocols and patterns
   - Cryptographic algorithm selections
   - Data storage and persistence strategies
   - Security model and trust boundaries
   - System decomposition and service boundaries
   - Integration patterns and APIs
   - Deferral of features to future phases

### CI/CD Pipeline Architecture & Stages

#### Build Stages

- Compilation
- Dependency caching
- Multi-arch builds

#### Test Stages

- Unit tests (with coverage thresholds)
- Integration tests
- Security tests

#### Quality Gates

- What causes a build to fail?

#### Code Quality & Security Scanning

For Rust security-critical code, the following tools are required:

- `cargo clippy` (linting)
- `cargo fmt` (formatting checks)
- `cargo audit` (dependency vulnerabilities)
- `cargo deny` (license/security policy enforcement)
- SAST tools (e.g., Semgrep, CodeQL)

#### Deployment Stages

- Artifact publishing
- Package signing

### Artifact Management

- Where are `.deb`/`.rpm` packages stored?
- How are they versioned and signed?
- Container registry for any Docker images?
- Binary reproducibility requirements?

### Deployment Automation

- Automated deployment to test environment
- Deployment verification tests
- Rollback procedures

### Development Workflow

- **Git branching strategy:** Trunk-based or GitFlow
- **PR/review requirements:** Required for all changes
- **Commit signing requirements:** Required (GPG) - critical for security

---

## References

- [Cervais_SG-X_SOW_09112025 - Phase 1 Development.pdf](./Cervais_SG-X_SOW_09112025%20-%20Phase%201%20Development.pdf)
- [Pouya follow up to SOW.pdf](./Pouya%20follow%20up%20to%20SOW.pdf)
