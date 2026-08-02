# G-X Guardian - Circle of Trust & Policy Automation

**Project**: SG-X Guardian Client (On-Premise Core)

**Phase**: Phase 1 - Circle of Trust & Policy Automation MVP

**Duration**: 8 Weeks (4 x 2-week Sprints)

**Document Date**: October 8, 2025

## Executive Summary

The SG-X Guardian is a cryptographically secure, self-hosted security system that enables a cohort of edge devices to autonomously form a "Circle of Trust," synchronize digitally signed security policies, and enforce them deterministically at the network layer. This Phase 1 MVP establishes the foundational security architecture with a **Self-Hosted First** design and provisions for future **Cloud-Optional** integration.

## Value Proposition

| Area | Value Delivered |
|------|----------------|
| **Trust Fabric** | Autonomous, Zero-Trust Fabric: Devices automatically discover peers, perform mutual software-based attestation, and establish secure mTLS channels |
| **Policy Control** | Deterministic Policy Enforcement: A signed Universal Edge Processing (UEP) policy is atomically synchronized and enforced across the cohort using nftables for immediate L3/L4 security control |
| **Operational Readiness** | Production-Readiness & Observability: System includes essential operational components including tamper-evident audit log, Prometheus-style metrics, and CLI status dashboard |
| **Future Path** | Cloud-Optional Pathway: Implementation of a secure, outbound-only cloud uplink mock to validate the integration path for future cloud-based management |

## Technical Architecture

### Core Components

#### 1. sgx-guardian Daemon (Core Service)

Built in **Rust** and runs on every edge node. Contains the following logical services:

- **p2p_discovery**: Uses mDNS for zero-configuration peer discovery
- **key_manager**: Manages the node's persistent ECDSA P-256 identity key pair
- **attestation_service**: Facilitates mutual software-based attestation
- **policy_manager**: Verifies policy digital signatures and manages atomic installation/rollback
- **enforcement_engine**: Translates UEP policy rules into concrete nftables commands
- **telemetry_service**: Collects and exposes Prometheus-style system metrics
- **audit_logger**: Writes a structured, tamper-evident log of all critical security events

#### 2. sgx-pa-cli Tool (Policy Authority CLI)

The on-premise command-line tool used by administrators for:

- Key pair generation
- Policy signing
- Viewing local node status

### Technology Stack

| Component | Technology | Justification |
|-----------|-----------|---------------|
| **Core Language** | Rust | Memory safety, fearless concurrency, and high performance are non-negotiable for security |
| **P2P Communication** | gRPC over mTLS | High-performance, strongly-typed RPC framework. mTLS ensures mutual authentication and encryption with forward secrecy |
| **Cryptography** | ECDSA P-256 | Standardized, efficient elliptic curve algorithm for FIPS-compliant device identity and policy signing |
| **Enforcement** | nftables | Modern, kernel-level successor to iptables for deterministic, high-performance L3/L4 policy enforcement |
| **Packaging/Init** | .deb/.rpm & systemd | Standard for enterprise Linux deployments, providing robust service lifecycle management |

### P2P Trust Establishment Protocol

1. **Discovery**: Nodes use mDNS to broadcast a service type (`_sgx-guardian._tcp`) and a random nonce
2. **Authentication**: Peers initiate a gRPC connection with a mutual TLS (mTLS) handshake, presenting a certificate signed by their persistent identity key
3. **Attestation**: Nodes exchange an AttestationEvidence (a cryptographic signature over combined nonces and the active policy digest), proving liveness and binding identity to operational state
4. **Virtual Identity**: The session's unique ID (VirtualID) is derived from a hash incorporating the device's public key, the policy digest, and the nonces, forcing re-attestation upon any state change
5. **Policy Sync**: Policies are distributed via the secure gRPC channel. Receiving nodes verify the Policy Authority's signature before atomically installing the new policy and updating their policy_digest

## Implementation Plan

### Sprint 1 (Week 1-2): Foundation & Bootstrap

**Objective**: Establish project backbone and finalize core specifications

**Key Tasks**:

- Setup CI/CD pipeline and 3-node test LAN
- Define all Protobuf API Schemas
- Design the minimal UEP Policy Schema v1 (L3/L4 rules)
- Build sgx-pa-cli skeleton
- Establish decision log for architectural decisions
- Implement security scanning tools (clippy, fmt, audit, deny, SAST)

**Deliverable**: API Spec v1.0, UEP Schema v1.0, and configured dev environment

### Sprint 2 (Week 3-4): Identity & Discovery

**Objective**: Enable autonomous peer discovery and verifiable identity

**Key Tasks**:

- Implement mDNS p2p_discovery
- Implement persistent key_manager (ECDSA P-256)
- Implement software attestation_service

**Milestone Demo 1**: 3 nodes boot, discover each other, and successfully complete a mutual attestation handshake

### Sprint 3 (Week 5-6): Secure Channels & Policy Sync

**Objective**: Establish encrypted communication and secure policy distribution

**Key Tasks**:

- Implement mTLS over gRPC for secure channels
- Complete sgx-pa-cli policy signing capability
- Implement policy_manager for signature verification and atomic loading

**Milestone Demo 2**: An admin signs a policy; it is securely distributed and verified by all peers in the cohort

### Sprint 4 (Week 7-8): Enforcement, Observability & Handoff

**Objective**: Activate enforcement, implement operational visibility, and finalize artifacts

**Key Tasks**:

- Implement enforcement_engine (UEP v1 to nftables translator)
- Implement telemetry_service (metrics) and audit_logger (tamper-evident log)
- Implement Cloud Uplink Mock (secure outbound-only channel)
- Create .deb/.rpm packages and final documentation
- Deployment automation with verification tests and rollback procedures

**Final Demo**: Full E2E script proving trust formation, policy sync, and active L3/L4 enforcement, with status visibility via the CLI

## Team Structure (3 FTE)

| Role | Key Responsibilities |
|------|---------------------|
| **Rust Backend Engineer** | P2P protocol state machine, gRPC/mTLS, cryptographic routines, core daemon architecture, and identity management |
| **Linux Systems Engineer** | nftables integration, policy engine logic, OS packaging (.deb/.rpm), systemd hardening, and telemetry/audit pipeline |
| **Project Lead / DevOps Engineer** | Project management, sprint coordination, CI/CD, comprehensive integration testing, documentation synthesis, and client demonstration |

## Phase 1 Deliverables

### Source Code

- Complete, modular, and documented Rust codebase for sgx-guardian and sgx-pa-cli

### Design Artifacts

- API_Specification_v1.0.pdf (Protobuf schemas & sequence diagrams)
- UEP_Policy_Schema_v1.0.pdf (YAML/JSON structure)

### Working Software & Artifacts

- sgx-guardian daemon binary
- sgx-pa-cli administration tool
- .deb and .rpm installation packages with systemd configuration

### Phase 1 Project Documentation

- Administrator_Guide_v0.5.pdf (Installation, configuration, key management, and operational procedures)
- Test_Report.pdf (Summary of all unit and integration test results)
- CI/CD_Pipeline_Documentation.md (Pipeline architecture, quality gates, workflow procedures, troubleshooting guide)
- Decision log tracking all architectural and technical decisions

### Demonstration

- A repeatable, scripted demo proving the core value proposition on a 3-node cohort

## Scope Exclusions (Deferred to Phase 2+)

To ensure timely delivery of a robust foundation, the following features are deferred:

| Feature | Justification |
|---------|--------------|
| **Virtual Shift (AI/ML)** | Requires significant R&D; the Circle of Trust plane must be stable first |
| **Protocol Connectors** | L7 protocol parsing (Modbus, OPC-UA) is a substantial, separate engineering effort |
| **Hardware TPM Attestation** | Software attestation validates the protocol flow. TPM integration adds hardware-specific complexity |
| **Advanced Enforcement** | nftables is sufficient for the MVP. eBPF/DPDK is a performance optimization for later |
| **CRL Gossip & Advanced Audit** | A full Certificate Revocation List (CRL) gossip protocol is a complex distributed systems problem |
| **Bi-directional Cloud Control** | Phase 1 is Self-Hosted First. Only a secure, outbound-only channel is implemented for future readiness |

## Development Workflow

### Repository & Branching

- **Repository**: Cervais GitHub Organization
- **Branching Strategy**: Main branch protected, requires PR approval
- **Commit Signing**: Required (GPG)
- **Status Checks**: All CI/CD checks must pass before merge

### Project Management

- **Platform**: GitHub Projects hosted in Cervais organization
- **Work Tracking**: All work tracked as GitHub Issues
- **Code-to-Ticket Traceability**: All commits must reference an issue number
- **Sprint Ceremonies**:
  - Daily stand-up
  - Sprint review
  - Demo (weekly or end of sprint)

### CI/CD Pipeline

**Build Stages**:

- Compilation
- Dependency caching
- Multi-arch builds

**Test Stages**:

- Unit tests (with coverage thresholds - 80% target)
- Integration tests
- Security tests

**Quality Gates**:

- cargo clippy (linting)
- cargo fmt (formatting checks)
- cargo audit (dependency vulnerabilities)
- cargo deny (license/security policy enforcement)
- SAST tools (Semgrep, CodeQL)

**Deployment Stages**:

- Artifact publishing
- Package signing
- Automated deployment to test environment
- Deployment verification tests

## Getting Started

### Prerequisites

- Rust toolchain (latest stable)
- Linux environment with nftables support
- systemd for service management

### Build Instructions

```bash
# Clone repository
git clone <repository-url>
cd new-guardian

# Build the project
cargo build --release

# Run tests
cargo test

# Run security checks
cargo clippy
cargo audit
```

### Installation

```bash
# Install from .deb package (Debian/Ubuntu)
sudo dpkg -i sgx-guardian_*.deb

# Install from .rpm package (RHEL/Fedora)
sudo rpm -i sgx-guardian-*.rpm

# Start the service
sudo systemctl start sgx-guardian
sudo systemctl enable sgx-guardian
```

## Project Documentation

- [Deliverables Tracking](deliverables/README.md) - Detailed deliverable tracking table
- [API Specification](docs/) - API schemas and sequence diagrams (Sprint 1 deliverable)
- [UEP Policy Schema](docs/) - Policy format specification (Sprint 1 deliverable)
- [Administrator Guide](docs/) - Installation and operational procedures (Sprint 4 deliverable)
- [CI/CD Pipeline Documentation](docs/) - Pipeline architecture and procedures (Sprint 1 deliverable)

## Security

This is security-critical software. All contributions must:

- Pass security scanning (clippy, audit, deny, SAST)
- Include unit tests with appropriate coverage
- Be reviewed and approved before merging
- Follow secure coding practices for Rust

## License

[License information to be added]

## Contact

For questions or issues, please contact:

- **Project Lead**: [Contact information]
- **Client Contact**: Pouya Barrach-Yousefi <pouya@cervais.com>
