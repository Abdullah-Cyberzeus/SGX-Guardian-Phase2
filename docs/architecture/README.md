# SG-X Guardian - System Architecture

**Project**: SG-X Guardian Client (On-Premise Core)

**Phase**: Phase 1 - Circle of Trust & Policy Automation MVP

**Document Version**: 1.0

**Document Date**: November 12, 2025

**Status**: Active Development

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [System Overview](#system-overview)
3. [Architecture Principles](#architecture-principles)
4. [High-Level Architecture](#high-level-architecture)
5. [Component Architecture](#component-architecture)
6. [Security Architecture](#security-architecture)
7. [Data Architecture](#data-architecture)
8. [Network Architecture](#network-architecture)
9. [Deployment Architecture](#deployment-architecture)
10. [Technology Stack](#technology-stack)
11. [Integration Architecture](#integration-architecture)
12. [Operational Architecture](#operational-architecture)
13. [Future Architecture Evolution](#future-architecture-evolution)
14. [Architecture Decision Records](#architecture-decision-records)

---

## Executive Summary

The SG-X Guardian system is a distributed, peer-to-peer security platform designed to create a cryptographically verified "Circle of Trust" among edge devices. This architecture document describes the technical design of Phase 1, which establishes the foundational security architecture with a **Self-Hosted First** approach.

### Key Architectural Characteristics

| Characteristic | Description |
| -------------- | ----------- |
| **Zero-Trust Security** | Continuous mutual attestation between peers; no implicit trust |
| **Decentralized** | No central authority required for peer discovery or trust establishment |
| **Deterministic Enforcement** | Atomic policy updates with guaranteed rollback capabilities |
| **Production-Ready** | Built-in observability, audit logging, and operational tooling |
| **Cloud-Optional** | Self-hosted by default; cloud integration path established for future |
| **Memory-Safe** | Rust implementation eliminates entire classes of vulnerabilities |

### Architecture Goals

1. **Security First**: Memory safety, cryptographic integrity, and zero-trust principles throughout
2. **Operational Simplicity**: Single-binary deployment with minimal configuration requirements
3. **Edge-Optimized**: Designed for resource-constrained environments
4. **Extensible Design**: Foundation for future L7 protocol inspection, TPM attestation, and cloud integration
5. **Enterprise Ready**: Standards-compliant packaging, systemd integration, and comprehensive monitoring

---

## System Overview

### Problem Statement

Modern edge computing environments require:

- Autonomous security policy enforcement without central coordination
- Cryptographic verification of peer identity and policy integrity
- Real-time policy synchronization across distributed devices
- Deterministic network security enforcement at kernel level
- Comprehensive audit trails for compliance and forensics

### Solution Architecture

The SG-X Guardian implements a distributed trust fabric where:

1. Devices autonomously discover peers on local networks via mDNS
2. Mutual attestation establishes cryptographic proof of identity and policy state
3. Secure channels (gRPC over mTLS) enable policy distribution
4. Kernel-level enforcement (nftables) provides deterministic L3/L4 filtering
5. Continuous re-attestation detects policy drift or compromise

### System Context Diagram

```sh
┌────────────────────────────────────────────────────────────────┐
│                    SG-X Guardian Cohort                        │
│                                                                │
│  ┌──────────┐         ┌──────────┐         ┌──────────┐        │
│  │  Node A  │◄───────►│  Node B  │◄───────►│  Node C  │        │
│  │ Guardian │  mTLS   │ Guardian │  mTLS   │ Guardian │        │
│  └──────────┘         └──────────┘         └──────────┘        │
│       ▲                     ▲                     ▲            │
│       │ mDNS Discovery      │                     │            │
│       └─────────────────────┴─────────────────────┘            │
│                                                                │
└────────────────────────────────────────────────────────────────┘
         │                          │                      │
         ▼                          ▼                      ▼
   ┌─────────┐              ┌─────────────┐         ┌─────────┐
   │ Policy  │              │  Monitoring │         │  Cloud  │
   │Authority│              │   System    │         │ Service │
   │ (Admin) │              │(Prometheus) │         │ (Mock)  │
   └─────────┘              └─────────────┘         └─────────┘
   sgx-pa-cli                    Scraper              Outbound
                                                      Telemetry
```

---

## Architecture Principles

The following principles guide all architectural decisions:

### 1. Security by Design

- **Memory Safety First**: Rust eliminates buffer overflows, use-after-free, and data races
- **Cryptographic Integrity**: All policies signed with ECDSA P-256; all communications encrypted
- **Zero Trust**: Continuous verification; never trust, always verify
- **Least Privilege**: Minimal capabilities required (CAP_NET_ADMIN only)

### 2. Operational Excellence

- **Fail-Safe Defaults**: Policy failures result in safe rollback, not enforcement gaps
- **Observable by Default**: Comprehensive metrics, structured logging, and audit trails
- **Deterministic Behavior**: No race conditions, atomic operations, predictable failure modes
- **Self-Healing**: Automatic peer re-discovery and re-attestation on state changes

### 3. Edge-First Design

- **Resource Efficiency**: Single-process architecture with minimal memory footprint
- **Offline Capable**: No cloud dependency for core security functions
- **Local Discovery**: mDNS-based peer discovery within subnet boundaries
- **Fast Convergence**: Sub-second policy propagation and enforcement

### 4. Enterprise Integration

- **Standard Packaging**: Native .deb/.rpm packages for package manager integration
- **systemd Native**: Leverages systemd security hardening and service management
- **Compliance Ready**: FIPS-compliant cryptography, tamper-evident audit logs
- **Monitoring Integration**: Prometheus-standard metrics for existing toolchains

### 5. Evolutionary Architecture

- **Protocol Versioning**: API schemas support backward-compatible evolution
- **Modular Design**: Clear service boundaries enable future microservice decomposition
- **Extension Points**: Plugin architecture for future L7 protocol connectors
- **Cloud Ready**: Architecture supports future bi-directional cloud management

---

## High-Level Architecture

### Logical Architecture

```sh
┌────────────────────────────────────────────────────────────────┐
│                    sgx-guardian Daemon                         │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                  Control Plane                           │  │
│  │                                                          │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │  │
│  │  │ P2P Discovery│  │  Attestation │  │    Policy    │    │  │
│  │  │   (mDNS)     │  │   Service    │  │   Manager    │    │  │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘    │  │
│  │         │                  │                  │          │  │
│  │         └──────────────────┼──────────────────┘          │  │
│  │                            │                             │  │
│  │                    ┌───────▼────────┐                    │  │
│  │                    │  Key Manager   │                    │  │
│  │                    │  (ECDSA P-256) │                    │  │
│  │                    └────────────────┘                    │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    Data Plane                            │  │
│  │                                                          │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │  │
│  │  │ Enforcement  │  │  Telemetry   │  │    Audit     │    │  │
│  │  │   Engine     │  │   Service    │  │    Logger    │    │  │
│  │  │  (nftables)  │  │ (Prometheus) │  │ (Hash Chain) │    │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘    │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### Service Architecture

The SG-X Guardian implements a **monolithic daemon architecture** with the following logical services:

| Service | Responsibility | Key Technology |
| ------- | -------------- | -------------- |
| **p2p_discovery** | Zero-configuration peer discovery using mDNS with nonce exchange | `mdns-sd` crate |
| **key_manager** | Persistent ECDSA P-256 key pair management and secure storage | `p256`, `ring` crates |
| **attestation_service** | Mutual software-based attestation with signature verification | ECDSA P-256 signing |
| **policy_manager** | Policy signature verification, atomic loading, rollback management | YAML parsing, signature verification |
| **enforcement_engine** | UEP policy translation to nftables rules with atomic application | `nftables` system API |
| **telemetry_service** | Prometheus-format metrics collection and HTTP endpoint | `prometheus` crate |
| **audit_logger** | Structured, tamper-evident security event logging with hash chain | `tracing`, JSON Lines |

**Rationale for Monolithic Architecture** (See [D008](../decision-log/README.md#d008-service-architecture---monolithic-daemon)):

- Operational simplicity: Single binary deployment and management
- Resource efficiency: No IPC overhead, shared memory space
- Atomic updates: Version-matched components guaranteed
- Edge optimization: Minimal footprint for resource-constrained devices

---

## Component Architecture

### Component Interaction Diagram

```sh
┌─────────────────────────────────────────────────────────────────────┐
│                      sgx-guardian Startup Flow                      │
└─────────────────────────────────────────────────────────────────────┘

1. Service Initialization
   ┌──────────────┐
   │   systemd    │ Starts daemon with hardened environment
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │ key_manager  │ Loads or generates ECDSA P-256 identity key
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │policy_manager│ Loads last known policy (if exists)
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │audit_logger  │ Opens tamper-evident log, verifies hash chain
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │telemetry_svc │ Starts Prometheus HTTP endpoint (localhost:9090)
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │p2p_discovery │ Broadcasts mDNS presence with nonce
   └──────────────┘

2. Peer Discovery & Trust Establishment
   ┌──────────────┐
   │ mDNS Announce│ Broadcast _sgx-guardian._tcp with nonce
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │  Peer Found  │ Discover peer via mDNS response
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │ mTLS Connect │ Establish gRPC channel with mutual TLS
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │ Attestation  │ Exchange signatures over nonces + policy digest
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │VirtualID Gen │ Hash(pubkey + policy_digest + nonces)
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │Trust Verified│ Peer added to Circle of Trust
   └──────────────┘

3. Policy Distribution & Enforcement
   ┌──────────────┐
   │Policy Received│ Via gRPC from trusted peer
   └──────┬────────┘
          │
          ▼
   ┌──────────────┐
   │Verify Sig    │ Check Policy Authority ECDSA signature
   └──────┬────────┘
          │
          ▼
   ┌──────────────┐
   │Validate Schema│ Ensure UEP v1.0 compliance
   └──────┬────────┘
          │
          ▼
   ┌──────────────┐
   │Store Policy  │ Atomic write to disk (temp + rename)
   └──────┬────────┘
          │
          ▼
   ┌──────────────┐
   │Translate UEP │ Generate nftables ruleset
   └──────┬────────┘
          │
          ▼
   ┌──────────────┐
   │Test Ruleset  │ Connectivity check (30s timeout)
   └──────┬────────┘
          │
          ├─ Success ──►┌──────────────┐
          │              │Apply Atomic  │ nft -f (atomic swap)
          │              └──────┬───────┘
          │                     │
          │                     ▼
          │              ┌──────────────┐
          │              │Update VirtID │ Re-derive VirtualID
          │              └──────┬───────┘
          │                     │
          │                     ▼
          │              ┌──────────────┐
          │              │Broadcast New │ Announce to peers
          │              │  VirtualID   │
          │              └──────────────┘
          │
          └─ Failure ──►┌──────────────┐
                        │Rollback      │ Restore previous policy
                        └──────┬───────┘
                               │
                               ▼
                        ┌──────────────┐
                        │Log Failure   │ Audit log + metrics
                        └──────────────┘
```

### Key Manager Component

**Responsibilities**:

- Generate ECDSA P-256 key pairs on first boot
- Securely store private keys with filesystem ACLs (future: TPM)
- Provide signing interface for attestation service
- Support key rotation (future phase)

**Data Flow**:

```sh
┌─────────────┐
│  First Boot │
└──────┬──────┘
       │
       ▼
  ┌─────────────────┐
  │ Generate Keypair│  Using cryptographically secure RNG
  │  (ECDSA P-256)  │
  └──────┬──────────┘
         │
         ▼
  ┌─────────────────┐
  │ Store Private   │  /var/lib/sgx-guardian/identity.key
  │ Key (0600 perms)│  Owner: sgx-guardian user
  └──────┬──────────┘
         │
         ▼
  ┌─────────────────┐
  │ Store Public Key│  /var/lib/sgx-guardian/identity.pub
  │ (0644 perms)    │
  └──────┬──────────┘
         │
         ▼
  ┌─────────────────┐
  │ Load to Memory  │  Keep private key in secure memory
  └─────────────────┘
```

**Security Considerations**:

- Private key never leaves process memory (Phase 1) or TPM (Phase 2)
- Key file permissions enforced by systemd hardening
- Audit log entry on key generation or loading
- Future: TPM-sealed keys with PCR binding

### Attestation Service Component

**Responsibilities**:

- Generate random nonces for freshness
- Create attestation evidence (signature over nonces + policy digest)
- Verify peer attestation evidence
- Derive and validate VirtualID
- Trigger re-attestation on policy changes

**Attestation Protocol**:

```sh
Node A                                          Node B
  │                                               │
  │─────────── mDNS Discovery ──────────────────►│
  │◄──────── mDNS Response (nonce_b) ────────────│
  │                                               │
  │────── gRPC Connect (mTLS) ──────────────────►│
  │◄──────── TLS Handshake ──────────────────────│
  │                                               │
  │──── AttestationRequest ────────────────────►│
  │     {                                         │
  │       nonce_a: [random],                      │
  │       public_key_a: [ECDSA P-256],            │
  │       policy_digest_a: [SHA-256]              │
  │     }                                         │
  │                                               │
  │◄─── AttestationEvidence ────────────────────│
  │     {                                         │
  │       signature_b: Sign(nonce_a +             │
  │                        nonce_b +              │
  │                        policy_digest_b)       │
  │     }                                         │
  │                                               │
  │ [Verify signature_b with public_key_b]        │
  │ [Derive VirtualID_b = Hash(public_key_b +     │
  │                           policy_digest_b +   │
  │                           nonce_a + nonce_b)] │
  │                                               │
  │──── AttestationEvidence ────────────────────►│
  │     {                                         │
  │       signature_a: Sign(nonce_a +             │
  │                        nonce_b +              │
  │                        policy_digest_a)       │
  │     }                                         │
  │                                               │
  │                               [Verify signature_a with public_key_a]
  │                               [Derive VirtualID_a]
  │                                               │
  │◄──── TrustEstablished ──────────────────────│
  │                                               │
```

**VirtualID Derivation**:

```rust
VirtualID = SHA256(
    public_key ||
    policy_digest ||
    nonce_self ||
    nonce_peer
)
```

**Attestation Triggers**:

1. New peer discovered via mDNS
2. Policy update applied (forces new policy_digest)
3. Periodic re-attestation timer (configurable, default: 5 minutes)
4. Manual trigger via CLI (`sgx-pa-cli attest`)

### Policy Manager Component

**Responsibilities**:

- Receive policies via gRPC from peers
- Verify Policy Authority digital signature
- Validate UEP schema compliance
- Atomic policy installation with rollback
- Maintain policy version history

**Policy Lifecycle**:

```sh
┌──────────────────────────────────────────────────────────────┐
│                    Policy Update Flow                        │
└──────────────────────────────────────────────────────────────┘

1. Policy Distribution
   ┌─────────────┐
   │Administrator│ Uses sgx-pa-cli to sign policy
   └──────┬──────┘
          │
          ▼
   ┌─────────────┐
   │Sign Policy  │ ECDSA signature over canonical YAML
   └──────┬──────┘
          │
          ▼
   ┌─────────────┐
   │Distribute   │ Send to one node via gRPC
   └──────┬──────┘
          │
          ▼
   ┌─────────────┐
   │ Gossip      │ Node propagates to peers in Circle
   └─────────────┘

2. Policy Verification (policy_manager)
   ┌─────────────┐
   │Receive Msg  │ PolicyUpdate RPC message
   └──────┬──────┘
          │
          ▼
   ┌─────────────┐
   │Extract Sig  │ signature, public_key_id, policy_yaml
   └──────┬──────┘
          │
          ▼
   ┌─────────────┐
   │Verify Sig   │ ECDSA verify with trusted PA public key
   └──────┬──────┘
          │
          ├─ Invalid ──►┌──────────────┐
          │              │Reject & Log  │
          │              └──────────────┘
          │
          ├─ Valid ──►┌──────────────┐
          │            │Parse YAML    │
          │            └──────┬───────┘
          │                   │
          │                   ▼
          │            ┌──────────────┐
          │            │Validate UEP  │ Check schema v1.0
          │            └──────┬───────┘
          │                   │
          │                   ▼
          │            ┌──────────────┐
          │            │Compute Digest│ policy_digest = SHA256(policy)
          │            └──────┬───────┘
          │                   │
          │                   ▼
          │            ┌──────────────┐
          │            │Write to Disk │ Atomic: temp file + rename
          │            └──────┬───────┘
          │                   │
          │                   ▼
          │            ┌──────────────┐
          │            │Notify Engine │ Trigger enforcement_engine
          │            └──────────────┘
```

**Policy Storage Structure**:

```sh
/var/lib/sgx-guardian/policy/
├── current.yaml              # Active policy
├── current.yaml.sig          # Detached signature
├── previous.yaml             # Rollback target
├── previous.yaml.sig
└── archive/
    ├── policy_001.yaml       # Historical versions
    ├── policy_002.yaml
    └── ...
```

### Enforcement Engine Component

**Responsibilities**:

- Translate UEP policy to nftables rules
- Apply rules atomically to kernel
- Perform connectivity validation
- Execute rollback on failure
- Report enforcement status to telemetry

**UEP to nftables Translation**:

```yaml
# UEP Policy Example (YAML)
version: "1.0"
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

**Translated nftables Ruleset**:

```nft
table inet sgx_guardian {
    chain input {
        type filter hook input priority filter; policy drop;

        # Allow SSH from management network
        ip saddr 10.0.1.0/24 tcp dport 22 counter accept

        # Block all other inbound (implicit via policy drop)
    }
}
```

**Atomic Application Process**:

1. Generate complete nftables ruleset in memory
2. Write to temporary file: `/tmp/sgx-guardian-policy-XXXX.nft`
3. Execute: `nft -c -f /tmp/sgx-guardian-policy-XXXX.nft` (check syntax)
4. If valid: `nft -f /tmp/sgx-guardian-policy-XXXX.nft` (atomic load)
5. Wait 30 seconds for connectivity validation
6. If validation fails: `nft -f /var/lib/sgx-guardian/policy/previous.nft` (rollback)
7. If validation succeeds: Commit new policy as active
8. Cleanup temporary files

**Connectivity Validation**:

- Ensure localhost loopback functional
- Verify gRPC port accessible (default: 50051)
- Validate Prometheus metrics endpoint (default: 9090)
- Check management interface SSH (if applicable)

---

## Security Architecture

### Threat Model

The SG-X Guardian system defends against the following threats in Phase 1:

| Threat | Mitigation |
| ------ | ---------- |
| **Network MITM** | All P2P communication over mTLS with mutual authentication |
| **Policy Tampering** | Digital signatures (ECDSA P-256) on all policies; verification before application |
| **Unauthorized Policy Distribution** | Only Policy Authority's public key trusted; signature verification enforced |
| **Policy Rollback Attacks** | Sequence numbers and timestamps in policy metadata; monotonic version enforcement |
| **Peer Impersonation** | Cryptographic attestation with nonce exchange; device identity bound to key pair |
| **Policy Drift** | Continuous attestation; VirtualID changes force re-verification |
| **Replay Attacks** | Fresh nonces in every attestation exchange; session-bound VirtualID |
| **Memory Safety Vulnerabilities** | Rust memory safety guarantees; no unsafe code in critical paths |
| **Privilege Escalation** | systemd hardening (NoNewPrivileges, CapabilityBoundingSet, Seccomp) |
| **Log Tampering** | Hash chain in audit log; each entry includes hash of previous entry |

### Cryptographic Architecture

**Key Hierarchy**:

```sh
┌────────────────────────────────────────────────────────────┐
│               Policy Authority (PA)                        │
│                                                            │
│  ┌────────────────────────────────────────────────────┐    │
│  │ PA Identity Key Pair (ECDSA P-256)                 │    │
│  │ - Private Key: Offline storage (HSM recommended)   │    │
│  │ - Public Key: Distributed to all guardian nodes    │    │
│  └────────────────────────────────────────────────────┘    │
│                          │                                 │
│                          │ Signs                           │
│                          ▼                                 │
│  ┌────────────────────────────────────────────────────┐    │
│  │ UEP Policy Documents                               │    │
│  │ - Signed with PA private key                       │    │
│  │ - Verified by nodes with PA public key             │    │
│  └────────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────────┘
                          │
                          │ Distributed via
                          ▼
┌────────────────────────────────────────────────────────────┐
│                  Guardian Nodes                            │
│                                                            │
│  Each Node Has:                                            │
│  ┌────────────────────────────────────────────────────┐    │
│  │ Node Identity Key Pair (ECDSA P-256)               │    │
│  │ - Private Key: /var/lib/sgx-guardian/identity.key  │    │
│  │ - Public Key: /var/lib/sgx-guardian/identity.pub   │    │
│  │ - Permissions: 0600 (private), 0644 (public)       │    │
│  └────────────────────────────────────────────────────┘    │
│                          │                                 │
│                          │ Used for                        │
│                          ▼                                 │
│  ┌────────────────────────────────────────────────────┐    │
│  │ mTLS Certificates (Self-Signed)                    │    │
│  │ - Generated from node identity key                 │    │
│  │ - Used for gRPC channel encryption                 │    │
│  └────────────────────────────────────────────────────┘    │
│                          │                                 │
│                          │ And                             │
│                          ▼                                 │
│  ┌────────────────────────────────────────────────────┐    │
│  │ Attestation Evidence                               │    │
│  │ - Signature over: nonce_a + nonce_b + policy_hash  │    │
│  │ - Proves possession of private key                 │    │
│  │ - Binds identity to current policy state           │    │
│  └────────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────────┘
```

**Cryptographic Operations**:

| Operation | Algorithm | Key Size | Purpose |
| --------- | --------- | -------- | ------- |
| **Policy Signing** | ECDSA with P-256 curve | 256 bits | Policy Authority signs policies |
| **Policy Verification** | ECDSA with P-256 curve | 256 bits | Nodes verify policy signatures |
| **Attestation Signing** | ECDSA with P-256 curve | 256 bits | Nodes prove identity and state |
| **mTLS Channel** | TLS 1.3, P-256 ECDHE | 256 bits | Encrypted P2P communication |
| **Policy Digest** | SHA-256 | 256 bits | Policy content hashing |
| **VirtualID Derivation** | SHA-256 | 256 bits | Session identity binding |
| **Audit Log Chain** | SHA-256 | 256 bits | Tamper-evident log linking |
| **Nonce Generation** | CSPRNG (ChaCha20) | 256 bits | Replay prevention |

**Signature Format** (Policy):

```yaml
signature:
  algorithm: "ECDSA-P256-SHA256"
  public_key_id: "PA-2025-001"
  signature: "MEUCIQDx... (base64-encoded DER)"
```

**Certificate Management**:

- Phase 1: Self-signed certificates derived from node identity keys
- Phase 2: PKI integration with certificate rotation
- Phase 3: TPM-backed certificates with hardware root of trust

### Trust Establishment

**Circle of Trust Formation**:

```sh
Initial State: 3 isolated nodes
┌──────┐  ┌──────┐  ┌──────┐
│Node A│  │Node B│  │Node C│
└──────┘  └──────┘  └──────┘

Step 1: mDNS Discovery (30-60 seconds)
┌──────┐  ┌──────┐  ┌──────┐
│Node A│◄─┼──────┼─►│Node C│
└──┬───┘  └──┬───┘  └───┬──┘
   │         │          │
   └─────────┼──────────┘
          Node B

Step 2: Mutual Attestation (each pair)
┌──────┐  ┌──────┐  ┌──────┐
│Node A│━━│Node B│━━│Node C│
└──┬───┘  └──┬───┘  └───┬──┘
   ┗━━━━━━━━━┻━━━━━━━━━━┛
   Trusted connections (mTLS + attested)

Step 3: Circle of Trust Established
        ┏━━━━━━━━━━━━━━━┓
        ┃ Circle of     ┃
        ┃ Trust         ┃
        ┃ ┌──────┐      ┃
        ┃ │Node A│      ┃
        ┃ └──╋───┘      ┃
        ┃ ┌──╋──┐       ┃
        ┃ │Node B│      ┃
        ┃ └──╋───┘      ┃
        ┃ ┌──╋──┐       ┃
        ┃ │Node C│      ┃
        ┃ └─────┘       ┃
        ┗━━━━━━━━━━━━━━━┛
   All nodes mutually attested
   Policy synchronized
   Enforcement active
```

**Trust Verification Conditions**:

1. Valid ECDSA signature on attestation evidence
2. Nonces match expected values (freshness)
3. Policy digest matches known good policy OR is newer version
4. VirtualID derivation matches expected value
5. mTLS certificate matches public key in attestation

**Trust Revocation**:

- Attestation failure triggers peer removal from trust list
- Policy digest mismatch triggers re-synchronization attempt
- Repeated failures trigger administrator alert
- Future: CRL gossip protocol (Phase 2)

### systemd Security Hardening

The sgx-guardian.service unit applies comprehensive security restrictions:

```ini
[Service]
# Process isolation
PrivateTmp=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

# Namespace restrictions
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes

# Capability restrictions (minimal set)
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

# System call filtering
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @module @debug @mount @raw-io @reboot @swap @obsolete
SystemCallErrorNumber=EPERM

# Filesystem access control
ReadOnlyPaths=/
ReadWritePaths=/var/lib/sgx-guardian
ReadWritePaths=/var/log/sgx-guardian
ReadWritePaths=/tmp

# Resource limits
MemoryMax=512M
TasksMax=128
```

---

## Data Architecture

### Data Storage Layout

```sh
/etc/sgx-guardian/
├── config.toml                    # Daemon configuration
├── policy-authority.pub           # Trusted PA public key
└── tls/
    └── ca-bundle.pem              # Future: trusted CA certificates

/var/lib/sgx-guardian/
├── identity.key                   # Node private key (0600)
├── identity.pub                   # Node public key (0644)
├── policy/
│   ├── current.yaml              # Active policy
│   ├── current.yaml.sig          # Active policy signature
│   ├── previous.yaml             # Rollback target
│   ├── previous.yaml.sig
│   └── archive/
│       └── policy_*.yaml         # Historical policies
├── nftables/
│   ├── current.nft               # Active nftables ruleset
│   └── previous.nft              # Rollback nftables ruleset
└── state/
    ├── peer_cache.json           # Known peers and trust state
    └── virtual_ids.json          # Peer VirtualID mappings

/var/log/sgx-guardian/
├── audit.jsonl                   # Tamper-evident audit log
├── audit.jsonl.1.gz              # Rotated audit logs
└── operational.log               # Standard application logs
```

### Data Flow Diagram

```sh
┌─────────────────────────────────────────────────────────────────┐
│                         Data Flows                              │
└─────────────────────────────────────────────────────────────────┘

1. Configuration Data (Read-Only)
   /etc/sgx-guardian/config.toml
   └──► Loaded at daemon startup
        └──► In-memory configuration struct

2. Identity Data (Read at Startup)
   /var/lib/sgx-guardian/identity.key
   └──► Loaded into secure memory
        └──► Used by key_manager for all signing operations

3. Policy Data (Read/Write)
   gRPC Policy Update Message
   └──► policy_manager verification
        └──► /var/lib/sgx-guardian/policy/current.yaml
             └──► enforcement_engine translation
                  └──► /var/lib/sgx-guardian/nftables/current.nft
                       └──► nftables kernel application

4. Telemetry Data (Write-Only)
   In-memory metrics collection
   └──► telemetry_service aggregation
        └──► Prometheus HTTP endpoint (pull)

5. Audit Data (Append-Only)
   Security events
   └──► audit_logger formatting
        └──► /var/log/sgx-guardian/audit.jsonl
             └──► External SIEM (future)

6. Peer State (Read/Write)
   mDNS discovery results
   └──► p2p_discovery cache
        └──► /var/lib/sgx-guardian/state/peer_cache.json
             └──► attestation_service lookup
```

### UEP Policy Schema

**UEP Policy v1.0 Structure**:

```yaml
# Metadata Section
version: "1.0"
metadata:
  policy_id: "550e8400-e29b-41d4-a716-446655440000"  # UUID
  sequence: 42                                       # Monotonic counter
  created_at: "2025-11-12T10:30:00Z"                # ISO 8601
  description: "Production edge device policy"
  author: "security-team@example.com"

# Cryptographic Signature (detached)
signature:
  algorithm: "ECDSA-P256-SHA256"
  public_key_id: "PA-2025-001"
  signature: "MEUCIQDx7VQ..." # Base64 DER-encoded

# Enforcement Rules (L3/L4 only in Phase 1)
rules:
  - name: "Allow SSH from management"
    action: accept
    protocol: tcp
    source_ip: "10.0.1.0/24"
    destination_port: 22
    log: true

  - name: "Allow HTTPS from anywhere"
    action: accept
    protocol: tcp
    destination_port: 443

  - name: "Allow guardian P2P"
    action: accept
    protocol: tcp
    source_port: 50051
    destination_port: 50051

  - name: "Allow established connections"
    action: accept
    connection_state: established

  - name: "Default deny inbound"
    action: drop
    direction: inbound
    log: true
```

**Schema Validation Rules**:

- `version` must be "1.0"
- `policy_id` must be valid UUID v4
- `sequence` must be greater than previous policy
- `created_at` must be valid ISO 8601 timestamp
- `rules` must be non-empty array
- Each rule must have `name` and `action` ("accept" | "drop" | "reject")
- IP addresses validated as CIDR notation
- Port numbers validated as 1-65535

### Audit Log Format

**Tamper-Evident JSON Lines Format**:

```jsonl
{"timestamp":"2025-11-12T10:30:00.123Z","sequence":1,"event":"daemon_started","details":{"version":"1.0.0"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","hash":"a1b2c3d4..."}
{"timestamp":"2025-11-12T10:30:05.456Z","sequence":2,"event":"peer_discovered","details":{"peer_id":"node-b","ip":"192.168.1.101"},"prev_hash":"a1b2c3d4...","hash":"e5f6g7h8..."}
{"timestamp":"2025-11-12T10:30:06.789Z","sequence":3,"event":"attestation_success","details":{"peer_id":"node-b","virtual_id":"9i0j1k2l..."},"prev_hash":"e5f6g7h8...","hash":"m3n4o5p6..."}
{"timestamp":"2025-11-12T10:35:00.012Z","sequence":4,"event":"policy_updated","details":{"policy_id":"550e8400...","sequence":42},"prev_hash":"m3n4o5p6...","hash":"q7r8s9t0..."}
```

**Hash Chain Verification**:

```rust
// Each entry includes hash of previous entry
current_entry.prev_hash == SHA256(previous_entry_json)

// Entry hash is computed over entire entry except "hash" field
current_entry.hash == SHA256(
    timestamp || sequence || event || details || prev_hash
)
```

**Audit Events**:

- `daemon_started`, `daemon_stopped`
- `peer_discovered`, `peer_lost`
- `attestation_success`, `attestation_failure`
- `policy_received`, `policy_verified`, `policy_applied`, `policy_rollback`
- `enforcement_updated`, `enforcement_failed`
- `key_generated`, `key_loaded`
- `configuration_changed`
- `admin_command` (CLI operations)

---

## Network Architecture

### Network Topology

```sh
┌────────────────────────────────────────────────────────────────┐
│                  Local Network Segment                         │
│                    (192.168.1.0/24)                            │
│                                                                │
│  ┌───────────────┐      ┌───────────────┐      ┌─────────────┐ │
│  │   Node A      │      │   Node B      │      │   Node C    │ │
│  │ 192.168.1.100 │      │ 192.168.1.101 │      │192.168.1.102│ │
│  └───────┬───────┘      └───────┬───────┘      └──────┬──────┘ │
│          │                      │                     │        │
│          └──────────────────────┼─────────────────────┘        │
│                                 │                              │
│                     ┌───────────▼──────────┐                   │
│                     │  Network Switch      │                   │
│                     │  (mDNS multicast)    │                   │
│                     └───────────┬──────────┘                   │
│                                 │                              │
└─────────────────────────────────┼──────────────────────────────┘
                                  │
                    ┌─────────────▼──────────────┐
                    │  Management Workstation    │
                    │  - sgx-pa-cli              │
                    │  - Prometheus Scraper      │
                    └────────────────────────────┘
```

### Protocol Stack

```sh
┌─────────────────────────────────────────────────────────────────┐
│                    Protocol Stack                               │
└─────────────────────────────────────────────────────────────────┘

Application Layer
├─ gRPC (P2P Communication)
│  ├─ PolicyUpdate RPC
│  ├─ AttestationRequest RPC
│  ├─ AttestationEvidence RPC
│  └─ PeerStatus RPC
│
├─ HTTP (Telemetry)
│  └─ GET /metrics (Prometheus)
│
└─ mDNS (Discovery)
   └─ _sgx-guardian._tcp.local

Transport Layer
├─ TLS 1.3 (over TCP)
│  ├─ mTLS mutual authentication
│  ├─ ECDHE P-256 key exchange
│  └─ AES-256-GCM encryption
│
└─ UDP (mDNS multicast)

Network Layer
├─ IPv4
└─ IPv6 (future)

Data Link Layer
└─ Ethernet (IEEE 802.3)
```

### Port Assignments

| Port | Protocol | Service | Direction | Purpose |
| ---- | -------- | ------- | --------- | ------- |
| **5353** | UDP | mDNS | Multicast | Peer discovery (224.0.0.251) |
| **50051** | TCP/TLS | gRPC | Bidirectional | P2P secure communication |
| **9090** | HTTP | Prometheus | Inbound (localhost) | Metrics endpoint |

**Firewall Requirements**:

```bash
# mDNS discovery (all nodes)
nft add rule inet filter input udp dport 5353 ip daddr 224.0.0.251 accept

# gRPC P2P (between trusted peers)
nft add rule inet filter input tcp dport 50051 ip saddr @trusted_peers accept

# Prometheus scraper (from management network)
nft add rule inet filter input tcp dport 9090 ip saddr 10.0.1.0/24 accept
```

### mDNS Service Advertisement

**Service Type**: `_sgx-guardian._tcp.local`

**TXT Record Format**:

```sh
version=1.0
nonce=a1b2c3d4e5f6...
pubkey_fingerprint=sha256:7f8g9h0i...
```

**DNS-SD Advertisement**:

```sh
_sgx-guardian._tcp.local. PTR node-a._sgx-guardian._tcp.local.
node-a._sgx-guardian._tcp.local. SRV 0 0 50051 node-a.local.
node-a._sgx-guardian._tcp.local. TXT "version=1.0" "nonce=..."
node-a.local. A 192.168.1.100
```

### Network Security Zones

```sh
┌────────────────────────────────────────────────────────────────┐
│                     Security Zones                             │
└────────────────────────────────────────────────────────────────┘

Zone 1: Circle of Trust (Trusted Peers)
┌──────────────────────────────────────────┐
│ - Attested peers only                    │
│ - mTLS encrypted communication           │
│ - Policy synchronization allowed         │
│ - Full bidirectional gRPC                │
└──────────────────────────────────────────┘

Zone 2: Management Network (10.0.1.0/24)
┌──────────────────────────────────────────┐
│ - Administrator workstations             │
│ - Prometheus monitoring                  │
│ - SSH access (policy-controlled)         │
│ - Read-only metrics access               │
└──────────────────────────────────────────┘

Zone 3: Untrusted Network (Internet)
┌──────────────────────────────────────────┐
│ - Outbound telemetry only (Phase 1 mock) │
│ - No inbound connections accepted        │
│ - Future: Cloud management (Phase 2)     │
└──────────────────────────────────────────┘

Zone 4: Localhost Only
┌──────────────────────────────────────────┐
│ - Prometheus metrics (127.0.0.1:9090)    │
│ - Admin CLI socket (future)              │
│ - No external access                     │
└──────────────────────────────────────────┘
```

---

## Deployment Architecture

### Deployment Model

**Target Platforms**:

- Debian 10+ (Buster and later)
- Ubuntu 20.04 LTS and later
- RHEL 8+ / Rocky Linux 8+
- Fedora 34+

**Minimum System Requirements**:

- CPU: x86_64 or ARM64 (2 cores recommended)
- RAM: 256 MB minimum, 512 MB recommended
- Disk: 100 MB for binaries, 1 GB for logs/state
- Network: 1 Gbps Ethernet recommended
- Kernel: Linux 5.4+ with nftables support

### Package Structure

**Debian/Ubuntu (.deb)**:

```sh
sgx-guardian_1.0.0_amd64.deb
├── DEBIAN/
│   ├── control                    # Package metadata
│   ├── preinst                    # Pre-installation script
│   ├── postinst                   # Post-installation script
│   ├── prerm                      # Pre-removal script
│   └── postrm                     # Post-removal script
├── usr/
│   ├── bin/
│   │   ├── sgx-guardian           # Main daemon binary
│   │   └── sgx-pa-cli             # Admin CLI tool
│   └── share/
│       └── doc/
│           └── sgx-guardian/
│               ├── README.md
│               └── LICENSE
├── etc/
│   └── sgx-guardian/
│       └── config.toml.example    # Example configuration
└── lib/
    └── systemd/
        └── system/
            └── sgx-guardian.service  # systemd unit file
```

**Installation Hooks**:

**postinst**:

```bash
#!/bin/bash
# Create system user and group
useradd -r -s /usr/sbin/nologin -d /var/lib/sgx-guardian sgx-guardian

# Create state directories
mkdir -p /var/lib/sgx-guardian/{policy,nftables,state}
mkdir -p /var/log/sgx-guardian
mkdir -p /etc/sgx-guardian

# Set ownership and permissions
chown -R sgx-guardian:sgx-guardian /var/lib/sgx-guardian
chown -R sgx-guardian:sgx-guardian /var/log/sgx-guardian
chmod 700 /var/lib/sgx-guardian
chmod 700 /var/log/sgx-guardian

# Copy example config if no config exists
if [ ! -f /etc/sgx-guardian/config.toml ]; then
    cp /etc/sgx-guardian/config.toml.example /etc/sgx-guardian/config.toml
    chown root:sgx-guardian /etc/sgx-guardian/config.toml
    chmod 640 /etc/sgx-guardian/config.toml
fi

# Enable and start service
systemctl daemon-reload
systemctl enable sgx-guardian.service
systemctl start sgx-guardian.service
```

### Configuration Management

**config.toml**:

```toml
[daemon]
log_level = "info"              # trace, debug, info, warn, error
state_dir = "/var/lib/sgx-guardian"
log_dir = "/var/log/sgx-guardian"

[network]
grpc_listen_addr = "0.0.0.0:50051"
metrics_listen_addr = "127.0.0.1:9090"
mdns_interface = "eth0"         # Auto-detect if empty

[discovery]
mdns_service_type = "_sgx-guardian._tcp"
announcement_interval_sec = 30
peer_timeout_sec = 300

[attestation]
re_attestation_interval_sec = 300
max_nonce_age_sec = 60

[policy]
policy_dir = "/var/lib/sgx-guardian/policy"
rollback_timeout_sec = 30
policy_authority_pubkey = "/etc/sgx-guardian/policy-authority.pub"

[enforcement]
nftables_table = "inet sgx_guardian"
connectivity_check_timeout_sec = 30

[telemetry]
enabled = true
retention_days = 7

[audit]
enabled = true
rotation_size_mb = 100
retention_days = 90

[cloud]
enabled = false                 # Phase 1: disabled
uplink_url = ""                 # Phase 2: cloud endpoint
heartbeat_interval_sec = 60
```

### systemd Service Unit

**sgx-guardian.service**:

```ini
[Unit]
Description=SG-X Guardian - Circle of Trust Daemon
Documentation=https://docs.example.com/sgx-guardian
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=sgx-guardian
Group=sgx-guardian
ExecStart=/usr/bin/sgx-guardian --config /etc/sgx-guardian/config.toml
Restart=on-failure
RestartSec=10s
TimeoutStartSec=30s
TimeoutStopSec=30s
WatchdogSec=60s

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @module @debug @mount @raw-io @reboot @swap @obsolete
SystemCallErrorNumber=EPERM

# Filesystem access
ReadOnlyPaths=/
ReadWritePaths=/var/lib/sgx-guardian
ReadWritePaths=/var/log/sgx-guardian
ReadWritePaths=/tmp

# Resource limits
MemoryMax=512M
TasksMax=128
LimitNOFILE=8192

[Install]
WantedBy=multi-user.target
```

### Deployment Workflow

```sh
┌────────────────────────────────────────────────────────────────┐
│                  Deployment Workflow                           │
└────────────────────────────────────────────────────────────────┘

1. Build Pipeline (GitHub Actions)
   ┌──────────────┐
   │ Git Push     │ Developer commits to main
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │ CI/CD Build  │ Compile, test, security scan
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │ Package Build│ Create .deb and .rpm
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │ Sign Package │ GPG signature for authenticity
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │ Publish      │ Upload to package repository
   └──────────────┘

2. Installation (Administrator)
   ┌──────────────┐
   │ Download Pkg │ apt install sgx-guardian
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │ Verify Sig   │ Package manager validates signature
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │ Install Files│ Extract and place binaries
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │ Run postinst │ Create user, directories, config
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │ Start Service│ systemctl start sgx-guardian
   └──────────────┘

3. Initial Configuration
   ┌──────────────┐
   │ Generate Keys│ First boot: creates identity keys
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │ Discover     │ mDNS finds peers
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │ Attest Peers │ Mutual attestation handshake
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │ Await Policy │ Wait for admin to distribute policy
   └──────────────┘

4. Policy Distribution (One-Time Setup)
   ┌──────────────┐
   │ Admin: Sign  │ sgx-pa-cli sign policy.yaml
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │ Distribute   │ Copy to one node or push via gRPC
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │ Gossip       │ Node propagates to Circle of Trust
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐
   │ Enforce      │ All nodes apply policy atomically
   └──────────────┘
```

---

## Technology Stack

### Core Technologies

| Layer | Technology | Version | Purpose |
| ----- | --------- | ------- | ------- |
| **Programming Language** | Rust | 1.70+ | Memory-safe systems programming |
| **RPC Framework** | gRPC (tonic) | 0.11+ | Strongly-typed P2P communication |
| **Serialization** | Protocol Buffers | proto3 | Efficient binary serialization |
| **Cryptography** | ring, p256 | Latest | ECDSA signatures, hashing |
| **TLS** | rustls | 0.21+ | Pure-Rust TLS 1.3 implementation |
| **Policy Format** | YAML | 1.0 | Human-readable policy definition |
| **Enforcement** | nftables | 0.9+ | Kernel-level packet filtering |
| **Service Management** | systemd | 230+ | Process lifecycle and hardening |
| **Logging** | tracing | 0.1+ | Structured, async-aware logging |
| **Metrics** | prometheus | 0.13+ | Metrics collection and exposition |

### Rust Crate Dependencies

**Critical Path (Security-Audited)**:

```toml
[dependencies]
# Core async runtime
tokio = { version = "1.36", features = ["full"] }

# gRPC and networking
tonic = "0.11"
prost = "0.12"
rustls = "0.21"
tokio-rustls = "0.24"

# Cryptography
ring = "0.17"
p256 = { version = "0.13", features = ["ecdsa", "pem"] }
sha2 = "0.10"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
serde_yaml = "0.9"

# Error handling
anyhow = "1.0"
thiserror = "1.0"

# Logging and observability
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }
prometheus = "0.13"

# mDNS discovery
mdns-sd = "0.10"

# CLI framework
clap = { version = "4.5", features = ["derive"] }

# Configuration
toml = "0.8"
config = "0.14"
```

**Development Dependencies**:

```toml
[dev-dependencies]
mockall = "0.12"       # Mocking for unit tests
criterion = "0.5"      # Benchmarking
proptest = "1.4"       # Property-based testing
```

### External System Dependencies

| Dependency | Minimum Version | Purpose |
| ---------- | -------------- | ------- |
| **Linux Kernel** | 5.4+ | nftables support, modern netfilter |
| **nftables** | 0.9.0+ | Policy enforcement |
| **systemd** | 230+ | Service management, journald |
| **glibc** | 2.27+ | Standard C library |
| **OpenSSL** | 1.1.1+ | System crypto libraries (build-time only) |

### Build Toolchain

```bash
# Rust toolchain
rustc 1.70.0+
cargo 1.70.0+

# Additional tools
cargo-clippy        # Linting
cargo-fmt           # Code formatting
cargo-audit         # Dependency vulnerability scanning
cargo-deny          # License and security policy enforcement
cargo-tarpaulin     # Code coverage
```

### CI/CD Tooling

| Tool | Purpose |
| ---- | ------- |
| **GitHub Actions** | Primary CI/CD platform |
| **Semgrep** | SAST (Static Application Security Testing) |
| **CodeQL** | Advanced security analysis |
| **cargo-audit** | Dependency vulnerability scanning |
| **cargo-deny** | License compliance and security policy |
| **tarpaulin** | Code coverage reporting |
| **debuild** | Debian package building |
| **rpmbuild** | RPM package building |

---

## Integration Architecture

### External System Integrations

```sh
┌───────────────────���────────────────────────────────────────────┐
│                   Integration Points                           │
└────────────────────────────────────────────────────────────────┘

1. Monitoring System (Prometheus)
   ┌─────────────────┐          ┌─────────────────┐
   │ Prometheus      │──scrape─►│ sgx-guardian    │
   │ Server          │◄─metrics─│ :9090/metrics   │
   └────────┬────────┘          └─────────────────┘
            │
            ▼
   ┌─────────────────┐
   │ Grafana         │ Visualization dashboards
   └─────────────────┘

2. Log Aggregation (journald → SIEM)
   ┌─────────────────┐          ┌─────────────────┐
   │ sgx-guardian    │──logs───►│ journald        │
   └─────────────────┘          └────────┬────────┘
                                         │
                                         ▼
                                ┌─────────────────┐
                                │ journald export │
                                │ (future: SIEM)  │
                                └─────────────────┘

3. Package Repository
   ┌─────────────────┐          ┌─────────────────┐
   │ GitHub Actions  │──upload─►│ APT Repository  │
   └─────────────────┘          │ YUM Repository  │
                                └────────┬────────┘
                                         │
                                         ▼
                                ┌─────────────────┐
                                │ Administrator   │
                                │ apt install     │
                                └─────────────────┘

4. Cloud Integration (Phase 1 Mock)
   ┌─────────────────┐          ┌─────────────────┐
   │ sgx-guardian    │──https──►│ Cloud Mock      │
   │ (outbound only) │◄─ack─────│ (TLS endpoint)  │
   └─────────────────┘          └─────────────────┘
   Payload: Heartbeat, telemetry summary, alert events

5. Policy Authority Workflow
   ┌─────────────────┐          ┌─────────────────┐
   │ Administrator   │──sign───►│ sgx-pa-cli      │
   │                 │          │ (offline)       │
   └─────────────────┘          └────────┬────────┘
                                         │
                                         ▼
                                ┌─────────────────┐
                                │ policy.yaml.sig │
                                └────────┬────────┘
                                         │
                                         ▼
                                ┌─────────────────┐
                                │ sgx-guardian    │
                                │ (distribution)  │
                                └─────────────────┘
```

### API Specifications

**gRPC Service Definitions** (Protobuf):

```protobuf
syntax = "proto3";
package sgx.guardian.v1;

// P2P Communication Service
service GuardianP2P {
  // Initiate attestation with a peer
  rpc Attest(AttestationRequest) returns (AttestationEvidence);

  // Distribute policy to peer
  rpc DistributePolicy(PolicyUpdate) returns (PolicyAck);

  // Query peer status
  rpc GetStatus(StatusRequest) returns (StatusResponse);
}

// Attestation Messages
message AttestationRequest {
  bytes nonce = 1;
  bytes public_key = 2;
  bytes policy_digest = 3;
}

message AttestationEvidence {
  bytes signature = 1;        // ECDSA signature over nonce+policy_digest
  bytes public_key = 2;
  bytes policy_digest = 3;
  bytes virtual_id = 4;
}

// Policy Distribution Messages
message PolicyUpdate {
  string policy_yaml = 1;
  bytes signature = 2;
  string public_key_id = 3;
  uint64 sequence = 4;
  int64 timestamp = 5;
}

message PolicyAck {
  bool accepted = 1;
  string message = 2;
  bytes policy_digest = 3;
}

// Status Query Messages
message StatusRequest {}

message StatusResponse {
  string version = 1;
  bytes virtual_id = 2;
  uint64 policy_sequence = 3;
  int32 peer_count = 4;
  int64 uptime_seconds = 5;
}
```

### Prometheus Metrics Catalog

**Exported Metrics**:

```sh
# System Health
sgx_guardian_up{version="1.0.0"} 1
sgx_guardian_uptime_seconds 3600

# Circle of Trust
sgx_guardian_peers_total{state="discovered"} 5
sgx_guardian_peers_total{state="attested"} 3
sgx_guardian_peers_total{state="failed"} 1

sgx_guardian_attestations_total{result="success"} 45
sgx_guardian_attestations_total{result="failure"} 2
sgx_guardian_attestation_duration_seconds{quantile="0.5"} 0.12
sgx_guardian_attestation_duration_seconds{quantile="0.99"} 0.35

# Policy Management
sgx_guardian_policy_version{policy_id="550e8400..."} 42
sgx_guardian_policy_updates_total{result="success"} 5
sgx_guardian_policy_updates_total{result="failure"} 0
sgx_guardian_policy_update_duration_seconds{quantile="0.99"} 1.2

# Enforcement
sgx_guardian_enforcement_rules_active 15
sgx_guardian_enforcement_updates_total{result="success"} 5
sgx_guardian_enforcement_updates_total{result="rollback"} 0
sgx_guardian_packets_filtered_total{action="accept"} 123456
sgx_guardian_packets_filtered_total{action="drop"} 789

# Audit Log
sgx_guardian_audit_events_total{event="attestation_success"} 45
sgx_guardian_audit_events_total{event="policy_updated"} 5
sgx_guardian_audit_log_size_bytes 1048576

# Resource Usage
sgx_guardian_memory_bytes{type="rss"} 134217728
sgx_guardian_cpu_seconds_total 120.5
sgx_guardian_goroutines 12
```

---

## Operational Architecture

### Operational Workflows

#### 1. Day 0: Initial Deployment

```sh
Administrator Actions:
1. Generate Policy Authority key pair (offline, secure workstation)
   $ sgx-pa-cli keygen --output pa-keypair.pem

2. Install guardian on all nodes
   $ ansible all -m apt -a "name=sgx-guardian state=present"

3. Distribute PA public key to all nodes
   $ ansible all -m copy -a "src=pa-public.pem dest=/etc/sgx-guardian/policy-authority.pub"

4. Start guardian services
   $ ansible all -m systemd -a "name=sgx-guardian state=started enabled=yes"

5. Wait for Circle of Trust formation (verify via CLI)
   $ sgx-pa-cli status --node node-a
   Circle of Trust: 3 peers attested

6. Create and sign initial policy
   $ sgx-pa-cli sign --policy initial-policy.yaml --key pa-keypair.pem

7. Distribute policy to one node (will gossip to others)
   $ sgx-pa-cli push-policy --policy initial-policy.yaml.sig --target node-a:50051
```

#### 2. Day 1: Policy Updates

```sh
Administrator Actions:
1. Edit policy file (add/remove rules)
   $ vim production-policy.yaml

2. Sign updated policy (increments sequence number)
   $ sgx-pa-cli sign --policy production-policy.yaml --key pa-keypair.pem

3. Distribute to Circle of Trust
   $ sgx-pa-cli push-policy --policy production-policy.yaml.sig --target node-a:50051

4. Monitor rollout (watch metrics or CLI)
   $ watch sgx-pa-cli status --node node-a,node-b,node-c
   Node A: Policy v43 applied (2s ago)
   Node B: Policy v43 applied (3s ago)
   Node C: Policy v43 applied (3s ago)
```

#### 3. Day 2: Incident Response

```sh
Scenario: Attestation failure detected

1. Alert triggered (Prometheus alerting rule)
   ALERT: sgx_guardian_attestations_total{result="failure"} > 0

2. Administrator investigates
   $ sgx-pa-cli logs --node node-b --level error --last 1h
   [ERROR] Attestation failed: policy_digest mismatch

3. Check policy state
   $ sgx-pa-cli status --node node-b --verbose
   Policy Sequence: 41 (expected: 43)
   Status: Out of sync

4. Force policy re-sync
   $ sgx-pa-cli push-policy --policy latest-policy.yaml.sig --target node-b:50051

5. Verify resolution
   $ sgx-pa-cli status --node node-b
   Policy Sequence: 43 ✓
   Circle of Trust: 3 peers attested ✓
```

#### 4. Monitoring & Observability

```sh
Key Operational Dashboards (Grafana):

1. Circle of Trust Health
   - Total peers discovered vs. attested
   - Attestation success rate (target: >99%)
   - Average time to attestation
   - Peer loss/recovery events

2. Policy Distribution
   - Policy version per node (should be uniform)
   - Policy update success rate
   - Policy update duration (p50, p95, p99)
   - Rollback events (should be rare)

3. Enforcement Metrics
   - Active rules count
   - Packets filtered per second
   - Rule hit rates (top 10 rules)
   - Enforcement failures (should be zero)

4. System Health
   - Daemon uptime per node
   - Memory/CPU usage
   - Audit log size and rotation status
   - API latency (gRPC endpoint performance)
```

### Backup and Recovery

**Critical Data to Backup**:

1. Node identity keys: `/var/lib/sgx-guardian/identity.key`
2. Active policy: `/var/lib/sgx-guardian/policy/current.yaml`
3. Configuration: `/etc/sgx-guardian/config.toml`
4. Audit logs: `/var/log/sgx-guardian/audit.jsonl*`

**Recovery Procedures**:

```sh
Scenario 1: Node Failure (Hardware)
1. Deploy new hardware
2. Install sgx-guardian package
3. Restore identity key backup (maintains peer identity)
4. Start daemon
5. Peers will re-discover and re-attest automatically
6. Policy will sync from Circle of Trust

Scenario 2: Corrupted Policy
1. Stop daemon: systemctl stop sgx-guardian
2. Remove corrupted policy: rm /var/lib/sgx-guardian/policy/current.yaml*
3. Restore from backup or fetch from peer
4. Restart daemon: systemctl start sgx-guardian
5. Verify policy via CLI

Scenario 3: Complete Circle Failure (All Nodes Down)
1. Bring up one node (seed node)
2. Push policy manually: sgx-pa-cli push-policy ...
3. Start remaining nodes
4. Nodes discover seed, sync policy, attest
5. Circle of Trust reforms automatically
```

### Maintenance Windows

**Planned Maintenance**:

1. Guardian software updates: Rolling update (one node at a time)
2. Policy updates: Zero downtime (atomic replacement)
3. Key rotation (future): Planned downtime or rolling rotation
4. Log rotation: Automatic, no downtime required

**Update Procedure (Rolling Update)**:

```bash
# Update one node at a time
for node in node-a node-b node-c; do
  ssh $node "sudo apt update && sudo apt install sgx-guardian"
  ssh $node "sudo systemctl restart sgx-guardian"
  sleep 60  # Wait for node to rejoin Circle of Trust
done
```

---

## Future Architecture Evolution

### Phase 2 Enhancements

#### 1. Hardware TPM Attestation

```sh
Current (Phase 1):              Future (Phase 2):
┌───────────────┐               ┌───────────────┐
│ Software      │               │ TPM 2.0       │
│ Attestation   │               │ - PCR binding │
│ - Filesystem  │   ────────►   │ - Sealed keys │
│   key storage │               │ - Quote API   │
│ - Signature   │               │ - Hardware RoT│
│   verification│               └───────────────┘
└───────────────┘
```

#### 2. Bi-directional Cloud Integration

```sh
Current (Phase 1):              Future (Phase 2):
┌──────────────┐               ┌──────────────┐
│ Outbound-Only│               │ Bi-directional│
│ - Heartbeat  │   ────────►   │ - Policy push│
│ - Telemetry  │               │ - Remote CLI │
│ - No inbound │               │ - Fleet mgmt │
└──────────────┘               └──────────────┘
```

#### 3. L7 Protocol Connectors

```sh
Current (Phase 1):              Future (Phase 2):
┌──────────────┐               ┌──────────────┐
│ L3/L4 Only   │               │ L7 Inspection│
│ - IP/Port    │   ────────►   │ - Modbus     │
│ - nftables   │               │ - OPC-UA     │
│              │               │ - BACnet     │
│              │               │ - eBPF/XDP   │
└──────────────┘               └──────────────┘
```

#### 4. Certificate Revocation List (CRL) Gossip

```sh
Current (Phase 1):              Future (Phase 2):
┌──────────────┐               ┌──────────────┐
│ No Revocation│               │ CRL Gossip   │
│ - Manual peer│   ────────►   │ - Distributed│
│   removal    │               │   CRL        │
│              │               │ - Auto-revoke│
└──────────────┘               └──────────────┘
```

### Phase 3+ Vision

#### 1. Virtual Shift (AI/ML Anomaly Detection)

```sh
┌────────────────────────────────────────────────────────────────┐
│                  Virtual Shift Architecture                    │
└────────────────────────────────────────────────────────────────┘

   Traffic Flow               ML Processing             Adaptive Policy
┌──────────────┐           ┌──────────────┐           ┌──────────────┐
│ Network      │──telemetry─►│ Anomaly     │──threat──►│ Auto-adjust  │
│ Traffic      │           │ Detection    │  score    │ Rules        │
│ (nftables)   │           │ (ML Model)   │           │ (Dynamic UEP)│
└──────────────┘           └──────────────┘           └──────────────┘
                                  │
                                  │ Training data
                                  ▼
                           ┌──────────────┐
                           │ Cloud ML     │
                           │ Training     │
                           └──────────────┘
```

#### 2. Scalability Enhancements

- Support for cohorts >100 nodes (gossip protocol optimization)
- Hierarchical trust domains (multi-cohort federation)
- Edge-to-cloud policy pipeline (bidirectional sync)

#### 3. Compliance & Audit

- FIPS 140-3 certification
- Common Criteria EAL4+ evaluation
- Integration with security orchestration platforms (SOAR)

### Extensibility Points

The architecture provides extension points for future capabilities:

| Extension Point | Interface | Future Use Case |
| -------------- | --------- | --------------- |
| **Attestation Provider** | Trait `AttestationProvider` | TPM, SGX, SEV attestation backends |
| **Policy Schema** | Versioned YAML schema | L7 rules, advanced filtering, dynamic policies |
| **Enforcement Backend** | Trait `EnforcementEngine` | eBPF/XDP, DPDK, hardware offload |
| **Discovery Mechanism** | Trait `PeerDiscovery` | Cloud-based discovery, DHT, static config |
| **Telemetry Sink** | Trait `TelemetrySink` | Cloud telemetry, custom SIEM, CEF format |

---

## Architecture Decision Records

This architecture document is supported by detailed decision records. All 20 architectural decisions are documented in the [Decision Log](../decision-log/README.md) with full context, rationale, alternatives considered, and implications.

### Key Decisions Reference

| Decision | Title | Impact |
| -------- | ----- | ------ |
| [D001](../decision-log/README.md#d001-core-programming-language---rust) | Core Programming Language - Rust | Foundation: Memory safety, performance |
| [D002](../decision-log/README.md#d002-inter-service-communication-protocol---grpc-over-mtls) | gRPC over mTLS | P2P communication protocol |
| [D003](../decision-log/README.md#d003-cryptographic-algorithm---ecdsa-p-256) | ECDSA P-256 Cryptography | All signing and encryption |
| [D004](../decision-log/README.md#d004-peer-discovery-mechanism---mdns) | mDNS Peer Discovery | Zero-configuration discovery |
| [D005](../decision-log/README.md#d005-policy-enforcement-layer---nftables) | nftables Enforcement | Kernel-level packet filtering |
| [D006](../decision-log/README.md#d006-virtual-identity-derivation) | Virtual Identity Derivation | State-bound identity |
| [D007](../decision-log/README.md#d007-attestation-model---software-based-phase-1) | Software Attestation (Phase 1) | Attestation approach |
| [D008](../decision-log/README.md#d008-service-architecture---monolithic-daemon) | Monolithic Daemon Architecture | Deployment model |
| [D009](../decision-log/README.md#d009-service-management---systemd) | systemd Service Management | Process lifecycle |
| [D010](../decision-log/README.md#d010-package-distribution---deb-and-rpm) | .deb/.rpm Packaging | Distribution mechanism |
| [D011](../decision-log/README.md#d011-error-handling-strategy---result-types-with-context) | Result Types Error Handling | Error management strategy |
| [D012](../decision-log/README.md#d012-logging-and-observability-strategy) | Dual Logging Strategy | Audit + operational logs |
| [D013](../decision-log/README.md#d013-policy-schema---yaml-based-uep-v10) | YAML Policy Schema | Policy format |
| [D014](../decision-log/README.md#d014-atomic-policy-updates-with-rollback) | Atomic Policy Updates | Policy safety mechanism |
| [D015](../decision-log/README.md#d015-metrics-and-telemetry---prometheus-format) | Prometheus Metrics | Observability standard |
| [D016](../decision-log/README.md#d016-cloud-integration---outbound-only-mock-phase-1) | Outbound-Only Cloud Mock | Cloud integration path |
| [D017](../decision-log/README.md#d017-cicd-pipeline---github-actions) | GitHub Actions CI/CD | Build automation |
| [D018](../decision-log/README.md#d018-branch-protection-and-development-workflow) | Branch Protection Workflow | Development process |
| [D019](../decision-log/README.md#d019-test-strategy---unit-integration-and-e2e) | Three-Tier Test Strategy | Quality assurance |
| [D020](../decision-log/README.md#d020-feature-deferrals-to-phase-2) | Feature Deferrals | Scope management |

---

## Document Maintenance

**Document Owner**: Project Lead

**Review Cycle**: Updated at each sprint boundary and milestone

**Versioning**:

- Version 1.0: Initial architecture (November 12, 2025)
- Future versions will be tracked in git history

**Related Documents**:

- [Project README](../README.md) - Overview and getting started
- [Decision Log](../decision-log/README.md) - Detailed architectural decisions
- [Deliverables Tracking](../deliverables/README.md) - Sprint and milestone tracking
- [Branch Protection Setup](../BRANCH_PROTECTION_SETUP.md) - Git workflow

---

**Last Updated**: November 12, 2025

**Status**: Living Document - Updated throughout Phase 1 development
