# Cervais New  Guardian Deliverable Tracking

## Project Timeline & Milestones

**Project Start Date**: October 27, 2025

**Project Duration**: 8 weeks (1.8 months)

### Milestone Payment Schedule

| Milestone | Sprint | Due Date | Description |
|-----------|--------|----------|-------------|
| **Milestone 1** | Sprint 1 (Week 1-2) | November 9, 2025 | Foundation & Bootstrap - API specs, CI/CD pipeline, security tools, test framework |
| **Milestone 2** | Sprint 2 (Week 3-4) | November 23, 2025 | Identity & Discovery - P2P discovery, key management, attestation, Demo 1 |
| **Milestone 3** | Sprint 3 (Week 5-6) | December 7, 2025 | Secure Channels & Policy Sync - mTLS/gRPC, policy signing, policy manager, Demo 2 |
| **Milestone 4** | Sprint 4 (Week 7-8) | December 21, 2025 | Enforcement & Handoff - Enforcement engine, telemetry, audit, packages, final demo |

## Deliverables

| Scope | Deliverable | Descriptions | Est Delivery | Target Date | Status | Notes | Client Depends | Billed | Paid | Original SOW | Invoice |
|-------|-------------|--------------|--------------|-------------|--------|-------|----------------|--------|------|--------------|---------|
| Project Management | GitHub Project Setup | Backlog, epics and features describing the product vision with prioritized features for the new guardian application across the Alpha, Beta, and V1 releases | 2025-11-03 | 2025-11-03 | | Include sprint ceremonies setup | Yes | | | Section 3 | |
| Project Management | Decision Log Documentation | Track all architectural, tactical, and procedural decisions including programming language, communication protocols, cryptographic algorithms, data storage, security model, system decomposition, service boundaries, integration patterns, and feature deferrals | 2025-11-09 | 2025-11-09 | | Client requested in follow-up | Yes | | | Follow-up email | |
| DevOps/CI-CD | CI/CD Pipeline Setup | Setup CI/CD pipeline with automated build stages (compilation, dependency caching, multi-arch builds), test stages (unit tests with coverage thresholds, integration tests, security tests), quality gates, and deployment stages (artifact publishing, package signing) | Milestone 1: $2,834 | 2025-11-09 | 2025-11-09 | | Include GitHub Actions | Yes | | | Section 3, Sprint 1 | |
| DevOps/CI-CD | CI/CD Pipeline Documentation | Pipeline architecture diagram, quality gate definitions, workflow procedures, and troubleshooting guide | 2025-11-09 | 2025-11-09 | | Client requested in follow-up | Yes | | | Follow-up email | |
| DevOps/CI-CD | 3-Node Test LAN Environment | Setup 3-node test LAN environment for integration testing and demos | 2025-11-09 | 2025-11-09 | | Required for all demos | No | | | Section 3, Sprint 1 | |
| Code Quality | Security Scanning Tools | Implement cargo clippy (linting), cargo fmt (formatting checks), cargo audit (dependency vulnerabilities), cargo deny (license/security policy enforcement), and SAST tools (Semgrep, CodeQL) | 2025-11-09 | 2025-11-09 | | Client requested in follow-up | Yes | | | Follow-up email | |
| Architecture | API Specification v1.0 | Complete Protobuf API schemas and sequence diagrams for all gRPC services | 2025-11-09 | 2025-11-09 | | Foundation for all dev | No | | | Section 3, Sprint 1 | |
| Architecture | UEP Policy Schema v1.0 | Design minimal UEP Policy Schema v1 (L3/L4 rules) in YAML/JSON structure | 2025-11-09 | 2025-11-09 | | Core policy format | No | | | Section 3, Sprint 1 | |
| Core Development | sgx-pa-cli Tool Skeleton | Build skeleton for Policy Authority CLI tool for key pair generation and policy signing | 2025-11-09 | 2025-11-09 | | Admin tool foundation | No | | | Section 3, Sprint 1 | |
| Core Development | P2P Discovery Service (mDNS) | Implement mDNS for zero-configuration peer discovery with service type broadcast and nonce exchange | 2025-11-23 | 2025-11-23 | | Foundation for Circle of Trust | No | | | Section 3, Sprint 2 | |
| Core Development | Key Manager (ECDSA P-256) | Implement persistent key manager for ECDSA P-256 identity key pairs | 2025-11-23 | 2025-11-23 | | Device identity foundation | No | | | Section 3, Sprint 2 | |
| Core Development | Software Attestation Service | Implement mutual software-based attestation service with cryptographic signature over nonces and policy digest | 2025-11-23 | 2025-11-23 | | Trust verification | No | | | Section 3, Sprint 2 | |
| Core Development | Milestone Demo 1 | Demonstrate 3 nodes boot, discover each other, and successfully complete mutual attestation handshake | 2025-11-23 | 2025-11-23 | | First major milestone | Yes | | | Section 3, Sprint 2 | |
| Core Development | mTLS over gRPC Implementation | Implement secure gRPC channels with mutual TLS for encrypted P2P communication | 2025-12-07 | 2025-12-07 | | Secure communication | No | | | Section 3, Sprint 3 | |
| Core Development | Policy Signing Capability | Complete sgx-pa-cli policy signing capability for administrators | 2025-12-07 | 2025-12-07 | | Policy distribution prereq | No | | | Section 3, Sprint 3 | |
| Core Development | Policy Manager | Implement policy manager for signature verification and atomic policy loading/rollback | 2025-12-07 | 2025-12-07 | | Policy sync foundation | No | | | Section 3, Sprint 3 | |
| Core Development | Milestone Demo 2 | Demonstrate admin signing a policy that is securely distributed and verified by all peers in the cohort | 2025-12-07 | 2025-12-07 | | Second major milestone | Yes | | | Section 3, Sprint 3 | |
| Core Development | Enforcement Engine | Implement enforcement engine to translate UEP v1 policy rules into concrete nftables commands for L3/L4 security control | 2025-12-21 | 2025-12-21 | | Core security enforcement | No | | | Section 3, Sprint 4 | |
| Core Development | Telemetry Service | Implement telemetry service to collect and expose Prometheus-style system metrics | 2025-12-21 | 2025-12-21 | | Operational visibility | No | | | Section 3, Sprint 4 | |
| Core Development | Audit Logger | Implement structured, tamper-evident audit log for all critical security events | 2025-12-21 | 2025-12-21 | | Security compliance | No | | | Section 3, Sprint 4 | |
| Core Development | Cloud Uplink Mock | Implement secure, outbound-only cloud uplink mock to validate integration path for future cloud management | 2025-12-21 | 2025-12-21 | | Future cloud readiness | No | | | Section 3, Sprint 4 | |
| Deployment | .deb/.rpm Packages | Create .deb and .rpm installation packages with systemd configuration and hardening | 2025-12-21 | 2025-12-21 | | Production deployment | No | | | Section 3, Sprint 4 | |
| Artifact Management | Package Storage & Versioning | Define where .deb/.rpm packages are stored, how they are versioned and signed, container registry strategy, and binary reproducibility requirements | 2025-12-21 | 2025-12-21 | | Client requested in follow-up | Yes | | | Follow-up email | |
| Deployment | Deployment Automation | Automated deployment to test environment, deployment verification tests, and rollback procedures | 2025-12-21 | 2025-12-21 | | Client requested in follow-up | Yes | | | Follow-up email | |
| Testing | Test Framework Setup | Establish test framework (cargo test) and testing infrastructure including unit tests and integration tests | 2025-11-09 | 2025-11-09 | | Client requested in follow-up | Yes | | | Follow-up email | |
| Testing | Automated Test Execution | Implement automated test execution in CI/CD pipeline with coverage thresholds (80% target) | 2025-11-23 | 2025-11-23 | | Client requested in follow-up | Yes | | | Follow-up email | |
| Testing | Test Report | Summary of all unit and integration test results across all sprints | 2025-12-21 | 2025-12-21 | | Final deliverable | Yes | | | Section 5 | |
| Documentation | Administrator Guide v0.5 | Installation, configuration, key management, and operational procedures for system administrators | 2025-12-21 | 2025-12-21 | | Final deliverable | Yes | | | Section 5 | |
| Documentation | Source Code & Documentation | Complete, modular, and documented Rust codebase for sgx-guardian daemon and sgx-pa-cli tool | 2025-12-21 | 2025-12-21 | | Final deliverable | No | | | Section 5 | |
| Demonstration | Final E2E Demo | Full end-to-end scripted demo on 3-node cohort proving trust formation, policy sync, and active L3/L4 enforcement with CLI status visibility | 2025-12-21 | 2025-12-21 | | Phase 1 completion | Yes | | | Section 3, Sprint 4 | |

## Phase 2 Extension – Additional Frontend & Containerization Deliverables (Target Date: 2026-07-27)

Acceptance is defined in the
[Phase 2 Extension demo use cases](acceptance/phase-2-extension-demo-use-cases.md).
Record each execution with the [demo run template](acceptance/demo-run-template.md);
a UI-only walkthrough does not complete a deliverable.

| Scope | Deliverable | Descriptions | Target Date | Status | Notes |
|-------|-------------|--------------|-------------|--------|-------|
| Communications | Text Chat / Messaging | Implement secure real-time Circle messaging including message history, timestamps, read receipts, image/file attachments, and encrypted message transport. | 2026-07-27 | Pending | Persistent message storage & sync |
| Communications | Voice Calling | Implement peer-to-peer and group voice communication with secure signaling, participant management, call history, mute/unmute controls, and encrypted media transport. | 2026-07-27 | Pending | Encrypted media transport |
| Communications | Video Calling | Implement secure video communication using the existing voice signaling layer, including camera streams, participant management, and hardware acceleration support. | 2026-07-27 | Pending | Uses voice signaling layer |
| Communications | In-Circle File Transfer | Implement secure file and image sharing within Circles, including attachment storage, transfer status tracking, file synchronization, and integration with the encrypted file vault. | 2026-07-27 | Pending | Integrates with file vault |
| Circle Management | Circle-as-Comms Container + Invites | Implement Circle creation, editing, membership management, QR-based invitations, signed invite tokens, and member administration using DID/VC identity verification. | 2026-07-27 | Pending | DID/VC verification |
| Storage | Encrypted Cloud Storage Vault | Implement encrypted device-hosted storage with folder hierarchy, upload/download, preview, deletion, storage quota management, and integration with Circle file sharing. | 2026-07-27 | Pending | Folder hierarchy & quotas |
| Smart Home | Smart Home Integration | Implement integrations for Ring, Google Nest, Wyze, Ecobee, TP-Link Kasa, and Arlo devices, including automation rules, telemetry synchronization, and local hardware hub management. | 2026-07-27 | Pending | 6 device brand integrations |
| Network Intelligence | Live Network Topology / Mesh Map | Implement real-time mesh network visualization, node/link mapping, geolocation support, event logging, topology analytics, and interactive monitoring tools. | 2026-07-27 | Pending | Real-time mesh map |
| Security | Geofencing / Location Zones | Implement geographic boundary management with entry/exit triggers, coordinate mapping, location-based alerts, and automation integration. | 2026-07-27 | Pending | Entry/exit triggers |
| System Management | Backup & Restore | Implement encrypted device backup and restoration capabilities, configuration snapshots, restore validation, backup history, and secure key handling. | 2026-07-27 | Pending | Encrypted snapshots |
| Notifications | Notification Preferences + Push Delivery | Implement notification preference management, delivery pipelines, push services, severity filtering, and real-time notification subscriptions. | 2026-07-27 | Pending | Severity filtering & push |
| Automation | Custom Alert Rules / Automation Engine | Implement event-condition-action rule engine supporting alert creation, modification, execution workflows, action handlers, and rule lifecycle management. | 2026-07-27 | Pending | ECA rule engine |
| Monitoring | Data Usage Monitoring | Implement per-device and per-category bandwidth monitoring, quota tracking, usage history, analytics, and reset scheduling using nftables counters. | 2026-07-27 | Pending | nftables counters |
| AI Services | AI Alert Recommendation | Implement AI-generated remediation recommendations for security alerts, integrating anomaly detection engines with contextual response generation and advisory services. | 2026-07-27 | Pending | Anomaly correlation |
| Identity / Auth | Cylenium SSO / Cloud Sign-On | Implement Cylenium single-sign-on as an identity-provider option alongside local email/password authentication, including the SSO/OIDC authorization flow, token exchange, session establishment, and linking of the Cylenium identity to the device DID and owner account. | 2026-07-27 | Pending | SSO/OIDC flow |
| Device Security | Connected Devices Management & Security / Privacy Scoring | Implement per-device security and privacy scoring, on-demand multi-step device security scans (firmware, open ports, encryption, known vulnerabilities, report), manual device onboarding, approve/reject workflows, and per-device block/remove enforcement, complementing NMAP network discovery. | 2026-07-27 | Pending | Privacy scoring & scans |
| Deployment / Containerization | Container Installation & Hardware Environment Demo | Demonstrate application installation and execution in containerized environments (Docker Compose / Kubernetes) across target hosts meeting hardware requirements (SE050, CAP_NET_ADMIN, host network). | 2026-07-27 | Pending | Hardware & container demo |
| Deployment / Containerization | Containerization Architecture & Tooling | Deliver multi-stage Docker build pipeline, multi-arch image support (AMD64 & ARM64), host network + CAP_NET_ADMIN isolation profiles, persistent volume mounts, and configurable path environment variables. | 2026-07-27 | Pending | Multi-arch Docker & Compose/K8s specs |

