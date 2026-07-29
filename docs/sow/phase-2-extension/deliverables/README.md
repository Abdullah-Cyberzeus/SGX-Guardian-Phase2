# Phase 2 Extension Deliverables

- **Target date:** July 27, 2026
- **Scope:** [Phase 2 Extension contract](../contract.md)
- **Acceptance baseline:** [Demo use cases](acceptance/demo-use-cases.md)
- **Execution record:** [Demo run template](acceptance/demo-run-template.md)

The contract defines what must be delivered. The linked demo use cases define
the observable pass conditions, and a completed run record captures the evidence
and both parties' acceptance decision. A UI-only walkthrough does not complete a
deliverable.

| Scope | Deliverable | Description | Target date | Status | Notes |
| --- | --- | --- | --- | --- | --- |
| Communications | Text Chat / Messaging | Implement secure real-time Circle messaging including message history, timestamps, read receipts, image/file attachments, encrypted transport, persistence, and synchronization. | 2026-07-27 | Pending | Persistent message storage and sync |
| Communications | Voice Calling | Implement peer-to-peer and group voice communication with secure signaling, participant management, call history, mute/unmute controls, and encrypted media transport. | 2026-07-27 | Pending | Encrypted media transport |
| Communications | Video Calling | Implement secure video communication using the existing voice signaling layer, including camera streams, participant management, and hardware acceleration support. | 2026-07-27 | Pending | Uses voice signaling layer |
| Communications | In-Circle File Transfer | Implement secure file and image sharing within Circles, including attachment storage, transfer status, synchronization, and encrypted-vault integration. | 2026-07-27 | Pending | Integrates with file vault |
| Circle Management | Circle-as-Comms Container + Invites | Implement Circle creation, editing, membership management, QR invitations, signed invite tokens, and member administration using DID/VC identity verification. | 2026-07-27 | Pending | DID/VC verification |
| Storage | Encrypted Cloud Storage Vault | Implement encrypted device-hosted storage with folder hierarchy, upload/download, preview, deletion, quota management, and Circle file-sharing integration. | 2026-07-27 | Pending | Folder hierarchy and quotas |
| Smart Home | Smart Home Integration | Implement integrations for Ring, Google Nest, Wyze, Ecobee, TP-Link Kasa, and Arlo devices, including automation rules, telemetry synchronization, and local hardware hub management. | 2026-07-27 | Pending | Six device-brand integrations |
| Network Intelligence | Live Network Topology / Mesh Map | Implement real-time mesh visualization, node/link mapping, geolocation support, event logging, topology analytics, and interactive monitoring. | 2026-07-27 | Pending | Real-time mesh map |
| Security | Geofencing / Location Zones | Implement geographic boundary management with entry/exit triggers, coordinate mapping, location-based alerts, and automation integration. | 2026-07-27 | Pending | Entry/exit triggers |
| System Management | Backup & Restore | Implement encrypted device backup and restoration, configuration snapshots, restore validation, backup history, and secure key handling. | 2026-07-27 | Pending | Encrypted snapshots |
| Notifications | Notification Preferences + Push Delivery | Implement notification preference management, delivery pipelines, push services, severity filtering, and real-time subscriptions. | 2026-07-27 | Pending | Severity filtering and push |
| Automation | Custom Alert Rules / Automation Engine | Implement an event-condition-action rule engine supporting alert creation, modification, execution, action handlers, and rule lifecycle management. | 2026-07-27 | Pending | ECA rule engine |
| Monitoring | Data Usage Monitoring | Implement per-device and per-category bandwidth monitoring, quota tracking, usage history, analytics, and reset scheduling using nftables counters. | 2026-07-27 | Pending | nftables counters |
| AI Services | AI Alert Recommendation | Implement AI-generated remediation recommendations for security alerts, integrating anomaly detection with contextual response generation and advisory services. | 2026-07-27 | Pending | Anomaly correlation |
| Identity / Auth | Cylenium SSO / Cloud Sign-On | Implement Cylenium SSO alongside local email/password authentication, including OIDC authorization, token exchange, session establishment, and identity linking to the device DID and owner account. | 2026-07-27 | Pending | SSO/OIDC flow |
| Device Security | Connected Devices Management & Security / Privacy Scoring | Implement per-device security/privacy scoring, multi-step scans, manual onboarding, approve/reject workflows, and block/remove enforcement, complementing NMAP discovery. | 2026-07-27 | Pending | Privacy scoring and scans |
| Deployment / Containerization | Container Installation & Hardware Environment Demo | Demonstrate installation and execution with Docker Compose and Kubernetes on target hosts meeting SE050, `CAP_NET_ADMIN`, and host-network requirements. | 2026-07-27 | Pending | Hardware and container demo |
| Deployment / Containerization | Containerization Architecture & Tooling | Deliver multi-stage builds, AMD64/ARM64 images, host-network and `CAP_NET_ADMIN` profiles, persistent volumes, and configurable path environment variables. | 2026-07-27 | Pending | Docker, Compose, and Kubernetes specifications |

Change a status to `Accepted` only when the required use cases pass and a
completed demo run is accepted by both Cervais and CyberZeus, or when both
parties record a written exception.
