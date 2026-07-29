# SG-X Guardian – Additional Frontend & Containerization Deliverables Contract

- **Phase:** Phase 2 Extension – Frontend Feature Implementation,
  Containerization & Integration
- **Target due date:** July 27, 2026
- **Status:** Proposed; effective upon signature by Cervais and CyberZeus

**Companion documents:**

[Deliverable tracker](deliverables/README.md) ·
[Acceptance demo use cases](deliverables/acceptance/demo-use-cases.md) ·
[Demo run template](deliverables/acceptance/demo-run-template.md)

---

## 1. Overview & Milestones

| Milestone / Due Date | Scope Covered | Status |
|---|---|---|
| **27 July, 2026** | Frontend Communications (Text, Voice, Video, File Transfer), Circle-as-Comms Container, Encrypted Cloud Storage Vault, Smart Home Integration, Live Network Topology Mesh Map, Geofencing, Backup & Restore, Push Notifications, Custom Alert Rules / Automation Engine, Data Usage Monitoring, AI Alert Recommendations, Cylenium SSO / Cloud Sign-On, Connected Device Security & Privacy Scoring, Containerization Requirements & Container Installation Demonstration. | Pending |

---

## 2. Extracted Scope & Deliverables

| Scope | Deliverable | Description |
|---|---|---|
| **Communications** | **Text Chat / Messaging** | Implement secure real-time Circle messaging including message history, timestamps, read receipts, image/file attachments, and encrypted message transport. Support persistent message storage and synchronization between Circle members. |
| **Communications** | **Voice Calling** | Implement peer-to-peer and group voice communication with secure signaling, participant management, call history, mute/unmute controls, and encrypted media transport. |
| **Communications** | **Video Calling** | Implement secure video communication using the existing voice signaling layer, including camera streams, participant management, and hardware acceleration support. |
| **Communications** | **In-Circle File Transfer** | Implement secure file and image sharing within Circles, including attachment storage, transfer status tracking, file synchronization, and integration with the encrypted file vault. |
| **Circle Management** | **Circle-as-Comms Container + Invites** | Implement Circle creation, editing, membership management, QR-based invitations, signed invite tokens, and member administration using DID/VC identity verification. |
| **Storage** | **Encrypted Cloud Storage Vault** | Implement encrypted device-hosted storage with folder hierarchy, upload/download, preview, deletion, storage quota management, and integration with Circle file sharing. |
| **Smart Home** | **Smart Home Integration** | Implement integrations for Ring, Google Nest, Wyze, Ecobee, TP-Link Kasa, and Arlo devices, including automation rules, telemetry synchronization, and local hardware hub management. |
| **Network Intelligence** | **Live Network Topology / Mesh Map** | Implement real-time mesh network visualization, node/link mapping, geolocation support, event logging, topology analytics, and interactive monitoring tools. |
| **Security** | **Geofencing / Location Zones** | Implement geographic boundary management with entry/exit triggers, coordinate mapping, location-based alerts, and automation integration. |
| **System Management** | **Backup & Restore** | Implement encrypted device backup and restoration capabilities, configuration snapshots, restore validation, backup history, and secure key handling. |
| **Notifications** | **Notification Preferences + Push Delivery** | Implement notification preference management, delivery pipelines, push services, severity filtering, and real-time notification subscriptions. |
| **Automation** | **Custom Alert Rules / Automation Engine** | Implement event-condition-action rule engine supporting alert creation, modification, execution workflows, action handlers, and rule lifecycle management. |
| **Monitoring** | **Data Usage Monitoring** | Implement per-device and per-category bandwidth monitoring, quota tracking, usage history, analytics, and reset scheduling using nftables counters. |
| **AI Services** | **AI Alert Recommendation** | Implement AI-generated remediation recommendations for security alerts, integrating anomaly detection engines with contextual response generation and advisory services. |
| **Identity / Auth** | **Cylenium SSO / Cloud Sign-On** | Implement Cylenium single-sign-on as an identity-provider option alongside local email/password authentication, including the SSO/OIDC authorization flow, token exchange, session establishment, and linking of the Cylenium identity to the device DID and owner account. |
| **Device Security** | **Connected Devices Management & Security / Privacy Scoring** | Implement per-device security and privacy scoring, on-demand multi-step device security scans (firmware, open ports, encryption, known vulnerabilities, report), manual device onboarding, approve/reject workflows, and per-device block/remove enforcement, complementing NMAP network discovery. |
| **Deployment / Containerization** | **Container Installation & Hardware Environment Demo** | Demonstrate the successful installation, configuration, and execution of the SG-X Guardian application in containerized environments (Docker Compose / Kubernetes) across any target host meeting hardware requirements (e.g., secure element SE050 integration, host network access, kernel netfilter capabilities). |
| **Deployment / Containerization** | **Containerization Architecture & Tooling** | Deliver multi-stage Docker build specifications, multi-architecture image support (AMD64 dev/server/CI and ARM64 production embedded boards), privilege/capability configurations (`CAP_NET_ADMIN`, `--network host`), persistent volume mapping (`/var/lib/sgx-guardian`, `/var/log/sgx-guardian`), and configurable directory environment variables (`SGX_CONFIG_DIR`, `SGX_DATA_DIR`, `SGX_LOG_DIR`). |

---

## 3. Containerization Requirements

Based on the architectural containerization assessment, the application containerization framework must fulfill the following technical requirements:

1. **Multi-Stage Build Pipeline**:
   - **Builder Stage**: Multi-stage Rust build image (`rust:1-bookworm`) with `protobuf-compiler` (`protoc`) installed for compiling Tonic gRPC protobuf schemas (`proto/*.proto`).
   - **Runtime Stage**: Minimal runtime image (`debian:bookworm-slim`) pre-installed with `nftables` (`nft` binary), `ca-certificates`, and required glibc libraries.
2. **Multi-Architecture Support**:
   - Support **AMD64 (x86_64)** for development, CI, server/VMs, and cloud mock services.
   - Support **ARM64 (aarch64)** cross-compilation for embedded production hardware boards running Yocto Linux (Scarthgap 5.0 LTS).
3. **Privilege & Network Isolation Requirements**:
   - Container execution requires `--network host` (or Kubernetes `hostNetwork: true`) to allow L3/L4 `nftables` kernel firewall rules to apply to the host network namespace and to support mDNS multicast peer discovery (224.0.0.251:5353, ports 5353–5360 UDP).
   - Require `CAP_NET_ADMIN` capability (or `--cap-add NET_ADMIN`) for the `nft -f` executor subsystem.
4. **Volume Storage & Directory Configuration**:
   - Writable persistent volume mounts for persistent identity keys (`/var/lib/sgx-guardian/`) and tamper-evident audit logs (`/var/log/sgx-guardian/`).
   - Read-only config mounts for node configuration files (`/etc/sgx-guardian/`).
   - Application support for environment variables `SGX_CONFIG_DIR`, `SGX_DATA_DIR`, and `SGX_LOG_DIR` to decouple runtime paths from CWD.
5. **Orchestration Deployment Profiles**:
   - **Development / Demo**: Docker Compose 3-node cohort (`nodeA`, `nodeB`, `nodeC`) with `0.0.0.0` service bindings, DNS-based peer target resolution, and optional dry-run/mock enforcement mode.
   - **Production Nodes**: Kubernetes `DaemonSet` deployment profile per host node with `hostNetwork: true` and hardware root-of-trust (SE050 secure element passthrough).

---

## 4. Phase 2 Extension – Demo Definition

The extended frontend & containerization demo will successfully demonstrate the following capabilities:

1. **Secure Circle-based text messaging** with attachment support.
2. **End-to-end encrypted voice and video communication**.
3. **Secure file sharing and synchronization** between Circle members.
4. **Circle creation, invitation, and membership management workflows**.
5. **Encrypted cloud storage vault** with file management operations.
6. **Smart home device integration** and automation workflows.
7. **Real-time network topology** and mesh visualization.
8. **Geofencing triggers** and location-based automation.
9. **Encrypted backup and restore operations**.
10. **Notification preference management** and push delivery.
11. **Custom event-driven automation rules execution**.
12. **Data usage monitoring** and analytics visualization.
13. **AI-powered alert recommendations** and remediation guidance.
14. **Containerized app installation & execution** on hardware-capable environments (demonstrating container deployment with SE050 hardware security, `CAP_NET_ADMIN` firewalling, and host network integration).

The detailed steps, evidence requirements, negative cases, and pass conditions
for these capabilities are part of the
[Phase 2 Extension acceptance demo use cases](deliverables/acceptance/demo-use-cases.md).

---

## 5. Mutual Agreement and Acceptance

By signing below, Cervais and CyberZeus confirm that they have reviewed and
agree to this Phase 2 Extension, including the linked deliverable tracker and
acceptance demo use cases. Those linked documents are incorporated into this
agreement as the delivery and acceptance baseline.

Changes, substitutions, waivers, or exceptions require written agreement by
both parties. Agreement to these terms does not itself mean that implementation
has been accepted. A deliverable is accepted only after its required demo use
cases pass and both parties record `Accept` in the corresponding demo run, or
both parties approve a written exception.

| Organization | Authorized representative | Title | Signature | Date |
| --- | --- | --- | --- | --- |
| Cervais |  |  |  |  |
| CyberZeus |  |  |  |  |
