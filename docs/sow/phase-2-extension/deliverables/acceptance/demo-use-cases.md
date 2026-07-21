# Phase 2 Extension Acceptance Demo Use Cases

- **Status:** Proposed; effective upon signature by Cervais and CyberZeus
- **SOW target date:** July 27, 2026
- **Scope source:** [Phase 2 Extension contract](../../contract.md)
- **Deliverables:** [Phase 2 Extension deliverable tracker](../README.md)
- **Execution record:** [Demo run template](demo-run-template.md)

## Purpose and acceptance standard

This document translates the latest SOW into repeatable, observable demos. It
uses the Guardian Admin Console as the operator-facing surface, but acceptance
requires end-to-end behavior rather than a UI-only walkthrough.

A use case passes only when:

1. the exact Guardian, Admin Console, image, configuration, and hardware versions
   are recorded;
2. the operator completes the flow through the delivered interface;
3. another participant or independent observer can see the resulting behavior;
4. state is durable after refresh or reconnect when persistence is part of the
   capability;
5. Guardian service and audit evidence corroborate the UI; and
6. the stated network profile is proven, including absence of upstream Internet
   for offline runs.

Mock data, simulated success toasts, screenshots of static screens, or API calls
made outside the delivered workflow do not satisfy acceptance.

Together with the [Phase 2 Extension contract](../../contract.md), this document
forms the mutual delivery and acceptance baseline. The contract defines scope;
this document defines how Cervais and CyberZeus will determine whether that
scope has been delivered.

## Product model that must be kept explicit

Three different things are called a "device" in project material:

- **Guardian node:** the SG-X hardware or containerized Guardian instance.
- **Client device:** the administrator's or invitee's phone, tablet, or computer.
- **Managed network device:** equipment discovered and controlled by a Guardian,
  such as a camera, PLC, drone, or smart-home device.

Similarly, these are separate approval flows:

- **Human or CoT membership:** invite, accept, reject or deny, remove, and revoke.
- **Managed-device admission:** discover, approve, reject, block, and remove.
- **Guardian pairing:** associate an administrator account or console with a
  Guardian node.

Every demo and defect must use those terms rather than the ambiguous word
"device."

## Admin Console capability reference

The Admin Console design and routes suggest the following acceptance surfaces:

| Capability | Admin Console surface |
| --- | --- |
| Pair a Guardian | OB-02 through OB-05; ST-08 |
| Create a CoT | OB-08; NW-02 |
| Invite and manage members | NW-06, NW-08 through NW-13 |
| Chat, calls, presence, and topology | NW-04 through NW-07 |
| Approve or reject managed devices | DV-01 Pending view |
| Score, scan, block, and remove devices | DV-03 through DV-10 |
| Smart-home hubs, dongles, cloud providers, and rules | DV-11 through DV-14 |
| Data usage, backup, geofencing, multi-Guardian, and dual Wi-Fi | ST-04, ST-05, ST-07, ST-09, ST-11 |
| Notifications and custom rules | ST-12, ST-13 |
| Offline state | SYS-01 and per-screen offline states |

Reference files are in the sibling `gaurdian-admin-console` repository:

- `docs/product/screen-inventory.md`
- `docs/flows/onboarding.md`
- `docs/flows/circle.md`
- `docs/flows/sgx-device.md`
- `docs/flows/settings.md`
- `docs/api-requirements.md`
- `src/app/routes.ts`

### Readiness observations as of July 27, 2026

These observations identify what must be proven or completed before using the UI
as acceptance evidence:

- Circle, topology, alert, and device screens import `mockData`; pending-device
  approve/reject actions currently display success toasts without proving a
  Guardian state change.
- Circle chat is local component state, while call controls do not establish a
  live media session.
- Admin Console authentication uses Supabase. An offline demo must therefore
  prove a local authentication path or a deliberately supported, securely cached
  session.
- The Guardian `main` branch exposes a local admin API on port 8443, but its CORS
  configuration allows only `http://localhost:3000`. The deployed Admin Console
  origin and certificate/trust flow must be demonstrated.
- The Guardian `main` branch does not currently register Circle, message, voice,
  video, SOW file-transfer, or vault routes. Work on another branch counts only
  after the tested commit and image are identified.

These are acceptance-readiness gates, not substitutions for running the demos.

## Network profiles

The number in each profile is the number of Guardian nodes; administrator and
invitee client devices are additional.

| ID | Guardian topology | Internet | Minimum participants | Primary question |
| --- | --- | --- | --- | --- |
| N1 | One Guardian | Physically or logically disconnected | 1 admin + 2 invitees | Can all core local workflows operate without a cloud dependency? |
| N2 | One Guardian | Connected | 1 admin + 2 invitees | Which cloud-assisted features activate, and does local behavior remain correct? |
| N3 | Two Guardians on one local network | Disconnected | 1 admin per Guardian + invitees | Can Guardians discover, attest, form trust, and communicate locally? |
| N4 | Three or more Guardians using all claimed local transports | Disconnected | 2 admins + invitees | Do mixed transports, failover, partition, and rejoin work without Internet? |
| N5 | Two or more Guardians at one site | Connected | 2 admins + invitees | Is local traffic kept local while cloud features and sync remain available? |
| N6 | Two or more Guardians at separate sites | Connected | 2 admins + invitees | Do NAT, relay, remote membership, synchronization, and recovery work? |

N1 and N2 require a product decision about whether multiple human users can
participate through one Guardian. If every CoT member must own a Guardian, the
demo must say so explicitly and must not imply that client accounts are Guardian
peers.

## Transport qualification

Run the applicable connectivity use cases once for every transport claimed as
supported in the delivered hardware and software.

| Candidate | What must be specified before the demo | Minimum proof |
| --- | --- | --- |
| Ethernet | NICs, RJ-45 cabling, switch or router, addressing, discovery boundary | Link and address acquisition, Guardian/API reachability, secure session, unplug/replug recovery |
| Wi-Fi | Guardian as client or access point, SSID provisioning, supported bands, captive-portal behavior | Pair/connect, secure session, roaming or reconnect, wrong-password behavior |
| USB | Exact network-capable mode: USB Ethernet adapter, tethering, or USB gadget mode | Driver detection, interface/address, reachability, removal/reinsert recovery |
| Bluetooth/BLE | Classic, BLE point-to-point, or Bluetooth Mesh; pairing and key model | Real radio traffic, authenticated peer identity, payload or control-plane operation, range loss/recovery |
| Other mesh or WAN | Exact implementation, such as Zigbee, cellular, satellite, LoRaWAN, or overlay relay | Hardware path, security boundary, routing behavior, failure and fallback |

An ordinary USB hub does not create a network, and an RJ-45 connector does not
define a protocol. The bill of materials and network mode must name the adapters,
switches, radios, drivers, and addressing used. "RG-45" should be corrected to
"RJ-45" in demo material.

## Core reusable use cases

### ADM-01 — Connect an administrator locally

**Setup:** Use N1 with the upstream Internet link disabled. Start with an
unconfigured admin client on each claimed local transport.

**Actions:**

1. Connect the admin client to the Guardian's local management network.
2. Discover or enter the documented Guardian address.
3. Establish browser/server trust without bypassing certificate warnings.
4. Load the Admin Console and authenticate as the administrator.
5. View live Guardian identity, status, connection type, and last-seen data.

**Pass:** No public DNS, Supabase, CDN, identity provider, or other Internet
request is required. The console shows live data from the named Guardian, rejects
invalid credentials, and records the successful and failed access attempts.

**Evidence:** Cable/radio topology, route table, public-connectivity probe, packet
capture, screen recording, Guardian API log, and audit event.

### ADM-02 — Pair and re-pair a Guardian

**Actions:** Pair using the supported QR flow, repeat using the documented manual
proof flow, attempt an invalid or expired proof, then re-pair from Settings.

**Pass:** Valid pairing binds the intended administrator and Guardian; invalid,
expired, replayed, or mismatched proofs fail without partial state. Re-pairing
shows its effect on the previously paired Guardian and preserves or resets data
according to the documented policy.

### MEM-01 — Attempt access, approve one person, and deny another

**Setup:** Two invitees who are not members attempt to join the same CoT.

**Actions:**

1. Have each invitee use every supported offline invitation method: QR, short
   code, local link, or DID search.
2. Capture what each invitee sees before the request, while pending, after
   approval, and after denial or expiry.
3. Have the admin inspect verified identity details and approve invitee A.
4. Have the admin deny invitee B and record a reason if reasons are supported.
5. Retry access from both clients.

**Pass:** Invitee A receives only the granted CoT permissions. Invitee B cannot
read membership, messages, files, calls, topology, or shared security data. Both
decisions are durable and audited, and the pending state cannot be bypassed by
reusing an invitation.

**Open decision:** The current Admin Console specifies invitee acceptance and
admin removal, but not an admin approve/deny screen for pending human members.
Acceptance owners must decide whether joining is auto-approved on possession of
a signed invitation or requires explicit admin approval.

### COT-01 — Create a Circle of Trust

**Actions:** Create a named CoT, verify the owner's DID/role, add the approved
invitee, and inspect member presence and topology.

**Pass:** The CoT has a unique identity and signed membership state; only approved
members appear; all members converge on the same roster; creation and membership
events are audited; and no Internet is used in N1, N3, or N4.

### COT-02 — Remove and revoke a member

**Actions:** Remove an online member, attempt access with their existing session,
then repeat while that member is offline and reconnect them.

**Pass:** Access is revoked within the agreed propagation time, cached data and
keys follow the documented retention policy, offline revocation converges on
reconnect, and remaining members retain service.

### COM-01 — Text chat

**Actions:** Exchange messages among at least three users, including concurrent
messages, timestamps, read receipts, reconnect, and history reload.

**Pass:** Messages are encrypted in transit, delivered exactly once in order
consistent with the product contract, persisted and synchronized, and unavailable
to denied or removed members.

### COM-02 — File and image transfer

**Actions:** Send small and large allowed files, an image preview, a duplicate
name, an interrupted transfer, a disallowed type, and a file exceeding quota.

**Pass:** Progress, completion, retry/cancel, integrity, encryption, vault
integration, quota, and authorization are visible at both ends. The received
hash matches the source; partial or rejected content is not exposed.

### COM-03 — Voice call

**Actions:** Start peer-to-peer and group calls, join/leave, mute/unmute, deny
microphone permission, interrupt a link, and review call history.

**Pass:** Only CoT members join; audio is intelligible and encrypted; controls and
participant state agree across clients; failure/recovery behavior and call
history match the contract.

### COM-04 — Video call

**Actions:** Start peer-to-peer and group video, toggle camera, deny permission,
change network quality or transport, and rejoin after interruption.

**Pass:** Authorized participants receive encrypted audio/video; controls,
participant state, hardware acceleration evidence, degradation, and recovery are
observable.

### COM-05 — Communication authorization boundary

**Actions:** During active chat, file, voice, and video sessions, deny a pending
user and remove an accepted member.

**Pass:** The denied user never gains access. The removed member loses new
content and live media within the agreed revocation time without disrupting
remaining participants.

### NET-01 — Multi-Guardian discovery, trust, and topology

**Setup:** N3, then N4.

**Actions:** Boot Guardians in different orders, discover peers, complete mutual
attestation, form the CoT, inspect topology and connection labels, add a node, and
remove a node.

**Pass:** Every live node converges on authenticated identity, membership, policy,
and topology; an untrusted node remains quarantined; the Admin Console reflects
real links rather than mock topology.

### NET-02 — Transport failover, partition, and rejoin

**Actions:** Move an active CoT session between each supported transport, sever a
link, create activity on both sides of a partition, restore the link, and remove
upstream Internet while local links remain.

**Pass:** Failover follows the documented priority, no unauthorized downgrade
occurs, local service survives loss of Internet, and membership, messages, files,
revocation, policy, and audit records reconcile without silent loss.

### RES-01 — Restart and power-loss persistence

**Actions:** Restart the Admin Console, restart one Guardian, then simulate abrupt
power loss during a state-changing operation.

**Pass:** Identities, approved membership, policy, vault metadata, and audit
integrity recover as documented; incomplete operations are rolled back or safely
resumed; no denied or removed access is restored.

### DEV-01 — Approve, reject, score, scan, block, and remove a managed device

**Actions:** Discover two network devices, approve one and reject the other,
inspect security/privacy scores, run a scan, block and unblock traffic, then
remove the approved device.

**Pass:** Each UI action changes Guardian enforcement and durable inventory state;
traffic tests corroborate block/unblock; the rejected device stays isolated; scan
results and all decisions are audited.

## SOW capability acceptance

The reusable cases above cover the highest-risk interaction flows. The following
table ensures every latest-SOW line item has an explicit observable demo.

| ID | SOW deliverable | Minimum passing demonstration | UI reference |
| --- | --- | --- | --- |
| SOW-01 | Text chat / messaging | COM-01 and COM-05 pass, including history, timestamps, read receipts, attachments, encryption, persistence, and sync | NW-04 |
| SOW-02 | Voice calling | COM-03 and COM-05 pass for peer and group calls, participant controls, history, and encrypted transport | NW-05 |
| SOW-03 | Video calling | COM-04 and COM-05 pass, including camera controls and hardware-acceleration evidence | NW-05 |
| SOW-04 | In-Circle file transfer | COM-02 and COM-05 pass, including transfer status, synchronization, and vault integration | NW-04 and vault surface to be identified |
| SOW-05 | Circle container and invites | MEM-01, COT-01, and COT-02 pass with QR, signed tokens, DID/VC verification, and member administration | NW-01 through NW-13 |
| SOW-06 | Encrypted storage vault | Create folders; upload, download, preview, search, delete, and exhaust quota; prove encryption at rest, access isolation, and Circle-share linkage | UI surface to be identified |
| SOW-07 | Smart-home integration | Connect each contracted provider or an authorized equivalent test environment; discover hubs, ingest telemetry, execute a rule, and operate locally where claimed | DV-11 through DV-14 |
| SOW-08 | Live topology / mesh map | NET-01 and NET-02 pass with live node/link labels, geolocation, event history, and interaction | NW-07, HM-03 |
| SOW-09 | Geofencing | Create and edit a zone, cross both boundaries, prove entry/exit alerts and automation, then deny location permission | ST-07 |
| SOW-10 | Backup and restore | Create encrypted backup, alter state, restore it, reject corrupt/wrong-key backup, and verify keys/configuration/history | ST-05 |
| SOW-11 | Notifications and push | Toggle severity/category preferences, generate matching and nonmatching events, prove real-time and offline-queued delivery, and prevent duplicates | ST-12 |
| SOW-12 | Alert rules / automation | Create, edit, disable, trigger, and delete event-condition-action rules; prove action, lifecycle, and audit records | ST-13 |
| SOW-13 | Data usage | Generate known traffic per device/category, compare Guardian counters and UI, cross a quota, reset the schedule, and restart | ST-04 |
| SOW-14 | AI alert recommendation | Generate a known alert, show contextual recommendation and provenance, handle unavailable AI, and prove advice does not auto-execute without authorization | AL-07 |
| SOW-15 | Cylenium SSO / cloud sign-on | Complete OIDC login, token/session establishment, DID/account linking, logout/revocation, wrong-account and provider-unavailable cases; prove the local-auth fallback promised by the SOW | Login/auth flow |
| SOW-16 | Connected-device management and scoring | DEV-01 passes, including manual onboarding, firmware/ports/encryption/CVE scan stages, report, approve/reject, and enforcement | DV-01 through DV-10 |
| SOW-17 | Container installation and hardware demo | Install a clean image on the target host, pass health checks, use SE050, apply a real firewall change with `CAP_NET_ADMIN`, persist data, restart, and uninstall or roll back | Operational demo |
| SOW-18 | Container architecture and tooling | Reproduce AMD64 and ARM64 builds, inspect minimal runtime contents, run Compose and Kubernetes profiles, verify host networking/capabilities/volumes/environment paths, and publish image digests/SBOM | Operational evidence |

If a contracted provider, transport, hardware root of trust, architecture, or
workflow is replaced with a simulator, the run is blocked unless Cervais and
CyberZeus have jointly authorized that substitution in writing.

## Scenario applicability matrix

`R` means required, `C` means required when the capability is claimed for that
profile, and `—` means not applicable. Execute every `R` cell and every `C` cell
that is part of the delivered claim.

| Use case group | N1 | N2 | N3 | N4 | N5 | N6 |
| --- | --- | --- | --- | --- | --- | --- |
| ADM-01 local admin connection | R | R | R | R | R | R |
| ADM-02 pairing and re-pairing | R | R | R | R | R | R |
| MEM-01 human approval/denial | R | R | R | R | R | R |
| COT-01/COT-02 membership lifecycle | R | R | R | R | R | R |
| COM-01 text | R | R | R | R | R | R |
| COM-02 file | R | R | R | R | R | R |
| COM-03 voice | R | R | R | R | R | R |
| COM-04 video | R | R | R | R | R | R |
| NET-01 multi-Guardian trust/topology | — | — | R | R | R | R |
| NET-02 transport/failure/rejoin | C | R | R | R | R | R |
| RES-01 restart/persistence | R | R | R | R | R | R |
| DEV-01 managed-device controls | R | R | R | R | R | R |
| SOW-06 vault | R | R | R | R | R | R |
| SOW-07 smart home | C | R | C | C | R | R |
| SOW-09 geofencing | C | R | C | C | R | R |
| SOW-11 push delivery | Local notification only | R | Local notification only | Local notification only | R | R |
| SOW-14 AI recommendation | Local AI if claimed | R | Local AI if claimed | Local AI if claimed | R | R |
| SOW-15 cloud SSO | Secure local fallback | R | Secure local fallback | Secure local fallback | R | R |
| SOW-17/SOW-18 container delivery | R | R | R | R | R | R |

For N2, N5, and N6, repeat the active workflow while disconnecting and restoring
Internet. The result must distinguish expected degradation of Internet-only
features from failure of local security, CoT, and communication functions.

## Decisions required before scheduling acceptance

1. **Human membership model:** Does an invite grant membership immediately when
   accepted, or must an administrator separately approve it? Can several users
   participate through one Guardian?
2. **Offline Admin Console:** Is it served by the Guardian, installed as a PWA,
   or hosted elsewhere? How are local URL discovery, TLS trust, login, password
   recovery, and first-admin bootstrap performed without Internet?
3. **Supported transports:** Which exact Ethernet, Wi-Fi, USB networking,
   Bluetooth/BLE, mesh, cellular, or satellite modes are in the delivered bill of
   materials and acceptance claim?
4. **Offline invitations:** Which invitation methods work without public DNS,
   email, SMS, or cloud DID lookup, and how do they expire or resist replay?
5. **Communication participants:** Are chat, file, voice, and video sessions
   client-to-client through one Guardian, Guardian-to-Guardian, or both?
6. **Vault meaning:** The SOW says "cloud storage vault" and "device-hosted
   storage." Identify the authoritative storage location, sync model, encryption
   keys, quotas, and offline behavior.
7. **Online path:** For same-site and remote Guardians, identify direct, relay,
   cloud, NAT traversal, and metadata paths, including what remains available
   when Internet fails.
8. **Performance thresholds:** Agree on participant count, file sizes, transfer
   rate, call quality, failover time, revocation propagation time, topology
   convergence, and recovery time.
9. **Target hardware:** Name AMD64/ARM64 hosts, SE050 connection, radios,
   adapters, kernel, container runtime, and Kubernetes distribution.
10. **Evidence and exceptions:** Name the acceptance authority, evidence
    retention location, severity policy, retest rule, and who may approve a
    simulator or partial substitution.

No unresolved item should be silently decided during the demo. Record the agreed
answer in this document or a linked, versioned acceptance decision before the
run.

## Acceptance Baseline Agreement

By signing below, Cervais and CyberZeus agree that these use cases, network
profiles, evidence requirements, and pass conditions govern acceptance of the
[Phase 2 Extension deliverables](../README.md). Changes or exceptions require
written agreement by both parties.

| Organization | Authorized representative | Title | Signature | Date |
| --- | --- | --- | --- | --- |
| Cervais |  |  |  |  |
| CyberZeus |  |  |  |  |
