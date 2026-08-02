# **Information Architecture**

## **Table of Contents**

1. [Overview](https://claude.ai/chat/4c605db0-7765-4f26-ab7e-6c4083d97133#1-overview)
2. [Navigation Structure](https://claude.ai/chat/4c605db0-7765-4f26-ab7e-6c4083d97133#2-navigation-structure)
3. [Full App Sitemap](https://claude.ai/chat/4c605db0-7765-4f26-ab7e-6c4083d97133#3-full-app-sitemap)
4. [Section Deep Dives](https://claude.ai/chat/4c605db0-7765-4f26-ab7e-6c4083d97133#4-section-deep-dives)
 * 4.1 [Onboarding](https://claude.ai/chat/4c605db0-7765-4f26-ab7e-6c4083d97133#41-onboarding)
 * 4.2 [Home (Dashboard)](https://claude.ai/chat/4c605db0-7765-4f26-ab7e-6c4083d97133#42-home-dashboard)
 * 4.3 [Alerts](https://claude.ai/chat/4c605db0-7765-4f26-ab7e-6c4083d97133#43-alerts)
 * 4.4 [Network (Circles)](https://claude.ai/chat/4c605db0-7765-4f26-ab7e-6c4083d97133#44-network-circles)
 * 4.5 [Devices](https://claude.ai/chat/4c605db0-7765-4f26-ab7e-6c4083d97133#45-devices)
 * 4.6 [Settings](https://claude.ai/chat/4c605db0-7765-4f26-ab7e-6c4083d97133#46-settings)
5. [Screen Hierarchy Map](https://claude.ai/chat/4c605db0-7765-4f26-ab7e-6c4083d97133#5-screen-hierarchy-map)
6. [Navigation Flow Between Sections](https://claude.ai/chat/4c605db0-7765-4f26-ab7e-6c4083d97133#6-navigation-flow-between-sections)
7. [Modal & Overlay Architecture](https://claude.ai/chat/4c605db0-7765-4f26-ab7e-6c4083d97133#7-modal--overlay-architecture)
8. [State Architecture](https://claude.ai/chat/4c605db0-7765-4f26-ab7e-6c4083d97133#8-state-architecture)
9. [IA Design Decisions](https://claude.ai/chat/4c605db0-7765-4f26-ab7e-6c4083d97133#9-ia-design-decisions)

---

## **1\. Overview**

The SG-X Guardian app is organized into **6 functional zones**:

| Zone | Access | Description |
| ----- | ----- | ----- |
| **Onboarding** | First run only | Hardware pairing, account setup, first Circle creation |
| **Home** | Bottom nav tab 1 | Guardian health, alert summary, quick actions |
| **Alerts** | Bottom nav tab 2 | Full alert management, AI threat intelligence |
| **Network** | Bottom nav tab 3 | Circle of Trust — team, chat, calls, topology |
| **Devices** | Bottom nav tab 4 | Connected device management, smart home integration |
| **Settings** | Bottom nav tab 5 | Guardian config, account, DID, preferences |

The app follows a **flat navigation model** — all 5 main sections are always one tap away via the persistent bottom navigation bar. Depth within sections is kept to a maximum of **3 levels** to ensure field usability.

### **Navigation Depth Rules**

| Level | Description | Example |
| ----- | ----- | ----- |
| **L0** | Bottom nav (always visible) | Home, Alerts, Network, Devices, Settings |
| **L1** | Section root screen | Alerts list, Circles list, Devices list |
| **L2** | Detail screen | Alert detail, Circle detail, Device detail |
| **L3** | Sub-action screen / modal | Invite member, Add device form, Smart Home modal |

**Rule:** No user action should require more than 3 taps from the bottom nav to complete.

---

## **2\. Navigation Structure**

### **Bottom Navigation Bar**

┌──────────────────────────────────────────────────────┐
│ │
│ │
│ Home Alerts Network Devices Settings │
│ (2) │
│ badge count │
└──────────────────────────────────────────────────────┘

### **Tab Rename Rationale**

| Old Name | New Name | Reason |
| ----- | ----- | ----- |
| Dashboard | **Home** | More intuitive — universal convention for app entry point |
| Alerts | **Alerts** | Kept — clear, accurate, universally understood |
| Circles | **Network** | Better reflects the underlying concept (Circle of Trust \= trusted network) |
| Devices | **Devices** | Kept — clear and accurate |
| Settings | **Settings** | Kept — universal convention |

### **Badge Rules**

| Tab | Badge Condition | Badge Content |
| ----- | ----- | ----- |
| Alerts | Any unread HIGH or MEDIUM alerts | Count of unread alerts |
| Network | Any pending Circle invites | Count of pending invites |
| Devices | Any pending device approvals | Count of pending devices |
| Home | Never | — |
| Settings | Never | — |

---

## **3\. Full App Sitemap**

graph TD
 APP(\[SG-X Guardian App\])

 APP \--\> OB\[Onboarding\]
 APP \--\> HM\[Home\]
 APP \--\> AL\[Alerts\]
 APP \--\> NW\[Network\]
 APP \--\> DV\[Devices\]
 APP \--\> ST\[Settings\]

 %% Onboarding
 OB \--\> OB1\[Welcome Screen\]
 OB1 \--\> OB2\[Hardware Pairing\]
 OB2 \--\> OB3\[Connection Verification\]
 OB3 \--\> OB4\[Account Setup / Login\]
 OB4 \--\> OB5\[DID Introduction\]
 OB5 \--\> OB6\[Create First Circle\]
 OB6 \--\> OB7\[Onboarding Complete\]
 OB7 \--\> HM

 %% Home
 HM \--\> HM1\[Dashboard\]
 HM1 \--\> HM2\[Guardian Detail\]
 HM1 \--\> AL
 HM1 \--\> NW

 %% Alerts
 AL \--\> AL1\[Active Alerts List\]
 AL \--\> AL2\[Archived Alerts List\]
 AL1 \--\> AL3\[Alert Detail\]
 AL2 \--\> AL3
 AL3 \--\> AL4\[Affected Device Detail\]
 AL3 \--\> AL5\[Remediation Actions\]

 %% Network
 NW \--\> NW1\[Circles List\]
 NW1 \--\> NW2\[Create Circle\]
 NW1 \--\> NW3\[Circle Detail\]
 NW3 \--\> NW4\[Chat Tab\]
 NW3 \--\> NW5\[Calls Tab\]
 NW3 \--\> NW6\[Members Tab\]
 NW3 \--\> NW7\[Topology Tab\]
 NW6 \--\> NW8\[Invite Member\]
 NW8 \--\> NW9\[Search DIDs\]
 NW8 \--\> NW10\[Share Link\]
 NW8 \--\> NW11\[QR Code\]

 %% Devices
 DV \--\> DV1\[Devices List\]
 DV1 \--\> DV2\[Device Detail\]
 DV2 \--\> DV3\[Security Scan Results\]
 DV2 \--\> DV4\[Vulnerability Detail\]
 DV1 \--\> DV5\[Add Device\]
 DV1 \--\> DV6\[Smart Home Integration\]
 DV6 \--\> DV7\[Hubs Tab\]
 DV6 \--\> DV8\[Dongles Tab\]
 DV6 \--\> DV9\[Cloud Services Tab\]
 DV6 \--\> DV10\[Automation Rules Tab\]
 DV1 \--\> DV11\[Pending Approvals\]
 DV1 \--\> DV12\[Service Access\]

 %% Settings
 ST \--\> ST1\[Settings Root\]
 ST1 \--\> ST2\[Guardian Info \+ DID\]
 ST1 \--\> ST3\[Profile\]
 ST1 \--\> ST4\[Data Usage\]
 ST1 \--\> ST5\[Backup and Restore\]
 ST1 \--\> ST6\[Network Topology\]
 ST1 \--\> ST7\[Location and Geofencing\]
 ST1 \--\> ST8\[Device Pairing\]
 ST1 \--\> ST9\[Manage Guardians\]
 ST1 \--\> ST10\[Device Settings\]
 ST1 \--\> ST11\[Dual WiFi Mode\]
 ST1 \--\> ST12\[Notification Preferences\]
 ST1 \--\> ST13\[Custom Alert Rules\]
 ST1 \--\> ST14\[Quick Start Guide\]
 ST1 \--\> ST15\[App Version\]
 ST1 \--\> ST16\[Logout\]

---

## **4\. Section Deep Dives**

### **4.1 Onboarding**

Onboarding is a **one-time linear flow** triggered on first app launch. It guides the user through hardware pairing, account creation, DID introduction, and first Circle setup. Once completed, the user lands on the Home dashboard and onboarding is never shown again.

flowchart LR
 A(\[App First Launch\]) \--\> B\[Welcome Screen\\nBrand intro \+ value prop\]
 B \--\> C\[Hardware Pairing\\nScan QR code OR\\nenter serial number\]
 C \--\> D{Pairing\\nSuccessful?}
 D \-- Yes \--\> E\[Connection Verified\\nGuardian found \]
 D \-- No \--\> F\[Retry / Help screen\]
 F \--\> C
 E \--\> G\[Account Setup\\nLogin or Create account\]
 G \--\> H\[DID Introduction\\nPlain language explainer\\nCopy your DID\]
 H \--\> I{Skip or\\nCreate Circle?}
 I \-- Create \--\> J\[Create First Circle\\nName \+ description\]
 I \-- Skip \--\> K\[Dashboard\]
 J \--\> K(\[Home Dashboard\\nOnboarding complete \])

**Key screens:** 7 screens (Welcome, Pairing, Verify, Account, DID, Create Circle, Complete) **Navigation type:** Linear wizard — no bottom nav visible during onboarding **Exit point:** Home Dashboard

---

### **4.2 Home (Dashboard)**

The Home section is a **single screen** with contextual deep links into Alerts and Network. It is the app's entry point on every launch after onboarding.

flowchart TD
 A\[Home Dashboard\] \--\> B\[Guardian Device Card\\nStatus \+ Battery \+ Signal \+ Peers\]
 A \--\> C\[Security Health Score\\n0-100 ring visualization\]
 A \--\> D\[Active Alerts Summary\\nCount by severity \+ View All link\]
 A \--\> E\[Quick Actions Tray\\nScan / View Topology / Archive All\]
 A \--\> F\[Your Circles Summary\\nCircle count \+ online members\]

 D \-- tap View All \--\> AL\[Alerts Section\]
 E \-- tap Topology \--\> NW7\[Network Topology View\]
 F \-- tap circle \--\> NW3\[Circle Detail\]
 B \-- tap card \--\> GD\[Guardian Detail\\nFull device info \+ firmware \+ uptime\]

**Key screens:** 2 screens (Dashboard, Guardian Detail) **Navigation type:** Hub — links out to other sections **Persistent elements:** Bottom nav, Guardian status indicator in header

---

### **4.3 Alerts**

The Alerts section follows a **list → detail** pattern with two parallel lists (Active and Archived) and a shared detail view.

flowchart TD
 A\[Alerts Root\] \--\> B\[AI Threat Intelligence Panel\\nThreat Score \+ 24h count \+ Blocked \+ Quarantined\]
 A \--\> C{View Mode}
 C \-- Active \--\> D\[Active Alerts List\\nFilter by severity / status / type\]
 C \-- Archived \--\> E\[Archived Alerts List\\nFilter by severity / status / type\]

 D \--\> F\[Alert Detail\\nEvent type \+ Device \+ IP \+ Protocol\\nSeverity \+ Timestamp \+ Status\]
 E \--\> F

 F \--\> G\[AI Recommendation\\nWhat happened \+ what to do\]
 F \--\> H\[Remediation Actions\\nArchive / Block Device / Run Scan\]
 F \--\> I\[Affected Device Quick Link\\nJumps to Device Detail\]

 D \--\> J{Bulk Select Mode}
 J \--\> K\[Select All\]
 J \--\> L\[Archive Selected\]
 J \--\> M\[Delete Selected\]

**Key screens:** 5 screens (Root/Active List, Archived List, Alert Detail, AI Recommendation panel, Bulk Select mode) **Navigation type:** List → detail with back navigation **Badge source:** Unread HIGH \+ MEDIUM alert count

---

### **4.4 Network (Circles)**

The Network section is the most **hierarchically deep** section — Circle detail has 4 tabs (Chat, Calls, Members, Topology) and the invite flow has 3 methods.

flowchart TD
 A\[Network Root\\nCircles List\] \--\> B\[Create Circle\\nName \+ Description\]
 B \--\> B1\[Certificate Authority Generation\\nLoading state\]
 B1 \--\> B2\[Circle Created \\nLands on Circle Detail\]

 A \--\> C\[Circle Detail\]
 C \--\> D\[Chat Tab\\nSecure P2P messages\]
 C \--\> E\[Calls Tab\\nVoice \+ Video call options\\nCall history\]
 C \--\> F\[Members Tab\\nMember list \+ online status\]
 C \--\> G\[Topology Tab NEW\\nVisual graph of peers\]

 F \--\> H\[Invite Member Modal\]
 H \--\> I\[Search DIDs\\nDecentralized Identifier lookup\]
 H \--\> J\[Share Link\\nInvite code \+ shareable URL\\nRecord invitation by email\]
 H \--\> K\[QR Code\\nScannable QR \+ share button\]

 F \--\> L\[Member Detail NEW\\nDID \+ connection type \+ last seen\]
 F \--\> M\[Remove Member\\nConfirmation dialog\]

**Key screens:** 10 screens (Circles List, Create Circle, Loading, Circle Detail ×4 tabs, Invite ×3 methods, Member Detail) **Navigation type:** List → tabbed detail → modal overlays **Badge source:** Pending Circle invites

---

### **4.5 Devices**

The Devices section is the **most feature-rich** section, containing device management, smart home integration, and the Guardian Simulator replacement.

flowchart TD
 A\[Devices Root\\nAll Devices List\] \--\> B{Filter Tabs}
 B \--\> B1\[All Devices\]
 B \--\> B2\[Regular\]
 B \--\> B3\[Drones\]
 B \--\> B4\[Smart Home\]
 B \--\> B5\[Pending\]
 B \--\> B6\[Service Access\]

 A \--\> C\[Scan Network\\nAuto-discovery\]
 A \--\> D\[Add Device Manually\\nDevice Name \+ Type \+ Connection\\nMAC \+ IP \+ Manufacturer \+ OS\]

 B1 \--\> E\[Device Detail\]
 E \--\> E1\[Device Info\\nManufacturer \+ Model \+ Protocol\\nMAC \+ IP \+ Firmware\]
 E \--\> E2\[Security Score \+ Privacy Score \+ Vuln Count\]
 E \--\> E3\[Security Features\\nEncryption \+ Auto-update \+ Connectivity\]
 E \--\> E4\[Vulnerability Detail\\nList \+ Recommendations\]
 E \--\> E5\[Guardian Monitoring Toggle\]
 E \--\> E6\[Actions\\nRun Security Scan\\nBlock from Network\\nRemove Device\]

 A \--\> F\[Smart Home Integration Modal\]
 F \--\> F1\[Hubs Tab\\nDiscover \+ Add smart home hubs\]
 F \--\> F2\[Dongles Tab\\nUSB dongles management\]
 F \--\> F3\[Cloud Services Tab\\nRing \+ Nest \+ Wyze \+ Ecobee\\nTP-Link \+ Arlo \+ more\]
 F \--\> F4\[Automation Rules Tab\\nSecurity Triggers \+ Schedules\\nGeofencing \+ Sensors\]

 B5 \--\> G\[Pending Approval Detail\\nApprove or Reject device\]

**Key screens:** 12 screens (Devices List, Device Detail ×4 views, Add Device, Scan Network, Smart Home ×4 tabs, Pending Approval) **Navigation type:** Tabbed list → detail → modal overlays **Badge source:** Pending device approval count

---

### **4.6 Settings**

Settings follows a **grouped list → detail** pattern. All items are organized into 5 logical groups.

flowchart TD
 A\[Settings Root\] \--\> B\[Guardian Section\\nGuardian selector card\]
 B \--\> B1\[DID Display \+ Copy\]
 B \--\> B2\[Connection Type Auto-detected\]
 B \--\> B3\[Signal Strength\]

 A \--\> C\[Account Group\]
 C \--\> C1\[Profile\\nName \+ Email \+ Avatar\]
 C \--\> C2\[Data Usage\]
 C \--\> C3\[Backup and Restore\]

 A \--\> D\[Network Group\]
 D \--\> D1\[Network Topology View\]

 A \--\> E\[Physical Security Group\]
 E \--\> E1\[Location and Geofencing\]

 A \--\> F\[Device Group\]
 F \--\> F1\[Device Pairing\]
 F \--\> F2\[Manage Guardians\]
 F \--\> F3\[Device Settings\]
 F \--\> F4\[Dual WiFi Mode\]

 A \--\> G\[Notifications Group\]
 G \--\> G1\[Notification Preferences\]
 G \--\> G2\[Custom Alert Rules\]

 A \--\> H\[Help and Support Group\]
 H \--\> H1\[Quick Start Guide\]
 H \--\> H2\[App Version\]

 A \--\> I\[Logout\\nConfirmation dialog\]

**Key screens:** 16 screens (Settings root \+ 15 detail screens) **Navigation type:** Grouped list → push navigation (no tabs)

---

## **5\. Screen Hierarchy Map**

graph LR
 subgraph L0 \[L0 — Always Visible\]
 NAV\[Bottom Navigation Bar\]
 end

 subgraph L1 \[L1 — Section Roots\]
 HM\[Home\]
 AL\[Alerts\]
 NW\[Network\]
 DV\[Devices\]
 ST\[Settings\]
 end

 subgraph L2 \[L2 — Detail Screens\]
 GD\[Guardian Detail\]
 AD\[Alert Detail\]
 CD\[Circle Detail\]
 DD\[Device Detail\]
 SD\[Settings Detail\]
 end

 subgraph L3 \[L3 — Sub-screens / Modals\]
 AR\[AI Recommendation\]
 IM\[Invite Modal\]
 SH\[Smart Home Modal\]
 VD\[Vulnerability Detail\]
 DP\[Device Pairing\]
 end

 NAV \--\> L1
 HM \--\> GD
 AL \--\> AD
 NW \--\> CD
 DV \--\> DD
 ST \--\> SD
 AD \--\> AR
 CD \--\> IM
 DV \--\> SH
 DD \--\> VD
 ST \--\> DP

---

## **6\. Navigation Flow Between Sections**

The app supports **cross-section deep links** — screens in one section can link directly into another section's detail view.

flowchart LR
 HM\[Home Dashboard\] \-- View All Alerts \--\> AL\[Alerts List\]
 HM\[Home Dashboard\] \-- Tap Circle \--\> CD\[Circle Detail\]
 HM\[Home Dashboard\] \-- View Topology \--\> NT\[Network Topology\]
 AL\[Alert Detail\] \-- Affected Device \--\> DD\[Device Detail\]
 DD\[Device Detail\] \-- Run Scan Results \--\> AL\[Alerts List\]
 ST\[Settings\] \-- Network Topology \--\> NT\[Network Topology\]
 OB\[Onboarding Complete\] \-- Lands on \--\> HM

---

## **7\. Modal & Overlay Architecture**

The following interactions are presented as **bottom sheet modals** (slide up from bottom) rather than full navigation pushes:

| Modal | Trigger | Parent Screen |
| ----- | ----- | ----- |
| Invite Member | Tap "Invite Member" in Members tab | Circle Detail |
| Add Device | Tap "+ Add Manually" | Devices List |
| Smart Home Integration | Tap "Smart Home Integration" banner | Devices List |
| Guardian Simulator | **Removed from production** | — |
| Alert Remediation Actions | Tap action button in Alert Detail | Alert Detail |
| Remove Member confirmation | Tap remove icon in Members tab | Circle Detail |
| Logout confirmation | Tap Logout in Settings | Settings Root |
| Block Device confirmation | Tap "Block from Network" | Device Detail |
| Remove Device confirmation | Tap "Remove Device" | Device Detail |

### **Modal Behavior Rules**

* All modals use **slide-up bottom sheet** animation
* Modals can be dismissed by **swipe down** or tapping the backdrop
* Destructive action modals (Remove, Block, Logout, Delete) require an **explicit confirmation tap** — they cannot be dismissed by backdrop tap
* Modals have a **drag handle** indicator at the top
* Full-screen modals (Smart Home Integration, QR Code) use a **back arrow** header instead of bottom sheet

---

## **8\. State Architecture**

Every screen in the app must handle 5 possible states. These are defined here at the IA level and will be designed in Figma for every screen.

stateDiagram-v2
 \[\*\] \--\> Loading : Screen opens
 Loading \--\> Populated : Data loaded successfully
 Loading \--\> Error : Network/API error
 Loading \--\> Empty : No data exists
 Populated \--\> Empty : User deletes all items
 Populated \--\> Error : Live data fetch fails
 Error \--\> Loading : User taps retry
 Empty \--\> Populated : User creates first item

| State | Description | Example |
| ----- | ----- | ----- |
| **Loading** | Data is being fetched | Skeleton cards on Devices list |
| **Populated** | Data loaded, normal use | Alert list with 3 events |
| **Empty** | No data exists yet | "No circles yet" on Network screen |
| **Error** | Guardian unreachable or API failure | "Cannot connect to Guardian" banner |
| **Offline** | App knows Guardian is disconnected | Persistent warning bar on all screens |

### **Offline State Behavior**

When the Guardian device is unreachable, the app must:

1. Show a persistent **red/amber warning bar** at the top of every screen: *"Guardian offline — last seen \[timestamp\]"*
2. Show **stale data** (last known state) rather than empty screens
3. **Disable** all action buttons that require a live connection (Scan, Block, Archive)
4. **Allow** read-only browsing of cached data

---

## **9\. IA Design Decisions**

### **Decision 1 — Rename "Circles" to "Network"**

**Rationale:** "Circles" is a product-specific term that new users may not understand. "Network" is immediately intuitive — it communicates that this section is about who you're connected to and how your trusted network is organized. The concept of "Circles" is retained as the entity name within the section.

### **Decision 2 — Onboarding as a Separate Pre-Auth Zone**

**Rationale:** Onboarding must be completely isolated from the main navigation. Showing the bottom nav during onboarding would confuse users into navigating away mid-setup. Onboarding is a wizard — linear, focused, exits only on completion or explicit skip.

### **Decision 3 — Maximum 3-Level Depth**

**Rationale:** Field engineers use this app in physical environments, often one-handed, in split attention contexts. A 4-level hierarchy means 4+ taps to get back to safety. Every section is designed to L3 maximum, and modals are used to avoid pushing depth.

### **Decision 4 — Cross-Section Deep Links**

**Rationale:** Security workflows don't respect section boundaries. A field engineer investigating an alert needs to jump to the affected device's detail view instantly — not navigate back to Home, then Devices, then find the device. Deep links between sections support real-world security workflows.

### **Decision 5 — Guardian Simulator Removed**

**Rationale:** The Guardian Simulator is a development and QA tool. Its presence in the production UI adds cognitive noise, creates accidental tap risks, and undermines the app's professional credibility. It is removed entirely from the production IA.

### **Decision 6 — Topology View Added to Network Section**

**Rationale:** Network topology (visual graph of Circle peers) is most contextually relevant when viewed alongside Circle membership. Adding it as a tab within Circle Detail puts the topology visualization exactly where users expect it — next to the members it represents.