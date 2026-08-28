# **Product Brief**

## **1\. Executive Summary**

Cervais, Inc. is a U.S.-based critical infrastructure cybersecurity company whose flagship hardware product, the **SG-X Gateway Device**, protects industrial edge environments across energy, healthcare, federal/defense, transportation, manufacturing, and agriculture sectors. The device is managed via a companion application called **SG-X Guardian**.

The current SG-X Guardian application was built as a functional proof-of-concept using the Base44 platform. While it successfully demonstrates the product's capabilities, it lacks the level of user experience, visual design quality, and interface polish required for a commercial-grade product that will be used by security professionals in high-stakes environments.

**Lightning Leap Analytics has been engaged to redesign the SG-X Guardian application from the ground up** — delivering a production-quality, brand-aligned, mobile browser-based web application that elevates the user experience while maintaining full functional parity with the existing system and incorporating new features identified through analysis.

The redesigned application will be delivered as a **Figma design system and high-fidelity prototype** followed by a **developer-ready handoff package** for the Backend engineering team.

---

## **2\. Company & Product Background**

### **2.1 About Cervais**

| Attribute | Detail |
| ----- | ----- |
| **Company** | Cervais, Inc. |
| **Headquarters** | United States |
| **Founder & CEO** | Dr. James Austin |
| **Focus** | Critical infrastructure cybersecurity |
| **Mission** | Redefine cybersecurity for high-risk edge environments |
| **Website** | cervais.com |

Cervais operates at the intersection of IT and OT (Operational Technology) security — a sector experiencing accelerating threat growth due to convergence of industrial systems with internet-connected infrastructure. Their target verticals include:

* Energy (generation, transmission, grid operations)
* Healthcare
* Federal & Defense
* Transportation
* Space
* Manufacturing
* Supply Chain
* Agriculture

### **2.2 Core Product Portfolio**

| Product | Type | Description |
| ----- | ----- | ----- |
| **SG-X Gateway Device** | Hardware | Edge security appliance deployed on-premise at industrial sites |
| **Cylenium Cloud** | SaaS Platform | Cloud platform for unified asset visibility, access control, threat detection, compliance |
| **SG-X Guardian** | Mobile Web App | Companion application for managing and monitoring the SG-X device |

### **2.3 The SG-X Guardian System — Technical Overview**

The SG-X Guardian is not just a UI layer — it sits on top of a sophisticated distributed security system:

| Component | Technology | Purpose |
| ----- | ----- | ----- |
| **Core Daemon** | Rust (`sgx-guardian`) | Memory-safe, high-performance security daemon running on the device |
| **P2P Communication** | gRPC over mTLS | Encrypted, mutually-authenticated peer-to-peer communication |
| **Cryptography** | ECDSA P-256 | Device identity, policy signing, attestation |
| **Peer Discovery** | mDNS | Zero-configuration discovery on local networks |
| **Policy Enforcement** | nftables | Kernel-level L3/L4 network packet filtering |
| **Identity System** | DID (Decentralized Identifiers) | Privacy-preserving authentication without revealing personal information |
| **Policy Format** | YAML (UEP v1.0) | Human-readable security policy definitions |
| **Telemetry** | Prometheus-compatible | Metrics exposure for operational monitoring |
| **Audit Logging** | Structured tamper-evident logs | Compliance and forensics |

**The Circle of Trust** is the core concept: a cryptographically verified peer group of SG-X devices that mutually attest each other's identity and synchronize security policies. The mobile app is the primary interface for managing this trust fabric.

### **2.4 Phase Context**

The backend system is being built by the Backend engineering team in **Phase 1** (Oct–Dec 2025), delivering:

* Circle of Trust formation and maintenance
* Cryptographic policy distribution
* L3/L4 network enforcement
* Operational observability
* Production-ready `.deb`/`.rpm` packaging

The mobile application redesign (this engagement) runs in parallel and feeds directly into Phase 1 delivery and beyond.

---

## **3\. Problem Statement**

### **3.1 The Core Problem**

The existing SG-X Guardian application was built quickly as a functional prototype. While it works, it creates three significant business and user problems:

**Problem 1 — Brand Misalignment** The current app uses a teal/cyan color scheme and generic dark UI that does not match Cervais's established brand identity (black backgrounds, purple/violet accents, clean bold typography). This creates a disjointed experience between the marketing website and the product.

**Problem 2 — Poor User Experience for High-Stakes Contexts** Security professionals using this app are often working in the field, under pressure, managing real threats. The current interface requires too much cognitive load — information is dense, actions are not obvious, and the dashboard does not communicate security status at a glance.

**Problem 3 — Missing Critical Features** The current app lacks several features that are essential for production use:

* No guided onboarding / hardware pairing flow
* No real-time network topology visualization
* No policy viewer for active device policies
* No multi-Guardian device switching
* No compliance posture summary
* Guardian Simulator (a dev tool) is exposed in the production UI

### **3.2 The Opportunity**

A redesigned, polished, brand-aligned application positions Cervais to:

* Demonstrate product maturity to enterprise and federal customers
* Reduce friction for field engineers managing Guardian devices
* Differentiate from competitors (Claroty, Dragos, Nozomi Networks, Forescout) who offer web-only dashboards with no mobile-first experience
* Build a strong foundation for future feature expansion (fleet management, policy editor, compliance reporting)

---

## **4\. Product Vision**

**"A security command center in your pocket — so every field engineer always knows the health of their Guardian, can act on threats instantly, and never has to wonder if their network is protected."**

The redesigned SG-X Guardian app will be:

* **Calm under pressure** — Critical information surfaces immediately. Noise is reduced. The interface earns trust by being predictable and reliable.
* **Action-oriented** — Every screen answers the question: "What do I need to do right now?"
* **Technically honest** — The app respects that its users are security professionals. It shows real data, real statuses, real cryptographic details — without hiding behind oversimplification.
* **Brand-true** — Every pixel aligns with the Cervais identity: dark, sharp, purposeful, premium.
* **Built to scale** — The architecture of the design supports future features without requiring a redesign.

---

## **5\. Goals & Success Metrics**

### **5.1 Design Goals**

| Goal | Description |
| ----- | ----- |
| **G1 — Brand Alignment** | 100% visual consistency with cervais.framer.website brand language |
| **G2 — Clarity** | Dashboard communicates Guardian health status in under 3 seconds |
| **G3 — Action Efficiency** | Alert triage (view → understand → act) in under 4 taps |
| **G4 — Completeness** | Full functional parity with existing app \+ all new features in scope |
| **G5 — Accessibility** | WCAG AA compliance across all screens |
| **G6 — Handoff Quality** | Zero ambiguity in Figma handoff — every state, component, and spacing documented |

### **5.2 Success Metrics (Post-Launch, to track with Cervais)**

| Metric | Target |
| ----- | ----- |
| Time to understand Guardian status on Dashboard | \< 5 seconds |
| Alert triage flow completion rate | \> 90% |
| Onboarding flow completion rate (new device setup) | \> 85% |
| WCAG AA compliance score | 100% |
| Developer handoff revision requests | \< 2 rounds |
| Client satisfaction score | 9/10 |

---

## **6\. Scope of Work**

### **6.1 In Scope**

| Deliverable | Description |
| ----- | ----- |
| **Product Brief** (this document) | Full detailed \+ one-pager versions |
| **User Personas** | 2 detailed personas |
| **Information Architecture** | Full sitemap with Mermaid diagrams |
| **Screen Inventory** | Complete table of all screens (existing \+ new) |
| **User Flows** | 6 detailed user flow documents with Mermaid diagrams |
| **Design System** | Color tokens, typography, spacing, component definitions in Figma |
| **High-Fidelity Mobile Screens** | All screens designed in Figma at 390px width (iPhone 14 base) |
| **Interaction States** | Loading, empty, error, success states for all major screens |
| **Developer Handoff Package** | Screen annotations, component specs, API-to-UI mapping |
| **Figma Handoff Guide** | How to navigate and use the Figma file |

### **6.2 Platform Specification**

| Attribute | Specification |
| ----- | ----- |
| **Type** | Mobile browser-based web app (PWA-compatible) |
| **Distribution** | Not in App Store / Play Store — accessed via browser URL |
| **Primary Target** | iOS Safari, Android Chrome |
| **Base Design Width** | 390px (iPhone 14\) |
| **Responsive Range** | 360px – 430px mobile viewport |
| **Accessibility** | WCAG AA |

---

## **7\. Target Users**

### **7.1 Primary User — Field Security Engineer**

The **Field Security Engineer** is the primary user of the SG-X Guardian mobile app. This person is responsible for deploying, configuring, and monitoring SG-X devices at industrial sites.

**Context of use:**

* Often working on-site at industrial facilities (power plants, factories, data centers)
* Checking device status while walking a floor or during an incident response
* Needs fast, glanceable information — not dense dashboards
* May be in low-light or harsh lighting environments
* One hand on phone, one hand doing fieldwork

**Goals:**

* Know immediately if their Guardian is healthy and connected
* Be alerted to threats and know how to respond
* Manage devices connected to the Guardian
* Communicate securely with team members via Circles

**Frustrations with current app:**

* Dashboard is not at-a-glance — requires reading multiple cards
* Alert details don't give enough context to act without external tools
* DID-based invite system is confusing
* Dev tools (Guardian Simulator) visible in production

### **7.2 Secondary User — Circle Admin / Team Lead**

The **Circle Admin** manages the trust group (Circle) — who is in it, who gets invited, and the team communication layer.

**Context of use:**

* May be in an office or on-site
* Managing a team of 2–10 people who all use Guardian devices
* Responsible for inviting new members, removing departed members
* May coordinate incident response over the Circle's secure chat and calls

**Goals:**

* Manage Circle membership easily
* Invite people via the most convenient method (DID, link, or QR)
* View who is online/offline in the Circle
* Communicate securely over chat and voice/video calls

---

## **8\. Current State Analysis**

### **8.1 What Works Well**

| Area | What Works |
| ----- | ----- |
| Navigation | 5-tab bottom nav is intuitive and correctly organized |
| Alert Severity | HIGH/LOW badge system is clear and scannable |
| Device Cards | Security score \+ privacy score \+ vulnerability count is excellent information architecture |
| Smart Home Integration | Modal-based design with tabbed organization (Hubs/Dongles/Cloud/Rules) is well structured |
| Circle Invite | Three-method invite (DID/Link/QR) covers all user scenarios |
| Settings | Section grouping (Account/Network/Physical Security/Device/Notifications/Help) is logical |
| Alert Bulk Actions | Select All \+ bulk archive/delete pattern works well |

### **8.2 What Needs Fixing**

| Issue | Severity | Description |
| ----- | ----- | ----- |
| Brand misalignment | Critical | Teal/cyan theme does not match Cervais brand (should be black \+ purple) |
| Dashboard density | Critical | Too much raw data, no health summary, no clear "all good" vs "action needed" state |
| No onboarding | Critical | First-time users have no guided setup experience |
| Guardian Simulator in prod | Critical | Dev tool exposed in production UI, confusing for real users |
| Alert detail depth | High | Alert expand shows only event type \+ status \+ archive button — not enough to act |
| DID UX explanation | High | Non-technical users don't understand what a DID is |
| Call button colors | Medium | Green/purple for voice/video feels disconnected from brand |
| Empty states | Medium | "No messages yet", "No circles yet" are plain text — missed opportunity |
| No search | Medium | No way to search alerts, devices, or circle members |
| No notification history | Medium | No unified notification center |
| Inconsistent card padding | Medium | Spacing inconsistencies across cards and list items |

### **8.3 Missing Features**

| Feature | Priority | Notes |
| ----- | ----- | ----- |
| Onboarding / Hardware Pairing Flow | Must Have | First-time setup wizard |
| Redesigned Dashboard with Health Score | Must Have | Single security health metric |
| Rich Alert Detail | Must Have | Device, IP, protocol, AI recommendation, actions |
| Network Topology Visualization | Should Have | Visual graph of Circle peers |
| Policy Viewer | Should Have | Read-only view of active UEP policy rules |
| Multi-Guardian Switcher | Nice to Have | For users who manage more than one device |
| Compliance Posture Summary | Nice to Have | Security posture score with audit export |
| Global Search | Nice to Have | Search across alerts, devices, members |
| Notification Center | Nice to Have | Unified notification history |

---

## **9\. Proposed Solution**

### **9.1 The Redesign Approach**

We are doing a **full ground-up redesign** — not a reskin. This means:

1. **Same navigation structure** — 5-tab bottom nav is kept (Dashboard, Alerts, Circles, Devices, Settings) but renamed and restructured where needed
2. **Same feature set** — full functional parity with the existing app
3. **New design language** — 100% aligned to Cervais brand (black, purple, clean typography)
4. **New screen architecture** — several screens are rebuilt from scratch with better information hierarchy
5. **New features added** — onboarding, health score dashboard, rich alert detail, network topology
6. **Removed** — Guardian Simulator removed from production UI

### **9.2 Navigation Structure (Proposed)**

| Tab | Icon | Current Name | Proposed Name | Reason |
| ----- | ----- | ----- | ----- | ----- |
| 1 | | Dashboard | **Home** | More intuitive label |
| 2 | | Alerts | **Alerts** | Keep — clear and correct |
| 3 | | Circles | **Network** | Better reflects the trust fabric concept |
| 4 | | Devices | **Devices** | Keep — clear and correct |
| 5 | | Settings | **Settings** | Keep — universal convention |

### **9.3 Dashboard Redesign Philosophy**

The new Dashboard will answer three questions instantly:

1. **Is my Guardian healthy?** → Security Health Score ring (0–100)
2. **Are there active threats?** → Alert summary with severity count
3. **What do I need to do?** → Quick Actions tray

---

## **10\. Feature Set**

### **10.1 Complete Feature List by Section**

#### **HOME (Dashboard)**

| \# | Feature | Status | Priority |
| ----- | ----- | ----- | ----- |
| H1 | Guardian device card (name, status, connection type) | Existing | Must Have |
| H2 | Security Health Score (0–100 ring visualization) | **New** | Must Have |
| H3 | Connection metrics (signal, peers) | Existing | Must Have |
| H4 | Active alerts summary (count by severity) | Existing — Enhanced | Must Have |
| H5 | Quick Actions tray (Scan, Archive All, View Topology) | **New** | Should Have |
| H6 | Your Circles summary (count, online members) | Existing | Should Have |
| H7 | Last scan timestamp | **New** | Should Have |

#### **ALERTS**

| \# | Feature | Status | Priority |
| ----- | ----- | ----- | ----- |
| A1 | AI Threat Intelligence panel (Threat Score, 24h count, Blocked, Quarantined) | Existing | Must Have |
| A2 | Active alerts list with severity badges | Existing | Must Have |
| A3 | Archived alerts list | Existing | Must Have |
| A4 | Search/filter (severity, status, type, date) | Existing | Must Have |
| A5 | Bulk select \+ archive/delete | Existing | Must Have |
| A6 | Alert detail — expanded (event type, device, IP, protocol) | Existing — Enhanced | Must Have |
| A7 | Alert detail — AI recommendation \+ remediation actions | **New** | Must Have |
| A8 | Alert detail — affected device quick link | **New** | Should Have |
| A9 | Alert detail — timeline view | **New** | Nice to Have |

#### **NETWORK (Circles)**

| \# | Feature | Status | Priority |
| ----- | ----- | ----- | ----- |
| N1 | Circles list (name, members, online count) | Existing | Must Have |
| N2 | Create Circle (name, description, certificate gen) | Existing | Must Have |
| N3 | Circle detail — Chat tab | Existing | Must Have |
| N4 | Circle detail — Calls tab (voice \+ video) | Existing | Must Have |
| N5 | Circle detail — Members tab (list, invite, status) | Existing | Must Have |
| N6 | Invite member — DID search | Existing | Must Have |
| N7 | Invite member — Share Link \+ invite code | Existing | Must Have |
| N8 | Invite member — QR Code | Existing | Must Have |
| N9 | Network Topology View (visual graph of peers) | **New** | Should Have |
| N10 | Member detail (DID, connection type, last seen) | **New** | Should Have |

#### **DEVICES**

| \# | Feature | Status | Priority |
| ----- | ----- | ----- | ----- |
| D1 | Connected devices list (All/Regular/Drones/Smart Home/Pending tabs) | Existing | Must Have |
| D2 | Device card (name, manufacturer, protocol, status, security score) | Existing | Must Have |
| D3 | Device detail (security/privacy score, vulnerabilities, monitoring toggle) | Existing | Must Have |
| D4 | Add Device manually (form) | Existing | Must Have |
| D5 | Scan Network | Existing | Must Have |
| D6 | Device actions (Run Security Scan, Block from Network, Remove Device) | Existing | Must Have |
| D7 | Smart Home Integration modal (Hubs, Dongles, Cloud, Rules) | Existing | Must Have |
| D8 | Cloud service connections (Ring, Nest, Wyze, Ecobee, TP-Link, Arlo) | Existing | Must Have |
| D9 | Device Automation Rules (Security Triggers, Schedules, Geofencing, Sensors) | Existing | Must Have |
| D10 | Pending device approval flow | Existing | Must Have |
| D11 | Device vulnerability detail \+ remediation recommendations | Existing — Enhanced | Must Have |
| D12 | Service Access management | Existing | Should Have |

#### **SETTINGS**

| \# | Feature | Status | Priority |
| ----- | ----- | ----- | ----- |
| S1 | Guardian selector (device name, connection status) | Existing | Must Have |
| S2 | My DID display \+ copy | Existing | Must Have |
| S3 | Connection Type (auto-detected) | Existing | Must Have |
| S4 | Signal Strength indicator | Existing | Must Have |
| S5 | Profile (name, email, avatar) | Existing | Must Have |
| S6 | Data Usage | Existing | Must Have |
| S7 | Backup & Restore | Existing | Must Have |
| S8 | Network Topology (link to view) | Existing | Must Have |
| S9 | Location & Geofencing | Existing | Must Have |
| S10 | Device Pairing | Existing | Must Have |
| S11 | Manage Guardians | Existing | Must Have |
| S12 | Device Settings | Existing | Must Have |
| S13 | Dual Wi-Fi Mode | Existing | Must Have |
| S14 | Notification Preferences | Existing | Must Have |
| S15 | Custom Alert Rules | Existing | Must Have |
| S16 | Quick Start guide | Existing | Must Have |
| S17 | App Version | Existing | Must Have |
| S18 | Logout | Existing | Must Have |

#### **ONBOARDING (New Section)**

| \# | Feature | Status | Priority |
| ----- | ----- | ----- | ----- |
| O1 | Welcome screen (brand intro) | **New** | Must Have |
| O2 | Hardware pairing (QR scan or serial entry) | **New** | Must Have |
| O3 | Connection verification (connecting to Guardian) | **New** | Must Have |
| O4 | Account creation / login | **New** | Must Have |
| O5 | DID explanation screen (plain language) | **New** | Must Have |
| O6 | Create first Circle prompt | **New** | Should Have |
| O7 | Onboarding complete → Dashboard | **New** | Must Have |

---

## **11\. Design Direction**

### **11.1 Brand Foundation**

The redesign is built directly on top of the Cervais brand as expressed on `cervais.framer.website`.

| Element | Specification |
| ----- | ----- |
| **Primary Background** | `#000000` / `#0A0A0A` — true black |
| **Secondary Background** | `#111111` / `#1A1A1A` — card surfaces |
| **Border Color** | `#222222` / `#2A2A2A` — subtle card borders |
| **Primary Accent** | `#7C3AED` — Cervais purple |
| **Accent Hover** | `#8B5CF6` — lighter purple for hover/active states |
| **Accent Glow** | `rgba(124, 58, 237, 0.15)` — purple radial glow for hero elements |
| **Primary Text** | `#FFFFFF` — white |
| **Secondary Text** | `#A1A1AA` — muted gray |
| **Tertiary Text** | `#52525B` — disabled / placeholder |
| **Success / Safe** | `#22C55E` — green |
| **Warning / Medium** | `#F59E0B` — amber |
| **Danger / Critical** | `#EF4444` — red |
| **Info** | `#3B82F6` — blue |

### **11.2 Typography**

| Role | Font | Weight | Size |
| ----- | ----- | ----- | ----- |
| **Page Title** | Inter | 700 Bold | 28px |
| **Section Header** | Inter | 600 SemiBold | 20px |
| **Card Title** | Inter | 600 SemiBold | 16px |
| **Body** | Inter | 400 Regular | 14px |
| **Caption / Label** | Inter | 400 Regular | 12px |
| **Code / DID** | JetBrains Mono | 400 Regular | 13px |

### **11.3 Design Principles**

1. **Black canvas, purple intent** — Every primary action, every active state, every key highlight uses Cervais purple. The rest stays black and white.
2. **Clarity over density** — Fewer elements per screen. Security dashboards fail when they show everything. Each screen has one primary focus.
3. **Action-first hierarchy** — The most important action on any screen is always visually dominant. Users should never hunt for what to do next.
4. **Progressive disclosure** — Technical detail (DID strings, nftables policies, gRPC status) is available but hidden behind expandable sections. Default view is human-readable.
5. **Status is always visible** — Guardian connection status, encryption state, and last-seen timestamp are persistent in the UI. Users should never wonder if the device is connected.
6. **Trust signals throughout** — Encryption badges, certificate validity indicators, and peer count are woven into the interface as passive confidence builders.

### **11.4 Component Design Language**

| Component | Style |
| ----- | ----- |
| **Cards** | Dark surface `#111111`, `1px` border `#222222`, `12px` border radius |
| **Primary Button** | Solid purple `#7C3AED`, white text, `8px` border radius, `44px` min height |
| **Secondary Button** | Transparent, `1px` purple border, purple text |
| **Destructive Button** | Solid red `#EF4444` or red border variant |
| **Input Fields** | `#1A1A1A` background, `#333333` border, white text, purple focus ring |
| **Badges** | Filled: RED for HIGH, AMBER for MEDIUM, BLUE for LOW, GREEN for Secure |
| **Bottom Nav** | `#0A0A0A` background, white active icon \+ label, gray inactive |
| **Modals** | `#111111` background, slide-up animation, rounded top corners |
| **Dividers** | `#222222` 1px horizontal lines |

---

## **12\. Technical Constraints**

| Constraint | Detail |
| ----- | ----- |
| **Platform** | Mobile browser (iOS Safari, Android Chrome) — not native |
| **No App Store** | App is accessed via URL, not installed from app store |
| **Thin Client** | App is a thin client — all security logic runs on the SG-X Guardian device |
| **Backend API** | gRPC-based backend (exposed via HTTP/REST gateway for web client) |
| **Auth** | DID-based decentralized authentication |
| **Offline State** | App must gracefully handle Guardian being unreachable |
| **Viewport** | Design base: 390px wide (iPhone 14). Must work 360px–430px |
| **Accessibility** | WCAG AA required (color contrast, touch target sizes min 44px) |
| **No Local Storage of Keys** | Cryptographic keys reside on Guardian hardware, not in browser |

---

## **13\. Assumptions & Dependencies**

### **Assumptions**

* Cervais will provide final brand assets (logo files, any brand guidelines document) before Figma design begins
* The Backend team's backend API structure will remain consistent with the API Specification v1.0
* The existing app's feature set (as observed in screenshots) is complete and no hidden screens exist
* Guardian Simulator is confirmed to be a development tool and will be removed from the production UI
* The primary user manages **one** SG-X Guardian device at a time (multi-device is out of scope for Phase 1\)

### **Dependencies**

| Dependency | Owner | Impact if Delayed |
| ----- | ----- | ----- |
| Brand assets / guidelines | Cervais | Design system cannot be finalized |
| API specification updates | Backend | API-to-UI mapping document delayed |
| Content / copy approval | Cervais | Screens with marketing copy cannot be finalized |
| Figma access setup | Lightning Leap | Design work cannot begin |

---

## **14\. Out of Scope**

The following are **explicitly excluded** from this engagement:

| Item | Reason |
| ----- | ----- |
| Web admin interface (Super Admin / Fleet Management) | Client confirmed mobile only for this phase |
| Native iOS / Android app development | Browser-based only |
| Backend / API development | Backend team's responsibility |
| Policy Editor (visual UEP rule builder) | Phase 2+ feature |
| Multi-Guardian fleet management | Phase 2+ feature |
| Compliance report export (PDF generation) | Phase 2+ feature |
| Guardian Simulator UI | Dev tool, removed from production |
| Cylenium Cloud platform design | Separate product |

---

## **15\. Risks & Mitigations**

| Risk | Probability | Impact | Mitigation |
| ----- | ----- | ----- | ----- |
| Brand guidelines not finalized before design | Medium | High | Begin with what's visible on cervais.framer.website; update tokens when guidelines arrive |
| API changes break UI-to-API mapping | Medium | Medium | Design to data contracts, not specific endpoints; flag API dependencies clearly in handoff |
| Scope creep from client | High | High | Strict change control — new features go to a Phase 2 backlog, not current scope |
| Figma handoff misinterpretation by dev | Low | High | Thorough annotation, component library, and a Figma walkthrough session |
| Browser compatibility issues | Low | Medium | Test designs in iOS Safari and Android Chrome specifically; avoid CSS features with poor support |

---

## **16\. Delivery Plan**

### **16.1 Document Delivery Sequence**

| \# | Document | Format | ETA |
| ----- | ----- | ----- | ----- |
| 1 | Product Brief (full) | Markdown | This document |
| 2 | Product Brief (one-pager) | Markdown | Next |
| 3 | User Personas | Markdown | TBD |
| 4 | Information Architecture \+ Mermaid diagrams | Markdown | TBD |
| 5 | Screen Inventory | Markdown | TBD |
| 6 | User Flows Overview (intro doc) | Markdown | TBD |
| 7 | Flow 1 — Onboarding | Markdown | TBD |
| 8 | Flow 2 — Alert Triage | Markdown | TBD |
| 9 | Flow 3 — Circle Creation \+ Invite | Markdown | TBD |
| 10 | Flow 4 — Device Discovery \+ Add | Markdown | TBD |
| 11 | Flow 5 — Smart Home Integration | Markdown | TBD |
| 12 | Flow 6 — Settings \+ DID Management | Markdown | TBD |

### **16.2 Design Phase (Post-Documentation)**

| Phase | Activity |
| ----- | ----- |
| **Design Sprint 1** | Design System setup in Figma (colors, typography, component library) |
| **Design Sprint 2** | Onboarding \+ Dashboard \+ Alerts screens |
| **Design Sprint 3** | Network (Circles) \+ Devices screens |
| **Design Sprint 4** | Settings \+ all states (loading, empty, error) |
| **Design Sprint 5** | Review, polish, and developer handoff package |

---

## **17\. Open Questions**

The following questions require answers from Cervais before design can be fully finalized:

| \# | Question | Impact | Owner |
| ----- | ----- | ----- | ----- |
| Q1 | Are there official brand guidelines beyond the website? (logo files, font license, color tokens) | Design system accuracy | Cervais |
| Q2 | What is the exact URL/domain where the app will be hosted? | Helps with PWA considerations | Cervais |
| Q3 | Is there a maximum member count per Circle? | Affects member list design | Cervais |
| Q4 | What alert types exist beyond what's shown in screenshots? (full event type taxonomy) | Alert detail design | Cervais / Backend |
| Q5 | What is the device type taxonomy? (full list beyond Regular/Drones/Smart Home) | Device filter tab design | Cervais / Backend |
| Q6 | Is the Chat feature encrypted end-to-end over the Guardian's P2P channel? (user-facing trust signal) | Circle chat screen design | Cervais |
| Q7 | What does "Service Access" in the Devices tab mean? (no screenshot available) | Devices screen completeness | Cervais |
| Q8 | Will the app require a login screen / auth flow, or does the DID handle all auth? | Onboarding flow design | Cervais |
