# **Screen Inventory**

# **Overview**

This document is the **master screen inventory** for the SG-X Guardian mobile web app redesign. It catalogs every screen, modal, and state that needs to be designed in Figma — including existing screens being redesigned, enhanced screens, and entirely new screens.

### **Status Key**

| Status | Meaning |
| ----- | ----- |
| **Existing** | Screen exists in current app — being redesigned with same function |
| **Enhanced** | Screen exists but is being significantly upgraded with new content or features |
| **New** | Screen does not exist in current app — being built from scratch |
| **Removed** | Screen exists in current app but will NOT appear in redesign |

### **Priority Key**

| Priority | Meaning |
| ----- | ----- |
| **P1 — Must Have** | Core functionality — app cannot ship without this |
| **P2 — Should Have** | Important — high value, design in Sprint 2 |
| **P3 — Nice to Have** | Valuable but deferrable — design if time permits |

### **Nav Depth Key**

| Level | Meaning |
| ----- | ----- |
| **L0** | Bottom navigation (persistent) |
| **L1** | Section root / first screen |
| **L2** | Detail screen |
| **L3** | Sub-screen or modal |

---

## **Total Screen Count**

| Zone | Existing | Enhanced | New | Removed | Total |
| ----- | ----- | ----- | ----- | ----- | ----- |
| Onboarding | 0 | 0 | 7 | 0 | 7 |
| Home | 1 | 1 | 2 | 0 | 4 |
| Alerts | 3 | 2 | 2 | 0 | 7 |
| Network | 7 | 2 | 3 | 0 | 12 |
| Devices | 8 | 2 | 2 | 2 | 14 |
| Settings | 10 | 1 | 0 | 0 | 11 |
| States (global) | 0 | 0 | 5 | 0 | 5 |
| **Total** | **29** | **8** | **21** | **2** | **60** |

**60 total screens / states to design in Figma.**

---

## **Section 0 — Onboarding**

First-run only. Linear wizard. Bottom nav not visible. 7 new screens.

| ID | Screen Name | Status | Priority | Nav Level | Description | States Needed |
| ----- | ----- | ----- | ----- | ----- | ----- | ----- |
| OB-01 | Welcome Screen | New | P1 | L1 | Brand intro screen — Cervais logo, SG-X Guardian name, tagline, "Get Started" CTA | Default |
| OB-02 | Hardware Pairing | New | P1 | L1 | Two options: Scan QR code on Guardian device OR manually enter serial number | Default, Camera scanning state |
| OB-03 | Pairing — Connecting | New | P1 | L1 | Loading state — "Connecting to your Guardian..." animated indicator | Loading |
| OB-04 | Pairing — Success | New | P1 | L1 | Success confirmation — Guardian name, device ID, connection type confirmed | Success |
| OB-05 | Pairing — Failed | New | P1 | L1 | Error state — "Couldn't find Guardian" with retry \+ help options | Error |
| OB-06 | Account Setup | New | P1 | L1 | Login or create account — email/password \+ DID auto-generation note | Default, Loading |
| OB-07 | DID Introduction | New | P1 | L1 | Plain-language explainer — "Your DID is your secure identity on this network" \+ copy DID button | Default |
| OB-08 | Create First Circle | New | P2 | L1 | Optional step — Circle name \+ description form \+ "Skip for now" link | Default |
| OB-09 | Onboarding Complete | New | P1 | L1 | Celebration screen — "You're all set" \+ summary of what's ready \+ "Go to Dashboard" CTA | Default |

**Onboarding subtotal: 9 screens (including 2 error/loading variants)**

---

## **Section 1 — Home (Dashboard)**

Single screen hub. Bottom nav visible. Deeplinks to Alerts and Network.

| ID | Screen Name | Status | Priority | Nav Level | Description | States Needed |
| ----- | ----- | ----- | ----- | ----- | ----- | ----- |
| HM-01 | Home Dashboard | Enhanced | P1 | L1 | Complete redesign — Health Score ring, Guardian device card, alert summary, quick actions tray, circles summary | Default, Offline, Loading |
| HM-02 | Guardian Detail | Existing | P1 | L2 | Full Guardian device info — firmware version, uptime, connection history, signal chart | Default, Offline |
| HM-03 | Network Topology View | New | P2 | L2 | Visual graph — Guardian at center, connected peers as nodes, connection type labels | Default, Empty, Loading |
| HM-04 | Quick Scan Initiated | New | P2 | L3 | Bottom sheet — "Scanning network..." progress \+ results summary | Loading, Results |

**Home subtotal: 4 screens**

---

## **Section 2 — Alerts**

List → detail pattern. Two parallel lists (Active / Archived). Shared detail view.

| ID | Screen Name | Status | Priority | Nav Level | Description | States Needed |
| ----- | ----- | ----- | ----- | ----- | ----- | ----- |
| AL-01 | Alerts Root — AI Panel \+ Active List | Enhanced | P1 | L1 | AI Threat Intelligence panel (Threat Score, 24h count, Blocked, Quarantined) \+ Active alerts list below | Default, Loading, Empty |
| AL-02 | Active Alerts List — Filtered | Existing | P1 | L1 | Same as AL-01 with active filters applied — shows filter chips above list | Filtered state |
| AL-03 | Active Alerts — Bulk Select Mode | Existing | P1 | L1 | Checkbox mode — Select All, Archive Selected, Delete Selected actions | Select mode |
| AL-04 | Archived Alerts List | Existing | P1 | L1 | Archived events only — same filter row, "View Active" toggle, empty state | Default, Empty, Filtered |
| AL-05 | Alert Detail — Collapsed | Existing | P1 | L2 | Alert row expanded in-line — event type \+ status \+ archive button (existing behavior) | Default |
| AL-06 | Alert Detail — Full Screen | Enhanced | P1 | L2 | Full detail screen: event type, severity, timestamp, affected device name \+ IP \+ protocol, status, AI recommendation summary, action buttons | Default |
| AL-07 | Alert Detail — AI Recommendation Panel | New | P1 | L3 | Expanded AI analysis — what happened, why it's a threat, step-by-step remediation | Default |
| AL-08 | Alert Remediation Actions Sheet | New | P1 | L3 | Bottom sheet — Archive Event, Block Device, Run Security Scan, View Affected Device | Default |

**Alerts subtotal: 8 screens**

---

## **Section 3 — Network (Circles)**

Most hierarchically deep section. Circle detail has 4 tabs. Invite flow has 3 methods.

| ID | Screen Name | Status | Priority | Nav Level | Description | States Needed |
| ----- | ----- | ----- | ----- | ----- | ----- | ----- |
| NW-01 | Circles List | Existing | P1 | L1 | List of all Circles — name, member count, online count, Chat \+ Members quick access buttons | Default, Empty, Loading |
| NW-02 | Create Circle — Form | Existing | P1 | L2 | Circle name \+ description inputs, Circle Network info card, Create Circle CTA, feature checklist | Default |
| NW-03 | Create Circle — Initializing | Existing | P1 | L2 | Loading state — "Initializing Circle network..." spinner with progress steps | Loading |
| NW-04 | Circle Detail — Chat Tab | Existing | P1 | L2 | Secure P2P messaging — message list, compose input, send button, delivery/read indicators | Default, Empty, Loading |
| NW-05 | Circle Detail — Calls Tab | Enhanced | P1 | L2 | Voice \+ Video call options, call history list — brand-aligned button colors replacing green/purple | Default, Empty, In-Call state |
| NW-06 | Circle Detail — Members Tab | Existing | P1 | L2 | Member list — name, email, role, online/offline status, last seen, Invite Member CTA | Default, Empty |
| NW-07 | Circle Detail — Topology Tab | New | P2 | L2 | Visual graph — Guardian at center, Circle peers as nodes, connection type labels, tap node for member detail | Default, Empty |
| NW-08 | Member Detail | New | P2 | L3 | Individual member: DID, connection type, last seen, Guardian health status, Remove Member option | Default |
| NW-09 | Invite Member — Modal Container | Existing | P1 | L3 | Modal with 3 tabs: Search DIDs (default hidden, accessible via "Advanced"), Share Link (default), QR Code | Default |
| NW-10 | Invite — Share Link Tab | Enhanced | P1 | L3 | Default invite method — invite code display, shareable link, Share Invite button, Record by email input | Default |
| NW-11 | Invite — QR Code Tab | Existing | P1 | L3 | QR code display \+ Share QR Code button \+ invite code label | Default |
| NW-12 | Invite — Search DIDs Tab | Existing | P2 | L3 | Advanced method — DID/user ID search, DID-Based Discovery explainer panel, Search button | Default, Results, Not Found |
| NW-13 | Remove Member — Confirmation | New | P1 | L3 | Confirmation bottom sheet — "Remove \[Name\] from \[Circle\]?" with destructive confirm \+ cancel | Default |

**Network subtotal: 13 screens**

---

## **Section 4 — Devices**

Most feature-rich section. Tabbed list \+ modal-heavy.

| ID | Screen Name | Status | Priority | Nav Level | Description | States Needed |
| ----- | ----- | ----- | ----- | ----- | ----- | ----- |
| DV-01 | Devices List — All | Existing | P1 | L1 | All approved devices — filter tabs (All/Regular/Drones/Smart Home/Pending/Service Access), search bar, Scan \+ Add buttons | Default, Loading, Empty |
| DV-02 | Devices List — Pending Tab | Enhanced | P1 | L1 | Pending approval devices — approve/reject per device, badge count on tab | Default, Empty |
| DV-03 | Device Detail — Info Tab | Existing | P1 | L2 | Security Score \+ Privacy Score \+ Vuln Count cards, Device Information table (Manufacturer, Model, Protocol, MAC, IP, Firmware), Guardian Monitoring toggle | Default |
| DV-04 | Device Detail — Security Features | Existing | P1 | L2 | Encryption / Auto-Update / Connectivity status, Vulnerabilities Detected panel with recommendations list | Default |
| DV-05 | Device Detail — Actions | Existing | P1 | L2 | Run Security Scan, Block from Network (amber), Remove Device (red) buttons | Default |
| DV-06 | Security Scan — In Progress | New | P1 | L3 | Scan running animation — progress bar, "Scanning \[device name\]..." | Loading |
| DV-07 | Security Scan — Results | Enhanced | P1 | L3 | Scan complete — vulnerability count, severity breakdown, recommendations, link to full alert | Results |
| DV-08 | Block Device — Confirmation | Existing | P1 | L3 | Confirmation sheet — "Block \[device\] from network?" \+ consequences explanation \+ confirm/cancel | Default |
| DV-09 | Remove Device — Confirmation | Existing | P1 | L3 | Confirmation sheet — "Remove \[device\]?" \+ consequences \+ confirm/cancel | Default |
| DV-10 | Add Device — Form | Existing | P1 | L3 | Device Name, Device Type dropdown, Connection Method dropdown, MAC Address, IP (optional), Manufacturer, Model, OS fields \+ Add Device CTA | Default, Validation errors |
| DV-11 | Smart Home Integration — Hubs | Existing | P2 | L3 | Start/Stop Service buttons, Discover Hubs, Discovered hubs list, Recent Activity log | Default, Discovering, Results |
| DV-12 | Smart Home Integration — Dongles | Existing | P2 | L3 | USB dongles management panel | Default, Empty |
| DV-13 | Smart Home Integration — Cloud | Existing | P2 | L3 | Cloud services grid: Ring, Nest, Wyze, Ecobee, TP-Link, Arlo \+ Connect buttons | Default, Connected state |
| DV-14 | Smart Home Integration — Rules | Existing | P2 | L3 | Device Automation: Security Triggers, Schedules, Geofencing, Sensors cards \+ Manage Automation Rules CTA | Default |
| DV-15 | Guardian Simulator | Removed | — | — | Dev tool — removed from production UI entirely | — |
| DV-16 | Service Access | Existing | P2 | L1 | Service access management (details to be confirmed with Cervais) | Default |

**Devices subtotal: 14 screens (+ 2 removed)**

---

## **Section 5 — Settings**

Grouped list → push navigation pattern. No tabs.

| ID | Screen Name | Status | Priority | Nav Level | Description | States Needed |
| ----- | ----- | ----- | ----- | ----- | ----- | ----- |
| ST-01 | Settings Root | Enhanced | P1 | L1 | Guardian selector card at top \+ grouped settings list: Account / Network / Physical Security / Device / Notifications / Help & Support \+ Logout | Default |
| ST-02 | Guardian Info \+ DID | Existing | P1 | L2 | Guardian device name, connection type (auto-detected), signal strength — plus My DID display with copy button and plain-language explainer | Default |
| ST-03 | Profile | Existing | P1 | L2 | Name, email, avatar — edit profile form | Default, Edit mode |
| ST-04 | Data Usage | Existing | P2 | L2 | Data consumption stats for app \+ Guardian sync | Default |
| ST-05 | Backup & Restore | Existing | P2 | L2 | Backup Circle keys \+ Guardian config, restore from backup | Default |
| ST-06 | Network Topology | Existing | P2 | L2 | Full-screen network topology visual (same as HM-03 but in Settings context) | Default, Empty |
| ST-07 | Location & Geofencing | Existing | P2 | L2 | Geofencing setup — define safe zones, Guardian behavior on leave/enter | Default |
| ST-08 | Device Pairing | Existing | P1 | L2 | Re-pair Guardian device — QR scan or serial entry (same as Onboarding OB-02 but in Settings context) | Default |
| ST-09 | Manage Guardians | Existing | P2 | L2 | List of paired Guardians — add new, remove existing, set primary | Default, Empty |
| ST-10 | Device Settings | Existing | P2 | L2 | Guardian-specific settings (details TBC with Cervais/Backend) | Default |
| ST-11 | Dual Wi-Fi Mode | Existing | P2 | L2 | Dual Wi-Fi configuration for Guardian device | Default |
| ST-12 | Notification Preferences | Existing | P1 | L2 | Toggle notifications by alert severity, by section, push notification settings | Default |
| ST-13 | Custom Alert Rules | Existing | P2 | L2 | Create/edit custom alert trigger rules — event type \+ threshold \+ action | Default, Empty, Edit mode |
| ST-14 | Quick Start Guide | Existing | P2 | L2 | In-app help content — key concepts, how-to guides, glossary (DID explanation, Circle of Trust, etc.) | Default |
| ST-15 | App Version | Existing | P3 | L2 | App version number, build date, changelog link | Default |
| ST-16 | Logout Confirmation | Existing | P1 | L3 | "Are you sure you want to log out?" confirmation bottom sheet | Default |

**Settings subtotal: 16 screens**

---

## **Global States & System Screens**

These apply across the entire app — not section-specific.

| ID | Screen Name | Status | Priority | Description |
| ----- | ----- | ----- | ----- | ----- |
| SYS-01 | Offline Warning Banner | New | P1 | Persistent red/amber bar shown across ALL screens when Guardian is unreachable: "Guardian offline — last seen \[time\]" |
| SYS-02 | App Loading / Splash | New | P1 | Initial app load — Cervais logo on black background, brief loading animation |
| SYS-03 | Global Error State | New | P1 | Full-screen error — "Something went wrong" with retry button. Used for catastrophic API failures. |
| SYS-04 | Empty State Template | New | P1 | Reusable empty state component — icon \+ heading \+ subtext \+ optional CTA. Applied per-section. |
| SYS-05 | Toast / Snackbar Notifications | New | P1 | In-app success/error/info toast messages — e.g., "Alert archived", "Device blocked", "Circle created" |

**Global subtotal: 5 screens**

---

## **Complete Screen Count Summary**

| Section | Total Screens | P1 | P2 | P3 | Existing | Enhanced | New | Removed |
| ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- |
| Onboarding | 9 | 7 | 2 | 0 | 0 | 0 | 9 | 0 |
| Home | 4 | 2 | 2 | 0 | 1 | 1 | 2 | 0 |
| Alerts | 8 | 8 | 0 | 0 | 3 | 2 | 3 | 0 |
| Network | 13 | 9 | 4 | 0 | 7 | 2 | 4 | 0 |
| Devices | 14 | 7 | 5 | 0 | 8 | 2 | 2 | 2 |
| Settings | 16 | 6 | 9 | 1 | 10 | 1 | 5 | 0 |
| Global | 5 | 5 | 0 | 0 | 0 | 0 | 5 | 0 |
| **Total** | **69** | **44** | **22** | **1** | **29** | **8** | **30** | **2** |

**69 total screens to design. 44 are P1 Must Have. 30 are brand new screens.**

---

## **Figma Page Structure (Recommendation)**

Based on this inventory, here is the recommended Figma file structure:

 SG-X Guardian — Design File
│
├── 00 — Cover & Index
├── 01 — Design System (Colors, Typography, Components)
├── 02 — Onboarding (9 screens)
├── 03 — Home (4 screens)
├── 04 — Alerts (8 screens)
├── 05 — Network (13 screens)
├── 06 — Devices (14 screens)
├── 07 — Settings (16 screens)
├── 08 — Global States (5 screens)
└── 09 — Prototype Flows (interactive connections)

---

## **Design Sprint Allocation**

| Sprint | Screens | IDs |
| ----- | ----- | ----- |
| **Sprint 1 — Design System** | Component library, tokens, base components | DS-all |
| **Sprint 2 — Onboarding \+ Home \+ Alerts** | 21 screens | OB-01→09, HM-01→04, AL-01→08 |
| **Sprint 3 — Network \+ Devices** | 27 screens | NW-01→13, DV-01→14 |
| **Sprint 4 — Settings \+ Global \+ Polish** | 21 screens | ST-01→16, SYS-01→05 |
| **Sprint 5 — States \+ Handoff** | All error / empty / loading variants | All sections |

