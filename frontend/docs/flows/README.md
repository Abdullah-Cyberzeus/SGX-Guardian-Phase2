# **User Flows**

# **What Are User Flows?**

User flows map the **step-by-step journey** a user takes to complete a specific goal inside the app. Each flow captures:

* Every screen the user encounters
* Every decision point (success / error / skip)
* Every system action that happens in the background
* The exact tap sequence from trigger to completion

User flows are the **bridge between Information Architecture and Figma design** — they tell us not just what screens exist, but how users move between them and what they experience at every step.

---

## **The 6 Core Flows**

These 6 flows cover the most critical user journeys in the SG-X Guardian app. Together they represent the **full lifecycle** of the product from first setup to daily operation.

| \# | Flow | Primary Persona | Trigger | Goal | Complexity |
| ----- | ----- | ----- | ----- | ----- | ----- |
| **Flow 1** | Onboarding / First Run | Marcus (Field Engineer) | First app launch | Pair Guardian hardware, set up account, create first Circle | High |
| **Flow 2** | Alert Triage | Marcus (Field Engineer) | Push notification or manual check | Understand a security alert and take appropriate action | High |
| **Flow 3** | Circle Creation \+ Member Invite | Sofia (Circle Admin) | Need to create a new trust group | Create a Circle, invite team members via multiple methods | Medium |
| **Flow 4** | Device Discovery \+ Add | Marcus (Field Engineer) | New device on network or manual add | Discover or manually register a device, approve and monitor it | Medium |
| **Flow 5** | Smart Home Integration | Marcus (Field Engineer) | Need to connect smart home devices to Guardian | Connect hubs, cloud services, and set up automation rules | High |
| **Flow 6** | Settings \+ DID Management | Both personas | Need to configure Guardian or share identity | Update settings, find and share DID, manage connection | Low |

---

## **Flow Complexity Guide**

Each flow is rated on three dimensions:

| Dimension | Description |
| ----- | ----- |
| **Screen count** | How many screens does the flow touch? |
| **Decision points** | How many branching paths exist (success/error/skip)? |
| **System dependencies** | How many backend/hardware calls does the flow require? |

 High \= 6+ screens, 3+ decision points, hardware/API dependent
 Medium \= 4–6 screens, 2 decision points, API dependent
 Low \= 2–4 screens, 1 decision point, mostly local/cached

---

## **Flow Map — How the 6 Flows Connect**

flowchart TD
 START(\[User Downloads / Opens App\]) \--\> F1

 F1\[Flow 1\\nOnboarding / First Run\]
 F1 \-- Guardian paired\\nAccount created \--\> DASH\[Home Dashboard\]

 DASH \--\> F2\[Flow 2\\nAlert Triage\]
 DASH \--\> F3\[Flow 3\\nCircle Creation \+ Invite\]
 DASH \--\> F4\[Flow 4\\nDevice Discovery \+ Add\]
 DASH \--\> F5\[Flow 5\\nSmart Home Integration\]
 DASH \--\> F6\[Flow 6\\nSettings \+ DID Management\]

 F2 \-- Alert resolved \--\> DASH
 F3 \-- Circle created\\nMembers invited \--\> DASH
 F4 \-- Device approved \--\> DASH
 F5 \-- Integration active \--\> DASH
 F6 \-- Settings saved \--\> DASH

 F2 \-- Affected device link \--\> F4
 F3 \-- Invite via DID \--\> F6
 F4 \-- Security scan triggers alert \--\> F2

---

## **Shared Flow Conventions**

All 6 flow documents follow the same conventions:

### **Notation**

| Symbol | Meaning |
| ----- | ----- |
| `([...])` | Start or end point |
| `[...]` | Screen or action |
| `{...}` | Decision point |
| `-->` | Navigation / tap action |
| `-- label -->` | Conditional path with label |
| `` | System action (background, no user input) |
| `` | Success state |
| `` | Error state |
| `` | Skip / optional path |

### **Every Flow Document Contains**

1. **Flow summary** — goal, persona, trigger, screens involved, estimated time
2. **Happy path** — the ideal, no-error journey in Mermaid diagram
3. **Full flow with all branches** — including errors, edge cases, skips
4. **Step-by-step narrative** — plain English description of each step
5. **Screen list** — exact screen IDs from the Screen Inventory
6. **API / system dependencies** — what backend calls are made
7. **Design notes** — UX considerations specific to this flow
8. **Edge cases** — what happens when things go wrong

---

## **Priority Order for Design**

Flows should be designed in Figma in this order — highest user impact first:

Flow 1 (Onboarding) → Flow 2 (Alert Triage) → Flow 4 (Device Add)
→ Flow 3 (Circle Invite) → Flow 5 (Smart Home) → Flow 6 (Settings)

---

## **Document Index**

| Document | File | Status |
| ----- | ----- | ----- |
| This overview | `SGX_UserFlows_Overview_v1.0.md` | Complete |
| Flow 1 — Onboarding | `SGX_Flow1_Onboarding_v1.0.md` | Complete |
| Flow 2 — Alert Triage | `SGX_Flow2_AlertTriage_v1.0.md` | Complete |
| Flow 3 — Circle Creation \+ Invite | `SGX_Flow3_CircleInvite_v1.0.md` | Pending |
| Flow 4 — Device Discovery \+ Add | `SGX_Flow4_DeviceAdd_v1.0.md` | Pending |
| Flow 5 — Smart Home Integration | `SGX_Flow5_SmartHome_v1.0.md` | Pending |
| Flow 6 — Settings \+ DID Management | `SGX_Flow6_Settings_v1.0.md` | Pending |

