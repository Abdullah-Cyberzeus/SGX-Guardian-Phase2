# **Alert Triage**

# **Flow Summary**

| Attribute | Detail |
| ----- | ----- |
| **Flow Name** | Alert Triage |
| **Primary Persona** | Marcus Webb — Field Security Engineer |
| **Trigger** | Push notification received OR manual check of Alerts tab |
| **Goal** | Open an alert, fully understand what happened, and take the appropriate remediation action |
| **Entry Points** | Push notification → Alert Detail (deep link) OR Bottom nav → Alerts tab |
| **Exit Points** | Alert archived / Device blocked / Security scan initiated / No action taken |
| **Screens Involved** | AL-01, AL-02, AL-03, AL-04, AL-05, AL-06, AL-07, AL-08, DV-03 |
| **Estimated Completion Time** | 30 seconds (quick triage) to 3 minutes (full investigation) |
| **Complexity** | High — multiple entry points, branching remediation paths, cross-section navigation |
| **Frequency** | Daily — 1–5 times per day for Marcus |

---

## **Why This Flow Is Critical**

Alert triage is the **highest-frequency, highest-stakes interaction** in the entire app. When Marcus gets a HIGH severity alert notification at 9 AM while walking a factory floor, he needs to:

1. Understand what happened in under 10 seconds
2. Decide if it requires immediate action or can wait
3. Take that action without leaving the app

The current app fails at step 2 — alert detail is too thin. This flow drives the design of the most important screen in the app: **AL-06 Alert Detail Full Screen**.

---

## **Happy Path — Mermaid Diagram**

Push notification → Alert Detail → Understand → Archive

flowchart TD
 A(\[Push notification received\\nHIGH — Service Account Abuse\]) \--\> B\[Tap notification\]
 B \--\> C\[ Deep link opens app\\nto AL-06 Alert Detail\]
 C \--\> D\[AL-06 Alert Detail\\nFull Screen\]
 D \--\> E\[Marcus reads:\\nEvent type \+ Severity \+ Timestamp\\nAffected device \+ IP \+ Protocol\\nAI Recommendation summary\]
 E \--\> F\[Tap View AI Recommendation\]
 F \--\> G\[AL-07 AI Recommendation Panel\\nWhat happened \+ Why it matters\\nStep-by-step remediation\]
 G \--\> H\[Marcus understands threat\\nDecides to archive \- already resolved\]
 H \--\> I\[Tap Archive Event\]
 I \--\> J\[ Alert status updated\\nto Archived on Guardian\]
 J \--\> K\[ Toast: Alert archived\]
 K \--\> L(\[Returns to AL-01\\nActive Alerts List\\nAlert removed from list\])

---

## **Full Flow With All Branches**

flowchart TD
 %% Entry Points
 PUSH(\[Entry Point A\\nPush notification\]) \-- Tap notification \--\> DEEP\[ Deep link\\nopens Alert Detail\]
 NAV(\[Entry Point B\\nTap Alerts tab\]) \--\> AL01\[AL-01 Alerts Root\\nAI Panel \+ Active list\]
 DASH(\[Entry Point C\\nHome Dashboard\\nTap View All Alerts\]) \--\> AL01

 DEEP \--\> AL06\[AL-06 Alert Detail\\nFull Screen\]
 AL01 \--\> AL02{Filter / Browse}
 AL02 \-- No filter \--\> LIST\[Active alerts list\\nDefault view\]
 AL02 \-- Apply filter \--\> AL02F\[AL-02 Filtered alerts list\\nFilter chips shown\]
 LIST \--\> AL05\[AL-05 Tap alert row\\nIn-line expand\]
 AL02F \--\> AL05
 AL05 \-- Tap View Full Detail \--\> AL06
 AL05 \-- Tap Archive \--\> ARCH\_QUICK\[ Quick archive\\nno full detail needed\]
 ARCH\_QUICK \--\> TOAST\_ARCH\[ Toast: Alert archived\]
 TOAST\_ARCH \--\> AL01

 %% Alert Detail Screen
 AL06 \--\> READ\[Marcus reads:\\nEvent \+ Severity \+ Time\\nDevice \+ IP \+ Protocol\\nStatus \+ AI summary snippet\]
 READ \--\> ACTION{What does Marcus do?}

 %% Path A — View AI Recommendation
 ACTION \-- Wants more context \--\> AL07\[AL-07 AI Recommendation\\nFull analysis \+ remediation steps\]
 AL07 \--\> DECIDE{Decision after reading}
 DECIDE \-- Threat resolved / low risk \--\> ARCH\[Archive Event\]
 DECIDE \-- Needs to block device \--\> BLOCK
 DECIDE \-- Needs to scan device \--\> SCAN
 DECIDE \-- Not sure — escalate \--\> ESC\[Escalate to team\\nvia Circle chat\]
 ESC \--\> CIRCLE\[NW-04 Circle Chat\\nSend message to team\]
 CIRCLE \--\> DONE(\[Flow continues\\nin Circle\])

 %% Path B — Take Action Directly
 ACTION \-- Knows what to do \--\> AL08\[AL-08 Remediation Actions\\nBottom sheet\]
 AL08 \--\> REMED{Choose action}

 %% Archive
 REMED \-- Archive Event \--\> ARCH
 ARCH \--\> ARCH\_API\[ PATCH /api/alerts/id\\nstatus: archived\]
 ARCH\_API \--\> ARCH\_SUCCESS{Result}
 ARCH\_SUCCESS \-- Success \--\> TOAST\_A\[ Toast: Event archived\]
 ARCH\_SUCCESS \-- Error \--\> ERR\_A\[ Toast: Failed to archive\\nRetry button\]
 TOAST\_A \--\> AL01\_CLEAN\[AL-01 Active list\\nAlert removed\]

 %% Block Device
 REMED \-- Block Device \--\> BLOCK\[Block from Network\\nConfirmation sheet\]
 BLOCK \--\> BLOCK\_CONFIRM{Confirm?}
 BLOCK\_CONFIRM \-- Confirm \--\> BLOCK\_API\[ POST /api/devices/id/block\]
 BLOCK\_CONFIRM \-- Cancel \--\> AL06
 BLOCK\_API \--\> BLOCK\_RESULT{Result}
 BLOCK\_RESULT \-- Success \--\> TOAST\_B\[ Toast: Device blocked\]
 BLOCK\_RESULT \-- Error \--\> ERR\_B\[ Error: Could not block device\]
 TOAST\_B \--\> AL01\_CLEAN

 %% Run Security Scan
 REMED \-- Run Security Scan \--\> SCAN\[DV-06 Security Scan\\nIn progress\]
 SCAN \--\> SCAN\_API\[ POST /api/devices/id/scan\]
 SCAN\_API \--\> SCAN\_RESULT{Scan result}
 SCAN\_RESULT \-- Complete \--\> DV07\[DV-07 Scan Results\\nVulnerabilities found\]
 SCAN\_RESULT \-- Error \--\> ERR\_S\[ Scan failed\\nRetry\]
 DV07 \--\> POST\_SCAN{Next action}
 POST\_SCAN \-- View device \--\> DV03\[DV-03 Device Detail\]
 POST\_SCAN \-- Archive alert \--\> ARCH
 POST\_SCAN \-- Done \--\> AL01\_CLEAN

 %% View Affected Device
 ACTION \-- Tap affected device link \--\> DV03\[DV-03 Device Detail\\nFull device info\]
 DV03 \--\> DV03\_ACTION{Action on device}
 DV03\_ACTION \-- Run scan \--\> SCAN
 DV03\_ACTION \-- Block device \--\> BLOCK
 DV03\_ACTION \-- Back to alert \--\> AL06

 %% Bulk Actions
 AL01 \--\> BULK{Bulk select mode?}
 BULK \-- Tap Select \--\> AL03\[AL-03 Bulk Select Mode\\nCheckboxes appear \+ Select All\]
 AL03 \--\> BULK\_ACTION{Bulk action}
 BULK\_ACTION \-- Archive Selected \--\> BULK\_ARCH\[ Bulk archive API call\]
 BULK\_ACTION \-- Delete Selected \--\> BULK\_DEL\[Confirmation sheet\\nthen delete\]
 BULK\_ACTION \-- Cancel \--\> AL01
 BULK\_ARCH \--\> TOAST\_BULK\[ Toast: X alerts archived\]
 TOAST\_BULK \--\> AL01\_CLEAN

 %% Archived view
 AL01 \--\> SWITCH\_ARCH\[Tap View Archived\] \--\> AL04\[AL-04 Archived Alerts\\nSame layout different list\]
 AL04 \--\> AL04\_DETAIL\[AL-06 Alert Detail\\nArchived state\]
 AL04\_DETAIL \--\> UNARCH\[Unarchive option available\]
 UNARCH \--\> ARCH\_API

---

## **Step-by-Step Narrative**

### **Entry Point A — Push Notification (Marcus's Most Common Path)**

Marcus's phone buzzes at 9:15 AM. The notification reads:

SG-X Guardian
 HIGH — Service Account Abuse Detected
Service account used for unauthorized interactive login
Tap to view →

He taps the notification. The app opens directly to **AL-06 Alert Detail Full Screen** — no extra navigation required. This is a deep link from the notification payload.

---

### **Entry Point B — Manual Check**

Marcus opens the app manually from his home screen. He taps **Alerts** in the bottom nav. He lands on **AL-01** — the Alerts root showing the AI Threat Intelligence panel and the active alerts list below it.

He can see at a glance:

* Threat Score: 92 (Low Risk)
* Threats (24h): 2 Critical/High
* Blocked: 0
* Quarantined: 0

He taps the first alert in the list to expand it in-line **(AL-05)** or taps "View Full Detail" to go to the full screen.

---

### **Screen AL-06 — Alert Detail Full Screen (The Most Important Screen)**

This is the redesign's biggest improvement over the current app. Marcus sees:

┌─────────────────────────────────┐
│ ← Back HIGH │
├─────────────────────────────────┤
│ Service Account Abuse Detected │
│ Service account used for │
│ unauthorized interactive login │
├─────────────────────────────────┤
│ 26 Jan 2026 — 23:15:44 │
│ Status: Active │
├─────────────────────────────────┤
│ AFFECTED DEVICE │
│ WORKSTATION-04 │
│ 192.168.1.47 · Windows │
│ → View Device › │
├─────────────────────────────────┤
│ AI RECOMMENDATION │
│ "Likely lateral movement │
│ attempt via service account │
│ misuse. Immediate review │
│ recommended." │
│ → View Full Analysis › │
├─────────────────────────────────┤
│ \[ Take Action ▼ \] │
└─────────────────────────────────┘

Key improvements over current app:

* **Affected Device** — shows device name, IP address, OS — with a direct link to Device Detail
* **AI Recommendation** — summary of what happened and what to do, with link to full analysis
* **Take Action** — single prominent CTA that opens the Remediation Actions bottom sheet

---

### **Screen AL-07 — AI Recommendation Panel**

Marcus taps "View Full Analysis." A screen pushes in showing:

**What Happened:** Plain-language explanation of the threat. No jargon unless necessary. Example: *"A Windows service account (svc-backup) that should only run automated background tasks was used to log in interactively. This is unusual behavior that could indicate an attacker has stolen service credentials and is using them to move laterally across your network."*

**Why It Matters:** *"Service account abuse is a common technique in lateral movement attacks. If an attacker has these credentials, they may be able to access other systems on your network."*

**Recommended Actions (numbered):**

1. Reset the credentials for `svc-backup` immediately
2. Review recent login activity for this account in your SIEM
3. Check for other devices that `svc-backup` has accessed in the last 24 hours
4. Consider blocking `WORKSTATION-04` from the network pending investigation

**Design note:** This panel should feel like a trusted advisor explaining a situation — not a system dump of log data. Language must be plain, actionable, and confident.

---

### **Screen AL-08 — Remediation Actions Sheet**

Marcus taps "Take Action." A bottom sheet slides up with 4 options:

┌─────────────────────────────────┐
│ Take Action on This Alert │
├─────────────────────────────────┤
│ Archive Event │
│ Mark as reviewed, remove │
│ from active list │
├─────────────────────────────────┤
│ Block Device from Network │
│ Isolate WORKSTATION-04 │
│ immediately │
├─────────────────────────────────┤
│ Run Security Scan │
│ Scan WORKSTATION-04 for │
│ vulnerabilities │
├─────────────────────────────────┤
│ View Affected Device │
│ Go to WORKSTATION-04 detail │
└─────────────────────────────────┘

**Design note:** Archive is listed first because it's the most common action (most alerts are reviewed and archived). Block Device uses amber styling (serious but not immediate danger). Remove Device uses red styling.

---

### **Bulk Select Mode (AL-03) — Sofia's Pattern**

When there are many alerts to clear at once, the user taps **Select** in the top right of AL-01. The list shifts to checkbox mode with a **Select All** row at the top. Bulk actions appear: **Archive Selected** and **Delete Selected**.

A confirmation sheet appears before Delete (destructive action). Archive executes immediately with a toast notification.

---

## **Screen List**

| Step | Screen ID | Screen Name | Notes |
| ----- | ----- | ----- | ----- |
| Entry A | System | Push notification | Deep links to AL-06 |
| Entry B | AL-01 | Alerts Root — AI Panel \+ Active List | Manual navigation entry |
| 1 | AL-01 | Active Alerts List | Default view |
| 2 | AL-02 | Active Alerts — Filtered | With filter chips |
| 3 | AL-03 | Bulk Select Mode | Optional path |
| 4 | AL-04 | Archived Alerts List | Optional path |
| 5 | AL-05 | Alert Detail — Collapsed (in-line) | Quick review |
| 6 | AL-06 | Alert Detail — Full Screen | Core screen |
| 7 | AL-07 | AI Recommendation Panel | Context \+ guidance |
| 8 | AL-08 | Remediation Actions Sheet | Action selection |
| 9 | DV-03 | Device Detail | Cross-section link |
| 10 | DV-06 | Security Scan In Progress | Via remediation action |
| 11 | DV-07 | Scan Results | Post-scan |

---

## **API / System Dependencies**

| Action | API Call | Description | Failure Handling |
| ----- | ----- | ----- | ----- |
| Load alerts | `GET /api/alerts?status=active` | Fetch active alert list | Show stale cached data \+ offline banner |
| Load archived | `GET /api/alerts?status=archived` | Fetch archived alerts | Same |
| Get alert detail | `GET /api/alerts/:id` | Full alert detail including device info | Error state on detail screen |
| Archive alert | `PATCH /api/alerts/:id` `{ status: "archived" }` | Update alert status | Error toast \+ retry |
| Bulk archive | `PATCH /api/alerts/bulk` `{ ids: [...], status: "archived" }` | Archive multiple | Error toast \+ retry |
| Delete alert | `DELETE /api/alerts/:id` | Permanent delete | Confirmation \+ error handling |
| Block device | `POST /api/devices/:id/block` | Block device from network | Confirmation dialog \+ error |
| Run scan | `POST /api/devices/:id/scan` | Trigger security scan | Loading state \+ result polling |
| Get AI recommendation | `GET /api/alerts/:id/recommendation` | AI analysis for alert | Graceful fallback to generic message |

---

## **Design Notes**

| \# | Note |
| ----- | ----- |
| DN-01 | The AI Threat Intelligence panel at the top of AL-01 must **always be visible** — it's the first thing Marcus sees when he opens Alerts. Do not hide it behind a scroll. |
| DN-02 | Severity badge colors: HIGH \= `#EF4444` red filled, MEDIUM \= `#F59E0B` amber filled, LOW \= `#3B82F6` blue filled. Badges must meet WCAG AA contrast ratio on dark background. |
| DN-03 | Alert list items must show enough to triage without tapping: **title, description snippet, severity badge, timestamp**. Users should be able to decide "I need to look at this" vs "I can archive this" from the list view. |
| DN-04 | The **Archive** action should be available as a **swipe gesture** (swipe left on alert row) in addition to the tap → action sheet flow. Swipe to archive is the fastest path for Marcus when clearing multiple known alerts. |
| DN-05 | When an alert is archived, it should **animate out** of the active list rather than disappearing instantly — this gives Marcus visual confirmation that his action worked. |
| DN-06 | The AI Recommendation panel (AL-07) must have a clear visual distinction from the rest of the UI — consider a subtle purple glow border or a ` AI Analysis` label badge to signal this is AI-generated content. |
| DN-07 | **Deep link behavior:** When Marcus taps a push notification, the app must open to AL-06 even if the app was previously closed. The Guardian connection status must also be re-verified when the app opens this way. |
| DN-08 | Filters on AL-01 must persist within the session so Marcus doesn't lose his filter state when navigating back from a detail screen. |

---

## **Edge Cases**

| Edge Case | Scenario | Handling |
| ----- | ----- | ----- |
| EC-01 | Alert already archived by another session | Show "This alert was already archived" message on AL-06 |
| EC-02 | Guardian offline when trying to archive | Disable action buttons, show offline banner, queue action for when Guardian reconnects |
| EC-03 | Affected device no longer in device list | Show device info as last-known data with "Device no longer monitored" label |
| EC-04 | AI recommendation not available | Show generic guidance: "Review your security logs for this event type" — no empty state |
| EC-05 | Block device fails (device already offline) | Error toast: "Device may already be offline. Check device status." |
| EC-06 | Zero active alerts | Empty state on AL-01: green shield icon \+ "No active alerts. Your network looks clean." |
| EC-07 | 100+ alerts in list | Paginate (load 20 at a time) with "Load more" at bottom. Show total count in section header. |
| EC-08 | Security scan already in progress for device | "A scan is already running for this device. View results when complete." |
| EC-09 | Push notification tapped when app is already on Alert Detail | Refresh the current alert detail with latest data |

