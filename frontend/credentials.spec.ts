# **User Personas**

# **Overview**

This document defines the two primary user personas for the SG-X Guardian mobile web application. These personas are grounded in the product's real-world deployment context — critical infrastructure environments (energy, manufacturing, healthcare, federal/defense) — and are used as the foundation for all UX, IA, and design decisions throughout this engagement.

Every design decision in this project should be evaluated against one question:

**"Does this make Marcus's or Sofia's job faster, clearer, or safer?"**

---

## **Persona 1 — Marcus Webb**

### **The Field Security Engineer**

---

┌─────────────────────────────────────────────────────────────────┐
│ │
│ Marcus Webb │
│ Age: 34 │
│ Role: Field Security Engineer │
│ Industry: Energy / Power Generation │
│ Location: Texas, USA │
│ Experience: 8 years in OT/ICS security │
│ │
│ "I need to know my network is protected before I can │
│ focus on anything else." │
│ │
└─────────────────────────────────────────────────────────────────┘

---

### **Who Is Marcus?**

Marcus is a senior field security engineer at a regional energy company that operates several power generation and transmission facilities across Texas. He is responsible for deploying, configuring, and maintaining SG-X Guardian devices across multiple substations and control rooms.

He is technically proficient — he understands networking, cryptography at a working level, and OT/ICS protocols. But he is not a software developer. He does not want to read documentation to understand a dashboard. He needs the app to tell him what's happening and what to do next, immediately.

Marcus is the **primary user** of the SG-X Guardian mobile app. He is the person we are designing for first.

---

### **Demographics & Context**

| Attribute | Detail |
| ----- | ----- |
| **Age** | 34 |
| **Education** | B.S. Computer Science \+ GICSP (Global Industrial Cyber Security Professional) certification |
| **Technical Level** | High — understands networking, Linux, basic cryptography, OT protocols |
| **Device** | iPhone 14 Pro (personal) \+ company-issued Android tablet for site work |
| **Connectivity** | Variable — good LTE at main facilities, weak signal at remote substations |
| **Work Environment** | Mix of office and field — often checking phone while walking a facility floor |
| **Team Size** | Works with a team of 4–6 security engineers |
| **Guardian Devices Managed** | 1–3 SG-X devices across his assigned sites |

---

### **A Day in Marcus's Life**

**7:30 AM** — Arrives at the substation control room. First thing: opens SG-X Guardian on his phone to check overnight alerts. Wants to know in 5 seconds: "Is everything okay?"

**9:15 AM** — Receives a push notification: HIGH severity alert — "Service Account Abuse Detected." He's in the middle of a walkthrough. Opens the app one-handed, needs to immediately understand what device is affected, what the threat is, and whether he needs to stop what he's doing.

**11:00 AM** — Adds a new PLCs (Programmable Logic Controller) to the Guardian's monitored device list. Scans the network, finds the device, approves it.

**2:30 PM** — Gets a call from his team lead Sofia. She's added him to a new Circle for their incident response team. He needs to accept the invite — she sent it as a link.

**4:45 PM** — End of day check: reviews the day's security posture, confirms no outstanding HIGH alerts, checks that the Guardian's battery and connection are healthy.

---

### **Goals**

| Priority | Goal |
| ----- | ----- |
| Primary | Know immediately whether his Guardian is healthy and connected |
| Primary | Identify, understand, and act on security alerts quickly |
| Secondary | Manage devices connected to the Guardian (approve, scan, block) |
| Secondary | Stay connected with his security team via Circles |
| Tertiary | Review security posture and compliance at end of day |

---

### **Pain Points (with Current App)**

| Pain Point | Severity | Detail |
| ----- | ----- | ----- |
| Dashboard doesn't communicate health at a glance | Critical | He has to read 4 separate cards to understand if things are okay. There's no "all clear" or "action needed" signal. |
| Alert details are too thin | Critical | When he expands an alert, he sees the event name and status. He needs to know: which device? what IP? what protocol? what should he do? |
| DID invite system is confusing | High | When Sofia sent him a Circle invite, he didn't know what a DID was or where to find his own. |
| App opens to raw data, not status | High | The current dashboard feels like a data dump. He wants a health score, not a list of metrics. |
| Guardian Simulator in the UI | Medium | He's accidentally tapped it twice thinking it was something else. It has no business being in a production app. |
| No search | Medium | When he has 50 devices listed, he can't search by name. He scrolls. |

---

### **Needs from the Redesigned App**

| Need | Design Implication |
| ----- | ----- |
| **Security health at a glance** | Dashboard must lead with a single Health Score ring (0–100) that gives an instant yes/no on system status |
| **Actionable alert detail** | Alert expanded view must include: device name, IP address, protocol, AI recommendation, and one-tap remediation options |
| **Clear connection status** | Guardian device card must always show: connected/disconnected, battery %, signal strength, last seen timestamp |
| **Fast one-handed navigation** | All primary actions must be reachable within 2 taps from the bottom nav. No buried menus. |
| **Offline awareness** | If the Guardian is unreachable, the app must say so clearly — not just show stale data silently |
| **Plain-language DID explanation** | First time Marcus sees his DID or needs to share it, the app must explain it in one sentence |

---

### **Behaviors & Patterns**

* Opens the app **5–8 times per day** — mostly quick status checks (\< 30 seconds)
* Has **2–3 longer sessions per week** — device management, Circle setup, settings changes
* Prefers **dark mode** always — easier on eyes in dimly lit control rooms
* Gets **frustrated by loading states** — if the app takes \> 3 seconds to show data, he loses confidence in it
* **Does not read help documentation** — the UI must be self-explanatory
* Uses **Face ID / fingerprint** to unlock his phone — expects the app to load instantly after unlock

---

### **Quote**

*"I don't need a pretty dashboard. I need to open the app and know in three seconds if my network is safe. Everything else is secondary."*

---

### **Marcus's App Journey Map**

TRIGGER ACTION EXPECTATION CURRENT REALITY REDESIGN TARGET
──────────── ───────────────── ───────────────── ───────────────── ─────────────────
Morning check Opens app See health status Reads 4 cards Health Score ring
 in 3 seconds to understand shows 94/100

Alert push Taps notification See full alert See event name Full detail:
notification → alert detail context \+ action \+ status only device, IP, AI rec

New device Devices → Scan Auto-discovers Works but slow Same \+ better
on network Network device feedback states empty/loading states

Team invite Circle → Invite Understands DID Confused by Plain language
from lead arrives and accepts DID concept DID explainer

End of day Opens Dashboard Confirm all clear Re-reads 4 cards Green health ring
check → Settings again \+ "All systems OK"

---

---

## **Persona 2 — Sofia Reyes**

### **The Circle Admin / Security Team Lead**

---

┌─────────────────────────────────────────────────────────────────┐
│ │
│ Sofia Reyes │
│ Age: 41 │
│ Role: OT Security Team Lead / Circle Admin │
│ Industry: Manufacturing │
│ Location: Chicago, Illinois │
│ Experience: 14 years in industrial cybersecurity │
│ │
│ "My job is to make sure my team is coordinated and │
│ that our trust boundary is never compromised." │
│ │
└─────────────────────────────────────────────────────────────────┘

---

### **Who Is Sofia?**

Sofia is the OT security team lead at a mid-sized automotive parts manufacturer. She manages a team of 5 security engineers (including people like Marcus) who are distributed across multiple factory floors. She is responsible for the overall security posture of the OT environment and for managing the Circle of Trust that connects her team's Guardian devices.

Sofia is more strategic than Marcus. She spends less time in the field and more time coordinating, reviewing posture reports, and managing who has access to what. She uses the Guardian app to manage her team's Circle — membership, communications, and incident coordination — rather than day-to-day device monitoring.

Sofia is the **secondary user** — but she is the one who sets up the Circle that Marcus and his colleagues operate inside. Her actions in the app affect the entire team.

---

### **Demographics & Context**

| Attribute | Detail |
| ----- | ----- |
| **Age** | 41 |
| **Education** | M.S. Information Security \+ CISSP certification |
| **Technical Level** | Very high — deep understanding of PKI, zero-trust, OT protocols, compliance frameworks |
| **Device** | Samsung Galaxy S24 (personal) \+ MacBook Pro for desk work |
| **Connectivity** | Reliable WiFi at office; uses app mostly from desk or conference room |
| **Work Environment** | Primarily office-based with occasional factory floor visits |
| **Team Size** | Manages 5 direct reports across 3 factory sites |
| **Guardian Devices Managed** | 1 Guardian for her own site; oversees team's Guardian usage |

---

### **A Day in Sofia's Life**

**8:00 AM** — Reviews the security posture of her site's Guardian. Checks if any HIGH alerts went unresolved overnight. If yes, assigns to team member.

**10:30 AM** — A new contractor team starts work today. She needs to add 2 new members to the incident response Circle so they can access the secure comms channel. She invites them via Share Link — easier than DID for external parties.

**1:00 PM** — Monthly security review meeting. She pulls up the AI Threat Intelligence panel to walk through the last 30 days of threat activity with her manager.

**3:15 PM** — One of her engineers (Marcus) reports a suspicious device appeared on the network. They coordinate over the Circle's secure voice call while Marcus investigates on-site.

**5:00 PM** — Reviews pending device approvals in Devices → Pending tab. Approves 3 devices flagged by the network scan.

---

### **Goals**

| Priority | Goal |
| ----- | ----- |
| Primary | Manage Circle membership — who's in, who's out, invites, permissions |
| Primary | Coordinate incident response with her team over secure comms |
| Secondary | Review and communicate security posture to management |
| Secondary | Approve or reject devices pending Guardian admission |
| Tertiary | Stay aware of active alerts even if she's not the first responder |

---

### **Pain Points (with Current App)**

| Pain Point | Severity | Detail |
| ----- | ----- | ----- |
| Invite flow is technically intimidating for external invitees | Critical | When she sends a DID-based invite to a contractor, they have no idea how to respond. Share Link works better but isn't the default. |
| No member status context | High | Members tab shows name \+ email \+ online/offline. She wants to see: last active, their Guardian's status, their connection type. |
| Chat is too bare | High | The chat UI has no message threading, no file sharing indication, no read receipts. For incident response, she needs to know if her message was seen. |
| No Circle-level security overview | High | She wants to see a summary of all members' Guardian health at a glance — not just her own. |
| Call UX feels disconnected from brand | Medium | The green/purple call buttons feel like a different app entirely. |
| No way to remove a member gracefully | Medium | Removing a member feels abrupt — there's no confirmation, no notification to the removed person. |

---

### **Needs from the Redesigned App**

| Need | Design Implication |
| ----- | ----- |
| **Invite-first design for Circles** | Share Link should be the default invite method (not DID search). DID is advanced — put it behind a "More options" toggle. |
| **Member context in Members tab** | Each member card should show: name, role, online status, last seen, connection type |
| **Chat with delivery indicators** | Message sent → delivered → read indicators. Timestamps on all messages. |
| **Voice call clarity** | Clear in-call UI with mute, speaker, end call. Remove "Simulate Incoming Call (Test)" from production. |
| **Pending device review** | Clear badge count on Devices tab when devices await approval |
| **Circle health summary** | Optional: a "team posture" view showing all members' Guardian health in one list |

---

### **Behaviors & Patterns**

* Opens the app **2–4 times per day** — mostly for Circle management and posture review
* Has **1–2 longer sessions per week** — adding members, reviewing devices, coordinating incidents
* Tends to use the app in **landscape or two-handed** — she's usually sitting, not walking
* **Reads UI labels carefully** — she notices inconsistencies and mislabels. She will report them.
* Is the person most likely to **share screenshots** of the app with her management team — the app needs to look polished enough to appear in a senior executive meeting
* Cares deeply about **confirmation dialogs** for destructive actions (remove member, delete circle, block device)

---

### **Quote**

*"When I'm coordinating an incident, I don't have time to wonder if my message went through or if my team can see the same alert I'm looking at. The app needs to be as reliable and clear as the hardware it's controlling."*

---

### **Sofia's App Journey Map**

TRIGGER ACTION EXPECTATION CURRENT REALITY REDESIGN TARGET
──────────── ───────────────── ───────────────── ───────────────── ─────────────────
New contractor Circles → Easy invite via DID search is Share Link is
joins team Members → link or QR default, confusing default method
 Invite Member (no DID needed) for non-tech users

Incident Circle → Calls Clear voice call Works but green/ Brand-aligned
response → Voice Call UI, mute/speaker purple buttons call UI with
call needed clearly labeled feel off-brand clear controls

Monthly Alerts → AI Clear 30-day Panel exists and Enhanced panel
posture Threat Intel summary to show works — but lacks with trend
review panel to management trend visualization charts \+ export

Device Devices → See pending list Pending tab exists Badge count on
approval Pending tab with enough but device context nav \+ richer
needed → approve context to decide is thin device cards

Team check-in Network → See all members' Only shows own Optional "team
(morning) Circles → Guardian health device status posture" view
 \[Circle\] → Members at a glance per Circle

---

## **Persona Comparison**

| Attribute | Marcus (Field Engineer) | Sofia (Circle Admin) |
| ----- | ----- | ----- |
| **Primary use** | Device monitoring \+ alert triage | Circle management \+ team coordination |
| **Session frequency** | 5–8x/day | 2–4x/day |
| **Session length** | Short (\< 1 min) \+ occasional long | Medium (2–5 min) |
| **Context of use** | Walking, one-handed, field | Sitting, two-handed, office |
| **Most used section** | Home \+ Alerts | Network (Circles) \+ Devices |
| **Biggest frustration** | No health-at-a-glance | Invite flow too technical |
| **Technical comfort** | High | Very High |
| **Design sensitivity** | Low (function \> form) | High (notices polish \+ consistency) |
| **Destructive action caution** | Medium | High (wants confirmations) |
| **Key design priority** | Speed \+ clarity | Reliability \+ polish |

---

## **Design Implications Summary**

These personas directly drive the following design decisions:

| Decision | Driven By | Rationale |
| ----- | ----- | ----- |
| Dashboard leads with Health Score ring | Marcus | Single glanceable status metric |
| Share Link is default invite method | Sofia | Less friction for external invitees |
| Alert detail includes device \+ IP \+ AI recommendation | Marcus | Needs context to act without leaving app |
| DID has plain-language explainer on first encounter | Marcus | Non-developer user confused by DID concept |
| Confirmation dialogs on all destructive actions | Sofia | She notices and reports missing confirmations |
| Bottom nav always accessible | Marcus | One-handed field use |
| Chat shows delivery \+ read indicators | Sofia | Incident coordination requires message confidence |
| Guardian Simulator removed from production | Marcus | He accidentally tapped it — not a user feature |
| Members tab shows last seen \+ connection type | Sofia | Needs team context not just online/offline |
| Min touch target 44px on all interactive elements | Marcus | Gloved hands, field conditions, WCAG AA |

