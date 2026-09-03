You are building a mobile web application called **SG-X Guardian** for a company called **Cervais** — a critical infrastructure cybersecurity company whose clients include power plants, factories, oil & gas facilities, and federal defense sites across the United States.

This is NOT a desktop app. This is NOT a native iOS or Android app. This is a **mobile browser web application** — it runs in Safari on iPhone and Chrome on Android. It is accessed via a URL. The entire UI is designed for a phone screen. Base width is **390px** (iPhone 14). It must work across 360px to 430px viewport widths. Every single screen you build must be mobile-first, touch-first, and optimized for one-handed use.

---

## The Story

The primary user is a field security engineer named Marcus. He is 34 years old. He works at an energy facility in Texas managing the physical security of industrial networks. He carries his phone while walking factory floors, checking equipment, and responding to incidents. He opens this app up to 8 times a day. Most of his sessions are under 30 seconds. He needs to open the app and know in 3 seconds whether his network is safe or not.

When a high severity security alert fires — say, a service account being used for unauthorized login at 9am — Marcus gets a push notification on his phone. He taps it. The app opens directly to that alert. He needs to immediately see: what happened, which device was affected, what the IP address was, what the it recommends, and what action to take. He cannot afford confusion. He cannot afford to dig through menus. He is a security professional, not a casual user, and the app must treat him like one.

The secondary user is Sofia. She is 41, the security team lead. She manages who has access to the team's secure network — called a Circle of Trust. She invites new engineers, removes people who leave, and coordinates incident response over secure voice calls. She uses the app from her office, sitting down, two-handed. She notices every visual inconsistency and will report them. She cares about polish, confirmation dialogs on destructive actions, and clear status information about her team members.

This app must feel like a professional security tool. It must feel precise, reliable, and calm under pressure. It must never feel like a consumer app, a startup MVP, or a marketing page. Every design decision should communicate trust and competence.

---

## The Tech Stack — Follow This Exactly

- **React**
- **shadcn/ui components ONLY** — do not use any other component library
- **Tailwind CSS ONLY** — do not write custom CSS
- **Radix UI primitives** — only through shadcn/ui
- **shadcn default color palette ONLY** — do not introduce any custom hex codes, custom CSS variables, or brand colors. Use the shadcn dark theme default colors as-is. No exceptions.
- **lucide-react** for all icons — this comes with shadcn
- **JetBrains Mono** font for DID strings and code values only — everything else uses the shadcn default font stack
- Do not add any animation libraries. Use only shadcn's built-in transitions.
- Do not add any charting libraries unless explicitly asked.

---

## The App Structure

The app has a **persistent bottom navigation bar** with 5 tabs. This bottom nav is always visible except during the Onboarding flow. The 5 tabs are:

1. **Home** — Dashboard
2. **Alerts** — Security alerts and threat intelligence
3. **Network** — Circle of Trust management
4. **Devices** — Connected device management
5. **Settings** — Account and Guardian configuration

Every screen in the app must handle **5 states**:
- **Loading** — use shadcn Skeleton components shaped like the content that will load. Never use a centered spinner.
- **Populated** — normal data view
- **Empty** — centered icon (lucide-react) + short heading + one line of subtext + optional single CTA button
- **Error** — clear error message + retry button
- **Offline** — a persistent warning bar pinned to the very top of every screen that reads: "Guardian offline — last seen [timestamp]". This never blocks content — stale cached data still shows beneath it. Action buttons that require a live connection are disabled and show a tooltip explaining why.

---

## Every Screen to Build

Build every screen below. Do them in order. Keep the same component system throughout — never break the system mid-build.

### ONBOARDING (bottom nav hidden, linear wizard, progress dots at top)

**OB-01 Welcome Screen**
Full screen. Cervais logo at top. App name "SG-X Guardian" large and bold. Tagline below: "Your Guardian. Secured. In your hands." One primary CTA button: "Get Started". One subtle text link below: "Learn More".

**OB-02 Hardware Pairing**
Two equally weighted options presented as cards: "Scan QR Code" (activates camera, shows QR viewfinder overlay with corner guide brackets) and "Enter Serial Number" (shows text input). Helper text below camera option: "Allow camera access when prompted". Progress dots show step 1 of 5.

**OB-03 Connecting**
Loading state only. Text: "Connecting to your Guardian..." with shadcn Skeleton animation. Below that, three progress steps shown as a vertical list — each with a check icon when complete and a loading indicator when in progress: "Guardian found on network", "Verifying device identity", "Establishing secure connection".

**OB-04 Pairing Success**
Success state. Guardian device name shown prominently. Device ID shown in monospace below. Connection type shown (e.g. WiFi). Green check icon. Single CTA: "Continue".

**OB-05 Pairing Failed**
Error state. Clear heading: "Couldn't connect to Guardian". One line of subtext explaining what to check. Three options: "Try Again" (primary button), "Get Help" (secondary button), "Skip for now" (text link, visually de-emphasized).

**OB-06 Account Setup**
Toggle at top between "Create Account" and "Log In". Email input. Password input with show/hide toggle. Password requirements shown inline as user types. Single CTA button matching the active toggle. No "confirm password" field.

**OB-07 DID Introduction**
Heading: "Your Secure Identity". One short plain-language paragraph: "Your DID is your unique identity on this network. Share it with teammates so they can invite you to their Circles." DID string shown in a shadcn Card using JetBrains Mono font, full string never truncated, Copy button right-aligned in the same row. On copy: shadcn Toast — "DID copied to clipboard". Expandable section below: "What is a DID?" with a two-sentence plain-language answer. Single CTA: "Continue".

**OB-08 Create First Circle (optional)**
Heading: "Create Your First Circle". Short explanation: "A Circle is your trusted team group. Add teammates to share alerts, chat securely, and coordinate responses." Circle Name input (required). Description input (optional, multiline). Primary CTA: "Create Circle". Text link below: "Skip for now". Expandable: "What is a Circle?"

**OB-09 Onboarding Complete**
Celebration screen. Heading: "You're all set." Checklist showing what was completed — each item with a green check: Guardian connected, Account created, DID copied, Circle created (or skipped). Single large primary CTA: "Go to Dashboard".

---

### HOME

**HM-01 Dashboard**
Top: Guardian device card — device name, green online dot, connection type (WiFi/Cellular/etc), signal strength with icon, peer count. Below that: Security Health Score — a large circular progress ring showing a number 0–100, label beneath it ("Secure" / "At Risk" / "Critical" depending on score range). Below that: Active Alerts summary card — count of HIGH severity alerts in red, count of MEDIUM in amber, "View All Alerts" link. Below that: Quick Actions row — two buttons side by side: "Scan Network" and "View Topology". Below that: Your Circles card — number of circles, number of members online, "View All" link. Build all 5 states: loading (skeletons for each card), populated, empty (no Guardian connected), error, offline banner.

**HM-02 Guardian Detail**
Full screen pushed from Dashboard. Guardian name as page title. Sections: Device Info (firmware version, uptime, device ID) and Connection (type, signal strength, last seen). All in shadcn Cards with shadcn Separator between sections. Back arrow in header.

**HM-03 Network Topology View**
Full screen. Visual graph — Guardian node at center, connected peer nodes around it. Each node is a circle with device name below. Connection lines between nodes. Connection type label on each line. Tap a node to see a small popover with name, DID preview, online status. Empty state: "No peers connected. Create a Circle to see your network." Loading state: pulsing skeleton graph.

**HM-04 Quick Scan Bottom Sheet**
shadcn Sheet sliding up from bottom. Title: "Scanning Network". Progress bar. List of discovered devices appearing one by one as they are found. "X new devices found" count updates live. "Done" button appears when scan completes.

---

### ALERTS

**AL-01 Alerts Root**
Top section (not scrollable): Threat Intelligence panel — four stat blocks in a 2x2 grid: Threat Score (large number, green/amber/red depending on value), Threats 24h (count), Blocked (count), Quarantined (count). Below (scrollable): "Recent Events (X)" heading with Select button and View Archived button top right. Search input. Three filter dropdowns in a row: All Severities, All Statuses, All Types. Alert list below. Each alert row: clock icon left, title bold, description one line muted below, severity badge right, timestamp right, delete icon far right, chevron for expand. Build all 5 states.

**AL-02 Filtered Alerts**
Same as AL-01 but with active filter chips shown below the dropdowns. "Clear all" link at end of filter chips row.

**AL-03 Bulk Select Mode**
Same list but checkboxes appear left of each row. "Select All" row at very top of list. "Cancel" replaces Select button in header. Bottom action bar slides up with: "Archive Selected" and "Delete Selected" buttons.

**AL-04 Archived Alerts**
Same layout as AL-01 but heading says "Archived Events". "View Active" button replaces "View Archived". Empty state: shield icon + "No archived alerts yet."

**AL-05 Alert Row Expanded Inline**
Alert row expanded in-place. Shows: Event Type label + value, Status label + value, Archive Event button (shadcn Button). Chevron rotates to point up.

**AL-06 Alert Detail Full Screen**
Pushed as a new screen. Header: back arrow + severity badge. Large title. Description. Divider. Section: "Affected Device" — device name bold, IP address muted below, OS muted, "View Device →" link. Divider. Section: "Recommendation" — badge label, two-sentence summary in italics, "View Full Analysis →" link. Divider. Bottom: large primary button "Take Action" that opens AL-08.

**AL-07 Recommendation Panel**
Full screen. Sections: "What Happened" (plain language paragraph), "Why It Matters" (plain language paragraph), "Recommended Actions" (numbered list using shadcn ordered list styling, each item is an actionable step). Back arrow in header.

**AL-08 Remediation Actions Sheet**
shadcn Sheet. Title: "Take Action". Four options as full-width buttons stacked vertically: "Archive Event" (default variant), "Block Device from Network" (warning/amber variant), "Run Security Scan" (secondary variant), "View Affected Device" (ghost variant). Each button has an icon left and a one-line description in muted text below the label.

---

### NETWORK

**NW-01 Circles List**
Page title: "Your Circles". Count below title: "X circles". Create button top right (+). Each circle as a shadcn Card: circle name bold, member count muted, online count with green dot, two buttons: "Chat" and "Members". Empty state: people icon + "No circles yet" + "Create your first Circle" CTA button.

**NW-02 Create Circle Form**
Page title: "Create New Circle". Centered icon at top (people icon in a circle). Subheading: "Create a secure group to connect with your trusted peers." Info card below (shadcn Card with border): "Circle Network" heading, description of P2P communication. Circle Name input. Description textarea (optional). Create Circle primary button. Four green check items below button: Certificate Authority will be generated, Circle network will be configured, Your Guardian will join automatically, Network relay enabled. Expandable: "What is a Circle?"

**NW-03 Create Circle Loading**
Same screen as NW-02 but button replaced with loading state: "Creating Circle..." with spinner icon in button. Info card below replaced with: "Initializing Circle network... This may take a moment." with loading animation.

**NW-04 Circle Detail — Chat Tab**
Page title is circle name. Three tabs: Chat, Calls, Members. Chat tab active. Message list in scrollable area — messages right-aligned for sent, left-aligned for received, timestamp below each, read receipt indicator. Compose input pinned to bottom with send button. Empty state: chat bubble icon + "No messages yet" + "Send your first message".

**NW-05 Circle Detail — Calls Tab**
Calls tab active. Two large full-width buttons: "Start Voice Call" (green variant) and "Start Video Call" (purple — use shadcn secondary or violet if in default palette). Call history list below with call type icon, participant name, duration, timestamp. Empty state: phone icon + "No call history".

**NW-06 Circle Detail — Members Tab**
Members tab active. "Invite Member" full-width teal/primary button at top. Member list below — each member: avatar initials, name bold, email muted, role badge (Owner/Member), online status dot + "online"/"offline" text, last seen timestamp. Pending invites shown with amber "Pending" badge.

**NW-07 Circle Detail — Topology Tab**
Topology tab active. Same visual graph as HM-03 but scoped to this Circle's peers only.

**NW-08 Member Detail**
shadcn Sheet. Member name as title. Sections: DID (monospace card with copy button), Connection Type, Last Seen, Guardian Status (health score). Destructive button at bottom: "Remove from Circle".

**NW-09 Invite Modal**
shadcn Sheet. Title: "Invite to [Circle Name]". Three tabs: Share Link (default active), QR Code, Search DIDs.

**NW-10 Invite — Share Link Tab**
"Share your invite link" info card. Invite Code: large monospace block with copy button. Shareable Link: smaller monospace with copy button. Large primary "Share Invite" button (triggers native share). Divider. "Or record an invitation" — email input + "Record" button. Tip at bottom: "Users need to have SG-X Guardian installed to join."

**NW-11 Invite — QR Code Tab**
Large QR code centered. "Share this QR code for quick access" caption. Invite code shown in text below QR. Large "Share QR Code" primary button.

**NW-12 Invite — Search DIDs Tab**
Info card: "DID-Based Discovery" — plain explanation. Search input: "Search by DID or user ID..." + Search button. Results list below. Not found state inline. Invalid format inline error.

**NW-13 Remove Member Confirmation**
shadcn Dialog (not Sheet — this is a blocking confirmation). Title: "Remove [Name]?" Body: "They will lose access to this Circle's chat, calls, and shared security data. This cannot be undone." Cancel button + Confirm (destructive red) button.

---

### DEVICES

**DV-01 Devices List**
Page title: "Connected Devices". Guardian card at top (same as Dashboard card — always visible). Two action buttons row: "Scan Network" (purple/primary) and "+ Add Manually" (secondary). Filter tabs row: All Devices, Regular, Drones, Smart Home, Pending (with badge count), Service Access. Search input. Device list below — each device card: device type icon, device name bold, manufacturer + protocol muted, Online/Offline badge, Secure/Unsecured badge, Encrypted/Unencrypted label with icon, firmware version muted, security score right-aligned, privacy score right-aligned, vulnerability count in red if >0.

**DV-02 Pending Approvals**
Same layout filtered to pending devices. Each pending device card shows Approve button (green) and Reject button (red/destructive) directly on the card. Swipe right gesture = approve (green reveal), swipe left = reject (red reveal).

**DV-03 Device Detail — Info**
Three score cards in a row at top: Security score (number + label), Privacy score (number + label), Vulnerabilities (count, red if >0). Device Information section below in a shadcn Card as a labeled table: Manufacturer, Model, Protocol, MAC Address, IP Address, Firmware Version. Guardian Monitoring toggle at bottom of card.

**DV-04 Device Detail — Security Features**
shadcn Card: three rows — Encryption (Enabled green / Disabled red), Auto-Update (Enabled/Disabled), Connectivity (type). If vulnerabilities exist: red-bordered shadcn Card below with "X Vulnerabilities Detected" heading, description, bullet list of recommendations.

**DV-05 Device Detail — Actions**
Three full-width stacked buttons: "Run Security Scan" (primary), "Block from Network" (warning/amber variant, icon: ban), "Remove Device" (destructive/red, icon: trash).

**DV-06 Security Scan In Progress**
Full screen loading. Device name as title. Progress bar. Checklist of scan steps appearing one by one with check icons as they complete: Checking firmware version, Checking open ports, Checking encryption status, Checking known vulnerabilities. "This may take a moment..." muted text.

**DV-07 Scan Results**
"Scan Complete" as title. Vulnerability count summary at top — number large, severity breakdown below (X High, X Medium, X Low). Recommendations list — each item as a shadcn Card with icon, title, description. "View Device" and "View Alerts" buttons at bottom.

**DV-08 Block Device Confirmation**
shadcn Dialog. Title: "Block [Device Name]?" Body explains consequence: device will lose network access immediately. Cancel + Confirm (destructive) buttons.

**DV-09 Remove Device Confirmation**
shadcn Dialog. Title: "Remove [Device Name]?" Body: "This device will be removed from Guardian monitoring. This cannot be undone." Cancel + Confirm (destructive) buttons.

**DV-10 Add Device Form**
shadcn Sheet. Title: "Add Device". Fields: Device Name (required), Device Type (shadcn Select dropdown: Phone/Computer/IoT/Camera/Switch/Router/Drone/Other), Connection Method (shadcn Select: WiFi/Ethernet/Bluetooth/Cellular/Zigbee/Z-Wave), MAC Address (required, auto-formats XX:XX:XX:XX:XX:XX as user types), IP Address (optional), Manufacturer (optional), Model (optional), Operating System (optional). Cancel + Add Device buttons at bottom.

**DV-11 Smart Home — Hubs**
shadcn Sheet. Title: "Smart Home Integration". Four tabs: Hubs, Dongles, Cloud, Rules. Hubs tab active. Two buttons: "Start Service" (green) / "Stop Service" (red) toggle, and "Discover Hubs". Recent Activity log below — timestamped list of activity entries. When hubs are discovered: "Discovered Hubs" list appears with hub name, IP, and Add button per hub.

**DV-12 Smart Home — Dongles**
Dongles tab. List of USB dongles with type, status, remove option. Empty state: "No USB dongles detected. Connect a dongle to your Guardian's USB port."

**DV-13 Smart Home — Cloud Services**
Cloud tab. Info card: "Connect cloud-based smart home services. Your credentials are encrypted and stored securely on your Guardian." 2-column grid of service cards: Ring Security, Google Nest, Wyze, Ecobee, TP-Link Kasa, Arlo. Each card: emoji icon, service name, description one line, Connect button. Connected services show green "Connected" badge and Disconnect option instead.

**DV-14 Smart Home — Rules**
Rules tab. Info card: "Device Automation — Create rules to automatically control your smart home devices based on security events, time schedules, location, or sensor readings." Manage Automation Rules primary button. 2x2 grid of rule type cards: Security Triggers (shield icon, "Lock doors when threat detected"), Schedules (clock icon, "Turn lights on/off at specific times"), Geofencing (pin icon, "Actions when leaving/arriving"), Sensors (thermometer icon, "React to sensor readings"). Recent Activity log at bottom.

---

### SETTINGS

**ST-01 Settings Root**
Page title: "Settings". Guardian selector card at top (device name, connected status dot, DID preview truncated). Grouped settings list using shadcn Separator between groups:

GROUP — Account: Profile, Data Usage, Backup & Restore
GROUP — Network: Network Topology
GROUP — Physical Security: Location & Geofencing
GROUP — Device: Device Pairing, Manage Guardians, Device Settings, Dual Wi-Fi Mode
GROUP — Notifications: Notification Preferences, Custom Alert Rules
GROUP — Help & Support: Quick Start Guide, App Version

Each row: icon left, label, chevron right. Destructive red "Logout" full-width button at very bottom. App version label below that in muted small text.

**ST-02 Guardian Info + DID**
Page title: "Settings". Subtitle: "Device Mode". User avatar + name + email at top. "Viewing settings for:" label, then Guardian device card (name + online dot). "My Decentralized Identifier (DID)" section: DID string in shadcn Card with JetBrains Mono, never truncated, Copy button right-aligned. Helper text below: "Share this DID with others to receive Circle invitations." What is a DID expandable. Connection Type Select (auto-detected, shows current type). Signal Strength Select.

**ST-03 Profile**
Name field, email field, avatar upload area. Edit mode toggled by pencil icon in header. Save button appears when in edit mode.

**ST-04 Data Usage**
Two sections: App data and Guardian sync data. Each shows usage in MB/GB for the current month. Reset period shown.

**ST-05 Backup & Restore**
Two full-width buttons: "Create Backup" (primary) and "Restore from Backup" (secondary). Last backup timestamp shown. Restore triggers a file picker and then a confirmation Dialog.

**ST-06 Network Topology**
Full screen, same component as HM-03.

**ST-07 Location & Geofencing**
Map view (placeholder if no map library — show a card with coordinates). Add Zone button. List of existing geofence zones each with name, radius, actions (edit/delete).

**ST-08 Device Pairing**
Same as OB-02 but in Settings context. Warning card above: "Re-pairing will replace the currently connected Guardian."

**ST-09 Manage Guardians**
List of paired Guardian devices. Each: name, last seen, online/offline, "Set as Primary" option, Remove option. Add Guardian button at top.

**ST-10 Device Settings**
Placeholder screen with "Device Settings" title and coming soon state if no spec available.

**ST-11 Dual Wi-Fi Mode**
Toggle with label and description. Current configuration shown below if enabled.

**ST-12 Notification Preferences**
Grouped toggle list: Alert Notifications (HIGH — on, MEDIUM — on, LOW — off), Device Notifications (New device discovered — off, Pending approvals — on, Guardian offline/online — on), Circle Notifications (New messages — on, Incoming calls — on, New member joined — off). All toggles auto-save on change. No Save button needed.

**ST-13 Custom Alert Rules**
List of existing rules each with toggle (on/off), rule name, delete icon. "New Rule +" button at top. Rule builder Sheet: When (event type Select + condition Select + value input), Then (action Select), Notify (who Select + method Select).

**ST-14 Quick Start Guide**
In-app help content. Sections as shadcn Accordion: What is SG-X Guardian, What is a Circle of Trust, What is a DID, How to add a device, How to triage an alert, How to invite a team member.

**ST-15 App Version**
Simple screen: App version number large, build date below, changelog link.

**ST-16 Logout Confirmation**
shadcn Dialog. Title: "Log Out?" Body: "You will need to enter your credentials to access SG-X Guardian again." Cancel + Log Out (destructive) buttons.

---

### GLOBAL SYSTEM SCREENS

**SYS-01 Offline Warning Banner**
Sticky bar pinned to top of every screen when Guardian is unreachable. Amber background (shadcn warning colors). Text: "Guardian offline — last seen [time]". Never blocks content below.

**SYS-02 Splash Screen**
Full screen. App logo centered. Loading bar or pulsing animation. Cervais name below logo.

**SYS-03 Global Error Screen**
Full screen error for catastrophic failures. Error icon. "Something went wrong" heading. One line description. "Try Again" primary button.

**SYS-04 Empty State Component**
Reusable component. Props: icon (lucide), heading (string), subtext (string), ctaLabel (optional string), ctaAction (optional function). Centered vertically in available space.

**SYS-05 Toast Notifications**
shadcn Toast configured for 4 variants: success (check icon), error (x icon), warning (triangle icon), info (info icon). Position: bottom of screen (above bottom nav). Auto-dismiss after 3 seconds.

---

## Hard Rules — Never Break These

- shadcn/ui components only — no other UI library
- shadcn default color palette only — no custom hex codes ever
- No gradients unless they exist in shadcn defaults
- No custom animations — shadcn built-in transitions only
- Mobile only — 390px base — never build desktop layouts
- Every touch target minimum 44x44px
- No hover-only states — everything works on touch
- Every screen must handle all 5 states: loading (skeletons), populated, empty, error, offline
- DID strings always in JetBrains Mono, never truncated, always have a copy button
- Destructive actions (delete, remove, block, logout) always require a shadcn Dialog confirmation
- Guardian Simulator does not exist — do not build it
- No placeholder lorem ipsum — use realistic security product content
- Bottom nav always visible except during Onboarding screens OB-01 through OB-09
