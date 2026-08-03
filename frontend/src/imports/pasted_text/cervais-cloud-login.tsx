You are continuing to build the SG-X Guardian app — a mobile security application for field engineers who protect critical infrastructure like power plants, factories, and defense facilities.
The app is already built. You have the existing screens. You are now adding new features that the client (Cervais, the company that makes the SG-X hardware device) has specifically requested after reviewing the first version.
Stack: React + shadcn/ui + Tailwind only. shadcn default dark theme colors only. Mobile browser, 390px base. No custom colors ever.

THE STORY BEHIND EACH ADDITION

ADDITION 1 — CYLENIUM CLOUD ON THE LOGIN SCREEN
Cervais makes their own cloud platform called Cylenium Cloud. Think of it like how AWS has its own dashboard — Cervais has Cylenium where enterprise clients can monitor all their Guardian devices from one place.
Right now when Marcus opens the app for the first time, he sees a sign up screen — enter email, create password. That's fine. But if Marcus already has a Cylenium Cloud account (which many enterprise users will), he should be able to just tap one button and be instantly authenticated — his Guardian gets linked to his Cylenium account automatically, no separate steps.
It works exactly like "Continue with Google" on any modern app. Simple, fast, one tap.
What to build on the Account Setup screen:
Keep everything that exists — the Create Account / Log In toggle, email input, password input, primary button. Just add below the primary button:

A thin divider line with the word "or" in the center
A new button: "Continue with Cylenium" — secondary/outline style, full width, with the Cervais shield icon on the left

Three things that can happen when Marcus taps "Continue with Cylenium":
Thing 1 — It works, he's a new user:
Show a brief success moment on the same screen — green check, "Cylenium account connected", "Your Guardian will sync automatically" — then automatically move him to the next step. He never has to think about connecting Cylenium again.
Thing 2 — It works, he's an enterprise user who already has this Guardian in their Cylenium system:
After OAuth succeeds, show him a special screen. Tell him "Welcome back — Guardian linked to Cylenium". But also show him a technical note — his IT admin needs to add this Guardian's DID (his unique identity string) to the Cervais admin console to complete the setup. Show the DID in a copyable code block. Add a "View Admin Docs" link. Then a Continue button.
Thing 3 — OAuth fails or he cancels:
Quietly return him to the sign up screen. Show a small toast at the bottom: "Cylenium connection failed. Try again or use email." Let him sign up with email normally. No drama.
Also — on the Onboarding Complete screen (the last onboarding screen that shows the checklist of what was set up):
If Cylenium was connected, add "✅ Cylenium Cloud connected" to that checklist. If it wasn't connected, don't show it.

ADDITION 2 — CYLENIUM CLOUD CARD IN DEVICES
For users who signed up with email and skipped Cylenium during onboarding, they should be able to connect later. They do this from Devices → Smart Home → Cloud tab.
Right now that tab shows a grid of third-party services: Ring, Nest, Wyze, Ecobee, TP-Link, Arlo.
Cylenium Cloud is NOT a third-party service — it's Cervais's own platform. It should feel like the premium native option, not just another entry in the grid.
What to build:
At the very top of the Cloud tab, before any of the third-party services, add a special full-width card for Cylenium Cloud. Give it a subtle purple border to set it apart. Add a small "CERVAIS" label at the top. Show the Cylenium Cloud name, a one-line tagline, and a "Connect Cylenium" button.
Below this card, add a separator that says "Third-party services" — then the existing Ring/Nest/Wyze grid continues as normal.
When Cylenium is already connected (for users who authenticated with Cylenium during onboarding), the same card shows a connected state — green Connected badge, last sync time, three checkmarks showing what's syncing (Security Alerts, Device Telemetry, Audit Logs), and a "View in Cylenium Dashboard" link.
When they tap "Connect Cylenium" from this screen, walk them through 3 steps:

A screen explaining what will sync — three cards: Security Alerts, Device Telemetry, Audit Logs — with a "Connect Now" button
A loading screen showing the connection progress — same style as the onboarding connecting screen Marcus already saw when pairing his Guardian
A success screen confirming everything is active — then return to the Cloud tab showing the connected state


ADDITION 3 — TWO MORE WAYS TO SHARE YOUR DID
Marcus's DID (Decentralized Identifier) is his unique identity on the Guardian network. Right now it's shown as a very long hex string: did:cervais:0x7a3f9b2c8d1e4a6f5c0b... — it works but it's hard to share verbally or remember.
The client wants two more ways to show and share the DID.
Where this appears: Both on the DID screen during onboarding AND in Settings → Guardian Info.
Add three tabs to the DID section:
Tab 1 — Full DID (already exists)
Keep exactly as-is. Long monospace string, copy button.
Tab 2 — Short Alias
Imagine a short code like your boarding pass number — easy to read out loud over a phone call. Show something like TX-042-MR — big characters, grouped clearly, like a banking verification code. Copy button directly below it (not beside it — below). A small note: "Short alias for quick identification. Share your full DID for Circle invites."
Tab 3 — QR Code
Show Marcus's DID as a scannable QR code. His teammate can point their phone camera at it to add him instantly. The QR must be large and have a white background (QR codes need light backgrounds to work). Show the short alias text below the QR code for reference. A "Share" button so Marcus can send the QR as an image via WhatsApp, SMS, etc.

ADDITION 4 — CIRCLE OF TRUST TOPOLOGY — MORE SCENARIOS
The Network Topology screen is already built and it's beautiful — Guardian device at the center, trusted peers connected around it. But right now it only shows one scenario: the Guardian with a few peers.
The client wants to see how the topology handles different real-world situations.
Scenario 1 — Marcus just set up his Guardian and has no teammates yet (Solo state)
The Guardian node sits alone at center. A dashed ring around it suggests where peers will appear. Below the canvas, show a message: "Your Circle of Trust is empty. Invite members to see your network topology." With an "Invite Member" button. This is the empty state — it should feel encouraging, not broken.
Scenario 2 — Marcus's team has grown and there are 8+ people in the Circle (Large Circle state)
Show 6 nodes around the Guardian at most. The 7th slot becomes a "+2 more" indicator — a grey dashed node. Tapping it reveals the rest. Connection type labels (WiFi, LTE, etc.) only appear on lines where there's enough space — don't clutter the view.
Scenario 3 — Two Guardian devices in the same Circle (Two Guardians state)
Imagine Marcus's facility has two SG-X Gateway devices — both belong to Cervais clients. Both appear as Guardian nodes in the topology. Marcus's own Guardian is solid purple (labeled "You"). The other Guardian is outlined purple (labeled with its device name). Both connect to shared team members. Tapping either Guardian opens a small bottom sheet showing that device's health status and a "View Guardian" link.
New way to CREATE a Circle — Visual Builder
Right now creating a Circle is just a form: enter name, enter description, tap Create. The client wants a visual option — where Marcus can actually see his Circle being built as he adds people.
Add a second option on the Create Circle screen. Two cards side by side: "Quick Create" (the existing form, selected by default) and "Build Visually" (the new option).
When Marcus taps "Build Visually":

Full screen dark canvas appears
His Guardian is at the center, labeled "You"
A dashed ring around it shows where peers will appear
At the top: an inline text field to name the Circle
At the bottom: an "Add Member" button that opens the existing invite modal
As people join: their nodes animate in and connect to the Guardian with a line
The "Create Circle" button at top right stays grey until Marcus has named the Circle AND added at least one member
When he taps Create Circle: brief loading animation, then the canvas transitions directly into the live Topology view for that Circle — the canvas becomes the real topology


BUILD ORDER
Build in exactly this order:

Account Setup screen — add "Continue with Cylenium" button + all 3 outcome states
Onboarding Complete screen — add conditional Cylenium checklist item
Devices → Smart Home → Cloud tab — add Cylenium featured card (both connected and disconnected states)
Cylenium Connect flow — 3 screens (what syncs, connecting, connected)
DID screen (onboarding) — add Short Alias and QR Code tabs
Settings → Guardian Info — apply same 3 DID tabs
Topology — Solo state
Topology — Large Circle state (6+ peers)
Topology — Two Guardians state
Create Circle — add Visual Builder option and canvas screen