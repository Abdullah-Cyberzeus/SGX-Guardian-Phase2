# Circles, Devices & Alerts Modules — Feature & API Integration Document

**Product:** SG-X Guardian Admin Console (Frontend)
**Audience:** Backend team
**Date:** 2026-07-07
**Purpose:** Complete specification of the **Circles** module (`/network`), the **Devices** module (`/devices`), and the **Alerts** module (`/alerts`, including the Suricata **Threat Protection** surface) — every screen, control, user flow, and data shape as implemented in the UI — plus the exact API contracts the frontend already calls, the contracts it *needs* (currently stubbed in the UI), and proposed request/response payloads for each.

**How to read this document:**
- **Wired** — the frontend already calls this endpoint today.
- **Stub** — the UI element exists and works visually, but performs no backend call (toast / local state / navigation only). Each stub lists the endpoint the frontend service layer already declares for it (if any) and the payload the UI can supply.
- Key frontend files are referenced as `path:line` so you can verify behavior directly.

---

# 0. Frontend Integration Architecture

Everything below applies to both modules. Source: `src/app/services/api.ts`, `src/app/hooks/useApiData.ts`.

## 0.1 API client (`api.ts`)

- **Base URL:** `import.meta.env.VITE_API_URL || '/api'` — in dev, requests go to `/api/*` on the Vite origin (proxy expected).
- **Content type:** `application/json` set automatically unless the body is `FormData` (the client supports `FormData` pass-through for future uploads).
- **Query params:** passed as an object, serialized to the query string, `undefined`/`null` skipped.
- **Health check:** `GET {base}/health` with a 2s timeout exists on the client (`checkServerHealth()`).
- **Error contract the client parses** (`api.ts:67-77`): on non-2xx, the client reads the JSON body and extracts a message from, in priority order:
  1. `{ "message": "..." }`
  2. `{ "error": "..." }`
  3. `{ "error": { "code": "...", "message": "..." } }`  ← the comment in code says *"Backend wraps errors as `{ error: { code, message } }`"* — please keep this envelope.
  Fallback message is `HTTP {status}`. The client `throw`s an `Error(msg)`; screens do **not** currently render these messages (see 0.3).
- **Monitoring:** every request is tracked (`monitoring.trackApiCall(method, endpoint, status, durationMs, errMsg?)`) — useful when correlating FE telemetry with backend logs.

## 0.2 Data fetching & polling (`useApiData.ts`)

- Every list/detail screen uses `useApiData(apiCall, { pollingInterval })`:
  - Initial fetch sets `loading` (full-screen spinner on every screen).
  - **Silent polling:** subsequent polls do not toggle `loading`; a failed poll **keeps the last good data** on screen (no error flash).
  - `refetch()` after user actions is also silent by design.
- **Polling intervals relevant to these modules:**

  | Hook | Endpoint | Interval |
  |---|---|---|
  | `useCircles()` | `GET /api/circles` | **30s** |
  | `useDevices(filters?)` | `GET /api/devices` | **15s** |
  | `useGuardianInfo()` | `GET /api/guardian/info` (guardianService) | **15s** |

  Plan for this steady read load; there is no websocket push today, so polling is the only freshness mechanism.

## 0.3 Mock fallback — important for rollout

Screens do not render API errors. Each consuming screen does a shape-check on the hook result and **silently falls back to hardcoded mock data** (`src/app/data/mockData.ts`) when the API returns nothing, errors, or returns a non-array:

- Circles: `NW01CirclesList` / `NW04CircleDetail` use `Array.isArray(data) ? data : mockCircles`.
- Devices: `DV01DevicesList` / `DV03DeviceDetail` fall back to `mockDevices` similarly.

**Consequence:** if the backend returns `200` with an empty array, users see a real empty state; if it returns an error or a mis-shaped body, users silently see demo data ("Texas Grid Ops", "PLC-Controller-03", …). Returning correct shapes matters more than returning errors.

---

# Part 1 — Circles Module

## 1.1 Concept

A **Circle of Trust** is a private, peer-to-peer, end-to-end-encrypted team group: secure chat, voice/video calls, file sharing, member management (DID-based identity), and invitations. In-app copy: *"A Circle of Trust is a private peer-to-peer encrypted group. Members share security alerts, coordinate via encrypted voice and video calls, and communicate without data leaving your private infrastructure."*

## 1.2 Screens & Navigation

| Screen | Route | Component | Entry points |
|---|---|---|---|
| Circles List | `/network` | `NW01CirclesList.tsx` | Sidebar "Circles", bottom nav, Dashboard "Your Circles" |
| Create Circle | `/network/create` | `NW02CreateCircle.tsx` | "+" button, empty-state CTA |
| Circle Detail | `/network/:circleId` | `NW04CircleDetail.tsx` | Circle card (mobile), dashboard deep link. Tab via `?tab=chat\|calls\|files\|members\|topology` (default `chat`) |
| Create First Circle | `/onboarding/circle` | `OB08CreateFirstCircle.tsx` | Onboarding step 8 |

**Sidebar badge:** the "Circles" nav item shows a red **"2"** badge — hardcoded (`AppSidebar.tsx:26`, `circlesBadgeCount = 2; // mock pending invites`). **Stub.** The intended semantic is **count of pending invites for the current user** — a backend counter endpoint (or a field on `GET /circles`) is needed to make this real.

## 1.3 Circles List (NW01)

Three responsive layouts:

- **Mobile:** header "Your Circles" + `{n} circle(s)` count + `+` create button. Circle cards: name, `{memberCount} members`, green dot + `{onlineCount} online`, description, and two quick actions — **Chat** and **Members** (deep-link to detail tabs).
- **Tablet:** 40/60 list + inline detail panel (same features as full detail, see 1.4). Placeholder: *"Select a Circle — Choose a Circle from the list to see chat, members, and network topology."*
- **Desktop:** three panes — 25% list / 45% detail panel / 30% topology rail (`{name} · Topology`).

**States:** loading spinner during initial fetch; empty state **"No circles yet"** — *"Create a Circle to build your trusted team."* + CTA **"Create your first Circle"**.

**Backend-relevant fields rendered here:** `name`, `memberCount`, `onlineCount`, `description`. Note `onlineCount` is a **presence-derived** number the current service contract does not provide (see 1.8).

## 1.4 Circle Detail (NW04 + inline panel)

Header: circle name, `{onlineCount} of {memberCount} online`, **voice call** / **video call** buttons (group call), **+ Invite**.

Five tabs — **Chat · Calls · Files · Members · Network**:

### 1.4.1 Chat tab
- Message bubbles: own messages right-aligned (primary color) with **`· Read` / `· Delivered`** receipts driven by `message.read`; others show sender name. Per-message timestamps.
- **Attachments:** images render as thumbnails with a lightbox; other files render as a download chip (name + human-readable size via `formatBytes`).
- Composer: **"+" attachment menu**, text input (*"Secure message..."*), send on Enter/click.
- **Send message** (**Stub**) — appends `{sender: "Me", initials: "MR", content, timestamp: "Now", isMe: true, read: false}` to local state only (`NW04CircleDetail.tsx` `sendMessage()`). No API exists in the service layer for messages at all.
- **Attach file** (**Stub** for backend; real cross-module effect in FE): creates an object-URL attachment message *and* mirrors the file into the Vault/"All Files" module (`VaultContext.addFile({circleId, circleName, sharedBy: "You", url, ...})`) under an auto-created per-circle folder. Backend file storage will need to honor this circle-scoped foldering (see 1.9).
- Empty state: **"No messages yet"** — *"Send a secure message to coordinate with your team. Messages are end-to-end encrypted."*

### 1.4.2 Calls tab
- "Call History" list: voice/video icon, participant, `{duration} · {timestamp}`. New records are prepended locally when a call ends.
- Empty state: **"No call history"** — *"Use the call icons in the header to call the whole Circle, or open the Members tab to call someone directly."*
- **Stub** — history is seeded from mock data + local session records; no persistence.

### 1.4.3 Call experience (CallScreen overlay)
- Full-screen overlay: shield icon + *"End-to-end encrypted {voice|video} call"*, live timer.
- Lifecycle is **fully simulated**: `connecting` → (~2.2s timer) → `ongoing` → end. **Stub** — no signaling, no media, no WebRTC.
- Voice stage: initials-avatar cluster with `+N` overflow. Video stage: placeholder tiles + self-tile ("Camera off" toggle).
- Controls: Mute, Start/Stop video (video mode), Speaker, End. Disabled while connecting.
- Group call participants = online members minus the current user; 1-on-1 calls start from a member sheet.
- On end, a `CallRecord {type, participant, duration}` is prepended to the Calls tab (`participant: "All Members"` for group; duration `"Xm Ys"` or `"Cancelled"` if ended while connecting).
- **Backend implication:** real calls need a signaling channel (WebSocket) + STUN/TURN infrastructure + a call-history write API. None is declared in the FE service layer yet — greenfield design decision.

### 1.4.4 Files tab
Read-only lens over chat attachments (`collectSharedFiles(messages)`, newest first): **Media · {n}** (3-col thumbnail grid + lightbox) and **Documents · {n}** (rows: name, `{size} · {sharedBy} · {sharedAt}`, download link). No direct upload — files enter via chat only. Empty state: **"No files shared yet"** — *"Photos and files you share in the chat show up here automatically."*

### 1.4.5 Members tab
- **"Invite Member"** button → invite sheet.
- Member rows: initials avatar, name, badges (**Pending** amber when `member.pending`, **Owner** info badge), email, presence (green dot `online` / `offline · {lastSeen}`).
- **Member detail sheet:** DID (monospace, copyable), Connection Type (hardcoded "WiFi"), Last Seen, Role, Guardian Health (hardcoded "Score: 88"). Actions: **Voice Call**, **Video Call**, and — non-Owners only — **"Remove from Circle"**.
- **Remove confirmation dialog:** *"Remove {name}? They will lose access to this Circle's chat, calls, and shared security data. This cannot be undone."* — **Stub**: the Remove button only closes the dialog. The service method exists and is unused: `circleService.removeMember(circleId, memberId)` → `DELETE /api/circles/:id/members/:memberId`.

### 1.4.6 Invite sheet (3 sub-tabs)
1. **Share Link:** invite code shown in segmented boxes (e.g. `TXG-OPS-7X2K-9M4P`), **Copy Code**, shareable link (`https://sgx.cervais.com/join/{code}`) with copy, **Share Invite** (**Stub**, no handler), email input + **Record** (**Stub**). Footer: *"Users need to have SG-X Guardian installed to join."*
2. **QR Code:** decorative pseudo-QR SVG (not a real encoding), **Share QR Code** (**Stub**). A real QR should encode the invite link — FE change needed once invites are real.
3. **Search DIDs:** *"Find team members by their Decentralized Identifier. The user must have their DID registered on the Cervais network."* Search input (**Stub**) — no search endpoint exists. Placeholder: *"Search results will appear here."*

**Backend implication:** `inviteCode` / `inviteLink` must be server-generated per circle, and a join/redeem flow (`POST /circles/join {code}` or similar), invite-by-email recording, and DID directory search are all net-new APIs (see 1.8).

### 1.4.7 Network tab
Renders the shared enterprise `TopologyCanvas`. Note: the component **ignores the circle context** — it's the generic enterprise scene regardless of selection (the `scenario` prop is accepted but ignored; see `HM03NetworkTopology.tsx` shim comment). A true per-circle topology would need `GET /circles/:id/devices` (already declared, unused) plus member/peer link data.

## 1.5 Create Circle (NW02)

Two modes via selector cards — **Quick Create** (*"Fill in a form and create instantly."*) and **Build Visually** (*"See your Circle form as you add people."*).

### Quick Create
- Info card: *"Your Circle uses peer-to-peer encrypted communication. No data passes through Cervais servers."*
- Fields: **Circle Name** (required), **Description** (optional).
- **Create Circle** → 3s fake spinner (*"Initializing Circle network..."*) → navigate to `/network`. **Stub** — `circleService.create` (`POST /api/circles {name, description?, members?}`) is never called.
- Perks checklist shown to the user (treat as backend acceptance criteria for circle provisioning): *"Certificate Authority will be generated" · "Circle network will be configured" · "Your Guardian will join automatically" · "Network relay enabled."*

### Visual Builder
- Radial SVG canvas: central **"You"** node, members added onto a ring from a candidate picker (mock candidates: Sofia Chen, James Park, Aisha Okonkwo, Raj Patel — a real implementation needs a **user/peer directory endpoint**).
- Create enabled with name + ≥1 member → 2.2s spinner → success overlay (**"Circle created!"**) → navigate. **Stub** — same missing `POST /circles` call; here the UI *can* also supply `members: string[]`.

### Onboarding variant (OB08)
Same form (name + description), **Create Circle** or **"Skip for now"** → `/onboarding/complete`. **Stub** — input discarded. When wired, this is the same `POST /circles`.

## 1.6 Circles — Current Wired API (what the backend must serve today)

Only **one** circle endpoint is consumed:

### `GET /api/circles` — every 30s
Declared response type (`circleService.ts:3-12`):

```ts
interface Circle {
  id: string;
  name: string;
  description: string;
  members: string[];        // ids
  memberCount: number;
  status: 'active' | 'inactive';   // never rendered in UI
  createdAt: string;
  updatedAt: string;
}
// GET /circles → Circle[]
```

**Contract gap — the UI renders a much richer shape.** The screens consume the mock shape, not the service interface. If `GET /circles` returns the interface above, the list will render (name/description/memberCount) but **detail screens will break or show blanks**: no `onlineCount`, no `inviteCode`/`inviteLink`, `members` as bare ids (UI needs objects), no `messages`, no `calls`.

### The shape the UI actually renders (target contract)

From `mockData.ts:194-242` and screen usage:

```jsonc
// GET /circles → Array of:
{
  "id": "cir_001",
  "name": "Texas Grid Ops",
  "description": "Primary operations team for ...",
  "memberCount": 6,
  "onlineCount": 4,                                   // presence-derived
  "inviteCode": "TXG-OPS-7X2K-9M4P",                  // server-generated
  "inviteLink": "https://sgx.cervais.com/join/TXG-OPS-7X2K-9M4P",
  "members": [
    {
      "id": "mem_001",
      "name": "Sofia Chen",
      "email": "sofia.chen@cervais.com",
      "role": "Owner",                                // "Owner" | "Member"
      "status": "online",                             // "online" | "offline"
      "lastSeen": "Now",                              // display string today; ISO + FE formatting preferred long-term
      "did": "did:cervais:0x9b2c...",
      "pending": false                                // optional; true → "Pending" badge
    }
  ],
  "messages": [                                        // chat history (could move to its own endpoint)
    {
      "id": "msg_001",
      "sender": "Sofia Chen",
      "initials": "SC",
      "content": "Alert alt_002 escalated — reviewing now",
      "timestamp": "9:05 AM",
      "isMe": false,                                   // server should key on requesting user
      "read": true,                                    // drives Read/Delivered receipt
      "attachment": {                                  // optional
        "name": "scada-01-capture.png",
        "sizeBytes": 842137,
        "mime": "image/png",
        "kind": "image",                               // "image" | "file"
        "url": "https://..."
      }
    }
  ],
  "calls": [
    { "id": "call_001", "type": "voice", "participant": "Sofia Chen",
      "duration": "12m 34s", "timestamp": "Yesterday 3:00 PM" }
  ]
}
```

Notes for backend design:
- `isMe` should not literally be stored — derive per requesting user (or return `senderId` and let FE compare; that requires a small FE change).
- All timestamps are currently **display strings** ("Now", "9:05 AM", "2h ago"). Recommend returning ISO 8601 and adding FE formatting — flag this in API review so both sides change together.
- Embedding full `messages` in the list response won't scale; a paginated `GET /circles/:id/messages` is the sensible split (requires a coordinated FE change).

## 1.7 Circles — Declared but Unused Endpoints (service layer already typed)

These exist in `circleService.ts` with exact types — wiring them is a FE task, but the backend contract is already fixed:

| Endpoint | Request | Response | UI feature it unblocks |
|---|---|---|---|
| `GET /circles/:id` | — | `Circle` | Detail refresh without full list |
| `POST /circles` | `{ name: string; description?: string; members?: string[] }` | `Circle` | Quick Create, Visual Builder, Onboarding create |
| `PUT /circles/:id` | `Partial<Circle>` | `Circle` | (No edit UI yet) |
| `DELETE /circles/:id` | — | `{ success: boolean; message: string }` | (No delete UI yet) |
| `POST /circles/:id/members` | `{ memberId: string; memberType?: string }` | `{ success, circleId, memberId }` | Add member / accept invite |
| `DELETE /circles/:id/members/:memberId` | — | `{ success, circleId, memberId }` | "Remove from Circle" dialog |
| `GET /circles/:id/devices` | — | `{ circleId, devices: string[], total }` | Per-circle topology / device sharing |

## 1.8 Circles — Net-new APIs Needed (nothing declared in FE yet)

Proposed contracts matching what the UI can already send/display:

1. **Messages**
   - `GET /circles/:id/messages?before=<cursor>&limit=50` → `{ messages: Message[], nextCursor? }`
   - `POST /circles/:id/messages` `{ content: string }` → `Message`
   - `POST /circles/:id/messages` with `multipart/form-data` (file) → `Message` with `attachment` (the API client already supports `FormData`).
   - Read receipts: `POST /circles/:id/messages/read` `{ upToMessageId }` (UI shows Read/Delivered per own message).
   - **Realtime:** message delivery + presence need push. Recommend a WebSocket channel (e.g. `/ws/circles`) emitting `message.new`, `member.presence`, `call.incoming`; FE currently polls 30s, which is too slow for chat.
2. **Presence** — source for `member.status`, `lastSeen`, `onlineCount` (may ride on the Guardian peer network rather than a REST endpoint; UI just needs the fields filled).
3. **Invites**
   - `POST /circles/:id/invites` → `{ inviteCode, inviteLink, expiresAt? }` (or keep one static code per circle as the UI implies)
   - `POST /circles/join` `{ code }` → membership pending/active
   - `POST /circles/:id/invites/email` `{ email }` (the "Record" input)
   - `GET /me/invites` → drives the sidebar "pending invites" badge (currently hardcoded **2**)
4. **DID directory search** — `GET /dids/search?q=...` → `[{ did, name, userId }]` (Invite sheet, "Search DIDs" tab; also usable as the Visual Builder candidate picker).
5. **Calls** — signaling (WebSocket) + TURN credentials + `POST /circles/:id/calls` history writes: `{ type: "voice"|"video", participants: string[], startedAt, endedAt, outcome }`.
6. **Owner constraint** — backend must enforce: Owner cannot be removed (UI hides the button for Owners, but the API must also reject it).

## 1.9 Cross-module: Circle files ↔ Vault ("All Files")

`VaultContext.tsx` creates a folder per circle (`kind: "circle"`, "Circle sync") and mirrors chat attachments into it; uploads routed with `circleId` land in that folder. When file storage gets a backend, circle attachments and vault files should share one canonical file object so the "shared in a Circle → appears in All Files" behavior holds server-side.

---

# Part 2 — Devices Module

## 2.1 Concept

"Connected Devices" is the inventory + security posture view for everything the Guardian appliance monitors: OT/ICS equipment (PLCs, SCADA servers), smart-home devices, drones, and unknown/pending devices. Per-device security & privacy scores, vulnerability findings, on-demand security scans, and smart-home hub/cloud/rules management.

## 2.2 Screens & Navigation

| Screen | Route | Component | Entry points |
|---|---|---|---|
| Connected Devices | `/devices` | `DV01DevicesList.tsx` | Sidebar "Devices", bottom nav |
| Device Detail | `/devices/:id` | `DV03DeviceDetail.tsx` | Device card/row, post-scan "View Device" |
| Security Scan | `/devices/:id/scan` | `DV06SecurityScan.tsx` | Detail → Actions → "Run Security Scan" |
| Smart Home Integration | `/devices/smart-home` | `DV11SmartHome.tsx` | Card on the devices list |
| Device Pairing (Settings) | `/settings/device-pairing` | `ST08DevicePairing.tsx` | Settings → Device |
| Device Settings (Settings) | `/settings/device-settings` | `ST10DeviceSettings.tsx` | Settings → Device ("Coming soon" placeholder) |

**Sidebar badge:** "Devices" badge = live count of devices with `category === "pending"` (shows **1** with seed data) — unlike Circles, this one is data-driven and will be correct as soon as the API returns pending devices.

**Adjacent module (do not conflate):** the NMAP-based discovery screen (`/network/discovery`, `NW07Discovery`) has its own `discoveryService` + whitelist and is already backend-integrated separately (`docs/nmap-discovery.md`). The Devices list's **"Scan Network"** button does *not* trigger discovery — it navigates to `/home/topology`.

## 2.3 Connected Devices List (DV01)

Three layouts: mobile cards / tablet 45-55 split / desktop table + 45% inline detail panel.

### Header & Guardian bar
- Title **"Connected Devices"**, subtitle `"{online} online · {total} devices"` — these two numbers come from the `DevicesResponse` envelope (`online`, `total`).
- **Guardian status card:** name ("Guardian-TX-042"), status + connection ("Online · WiFi"), firmware ("v4.2.1") — from `useGuardianInfo()` (separate guardian endpoint, 15s poll).

### Actions
- **Scan Network** → navigates to `/home/topology` (no scan API call today).
- **Add Manually** → opens **Add Device** sheet: fields **Device Name**, **IP Address**, **MAC Address**, **Manufacturer** (form state also holds unused `type`, `connection`, `model`, `os`). Submit → toast `"{name} added"`. **Stub** — should call `deviceService.register` → `POST /api/devices` `{ name, type?, address? }`. Note the declared request body **lacks `mac` and `manufacturer`** which the form collects — extend the contract to `{ name, ip, mac, manufacturer, type? }` (FE service change is trivial once agreed).
- **Smart Home Integration** card → `/devices/smart-home`.

### Filtering & search
- **Category chips:** `All · Regular · Drones · Smart Home · Pending` — client-side filter on `device.category`. Pending chip shows a red count badge.
- **Search:** client-side, case-insensitive, matches `name` OR `manufacturer`, ANDed with the category chip.
- The service layer supports server-side `?status=&type=` filters on `GET /devices`, but the UI currently filters client-side on the full list — server-side filtering is optional.

### Desktop table columns
**Device Name** (+ manufacturer sub-row) · **Type** (renders `protocol`) · **Status** (Online/Offline badge) · **Sec. Score** · **Priv. Score** · **Vulnerabilities** (warning icon + count in red, or "None" in green). Pending rows are non-clickable; other rows open the inline panel.

### Pending device approval (mobile expansion)
Pending cards expand to show **First seen** (`lastSeen`), **IP Address**, **OS**, plus:
- **Approve** → toast `"{name} approved"` (**Stub**)
- **Reject** → toast `"{name} rejected"` (**Stub**)

**Needed API:** no approve/reject endpoints are declared. Proposal:
- `POST /devices/:id/approve` → `Device` (status flips `pending → online`, `category → regular`, monitoring on)
- `POST /devices/:id/reject` → `{ success, message }` (device removed or blocked — product decision needed)
Alternatively `PUT /devices/:id { status }` via the existing update endpoint. This flow also pairs with the existing alert type "New Unrecognized Device Connected" (see `mockAlerts alt_004`, which references "Devices > Pending Approvals").

### Inline detail panel (tablet/desktop)
Stat tiles (Status / Security / Privacy), **Device Info** table (IP, MAC, Protocol, OS, Firmware, Vulnerabilities), **Security** section (Secured/Unsecured, Encrypted/Unencrypted), and **Actions**: *Run Security Scan · Force Firmware Update · Block Device · Remove Device* — each currently a toast-only **Stub**.

> Known FE bug (cosmetic): panel reads `device.firmwareVersion` but the data field is `firmware`, so Firmware shows "Unknown" in the panel. Backend should still ship `firmware`; we'll fix the FE read.

### States
Loading spinner; empty state **"No devices found"** — *"Try adjusting your filters or scan for new devices."*; "Select a device" placeholder on wide layouts.

## 2.4 Device Detail (DV03)

Header: name + `{manufacturer} · {protocol}`; "Device not found" for unknown ids (client-side lookup in the polled list — `GET /devices/:id` declared but unused).

**Score header:** two SVG ring gauges — **Security**, **Privacy** — plus **Vulns** count.

### Info tab
Rows: Manufacturer, Model (`type`), Protocol, MAC, IP, Firmware, OS, Last Seen. **"Guardian Monitoring"** toggle (*"Active threat detection for this device"*) — local state only (**Stub**); wiring target: `PUT /devices/:id { guardianMonitoring: boolean }` (field must be added to the update contract).

### Security tab
- **Security Features:** Encryption (Enabled/Disabled), Auto-Update (Enabled/Disabled), Connectivity (protocol) — driven by `encrypted`, `autoUpdate`, `protocol`.
- **Vulnerabilities:** banner *"{n} Vulnerabilities Detected — Address these issues to improve your security score."* + cards (title, HIGH/MED/LOW badge, description) from `vulnerabilityList`. Clean state: *"No vulnerabilities detected — This device passed all security checks."*

### Actions tab
- **Run Security Scan** → `/devices/:id/scan` (see 2.5).
- **Block from Network** → dialog: *"Block {name}? This device will lose network access immediately. All active connections will be terminated. You can unblock it later from device settings."* **Stub** — confirm only closes the dialog. **Needed API:** `POST /devices/:id/block` (+ `/unblock`; the copy promises unblock exists). No block state exists in the device model yet — add e.g. `blocked: boolean` or `status: 'blocked'`.
- **Remove Device** → dialog: *"Remove {name}? This device will be removed from Guardian monitoring. All associated alerts and data will be cleared. This cannot be undone."* → navigates to `/devices`. **Stub** — should call `deviceService.remove` → `DELETE /api/devices/:id` → `{ success, message }`. Note the copy promises **cascade deletion of associated alerts/data** — backend behavior to confirm.

## 2.5 Security Scan (DV06)

Currently a **pure frontend simulation** (**Stub**): five timed steps — *Checking firmware version (1.4s) · Checking open ports (1.6s) · Checking encryption status (1.2s) · Checking known vulnerabilities (2.0s) · Generating security report (1.0s)* — animated progress, then results rendered from the device's static `vulnerabilityList`:
- Summary: red **"{n} Vulnerabilities Found"** or green **"No Vulnerabilities Found"**.
- Severity breakdown: High / Medium / Low counts.
- **Recommendations** list = vulnerability cards.
- Footer: **View Device** / **View Alerts**.

**Needed API (async job shape suggested):**
- `POST /devices/:id/scan` → `{ scanId, status: "running", steps: [...] }`
- `GET /devices/:id/scan/:scanId` (poll) → `{ status: "running"|"complete"|"failed", progress: 0-100, currentStep, result?: { vulnerabilities: VulnerabilityFinding[], scores?: { security, privacy } } }`
- A completed scan should refresh the device's `securityScore` / `privacyScore` / `vulnerabilityList`.
- Related existing contract: `POST /devices/:id/attest` → `{ success, deviceId, attestationStatus, timestamp }` is declared (device attestation) but has **no UI surface** yet — clarify with product whether scan and attestation are one flow or two.

## 2.6 Smart Home Integration (DV11)

Four tabs, all local state (**Stub**) — this is the least-specified area and needs joint API design:

- **Hubs:** **Start/Stop Service** toggle; **Discover Hubs** (unwired); when "running", a hardcoded discovered list — "Zigbee Hub v2" (192.168.1.45, Zigbee), "Z-Wave Controller" (192.168.1.72, Z-Wave) — each with an **Add** button (unwired); a "Recent Activity" feed. Implies: hub service control (`POST /smarthome/service/start|stop`), hub discovery + adoption, activity log.
- **Dongles:** empty state *"No USB dongles detected — Connect a dongle to your Guardian's USB port to get started."* Implies a USB dongle enumeration endpoint on the appliance.
- **Cloud:**
  - **Cylenium Cloud** connect flow (Cervais's enterprise platform). Steps: "What will sync" (**Security Alerts** — *real-time threat notifications*, **Device Telemetry** — *Guardian health, battery, connectivity*, **Audit Logs** — *all events and actions*) → animated "Establishing secure tunnel" → connected. State is a localStorage flag `sgx_cylenium_connected`. Real integration needs: `POST /cloud/cylenium/connect`, `GET /cloud/cylenium/status` (`lastSyncAt`, active features), disconnect, and a real dashboard URL (link is currently `href="#"`).
  - **Third-party services** grid — Ring Security, Google Nest, Wyze, Ecobee, TP-Link Kasa, Arlo — connect/disconnect toggles (local Set). Real integration implies OAuth-style flows per provider: `GET /integrations`, `POST /integrations/:provider/connect`, `DELETE /integrations/:provider`.
- **Rules:** *"Create rules to automatically control your smart home devices based on security events, time schedules, location, or sensor readings."* **Manage Automation Rules** button (unwired), rule-type tiles (Security Triggers / Schedules / Geofencing / Sensors), activity feed. Implies a rules CRUD API. Note: a related shape already exists in the app — `mockAlertRules` (`{id, name, enabled, event, condition, action, notify}`) used by Settings → Alert Rules — consider one unified rules engine.

## 2.7 Related Settings screens

- **ST08 Device Pairing** — re-pair the Guardian appliance itself. Warning: *"Re-pairing will replace the currently connected Guardian (Guardian-TX-042)."* Methods: **Scan QR Code** (2.5s fake scan → onboarding connect flow) and **Enter Serial Number** ("e.g. GX-2024-TX-042-A9F3", enabled at ≥6 chars). Both **Stub** — the pairing handshake API belongs to the onboarding/guardian domain, listed here for completeness.
- **ST10 Device Settings** — placeholder: *"Advanced device configuration options will be available in a future Guardian firmware update."*

## 2.8 Devices — Current Wired API

### `GET /api/devices` — every 15s (optional `?status=&type=`)
Declared envelope (`deviceService.ts:15-20`) — **note: unlike circles, devices are wrapped**:

```ts
interface DevicesResponse {
  devices: Device[];
  total: number;      // rendered in header
  online: number;     // rendered in header
  timestamp: string;
}
interface Device {
  id: string; name: string; type: string; address: string;
  status: 'online' | 'offline' | 'pending';
  lastSeen: string; registeredAt: string;
  attestationStatus?: 'passed' | 'failed' | 'pending';
  metadata?: Record<string, unknown>;
}
```

**Contract gap — the UI renders a much richer per-device shape** (mock: `mockData.ts:244-365`). The declared `Device` above is missing almost every column the table shows. Target contract:

```jsonc
// GET /devices → { "devices": [ ... ], "total": 5, "online": 4, "timestamp": "..." }
{
  "id": "dev_001",
  "name": "PLC-Controller-03",
  "type": "IoT",                      // "IoT" | "Computer" | "Drone" | "Unknown"
  "manufacturer": "Siemens",
  "protocol": "Modbus TCP",           // shown in the "Type" column
  "mac": "C8:5B:76:2A:F3:91",
  "ip": "10.0.2.47",
  "firmware": "v2.1.4",
  "os": "Linux Embedded 5.4",
  "status": "online",                 // "online" | "offline" (pending expressed via category)
  "secured": true,
  "encrypted": true,
  "securityScore": 72,                // 0–100
  "privacyScore": 84,                 // 0–100
  "vulnerabilities": 2,               // count; keep consistent with list length
  "autoUpdate": false,
  "guardianMonitoring": true,
  "category": "regular",              // "regular" | "drones" | "smart-home" | "pending"
  "lastSeen": "Now",                  // display string today; ISO preferred (see Part 3)
  "vulnerabilityList": [
    { "id": "v1", "title": "Outdated Modbus Library", "severity": "HIGH",
      "description": "libmodbus v3.0.1 has a known buffer overflow vulnerability. Upgrade to v3.1.7+" }
  ]
}
```

Model reconciliation needed with backend:
- UI splits `ip` + `mac`; service contract has a single `address`.
- UI expresses pending-ness via `category: "pending"`; service via `status: "pending"`. Pick one (suggest: keep `status` as connectivity, keep `category` as classification, and derive the pending filter from an explicit `approvalState: "pending" | "approved" | "rejected"`).
- `severity` enum: `"HIGH" | "MEDIUM" | "LOW"` (UI renders MED label for MEDIUM).

## 2.9 Devices — Declared but Unused Endpoints

| Endpoint | Request | Response | UI feature it unblocks |
|---|---|---|---|
| `GET /devices/:id` | — | `Device` | Detail screen (currently list-lookup) |
| `POST /devices` | `{ name; type?; address? }` — **extend with ip/mac/manufacturer** | `Device` | Add Device sheet |
| `PUT /devices/:id` | `Partial<Device>` | `Device` | Guardian Monitoring toggle, rename, approve (option) |
| `DELETE /devices/:id` | — | `{ success; message }` | Remove Device dialog |
| `POST /devices/:id/attest` | — | `{ success; deviceId; attestationStatus; timestamp }` | No UI yet — clarify vs. Security Scan |

## 2.10 Devices — Net-new APIs Needed

| Feature (UI ready today) | Proposed endpoint |
|---|---|
| Approve pending device | `POST /devices/:id/approve` → `Device` |
| Reject pending device | `POST /devices/:id/reject` → `{ success, message }` |
| Block / Unblock | `POST /devices/:id/block`, `POST /devices/:id/unblock` (+ `blocked` state in model) |
| Force firmware update | `POST /devices/:id/firmware-update` → job id / status |
| Security scan | `POST /devices/:id/scan` + poll `GET /devices/:id/scan/:scanId` (see 2.5) |
| Smart-home hub service & discovery | `POST /smarthome/service/{start\|stop}`, `GET /smarthome/hubs/discovered`, `POST /smarthome/hubs` |
| USB dongles | `GET /smarthome/dongles` |
| Cylenium Cloud | `POST /cloud/cylenium/connect`, `GET /cloud/cylenium/status`, `DELETE /cloud/cylenium` |
| Third-party integrations | `GET /integrations`, `POST /integrations/:provider/connect`, `DELETE /integrations/:provider` |
| Automation rules | CRUD `/smarthome/rules` (align with alert-rules engine) |

## 2.11 Display rules (FE-computed — backend supplies raw values only)

| Signal | FE rule |
|---|---|
| Security / Privacy score color | ≥ 80 green · 50–79 amber · < 50 red |
| Vulnerability count | > 0 → warning icon + count in red · 0 → "None" in green |
| Severity badge | HIGH red · MEDIUM amber ("MED") · LOW grey |
| Status badges | online/secured/enabled green · offline grey · unsecured/disabled red · pending amber |

Backend should **not** send colors or display strings for these — just the numeric scores, counts, severities, and booleans.

---

# Part 3 — Alerts & Threat Protection Module

## 3.1 Concept — two alert sources under one tab

The **Alerts** tab (`/alerts`) surfaces two *distinct* data sources, and their backend status could not be more different:

1. **AI security alerts** (screens AL01/AL06/AL07) — curated, AI-analyzed security events with a "what happened / why it matters / recommended actions" narrative. **Mock-only today**: a full `alertService` is declared but no endpoint is wired; the UI renders `mockAlerts`.
2. **Suricata IDS/IPS threat** (screen AL08 "Threat Protection") — real network intrusion detection. **Fully wired**: all 10 `/threat/*` endpoints are consumed live (backend commit `1c8dd4c`). This is the **only fully backend-integrated surface** documented in this spec — reads *and* writes hit the API.

## 3.2 Screens & Navigation

| Screen | Route | Component | Entry points |
|---|---|---|---|
| Alerts List | `/alerts` | `AL01AlertsList.tsx` | Sidebar "Alerts", bottom nav |
| Alert Detail | `/alerts/:id` | `AL06AlertDetail.tsx` | Tap an AI alert |
| AI Analysis | `/alerts/:id/ai` | `AL07AIRecommendation.tsx` | "View Full AI Analysis" on detail |
| Threat Protection | `/alerts/threat` | `AL08ThreatProtection.tsx` / `ThreatProtectionPanel` | **"Threat Protection" segmented tab** at the top of the Alerts screen (renders inline); also deep-linkable at `/alerts/threat` |

**Top-level view switch:** the Alerts screen has an `Events | Threat Protection` segmented control at the top. **Events** shows the AI-alerts list/detail split (3.3–3.4); **Threat Protection** renders the Suricata IDS panel (3.6) inline at full content width. The threat tab carries a live Suricata status dot (green when active). The panel content is shared via `ThreatProtectionPanel`, so the `/alerts/threat` route (deep link) shows the same thing with a page header.

**Sidebar badge:** the "Alerts" badge = count of **non-archived HIGH-severity** mock alerts (`AppSidebar.tsx:24`, `mockAlerts.filter(!archived && severity === "HIGH")` → **2** with seed data). Mock-derived; will need a real source (e.g. `GET /alerts/summary` unread/critical count, or `/threat/status.alert_count`).

## 3.3 Alerts List (AL01) — the AI-alerts surface (Events tab)

Shown under the **Events** segmented tab. Three responsive layouts: mobile (navigate to detail), tablet 40/60 split, desktop 35/65 split (list + inline `AlertDetailPanel`). Below the pinned "Alerts" header, the intel card, controls, and list scroll together as one region so the list keeps full height on short viewports.

- **AI Threat Intelligence card** — four stat tiles: **Threat Score** (mock "34"), **IDS Alerts** (live `threatStatus.alert_count`, falls back to mock "12"), **Blocked** (live `threatStatus.block_count`, falls back to mock "47"), **Quarantined** (mock "3"). So two of the four tiles are now real (from `GET /threat/status`); Threat Score and Quarantined remain mock pending a threat-intel/quarantine source.
- **Controls:** search (matches title/device), severity filter (ALL/HIGH/MEDIUM/LOW), status filter (ALL/Active/Acknowledged/Blocked), Archived toggle, and **bulk mode** (select → Archive/Delete).
- **AI-alert write actions are all Stub:** per-row archive (toast `"Alert archived"`), bulk Archive/Delete (toast only). No `alertService` write is called.
- **Inline detail panel (`AlertDetailPanel`, tablet/desktop):** severity + status badges, title, meta line (time · date · device), a subtle "active threat" banner for HIGH, a 2-column details grid (Device / IP / Event Type / OS), the AI Summary card, stubbed recommended-action cards (toast `"{label} — action initiated"`), and a pinned **View Full Details** → AL06.
- **States:** loading spinner; empty state **"Your network looks clean"** / **"No archived alerts"**.
- **Data:** `useAlerts()` → `alertService.getAll()` → `GET /api/alerts` — **no backend; silently falls back to `mockAlerts`** (same pattern as circles/devices).

## 3.4 Alert Detail (AL06) & AI Analysis (AL07)

- **AL06 Alert Detail** — severity accent bar + HIGH-severity warning banner; metadata table (Device, Device IP, Event Type, Status); **AI Summary** card; **Recommended Actions** (all **Stub**, toast `"{label} — action initiated"`): *Archive Event · Block Device from Network · Run Security Scan · View Affected Device*; "View Full AI Analysis" → AL07.
- **AL07 AI Analysis** — full narrative from `alert.aiDetail`: **What Happened**, **Why It Matters**, and a numbered **recommended actions** list.
- Both look up the alert in the polled list (mock fallback); no dedicated detail fetch (`GET /alerts/:id` declared, unused).

## 3.5 AI Alerts — API contract (declared, entirely unwired)

`alertService.ts` — none of these are consumed today:

| Endpoint | Request | Response | Feature it unblocks |
|---|---|---|---|
| `GET /alerts` | `?severity&status&limit` | `{ alerts: Alert[], total, unread, timestamp }` | Alerts list |
| `GET /alerts/:id` | — | `Alert` | Detail refresh |
| `PUT /alerts/:id/read` | — | `{ success, alertId, status }` | Mark read |
| `PUT /alerts/:id/dismiss` | — | `{ success, alertId, status }` | Dismiss |
| `PUT /alerts/read-all` | — | `{ success, message }` | Mark all read |
| `DELETE /alerts/:id` | — | `{ success, message }` | Delete/bulk delete |
| `GET /alerts/summary` | — | `{ total, bySeverity, byStatus, timestamp }` | Sidebar badge, intel card |

```ts
// Declared Alert (alertService.ts):
interface Alert {
  id; severity: 'critical'|'warning'|'info'; status: 'unread'|'read'|'dismissed';
  title; message; source; timestamp; metadata?;
}
```

**Contract gap (same as circles/devices):** the UI renders the richer `mockAlerts` shape, not the declared interface:

```jsonc
// mockData.ts mockAlerts — what AL01/06/07 actually render:
{
  "id": "alt_001",
  "severity": "HIGH",                 // "HIGH" | "MEDIUM" | "LOW"
  "title": "Unauthorized Service Account Login",
  "description": "...",
  "eventType": "Authentication Failure",
  "status": "Active",                 // "Active" | "Acknowledged" | "Blocked"
  "timestamp": "9:14 AM", "date": "Today",
  "device": "PLC-Controller-03", "deviceIp": "10.0.2.47", "os": "Linux Embedded 5.4",
  "aiSummary": "...",
  "aiDetail": { "whatHappened": "...", "whyItMatters": "...", "actions": ["...", "..."] },
  "archived": false
}
```

## 3.6 Threat Protection (AL08) — Suricata IDS/IPS — FULLY WIRED

Shown under the **Threat Protection** segmented tab (and at `/alerts/threat`), a four-tab panel (`ThreatProtectionPanel`). Unlike everything else in this document, **all reads and writes hit real endpoints** (with real loading/empty/error states — **no mock fallback**).

- **Overview tab** — Suricata engine status (`GET /threat/status`: service state, enabled, block mode, alert/block counts) plus service actions: **Start Suricata** (`POST /threat/start`, shown only when service ≠ active), **Validate config** (`POST /threat/validate`), **Update rules** (`POST /threat/rules/update`, flags `restartRequired`).
- **IDS Alerts tab** — `GET /threat/alerts?limit=500` with an in-UI severity filter; each alert card shows severity badge, category, `src_ip:port → dst_ip:port · protocol`, SID, timestamp, and a **Block IP** action (`POST /threat/blocks {ip}`) for non-blocked src IPs. 404 ("no alerts yet") renders a clean empty state.
- **Blocked IPs tab** — `GET /threat/blocks`; add via an input (`POST /threat/blocks`), remove per-row (`POST /threat/blocks/unblock`).
- **Config tab** — `GET /threat/config`; editable block mode, block TTL, rule-update cadence, and exempt CIDRs, saved via `POST /threat/config` (patch — only changed fields sent); read-only display of interface / EVE log / Suricata YAML paths.
- **Cross-feed:** `GET /threat/status` also drives the AL01 intel-card counts and the segmented-tab Suricata status dot (3.3).

## 3.7 Threat — API contract (all 10 WIRED)

Consumed via `threatService.ts` + hooks (`useThreatStatus` 15s, `useThreatAlerts` 15s, `useThreatBlocks` 15s, `useThreatConfig` 30s):

| Method | Endpoint | Request | Response |
|---|---|---|---|
| GET | `/threat/status` | — | `ThreatStatus` |
| GET | `/threat/alerts` | `?limit&severity` | `ThreatAlert[]` (404 until events exist) |
| GET | `/threat/blocks` | — | `{ blocked: string[] }` |
| POST | `/threat/blocks` | `{ ip }` | `ThreatActionResponse` |
| POST | `/threat/blocks/unblock` | `{ ip }` | `ThreatActionResponse` |
| POST | `/threat/rules/update` | — | `ThreatActionResponse` (`restartRequired: true`) |
| POST | `/threat/validate` | — | `ThreatActionResponse` |
| GET | `/threat/config` | — | `ThreatConfig` |
| POST | `/threat/config` | `ThreatConfigPatch` (partial) | `ThreatActionResponse` |
| POST | `/threat/start` | — | `ThreatActionResponse` |

```jsonc
// ThreatAlert (GET /threat/alerts)
{
  "alert_id": "838deb6e032238c8", "timestamp": "2026-07-02T06:01:25Z",
  "src_ip": "10.0.2.5", "src_port": 44120, "dst_ip": "ff02::16", "dst_port": 0,
  "protocol": "IPv6-ICMP", "signature_id": 10000131, "signature": "SGX MALWARE TEST TROJAN",
  "category": "malware",          // malware|exploit|policy_violation|reconnaissance|anomaly|other
  "severity": "critical",         // info|low|medium|high|critical
  "rev": 1, "gid": 1, "event_type": "alert", "blocked": false
}

// ThreatStatus (GET /threat/status)
{ "suricata": "active", "enabled": true, "block_mode": "inline_block",
  "alert_count": 124, "block_count": 3 }   // suricata: active|inactive|unknown

// ThreatConfig (GET /threat/config)
{ "enabled": true, "interface": "wlan0", "eve_path": "...", "suricata_yaml": "...",
  "block_mode": "inline_block",            // alert_only | inline_block
  "block_ttl_secs": 86400, "block_exempt": ["127.0.0.0/8"], "rule_update_hours": 24 }

// ThreatActionResponse (all mutations)
{ "success": true, "stdout": "...", "stderr": "", "restartRequired": false, "timestamp": "..." }
```

**Notes for backend parity:**
- `ThreatActionResponse` uses **camelCase `restartRequired`** — deliberately different from the discovery endpoints' snake_case action envelope. The FE handles each correctly; keep them stable.
- `GET /threat/alerts` returns **404** until Suricata has produced events; the FE treats 404 as a clean empty state, not an error.
- `POST /threat/config` is a **patch** — the FE sends only `enabled`, `block_mode`, `block_ttl_secs`, `rule_update_hours`, `block_exempt`; `interface`/`eve_path`/`suricata_yaml` are read-only in the UI.

---

# Part 4 — Cross-cutting Backend Notes

1. **Timestamps.** The entire UI currently renders human strings ("Now", "9:05 AM", "2h ago", "Yesterday 3:00 PM") because mock data hardcodes them. Recommend all new/updated endpoints return **ISO 8601 UTC** and we add FE relative-time formatting in the same release. Please flag which shape you'll ship so FE can prepare.
2. **Identity.** Members carry DIDs (`did:cervais:0x…`). Message `isMe` and call participant naming must be resolved per-requesting-user server-side, or endpoints should return stable `senderId`/`memberId` for FE resolution.
3. **Realtime.** Chat, presence, incoming calls, and pending-device appearance are poll-based today (15–30s). For chat/calls this is inadequate — propose a WebSocket channel with events: `circle.message.new`, `circle.member.presence`, `circle.call.incoming`, `device.pending.new`, `device.updated`. FE will adopt incrementally.
4. **Error envelope.** Keep `{ "error": { "code", "message" } }` (or top-level `message`) — that's what the client parses. Screens currently swallow errors and fall back to mocks; as endpoints go live we will remove the mock fallbacks module-by-module, at which point error bodies become user-visible.
5. **Empty vs. error.** `200` + empty array/list ⇒ real empty states ("No circles yet" / "No devices found"). Errors ⇒ demo data (until fallbacks are removed). Never return `200` with a non-array/mis-shaped body — it silently triggers demo data. **Exception: the `/threat/*` endpoints have no mock fallback** — the Threat Protection screen shows real loading/empty/error states, so error bodies there are already user-visible.
5b. **Two action envelopes.** Discovery/most mutations use snake_case fields; the `/threat/*` mutations use the camelCase `ThreatActionResponse` (`restartRequired`). Keep each stable — the FE parses them separately.
6. **Badges.** Sidebar Devices badge = count of pending devices from `GET /devices` (works as soon as data is real). Sidebar Circles badge = hardcoded `2` — needs a pending-invites source (1.8 #3).
7. **Authorization rules the UI assumes** (must be enforced server-side): Circle Owner cannot be removed; pending members can't act until approved; pending devices are read-only (rows non-clickable) until approved.

# Part 5 — Integration Priority Checklist (suggested)

**P0 — replace demo data with live data**
1. `GET /circles` and `GET /devices` returning the **UI shapes** in 1.6 / 2.8 (these two endpoints alone bring both modules fully live with real data, including scores, vulnerabilities, members, chat history seed, and the pending-device badge).
1b. `GET /alerts` (+ `GET /alerts/summary`) returning the `mockAlerts` UI shape (3.5), to move the AI-alerts list, detail, and sidebar badge off mock data. **The 10 `/threat/*` endpoints are already fully wired — no FE work needed there.**
2. `POST /circles` (create flows), `POST /devices` (add manually — extended body), `DELETE /devices/:id` (remove), `DELETE /circles/:id/members/:memberId` (remove member).
3. Device approve/reject endpoints (pending flow + sidebar badge already wired to data).

**P1 — core interactivity**

4. Circle messages API + attachments (+ WebSocket push).
5. Device security scan job API.
6. Block/unblock device; guardian-monitoring toggle via `PUT /devices/:id`.
7. Invites (generate/join/email) + pending-invites count for the Circles badge.

**P2 — advanced**

8. Presence service; call signaling + TURN + call history.
9. DID directory search.
10. Smart-home (hubs/dongles/rules), Cylenium Cloud, third-party integrations.
11. Per-circle topology data (`GET /circles/:id/devices` + link data).

---

*Key FE source files: `src/app/routes.ts`, `src/app/services/{api,circleService,deviceService,alertService,threatService}.ts`, `src/app/hooks/useApiData.ts`, `src/app/data/mockData.ts` (circles 194-242, devices 244-365, alerts 39-192), `src/app/screens/network/NW0{1,2,4}*.tsx`, `src/app/screens/devices/DV{01,03,06,11}*.tsx`, `src/app/screens/alerts/AL0{1,6,7,8}*.tsx`, `src/app/components/circle/*`, `src/app/components/AppSidebar.tsx`, `src/app/contexts/VaultContext.tsx`. Related docs: `backend-frontend-integration-gap-analysis.md`, `circle-comms-decisions.md`, `nmap-discovery.md`.*
