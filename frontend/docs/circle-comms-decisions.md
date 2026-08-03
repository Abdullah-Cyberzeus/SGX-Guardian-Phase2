# Circle Communications — Decision & Change Log

Living log for the **Voice Call / Video Call / Chat attachments / File sharing** feature
added to Circles. Append to this as work progresses — newest entries at the bottom of
each section.

- **Branch:** `feature/cloud-storage-comms` (off `develop`)
- **Scope:** frontend only — no backend, no WebRTC, no real uploads
- **Started:** 2026-05-18

---

## Ground rules (locked with the user)

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | **Frontend only** — calls are simulated, files use in-memory `URL.createObjectURL` | No backend work in scope; data resets on refresh |
| 2 | **shadcn for new features only** | Existing screens are inline-styled; new components use `src/app/components/ui/*`. Existing Chat/Members/Topology tabs left untouched |
| 3 | **No other UI libraries** | `@mui/material` is installed but must not be used |
| 4 | **Dedicated Files tab** | Circle detail goes 4 → 5 tabs: Chat / Calls / Files / Members / Topology |
| 5 | **Full simulated call UI** | Connecting → Ongoing (live timer) → Ended state machine; no real camera |
| 6 | **Mobile-first, but also desktop** | Mobile-first ≠ mobile-only — the app runs on desktop too. Features land in **both** the mobile `NW04CircleDetail.tsx` and the tablet/desktop `CircleDetailPanel` in `NW01CirclesList.tsx` (see change log entry 5) |

---

## Architecture

New components live in `src/app/components/circle/`:

| File | Purpose |
|------|---------|
| `CallScreen.tsx` | Full-screen call overlay — voice + video modes |
| `CallControls.tsx` | Mute / camera / speaker / end-call buttons |
| `AttachmentMenu.tsx` | "+" menu in chat composer; hidden file inputs |
| `MessageAttachment.tsx` | Image-thumbnail & file-chip chat bubbles + lightbox |
| `FilesTab.tsx` | Shared-files list = the cloud-storage view |

Data model lives in `src/app/data/mockData.ts`.

---

## Change log

### Setup
- Created `feature/cloud-storage-comms` branch off `develop`.
- Created this decision log.

### 1 — Data model (`src/app/data/mockData.ts`)
- Added `files: CircleFile[]`, `storageUsedBytes`, `storageQuotaBytes` to each circle in `mockCircles`.
- `cir_001` seeded with 4 files + ~1.28 GB used of a 5 GB quota; `cir_002` left empty (demos the empty state).
- Chat message attachments (`type` / `attachment`) are **not** seeded — they are created at runtime when a user attaches a file.

### 2 — Voice & Video calls
- New `CallScreen.tsx` — full-screen overlay, voice + video modes. Simulated state machine: `connecting` (~2.2 s) → `ongoing` (live timer) → ends on hang-up.
- New `CallControls.tsx` — mute / camera / speaker / end-call, built with shadcn `Button`.
- Video tiles are placeholder gradients (no real camera, per decision 5).
- Wired the previously-dead "Start Voice/Video Call" buttons in `NW04CircleDetail.tsx`.
- On hang-up a `CallRecord` is prepended to the circle's `calls` history.
- **Decision:** call participants = online members excluding the current user; falls back to all members if none online.

### 3 — Chat attachments
- New `AttachmentMenu.tsx` — "+" button in the composer; shadcn `DropdownMenu` with Photo/Video, Document, Camera, each backed by a hidden `<input type="file">`.
- New `MessageAttachment.tsx` — image bubbles (thumbnail + tap-to-zoom `Dialog` lightbox) and file chips (icon, name, size, download).
- `NW04CircleDetail.tsx` chat bubble updated to render an attachment when present, otherwise text.
- **Decision:** picked files become object URLs (`URL.createObjectURL`) — session-only, lost on refresh (frontend-only constraint).

### 4 — Files tab (cloud storage)
- New `FilesTab.tsx` — storage meter (shadcn `Progress`), Upload button, filter chips (All / Images / Docs / Media), file list.
- Circle detail tab bar expanded 4 → 5 tabs: **Chat / Calls / Files / Members / Topology** (`FolderOpen` icon).
- **Decision:** `files`, `calls`, and storage values are captured into `useState` on the first render (which always uses the mock-data fallback before the API resolves). The mock API's `generateCircles()` does not return these new frontend-only fields, so this first-render capture is what makes the seeded data display — no backend change required.

### 5 — Desktop parity
- Initially the features were added only to the mobile `NW04CircleDetail.tsx`; at desktop width the app renders a different component (`CircleDetailPanel` inside `NW01CirclesList.tsx`), so nothing showed.
- Added the same Calls tab, Files tab, chat attachments and call overlay to `CircleDetailPanel` — circle detail is now 5 tabs (Chat / Calls / Files / Members / Topology) at **every** width.
- Added `key={selectedCircle.id}` to the `CircleDetailPanel` usages so it remounts per circle (fixes stale chat/calls state when switching circles, and re-seeds files/storage correctly).

### 6 — UX rework → WhatsApp / Slack model
Feedback: the first cut felt like a file-storage app bolted onto a chat, and the chat "+" was dead. Reworked around one principle — **the chat is the source of truth**.

- **Fixed the dead "+"** — root cause: `AttachmentMenu` used Radix `DropdownMenuTrigger asChild` around the shadcn `Button`, which is not a `forwardRef` component, so on this React 18 setup Radix could not anchor the menu. Rewrote `AttachmentMenu` as a plain bottom sheet (the app's own sheet pattern) opened by a plain `<button>` — no Radix `asChild`, no shadcn `Button` as a trigger.
- **Files tab is now chat-derived** — removed the storage meter, the separate Upload button, the seeded `circle.files` and the `storage*` fields. `FilesTab` now takes `SharedFile[]` computed by `collectSharedFiles(messages)` — a Media grid + Docs list. Uploading only happens in chat.
- **1-on-1 calls** — Members are callable individually: voice/video buttons in the member sheet (mobile) and per-row icons (desktop).
- **Group calls moved to the header** — voice + video icons in the circle header (mobile `PageHeader` right slot, desktop panel header). The Calls tab is now history-only; the big in-tab call buttons were removed.
- `CallScreen` prop `circleName` → `title` so it shows the person's name for 1-on-1 calls.
- Seeded two chat messages with attachments (one image as an inline SVG data URI, one document) so Chat and Files have content on first open.
- **Rule for this codebase:** never wrap the shadcn `Button` in a Radix `asChild` trigger — it silently breaks. Plain `Button` usage and Radix-native components (Dialog/Progress content) are fine.

### 7 — Polish: no all-caps, desktop overlays, dead Invite button
- Removed `textTransform: "uppercase"` from all Circle-screen labels (NW01, NW02, NW04, `FilesTab`).
- Desktop overlay fix: call screen, attachment sheet, and the invite/member sheets used `maxWidth: 440px` on the `fixed inset-0` element itself, so on a wide screen only a 440px strip was covered and the app showed through the sides. Moved the width cap to the inner panel — the backdrop now covers the full viewport with the panel centred.
- The desktop `CircleDetailPanel` Invite button had no `onClick` (dead since before this feature). Wired it to a compact invite sheet (code + copy link).

### Verification
- Circle feature files all pass an isolated esbuild syntax check.
- Full `npm run build` is currently **blocked by unrelated work**: `src/app/routes.ts` imports `./screens/storage/CS01StorageOverview` and `CS02FileDetail`, which do not exist — a separate "Cloud Storage / SGX Vault" feature being built in another session (`components/vault/`, `VaultContext`, `ThemeContext` also appeared). Not touched here; the build will pass once those screen files are added.
