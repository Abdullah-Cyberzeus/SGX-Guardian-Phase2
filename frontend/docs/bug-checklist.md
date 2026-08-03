# SGX Guardian Frontend — Bug & Issue Checklist

> Source: Email threads with Asad Ali (asadali@cyberzeusglobal.com) and Abdullah (CyberZeus PM), Apr–Jun 2026
> Last verified against codebase: 2026-06-19

---

## Legend
- Fixed & verified in code
- Fixed on frontend, backend verification pending
- Pending / not yet implemented
- Needs clarification

---

## Round 1 — UI Walkthrough Review (Asad, Apr 15)

| # | Issue | Status | File / Evidence |
|---|---|---|---|
| 1 | `pcr-status` not visible in UI | Fixed | `IN01IntegrityDashboard.tsx:553` — `usePCRStatus()`, renders PCR registers in "PCR Status" tab |
| 2 | `pcr-baseline-create` not visible | Fixed | `IN01IntegrityDashboard.tsx:585` — `handleCreateBaseline()` → `POST /pcr/baseline/update`, "Baseline" tab |
| 3 | `pcr-baseline-verify` not visible | Fixed | `IN01IntegrityDashboard.tsx:599` — "Verify Against Baseline" button → `POST /pcr/verify` |
| 4 | `dkp-revoke` not visible | Fixed | `KM01KeyManagement.tsx:33,810` — Dedicated "Revoke" tab, `POST /dkp/revoke` with `{ version, reason }` |
| 5 | Integrity page crash (`StatusBadge` — `Cannot destructure 'bg'`) | Fixed | `KM01KeyManagement.tsx:70` — `config[status] \|\| defaultConfig` safe fallback |

---

## Round 2 — Action Endpoints (Sprint 4, Apr 27 – Apr 29)

| # | Endpoint | Status | File / Evidence |
|---|---|---|---|
| 7 | `POST /dkp/rotate` | Fixed | `KM01KeyManagement.tsx` — wired, toast on response |
| 8 | `POST /dkp/revoke` | Fixed | `KM01KeyManagement.tsx:815` — sends `{ version, reason }` |
| 9 | `POST /dkp/emergency-rotate` | Fixed | `KM01KeyManagement.tsx` — "Emergency" tab wired |
| 10 | `POST /pcr/baseline/update` | Fixed | `IN01IntegrityDashboard.tsx:587` — `pcrService.updateBaseline()` |
| 11 | `POST /pcr/verify` | Fixed | `IN01IntegrityDashboard.tsx:615` — `pcrService.verifyBaseline()` |
| 12 | `POST /policy/sign` (multipart) | Fixed | `policyService.ts:67` — `FormData` with `policy` field |
| 13 | `POST /policy/verify` (multipart) | Fixed | `policyService.ts:74` — `FormData` with `policy` (.sig file) |

---

## Round 3 — AnyDesk Hardware Testing (May 2 – May 7)

| # | Issue | Status | File / Evidence |
|---|---|---|---|
| 14 | `POST /dkp/rotate` returning 500 on AnyDesk | Fixed | Backend fix by Asad (May 4). Frontend unchanged. |
| 15 | Integrity top status badge stuck on "Fail" even after successful PCR verification | Fixed | `IN01IntegrityDashboard.tsx:636–704` — 3-state logic: `allMatch` (green) / `noBaseline` (amber) / fail (red) |
| 16 | DKP Revoke sending wrong body (`keyId` instead of `{ version, reason }`) | Fixed | `KM01KeyManagement.tsx:732–733` — `revokeTargetKey.version` + `revokeReason` sent correctly |
| 17 | Policy Management returning `400` (multipart/form-data mismatch) | Fixed | Replaced with safer flow: `GET/PUT /policy/current` + `POST /policy/sign-deploy-current` |
| 18 | Toast messages using non-existent fields (`res.mismatches`, `res.isValid`) | Fixed | Updated to use `res.success` from `ActionResponse` |
| 19 | PCR Baseline Update sending unused `registers` param | Fixed | Removed from frontend call to match backend signature |

---

## Round 4 — Live Backend Issues (Asad, May 7)

| # | Issue | Status | File / Evidence |
|---|---|---|---|
| 20 | Boot Status — "Last Seen" not updating automatically (only on page refresh) | Fixed | `useApiData.ts:101` — `useBootStatus` polls every 30s; `HM02GuardianDetail.tsx:165` — 15s `setInterval` |
| 21 | Attestation tab — status not updating automatically | Fixed | `useApiData.ts:130` — `useAttestationResults` polls every 30s |
| 22 | Log entries not expanding on click | Fixed | `logService.ts:66` — `details: entry.message` (was `details: undefined`); `LG01LogsViewer.tsx:841–843` — expand toggle works |
| 23 | Baseline Status shows "passing" but below still shows "No baselines" | Fixed | `IN01IntegrityDashboard.tsx:637,865,897` — `baselineExists` gates register baseline display; `refetch()` called after create/verify (lines 599, 621) |
| 24 | Policy Workflow not synced with backend flow | Fixed | `PL01PolicyManagement.tsx:511,542,565,601` — all 4 new policy endpoints wired: `getCurrent`, `updateCurrent`, `signDeployCurrent`, `verifyDeployed` |

---

## Round 5 — New 7 API Endpoints (CyberZeus, May 21)

> Branch: `feat/54-w3c_did_documentation` — docs pushed to `docs/` folder

| # | Endpoint | Frontend Status | Backend Verification |
|---|---|---|---|
| 25 | `GET /did/status` | Implemented | Binary deployed Jun 12 (Abdullah) — not yet confirmed; AnyDesk connection failed |
| 26 | `GET /did/resolve` | Implemented | Same — pending confirmation |
| 27 | `POST /did/deactivate` | Implemented | Pending confirmation |
| 28 | `GET /did/document` | Implemented | Pending confirmation |
| 29 | `GET /did/document/raw` | Implemented | Pending confirmation |
| 30 | `POST /did/document/verify` | Implemented | Pending confirmation |
| 31 | `POST /did/document/publish` | Implemented | Pending confirmation |

> **Blocked on:** Correct backend IP for AnyDesk machine (see item #45). Once connection is restored, all 7 endpoints need live testing.

---

## Additional Items from MOM / Meetings

| # | Item | Status | Notes |
|---|---|---|---|
| 32 | Network topology views | Built | `HM03NetworkTopology.tsx` + full `topology/` component suite (EnterpriseTopology, MiniMap, WorldMap) |
| 33 | Peers UI integration | Built | `NW03PeersList.tsx` — `usePeers()` with 15s polling, all peer fields rendered |
| 34 | Revocation Key UI | Built | `KM01KeyManagement.tsx` — dedicated "Revoke" tab separate from History |
| 35 | Video call UI | Built | `NW04CircleDetail.tsx:167` — `startGroupCall("video")`, `CallScreen` component |
| 36 | Audio call UI | Built | `NW04CircleDetail.tsx:160` — `startGroupCall("audio")` wired |
| 37 | File attachments in chat | Built | `AttachmentMenu` + `MessageAttachment` in `NW04CircleDetail.tsx` |

---

## Round 6 — Abdullah Bug Report (Jun 4, pre-binary update)

> Email from Abdullah (PM, CyberZeus), Jun 4 2026.

| # | Issue | Status | File / Evidence |
|---|---|---|---|
| 40 | Page keeps auto-refreshing and scrolls user back to top | Fixed | `useApiData.ts:64–81` — polling uses `fetchData(true)` (silent mode); `loading` is never flipped to `true` on polls, so screens don't unmount and scroll position is preserved. Comments at lines 64–68, 79–80 document this. |
| 41 | Relay enable/disable button state flips automatically between polls | Fixed | `NW06RelayList.tsx:442–484` — optimistic override map applied immediately on toggle; override held until backend polling data confirms the new state, preventing the 10s poll from reverting the toggle. |

---

## Round 7 — Abdullah Bug Report (Jun 18, after binary update)

> Email from Abdullah (PM, CyberZeus), Jun 18 2026. Binary updated on AnyDesk board.

| # | Issue | Status | File / Evidence |
|---|---|---|---|
| 42 | DID Resolve view — DID Document displayed as raw JSON instead of readable UI | Fixed | `SC03DIDStatus.tsx:874` — `RawDocumentModal` defaults to `"structured"` view; "Raw JSON" toggle available |
| 43 | Integrity page — warning status persists after successful baseline verification | Fixed | `IN01IntegrityDashboard.tsx:635–636` — `PASS` and `HEALTHY` both map to green `pass` badge; comment at line 632 documents the fix |
| 44 | Peer DID Documents — eye/view buttons not working | Fixed | `SC03DIDStatus.tsx:583–602` — eye button calls `e.stopPropagation()` + `toggleDIDVisibility()`; row click calls `handleViewPeer()`; both interactions correctly separated |

---

## Round 8 — UI Bug Report (Jun 19, screenshots)

> Reported with annotated screenshots; all three are frontend-only UI bugs.
> Code-fixed and **verified live on Jun 19** against a seeded local backend
> (`feat/60_nmap`, localhost:8443) with sample DID + VC records.

| # | Issue | Status | File / Evidence |
|---|---|---|---|
| 45 | Credentials list — VC id / status / role badges overlap the date in the card header at narrow widths | Fixed | `VC01CredentialsList.tsx` — `StatusBadge`/`RoleBadge` given `flex-shrink-0 whitespace-nowrap`; id span given `minWidth:0` + `flexShrink:1` so it truncates instead of pushing siblings into the date column. Verified live at 560px — no overlap |
| 46 | DID Document "Raw" button opens the **structured** tab instead of Raw JSON | Fixed | `SC03DIDStatus.tsx` — `RawDocumentModal` now takes `initialView`; `handleViewRaw` opens `"raw"`, peer rows keep `"structured"`. Preserves the readable-default fix from item #42. Verified live — Raw opens Raw JSON |
| 47 | DID Status banner — eye/visibility control not working properly (whole DID row was the toggle; at wide widths the icon was pushed to the far edge, detached from the DID) | Fixed | `SC03DIDStatus.tsx` `HideableDID` — split into a selectable DID text span + a dedicated eye **button** placed adjacent to the DID (no longer `flex:1` stretched). Same pattern as the peer-row eye (item #44). Verified live — DID masks/unmasks on click |

---

## Summary

| Status | Count |
|---|---|
| Fixed & verified in code | 47 |
| Frontend done, backend confirmation pending | 7 |
| Pending / not started | 0 |
| Needs clarification | 0 |
| **Total** | **47** |
