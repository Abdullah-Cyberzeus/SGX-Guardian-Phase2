# Multi-User Roles & Permissions — Implementation Plan

## Context

The admin console today is **single-tier**: it uses Supabase email/password auth
(`src/app/contexts/AuthContext.tsx`) and every authenticated user gets the full
console. There is **no role or permission concept in the frontend**.

The Guardian **backend already has the model we need**. Identity is DID-based and
authorization flows through **Verifiable Credentials**:

- `CredentialRole = Owner | Member` (`new-guardian/src/vc/credential.rs`)
- Each credential carries a **`permissions: string[]`** array
  (`VcCredentialSubject` in `src/app/services/vcService.ts`)
- `MembershipStatus = Active | Suspended | Revoked` — a ready-made lifecycle
- Owner/Member default permission sets in `new-guardian/src/vc/issue.rs`
  (`OWNER_DEFAULT_PERMISSIONS`, `MEMBER_DEFAULT_PERMISSIONS`, `ALLOWED_PERMISSIONS`)
- `IssueVcRequest` **already accepts a custom `permissions` array**, so the Owner
  can mint arbitrary permission profiles without any backend change.

The backend enforces these permissions server-side. This plan adds the **frontend
gating layer** so the UI reflects what each user is allowed to do, and adds the
screens/flows to manage other users.

**Goal:** support four tiers — **Owner/Admin, Member/Operator, Auditor (read-only),
Circle/End-user** — with the user's tier derived from their **VC**.

## Core design decision: gate on permissions, label by role

The backend role enum is coarse (`Owner`/`Member`), but every credential already
ships a granular `permissions[]`. So:

- **Authorization is permission-based.** The UI checks `can('vc:issue')`, never
  `role === 'owner'`. This is forward-compatible and matches what the backend
  enforces.
- **"Role" is a display label** derived from the permission profile.
- **Auditor and Circle/End-user are permission *profiles*, not new backend roles.**
  The Owner issues a Member VC with a curated `permissions` array (via the existing
  `IssueVcRequest.permissions`). The FE recognises the profile by its capabilities.

This means **zero backend changes are required for v1**. (A later enhancement can
add finer-grained backend permission strings — see "Backend follow-ups".)

## Permission profiles (what the Owner issues)

| Profile | Backend role | Permissions (issued in the VC) |
|---|---|---|
| **Owner/Admin** | `owner` | full `OWNER_DEFAULT_PERMISSIONS` |
| **Member/Operator** | `member` | `MEMBER_DEFAULT_PERMISSIONS` (`mesh:join`, `cert:request`, `cert:renew`, `attest:peer`, `did:resolve`, `status:read`) |
| **Auditor (read-only)** | `member` | read-only subset: `did:resolve`, `status:read` only |
| **Circle/End-user** | `member` | `mesh:join`, `did:resolve`, `status:read` (+ circle use is app-level, not a guardian permission) |

These four profiles are defined once in the FE as named permission sets so the
Owner picks a profile in the UI instead of hand-editing permission strings.

## Capability → required-permission map (the gate)

The FE maps each app capability to the permission(s) it requires. Screens/sections
without a finer-grained backend permission fall back to an **Owner-tier** check
(documented as a v1 limitation).

| Capability / screen | Required permission(s) |
|---|---|
| View dashboards / topology / logs / attestation / integrity | `status:read` |
| Circles: chat / files / calls | `mesh:join` (app-level membership) |
| Run device / NMAP security scans | `status:write` *(Owner-tier in v1)* |
| Request / renew **own** cert | `cert:request` / `cert:renew` |
| Credentials → **issue / revoke** | `vc:issue` / `vc:revoke` |
| Manage circle membership | `circle:manage` |
| Key Management (DKP), DID publish, Policy, Transport lock | Owner-tier *(no fine-grained backend perm yet)* |
| Manage users / assign roles | `vc:issue` (Owner-tier) |

Read-only tiers (Auditor) get `status:read` only → they see everything gated on
`status:read` and **every mutating action/button is hidden**.

## Architecture — what to add / change (FE)

### 1. Link the logged-in user to their credential
The Supabase user and the Guardian DID/VC are separate. Bridge them:
- Store the user's **subject DID** in Supabase `user_metadata.did` at invite/onboarding.
- On login, fetch the active VC for that DID and read `role` + `permissions`.

**New:** `src/app/services/` — reuse `vcService.show()` / `vcService.getStatus()`.
Add a `vcService.showForSubject(did)` helper (filter `/vc/show` by subject) if a
server-side filter isn't already available; otherwise match client-side on
`VcMetaItem.subject`.

### 2. Permissions context + hook
**New:** `src/app/contexts/PermissionsContext.tsx`
- On auth ready, resolve the current user's `{ role, permissions, membershipStatus }`
  from their VC (bootstrap from `user_metadata.role` while the VC loads).
- Expose:
  - `useAuthz()` → `{ role, permissions, profile, loading }`
  - `can(permission: string): boolean`
  - `hasProfile('owner' | 'member' | 'auditor' | 'circle')`
- Handle `membership_status`: `Suspended`/`Revoked` → force read-only / sign-out.

**New:** `src/app/lib/permissions.ts` — the profile definitions + capability map
above as plain constants (single source of truth).

### 3. Gate the three surfaces
- **Navigation** — `src/app/components/AppSidebar.tsx`, `BottomNav.tsx`,
  `screens/settings/ST01SettingsRoot.tsx`: filter nav groups/items by `can(...)`.
  Hide (don't just disable) Owner-only sections — Security & Keys, Policy, DID,
  Transport, Credentials-issue — for non-owners.
- **Route guards** — `src/app/routes.ts` + `Root.tsx`/`MainLayout`: wrap protected
  routes in a `<RequirePermission perm="...">` element that redirects unauthorized
  users to their role landing (or a 403 screen). Add **new** component
  `src/app/components/RequirePermission.tsx`.
- **Action buttons** — inside screens (e.g. `VC01CredentialsList`, `KM01KeyManagement`,
  `NW05TransportStatus`, `NW07Discovery`): wrap mutating controls in `can(...)` so
  Members/Auditors see read-only views.

### 4. Role-aware landing
- **New:** a simplified Member/Circle home (`screens/home/MemberHome.tsx`) showing
  dashboard summary + Circles + own device/cert status.
- `Root.tsx` post-login redirect chooses landing by profile (Owner → current Home,
  Member/Circle → MemberHome, Auditor → read-only dashboard).

### 5. User management flow (Owner)
- **New/extend:** `screens/settings/ST09ManageGuardians.tsx` → a **Manage Members**
  view: list holders (`vcService.show()`), **Invite** (issue VC with a chosen
  profile via `vcService.issue` + the existing `permissions` override), **Suspend** /
  **Revoke** (`vcService.revoke` → `MembershipStatus`), and re-issue/renew.

## User flows delivered

1. **Member invite & onboarding** — Owner → Credentials/Manage Members → *Invite*,
   pick **Member/Auditor/Circle** profile, issue VC to the invitee's DID → invitee
   receives DID/QR → signs in → lands on the role-appropriate console.
2. **Member daily use** — login → Member home → Circles (chat/files/calls), own
   device + cert status, renew own cert, relevant alerts. Admin sections hidden.
3. **Auditor / compliance** — read-only access to logs, attestation, integrity,
   topology + report export. No mutating actions anywhere.
4. **Circle/End-user** — Circles + own devices only; no Guardian admin surface.
5. **Role lifecycle (Owner)** — invite, assign profile, **Suspend**/**Revoke** a
   member (maps to `vc:revoke` + `MembershipStatus`).

## Phased rollout

- **Phase 1 — gating core:** `permissions.ts`, `PermissionsContext`, `useAuthz/can`,
  VC resolution + Supabase `did`/`role` metadata. No UI changes yet (verify via a
  debug readout).
- **Phase 2 — gate surfaces:** nav filtering, `RequirePermission` route guards,
  action-button gating across mutating screens.
- **Phase 3 — Member experience:** role-aware landing + simplified Member home.
- **Phase 4 — Manage Members:** invite/assign/suspend/revoke screen.

## Backend follow-ups (optional, not required for v1)
- Add finer-grained permission strings (e.g. `keys:manage`, `policy:write`,
  `transport:lock`, `discovery:scan`) to `ALLOWED_PERMISSIONS` so Key/Policy/Transport
  screens gate on a real permission instead of an Owner-tier fallback.
- Consider a first-class `Auditor` `CredentialRole` if read-only becomes common.

## Risks / open questions
- **Supabase ↔ DID binding:** confirm where the invitee's DID is created and how it
  lands in `user_metadata.did` (invite flow needs to write it).
- **Client-side gating is UX, not security** — the backend already enforces
  permissions, so a gated button hidden in the FE is defence-in-depth, not the
  boundary. Keep all enforcement server-side.
- **Single-board assumption:** if one Guardian = one Owner, "members" are credential
  holders on that board; multi-board tenancy is out of scope here.
- **`/vc/show` subject filter:** verify it can filter by subject DID; otherwise
  filter client-side.

## Verification
- Unit: `can()` / profile-resolution against sample VC permission sets.
- E2E (Playwright, live board): issue Member/Auditor/Circle VCs, sign in as each,
  assert Owner-only nav/routes are **absent** and mutating buttons are hidden;
  assert Owner still sees everything. Extend `e2e/` with a `roles.spec.ts`.
- Manual on AnyDesk: Owner issues each profile → log in as each → walk the flows.
