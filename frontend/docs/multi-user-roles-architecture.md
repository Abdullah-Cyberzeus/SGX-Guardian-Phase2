# Multi-User Roles — Architecture & Diagrams

Companion to [`multi-user-roles-plan.md`](./multi-user-roles-plan.md). This document
is the **visual reference**: role hierarchy, permission model, file/component tree,
route-guard map, and the auth→authorization data flow.

> **One-line model:** Identity = **DID**, Authorization = **Verifiable Credential
> permissions**, UI = **gated on permissions, labelled by role**.

---

## 1. Role / profile hierarchy

```
                         ┌──────────────────────────┐
                         │        OWNER / ADMIN      │   backend role: owner
                         │  full OWNER_DEFAULT_PERMS │   (the console today)
                         └────────────┬─────────────┘
                                      │ issues credentials to ▼
            ┌─────────────────────────┼─────────────────────────┐
            ▼                         ▼                          ▼
 ┌────────────────────┐   ┌────────────────────┐    ┌────────────────────┐
 │  MEMBER / OPERATOR │   │   AUDITOR (R/O)    │    │  CIRCLE / END-USER │
 │  role: member      │   │   role: member     │    │   role: member     │
 │  operational perms │   │   read-only perms  │    │   circle-only      │
 └────────────────────┘   └────────────────────┘    └────────────────────┘

 Backend roles are only {owner, member}. Auditor and Circle are PERMISSION
 PROFILES the Owner issues (curated `permissions[]` on a member VC) — not new roles.
```

### Profile → permission set

```
owner    ─ mesh:join cert:issue cert:approve cert:renew vc:issue vc:revoke
           vc:status:update attest:peer did:resolve status:read status:write
           circle:manage                                      (OWNER_DEFAULT_PERMISSIONS)

member   ─ mesh:join cert:request cert:renew attest:peer did:resolve status:read
                                                            (MEMBER_DEFAULT_PERMISSIONS)

auditor  ─ did:resolve status:read                          (read-only subset)

circle   ─ mesh:join did:resolve status:read                (circle use is app-level)
```

---

## 2. Permission → capability map

What each permission unlocks in the UI. The gate checks the **left** column;
the UI shows the **right**.

```
PERMISSION              CAPABILITY (UI)
─────────────────────────────────────────────────────────────────────
status:read       ──►   View dashboards · topology · logs · attestation · integrity
mesh:join         ──►   Circles: chat / files / calls
cert:request      ──►   Request own certificate
cert:renew        ──►   Renew own certificate
attest:peer       ──►   Run peer attestation
did:resolve       ──►   Resolve / view DIDs
circle:manage     ──►   Manage circle membership
vc:issue          ──►   Credentials → Issue · Manage Members → Invite
vc:revoke         ──►   Credentials → Revoke · Suspend / Revoke member
vc:status:update  ──►   Update credential status
cert:issue        ──►   Approve / issue peer certificates
cert:approve      ──►   Approve cert requests
status:write      ──►   Mutating actions (toggles, scans, locks)

OWNER-TIER (no fine-grained backend perm yet — gated on owner profile in v1):
  Key Management (DKP) · DID publish · Policy · Transport lock · NMAP scan admin
```

---

## 3. Access matrix (role × area)

```
AREA                              OWNER   MEMBER   AUDITOR   CIRCLE
────────────────────────────────────────────────────────────────────
Home / dashboard / topology        ✅      ✅       👁        ✅
Circles (chat/files/calls)         ✅      ✅       👁        ✅
Devices + run scans                ✅      ✅       👁        own
Logs / Attestation / Integrity     ✅      👁       👁        ✖
Request/renew OWN cert             ✅      ✅       ✖         ✖
Key Management (DKP)               ✅      ✖        ✖         ✖
DID publish / Policy / Transport   ✅      ✖        ✖         ✖
Credentials: issue / revoke        ✅      ✖        ✖         ✖
Manage users / assign roles        ✅      ✖        ✖         ✖

✅ full   👁 read-only   own = own resources only   ✖ hidden
```

---

## 4. Authorization data flow

How a logged-in user's permissions are resolved and enforced.

```
  ┌────────────┐   email+pwd    ┌──────────────────┐
  │  Login UI  │ ─────────────► │  Supabase Auth   │
  └────────────┘                │  (AuthContext)   │
                                └─────────┬────────┘
                                          │ session.user.user_metadata.did
                                          ▼
                                ┌──────────────────────┐
                                │  PermissionsContext  │
                                │  resolve(did)        │
                                └─────────┬────────────┘
                                          │ vcService.show() → match subject==did
                                          ▼
                          ┌────────────────────────────────┐
                          │  Active VC for this DID         │
                          │  { role, permissions[],         │
                          │    membership_status }          │
                          └─────────┬──────────────────────┘
                                    │ derive profile + can()
                                    ▼
            ┌───────────────────────┼───────────────────────────┐
            ▼                       ▼                            ▼
   ┌─────────────────┐   ┌────────────────────┐      ┌────────────────────┐
   │   Navigation    │   │   Route guards     │      │  Action buttons    │
   │  filter by can()│   │ <RequirePermission>│      │  wrap in can()     │
   └─────────────────┘   └────────────────────┘      └────────────────────┘

  membership_status:  Active → normal   Suspended/Revoked → force read-only / sign-out
  NOTE: FE gating is UX/defence-in-depth. The backend ALSO enforces every permission.
```

---

## 5. File / component tree (new = +, changed = ~)

```
src/app/
├── lib/
│   └── permissions.ts                     + profiles, capability map, can() core
├── contexts/
│   ├── AuthContext.tsx                     ~ store/read user_metadata.did + role
│   └── PermissionsContext.tsx              + resolve VC → {role,permissions}; useAuthz()
├── components/
│   ├── RequirePermission.tsx               + route guard wrapper (redirect/403)
│   ├── AppSidebar.tsx                       ~ filter nav items by can()
│   ├── BottomNav.tsx                        ~ filter tabs by can()
│   └── PermissionGate.tsx                  + <PermissionGate perm="…"> for buttons
├── services/
│   └── vcService.ts                         ~ showForSubject(did) helper
├── screens/
│   ├── home/
│   │   ├── HM01Dashboard.tsx                  (Owner landing — unchanged)
│   │   └── MemberHome.tsx                   + simplified Member/Circle landing
│   ├── settings/
│   │   ├── ST01SettingsRoot.tsx             ~ filter nav groups by can()
│   │   └── ST09ManageGuardians.tsx          ~ → "Manage Members": invite/suspend/revoke
│   └── (mutating screens)                   ~ gate action buttons:
│       ├── credentials/VC01CredentialsList.tsx
│       ├── keys/KM01KeyManagement.tsx
│       ├── network/NW05TransportStatus.tsx
│       ├── network/NW07Discovery.tsx
│       └── policy/PL01PolicyManagement.tsx
├── routes.ts                                ~ wrap protected routes; role landing
└── Root.tsx                                 ~ post-login redirect by profile

e2e/
└── roles.spec.ts                            + per-profile nav/route/button assertions

docs/
├── multi-user-roles-plan.md                  (the plan)
└── multi-user-roles-architecture.md          (this file)
```

---

## 6. Route-guard map

Which routes are reachable per profile. Guarded by `<RequirePermission>`.

```
ROUTE                          REQUIRED PERM        OWNER  MEMBER  AUDITOR  CIRCLE
──────────────────────────────────────────────────────────────────────────────────
/home                          status:read            ✅     ✅      ✅       ✅
/network (circles)             mesh:join              ✅     ✅      👁       ✅
/network/discovery             owner-tier             ✅     ✖       ✖        ✖
/devices                       status:read            ✅     ✅      👁       own
/storage (files)               mesh:join              ✅     ✅      👁       ✅
/alerts                        status:read            ✅     ✅      👁       ✖
/settings/credentials          vc:issue               ✅     ✖       ✖        ✖
/settings/keys                 owner-tier             ✅     ✖       ✖        ✖
/settings/policy               owner-tier             ✅     ✖       ✖        ✖
/settings/did                  owner-tier             ✅     ✖       ✖        ✖
/settings/transport            owner-tier             ✅     ✖       ✖        ✖
/settings/integrity|logs|…     status:read            ✅     👁      👁       ✖
/settings/guardians (members)  vc:issue               ✅     ✖       ✖        ✖

Unauthorized access → redirect to the user's role landing (or a 403 screen).
```

---

## 7. User-flow diagrams

### 7a. Member invite & onboarding

```
OWNER                                   INVITEE
  │                                        │
  │ Manage Members → Invite                │
  │ pick profile {member|auditor|circle}   │
  │ vcService.issue(did, role, perms) ─────┼──► VC issued to invitee DID
  │                                        │
  │ share DID / QR ──────────────────────► │ sign in (Supabase)
  │                                        │ PermissionsContext resolves VC
  │                                        ▼
  │                                  role landing (Member/Auditor/Circle)
```

### 7b. Runtime gate (every protected action)

```
user action ──► can(permission)? ──── yes ──► render / allow
                      │
                      └──── no ──► hide control  (route → redirect to landing)
```

### 7c. Member lifecycle

```
        Invite                Suspend                 Revoke
 (issue VC) ──► Active ───────────────► Suspended ───────────► Revoked
                  ▲                         │                     │
                  └──────── reinstate ──────┘                     ▼
                                                        access removed (VC revoked)
   maps to: vcService.issue / vcService.revoke  +  MembershipStatus
```

---

## 8. Build phases (summary)

```
Phase 1  Gating core      permissions.ts · PermissionsContext · VC resolution
Phase 2  Gate surfaces    nav filter · RequirePermission · button gates
Phase 3  Member UX        role landing · MemberHome
Phase 4  Manage Members   invite / assign / suspend / revoke
```

See the plan doc for detail, risks, and the Supabase↔DID binding open question.
