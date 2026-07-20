# Circle-as-Comms Container + Invites — Complete Development Plan
### Base branch: `feat/62-CRL` · Module: `src/circle/` · **No new port required**

---

## 0. Grounding note (read first)

Written against the **actual indexed repo state**, not memory. Every claim below traces to a file I read.

**What I could NOT verify (be honest with the team):**

1. **GitHub live PR/diff fetch failed this session** — private repo (unauthenticated → 404), then rate-limited. Code below comes from the **project-knowledge index**. Re-confirm anchors against the tip of `feat/62-CRL` before applying.
2. **The full `ALLOWED_PERMISSIONS` list** — I saw these in use: `mesh:join`, `cert:request`, `cert:renew`, `attest:peer`, `did:resolve`, `status:read`, `vc:issue`, `vc:revoke`. Read `src/vc/issue.rs` for the complete constant before hard-coding any permission set.
3. **The `src/api/mod.rs` router-merge line** — I have `src/api/routes.rs` verbatim (so the new router fn is exact) but not the merge site. One-second eyeball needed.
4. **Whether the admin API port (8443) is permitted by nftables.** `build_nft_ruleset()` hard-codes allows for 22 / 5353 / 50051-53 / 50151-53 / 50061 / 50062 / 50063 / 50070 / 9000-udp / 4242-udp — **8443 is not in that list**; it presumably comes in via the active UEP policy rules. **The join flow depends on a peer reaching the owner's 8443.** Verify with `nft list ruleset | grep 8443` before D5, or the join will fail silently under enforcement (the same class of bug that once killed the gossip port).

---

## 1. The key architectural finding

### What already exists (do NOT rebuild any of this)

The VC layer is **complete and live**. `src/vc/issue.rs` already gives us:

| Capability | Function |
|---|---|
| Issue a membership VC | `issue_membership_vc(issuer_did, km, IssueRequest{ subject_did, role, permissions, circle_id, node_hint, duration_days })` |
| Reuse-or-replace logic | `issue_membership_vc_with_outcome()` → `ReusedExisting` / `IssuedNew{replaced_expired}` |
| Renew | `renew_membership_vc(issuer_did, km, RenewRequest{..}, node_id)` |
| Revoke (StatusList2021) | `StatusListManager::{load_or_create, allocate_index, set_revoked, commit}` |
| **Authorization gate** | `ensure_circle_owner(issuer_did, circle_id, VcAdminAction::{Issue,Revoke,Renew}, can_bootstrap)` |
| Verify | `verify_vc(vc, resolver, VerifyOptions{ expected_subject_did, expected_circle_id, expected_issuer_did, check_status_list, status_list })` |
| Lifecycle state | `classify_vc_state()` → `VcLifecycleState::{Active, Expired, Revoked}` |
| Roles / permissions | `CredentialRole::{Owner, Member}`, `default_permissions_for_role()` |
| Persistence | `save_issued / save_own / save_peer / list_issued / find_issued_for_subject_and_role / load_own_any`, `write_atomic` |
| Signing | `sign_in_place_generic(&mut proof, &canonical, km, &vm_ref)`, `vm_ref = "{did}#dkp-v{n}"` |
| **Cached KeyManager** | `load_runtime_key_manager(&node_id)` — **use this, never re-init `DkpManager`** (there is an explicit comment about SE050 traffic and collision risk) |
| Revoked-peer gate | `crl::is_revoked(did)` — fail-closed |
| REST already shipped | `POST /vc/issue`, `POST /vc/renew`, `/vc/*` |

### What is actually missing (this is the whole task)

```rust
// src/crl/issue.rs
pub const DEFAULT_CIRCLE_ID: &str = "guardian-circle-alpha";
```

**A Circle is currently just a hardcoded string.** There is no Circle entity, no registry, no CRUD, no invite token, no QR payload, no member-listing API.

But — and this is the finding that de-risks the whole feature — **the VC primitives are already multi-circle-capable**: `issue_membership_vc()` accepts *any* `circle_id`, and `verify_vc()` checks against *any* `expected_circle_id`. Only the *runtime* "which circle am I in" resolution is single-circle:

```rust
// src/crl/issue.rs — circle_id is derived from the local membership VC, not a constant
pub fn current_circle_id() -> Result<String, CrlError> {
    let membership = crate::vc::persistence::load_own_any()?...;
    Ok(membership.credential_subject.circle_id.clone())
}
```

### The resolution: two kinds of Circle

This is what the deliverable title — "Circle-**as-Comms-Container**" — is actually asking for, and it lets us ship multi-circle **without touching CRL gossip, Nebula, or cert-bootstrap at all**:

| | **Mesh Circle** (exactly one) | **Comms Circle** (many — new) |
|---|---|---|
| circle_id | `DEFAULT_CIRCLE_ID` | `circle-<uuid>` |
| Drives | Nebula certs, CRL gossip, attestation, overlay IP | Chat / Calls / Files membership scope |
| Created | Implicitly at first boot (owner VC) | By the operator, via this feature |
| Can be archived? | **No** | Yes |
| Touched by this task? | **No — read-only** | Yes |

Comms circles **ride the existing mesh**; they scope *who is in a conversation*, not *who is on the network*. `current_circle_id()`, gossip's circle-match check, and cert-bootstrap keep resolving to the Mesh Circle exactly as they do today.

> **Regression risk to Milestone 4 (CRL gossip): zero.** That is the point of this design. If we instead made gossip multi-circle-aware, we would be editing the module that is currently on the critical path.

**Trade-off to state openly:** a comms circle gives cryptographic membership proof (VC) and revocation (status list), but **not** a separate Nebula overlay. Two members of a comms circle must both be on the mesh. That is correct for the product (Circles are groups *within* your Guardian network), and it should be confirmed with Cervais rather than assumed.

---

## 2. Architecture

```
   OWNER (nodeA)                                    JOINER (nodeB)
┌──────────────────────────┐                   ┌──────────────────────────┐
│ POST /circles            │  create           │                          │
│ POST /circles/:id/invites│  mint             │                          │
└───────────┬──────────────┘                   └───────────┬──────────────┘
            │                                              │
            │  InviteToken (ECDSA-P256 signed by owner)    │
            │  { id, circle_id, circle_name, issuer_did,   │
            │    role, permissions, issued_at, expires_at, │
            │    max_uses, nonce, proof }                  │
            │                                              │
            │      ── QR / link / paste-code ──────────────►
            │                                              │
            │                                   POST /circles/join
            │                                   { token_b64, owner_host }
            │                                              │
            │                                   verify owner sig via Resolver
            │                                   check not expired
            │                                   build signed JoinRequest
            │                                              │
            │  ◄─── POST /circles/redeem  (over overlay/LAN, owner's :8443)
            │       { invite_token, joiner_did, nonce, proof(joiner DKP) }
            │                                              │
   OWNER verifies, in order:                               │
     1. invite proof  → own DKP, via Resolver                     
     2. expires_at not passed                                     
     3. invite not already at max_uses  ← replay ledger           
     4. joiner proof  → joiner's resolved DID Document            
     5. crl::is_revoked(joiner_did) → REJECT                      
     6. ensure_circle_owner(self, circle_id, Issue)               
            │                                              │
     issue_membership_vc(circle_id = comms circle)         │
     mark invite redeemed (atomic, under lock)             │
            │                                              │
            │  ──── 201 { vc } ────────────────────────────►
            │                                    persistence::save_own(&vc)
            │                                    member is now in the circle
```

**Two signatures = mutual proof.** The owner proves the invite is genuine; the joiner proves they control the DID they claim. Neither side trusts the channel — same zero-trust posture as CRL gossip.

**No new port, no new wire protocol.** The join call is plain REST over the existing admin API, reached over the overlay (already-enrolled node) or the LAN (fresh node, same path cert-bootstrap uses). This is the single biggest scope saving in this plan.

---

## 3. Security design

**Invite token** — signed, time-limited, replay-protected:

```rust
pub struct InviteToken {
    #[serde(rename = "@context")] pub context: Vec<String>,
    pub id: String,                    // urn:uuid:v4 — the replay key
    pub circle_id: String,
    pub circle_name: String,           // so the joiner can preview before accepting
    pub issuer_did: String,            // circle owner
    pub role: CredentialRole,          // role granted on redemption
    pub permissions: Vec<String>,      // must pass validate_permissions_for_role()
    pub issued_at: String,             // RFC3339
    pub expires_at: String,            // RFC3339 — default 24 h, clamp 5 min .. 30 d
    pub max_uses: u32,                 // default 1 (single-use)
    pub nonce: String,                 // 32 random bytes, base64
    pub proof: Proof,                  // ECDSA-P256, vm_ref = "{owner_did}#dkp-v{n}"
}
```

**Replay ledger** (owner side): `invites/redeemed.json` — `{ invite_id → [{redeemer_did, redeemed_at}] }`. Redemption is a read-modify-write serialized by `CIRCLE_WRITE_LOCK` (a `Lazy<Mutex<()>>`, exactly the `CRL_WRITE_LOCK` discipline). Refuse when `uses >= max_uses`. Refuse a second redemption by the same DID.

**Why a nonce when there is already a UUID id:** the id is the dedup key; the nonce ensures two invites minted in the same second with identical fields still produce distinct signatures.

**Permissions are never taken from the token blindly** — on redemption the owner re-derives them with `default_permissions_for_role(role)` and validates against `ALLOWED_PERMISSIONS`. A tampered token cannot escalate to `vc:issue`.

**Removal semantics — two different things, do not conflate:**

| Action | Meaning | Mechanism |
|---|---|---|
| **Remove from Circle** (the FE button) | "You are no longer in this group" | Revoke the membership VC → `status_list.set_revoked(index, true)` + `commit()` |
| **Revoke device** (security) | "This device is compromised" | `crl::issue::issue_revocation()` → gossips to the whole mesh |

The FE's *Remove from Circle* is the **first** one. It must **not** fire a CRL revocation — that would kick the device off the entire mesh.

---

## 4. Deliverables

Each is independently reviewable, independently testable, leaves the tree green (`cargo build && cargo test && cargo clippy -- -D warnings`), and changes no existing behaviour.

| # | Deliverable | Files | Acceptance test |
|---|---|---|---|
| **D1** | **Circle registry + persistence** (no network) | `src/circle/{mod,errors,model,persistence,store}.rs`, `src/lib.rs` | Unit: registry lazily seeds the Mesh Circle from the local owner VC on first read; create/edit/archive round-trips through signed, atomically-written `circles.json`; signature verifies; a tampered registry is rejected. |
| **D2** | **Circle CRUD + REST** | `src/api/handlers/circle.rs`, `src/api/routes.rs`, `src/api/mod.rs` | `POST /api/v1/circles` on nodeA creates a comms circle; `GET /circles` lists it plus the Mesh Circle; `PATCH` renames; `POST /circles/:id/archive` archives. A **member** node (non-owner) gets `403` — `ensure_circle_owner` gate fires. Mesh Circle cannot be archived. |
| **D3** | **Member administration** (pure VC reuse — no new crypto) | `src/circle/members.rs`, handlers | `POST /circles/:id/members {did, role}` issues a VC scoped to that comms circle; `GET /circles/:id/members` lists members with role + lifecycle state; `DELETE .../members/:did` flips the status-list bit (verify with `GET /vc/status`); `PATCH .../members/:did` changes role (revoke + reissue). **CRL is untouched** — assert `crl/list` is unchanged. |
| **D4** | **Invite tokens** (mint + verify + replay ledger — no network) | `src/circle/invite.rs` | Unit: valid token verifies; **expired → rejected**; **tampered byte → rejected**; **second redemption of a `max_uses:1` token → rejected**; token minted by a non-owner → rejected. Compact encoding round-trips and stays under the QR size budget. |
| **D5** | **Join flow, 2-node board test** | `src/api/handlers/circle.rs` (join + redeem) | nodeA mints an invite → nodeB `POST /circles/join` → nodeB holds a valid membership VC for the comms circle (`GET /vc/own`), nodeA's replay ledger shows one use. **Revoked joiner is rejected** (`crl::is_revoked` gate). |
| **D6** | **QR payload + share link** | `src/circle/invite.rs`, handlers | `POST /circles/:id/invites` returns `{invite_id, token_b64, qr_payload, link, expires_at}`; the FE renders a scannable QR from `qr_payload` without further encoding. |
| **D7** | **Regression + 3-node validation** | `tests/circle_*.sh` | Full 3-node run. **Mesh Circle untouched:** gossip rounds still complete, `crl/gossip/status` healthy, cert-bootstrap still enrolls, attestation still passes. Comms-circle membership does **not** leak into gossip's circle-match check. |

**Sequencing:** D1 → D2 → D3 is one dev, back-to-back (each small). **D4 can run fully in parallel** with D2/D3 — it is pure crypto + storage, no dependency on the CRUD endpoints. D5 re-converges. D6/D7 finish.

**Two devs:** Dev A takes D1→D2→D3; Dev B takes D4 from day one, then both meet at D5.

---

## 5. File structure (all new — strictly additive)

```
src/circle/
├── mod.rs           # CircleConfig, re-exports                        [D1]
├── errors.rs        # CircleError                                     [D1]
├── model.rs         # Circle, CircleKind, CircleStatus, CircleRegistry[D1]
├── persistence.rs   # paths + write_atomic (mirror vc/persistence.rs) [D1]
├── store.rs         # CIRCLE_WRITE_LOCK, load_or_seed, CRUD           [D1]
├── members.rs       # list/add/remove/role-change over the VC layer   [D3]
├── invite.rs        # InviteToken, sign, verify, replay ledger, QR    [D4]
└── tests/mod.rs     # unit tests                                      [D1/D4]

src/api/handlers/circle.rs   # REST handlers                           [D2/D3/D5]
```

Storage:

```
/var/lib/sgx-guardian/identity/circles/
├── circles.json                 # signed registry (owner's DKP)
└── invites/
    ├── <invite_id>.json         # minted invites (owner side)
    └── redeemed.json            # replay ledger
```

Env override: `SGX_GUARDIAN_CIRCLE_BASE` (mirrors `SGX_GUARDIAN_VC_BASE` — needed so unit tests can run in temp dirs).

---

## 6. Exact FIND → REPLACE blocks

### 6.1 `src/api/routes.rs` — add the router

**FIND** (verbatim — the closing lines of `crl_router()`):

```rust
        .route(
            "/api/v1/crl/gossip/trigger",
            post(handlers::crl::gossip_trigger),
        )
}
```

> ⚠️ If the **File Transfer** plan was already applied, `xfer_router()` now sits directly after this block. Append `circle_router()` after `xfer_router()` instead — the anchor above is still the right place to look, just add below the last router.

**REPLACE:**

```rust
        .route(
            "/api/v1/crl/gossip/trigger",
            post(handlers::crl::gossip_trigger),
        )
}

pub fn circle_router() -> Router<Arc<AppState>> {
    Router::new()
        // Circle CRUD
        .route("/api/v1/circles", get(handlers::circle::list).post(handlers::circle::create))
        .route(
            "/api/v1/circles/:id",
            get(handlers::circle::detail).patch(handlers::circle::edit),
        )
        .route("/api/v1/circles/:id/archive", post(handlers::circle::archive))
        // Members
        .route(
            "/api/v1/circles/:id/members",
            get(handlers::circle::list_members).post(handlers::circle::add_member),
        )
        .route(
            "/api/v1/circles/:id/members/:did",
            patch(handlers::circle::change_role).delete(handlers::circle::remove_member),
        )
        // Invites
        .route(
            "/api/v1/circles/:id/invites",
            get(handlers::circle::list_invites).post(handlers::circle::mint_invite),
        )
        .route(
            "/api/v1/circles/:id/invites/:invite_id",
            axum::routing::delete(handlers::circle::revoke_invite),
        )
        // Join (joiner side) / Redeem (owner side)
        .route("/api/v1/circles/join/preview", post(handlers::circle::join_preview))
        .route("/api/v1/circles/join", post(handlers::circle::join))
        .route("/api/v1/circles/redeem", post(handlers::circle::redeem))
}
```

Also extend the existing import at the top of `routes.rs`:

**FIND:**
```rust
use axum::{
    routing::{get, post},
    Router,
};
```

**REPLACE:**
```rust
use axum::{
    routing::{get, patch, post},
    Router,
};
```

---

### 6.2 `src/api/mod.rs` — merge the router  ⚠️ **verify this anchor**

Locate where `routes::crl_router()` is merged and add:

```rust
        .merge(routes::crl_router())
        .merge(routes::circle_router())   // ← add this line
```

---

### 6.3 `src/main.rs` — **no change required**

The registry is **lazily seeded on first read** (`store::load_or_seed()` from the handlers), not spawned at boot. This is deliberate: it keeps the feature strictly additive and keeps us far away from daemon-lifecycle code, which is the confirmed board-freeze surface.

### 6.4 `src/enforcement/executor.rs` — **no new port required**

Everything rides the existing admin API. **But run the 8443 check** (§0, item 4) before D5 — if the admin port is not reachable peer-to-peer under enforcement, the join call dies silently.

---

## 7. Implementation contracts

**Reuse, do not reimplement:**

```rust
// Issue a member into a comms circle — this is the entire "add member" implementation
crate::vc::issue::issue_membership_vc(
    &owner_did_record,
    &km,                                   // from load_runtime_key_manager(node_id) — CACHED
    IssueRequest {
        subject_did: &joiner_did,
        role: CredentialRole::Member,
        permissions: default_permissions_for_role(CredentialRole::Member),
        circle_id: &comms_circle_id,       // ← the only thing that differs from today
        node_hint: None,
        duration_days: Some(days),
    },
)?;
```

**Authorization** — never write a new permission check:

```rust
// Already enforces: caller holds an active, unexpired, unrevoked VC in this
// circle carrying the required permission (vc:issue / vc:revoke).
ensure_circle_owner(issuer_did, circle_id, VcAdminAction::Issue, /*can_bootstrap*/ false)?;
```

**Signing the registry and invites** — same as everything else:

```rust
let vm_ref = format!("{}#dkp-v{}", owner.did, owner.current_dkp_version.max(1));
crate::did::doc_sign::sign_in_place_generic(&mut obj.proof, &canonical, km, &vm_ref)?;
```

**KeyManager** — always `load_runtime_key_manager(&node_id)`. The code carries an explicit warning that re-running `DkpManager::init()` re-probes the SE050 slot and increases the odds of colliding with a concurrent SE050 operation. **Never construct a fresh `KeyManager` in a handler.**

**Async safety (board freeze):**
- No `std::thread::sleep`; no synchronous `Command::new().output()` in the runtime.
- Registry/ledger files are small (KB) — `std::fs` inside a short critical section is acceptable, matching what `vc/persistence.rs` already does. **Do not** hold `CIRCLE_WRITE_LOCK` across an `.await` on the network.
- The joiner→owner HTTP call must use an async client with an explicit timeout.
- Do not touch `NebulaDaemon::start()` or `resolve_ca_ip_from_config_inner()`. This feature has no reason to go near them.

**Audit** — add `AuditCategory::Circle`; log create / edit / archive / invite-minted / invite-redeemed / invite-replay-rejected / member-added / member-removed / role-changed.

---

## 8. Regression checks

```bash
cargo build --release
cargo test
cargo clippy -- -D warnings
cargo build --release --target aarch64-unknown-linux-gnu

# Must all still pass — we touched none of these
cargo test --package sgx-guardian-client vc::
cargo test --package sgx-guardian-client crl::
cargo test --package sgx-guardian-client did::
```

On the boards (binaries direct — **not** `systemctl` / `journalctl`):

```bash
./sgx_guardian_client nodeA      # owner
./sgx_guardian_client nodeB      # joiner

# PRE-FLIGHT for D5: can nodeB actually reach nodeA's admin API?
nft list ruleset | grep 8443     # ← if this is empty, the join dies silently

# Mesh Circle must be unharmed — this is the Milestone-4 guard
curl -s -X POST http://127.0.0.1:8443/api/v1/crl/gossip/trigger | jq .
curl -s http://127.0.0.1:8443/api/v1/crl/gossip/status | jq '.merkle_root, .rounds_initiated'
curl -s http://127.0.0.1:8443/api/v1/crl/list | jq '.count'

# Comms circle must NOT appear in the mesh circle's membership
curl -s http://127.0.0.1:8443/api/v1/vc/own | jq '.[].credentialSubject.circleId'

pkill -f sgx_guardian_client
```

---

## 9. Step-by-step checklist

**D1 — registry**
- [ ] `src/circle/{mod,errors,model,persistence,store}.rs`; `pub mod circle;` in `src/lib.rs`
- [ ] `Circle { circle_id, name, description, owner_did, kind: Mesh|Comms, status: Active|Archived, created_at, updated_at }`
- [ ] `CircleRegistry { circles: Vec<Circle>, sequence, proof }` — signed, atomically written
- [ ] `load_or_seed()` — on first read, seed the **Mesh Circle** from `load_own_any()`'s `circle_id` (do **not** hardcode `DEFAULT_CIRCLE_ID` into the registry — read it from the owner VC, so it stays correct if the constant ever changes)
- [ ] `CIRCLE_WRITE_LOCK`; `SGX_GUARDIAN_CIRCLE_BASE` env override
- [ ] Unit: seed, create, edit, archive, tampered-registry rejected

**D2 — CRUD + REST**
- [ ] `src/api/handlers/circle.rs`
- [ ] `ensure_circle_owner(.., VcAdminAction::Issue, false)` on every mutating route
- [ ] Mesh Circle: archive → `409 Conflict`
- [ ] routes.rs + mod.rs (§6.1, §6.2)
- [ ] Board: create + list + rename + archive on nodeA; non-owner nodeB gets 403

**D3 — members**
- [ ] `list_members(circle_id)` — `persistence::list_issued()` filtered by `circle_id`, state via `classify_vc_state()`
- [ ] `add_member` → `issue_membership_vc()`
- [ ] `remove_member` → status-list revoke **only** (assert CRL count unchanged)
- [ ] `change_role` → revoke + reissue
- [ ] Board: nodeB added to a comms circle, listed, removed; `crl/list` count unchanged

**D4 — invites** *(parallel with D2/D3)*
- [ ] `InviteToken` + canonical bytes + `sign_in_place_generic`
- [ ] `verify_invite(token, resolver)` — issuer resolved via `Resolver`, expiry, permission validation
- [ ] Replay ledger under `CIRCLE_WRITE_LOCK`; `max_uses` honoured
- [ ] Compact encoding + QR size budget check
- [ ] Unit: expired / tampered / replayed / non-owner-minted all rejected

**D5 — join flow**
- [ ] `POST /circles/join` (joiner) → builds signed `JoinRequest`, async HTTP to owner with timeout
- [ ] `POST /circles/redeem` (owner) → 6-step verification chain (§2), issue VC, mark redeemed, return VC
- [ ] Joiner `persistence::save_own(&vc)`
- [ ] **Pre-flight: `nft list ruleset | grep 8443`**
- [ ] Board: nodeA → nodeB end-to-end; revoked joiner rejected

**D6 — QR + link**
- [ ] `qr_payload` + `link` in the mint response; FE renders without re-encoding

**D7 — regression**
- [ ] 3-node run; gossip / CRL / cert-bootstrap / attestation all green
- [ ] Comms-circle VCs do not satisfy gossip's circle-match check

---

## 10. Risks

| Risk | Mitigation |
|---|---|
| **8443 not reachable peer-to-peer under nftables** → join dies silently | Pre-flight `nft list ruleset \| grep 8443` is a **D5 gate**, not an afterthought |
| **"Remove from Circle" wired to CRL revoke** → kicks the device off the whole mesh | Two distinct code paths, called out in §3; D3 acceptance asserts `crl/list` count is unchanged |
| **Comms circle leaks into gossip's circle check** → gossip rejects peers | D7 explicitly tests this. Gossip resolves circle via `current_circle_id()` → `load_own_any()`, which must keep returning the **Mesh** VC |
| `load_own_any()` ambiguity once a node holds **several** own VCs | **Design decision to make in D1:** `load_own_any()` must deterministically prefer the **Mesh Circle** VC. If it currently returns "the first found", that becomes a real bug the moment a node joins a comms circle. **Read that function before writing D1** — this is the sharpest hidden edge in the whole task. |
| SE050 contention from re-initialising KeyManager | Always `load_runtime_key_manager()` (cached) |
| Branch drift | Re-verify anchors against the tip of `feat/62-CRL` |

---

## 11. Explicitly out of scope (flag to Cervais)

- **Separate Nebula overlay per comms circle.** Comms circles scope membership, not network. Members must already share the mesh.
- **Multi-circle CRL gossip.** Gossip stays bound to the Mesh Circle. Revoking a device is mesh-wide by design.
- **Cross-Guardian invites to nodes not yet on the mesh.** Those still enrol through the existing cert-bootstrap flow (port 50061). Carrying the invite token inside that flow is a clean follow-up, deliberately not bundled here.
