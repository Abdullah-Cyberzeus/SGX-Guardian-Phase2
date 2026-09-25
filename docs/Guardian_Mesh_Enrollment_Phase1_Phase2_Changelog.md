# Guardian Mesh Enrollment — Phase 1 & Phase 2 Changelog

What actually changed in the codebase for Phase 1 (`main()` split + no fatal
exits) and Phase 2 (Create Mesh Circle), and the workflow that resulted.
Companion to [Guardian_Mesh_Enrollment_Complete_Plan.md](Guardian_Mesh_Enrollment_Complete_Plan.md)
(the plan and its per-phase exit criteria) and
[Guardian_Mesh_Enrollment_Outcomes.md](Guardian_Mesh_Enrollment_Outcomes.md)
(the plain-language before/after picture).

---

## 1. Phase 1 — `main()` split into boot vs. mesh activation

**Problem before:** `main()` did everything in one linear, synchronous
sequence — REST API bind, TLS identity setup, *and* the entire Nebula/CA/
enrollment flow — with several `std::process::exit(1)` calls scattered
through the enrollment section. Any enrollment failure (no CA reachable, no
cohort match, a bad policy load) killed the whole process, including the
REST API that Phase 2+ needs to be reachable *before* enrollment finishes.

**What changed:**

- `src/main.rs` — the REST API bind, TLS identity, mTLS server, and
  `AppState` setup now happen first, right after the legacy `cohort.split()`
  lookup. The rest of the old flow (Nebula install checks, CA discovery,
  cert request/broker fallback, DID publishing, policy enforcement — roughly
  1900 lines) was extracted into a new function and is no longer run inline.
- `src/mesh/activation.rs` (new) — holds that extracted function,
  `activate_mesh(...)`. `main()` now launches it with `tokio::spawn`
  instead of `.await`ing it, so a slow or failing enrollment no longer
  blocks the API from coming up.
- Every `std::process::exit(1)` in that path was replaced with
  `mesh::lifecycle::fail(reason)` followed by returning `Err(...)` from the
  spawned task — the process stays alive, and the failure becomes an
  observable `ERROR` lifecycle state instead of a crash. Two non-enrollment
  failures (an unmatched legacy cohort name, a bad policy-runtime reload)
  were downgraded further, from fatal to logged-and-continue, since neither
  is actually fatal to a running Guardian.
- `src/mesh/lifecycle.rs` (new in Phase 1) — the state machine
  (`Boot → Initializing → Unenrolled → ... → CircleMember → Online`, with
  `Error` reachable from anywhere) that makes the above observable over
  `GET /api/v1/mesh/lifecycle` and a live socket, instead of only in logs.

**Net effect:** the Guardian's web UI and API are reachable immediately on
boot, independent of whether mesh enrollment ever succeeds.

---

## 2. Phase 2 — Create Mesh Circle

**Problem before:** the Guardian that acts as CA was always `nodeA`, fixed
by hardcoded legacy cohort config. There was no way for an operator to make
*any* Guardian the CA of a brand-new circle from the UI.

**What changed:**

- `src/mesh/ca/mod.rs` + `src/mesh/ca/policy.rs` (new) —
  `mesh::ca::create_circle(...)`: generates a new Nebula CA, this
  Guardian's own keypair + self-signed membership cert, an overlay IP
  registry, and a per-circle enrollment policy, then commits it all into
  `/var/lib/sgx-guardian/nebula` and writes a `MeshProfile` marking this
  Guardian `role: Ca`. Everything is built in a staging directory first and
  only `rename`d into place once every step has succeeded, so a crash
  mid-creation leaves either nothing or a complete `nebula/` tree, never a
  half-built one.
- `src/api/handlers/mesh.rs` — `POST /api/v1/mesh/circles` (admin-only),
  `GET /api/v1/mesh/circle`. Circle creation is not activated live in the
  same process — see workflow below.
- `src/circle/store.rs` — `create_circle` now takes a `CircleKind`
  (`Mesh` vs `Comms`); the mesh circle created above is recorded as a
  distinct kind from the existing chat/alerts "Comms Circle" concept.
- Frontend: `frontend/src/app/screens/setup/SU02CreateCircle.tsx` (new,
  wired from the existing `SU01SetupChoice` screen's "Create Mesh Circle"
  button), `frontend/src/app/services/meshService.ts` (new). The two
  existing "Create Circle" screens for the chat/alerts feature
  (`OB08CreateFirstCircle.tsx`, `NW02CreateCircle.tsx`) were relabeled
  "Create Comms Circle" to avoid confusion with the new mesh flow.

---

## 3. The new workflow

**Boot (every start, Phase 1):**

1. `main()` loads config, sets up TLS/identity, binds the REST API — the UI
   is reachable at this point regardless of enrollment state.
2. `mesh::lifecycle::resolve_boot_state()` figures out where this Guardian
   left off (e.g. `Unenrolled` if no `MeshProfile` exists yet, `CircleMember`
   if one does).
3. `mesh::activation::activate_mesh(...)` is spawned in the background. If a
   `MeshProfile` already exists (this Guardian already belongs to a circle),
   it brings Nebula up using that profile. If not, it still runs the legacy
   self-bootstrap path (LAN CA discovery → cloud broker fallback) for
   backward compatibility with the old nodeA/B/C cohort setup — any failure
   here lands in `ERROR`, not a crash.

**Creating a circle (Phase 2, operator-driven):**

1. Operator opens the UI, lands on `SU01SetupChoice` while `Unenrolled`,
   picks **Create Mesh Circle** → `SU02CreateCircle`.
2. Frontend calls `POST /api/v1/mesh/circles` with a name and overlay CIDR.
3. The handler runs `mesh::ca::create_circle(...)` synchronously (staged →
   committed, as above), then schedules `std::process::exit(90)` ~400ms
   after responding.
4. Docker (`restart: unless-stopped`) or systemd (`Restart=on-failure`)
   restarts the process — this is the intentional activation mechanism:
   there is no live path from a running API handler into
   `activate_mesh`, which only runs from `main()`'s own stack frame.
5. On the *next* boot, `resolve_boot_state()` now finds the `MeshProfile`
   written in step 3, so `activate_mesh` brings Nebula up as `CircleMember`
   using the circle just created, and the lifecycle reaches `Online`.
6. The frontend polls/watches `GET /api/v1/mesh/lifecycle` through the
   restart and moves off the "restarting…" state once `Online` is observed.

---

## 4. Bugs found via live boot testing (and why unit tests missed them)

All four were only found by the user actually booting the container and
exercising the flow — not by `cargo check` or existing unit tests:

1. **Fatal exit on non-cohort node name.** `cohort.split(&node_id)`
   returned `None` for any Guardian not named `nodeA`/`nodeB`/`nodeC`, which
   called `exit(1)`. Fixed to fall back to `default_node_config` with no
   legacy peers instead of exiting.
2. **Fatal exit on policy runtime reload failure.** Downgraded to
   logged-and-continue, matching the handling its sibling "rejected
   signature" branch already used.
3. **False-positive in the Nebula self-signing safety check.**
   `NebulaCA::issue_node_cert_from_pub_with` (`src/nebula/ca.rs`) checked
   only whether `nodes/<name>.key` existed *after* signing, and treated
   that as proof `nebula-cert` had secretly written a private key despite
   `-in-pub`. True for every Phase 0 caller (a CA signing a *member's*
   cert never already holds that member's key) — false for Phase 2's
   self-signing case, where the CA generates its own key first and then
   signs its own membership cert with the same name. Fixed by capturing
   `key_pre_existed` before signing and only flagging a key that *appeared*
   during the call.
4. **Commit-time `rename()` onto a non-empty live directory.**
   `mesh::activation::activate_mesh`'s background legacy self-bootstrap
   (still running on every boot per Phase 1, see §3) can reach a LAN CA and
   call `cert_client::request_certificate_from_ca`, which mints this
   Guardian's own keypair straight into the *live* `nebula/nodes/` directory
   before it knows whether a signed cert will come back. If that legacy
   request doesn't fully complete, the bare keypair is left behind — and
   `create_circle`'s original pre-flight guard (checking only for `ca.crt`
   and a signed node `.crt`) didn't catch it, so the final
   `std::fs::rename(staging, live)` failed with `ENOTEMPTY`
   ("Directory not empty"). Fixed by re-running the same "no real identity
   material" check immediately before the commit rename, and clearing the
   directory only when it holds nothing but that harmless leftover keypair.

---

## 5. What Phase 2 deliberately does not do yet

- **Join Existing Circle** is still a placeholder alert in the UI — that is
  Phase 3+ work per the plan.
- Overlay CIDR is restricted to `/24` (the plan's aspirational `/16`–`/24`
  range needs `OverlayRegistry` and friends to support variable-width
  prefixes first).
- The self-issued owner VC on circle creation is best-effort: if issuance
  fails, circle creation still succeeds and the failure is only logged, not
  surfaced to the operator.
