# Guardian Mesh Circles — Create / Join, LAN + WAN Enrollment — Complete Development Plan
### Source spec: `Admin Invitation.md` (Multi-Guardian, Multi-Circle, LAN/WAN Enrollment Workflow)
### Base branch: `last-merge` @ `5a5dd0d` · Crates touched: `sgx_guardian_client`, `sgx-broker`, `frontend/`

---

## 0. Grounding note (read first)

This plan was written against the repository as it stands at `5a5dd0d`. Every "current state" claim below cites a file I read. Line numbers drift, so re-confirm anchors against the branch tip before editing.

**What I did NOT verify (confirm before the relevant phase):**

1. ~~**Nebula version on boards.**~~ **Resolved.** The vendored `docker/vendor/nebula-cert` is **1.10.3** and supports `keygen`, `sign -in-pub`, `verify` and `pki.blocklist`. Two caveats found while confirming this: `generate_ca` (`src/nebula/ca.rs:50-55`) passes no `-curve`, so all existing CAs are **25519** and member `keygen` must use the default curve too; and `nebula-cert` is invoked by bare PATH name at 6 sites, which P0.12 centralises. Still re-check each board image with `nebula-cert -version`, since P0.1 puts the binary on the member's critical path for the first time.
2. **First-admin creation security.** The frontend onboarding (`OB06AccountSetup`) creates the first admin locally. I did not audit how that first request is authenticated (setup code, physical presence, or the pairing challenge). Phase 1 makes the UI reachable earlier, so this must be confirmed before Phase 1 ships.
3. **nftables allow-list.** The current ruleset hard-codes 50061 and similar ports (noted in `docs/Circle_Management_Complete_Plan.md` §0.4). The new enrollment port and the mDNS CA advertisement must be added. Check `src/enforcement/` before Phase 3.
4. **Docker dev cohort.** `docker-compose.dev.yml` and `optional/container-cohort/` run nodeA/B/C on one host with name-derived ports. They will need matching updates, which I did not trace in detail.

---

## 1. Executive summary

The spec asks us to turn SGX Guardian from a **fixed three-node system where the first node is the CA** into a **Circle-based trust system**. In that system any Guardian boots to a local setup UI and the operator chooses **Create Mesh Circle** or **Join Existing Circle**. Joining tries the LAN first and falls back to the WAN. Enrollment keeps the private key on the Guardian and is gated by attestation and policy.

About 60% of the building blocks already exist. What blocks the product is mainly **structural**:

| # | Blocker | Where | Severity |
|---|---|---|---|
| B1 | **The CA generates and ships each member's Nebula private key**, over plaintext gRPC on the LAN and through the VPS broker on the WAN | `src/nebula/ca.rs:243` (`nebula-cert sign … -out-key`), `proto/cert.proto:19` (`node_key_pem`), `src/cloud/ca_broker.rs:421-475` (`key`), `sgx-broker/src/models.rs:43` | **Critical (security)**. Violates spec Principle 7 |
| B2 | Enrollment runs inline in `main()` before the API starts. The frontend is unreachable until a cert exists, and failure calls `exit(1)` | `src/main.rs:1113-1430`, then API bind at `src/main.rs:2788` | Blocks Phase 1 |
| B3 | "Am I the CA?" means `node_id == "nodeA"`. There are about 700 `nodeA` literals across `src/` | `src/main.rs:94,119,875,2908,2966`, `src/cert_service.rs`, `src/nebula/*`, `src/attestation_service.rs` … | Blocks Create/Join |
| B4 | Circle ID and overlay subnet are constants: `"guardian-circle-alpha"` appears 204 times and `"192.168.100…"` 464 times | `src/crl/issue.rs` (`DEFAULT_CIRCLE_ID`), `OverlayRegistry::load_or_create(… "192.168.100", "nodeA")` everywhere | Blocks multi-circle |
| B5 | Ports are derived from the names nodeA/B/C | `src/startup/config.rs:28` (`chat_grpc_port`), `src/attestation_service.rs:292`, `src/p2p_discovery.rs:230`, `src/client.rs:27`, `src/startup/bootstrap.rs:34` | Creates the literal three-node limit |
| B6 | Enrollment channel is unauthenticated. `:50061` is plaintext, `pairing_proof` is sent but **never checked** by the CA, and the CA is trusted by IP address | `src/server.rs:172`, `src/cert_service.rs` (no `pairing` reference), `src/main.rs:3419-3489` | High. Violates Principle 10 of the spec (§10) |
| B7 | No attestation at enrollment time. Attestation is peer-to-peer only after joining | `src/attestation_service.rs` | Violates Principle 8 |
| B8 | Approval happens by editing `nebula/requests/<node>.yaml` on disk. The gRPC call blocks for up to one hour while it polls | `src/cert_service.rs:411-595` | UX / scalability |
| B9 | LAN discovery looks for "nodeA's config file". There is no CA advertisement, so multiple CAs on one LAN cannot be told apart | `src/main.rs:3432`, `src/startup/ca_discovery.rs` | Blocks LAN CA list |

**Recommended strategy:** fix B1 and B6 first as a standalone security hotfix. Then land a **"Mesh Profile" abstraction** that replaces name-based roles (B3–B5). Build the new boot and enrollment flows on top of it. Legacy nodeA/B/C deployments stay working through automatic migration.

---

## 2. Correction to the source spec: Nebula cannot carry enrollment

The spec (§17–18 and §41, steps 7–10) has the joining Guardian reach the remote CA **over the Nebula overlay** and then enroll. **This does not work with Nebula.** A host cannot complete a Nebula handshake, including with a lighthouse, without a certificate signed by a CA the peer trusts. A Guardian without a certificate therefore cannot use the overlay to obtain its first certificate.

**Resolution, which matches the code we already have:**

```
                 PUBLIC VPS  (one host, two services)
       ┌─────────────────────────────────────────────────────┐
       │ sgx-broker  = RENDEZVOUS (HTTPS/WSS, TCP)           │  ← pre-enrollment
       │   • circle directory / join-code lookup             │
       │   • relays signed enrollment msgs to the home CA    │
       │ nebula      = LIGHTHOUSE (+relay) (UDP 4242+)       │  ← post-enrollment
       │   • per-circle instance, cert signed by circle CA   │
       └─────────────────────────────────────────────────────┘
```

- **Before enrollment:** the Guardian talks to the **Rendezvous** (`sgx-broker`) over HTTPS. The CA keeps an outbound WSS to the broker (`src/cloud/ca_broker.rs`, already implemented), which works behind the USA CA's NAT.
- **After enrollment:** the Guardian has a certificate, so Nebula starts, the Lighthouse assists discovery, and peers talk directly or through a relay.
- The spec's roles hold: the Rendezvous and Lighthouse are **not** the CA. They carry only public, signed messages, and the private key never leaves the Guardian.
- In the frontend, the "Lighthouse address" field from the spec (§12) becomes **"Rendezvous / Lighthouse server"**. It is one hostname, for example `lighthouse.example.com`. The broker returns the Nebula lighthouse endpoints inside the enrollment bundle.

### 2.1 Mapping spec concepts to codebase components

| Spec concept | Codebase today | Target |
|---|---|---|
| Guardian | `sgx-guardian <node_id>` daemon (`src/main.rs`) | Same binary. `node_id` becomes `guardian_id` |
| Circle (trust domain) | `Circle{kind: Mesh}` model in `src/circle/model.rs`. The runtime still uses the constant `guardian-circle-alpha` | `MeshProfile.circle_id` plus a `Circle` record |
| CA | `NebulaCA` (`src/nebula/ca.rs`) + `MyCertService` (`src/cert_service.rs`), active only on `nodeA` | `mesh::ca` module, active when `MeshProfile.role == Ca` |
| Enrollment | `CertService.RequestCertificate` (`proto/cert.proto`), `cert_client.rs`, `cloud/ca_broker.rs` | `EnrollmentService v2` (§5.3) |
| Attestation evidence | `AttestationEvidence` (PCR composite, DKP, nonces) in `src/attestation_service.rs` | Reused as the enrollment evidence payload |
| Membership credential | VC issued by `issue_member_vc` (`src/cert_service.rs:97`) via `src/vc/issue.rs` | Unchanged. It is already multi-circle capable |
| Lighthouse | `LighthouseRegistry` (`src/nebula/lighthouse.rs`), VPS nebula (`sgx-broker/src/lighthouse_manager.rs`) | Per-circle lighthouse, with endpoints delivered in the enrollment bundle |
| WAN channel | `sgx-broker` `POST /api/v1/enroll` + `/ws/ca-bridge` | `sgx-broker` API v2 (§Phase 6) |
| LAN discovery | UDP broadcast `node_broadcast.rs`/`node_listener.rs`, mDNS `_sgx-guardian._tcp` (`p2p_discovery.rs`) | New signed `_sgx-ca._tcp` advertisement |
| Approval UI | `/api/v1/cert/requests`, `/cert/approve`, `/cert/requests/ws` (`src/api/handlers/cert.rs`), `ST16PendingApprovals`, `IncomingCertificateRequestDialog` | Same screens, backed by the v2 request store |
| Revocation | CRL + gossip + offline sync (`src/crl/`) | Plus Nebula `pki.blocklist` generation |
| Frontend setup | `OB01Welcome` (signup/join), `OB08CreateFirstCircle`, `MemberJoinOnboarding` | New `SU*` setup screens behind a lifecycle gate |

---

## 3. What already exists — reuse it, do not rebuild

| Capability | Where | Used in phase |
|---|---|---|
| Testable startup with a path sandbox | `src/startup/mod.rs` (`GuardianPaths::rooted_at`) | 0, 1 |
| Circle entity with `CircleKind::Mesh` / `Comms` | `src/circle/model.rs`, `store.rs`, `persistence.rs` | 2 |
| Multi-circle VC issue/verify/revoke | `src/vc/issue.rs`, `src/vc/verify.rs`, `status_list.rs` | 4, 8 |
| DID + signed DID documents | `src/did/*` | 3, 4 |
| Hardware keys (SE050 DKP/DIK, TPM) | `src/key_manager.rs`, `src/secure_element/*`, `src/tpm/*` | 4, 5 |
| Pairing challenge/proof primitives | `src/api/auth/pairing.rs` (`issue_challenge`, `build_pairing_proof`, `verify_proof`) | 4 (join codes) |
| PCR / boot-chain evidence | `src/secure_element/pcr.rs`, `src/startup/pcr_status.rs`, `AttestationEvidence` | 5 |
| CA approval REST + WebSocket + UI | `src/api/handlers/cert.rs`, `features/certificates/*`, `ST16PendingApprovals` | 4 |
| Broker keyed by `circle_id` | `sgx-broker/src/state.rs` (`get_ca_sender(circle_id)`) | 6 |
| CA outbound WSS worker | `src/cloud/ca_broker.rs` (`start_ca_broker_worker`) | 6 |
| Lighthouse / relay registries | `src/nebula/lighthouse.rs`, `relay_registry.rs`, `registry_sync.rs` | 7, 9 |
| Nebula config generator | `src/nebula/config.rs` | 0, 7 |
| Cert expiry monitor | `src/nebula/cert_lifecycle.rs` (`ExpiryMonitor`) | 8 |
| CRL gossip + offline sync | `src/crl/gossip/*`, `src/crl/offline/*` | 8 |
| QR generate / scan dependencies | `qrcode.react`, `jsqr` in `frontend/package.json` | 2, 3 |

---

## 4. Target architecture

### 4.1 Module layout (new code is additive)

```
src/
├── mesh/                         ← NEW: the "who am I in which circle" layer
│   ├── mod.rs
│   ├── profile.rs                MeshProfile (persisted), role, circle, overlay, CA pin
│   ├── lifecycle.rs              GuardianLifecycle state machine + watch channel
│   ├── activation.rs             activate_mesh(): everything main.rs does after enrollment
│   ├── legacy.rs                 nodeA/B/C → MeshProfile migration (the ONLY place
│   │                             allowed to contain the literal "nodeA")
│   ├── ca/
│   │   ├── mod.rs                CA initialisation (wraps nebula::ca::NebulaCA)
│   │   ├── descriptor.rs         Signed CaDescriptor (identity, fingerprints, endpoints)
│   │   ├── requests.rs           Enrollment request store (replaces YAML polling)
│   │   ├── policy.rs             CircleEnrollmentPolicy evaluation
│   │   └── issuer.rs             sign -in-pub, VC issue, bundle assembly
│   ├── enroll/
│   │   ├── mod.rs
│   │   ├── keys.rs               local `nebula-cert keygen` (private key never leaves)
│   │   ├── request.rs            build EnrollRequestV2 (+ binding signature, evidence)
│   │   ├── transport_lan.rs      gRPC-over-TLS with CA pinning
│   │   ├── transport_wan.rs      Rendezvous (sgx-broker v2) client
│   │   └── install.rs            validate + atomically install EnrollmentBundle
│   ├── discovery/
│   │   ├── advertise.rs          CA: mDNS `_sgx-ca._tcp` + UDP beacon (signed)
│   │   └── browse.rs             Joiner: collect + verify advertisements
│   └── joincode.rs               Join code / QR payload encode, decode, verify
├── api/handlers/mesh.rs          ← NEW: /api/v1/mesh/* endpoints
proto/enroll.proto                ← NEW: EnrollmentService v2
sgx-broker/src/v2/                ← NEW: rendezvous directory + enrollment relay v2
frontend/src/app/screens/setup/   ← NEW: SU01–SU09 setup screens
frontend/src/app/services/meshService.ts ← NEW
```

### 4.2 MeshProfile, the single source of truth

Stored at `/var/lib/sgx-guardian/mesh/profile.json` (mode 0600, atomic write). It replaces every name-based role check.

```rust
pub struct MeshProfile {
    pub schema_version: u32,              // 1
    pub guardian_id: String,              // was node_id; [A-Za-z0-9_-]{1,48}
    pub role: MeshRole,                   // Ca | Member
    pub circle_id: String,                // e.g. "circle-7f3c…" (random, not a name)
    pub circle_name: String,              // display name, e.g. "SGX-Alpha"
    pub ca_guardian_id: String,           // who signs for this circle
    pub ca_fingerprint: String,           // SHA-256 of Nebula CA cert — the trust pin
    pub ca_owner_did: String,             // DID of the CA Guardian (signs descriptors)
    pub overlay_cidr: String,             // e.g. "192.168.100.0/24" (per circle)
    pub overlay_ip: String,               // this Guardian's overlay IP/CIDR
    pub lighthouses: Vec<LighthouseHint>, // overlay IP + public endpoint(s)
    pub rendezvous_url: Option<String>,   // WAN broker, if joined via WAN
    pub enrolled_via: EnrollChannel,      // Created | Lan | Wan | LegacyMigration
    pub enrolled_at: String,
}
```

Accessor API that replaces the `nodeA` literals:

```rust
mesh::profile::current()                -> Option<Arc<MeshProfile>>   // None = UNENROLLED
mesh::profile::is_ca()                  -> bool
mesh::profile::circle_id()              -> Result<String>
mesh::profile::ca_guardian_id()         -> Result<String>
mesh::profile::overlay_prefix()         -> Result<String>              // "192.168.100"
```

### 4.3 Lifecycle state machine

Stored at `/var/lib/sgx-guardian/mesh/lifecycle.json`. Broadcast in-process through `tokio::sync::watch` so the API, UI WebSocket and `activation.rs` all see transitions.

```
BOOT → INITIALIZING → UNENROLLED ─┬─ CREATING_CIRCLE ───────────────────────────┐
                                  └─ DISCOVERING_CA (LAN)                        │
                                        ├─ WAITING_FOR_CA_SELECTION              │
                                        └─ CONNECTING_TO_REMOTE_CA (WAN)         │
                                               ↓                                 │
                                        ENROLLING → PENDING_APPROVAL             │
                                               ↓           ↓ (reject)            │
                                   CERTIFICATE_RECEIVED   REJECTED → UNENROLLED  │
                                               ↓                                 │
                                   CERTIFICATE_VALIDATED                         │
                                               ↓                                 ↓
                                        CIRCLE_MEMBER  ←─────────────────────────┘
                                               ↓ activate_mesh()
                                            ONLINE   (ERROR reachable from any state)
```

Rules:
- `PENDING_APPROVAL` is new relative to the spec. Manual approval is asynchronous, so the Guardian must survive restarts while waiting. The request ID is persisted and polling resumes.
- On boot: a valid profile and certificate go straight to `CIRCLE_MEMBER` and then `ONLINE`. A persisted `PENDING_APPROVAL` resumes polling. Anything else becomes `UNENROLLED`.
- `ERROR` never calls `exit(1)`. It shows the reason in the UI and offers **Retry** or **Reset to UNENROLLED**.

### 4.4 Key custody (fixes B1)

| Key | Generated by | Stored | Ever transmitted? |
|---|---|---|---|
| Circle CA key (`nebula/ca/ca.key`) | CA Guardian at **Create Circle** | CA Guardian, 0600. Phase 8 can wrap it with SE050/TPM | Never. Encrypted backup only |
| Guardian Nebula key | **Each Guardian locally**, with `nebula-cert keygen` | Guardian, 0600 | **Never.** Only the `.pub` goes to the CA |
| Guardian device/DID key (DKP/DIK) | SE050 / TPM / software `KeyManager` | Secure element | Never. It signs the binding |
| VPS lighthouse Nebula key | VPS locally | VPS | Never. The CA signs its `.pub` over WSS |

CA side: `nebula-cert sign -name <gid> -ip <ip> -groups <g> -in-pub <gid>.pub -ca-crt … -ca-key … -out-crt <gid>.crt`. With `-in-pub` no private key is created on the CA.

### 4.5 Trust pinning: how the joiner knows it has the right CA (fixes B6)

Every CA publishes a **CaDescriptor** signed with its DID key:

```json
{
  "v": 1,
  "circle_id": "circle-7f3c…", "circle_name": "SGX-Alpha",
  "ca_guardian_id": "us-hq-01", "ca_owner_did": "did:guardian:…",
  "nebula_ca_fingerprint": "sha256:…",
  "enroll_tls_spki_sha256": "…",
  "endpoints": { "lan": ["192.168.1.50:50071"], "rendezvous": "https://lh.example.com" },
  "policy_summary": { "attestation": "required", "approval": "manual|join_code" },
  "issued_at": "…", "expires_at": "…",
  "proof": { "type": "EcdsaSecp256r1Signature2019", "verificationMethod": "did:guardian:…#dkp-v3", "jws": "…" }
}
```

The joiner accepts a CA in one of two ways:

1. **Join code or QR (recommended, default).** The CA admin creates a single-use code in the UI. It contains `circle_id`, `nebula_ca_fingerprint`, `ca_owner_did` fingerprint, a one-time secret and an expiry. The joiner rejects any CA whose descriptor does not match. The secret authenticates the joiner, and requests carrying a valid code can be auto-approved if policy allows.
2. **Trust on first use with an out-of-band check.** No code is used. The UI shows the fingerprint as a short phrase plus hex, and the operator must confirm that it matches the CA's own screen. The request always goes to **manual approval** on the CA.

The TLS server certificate of the LAN enrollment endpoint must match `enroll_tls_spki_sha256` from the signed descriptor. This closes the gap where the CA was trusted by IP address alone.

---

## 5. Protocols

### 5.1 LAN CA advertisement (`mesh::discovery`)

- **mDNS:** service `_sgx-ca._tcp.local`, port = enrollment port (default **50071**, configurable). TXT: `v=1`, `cid=<circle_id>`, `cn=<circle_name>`, `fp=<first 16 hex of CA fp>`, `did=<owner DID suffix>`. Reuse the `libmdns` responder already in `p2p_discovery.rs`.
- **UDP beacon fallback:** networks and boards where mDNS is unreliable already use UDP broadcast (`node_broadcast.rs`, port 9000). Add a new message type `CaBeacon{descriptor_url, circle_id, fp}` alongside `NodeAnnouncement`.
- **Browse:** the joiner collects candidates for about 5 s, then fetches the full `CaDescriptor` from each (`GetCaDescriptor` RPC). It verifies the signature and expiry and drops invalid ones. The API returns the verified list. Duplicate `circle_id`s are shown grouped. Several CAs on one LAN are therefore naturally supported.
- A candidate is never trusted because of its IP address. Unverified candidates are shown greyed out as "unverified" and cannot be selected.

### 5.2 Join code format

`SGXJ1-<base32(payload)>-<checksum>`. The payload is CBOR or compact JSON: `{cid, cafp, didfp, secret(16B), exp, rv?(rendezvous URL), lan?(hint)}`. The QR code encodes the same string. It is single-use and expires in 24 h by default. The CA stores only `sha256(secret)`. Implement it in `mesh/joincode.rs`, reusing the challenge and TTL handling from `api/auth/pairing.rs`.

### 5.3 EnrollmentService v2 (`proto/enroll.proto`)

This replaces the blocking `CertService.RequestCertificate`. It is the same message set on LAN (gRPC over TLS) and WAN (JSON over the broker), so there is one code path in `mesh/ca/*`.

```protobuf
service EnrollmentService {
  rpc GetCaDescriptor (Empty)               returns (SignedCaDescriptor);
  rpc BeginEnrollment (BeginRequest)        returns (EnrollmentChallenge);   // nonce
  rpc SubmitEnrollment(EnrollRequestV2)     returns (EnrollmentTicket);      // request_id
  rpc GetEnrollmentStatus(TicketQuery)      returns (EnrollmentStatus);      // poll
  rpc FetchBundle     (TicketQuery)         returns (EnrollmentBundle);      // when approved
}

message EnrollRequestV2 {
  uint32 protocol_version     = 1;   // 2
  string circle_id            = 2;
  string requested_guardian_id= 3;
  string did                  = 4;
  string did_document_json    = 5;   // signed DID doc (already produced by did_boot)
  string nebula_public_key_pem= 6;   // from local `nebula-cert keygen`
  bytes  device_pubkey_der    = 7;   // DKP/DIK public key
  bytes  challenge_nonce      = 8;   // from BeginEnrollment
  bytes  binding_signature    = 9;   // DeviceKey.sign(SHA256("SGX-ENROLL-v2"‖circle_id‖
                                      //   ca_fp‖nonce‖nebula_pub‖did))
  string attestation_evidence_json = 10;  // AttestationEvidence (PCR composite, boot chain,
                                          //   DKP version) signed over the same nonce
  string join_code_proof      = 11;  // HMAC(secret, transcript_hash) or empty (TOFU)
  repeated string requested_roles = 12;  // "member" | "lighthouse" | "relay"
  string device_metadata_json = 13;  // model, fw version, hw backend (SE050/TPM/soft)
}

message EnrollmentStatus {
  string request_id = 1;
  string state      = 2;  // PENDING_APPROVAL | APPROVED | REJECTED | EXPIRED
  string reason     = 3;
  string policy_report_json = 4;   // which checks passed/failed (shown in UI)
}

message EnrollmentBundle {           // everything here is PUBLIC; no private keys
  string guardian_cert_pem   = 1;
  string ca_cert_pem         = 2;   // may be a bundle (multi-CA, Phase 9)
  string circle_json         = 3;   // Circle record
  string overlay_ip_cidr     = 4;
  string lighthouses_json    = 5;   // overlay IPs + public endpoints + ports
  string relays_json         = 6;
  string member_vc_json      = 7;
  bytes  pa_signing_pubkey_der = 8;
  bytes  signed_policy_bytes = 9;
  string blocklist_json      = 10;  // Phase 8
  bytes  bundle_signature    = 11;  // CA DID key over SHA256(fields 1..10) — detects
                                     //   tampering by the broker
}
```

**Joiner validation before installing (`mesh/enroll/install.rs`):**
1. `bundle_signature` verifies against `ca_owner_did`, which was pinned via the join code or TOFU.
2. `sha256(ca_cert_pem) == pinned ca_fingerprint`.
3. `nebula-cert verify -ca ca.crt -crt guardian.crt` succeeds.
4. `nebula-cert print -json` public key equals the local `.pub`.
5. The name equals the assigned `guardian_id`, the IP is inside the circle `overlay_cidr`, the groups are expected, and `notBefore ≤ now < notAfter`.
6. VC `verify_vc(expected_subject_did = own DID, expected_circle_id)` passes.
7. The install is atomic: write to `mesh/staging/`, fsync, then rename. The profile is written last.

---

## 6. Phased implementation plan

Sizes: **S** ≤ 2 dev-days, **M** 3–5, **L** 6–10. Each task lists files, the change, and acceptance criteria (AC).

```
Phase 0 ─► Phase 1 ─► Phase 2 ─┐
   │                           ├─► Phase 4 ─► Phase 5 ─► Phase 6 ─► Phase 7 ─► Phase 9
   │           Phase 3 ────────┘                                      │
   └─ P0.1 security hotfix can ship on its own              Phase 8 ◄─┘   Phase 10 (parallel from 5)
```

---

### Phase 0 — Security hotfix + de-hardcoding foundations

**Goal:** stop private keys leaving Guardians, and introduce `MeshProfile` so no later code depends on the name `nodeA`. No user-visible flow changes. Legacy nodeA/B/C keep working.

**Verified against `5a5dd0d` before sizing.** Two §0 unknowns are now closed: the vendored `docker/vendor/nebula-cert` is **1.10.3** and supports both `keygen` and `sign -in-pub`; and `NebulaCA::generate_ca` (`src/nebula/ca.rs:50-55`) passes **no `-curve`**, so every existing CA is **25519**. Member-side `keygen` must therefore also use the default curve — passing `-curve P256` to match the device DID keys makes signing fail.

| ID | Task | Files | Size |
|---|---|---|---|
| P0.1 | **Local Nebula keygen + `-in-pub` signing (hotfix).** Member runs `nebula-cert keygen` (default curve, **not** `-curve P256`) before requesting. Add `string nebula_public_key_pem = 14;` to `CertSignRequest`. When it is present, the CA signs with `-in-pub` and returns an empty `node_key_pem`. Do the same in broker `EnrollmentRequest` (new field `nebula_public_key_pem`) and `process_enrollment`. The `key` field is omitted when a public key was supplied. Old clients still work until P0.2. New `NebulaCA::issue_node_cert_from_pub` must **not** copy the partial-state guard at `ca.rs:219` (`cert.exists() != key.exists() → Err`), which by design never holds once the CA stops writing `.key` | `proto/cert.proto`, `src/nebula/ca.rs` (new `issue_node_cert_from_pub`), `src/cert_service.rs`, `src/cert_client.rs`, `src/cloud/ca_broker.rs`, `sgx-broker/src/models.rs` | M |
| P0.1a | **Rework CA-side idempotency for the keyless CA (regression guard for P0.1).** `src/cert_service.rs:306` gates the "cert already exists" fast-path on `cert_path.exists() && key_path.exists()`. Once the CA stops writing `nodes/<id>.key` that is never true again, so **every** retry falls through to fresh enrollment, rewrites the approval YAML and re-blocks for `APPROVAL_TIMEOUT_SECS` (3600 s). Re-key the fast-path on `cert_path` + `nodes/<id>.pubkey_fp` only, and drop the `remove_file(&key_path)` calls from the two regeneration branches at `:391-408` | `src/cert_service.rs` | S |
| P0.1b | **Member-side stale-identity path must regenerate the key.** `src/cert_client.rs:159-171` deletes `key_path` when the local device pubkey fingerprint no longer matches the cached pair. With local keygen that key is unrecoverable, so the discard path must re-run `keygen` before building the request | `src/cert_client.rs` | S |
| P0.1c | **Fix the misleading broker field comment.** `sgx-broker/src/models.rs:22-23` documents `public_key_pem` as "Nebula public key PEM generated on the requesting node", but `src/cloud/ca_broker.rs:109` base64-decodes it as a **device P-256 DER** key for DID binding. Left as-is, an implementer will conclude the field P0.1 adds is already there | `sgx-broker/src/models.rs` | S |
| P0.2 | **Deprecate CA-generated keys.** Add env `SGX_ALLOW_LEGACY_KEYGEN` (default `false` after one release). When false, reject requests without a public key. On the CA, delete `nodes/<gid>.key` for any member cert already issued, after the member confirms it holds its own copy. Migration script provided. Nothing on the CA reads a *member's* `.key` — verified: the only readers are the member's own paths plus `src/cloud/ca_broker.rs:375`, which is the WAN leg of B1 and is removed by P0.1 | same + `scripts/migrate_member_keys.sh` | S |
| P0.3 | **Verify `pairing_proof` on the CA** (quick win for B6). **No change to `MyCertService`'s signature is needed:** it is a unit struct (`src/cert_service.rs:60`) built with no state at `src/server.rs:189`, and `global_admin_stores()` (`src/api/auth/store.rs:496`) is installed at `src/main.rs:2754`, before the cert bootstrap server spawns at `src/main.rs:2916`. **Use `verify_proof` for the gate, and consume the challenge only after the cert is signed:** `authorize_pairing_proof` sets `bootstrap_consumed` (`src/api/auth/pairing.rs:215-220`), and `cert_client` retries on any transient error with no coalescing, so consuming up-front makes attempt #2 fail with "already used for bootstrap" and the node can never enroll. If valid, show "pairing verified" in the approval YAML/UI | `src/cert_service.rs`, `src/api/auth/pairing.rs` | S |
| P0.4 | **`mesh::profile` module.** `MeshProfile` struct, load/save (atomic, 0600), `current()` cached in `ArcSwap`/`RwLock`, accessors (§4.2). Unit tests with `GuardianPaths::rooted_at` | `src/mesh/mod.rs`, `src/mesh/profile.rs`, `src/lib.rs` | M |
| P0.5 | **Legacy migration.** On boot with no profile: if `nebula/ca/ca.key` exists → `role=Ca, circle_id="guardian-circle-alpha", ca_guardian_id=node_id`. If a member cert exists → `role=Member`, `ca_guardian_id="nodeA"`, overlay/lighthouses from the existing registries. `enrolled_via=LegacyMigration`. **Idempotent and never destructive** | `src/mesh/legacy.rs` | M |
| P0.6 | **Replace role checks.** Mechanically replace `node_id == "nodeA"` / `!= "nodeA"` with `mesh::profile::is_ca()`. Replace `"guardian-circle-alpha"` with `mesh::profile::circle_id()?`. Replace `OverlayRegistry::load_or_create(…,"192.168.100","nodeA")` with profile values. Work module by module (order: `startup/`, `cert_service`, `nebula/*`, `cloud/*`, `crl/*`, `vc/*`, `attestation_service`, `api/handlers/*`, `call/*`, `xfer/*`, `threat/*`). **Tests may keep literals** — see the measured surface below | ~25 production files (see §9) | M |
| P0.7 | **Name-independent ports.** Replace `chat_grpc_port(node_id)`, `attestation_listener_port_for_node`, `p2p_discovery` port `match`, `client.rs:27` and `DEFAULT_NODE_PORTS` with config values (`NodeConfig.ports.{grpc,chat,attest}`) defaulting to 50051/50251/50151. **`NodeConfig` lives at `src/config_loader.rs:90`, not `src/startup/config.rs`** — it is a serde struct fed by `config/node{A,B,C}.yaml`, so those YAMLs, `ha-dev-config/` and `optional/container-cohort/` all need matching keys. `src/startup/config.rs` holds only the helpers, and `default_node_config` (`:38`) *also* derives from the name via `node_id.strip_prefix("node")`. Peers learn each other's ports from the **DID document service endpoints** — verified present at `src/did/document.rs:138-150` (`SGXAttestation`, `SGXCertBootstrap` as `tcp://ip:port`), but `src/main.rs:1509` is the only consumer today, so this needs a resolver helper **plus a config fallback for peers whose DID doc is not yet published**, or removing the `match` at `src/p2p_discovery.rs:230-235` leaves discovery with nothing. `src/client.rs:25-29` is a cosmetic audit label only — lowest priority. The Docker cohort sets explicit per-container ports via env | `src/config_loader.rs`, `src/startup/config.rs`, `src/attestation_service.rs`, `src/p2p_discovery.rs`, `src/client.rs`, `src/startup/bootstrap.rs`, `config/node*.yaml`, `docker-compose.dev.yml`, `optional/container-cohort/` | M |
| P0.8 | **Regression guard.** Add a CI test that fails if `"nodeA"` appears in `src/` outside the allow-list, and likewise for `"guardian-circle-alpha"`. A line-based grep cannot distinguish test code, so implement it as a per-file scan that **cuts each file at its first `#[cfg(test)]`** and checks only what precedes it. The allow-list is `src/mesh/legacy.rs`, `src/testkit/`, `src/bin/test_*` and `tests/` — `src/testkit/test_server.rs` (2 occurrences) and `src/bin/test_guardian_server.rs` (1) are shipped test harnesses under `src/` and are not legacy code. Wire it into `.github/workflows/ci.yml` | `tests/no_hardcoded_roles.rs`, `.github/workflows/ci.yml` | S |
| P0.9 | **Thread the audit actor.** Replace `log_audit("nodeA", …)` / `log_event("nodeA", …)` with `audited_node_id()` (already exists at `src/server.rs:19`) or the profile's `guardian_id`. Much of `cert_service.rs`'s 29 production literals are these calls: today every CA action in the audit log is attributed to the literal string "nodeA" regardless of which Guardian performed it. This is audit-record correctness, not cosmetics | `src/cert_service.rs`, `src/cloud/ca_broker.rs`, `src/api/handlers/*` | S |
| P0.10 | **Route credential authority through `is_ca()`.** `src/cert_service.rs:99-118` uses `node_id == "nodeA"` to choose `CredentialRole::Owner` vs `Member` and calls `load_runtime_key_manager("nodeA")`; `src/cloud/ca_broker.rs:147` does the same. Role-by-name deciding **VC issuance authority** is security-relevant and must not be swept in with the bulk P0.6 rename | `src/cert_service.rs`, `src/cloud/ca_broker.rs`, `src/vc/issue.rs` | S |
| P0.11 | **Parameterise CA identity.** `src/nebula/ca.rs:53` hardcodes the CA subject name `guardian-circle-ca`, and `:250-254` hardcodes `-duration 8600h` and `-groups guardian,member`. Without this every circle's CA shares one subject name, so Phase 2 cannot create distinguishable circles and the §4.5 fingerprint pin is confusing to operators. Thread name/duration/groups as parameters now; Phase 2 supplies per-circle values | `src/nebula/ca.rs`, `src/cert_service.rs` | S |
| P0.12 | **Resolve `nebula-cert` through one helper.** It is invoked by bare PATH name at 6 sites (`ca.rs:50`, `:141`, `:243`, `cert_service.rs:145`, `nebula/health.rs:94`, `startup/nebula_cert.rs:21`); member-side keygen adds a 7th. P0.1 puts `nebula-cert` on the **member's** critical path for the first time, on boards where it may not be installed — today that is an `exit(1)`. One resolver (`$SGX_NEBULA_CERT_BIN`, then PATH, then the vendored path) with a clean typed error, ahead of P1.3 | `src/nebula/bin.rs` (new), the 6 call sites | S |

**Phase 0 exit criteria**
- Existing 3-board LAN cohort and the VPS WAN path both enroll and run calls, chat, xfer and CRL with **no private key on the CA for any member** (`ls nebula/nodes/*.key` on the CA shows only its own).
- A 4th and 5th Guardian (`nodeD`, `edge-7`) on separate hardware enroll through the legacy path and reach all peers. This proves the 3-node limit is gone.
- **A member that already holds a valid cert re-requests and gets the idempotent fast-path back in under 5 s** — not a 3600 s YAML re-block (guards P0.1a).
- **A member whose pairing proof is retried after a transient failure still enrolls** (guards P0.3).
- `cargo test --workspace` green; P0.8 guard green.

---

### Phase 1 — Frontend before certificate (boot → frontend → enrollment)

**Goal:** every Guardian serves the UI within seconds of boot, whatever its enrollment state. Mesh-dependent subsystems start only after enrollment. No `exit(1)` on enrollment problems.

**Verified against the post-Phase-0 tree.** The Stage A/B boundary the plan assumes is real and mechanically movable — confirmed by tracing every section header in `main.rs`. All line-number citations below are corrected for the ~50-line shift Phase 0 introduced (the new mesh-profile-migration block near the top of `main()`).

| ID | Task | Files | Size |
|---|---|---|---|
| P1.1 | **Lifecycle module.** `GuardianLifecycle` enum (§4.3), persisted state, `watch::Sender`, transition validation (illegal transitions are rejected and logged), audit log entry per transition | `src/mesh/lifecycle.rs` | M |
| P1.2 | **Split `main()` into two stages.** **Done, in six verified, boot-tested steps** — the "materially harder than a single contiguous block" finding below was real, and each of the three specific hazards it named was fixed as part of the same pass, not deferred: (1) `cohort.split(&node_id)` — which produces `this_node`/`peers`, needed early — was hoisted from its old position to right after `cohort` loads (`main.rs:741,775`), with a boot-tested fallback (`startup_config::default_node_config(&node_id)` + empty peers) for any Guardian outside the legacy nodeA/B/C names, replacing what used to be a fatal exit there too (found via live testing — see P1.3). (2) `AppState`/REST API bind/TLS identity/wifi daemon moved to run immediately after that (`main.rs:912`), confirmed by log order in a live boot (`REST API starting` now logs before `Verifying Guardian Mesh Installation`). (3) The ~1900-line Nebula/CA/member/CoT/discovery/broadcast/policy-enforcement body was extracted verbatim into `mesh::activation::activate_mesh()` (14 parameters, each discovered by letting the compiler enumerate every `cannot find value` rather than guessed) and is now `tokio::spawn`ed (`main.rs:875`) instead of awaited inline — the change that actually makes a Stage B failure no longer take the already-bound API down with it. `did_doc_publish_state` became `Arc<Mutex<Option<(...)>>>` (spawn-safe) rather than the `&mut` local reference the plan's own P1.4 entry anticipated. All confirmed live: an unmodified 3-node legacy cohort still boots and enrolls identically; a `no-lan`-named, `SGX_DISABLE_NEBULA=1` container serving `GET /api/v1/mesh/lifecycle` over real HTTP while Nebula never runs | `src/main.rs`, `src/mesh/activation.rs`, `src/circle/store.rs` (unrelated fix found along the way — see the `PolicyRuntimeLoad` note below) | L (delivered in 6 staged, individually boot-tested steps rather than one L-sized cut) |
| P1.3 | **Remove fatal exits from the enrollment path.** **Done — zero `std::process::exit(1)` remain in `main.rs`, `mesh/`, or `startup/`** (confirmed by grep; the two remaining matches are comments referencing the old behaviour). Beyond the plan's own three named sites (member branch, Nebula binary checks, the P0-added profile-load exit — all converted to `lifecycle::fail(reason)` + a non-fatal continuation or an `Err` return the caller handles), **live testing surfaced two more the plan didn't anticipate**, both now fixed: the `cohort.split()` "Unknown node ID" exit (P1.2 above — this was the literal bug a real boot test caught: hoisting the split in P1.2 step 1 moved this failure from deep in Stage B, after enrollment had already run, to before the API ever bound), and a policy-runtime-load failure that sat between the moved-early API bind and the code that used to always report it a success regardless. One exit was deliberately *kept* fatal — TLS device-cert generation, which nothing downstream (not even the peer mTLS server) can function without — but even that one now calls `lifecycle::fail()` first, so the reason is persisted and API-readable before the process ends, instead of the previous bare, silent `exit(1)` | `src/main.rs`, `src/mesh/activation.rs`, `src/mesh/lifecycle.rs` (two new legal transitions, `Unenrolled`/`Error` → `CircleMember`, added and tested for the case where `activate_mesh` itself is what proves membership, pre-Phase-2/3) | S |
| P1.4 | **Late-bound dependencies in `AppState`.** `did::Resolver.ca_host` (confirmed: a plain `String` set once in `ResolverConfig`, `did/resolver.rs:63`, never mutated after construction — `set_ca_host()` is genuinely new capability, not a rename) and `did_doc_publish_state` must be updatable after activation. **`did_doc_publish_state` is not a struct field today — it is a stack-local `Option<(String,String,bool,String)>` inside `main()` (`main.rs:821`), populated deep inside the CA/member branches (`:1052`, `:1127`, `:1169`, `:1393`) and consumed both immediately (`:1526`) and by a periodic re-publish tick (`:3203-3212`).** Splitting `main()` means this has to become real owned, shared state Stage B populates and a background task polls, not a local variable — "wrap in `ArcSwap`" understates the redesign. Introduce a `MeshActivationState` (or similar) held in `AppState`, written once by `activate_mesh()`, read by the DID re-publish task and by `Resolver::set_ca_host()` | `src/did/resolver.rs`, `src/api/state.rs`, `src/mesh/activation.rs` | M |
| P1.5 | **API gating middleware.** Route groups are tagged `Provisioning` (always on: auth, node/status, boot-status, wifi, `/api/v1/mesh/*`, logs, PCR, DID self) or `MeshRequired` (peers, chat, call, group_call, xfer, circles (comms), crl, relay, transport, vc, vault-sharing…). While not `ONLINE`, `MeshRequired` returns **409 `{code:"GUARDIAN_NOT_ENROLLED", lifecycle:"UNENROLLED"}`**. **Measured surface: 321 `.route()` calls (188 in `api/mod.rs`, 133 in `api/routes.rs`), none currently tagged or grouped.** The mechanism itself is cheap — `api/mod.rs:1717` already runs `axum::middleware::from_fn_with_state(state, auth::middleware::require_auth)`, so `mesh_gate` follows the identical pattern. Implement as a short explicit allow-list of Provisioning path prefixes checked by one middleware, rather than tagging 321 individual routes — everything not on the allow-list defaults to `MeshRequired`, which is both less error-prone and mechanically smaller than per-route tagging | `src/api/mod.rs`, `src/api/routes.rs`, new `src/api/mesh_gate.rs` | **M for the mechanism, L for full correct classification** |
| P1.6 | **Lifecycle API.** `GET /api/v1/mesh/lifecycle` → `{state, since, detail, profile?: {circle_name, role, ca_fingerprint, overlay_ip}}`. `GET /api/v1/mesh/lifecycle/ws` pushes transitions. `POST /api/v1/mesh/reset` (admin, confirm token) goes back to UNENROLLED from REJECTED/ERROR/PENDING | `src/api/handlers/mesh.rs` | S |
| P1.7 | **Frontend lifecycle gate.** New `MeshLifecycleContext` (poll + WS). `SYS02SplashScreen` (confirmed: currently purely session-based via `AuthContext` + `localStorage["sgx_onboarded"]`, zero mesh-lifecycle awareness) flow: no admin → onboarding account setup. Admin exists and state ≠ ONLINE → `/setup`. ONLINE → home. `ProtectedRoute` (confirmed: currently gates on `session` alone) for mesh screens redirects to `/setup` on 409 | `frontend/src/app/contexts/MeshLifecycleContext.tsx`, `screens/system/SYS02SplashScreen.tsx`, `components/ProtectedRoute.tsx`, `routes.ts` | M |
| P1.8 | **SU01 Setup Choice screen** (spec §32 "Initial state"). Status card showing `UNENROLLED`, the Guardian ID, and DID/hardware badges. Two actions: **Create Mesh Circle** and **Join Existing Circle** | `frontend/src/app/screens/setup/SU01SetupChoice.tsx` (directory does not exist yet — confirmed net-new) | S |
| P1.9 | **Guardian ID choice.** For a fresh unit the CLI arg becomes optional: `sgx-guardian [guardian_id]`. If absent, derive `gx-<first 8 of DID hash>` and let the operator rename it in SU01 before enrollment. **A real latent bug to fix here: all three systemd unit copies — `packaging/sgx-guardian.service`, `packaging/deb/systemd/sgx-guardian.service`, `packaging/rpm/systemd/sgx-guardian.service` — already ship `ExecStart=/usr/bin/sgx-guardian ${SGX_NODE_ID:-nodeA}`, directly contradicting `main.rs`'s own safety check and its comment ("Defaulting to nodeA is unsafe... An unconfigured node silently becoming CA would break trust"). The three copies have also drifted from each other (different capability sets, different comments) — fix the default in all three, not just one** | `src/main.rs`, `packaging/sgx-guardian.service`, `packaging/deb/systemd/sgx-guardian.service`, `packaging/rpm/systemd/sgx-guardian.service` | S |

**Phase 1 exit criteria**
- A fresh Guardian with an empty `/var/lib/sgx-guardian` serves `https://<lan>:8443` in under 30 s, shows SU01, and the daemon stays up indefinitely without a circle. **Met — boot-confirmed**: a `no-lan`-named container with `SGX_DISABLE_NEBULA=1` stayed `Up` and served `GET /api/v1/mesh/lifecycle` (401, not a connection failure — the API was genuinely listening and routing) with no circle ever formed.
- An already-enrolled Guardian boots straight to ONLINE with identical behaviour to Phase 0, verified by the full regression suite. **Met for the manual regression checks performed** (the 3-node legacy cohort reaches `healthy`, enrolls, and shows zero panics/leaked keys across every step of this pass) — "full regression suite" in the sense of an automated suite was not run, per the no-heavy-`cargo test` constraint this session operated under.
- Unplugging the CA during member boot leads to `ERROR` with a readable reason, not a crash loop under systemd. **Met by construction** (every reachable fatal exit converted to `lifecycle::fail()`, confirmed by the zero-`exit(1)` grep) — not separately boot-tested with a physically unplugged CA.

**Implementation status (this pass):**

| Task | Status |
|---|---|
| P1.1 Lifecycle module | ✅ Done — `src/mesh/lifecycle.rs`, full state machine, `watch` broadcast, atomic persistence, boot-state resolution, 19 unit tests (2 more added during P1.2's completion — 21 total) |
| P1.2 Split `main()` | ✅ **Done.** See the row above — completed in 6 staged, individually boot-tested steps after the deferral below turned out to be resolvable once actually attempted with live verification available |
| P1.3 Remove fatal exits | ✅ **Done** — zero `std::process::exit(1)` remain reachable; see the row above for the two extra sites live testing found beyond the plan's original three |
| P1.4 Late-bound `Resolver`/`AppState` | ✅ Done — `Resolver.cfg` is now `Arc<RwLock<ResolverConfig>>` with `set_ca_host()`/`ca_host()`. The `did_resolver.set_ca_host(...)` call site in `activate_mesh()` was itself fixed from a reassignment (`did_resolver = Resolver::new(...)`, which would have silently stopped reaching `AppState`'s clone once construction moved early) to the in-place mutation this was built for |
| P1.5 API gating middleware | ✅ Done and **now live** — the API binds before `activate_mesh` runs (P1.2), so `mesh_gate` is exercised on every request, not dormant. Confirmed over real HTTP: `GET /api/v1/peers` and `GET /api/v1/mesh/lifecycle` both correctly reach the auth layer (401, not a dropped connection or a 409 bypass) |
| P1.6 Lifecycle API | ✅ Done — `GET /api/v1/mesh/lifecycle`, `GET /api/v1/mesh/lifecycle/ws`, `POST /api/v1/mesh/reset`, `src/api/handlers/mesh.rs`. Boot-confirmed reachable over real HTTP on an already-enrolled node |
| P1.7 Frontend lifecycle gate | ✅ Done — `MeshLifecycleContext.tsx` (poll + WS), `SYS02SplashScreen`/`ProtectedRoute` updated, `sgx:mesh-not-enrolled` event wired through `services/api.ts`. `GET /setup` confirmed served (200, HTML) over real HTTP |
| P1.8 SU01 screen | ✅ Done — `screens/setup/SU01SetupChoice.tsx`. Create action now leads into Phase 2's SU02; Join remains a placeholder (Phase 3/4 build that flow) |
| P1.9 Guardian ID + systemd fix | ✅ Done — CLI arg optional via `mesh::fresh_guardian_id()`; all three systemd units' unsafe `${SGX_NODE_ID:-nodeA}` default removed |

Verification: `cargo check --lib --tests` and `--bin` clean throughout (large `cargo test` runs avoided per operator instruction). Live-boot-verified on the 3-node Docker cohort and on standalone containers at each of P1.2's six steps — including the actual bug a real boot test catches that a compiler cannot: the `cohort.split()` "Unknown node ID" exit, found and fixed mid-pass (see P1.2/P1.3 above).

---

### Phase 2 — Create Mesh Circle

**Goal:** the operator explicitly makes this Guardian the CA of a new circle. No Guardian becomes a CA because of its name or because it booted first (Principle 3).

**Verified against the post-Phase-1 tree.** Unusually good shape: P0.4 (`MeshProfile`) and P0.11 (`CaIdentity`) were built with this phase in mind and need no changes — `MeshProfile` already has `role: MeshRole::Ca`, `circle_id`, `circle_name`, `overlay_cidr`, `ca_fingerprint`, `ca_owner_did`, and `EnrollChannel::Created`; `CaIdentity::for_circle(circle_name)` plus `NebulaCA::generate_ca_with`/`issue_node_cert_from_pub_with` (`nebula/ca.rs:50,82,381`) already take exactly the parameters P2.1 needs. The PA-key bootstrap the plan calls "formerly nodeA-only at `main.rs:119`" is already gated on `is_ca()` (`main.rs:176`), not the name — P0.6 already fixed it.

| ID | Task | Files | Size |
|---|---|---|---|
| P2.1 | **CA initialisation service.** `mesh::ca::create_circle(name, options)`: generate `circle_id = "circle-" + 12 random base32` and overlay CIDR (default `192.168.100.0/24`, optionally a user-chosen `/16`–`/24`). Run `nebula-cert ca -name "<circle_name> CA" -duration <policy>` via `CaIdentity::for_circle` (already exists — **note it currently produces `"{circle_name}-ca"`, not `"<circle_name> CA"`; align the format string**). Issue its own cert via local keygen (`mesh::enroll::keys::ensure_local_keypair`, already exists) + `-in-pub`, generate the PA key (already `is_ca()`-gated, not name-gated), create the `Circle{kind: Mesh}` record and **self-issued owner VC**, write the `MeshProfile{role: Ca}`, then go to `CIRCLE_MEMBER` → activate. **Two things the plan doesn't flag, both load-bearing:** (1) `circle::store::create_circle` (`circle/store.rs:49`) **hardcodes `kind: CircleKind::Comms`** — it cannot be reused unchanged; needs a `kind` parameter or a sibling function. (2) the self-issued owner VC is not cosmetic — `circle::store::mesh_circle_id()` (`circle/store.rs:27`) resolves the circle from a **locally persisted membership VC**, independently of `MeshProfile`, and `api/handlers/circle.rs:287-288` already calls `ensure_circle_owner()` against it; skip issuing that VC and existing owner-only circle actions silently fail once `allow_bootstrap` isn't set. No `base32`/`data-encoding` crate is present yet — add one, or hand-roll the ~20-line encoder (`rand`/`hex` alone aren't a drop-in substitute for the human-typed-code-friendly alphabet base32 gives Phase 4's join codes) | `src/mesh/ca/mod.rs`, `src/nebula/ca.rs`, `src/circle/store.rs`, `src/policy_authority.rs` | M |
| P2.2 | **Crash safety.** Creation is a staged transaction under `mesh/staging/create-<ts>/`. Only the final rename commits it. On boot, stale staging directories are cleaned up. This replaces the "partial CA state → manual intervention" error, now at `ca.rs:96` (was `:40` — drifted from P0.11's edits, same bug, same fix) | `src/mesh/ca/mod.rs` | S |
| P2.3 | **Circle enrollment policy (defaults).** `CircleEnrollmentPolicy{approval: Manual|JoinCodeAuto|JoinCodeThenManual, attestation: Required|Preferred|Off, allowed_hw_backends, pcr_baselines: [], max_members, cert_validity_days (default 365), allow_roles}` saved in `mesh/ca/policy.json` and editable later (Phase 10) | `src/mesh/ca/policy.rs` | S |
| P2.4 | **API.** `POST /api/v1/mesh/circles` `{name, overlay_cidr?, policy?}` → 202 + lifecycle transitions. `GET /api/v1/mesh/circle` returns the current circle (both roles). **Confirmed no collision** — only `/api/v1/mesh/lifecycle`, `/lifecycle/ws`, `/reset` exist (P1.6). **A design decision the plan leaves implicit**: `mesh::activation::activate_mesh` is only ever called once, from `main()` at boot, with 14 parameters that live in `main()`'s own stack frame (P1.2) — there is no live path from a running API handler into it. The lowest-risk option, reusing 100% of what Phase 0/1 already built and boot-tested rather than re-deriving those parameters from `AppState`: after `create_circle()` writes the profile and CA material, respond `202`, then exit with a distinctive non-zero code after a short flush delay. `docker-compose.dev.yml` already sets `restart: unless-stopped` (restarts on any exit) and the systemd units already set `Restart=on-failure` (restarts on non-zero exit) — both already do the right thing with no packaging change, and the *next* boot's existing `resolve_boot_state` → `CircleMember` → `activate_mesh` path (already proven in Phase 0/1 testing) takes the CA branch correctly. The cost is a few seconds of restart during an explicit, operator-initiated, one-time action — a materially different thing from the unexpected mid-session crash Phase 1 removed | `src/api/handlers/mesh.rs` | S |
| P2.5 | **Frontend SU02 Create Circle** (spec §32). Name, advanced options (subnet, validity, attestation mode), progress steps (CA key → own cert → policy → mesh online), then a success screen showing the **CA fingerprint** in words + hex, with a **"Invite a Guardian"** CTA leading to P4.8. **Confirmed net-new** — `screens/setup/` currently holds only `SU01SetupChoice.tsx` (P1.8); `services/meshService.ts` does not exist (P1.7's `MeshLifecycleContext.tsx` called lifecycle endpoints inline rather than through a shared service — P2.5 is what makes a dedicated service worth having). SU01's "Create Mesh Circle" button is currently a placeholder `window.alert`; wire it to navigate to `/setup/create` (this screen) | `screens/setup/SU02CreateCircle.tsx`, `services/meshService.ts`, `screens/setup/SU01SetupChoice.tsx` (button wiring), `routes.ts` | M |
| P2.6 | **Keep Comms Circles separate.** The existing `OB08CreateFirstCircle` / `NW02CreateCircle` create **Comms** circles. Relabel the UI to "Comms Circle" vs "Mesh Circle" so operators do not confuse them. Mesh circle creation happens only in `/setup`. **Confirmed both files exist** at `screens/onboarding/OB08CreateFirstCircle.tsx` and `screens/network/NW02CreateCircle.tsx` | `screens/onboarding/OB08…`, `screens/network/NW0*` | S |

**Exit criteria:** on a fresh Guardian, Create Circle leads to ONLINE, `nebula` running with its own overlay IP, `is_ca()==true`, and a distinct random `circle_id`. Two Guardians that each create a circle get two different CAs and circle IDs.

---

### Phase 3 — LAN CA discovery (multiple CAs per LAN)

**Done.** Implemented top to bottom — this was the first phase with nothing
pre-existing to verify/rewire against, so every file below is net-new except
the `mesh::legacy`/`mesh::activation` edits in P3.5. Four decisions were
resolved during implementation, each because the plan's literal text ran
into something the live tree actually does:

1. **Presence vs. proof, made explicit.** Neither mDNS nor `CaBeacon` carry
   any signature — they are pure "look here" pointers. All trust comes from
   `CaDescriptor`, fetched over TCP from wherever the pointer said, then
   verified against the CA's own DID document (bundled in the same
   response, so verification needs no separate resolver hop — LAN discovery
   has to work with no WAN reachable at all). A spoofed beacon can get an
   entry to *appear*; it cannot make that entry verify without the real
   CA's key. This is what the exit criterion actually tests.
2. **Replay protection added to `CaDescriptor` beyond what P3.1 asked for.**
   A signature alone proves the CA once produced those bytes, not that a
   captured, long-stale copy (pre-rotation, pre-revocation) is still
   trustworthy. `verify_with_document` also rejects anything outside a 26h
   freshness window (12h refresh + slack), the same reasoning
   `did::doc_sign::verify_with_replay_protection`'s version-floor check
   already uses elsewhere in this codebase.
3. **`CaBeacon` does not reuse UDP 9000.** `node_listener.rs` already binds
   `0.0.0.0:9000` exclusively for the legacy `NodeAnnouncement` receiver —
   a second exclusive bind there would fail, not share. `CaBeacon` uses its
   own port instead (`SGX_CA_BEACON_PORT`, default **9100**), with its own
   firewall rule.
4. **mDNS *browsing* is out of scope for this pass.** `libmdns` (the only
   mDNS crate already in the workspace) is a responder only, no client-side
   browse API. `advertise.rs` still publishes `_sgx-ca._tcp` with it (real
   interop value, zero new risk); `browse.rs` discovers over the `CaBeacon`
   UDP channel only. Adding a browsing-capable crate (e.g. `mdns-sd`) is a
   real dependency decision, left for whoever picks this back up rather
   than folded in silently.

| ID | Task | Files | Size |
|---|---|---|---|
| P3.1 | **CaDescriptor** build and sign (DID key, `doc_sign`), refreshed every 12 h. `GetCaDescriptor` served on the enrollment port. **Done** — plus the freshness-window replay check (decision 2 above). Verification is self-contained: the HTTP response is `{descriptor, ca_did_document}`, not just the descriptor, so no separate DID resolution is needed | `src/mesh/ca/descriptor.rs` | M |
| P3.2 | **Advertiser** (CA role only, after activation): mDNS `_sgx-ca._tcp` + UDP `CaBeacon`. **Done** — spawned from `mesh::activation::activate_mesh` right after reaching `ONLINE`, gated on `MeshRole::Ca` (a no-op for a `Member`, and for now every enrolled Guardian *is* a CA — Phase 4 is what introduces members). See decisions 3–4 above for the two departures from the literal text | `src/mesh/discovery/advertise.rs` | M |
| P3.3 | **Browser** (joiner): 5 s collection window (`browse::COLLECTION_WINDOW`), fetch-and-verify in parallel (`tokio::spawn` per candidate) with a 3 s per-fetch timeout, dedupe by `(circle_id, ca_fingerprint)`, returns `DiscoveredCa{circle_name, circle_id, ca_guardian_id, fingerprint, fingerprint_words, lan_endpoint, verified, policy_summary}` exactly as specified. `fingerprint_words` ports the frontend's own `fingerprintPhrase()` (`SU02CreateCircle.tsx`) into Rust so a CA's own fingerprint phrase reads identically whether it's showing its own or being discovered. **Done** | `src/mesh/discovery/browse.rs` | M |
| P3.4 | **API.** `POST /api/v1/mesh/discovery/lan` → `202 {scan_id}`, `GET /api/v1/mesh/discovery/lan/{scan_id}` → `{status, results}`, `POST /api/v1/mesh/discovery/probe {host, port}` for the manual-entry fallback. **Done**, admin-gated same as `POST /mesh/circles`. In-memory scan tracking only (`LAN_SCANS`, process-lifetime) — a scan is only ever useful to the operator mid-setup in that session, nothing here needs to survive a restart | `src/api/handlers/mesh.rs`, `src/api/mod.rs` | S |
| P3.5 | **Retire `discover_lan_node_a`.** **Done** — moved (not just gated) to `mesh::legacy`, `pub(crate)`, with a doc comment explaining it now exists only for the hardcoded nodeA/B/C cohort's self-bootstrap; `mesh::activation`'s one call site updated to `mesh::legacy::discover_lan_node_a`. The plan's own file reference (`main.rs:3432`) was already stale — P1.2 had moved this function to `mesh/activation.rs` before this phase started; it's now in `mesh/legacy.rs` instead. `startup/ca_discovery.rs` was untouched — out of this pass's scope, still legacy config-file polling | `src/mesh/legacy.rs`, `src/mesh/activation.rs` | S |
| P3.6 | **Frontend SU03 Join — Local search.** **Done**, with one deliberate cut: the join-code/QR-scan field is not built, because redeeming one has no backend yet (that's P4.6/P4.7) — an input with nowhere to submit would be a dead UI element, not a head start. What *is* real: a live-polling scan (`GET .../lan/{scan_id}` every 700ms), a verified/unverified list (unverified entries rendered greyed-out and `disabled`, matching P3.6's own spec), and the manual `host:port` probe field wired to the real `POST .../probe` endpoint. "Join Selected Circle" is a placeholder alert, the same honest-about-scope pattern SU02's "Invite a Guardian" already uses for P4.8. "Search via WAN" was not built — Phase 3 is LAN-only by its own title | `frontend/src/app/screens/setup/SU03JoinLan.tsx`, `frontend/src/app/services/meshDiscoveryService.ts`, `SU01SetupChoice.tsx` (button wiring), `routes.ts` | M |
| P3.7 | **Firewall.** **Done**, with the port adjusted for decision 3: UDP 5353 was already allowed (confirmed, not just assumed), UDP **9100** (not 9000, see above) for `CaBeacon`, TCP 50071 for `GetCaDescriptor` — opened now as forward-provisioning; P4.2 takes the same port over for the real TLS enrollment server | `src/enforcement/executor.rs` | S |

**Exit criteria:** a LAN with 3 CAs (3 circles) shows 3 verified entries — structurally true by construction (`browse::scan()` dedupes by `(circle_id, ca_fingerprint)`, so 3 distinct circles necessarily produce 3 distinct entries), not yet re-confirmed live with 3 simultaneous CA containers the way Phase 1/2's staged live-boot testing confirmed each of *their* exit criteria — that's the natural next verification step. A spoofed advertiser without a valid signature shows as unverified and cannot be selected: enforced in code (`verify_with_document` fails closed on a bad/missing signature or a mismatched DID; `SU03JoinLan.tsx` disables selection whenever `!entry.verified`), covered by `descriptor.rs`'s unit tests for the signature-verification path, not yet by a live forged-beacon test.

**Verification:** `cargo check --lib` clean throughout. Frontend: `npx tsc --noEmit` shows the same 91 pre-existing errors the tree already had before this phase, none in any file this phase touched. Live boot testing (a real multi-CA LAN scan, and a forged-signature negative test) has not been run yet, per the no-heavy-`cargo test`/staged-testing pattern the operator runs this session under — next step once this is boot-tested.

---

### Phase 4 — Enrollment protocol v2 on the LAN (local enrollment)

**Done.** The biggest phase so far — a whole join protocol, not a single
feature — implemented end to end: CA-side request store and verification
pipeline, issuer, joiner client, approval API, join codes, and four new
frontend screens. Five corrections to this section's own text, found before
implementation (the first four were live text/design gaps; the fifth,
transport, was the one substantive engineering call made along the way):

1. **P4.2's port note.** Fixed below — it now says plainly that this
   replaces Phase 3's interim HTTP `GetCaDescriptor` listener on the same
   port, not a second server contending for it.
2. **P4.3 vs. the existing v1 approval API — resolved by not touching v1
   at all.** `GET/POST /api/v1/cert/*` (YAML-backed) is untouched and still
   serves the legacy nodeA/B/C cohort exactly as before. Phase 2+ circles
   get their own, separate routes (`/api/v1/mesh/enroll-requests/*`,
   `/api/v1/mesh/join`, `/api/v1/mesh/join-codes/*`) backed by the new
   store. Zero shared code path, zero regression risk to the working v1
   flow.
3. **P4.4's join-code check, reordered.** Built P4.8 (join codes) before
   wiring check (4), exactly as flagged — `requests::submit` takes an
   already-validated `join_code_check: Option<Result<(), String>>` rather
   than reaching into `mesh::joincode` itself, so the dependency runs one
   way only.
4. **`transport_wan` — confirmed genuinely out of scope**, not silently
   dropped. `mesh::enroll::mod.rs`'s own doc comment now says so directly:
   it belongs to whichever later phase does WAN joining (not named in this
   plan today), not Phase 4.
5. **Transport: HTTP/JSON, not gRPC+TLS+SPKI-pinning — a real, deliberate
   departure, documented in code (`mesh::ca::server`'s own module doc) and
   here.** Every message is signed and verified at the application layer
   instead — `CaDescriptor`, `EnrollmentSubmission` and `EnrollmentBundle`
   all sign `canonical_bytes_for_sign` and verify against a DID the other
   side already has reason to trust (the CA's, proven by the P3-verified
   descriptor; the joiner's, proven by its own DID document travelling
   with its submission). This is *why* the plan's own exit criteria
   ("tampering any bundle field makes B reject it") hold structurally. A
   custom `rustls` SPKI-pinning verifier — the plan's literal transport —
   would be real defence-in-depth on top of that, but this codebase has
   zero precedent for one, and hand-rolling security-critical, unreviewed
   crypto-adjacent code under this pass's time budget was judged a worse
   risk than shipping a working, board-portable flow without it. Flagged
   as a good hardening follow-up, not silently cut — see P4.2's row.

| ID | Task | Files | Size |
|---|---|---|---|
| P4.1 | ~~`enroll.proto` + codegen~~ — **not built.** Superseded by decision 5: no gRPC, no protobuf, so nothing to generate. `EnrollmentSubmission`/`EnrollmentBundle`/`CaDescriptor` are plain serde JSON structs instead | — | — |
| P4.2 | **LAN enrollment server (CA).** **Done**, as plain HTTP/JSON (decision 5) on port 50071 — this *is* Phase 3's `GetCaDescriptor` listener, extended: `mesh::ca::descriptor.rs` now holds only the `CaDescriptor` type and its sign/verify logic, `mesh::ca::server.rs` owns the actual listener (`GET /ca-descriptor`, `POST /enroll`, `GET /enroll/{request_id}`) plus the CA-side auto-approve path. The legacy plaintext `start_cert_bootstrap_server` (50061) is now gated behind `SGX_LEGACY_ENROLL`, **defaulting to *enabled*** — the existing nodeA/B/C cohort's own `cert_client.rs` still dials that exact port today, so flipping the default off would have broken it; only an explicit `SGX_LEGACY_ENROLL=0/false/off` disables it, for an operator who has fully moved off the legacy cohort | `src/mesh/ca/server.rs`, `src/mesh/ca/descriptor.rs`, `src/mesh/activation.rs` | M |
| P4.3 | **Request store.** **Done** exactly as specified — `mesh/ca/requests/<request_id>.json`, states Pending/Approved/Rejected/Expired, 7-day TTL, per-guardian_id dedupe (an active Pending/Approved request blocks a second one under the same name), per-source-IP rate limit (10/hour, in-memory). `SubmitEnrollment` (`POST /enroll`) returns the ticket immediately; the bundle itself is only ever handed out via the separate poll route | `src/mesh/ca/requests.rs` | M |
| P4.4 | **Verification pipeline.** **Done**, checks (1)(2)(3)(5)(6) exactly as specified plus two the plan's 7-item list didn't itemise but `CircleEnrollmentPolicy` already has fields for (`allowed_hw_backends`, `max_members`) — both folded in since the policy struct existed for exactly this. (2)+(3) are one combined check in practice: `EnrollmentSubmission` signs itself and is verified against its own embedded DID document, which is simultaneously "fresh, single-use nonce" and "signed by the key the DID document claims." (4) join-code HMAC — see decision 3. (7) attestation — a `PolicyReport` row that always passes today, exactly as the plan says Phase 5 is what enforces it | `src/mesh/ca/requests.rs` | M |
| P4.5 | **Issuer.** **Done.** Every primitive it names already existed from Phase 2/3 and needed no changes: `OverlayRegistry`, `NebulaCA::issue_node_cert_from_pub_with` (the same function P2's self-signing false-positive was fixed in), `vc::issue::issue_membership_vc`. Not staged/transactional the way `create_circle` is — reasoned through in the module doc: signing one more member cert into an already-live `nodes/` directory has no partial-tree hazard the way standing up a whole new CA does | `src/mesh/ca/issuer.rs`, `src/mesh/ca/bundle.rs` | M |
| P4.6 | **Joiner client.** **Done** — `enroll/request.rs` (build + sign, keygen once via the existing `enroll/keys.rs`, reused on every retry), `enroll/transport_lan.rs` (submit + poll with capped exponential backoff, 2s→30s), `enroll/install.rs` (verifies the whole bundle, writes cert/CA/VC, installs `MeshProfile{role: Member}`). "Survives restarts via the persisted request_id" is real: `(lan_endpoint, request_id)` is persisted right after submit, and a dedicated boot-time hook (`mesh::enroll::resume_pending_join_if_any`, called from `main.rs` next to the existing staging-cleanup sweep) resumes polling the same request on the next boot instead of ever re-submitting | `src/mesh/enroll/*` | L |
| P4.7 | **Approval API + UI, for Phase 2+ circles.** **Done** as new, separate routes rather than a v1 upgrade — see decision 2. `GET/POST /api/v1/mesh/enroll-requests*` return/act on `PolicyReport`s with ✔/✖ per check, same shape the plan describes for v1. UI: an additive panel appended to `ST16PendingApprovals.tsx` (its own fetch/poll, zero changes to the existing YAML-backed list or `CertificateRequestContext`) — the incoming-request popup dialog (`IncomingCertificateRequestDialog`) was **not** extended to cover v2 requests in this pass, a real, flagged cut: the dedicated settings page is the functional approval surface today, the popup notification is not | `src/api/handlers/mesh.rs`, `frontend/.../ST16PendingApprovals.tsx`, `frontend/.../enrollService.ts` | M |
| P4.8 | **Join codes.** **Done**, with one hardening beyond the spec: only an HMAC of each code is ever persisted (`mesh::joincode`'s own per-Guardian secret, generated on first use), not the plaintext — a leaked join-codes directory reveals nothing usable. `qrcode.react` was **not** added (no QR rendering in `SU09InviteGuardian.tsx` this pass) — the code displays as large monospace text only; a real, flagged cut, not an oversight | `src/mesh/joincode.rs`, `src/api/handlers/mesh.rs`, `frontend/.../SU09InviteGuardian.tsx` | M |
| P4.9 | **Joiner UI.** **Done** — SU05 (confirm, reached from SU03's now-wired "Join Selected Circle" button), SU06 (live stepper, watching `useMeshLifecycle()` exactly as `SU02CreateCircle` already watches its own restart — a new `(Unenrolled, Enrolling)` lifecycle transition had to be added, since Phase 3's LAN scan runs as its own independent job rather than through the lifecycle machine), SU07 (reject/error, wired to the existing P1.6 `/mesh/reset`), SU08 (member card, reads `lifecycle.profile` — already populated, no extra fetch) | `frontend/.../SU05…SU09*.tsx` | M |

**Exit criteria:** fresh Guardian B joins circle A on the LAN (1) with a join code and auto-approve in under 60s, and (2) without a code, through manual approval in the CA UI — both paths implemented and structurally sound (auto-approve issues the bundle synchronously inside `POST /enroll` itself, so the very first poll after submission already has it), not yet live-boot-verified with two real Guardian containers the way Phase 1/2/3's criteria were confirmed. B restarts while PENDING and resumes: implemented via `resume_pending_join_if_any`, not yet live-restart-tested. The CA never holds B's private key: structurally true — `EnrollmentSubmission` only ever carries `nebula_public_key_pem`, never a key. Tampering any bundle field makes B reject it: structurally true (`EnrollmentBundle::canonical_bytes_for_sign` covers the whole struct, unit-tested), not yet tested against a live tampered-in-transit bundle.

**Verification:** `cargo check --lib` and `--bin` clean throughout, zero warnings. Frontend `npx tsc --noEmit`: the same 91 pre-existing errors the tree already had, zero new ones across all of `enrollService.ts`, `SU05`–`SU09`, `SU02`/`SU03`'s wiring, `ST16PendingApprovals.tsx`, and `routes.ts`. One new dependency added: `hmac = "0.12"` (RustCrypto family, same lineage as `sha2`/`p256`/`ecdsa` already in the dependency tree) for P4.8's code hashing — resolved cleanly, no version conflicts. Live boot testing (two real Guardians, one CA one joiner, both join paths, a restart mid-PENDING, a deliberately tampered bundle) has not been run yet — the natural next step, same pattern as every prior phase.

---

### Phase 5 — Attestation-gated enrollment

| ID | Task | Files | Size |
|---|---|---|---|
| P5.1 | **Evidence producer (joiner).** Build `AttestationEvidence` over the CA nonce, reusing the producer in `attestation_service.rs`, PCR composite from `secure_element/pcr.rs` / TPM, boot chain status and DKP version. Sign with the device key. Include the `hw_backend` claim (SE050/TPM/software) | `src/mesh/enroll/request.rs`, `src/attestation_service.rs` (extract a pure `build_evidence(nonce)` fn) | M |
| P5.2 | **Evidence verifier (CA).** Signature valid, nonce matches, PCR composite in `policy.pcr_baselines` (or `Preferred` gives a warning only), hw backend allowed, boot chain OK. Output goes into `PolicyReport` | `src/mesh/ca/policy.rs`, `src/attestation_service.rs` (extract a pure `verify_evidence`) | M |
| P5.3 | **Baseline management.** CA UI and API to add a PCR baseline from an already-approved Guardian ("trust this firmware") and list/remove baselines | `src/api/handlers/mesh.rs`, `screens/security/*` | S |
| P5.4 | **Binding.** The binding signature (P4.4) and evidence share the nonce, so the Nebula key in the cert is proven to belong to the attested device (spec §25) | — (test only) | S |

**Exit criteria:** with `attestation: Required`, a software-key Guardian or one with an unknown PCR is rejected with a clear report. Replaying an old request fails the nonce check.

---

### Phase 6 — WAN rendezvous (sgx-broker v2)

**Goal:** a Guardian with no suitable LAN CA can find and enroll with a remote circle through the public server. The server learns only public data and cannot forge or alter results.

| ID | Task | Files | Size |
|---|---|---|---|
| P6.1 | **CA registration v2.** The CA's WSS (`/ws/v2/ca-bridge`) authenticates with a **signed CaDescriptor plus a DID-key challenge**, replacing the shared `broker_token` alone. The broker stores `circle_id → {descriptor, listed: bool, ws}`. Multiple circles per broker are already supported by `state.rs` | `sgx-broker/src/v2/*`, `src/cloud/ca_broker.rs` | M |
| P6.2 | **Directory API.** `GET /api/v2/circles/lookup?code=<join-code-id>` resolves to a descriptor (the default path, private). `GET /api/v2/circles` lists only circles with `listed=true` (opt-in, for the spec §18 "Remote Circles Available" list). Rate-limited | `sgx-broker/src/v2/directory.rs` | S |
| P6.3 | **Enrollment relay v2.** `POST /api/v2/enroll/begin` → nonce (from CA via WS). `POST /api/v2/enroll/submit` → ticket. `GET /api/v2/enroll/{ticket}` → status or bundle. The broker persists tickets (sqlite/json) so a CA offline for hours still gets the request when it reconnects. **The broker never sees a private key.** Bundles are CA-signed, so the broker cannot tamper with them | `sgx-broker/src/v2/enroll.rs`, `sgx-broker/src/state.rs` | L |
| P6.4 | **Optional confidentiality.** Encrypt `EnrollRequestV2` to the CA's descriptor key (ECIES P-256) so the broker cannot read DID/metadata. Default on | `src/mesh/enroll/transport_wan.rs`, `src/cloud/ca_broker.rs` | M |
| P6.5 | **TLS for the broker.** Terminate HTTPS (Caddy is already used in `docker/Caddyfile.dev`). The joiner validates via WebPKI (the URL is typed by the user) and still pins the CA via the join code | `sgx-broker/deploy/*` | S |
| P6.6 | **Joiner WAN transport.** Same `EnrollmentService` semantics as LAN, carried over HTTPS through the broker. `mesh/enroll/*` is transport-agnostic behind a `trait EnrollTransport` | `src/mesh/enroll/transport_wan.rs` | M |
| P6.7 | **Frontend SU04 Remote Circle** (spec §32 "WAN fallback" + "Remote Circle discovery"). Rendezvous URL (prefilled from join code `rv` if present), Connect, then join-code lookup result or the listed circles, then SU05 confirm → SU06 progress | `screens/setup/SU04JoinWan.tsx` | M |
| P6.8 | **Retire v1** `/api/v1/enroll` after one release (it returns private keys, see B1) | `sgx-broker/src/handlers.rs` | S |

---

### Phase 7 — Remote enrollment end-to-end + overlay bring-up (Pakistan ↔ USA)

| ID | Task | Files | Size |
|---|---|---|---|
| P7.1 | **Per-circle VPS lighthouse provisioning.** When a CA registers with a broker, the broker's `lighthouse_manager` creates `/etc/nebula/circles/<circle_id>/`, runs `nebula-cert keygen` locally, and sends the `.pub` to the CA. The CA signs `vps-lighthouse` with `-in-pub`, groups `lighthouse,relay`. The broker starts a dedicated nebula instance on a **per-circle UDP port** (4242, 4243, …). This replaces the manual `scp ca.key`-era steps in `deploy/README.md` | `sgx-broker/src/lighthouse_manager.rs`, `src/cloud/ca_broker.rs` | L |
| P7.2 | **Lighthouse hints in the bundle.** `lighthouses_json` = the CA's own LAN or public endpoint(s) + VPS per-circle endpoint + relays. `nebula/config.rs` generates `static_host_map` / `lighthouse.hosts` / `relay.relays` **from the profile**, not from the `192.168.100.1` literal (`nebula/config.rs:36`) | `src/nebula/config.rs`, `src/mesh/activation.rs` | M |
| P7.3 | **Activation for WAN members.** Remove the `159.203.186.55` / `192.168.100.10` defaults (`main.rs:1075,1079,1333`). Everything comes from the bundle or profile. Keep the DID-publish fast-retry loop (`main.rs:1374-1416`) | `src/mesh/activation.rs` | M |
| P7.4 | **Post-enroll connectivity check.** After activation, probe the CA overlay IP and one lighthouse, then report `network: CONNECTED | RELAYED | UNREACHABLE` in lifecycle detail and SU08 | `src/mesh/activation.rs`, `src/nebula/health.rs` | S |
| P7.5 | **E2E WAN test harness.** Two Docker networks with separate NAT (`optional/container-cohort` style) + a broker container. Scenario from spec §41: USA creates circle, invites; Pakistan joins over WAN; the call and file transfer succeed **without traffic through the CA**, verified by checking the Nebula tunnel peer is the target and not the CA | `tests/e2e_wan_enroll/`, `optional/container-cohort/*` | L |

**Exit criteria:** the spec §47 25-step scenario passes on real boards across two ISPs. Killing the CA after enrollment does not affect existing member↔member calls (spec §37).

---

### Phase 8 — Certificate lifecycle

| ID | Task | Files | Size |
|---|---|---|---|
| P8.1 | **Renewal.** `ExpiryMonitor` (`nebula/cert_lifecycle.rs`) triggers a renewal at 80% of validity via `EnrollmentService.Renew` (same key, mTLS over the **overlay**, no approval if VC active and not revoked). If the CA is unreachable, the Guardian keeps running and warns in the UI | `src/mesh/enroll/renew.rs`, `src/mesh/ca/issuer.rs` | M |
| P8.2 | **Key rotation.** Admin-triggered: new local keygen → Renew with `rotate=true` → atomic swap + Nebula reload | same | S |
| P8.3 | **Revocation → Nebula.** When the CRL marks a Guardian DID revoked, the CA adds its cert fingerprint to a signed blocklist. It is distributed through the existing CRL gossip. Each Guardian writes `pki.blocklist` into its Nebula config and reloads, so revoked peers are cut off at the tunnel layer | `src/crl/*`, `src/nebula/config.rs` | M |
| P8.4 | **Remove Guardian** UI on the CA (circle members list → Remove) does revoke VC + CRL + blocklist + free the overlay IP | `src/api/handlers/mesh.rs`, frontend circle detail | S |
| P8.5 | **CA backup & restore.** Encrypted export of `ca.key`, policy, request store and registries through the existing `src/backup/*` components. The UI warns that without a backup a lost CA means re-creating the circle | `src/backup/components.rs` | M |
| P8.6 | **Leave circle** (member): revoke self (best-effort), wipe mesh material, go back to UNENROLLED | `src/mesh/lifecycle.rs`, `api/handlers/mesh.rs` | S |

---

### Phase 9 — Multi-circle environment + CA redundancy

| ID | Task | Files | Size |
|---|---|---|---|
| P9.1 | **Isolation test matrix.** Circles A and B on the same LAN and the same broker: A members cannot handshake with B (different CA pin), per-circle lighthouse instances do not leak host maps, and overlay CIDRs may overlap safely | tests | M |
| P9.2 | **Secondary CA for a circle** (spec: "a Circle can have one or more CAs"). The primary CA signs a **delegation VC** for a second Guardian. The circle's trust bundle (`ca_cert_pem` becomes a list of CA certs, which Nebula supports natively) is distributed to all members. Either CA can issue. The request store and CRL are replicated via gossip. Promote-to-primary is available if the original is lost | `src/mesh/ca/*`, `src/crl/gossip/*` | L |
| P9.3 | **Decision (v1): one Mesh Circle per Guardian.** Joining a second mesh circle needs a second Nebula instance/tun, port allocation and policy separation. It is out of scope unless product requires it. Comms Circles remain many-per-Guardian as today | — | — |

---

### Phase 10 — Authorization / policy (can run in parallel from Phase 5)

| ID | Task | Files | Size |
|---|---|---|---|
| P10.1 | **Certificate groups → roles.** Cert groups become `guardian,member[,lighthouse][,relay][,ca]`. The Nebula firewall section in `nebula/config.rs` becomes group-based (for example, only `ca` group may receive on the renewal port) | `src/nebula/config.rs`, `src/mesh/ca/issuer.rs` | M |
| P10.2 | **VC permissions enforcement.** API handlers for calls, xfer, chat and vault check the caller's VC permissions for the circle (existing `ALLOWED_PERMISSIONS` in `vc/issue.rs`). There is one `authorize(peer_did, circle_id, permission)` helper | `src/api/auth/authorization.rs` | M |
| P10.3 | **Circle policy editor UI** for the enrollment policy (P2.3) + permissions per role | frontend `screens/policy/*` | M |

---

### Phase 11 — Migration, hardening, release

| ID | Task | Size |
|---|---|---|
| P11.1 | Upgrade guide: legacy nodeA/B/C → profile migration (automatic), member private-key cleanup on the CA, broker v1 → v2 cut-over | S |
| P11.2 | Update `docs/SGX Admin Guide`, `README.md`, `sgx-broker/deploy/README.md`, `docs/API_Specification_v1.0.md` | M |
| P11.3 | Threat-model delta (`docs/Threat_Model.pdf`): rogue LAN CA, malicious broker, replayed enrollment, stolen join code, compromised CA | S |
| P11.4 | Verification log `docs/Guardian_Mesh_Enrollment_Verification_Log.md`, matching the existing `*_Verification_Log.md` convention | S |
| P11.5 | Packaging: new ports, systemd unit (optional guardian_id), `.deb/.rpm` post-install doesn't pre-seed nodeA/B/C configs (`startup/bootstrap.rs:34`) for fresh installs | S |

---

## 7. API summary (new and changed)

All endpoints live under the existing `/api/v1` style. Admin session is required unless noted.

| Method | Path | Phase | Notes |
|---|---|---|---|
| GET | `/api/v1/mesh/lifecycle` | 1 | Any authenticated session |
| GET | `/api/v1/mesh/lifecycle/ws` | 1 | Push transitions |
| POST | `/api/v1/mesh/reset` | 1 | From REJECTED/ERROR/PENDING only |
| POST | `/api/v1/mesh/circles` | 2 | Create Mesh Circle (UNENROLLED only) |
| GET | `/api/v1/mesh/circle` | 2 | Current circle + role + CA fingerprint |
| POST | `/api/v1/mesh/discovery/lan` | 3 | Start scan → `scan_id` |
| GET | `/api/v1/mesh/discovery/lan/{scan_id}` | 3 | Verified CA list |
| POST | `/api/v1/mesh/discovery/probe` | 3 | Manual `host:port` |
| POST | `/api/v1/mesh/discovery/wan` | 6 | `{rendezvous_url, join_code?}` → descriptors |
| POST | `/api/v1/mesh/join-codes/decode` | 4 | Parse/validate code or QR (no network) |
| POST | `/api/v1/mesh/enrollment` | 4/6 | `{channel: lan|wan, ca_ref, join_code?, tofu_confirmed_fp?, requested_roles}` |
| GET | `/api/v1/mesh/enrollment` | 4 | Status + policy report |
| DELETE | `/api/v1/mesh/enrollment` | 4 | Cancel pending |
| POST/GET/DELETE | `/api/v1/mesh/join-codes[/{id}]` | 4 | CA only |
| GET | `/api/v1/cert/requests` (+ `/ws`) | 4 | **Extended** with v2 fields |
| POST | `/api/v1/cert/approve` | 4 | **Changed** body: `{request_id, decision, reason}` |
| GET/PUT | `/api/v1/mesh/policy` | 2/10 | CA only |
| POST/GET/DELETE | `/api/v1/mesh/pcr-baselines` | 5 | CA only |
| DELETE | `/api/v1/mesh/members/{guardian_id}` | 8 | Remove + revoke |
| POST | `/api/v1/mesh/leave` | 8 | Member only |
| POST | `/api/v1/mesh/renew` | 8 | Manual renew / rotate |

## 8. Frontend screen map

| Screen | Spec § | Phase | Replaces / relates to |
|---|---|---|---|
| `SU01SetupChoice` | 32 Initial | 1 | New. Shown when lifecycle ≠ ONLINE |
| `SU02CreateCircle` | 32 Create | 2 | Separate from `OB08CreateFirstCircle` (Comms) |
| `SU03JoinLan` | 32 Join | 3 | New. Join code / QR entry |
| `SU04JoinWan` | 32 WAN + Remote | 6 | New |
| `SU05ConfirmCa` | 10, 24 | 4 | New. Fingerprint confirmation |
| `SU06EnrollmentProgress` | 26 | 4 | New. Live lifecycle stepper |
| `SU07EnrollmentFailed` | 5 REJECTED/ERROR | 4 | New. Reason + retry/reset |
| `SU08EnrollmentComplete` | 26 | 4 | New. Circle/CA/cert/attestation/network card |
| `SU09InviteGuardian` | — | 4 | New (CA). QR + code |
| `ST16PendingApprovals`, `IncomingCertificateRequestDialog` | 21 | 4 | **Extended** with policy report |
| Circle detail (mesh) → Members / Remove / Policy | 36, 10 | 8/10 | Extend `NW04CircleDetail` for kind=mesh |
| `HM01Dashboard` / `ST02GuardianInfo` | 26 | 7 | Add mesh card (circle, role, CA, cert expiry, network) |

## 9. Tracking the de-hardcoding (Phase 0.6)

Baseline counts at `5a5dd0d`. A raw `grep` over `src/` counts test fixtures, which §P0.6 explicitly exempts, so it overstates the work by roughly 3×. The **production** column cuts each file at its first `#[cfg(test)]` and counts only what precedes it, excluding `src/**/tests/` and `*tests.rs`:

| Literal | Raw `grep` total | **Production** | Production files |
|---|---|---|---|
| `"nodeA"` | 726 | **132** | **22** |
| `guardian-circle-alpha` / `DEFAULT_CIRCLE_ID` | 207 | **26** | **8** |
| `"192.168.100` | 464 | **52** | **18** |

Of the `"nodeA"` production occurrences, only **34 across 11 files** are actual role checks (`== "nodeA"` / `!= "nodeA"`) — the rest are default arguments, audit actors (P0.9) and registry owner strings. Total production surface is about **210 occurrences in ~25 files**, which is why P0.6 is sized **M**, not L.

Reproduce the production counts with:

```bash
python3 - <<'PY'
import os
for pat in ['"nodeA"','guardian-circle-alpha','"192.168.100']:
    prod=0; files={}
    for root,_,fs in os.walk('src'):
        for f in fs:
            if not f.endswith('.rs'): continue
            p=os.path.join(root,f)
            if '/tests/' in p or f.endswith('tests.rs'): continue
            lines=open(p,encoding='utf-8',errors='replace').read().split('\n')
            cut=next((i for i,l in enumerate(lines) if '#[cfg(test)]' in l), len(lines))
            c=sum(l.count(pat) for l in lines[:cut])
            if c: files[p]=c; prod+=c
    print(f'{pat}: prod={prod} files={len(files)}')
    for k,v in sorted(files.items(), key=lambda x:-x[1]): print(f'   {v:4d}  {k}')
PY
```

Heaviest **production** files to convert first: `cert_service.rs` (29), `main.rs` (29), `attestation_service.rs` (27), `cloud/ca_broker.rs` (8), `p2p_discovery.rs` (6), `vc/issue.rs` (4), `startup/config.rs` (4). Note that `nebula/lighthouse.rs` and `call/group.rs` — which a raw grep ranks 2nd and 6th at 42 and 29 — have **zero** production occurrences; they are entirely test fixtures. Track progress by the P0.8 guard's allow-list shrinking to `mesh/legacy.rs`, `src/testkit/` and `src/bin/test_*`.

## 10. Test strategy

| Layer | What | Where |
|---|---|---|
| Unit | Profile load/save/migrate, lifecycle transitions (illegal ones rejected), join code encode/decode/expiry, descriptor sign/verify, binding signature, bundle validation (each of the 7 checks has a negative test), policy evaluation | `src/mesh/**` `#[cfg(test)]` with `GuardianPaths::rooted_at` |
| Integration | CA + joiner in one process over localhost TLS; broker v2 in-process (`sgx-broker/tests`), including CA offline → reconnect → ticket delivered | `tests/mesh_enroll_*.rs`, `sgx-broker/tests/` |
| Security | Rogue CA advertiser; MITM with a different TLS cert; broker modifying a bundle; replayed nonce; reused join code; request for a taken guardian_id with a different key; `-in-pub` path never writes `.key` on the CA | `tests/mesh_security_*.rs` |
| Frontend | Vitest for `meshService` + context; Playwright flows: create circle, LAN join with code, manual approval, WAN join, reject → reset | `frontend/src/**/*.test.ts`, `frontend/e2e/setup-*.spec.ts` |
| E2E | Docker cohort LAN (≥5 Guardians, 2 circles) + two-NAT WAN scenario (P7.5) + real boards | `optional/container-cohort`, board matrix |
| Regression | Existing calls, group calls, chat, xfer, CRL gossip/offline, vault, DID publish on migrated legacy cohort | existing suites |

## 11. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| `main.rs` split (P1.2) changes init ordering, reintroducing SE050 contention / DKP issues noted in comments | Boot failures on hardware | Move code in the same order; do not re-init `DkpManager`; board soak test before merge |
| The `nodeA` replacements introduce subtle behaviour changes (e.g. "nodeA is always relay" at `main.rs:1961`) | Relay/lighthouse regressions | The measured production surface is 132 occurrences in 22 files, not ~700 (§9). Convert module by module with the legacy cohort as a regression gate; `is_ca()` preserves the old semantics exactly |
| P0.1 removes the CA's member `.key` files, which two idempotency fast-paths currently test for | Every cert re-request re-blocks for 3600 s | P0.1a re-keys those paths on the cert + `pubkey_fp` before P0.1 lands, with an exit-criteria test asserting a sub-5 s re-request |
| P0.3 consumes the pairing challenge before the cert is signed, while `cert_client` retries freely | A transient error permanently bricks enrollment for that node | P0.3 verifies without consuming and consumes only after signing; exit criteria cover the retry |
| Legacy members cannot re-verify their CA pin (no descriptor existed) | Migration trust gap | Migrated profiles pin the **currently installed** `ca.crt` fingerprint (the existing trust anchor in `save_ca_cert` already refuses changes) |
| Frontend reachable pre-enrollment widens attack surface | Unauthorised provisioning | Confirm first-admin protection (§0.2); provisioning routes require admin session; rate limits; audit every transition |
| Broker availability | WAN joins blocked | Tickets persisted; CA reconnect delivers; LAN path independent; members unaffected after enrollment |
| CA loss | Circle can't enroll/renew | P8.5 backup, P9.2 secondary CA; members keep working until cert expiry (365 d default) |
| Overlay /24 limits circle to 253 Guardians | Scale ceiling | CIDR chosen at circle creation (P2.1), `/16` allowed |

## 12. Open decisions for product/security (please answer before Phase 3)

1. **Join code mandatory?** The recommendation is **mandatory for WAN**, and on the LAN either a code or TOFU followed by manual approval.
2. **Public circle listing on the broker?** The recommendation is **unlisted by default** with lookup by join code. Listing is opt-in per circle.
3. **Attestation default for new circles:** `Required` (hardware-only fleets) or `Preferred` (mixed/software dev units)? The recommendation is `Preferred` in dev builds and `Required` in release builds.
4. **One Mesh Circle per Guardian (v1)?** The recommendation is yes (§P9.3).
5. **Who runs the Rendezvous?** One vendor-operated broker for all customers, or self-hosted per customer? This affects tenancy and auth in Phase 6.
6. **Legacy key cleanup (P0.2):** is automatic deletion of member keys on the CA acceptable, or should it be operator-confirmed?

## 13. Suggested milestones

| Milestone | Phases | Demo |
|---|---|---|
| **M1 — Safe & scalable legacy** | 0 | 5+ Guardians on the existing flow, no private keys on the CA |
| **M2 — Setup UI** | 1, 2 | Fresh box → browser → Create Mesh Circle → online |
| **M3 — LAN Join** | 3, 4 | Two circles on one LAN; new Guardian picks one, joins with QR code or manual approval |
| **M4 — Trusted Join** | 5 | Enrollment rejected for an unknown firmware PCR; accepted after baseline added |
| **M5 — WAN Join** | 6, 7 | Pakistan Guardian joins USA circle via rendezvous; direct Nebula call, CA not in path |
| **M6 — Lifecycle & multi-CA** | 8, 9, 10, 11 | Renewal, remove Guardian (blocked at tunnel), CA backup/restore, secondary CA |
