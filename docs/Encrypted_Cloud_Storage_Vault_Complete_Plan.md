# Encrypted Cloud Storage Vault — Complete Development Plan
### Feature #6 · The "All Files" browse experience on top of the encrypted store
### Base branch: `feat/62-CRL` · Module: `src/vault/` (extends) · **No new port**

---

## 0. Grounding note + boundary

Written against the **actual indexed repo state**, not memory.

**This feature is a layer, not a rebuild.** It builds directly on the **encrypted attachment store** defined in the File-Transfer vault-integration plan (`src/vault/{model,persistence,crypto,wrapper,ingest}.rs`). That plan gives us blob storage, per-file DEK + `KeyWrapper` (SE050 / software), streaming AES-256-GCM, per-circle namespacing, ingest, and minimal read. **This plan does NOT re-implement any of that.** It adds the browse experience the frontend "All Files" tab needs: **folders, direct upload, quota, search, star, rename/move/delete, and a storage overview.**

```
   File-Transfer vault-integration plan  →  the STORE  (blobs, DEK, crypto, ingest, minimal read)
                                             ▲
   THIS plan (feature #6)  ─────────────────┘  adds the DRIVE
                                                (folders · upload · quota · search · star · ops)
```

**Prerequisite / sequencing.** If the store is already built (File Transfer done), start at D1. If building standalone, land the store first — pull V1, V2, V4, V5 of the vault-integration plan (store + crypto + software wrapper + minimal read), then this plan's D1. The two plans share one module and one on-disk contract on purpose.

**What I confirmed this session:**
- **No storage / disk-usage / quota concept exists** anywhere in the backend. The FE "All Files" vault (`{fileCount} files · {used} of {capacity}`, folders, upload, star, search) is entirely mock (`VaultContext`).
- **Multipart upload pattern** exists (`src/api/handlers/policy.rs`: `Multipart` → `next_field` → `bytes()` → `tokio::fs::write`) — **but it calls `field.bytes().await`, which buffers the whole field in memory.** On a 4 GB board that OOMs on a large upload. **Upload here must stream** (§5).

**Could not verify:** GitHub live PR/diff (private repo → 404, then rate-limited). Anchors from the project-knowledge index — re-verify against the tip of `feat/62-CRL`. The `src/api/mod.rs` merge line still needs a one-second eyeball.

---

## 1. What exists vs what #6 adds

| Capability | Store (already) | #6 adds |
|---|---|---|
| Encrypted blob at rest (streaming AES-256-GCM) | ✅ `crypto.rs` | reuse |
| Per-file DEK + `KeyWrapper` (SE050 / software) | ✅ `wrapper.rs` | reuse |
| `VaultRecord` metadata + atomic write | ✅ `model.rs`, `persistence.rs` | **extend** (`folder_id`, `starred`) |
| Per-circle namespace | ✅ | **add `Personal` namespace** for direct uploads |
| Ingest from File Transfer | ✅ `ingest.rs` | reuse |
| List / get / download | ✅ minimal | **extend** (folder-scoped listing, breadcrumbs) |
| **Folder hierarchy** (create/nest/move/rename/empty) | ✗ | ✅ folder index |
| **Direct upload** (streamed, encrypted) | ✗ | ✅ |
| **Quota / capacity** ("8 GB, {used} of {capacity}") | ✗ | ✅ accounting + enforcement |
| **Search** across all files | ✗ | ✅ |
| **Star / favourite** | ✗ | ✅ |
| **Rename / move / delete** (file + folder) | ✗ | ✅ |
| **Storage overview** (counts, used, capacity, per-namespace) | ✗ | ✅ |

---

## 2. Architecture — a browsable drive over the encrypted store

```
                        "All Files" tab
        ┌───────────────────────────────────────────────┐
        │  GET  /vault/overview      → counts, used, cap │
        │  GET  /vault/tree?ns=      → folders + files   │
        │  POST /vault/folders       → mkdir             │
        │  POST /vault/upload        → STREAM → encrypt  │
        │  PATCH/DELETE files+folders → rename/move/rm   │
        │  POST /vault/files/:id/star                    │
        │  GET  /vault/search?q=                         │
        └───────────────────────┬───────────────────────┘
                                │  all reuse the store's crypto + blob layer
                                ▼
   NAMESPACES                FOLDER INDEX               BLOB + META (store)
   ┌──────────────┐          ┌────────────────┐         ┌──────────────────┐
   │ Personal     │          │ folders.json   │         │ blobs/<ns>/<id>.enc│
   │ Circle:<id>  │◄────────►│ per namespace, │◄───────►│ meta/<ns>/<id>.json│
   │ Circle:<id2> │          │ signed tree    │  file→   │ (VaultRecord +    │
   └──────────────┘          └────────────────┘  folder  │  folder_id,starred)│
                                                          └──────────────────┘
```

**Namespaces.** The store namespaces by `circle_id`. The "All Files" view is the *device's* whole vault, which is more than circles — it also holds files the user uploads directly. So #6 generalises the namespace:

```rust
pub enum VaultNamespace {
    Personal,            // direct uploads, not tied to a circle → blobs/personal/…
    Circle(String),      // files shared in a circle           → blobs/<circle_id>/…
}
```

Circle-shared files (ingested by File Transfer) stay read-mostly in their circle namespace (matching the FE's per-circle folder); the Personal namespace is the user's own drive. The overview and search aggregate across all namespaces.

---

## 3. Data model additions

### 3.1 Extend `VaultRecord` (additive fields — old records default cleanly)

```rust
// added by #6:
pub folder_id: String,     // "" = namespace root
pub starred: bool,         // default false
```

Old records written by the store (pre-#6) have neither; deserialize with `#[serde(default)]` so they read as root-level, unstarred. No migration needed.

### 3.2 Folder index (new — one signed file per namespace)

```rust
pub struct FolderNode {
    pub folder_id: String,     // urn:uuid
    pub parent_id: String,     // "" = root
    pub name: String,
    pub created_at: String,
}
pub struct FolderIndex {
    pub namespace: String,     // "personal" | circle_id
    pub folders: Vec<FolderNode>,
    pub sequence: u64,
    pub proof: Proof,          // ECDSA-P256, owner DKP — same as every other registry
}
```

Explicit folder nodes (not path-derived) so **empty folders, rename, and move** work cleanly. Stored at `meta/<ns>/folders.json`, signed and atomically written, guarded by `VAULT_WRITE_LOCK`.

Move a file = change its `folder_id`. Move a folder = change a node's `parent_id` (reject cycles). Rename = change `name`. Delete a folder = require empty, or cascade with an explicit `?recursive=true`.

### 3.3 Quota

```rust
pub struct VaultQuota {
    pub capacity_bytes: u64,   // SGX_VAULT_CAPACITY_BYTES, default 8 GiB (matches FE "8 GB")
    pub used_bytes: u64,       // Σ size_cipher across all namespaces
}
```

`used_bytes` is derived by summing `size_cipher` from the meta records (cheap — metadata only, never opens blobs), cached and recomputed on write. Upload/mkdir-of-file rejects with `413 Payload Too Large` when it would exceed capacity.

---

## 4. The crypto label discrepancy (decide this)

The FE shows the vault as **"AES-256-XTS"**. The store uses **AES-256-GCM (STREAM)**. **GCM is the correct choice and XTS is wrong here** — XTS is a length-preserving, *unauthenticated* disk-sector mode; it gives confidentiality but **not integrity**, so a tampered blob would decrypt to garbage silently. For a zero-trust security appliance the at-rest scheme must be **authenticated** (GCM), which is what the store already does.

**Recommendation:** keep the authenticated GCM/STREAM scheme; correct the FE display string from "AES-256-XTS" to "AES-256-GCM" (or a neutral "AES-256, authenticated"). Flag to the frontend team — this is a one-word label fix, not a re-architecture, but it should be accurate on a security product.

---

## 5. Upload must stream (the 4 GB-board rule, again)

The existing multipart pattern (`policy.rs`) does `field.bytes().await` — it materialises the **entire** field in memory. That is fine for a small YAML policy; for a multi-GB vault upload on a 4 GB board it **OOMs**.

**Upload here must stream the multipart field** through the STREAM encryptor without ever holding the whole file:

```rust
// Instead of field.bytes().await (buffers everything):
while let Some(chunk) = field.chunk().await? {   // bounded pieces
    // feed `chunk` into the STREAM encryptor (spawn_blocking for the AES work),
    // write ciphertext to blobs/<ns>/<id>.enc via tokio::fs — never assemble plaintext
}
```

Peak memory ≈ one chunk, independent of file size — same guarantee the store's ingest already gives. This is the single most important implementation detail in the upload path.

---

## 6. Deliverables

Each independently reviewable/testable; tree stays green (`cargo build && cargo test && cargo clippy -- -D warnings`); no existing behaviour changes.

| # | Deliverable | Files | Acceptance test |
|---|---|---|---|
| **D1** | **Namespace + record extensions** (no network) | `src/vault/model.rs`, `namespace.rs` | Unit: `Personal` and `Circle(id)` map to correct paths; extended `VaultRecord` deserialises old (folder-less) records as root/unstarred; store still reads/writes. |
| **D2** | **Folder index** (no network) | `src/vault/folders.rs` | Unit: mkdir / nest / rename / move; **cycle move rejected**; delete-nonempty rejected; recursive delete works; signed + atomic; tampered index rejected. `VAULT_WRITE_LOCK` serialises. |
| **D3** | **Quota accounting** (no network) | `src/vault/quota.rs` | Unit: `used_bytes` = Σ `size_cipher` from meta only (never opens a blob); recompute on write; over-capacity check returns the right verdict. |
| **D4** | **Tree + overview + search REST** | `src/api/handlers/vault.rs`, `routes.rs`, `mod.rs` | `GET /vault/tree?ns=&folder=` returns folders + files + breadcrumbs; `GET /vault/overview` returns counts/used/capacity per namespace; `GET /vault/search?q=` matches filenames across namespaces. |
| **D5** | **Streaming upload** | `src/api/handlers/vault.rs`, `src/vault/upload.rs` | Board: upload a large file → encrypted blob + record in `Personal`; **RSS stays bounded** (does not scale with file size); over-quota upload → `413`; download round-trips to the original bytes. |
| **D6** | **File + folder operations** | `src/api/handlers/vault.rs`, `folders.rs` | `PATCH /vault/files/:id` (rename / move folder); `DELETE /vault/files/:id` (removes blob + record, quota decremented); `POST /vault/files/:id/star`; folder create/rename/move/delete endpoints. Delete is confirmed + irreversible within the vault. |
| **D7** | **Preview support** | `src/api/handlers/vault.rs` | `GET /vault/files/:id/preview` streams decrypted bytes with a correct `Content-Type` for inline display (images/PDF/text); large/opaque types return metadata only. **Thumbnail generation is out of scope** (§13) — preview = the real decrypted bytes, hash-verified. |
| **D8** | **Regression + 3-node + FE contract** | `tests/vault_*.sh` | 3-node run: uploaded + circle-shared files both appear in `overview`; folders survive restart; quota correct; encrypted at rest; no watchdog reset under a large upload. Store, File Transfer, gossip, CRL all green. |

**Sequencing:** D1 → D2 → D3 one dev (small, no network). D4 depends on D1-D3. D5 (upload) is the heaviest and can run in parallel with D6/D7 once D1-D4 land. **Two devs:** Dev A → D1→D2→D3→D4; Dev B picks up D5 (streaming upload) as soon as D1 exists, since it only needs the store + namespace.

---

## 7. File structure

```
src/vault/                         # extends the store module
├── (model.rs)        # + folder_id, starred, VaultNamespace helpers     [D1]
├── namespace.rs      # VaultNamespace, path resolution                  [D1]
├── folders.rs        # FolderIndex, mkdir/rename/move/delete, cycle-check[D2]
├── quota.rs          # VaultQuota, used-bytes accounting + enforcement   [D3]
├── upload.rs         # streamed multipart → STREAM encrypt → blob        [D5]
└── (crypto.rs, wrapper.rs, ingest.rs, persistence.rs)   # REUSED, untouched

src/api/handlers/vault.rs          # extend: tree, overview, search,
                                   #         upload, ops, star, preview   [D4-D7]
```

Storage layout (extends the store):

```
/var/lib/sgx-guardian/vault/
├── blobs/<namespace>/<vault_id>.enc      # <namespace> = personal | <circle_id>
├── meta/<namespace>/<vault_id>.json      # VaultRecord (+ folder_id, starred)
├── meta/<namespace>/folders.json         # signed FolderIndex        (NEW)
└── staging/<vault_id>.part               # transient, 0700, shredded
```

No `main.rs` change and **no new port** — everything rides the admin API (`:8443`). No boot-time task. Keeps us clear of daemon-lifecycle code (board-freeze surface).

---

## 8. Exact FIND → REPLACE

### 8.1 `src/api/routes.rs` — extend the vault router

If the store's minimal `vault_router()` already exists (from the vault-integration plan), **replace it** with the full router below. If not, add it after the last router in `crl_router()` (see the store plan's §8.1 anchor).

**FIND** (the minimal router from the store plan):

```rust
pub fn vault_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/vault/files", get(handlers::vault::list))
        .route("/api/v1/vault/files/:id", get(handlers::vault::detail))
        .route("/api/v1/vault/files/:id/download", get(handlers::vault::download))
}
```

**REPLACE:**

```rust
pub fn vault_router() -> Router<Arc<AppState>> {
    Router::new()
        // Overview + browse
        .route("/api/v1/vault/overview", get(handlers::vault::overview))
        .route("/api/v1/vault/tree", get(handlers::vault::tree))
        .route("/api/v1/vault/search", get(handlers::vault::search))
        // Upload (streamed)
        .route("/api/v1/vault/upload", post(handlers::vault::upload))
        // Folders
        .route(
            "/api/v1/vault/folders",
            post(handlers::vault::create_folder),
        )
        .route(
            "/api/v1/vault/folders/:folder_id",
            patch(handlers::vault::rename_or_move_folder)
                .delete(handlers::vault::delete_folder),
        )
        // Files
        .route("/api/v1/vault/files", get(handlers::vault::list))
        .route(
            "/api/v1/vault/files/:id",
            get(handlers::vault::detail)
                .patch(handlers::vault::rename_or_move_file)
                .delete(handlers::vault::delete_file),
        )
        .route("/api/v1/vault/files/:id/download", get(handlers::vault::download))
        .route("/api/v1/vault/files/:id/preview", get(handlers::vault::preview))
        .route("/api/v1/vault/files/:id/star", post(handlers::vault::toggle_star))
}
```

Extend the `routes.rs` import if `patch` isn't already there:

**FIND:** `use axum::{ routing::{get, post}, Router };`
**REPLACE:** `use axum::{ routing::{get, patch, post}, Router };`

### 8.2 `src/api/mod.rs` — merge (⚠️ verify anchor)

If `vault_router()` is already merged (store plan), **no change**. Otherwise:

```rust
        .merge(routes::crl_router())
        .merge(routes::vault_router())   // ← add
```

### 8.3 `src/main.rs` / `src/enforcement/executor.rs` — **no change** (no boot task, no new port).

---

## 9. Implementation contracts

**Reuse the store — never re-encrypt differently:**

```rust
// Upload path reuses the store's crypto + wrapper exactly:
let dek = crate::vault::crypto::random_dek();
let wrapper = crate::vault::wrapper::default_wrapper()?;   // SE050 or software
// stream field → STREAM encrypt (spawn_blocking) → blobs/<ns>/<id>.enc
let enc_meta = crate::vault::crypto::stream_encrypt(field_stream, &dek, chunk_bytes).await?;
let record = VaultRecord { /* + folder_id, starred:false */ };
crate::vault::persistence::save_record(&namespace, &record)?;   // atomic
```

**Signing** folder index / any registry — identical to everywhere:

```rust
let vm_ref = format!("{}#dkp-v{}", owner.did, owner.current_dkp_version.max(1));
crate::did::doc_sign::sign_in_place_generic(&mut folders.proof, &canonical, km, &vm_ref)?;
```

**KeyManager** — always `crate::vc::issue::load_runtime_key_manager(&node_id)` (cached). Never re-init `DkpManager` in a handler (SE050 contention).

**Async safety (board freeze — upload is the heaviest path):**
- **Streaming upload via `field.chunk().await`, never `field.bytes().await`** (§5). This is the OOM guard.
- **All AES work in `spawn_blocking`**; blob I/O via `tokio::fs`.
- Never hold `VAULT_WRITE_LOCK` across an `.await` — take it only for the short folder/record/quota mutation.
- No `std::thread::sleep`; no synchronous `Command::new().output()` in the runtime.
- Do **not** touch `NebulaDaemon::start()` / `resolve_ca_ip_from_config_inner()`.

**Path safety:** all namespace/folder/file ids sanitised via the store's `safe_id()`; reject `..`, absolute paths, and traversal in folder names. `tree`/`download` must confirm the resolved path stays under the vault base (the `logs.rs` handler already does exactly this with `canonicalize` + `starts_with` — copy that guard).

**Search** is metadata-only (filenames from `meta/`), never decrypts blobs, never opens ciphertext. Case-insensitive substring, capped result count.

**Audit** — extend `AuditCategory::Vault`: log upload / delete / folder-op / star / (over-quota rejected).

---

## 10. Regression checks

```bash
cargo build --release
cargo test
cargo clippy -- -D warnings
cargo build --release --target aarch64-unknown-linux-gnu

# Untouched — must still pass
cargo test --package sgx-guardian-client vault::   # store tests
cargo test --package sgx-guardian-client xfer::    # if transfer applied
cargo test --package sgx-guardian-client vc::
cargo test --package sgx-guardian-client crl::
```

On the boards (binaries direct — **not** `systemctl`/`journalctl`):

```bash
./sgx_guardian_client nodeA

# Upload stays memory-bounded (the 4GB-vs-large-file check)
top -b -d 2 -p "$(pgrep -f 'sgx_guardian_client nodeA')" | grep sgx_guardian   # watch RSS
curl -s -F "file=@big.bin" "http://127.0.0.1:8443/api/v1/vault/upload?ns=personal" | jq .

# Over-quota is rejected, not silently accepted
#   (set SGX_VAULT_CAPACITY_BYTES low, upload past it → expect 413)

# Encrypted at rest
file /var/lib/sgx-guardian/vault/blobs/personal/*.enc     # → "data", not the real type

# Browse + overview + search
curl -s "http://127.0.0.1:8443/api/v1/vault/overview" | jq .
curl -s "http://127.0.0.1:8443/api/v1/vault/tree?ns=personal" | jq '.folders, .files | length'
curl -s "http://127.0.0.1:8443/api/v1/vault/search?q=report" | jq '.results | length'

# Folders survive restart
pkill -f sgx_guardian_client && ./sgx_guardian_client nodeA
curl -s "http://127.0.0.1:8443/api/v1/vault/tree?ns=personal" | jq '.folders'

# Circle-shared file (from a transfer) also shows in the vault
curl -s "http://127.0.0.1:8443/api/v1/vault/tree?ns=guardian-circle-alpha" | jq .

tail -f /var/log/sgx-guardian/*.log | grep -iE "vault|panic|watchdog"
pkill -f sgx_guardian_client
```

---

## 11. Step-by-step checklist

**D1 — namespace + record**
- [ ] `VaultNamespace { Personal, Circle(String) }` + path resolution
- [ ] `VaultRecord` + `#[serde(default)] folder_id`, `starred`
- [ ] Old (store-written) records still read; unit tests

**D2 — folders**
- [ ] `FolderIndex` + `FolderNode`; signed + atomic; `VAULT_WRITE_LOCK`
- [ ] mkdir / rename / move (cycle-check) / delete (empty | recursive)
- [ ] Unit: cycle rejected, nonempty-delete rejected, tampered index rejected

**D3 — quota**
- [ ] `VaultQuota`; `used_bytes` = Σ `size_cipher` (meta only)
- [ ] Recompute-on-write; over-capacity check
- [ ] Unit: never opens a blob; verdict correct

**D4 — tree / overview / search**
- [ ] `overview`, `tree?ns=&folder=` (breadcrumbs), `search?q=`
- [ ] Path-traversal guard (canonicalize + starts_with, per `logs.rs`)
- [ ] routes.rs + mod.rs (§8.1, §8.2)

**D5 — streaming upload**
- [ ] `upload.rs`: `field.chunk().await` loop → STREAM encrypt (`spawn_blocking`) → blob
- [ ] Quota check → `413` when over
- [ ] Board: large upload, **RSS bounded**, download round-trips

**D6 — operations**
- [ ] file rename/move/delete (blob + record + quota decrement)
- [ ] folder rename/move/delete endpoints
- [ ] star toggle; delete confirmed + irreversible in-vault

**D7 — preview**
- [ ] `preview` streams decrypted bytes with correct `Content-Type`, hash-verified
- [ ] Opaque/large types → metadata only

**D8 — regression + 3-node**
- [ ] Uploaded + circle-shared files both in `overview`
- [ ] Folders persist across restart; quota correct; encrypted at rest
- [ ] store / transfer / gossip / CRL green; no watchdog reset

---

## 12. Risks

| Risk | Mitigation |
|---|---|
| **OOM on upload** (4 GB board, large file) via `field.bytes()` | Stream with `field.chunk()` + `spawn_blocking` (§5); D5 asserts bounded RSS |
| **Board freeze** — heaviest I/O path | AES in `spawn_blocking`; `tokio::fs`; no lock across await; no daemon-lifecycle edits |
| **Path traversal** in folder/file names | Sanitise via `safe_id`; reject `..`/absolute; canonicalize + `starts_with` guard (copy `logs.rs`) |
| **Quota drift** (used-bytes wrong after crash) | Recompute from meta (source of truth) on load; never trust a stale cached counter across restart |
| **"AES-256-XTS" label is inaccurate** | Keep authenticated GCM/STREAM; correct the FE display string (§4) — flag to FE team |
| **Contract drift** with the store / Backup #10 | This plan only *extends* the store contract additively; circulate the model additions (§3) to the store + backup tracks |
| **SE050 contention** on upload wrap | One DEK-wrap per file; cached handle; bulk never touches SE050 |
| Branch drift | Re-verify anchors against the tip of `feat/62-CRL` |

---

## 13. Out of scope (flag to Cervais / other tracks)

- **Thumbnail generation** for image previews. Generating thumbnails on the i.MX8MP is CPU cost per file and image-decoder attack surface; the FE can render a preview from the decrypted `download`/`preview` bytes. Revisit only if a gallery view demands server-side thumbnails.
- **Cross-device vault sync / replication.** Each Guardian's vault is local; sharing a file is a transfer, not shared storage.
- **Versioning / file history.** Overwrite/rename is last-write-wins; no version chain in this cut.
- **Deduplication** across identical uploads. Possible later (hash-keyed blobs) but adds refcount complexity — deliberately not here.
- **Backup bundling/restore of the vault** — this plan (and the store) define the on-disk contract so Backup #6→#10 *can* read it; the actual backup/restore logic is that feature's work.
- **Per-circle master-key provisioning** for the SE050 wrapper — a separate security-ops decision consumed by the store's `Se050Wrapper`.
