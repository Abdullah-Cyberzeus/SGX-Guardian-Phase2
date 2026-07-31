# SE050 backend — multi-node-on-one-chip identity

Mirrors [`src/tpm/README.md`](../tpm/README.md): a single physical SE050
issues one identity per key slot, not per process. If several containers on
the *same physical board* ever talk to one SE050 chip over I2C, they must
not share the DKP/DIK slot IDs or the hardware UID reading — otherwise the
second and third container to boot will find the slot already provisioned
and silently adopt the first container's keys and identity.

**This only matters when multiple containers share one physical chip.**
Every existing single-node deployment — bare metal board or a lone
container — is unaffected: none of the env vars below are set for it, so
every code path below returns byte-for-byte what it always returned.

## Opt-in per-node env vars

| Var | Default | Purpose |
|---|---|---|
| `SGX_SE_DKP_KEY_ID_BASE` | `0x20000010` (`dkp::DKP_BASE_KEY_ID`) | DKP slot base; version N = base + N - 1, same rotation math as today |
| `SGX_SE_DIK_KEY_ID` | `0x20000100` (`dik::DIK_KEY_ID`) | DIK slot (fixed, non-rotating) |

Set these only for containers that share one physical SE050 with siblings,
spaced the same way as the TPM guidance (0x10 apart is plenty of rotation
headroom: `0x20000010` / `0x20000020` / `0x20000030`, `0x20000100` /
`0x20000110` / `0x20000120`).

## `device_uid` divergence is opt-in too

`pcr::node_device_uid(config, dkp_pub_path, fallback)` returns the raw
`ssscli se05x uid` hardware UID unchanged **unless** `dkp_key_id_base` has
been explicitly overridden away from its default. Only then does it fold in
the node's own DKP public key (`SHA256(hw_uid || dkp_pub_der)`) so that PCR
snapshots, baselines, and audit records stay distinguishable per node even
though the physical chip UID is identical for all of them. `main.rs` wires
this in only when `KeyManager::backend_name() == "SE050"`; the software
backend and every existing hardware deployment are untouched.

## What was intentionally NOT changed

- **Per-key auth on `ssscli generate`/`sign`.** Unlike TPM's `tpm2_create -p`,
  the `ssscli` wrapper in `ssscli.rs` has no auth/policy parameter wired for
  key generation or signing today. Adding one would mean guessing at
  undocumented CLI flags against production board firmware — too risky to
  do without confirming the exact NXP EdgeLock policy syntax from board
  docs first. Left as a follow-up, not silently done.
- **`runtime_device_uid_details()` in `key_manager.rs`** (used by DID
  derivation in `did/method.rs` and by `attestation_service.rs`) was left
  untouched. DID uniqueness across nodes already comes from the DIK pubkey
  itself (`derive(uid_bytes, dik_pubkey)` hashes both together) once DIK
  slots are separated via `SGX_SE_DIK_KEY_ID` — changing the shared
  `device_uid` computation there would also silently change the DID of
  every *already-deployed*, single-node SE050 board on upgrade, which is
  exactly the breakage this change must not cause.
