# TPM backend — multi-node identity

See also [`src/secure_element/README.md`](../secure_element/README.md) for
the equivalent SE050 fix — same problem, opt-in the same way.

A single TPM issues one identity per persistent **handle**, not per process.
When multiple containers/nodes share one TPM (e.g. the `nodeA/nodeB/nodeC`
dev cohort), they must use distinct handles and, ideally, distinct object
auth — otherwise the second and third node to start will find the first
node's handle already provisioned and silently adopt its keys and DID.

## Required per-node env vars

| Var | nodeA | nodeB | nodeC |
|---|---|---|---|
| `SGX_TPM_DKP_HANDLE_BASE` | `0x81000010` | `0x81000020` | `0x81000030` |
| `SGX_TPM_DIK_HANDLE` | `0x81000100` | `0x81000110` | `0x81000120` |
| `SGX_TPM_KEY_AUTH` | distinct secret | distinct secret | distinct secret |

`SGX_TPM_KEY_AUTH` should come from a container secret, not compose
plaintext — see `docker-compose.dev.yml`, which reads it from
`${NODEA_TPM_KEY_AUTH}` / `${NODEB_TPM_KEY_AUTH}` / `${NODEC_TPM_KEY_AUTH}`.
Leaving it unset falls back to no object auth (same as today).

### Why 0x10 spacing

`dkp::TpmDkpManager::rotate()` computes
`new_handle = dkp_handle_base + new_version - 1`. Tighter spacing (e.g.
`0x10/0x11/0x12`) means a node's *first* key rotation lands on the next
node's base handle. `0x10` gives 16 rotations of headroom before that risk
reappears.

## `device_uid` is node-unique, not just TPM-unique

`ek::node_uid[_hex]` derives the identity used in PCR snapshots
(`secure_element::pcr::PcrSnapshot::device_uid`) as
`SHA256(EK_pub DER || DKP_pub DER)`, not the bare EK digest
(`ek::uid_hex`). A shared TPM has exactly one EK, so hashing only the EK
would produce an identical `device_uid` for every node on that TPM; folding
in the DKP public key — distinct per node once handles are separated above —
makes it unique per node while still binding to the physical TPM.

Callers must pass the node's own DKP public key path (see
`dkp::DKP_PUB_PATH`); there is no internal fallback, so a missing DKP key
fails loudly instead of silently reintroducing the collision.

## Not fixed by any of the above

The root of trust is still the one physical TPM. Host or TPM compromise
compromises every node's identity simultaneously. This setup is valid for a
demo/dev cohort, not as a production claim of per-node hardware roots of
trust.
