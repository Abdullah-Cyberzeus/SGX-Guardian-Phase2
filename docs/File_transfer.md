# SG-X Guardian File Transfer and Vault APIs

Last updated: July 24, 2026

## Transfer source contract

`POST /api/v1/xfer/send` accepts exactly one source:

```json
{
  "peer_did": "did:guardian:RECEIVER",
  "path": "/tmp/file.pdf"
}
```

or:

```json
{
  "peer_did": "did:guardian:RECEIVER",
  "vault_id": "urn:uuid:..."
}
```

Rules:

- Exactly one of `path` or `vault_id` must be supplied.
- Supplying both returns `400 BAD_REQUEST`.
- Supplying neither returns `400 BAD_REQUEST`.
- Unknown `vault_id` returns `404 NOT_FOUND`.
- Maximum transfer size is `52,428,800` bytes (50 MiB).
- Size is validated in both the API handler and the XFER engine.

## Vault-backed sending

Vault send flow:

1. Load the Vault record by `vault_id`.
2. Reject oversized records before decrypting or staging.
3. Decrypt with the existing Vault crypto.
4. Verify plaintext SHA-256 against `sha256_plain`.
5. Stage plaintext in XFER temp storage with directory mode `0700` and file mode `0600`.
6. Send through the existing signed XFER protocol.
7. Remove plaintext staging on success, failure, cancellation, or receiver rejection.

Notes:

- The sender's encrypted Vault record remains unchanged.
- The sender's `.enc` blob is never sent directly.
- The receiver still creates its own encrypted Vault record after ingest.

## Folder list API

`GET /api/v1/vault/folders` returns created folders from the persisted folder index.

Supported filters:

- `namespace`
- `circle_id`
- `parent_id`

Response shape:

```json
{
  "count": 2,
  "folders": [
    {
      "folder_id": "urn:uuid:...",
      "parent_id": "",
      "name": "Root",
      "namespace": "personal",
      "circle_id": "",
      "created_at": "2026-07-24T10:00:00Z"
    }
  ]
}
```

Behavior:

- Root folders are identified by `parent_id: ""`.
- Child folders carry their stored `parent_id`.
- Personal and Circle namespaces remain separated.
- Empty storage returns `count: 0` and an empty `folders` array.

## API counts

- XFER APIs: `5`
- Vault APIs: `12`
- Total APIs: `17`

## Folder map

Logical folder map returned by `GET /api/v1/vault/folders`:

```text
personal
  root folders: parent_id=""
  child folders: parent_id="<folder_id>"

<circle_id>
  root folders: parent_id=""
  child folders: parent_id="<folder_id>"
```
