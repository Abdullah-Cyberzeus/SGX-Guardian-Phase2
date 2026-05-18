# `did:guardian` DID Method Specification v1.0

## 1. Method Name
`guardian`

## 2. Method-Specific Identifier Syntax

```abnf
did               = "did:guardian:" guardian-id
guardian-id       = 32*44 base58btc-char
base58btc-char    = ALPHA / DIGIT
```

## 3. Derivation

```text
did_id_bytes = SHA-256(SE050_UID_BYTES || DKP_v1_PUBKEY_DER)
guardian-id  = base58btc(did_id_bytes)
```

- `SE050_UID_BYTES`: SE050 hardware UID from `ssscli se05x uid` (or fallback string bytes in software mode)
- `DKP_v1_PUBKEY_DER`: public key bytes from `/var/lib/sgx-guardian/keys/dkp_pub.der`

## 4. Operations

### 4.1 Create
- Trigger: first startup when `did.json` is absent
- Behavior: derive DID, sign derivation proof with DKP, persist to `/var/lib/sgx-guardian/identity/did.json`
- Idempotent: existing valid record is reused

### 4.2 Resolve
- Input: DID string
- Output: local DID status and active public key bytes
- Scope in Sprint 5 Task 1: local self/peer-cache resolution

### 4.3 Update
- Trigger: DKP rotation
- Behavior: update `current_dkp_version`
- DID identifier is immutable

### 4.4 Deactivate
- Trigger: admin command
- Behavior: set `deactivated_at` timestamp
- Deactivation persists across restarts

## 5. Security Notes

- DID binds to hardware UID and key material.
- DID carries no user PII.
- A derivation proof signature is persisted for verification workflows.
