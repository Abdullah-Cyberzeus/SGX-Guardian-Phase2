# Phase 2 Test Cases Addendum - CRL-001..010

This is the source addendum for the existing `docs/Test Cases.pdf` artifact. It covers Sprint 4 Task 1 Certificate Revocation List behavior.

| Case | Setup | Pass Criteria |
|---|---|---|
| CRL-001 Owner revokes member, all reasons | nodeA CA, nodeB member | `sgx-pa-cli crl revoke --did <B-DID> --reason compromised --severity critical` succeeds; `sgx-pa-cli crl check --did <B-DID>` returns `revoked: true`. |
| CRL-002 Member reports another member compromise | nodeB revokes nodeC | Succeeds for `critical` or `high` severity with a security-critical reason; `sgx-pa-cli crl verify` passes. |
| CRL-003 Member tries Medium severity | nodeB attempts `--severity medium` | Fails with `MemberSeverityTooLow(Medium)`. |
| CRL-004 Member tries `voluntary_departure` | nodeB attempts `--reason voluntary_departure` | Fails with `MemberReasonNotCritical`. |
| CRL-005 Self-revocation | nodeA tries to revoke its own DID | Fails with `SelfRevocation`. |
| CRL-006 Idempotent re-revoke | Revoke nodeC twice | First revoke succeeds; second revoke fails with `AlreadyRevoked`. |
| CRL-007 Persistence across restart | Revoke, kill daemon, restart, run `sgx-pa-cli crl check` | Returns `revoked: true` after restart. |
| CRL-008 Forgery rejected | Hand-craft entry with `revoker_did=<B-DID>` but sign with C's key | `sgx-pa-cli crl verify` returns `InvalidProof`. |
| CRL-009 Merkle root anti-entropy | Revoke 3 DIDs on nodeA; copy `crl.json` to nodeB; recompute/check root | Identical root values; `sgx-pa-cli crl verify` passes. |
| CRL-010 Cross-ref VC revocation | nodeA owner revokes nodeB that has an issued membership VC | Status-list bit for nodeB's VC is `1` after the CRL revoke. |

Board smoke script: `scripts/crl_board_check.sh`.
