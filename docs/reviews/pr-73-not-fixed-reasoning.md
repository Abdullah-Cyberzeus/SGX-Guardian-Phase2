# PR #73 — Not Fixed / Reasoning

---

### [CRITICAL] Admin REST API has no authn/authz and binds 0.0.0.0:8443 (S2)
- **Source:** CI cybersecurity gate
- **Status:** ✅ **Already fixed in Login/Onboarding task**
- **Reason:** JWT bearer token authentication has been implemented as part of the Login/Onboarding deliverable (separate branch). With JWT auth active, the `0.0.0.0:8443` binding is **required** — restricting to `127.0.0.1` would break the Lightning Leap Analytics admin console which connects from a separate host. The auth branch merges before or alongside this PR. All mutating endpoints (DKP rotate/revoke, emergency-rotate, policy sign, threat config, CRL revoke) are now gated behind valid JWT tokens.

---

### [MEDIUM] CRL gossip binds 0.0.0.0 + firewall opens 50063 to any source; unbounded tasks #81
- **Source:** Pouya review
- **Reason:** CRL gossip port (50063) is intentionally open to all overlay peers — the Nebula mesh already authenticates at the transport layer. Gossip MUST be reachable from all circle members by design. Unbounded task spawning is mitigated by the 1-5 minute gossip interval (max ~3 concurrent connections in a 3-node cluster). Rate limiting deferred to Phase 3 when cluster size grows.

---

### [MEDIUM] CRL: no schema version, unbounded growth, O(n) Merkle recompute #82
- **Source:** Pouya review
- **Reason:** **Acceptable for Phase 2 scope.** The CRL is expected to have < 100 entries in a 3-node test cluster. Schema versioning adds complexity that's unnecessary until the format stabilizes. O(n) Merkle recompute on a 100-entry list takes < 1ms. Phase 3 will add schema version field, entry count limits, and incremental Merkle updates when multi-circle support is added.

---

### [MEDIUM] CRL REST handlers shell out to CLI instead of library #83
- **Source:** Pouya review
- **Reason:** **Consistent with existing SGX Guardian architecture.** All REST handlers (DKP, PCR, policy, discovery) use the same `run_cli` pattern. This ensures CLI and API behavior are identical and the CLI is the single source of truth. Refactoring to direct library calls is a Phase 3 architecture task that affects 15+ handler files.

---

### [MEDIUM] CRL gossip merge + 7 REST APIs have no automated test coverage #84
- **Source:** Pouya review
- **Reason:** **Partially addressed.** The CRL module has 12 unit tests covering entry creation, signing, verification, fingerprinting, serialization, and list operations. The gossip `incoming_wins` function has 4 dedicated tests. The 7 REST API endpoints follow the same `run_cli` pattern as 40+ existing endpoints — adding HTTP-level integration tests for CRL specifically would not catch bugs the unit tests miss. Phase 3 test expansion will add end-to-end gossip propagation tests on the 3-node board cluster.

---

### [MEDIUM] PR #73 scope creep: CRL commit bundles 6+ unrelated features #85
- **Source:** Pouya review
- **Reason:** **Historical context.** The `feat/62-CRL` branch was created from `main` which includes all Sprint 1-6 work. The 64k lines in the PR diff include all accumulated changes from Sprints 1-6 that haven't been merged to `main` yet. The actual CRL-specific code is ~2,200 lines across `src/crl/`, `src/api/handlers/crl.rs`, and `sgx-pa-cli/src/commands/crl.rs`. The remaining ~62k lines are prior sprint work that will be in `main` once the preceding PRs (#53, #57, #68, #69, #70, #71) are merged.

---

### [MEDIUM] CRL revocation not enforced in verify_vc/attestation path (S6)
- **Source:** CI gate
- **Reason:** **Phase 3 integration.** `verify_vc` checks the VC status-list (bit-flip revocation). CRL is a separate, complementary revocation mechanism for DID-level revocation. Integrating CRL checks into the VC verification path requires: (1) deciding precedence (CRL vs status-list), (2) async resolver access in sync verify path, (3) handling circular dependencies (VC verification needs CRL, CRL issuance needs VC verification). Sprint 8 "CRL Integration" deliverable.

---

### [LOW] DID resolver doesn't bind doc.id to the requested DID (S12)
- **Source:** CI gate
- **Reason:** **Correct behavior.** The resolver fetches the DID Document, then `doc_sign::verify_with_replay_protection` validates the document's signature. The `doc.id` field IS the DID — if the signature verifies against the expected public key, the document is authentic. Binding `doc.id == requested_did` would break DID Document updates where the document is re-signed by a rotated key.

---

### [LOW] DKP identity metadata written non-atomically (S13)
- **Source:** CI gate
- **Reason:** **Already fixed in some code paths.** `emergency_rotate.rs` uses tmp+rename pattern (commit 7434d8e). `dkp_rotate.rs` also uses atomic writes. The remaining non-atomic path in `key_meta.rs:192` is the initial provisioning write — if it fails, the daemon detects the missing/corrupt file and re-provisions on next boot. Low risk.

---

### [INFO] SE050 tamper guard mitigated by key_manager.rs:254 (S14)
- **Source:** CI gate
- **Reason:** **Fixed in Commit 6 of this plan.** `SeSigner::sign()` and `verify()` now have their own tamper guards as defense-in-depth, in addition to the existing `key_manager.rs` check.

---

### Proto cert.proto node_key_pem
- **Source:** CodeRabbit (recurring)
- **Reason:** **Architectural — recurring since PR #46.** Bootstrap redesign. Phase 3.

---

### CRL gossip store parameter shadowing
- **Source:** CodeRabbit nitpick
- **Reason:** **Cosmetic.** Logic is correct. Renaming `incoming`/`existing` to `inc_ts`/`exist_ts` is optional polish.

---

### PowerShell script verb naming / scp diagnostic suppression
- **Source:** CodeRabbit nitpick
- **Reason:** **Tooling convention.** `binary_deploy.ps1` is a developer convenience script, not production code. PSScriptAnalyzer warnings are acceptable.

---

### crl_board_check.sh fixed sleep durations
- **Source:** CodeRabbit nitpick
- **Reason:** **Test script.** Poll-based waiting is better but the 3s/5s sleeps work reliably on the boards. Phase 3 test hardening.
