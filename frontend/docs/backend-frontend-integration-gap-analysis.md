# SGX Guardian: Backend-Frontend Integration Gap Analysis

> **Document Version:** 3.0
> **Date:** 2026-05-20
> **Last Updated:** 2026-05-20
> **Purpose:** Compare backend CLI commands with frontend implementation to identify gaps

---

## Executive Summary

The SGX Guardian backend provides **15 CLI commands** via `sgx-pa-cli` for node management, security operations, key management, and integrity verification. All 15 commands have complete frontend UI coverage with live API integration.

| Metric | Count | Percentage |
|--------|-------|------------|
| **Fully Implemented** | 15 | **100%** |
| **Partially Implemented** | 0 | 0% |
| **Not Implemented** | 0 | 0% |

**Status Update (2026-05-20):** All mock data replaced with live API calls across all screens. Baseline tab, history tab, emergency rotation history, policy authority key, guardian status labels, pending device metadata, and scan results now all sourced from backend API responses.

---

## Quick Reference: Implementation Status

| # | Backend Command | Category | Status | Frontend Page |
|---|-----------------|----------|--------|---------------|
| 1 | `status` | Node Info | DONE | `HM02GuardianDetail.tsx` — hostname, port, public key; status label from API |
| 2 | `boot-status` | Security | DONE | `SC01BootStatus.tsx` — HAB state, trust chain, enforcing/permissive from `deviceClosed` |
| 3 | `peers` | Network | DONE | `NW03PeersList.tsx`, `HM03NetworkTopology.tsx` |
| 4 | `attestation` | Security | DONE | `SC02AttestationStatus.tsx` — results, history, re-attest action |
| 5 | `logs` | Monitoring | DONE | `LG01LogsViewer.tsx` — filters, search, export |
| 6 | `keygen` | Key Mgmt | DONE | `KM01KeyManagement.tsx` — key generation, status from `policyService.getKeyStatus()` |
| 7 | `sign` | Policy | DONE | `PL01PolicyManagement.tsx` — sign tab with key from `keyStatus.algorithm` |
| 8 | `verify` | Policy | DONE | `PL01PolicyManagement.tsx` — verify in Policies tab |
| 9 | `dkp-status` | Key Mgmt | DONE | `KM01KeyManagement.tsx` — DKP Status tab via `useDKPStatus()` |
| 10 | `dkp-rotate` | Key Mgmt | DONE | `KM01KeyManagement.tsx` — rotate action |
| 11 | `dkp-revoke` | Key Mgmt | DONE | `KM01KeyManagement.tsx` — revoke with reason |
| 12 | `emergency-rotate` | Key Mgmt | DONE | `KM01KeyManagement.tsx` — Emergency tab; history built from API responses |
| 13 | `pcr-status` | Integrity | DONE | `IN01IntegrityDashboard.tsx` — PCR Status tab via `usePCRStatus()` |
| 14 | `pcr-baseline-create` | Integrity | DONE | `IN01IntegrityDashboard.tsx` — Baseline tab via `usePCRBaseline()` |
| 15 | `pcr-baseline-verify` | Integrity | DONE | `IN01IntegrityDashboard.tsx` — Verify action; history via `usePCRHistory()` |

---

## Mock Data Elimination Log

All screens that previously mixed mock data with live API data have been updated. The following changes were made on 2026-05-20:

| Screen | Was Hardcoded | Now Sources From |
|--------|--------------|-----------------|
| `IN01IntegrityDashboard.tsx` | `mockPCRBaseline` in Baseline tab | `GET /api/v1/pcr/baseline` via `usePCRBaseline()` |
| `IN01IntegrityDashboard.tsx` | `mockPCRVerifications` in History tab | `GET /api/v1/pcr/history` via `usePCRHistory()` |
| `IN01IntegrityDashboard.tsx` | Baseline badge always "Match" | Derived from `pcrMetadata.integrityStatus` |
| `KM01KeyManagement.tsx` | `mockEmergencyRotations` history | Accumulated from `POST /api/v1/dkp/emergency-rotate` responses |
| `KM01KeyManagement.tsx` | Hardcoded key list `["DKP", "Software Attestation Key", "TLS Certificate"]` | Real active keys from `dkpKeys` state |
| `PL01PolicyManagement.tsx` | `mockPolicyAuthorityKey.name/.algorithm` | `keyStatus.algorithm` from `policyService.getKeyStatus()` |
| `HM01Dashboard.tsx` | `"Online"` status label | `guardian.status` from `GET /api/v1/node/status` |
| `HM01Dashboard.tsx` | Hardcoded scan device names/IPs | Real device names/IPs from `useDevices()` |
| `DV01DevicesList.tsx` | `"Online"` in guardian card | `guardian.status` from API |
| `DV01DevicesList.tsx` | Pending device: "3 minutes ago", "10.0.4.0/24 · VLAN 40", "Linux (fingerprint)" | `device.lastSeen`, `device.ip`, `device.os` from API |
| `SC01BootStatus.tsx` | `"enforcing"` hardcoded label | Derived from `bootStatus.deviceClosed` → "enforcing" / "permissive" |

---

## Backend CLI Command Reference

| # | Command | Category | Purpose |
|---|---------|----------|---------|
| 1 | `status` | Node Info | Show node identity and config |
| 2 | `boot-status` | Security | Show secure boot chain status |
| 3 | `peers` | Network | List discovered and attested peers |
| 4 | `attestation` | Security | Show last attestation result |
| 5 | `logs` | Monitoring | View recent node logs |
| 6 | `keygen` | Key Mgmt | Generate ECDSA-P256 keypair |
| 7 | `sign` | Policy | Sign a UEP policy file |
| 8 | `verify` | Policy | Verify a signed policy file |
| 9 | `dkp-status` | Key Mgmt | Show DKP key version history |
| 10 | `dkp-rotate` | Key Mgmt | Rotate DKP to next version |
| 11 | `dkp-revoke` | Key Mgmt | Revoke a specific DKP version |
| 12 | `emergency-rotate` | Key Mgmt | Emergency rotation of ALL keys |
| 13 | `pcr-status` | Integrity | Show current PCR measurements |
| 14 | `pcr-baseline-create` | Integrity | Create golden PCR baseline |
| 15 | `pcr-baseline-verify` | Integrity | Verify PCRs against baseline |

---

## Detailed Implementation Status

### 1. Node Status (`status`)

**CLI Command:**
```bash
$ sgx-pa-cli status --node nodeA
```

**Frontend Status:** DONE

| File | Features |
|------|----------|
| `HM02GuardianDetail.tsx` | Hostname, port, public key, node ID |
| `HM01Dashboard.tsx` | Guardian name, status (from API), connection type, IP |
| `DV01DevicesList.tsx` | Guardian card with live status label |

---

### 2. Boot Status (`boot-status`)

**CLI Command:**
```bash
$ sgx-pa-cli boot-status
```

**Frontend Status:** DONE

| File | Features |
|------|----------|
| `SC01BootStatus.tsx` | HAB state, device closed/open, enforcing/permissive mode from `deviceClosed` field, trust chain visualization, binary hash, boot chain integrity |

---

### 3. Peers (`peers`)

**CLI Command:**
```bash
$ sgx-pa-cli peers
```

**Frontend Status:** DONE

| File | Features |
|------|----------|
| `NW03PeersList.tsx` | Peer list with verification status, last seen |
| `HM03NetworkTopology.tsx` | Network topology visualization |

---

### 4. Attestation (`attestation`)

**CLI Command:**
```bash
$ sgx-pa-cli attestation
```

**Frontend Status:** DONE

| File | Features |
|------|----------|
| `SC02AttestationStatus.tsx` | Last attestation result, history, per-peer checks (PCR, signature, policy), re-attest all action |

---

### 5. Logs (`logs`)

**CLI Command:**
```bash
$ sgx-pa-cli logs --node nodeA --tail 20
```

**Frontend Status:** DONE

| File | Features |
|------|----------|
| `LG01LogsViewer.tsx` | Log entries from API, filter by node/level/category, search, export |

---

### 6. Keygen (`keygen`)

**CLI Command:**
```bash
$ sgx-pa-cli keygen
```

**Frontend Status:** DONE

| File | Features |
|------|----------|
| `KM01KeyManagement.tsx` | Key generation, key status from `policyService.getKeyStatus()`, algorithm from API |
| `PL01PolicyManagement.tsx` | Policy signing key name and algorithm sourced from `keyStatus` API response |

---

### 7. Sign Policy (`sign`)

**CLI Command:**
```bash
$ sgx-pa-cli sign --policy policy.yaml --key guardian_private.key
```

**Frontend Status:** DONE

| File | Features |
|------|----------|
| `PL01PolicyManagement.tsx` | Policy file upload, key selector (algorithm from API), sign action, download signed policy |

---

### 8. Verify Policy (`verify`)

**CLI Command:**
```bash
$ sgx-pa-cli verify --policy policy.yaml.sig
```

**Frontend Status:** DONE

| File | Features |
|------|----------|
| `PL01PolicyManagement.tsx` | Upload signed policy, verification result with status badges, detailed check display |

---

### 9. DKP Status (`dkp-status`)

**CLI Command:**
```bash
$ sgx-pa-cli dkp-status
```

**Frontend Status:** DONE

| File | Features |
|------|----------|
| `KM01KeyManagement.tsx` | Active key card, key version history, SE050 indicator, algorithm — all from `GET /api/v1/dkp/status` |

---

### 10. DKP Rotate (`dkp-rotate`)

**CLI Command:**
```bash
$ sgx-pa-cli dkp-rotate
```

**Frontend Status:** DONE

| File | Features |
|------|----------|
| `KM01KeyManagement.tsx` | Rotate key button, confirmation dialog, daemon restart notification banner |

---

### 11. DKP Revoke (`dkp-revoke`)

**CLI Command:**
```bash
$ sgx-pa-cli dkp-revoke --version 1 --reason "compromised key"
```

**Frontend Status:** DONE

| File | Features |
|------|----------|
| `KM01KeyManagement.tsx` | Revoke action on deprecated keys, reason input, irreversibility warning, 30-day grace period notice |

---

### 12. Emergency Rotate (`emergency-rotate`)

**CLI Command:**
```bash
$ sgx-pa-cli emergency-rotate
```

**Frontend Status:** DONE

| File | Features |
|------|----------|
| `KM01KeyManagement.tsx` | Emergency tab, confirmation dialog, rotation history populated from `POST /api/v1/dkp/emergency-rotate` response, key list from live `dkpKeys` state, daemon restart banner |

---

### 13. PCR Status (`pcr-status`)

**CLI Command:**
```bash
$ sgx-pa-cli pcr-status
```

**Frontend Status:** DONE

| File | Features |
|------|----------|
| `IN01IntegrityDashboard.tsx` | PCR0-PCR4 register cards, hash values, integrity status badge, composite digest, DKP version — all from `GET /api/v1/pcr/status` |

---

### 14. PCR Baseline Create (`pcr-baseline-create`)

**CLI Command:**
```bash
$ sgx-pa-cli pcr-baseline-create
```

**Frontend Status:** DONE

| File | Features |
|------|----------|
| `IN01IntegrityDashboard.tsx` | Baseline tab fetches from `GET /api/v1/pcr/baseline`, displays version, created date, registers, composite digest; Create New Baseline action posts to `POST /api/v1/pcr/baseline/update`; overall badge derived from live integrity status |

---

### 15. PCR Baseline Verify (`pcr-baseline-verify`)

**CLI Command:**
```bash
$ sgx-pa-cli pcr-baseline-verify
```

**Frontend Status:** DONE

| File | Features |
|------|----------|
| `IN01IntegrityDashboard.tsx` | "Verify Against Baseline" button posts to `POST /api/v1/pcr/verify`; History tab fetches from `GET /api/v1/pcr/history` via `usePCRHistory()`; match/mismatch badges derived from live API data |

---

## Frontend Features Not in Backend CLI

| Feature | Frontend Location | Backend Support |
|---------|-------------------|-----------------|
| Circle/Team Collaboration | `NW01–NW04` pages | Not in CLI |
| AI Threat Recommendations | `AL07AIRecommendation.tsx` | Not in CLI |
| Smart Home Integrations | `DV11SmartHome.tsx` | Not in CLI |
| Custom Alert Rules Engine | `ST12AlertRules.tsx` | Not in CLI |
| Geofencing | `ST07Geofencing.tsx` | Not in CLI |
| Device Security Scanning | `DV06SecurityScan.tsx` | Not in CLI |
| DID (Decentralized ID) | `ST02GuardianInfo.tsx` | Not in CLI |

---

## Remaining Mock Fallbacks (Intentional)

Some screens still use mock data as a **null fallback only** — when the API returns no data, mock data is shown rather than an empty state. These are intentional and will be addressed when the respective backend APIs are stabilised.

| Screen | Mock Used As Fallback | Backend API Status |
|--------|----------------------|-------------------|
| `HM01Dashboard.tsx` | `mockAlerts`, `mockCircles`, `mockThreatIntel` | No backend endpoint yet |
| `AL01AlertsList.tsx` | `mockAlerts` | Fallback only when API returns null |
| `DV01DevicesList.tsx` | `mockDevices`, `mockGuardian` | Fallback only when API returns null |
| `NW01CirclesList.tsx` | `mockCircles` | Fallback only when API returns null |
| `STTopology.tsx` | `mockGuardian`, `mockDevices` | Fallback only when API returns null |
| `PL01PolicyManagement.tsx` | `mockSignedPolicies` | Fallback only when API returns empty list |

---

## API Endpoints In Use

| Endpoint | Method | Used By |
|----------|--------|---------|
| `/node/status` | GET | `HM01Dashboard`, `HM02GuardianDetail`, `DV01DevicesList` |
| `/node/boot-status` | GET | `SC01BootStatus` |
| `/node/restart` | POST | `KM01KeyManagement`, `PL01PolicyManagement` |
| `/dkp/status` | GET | `KM01KeyManagement` |
| `/dkp/rotate` | POST | `KM01KeyManagement` |
| `/dkp/revoke` | POST | `KM01KeyManagement` |
| `/dkp/emergency-rotate` | POST | `KM01KeyManagement` |
| `/pcr/status` | GET | `IN01IntegrityDashboard` |
| `/pcr/baseline` | GET | `IN01IntegrityDashboard` |
| `/pcr/verify` | POST | `IN01IntegrityDashboard` |
| `/pcr/baseline/update` | POST | `IN01IntegrityDashboard` |
| `/pcr/history` | GET | `IN01IntegrityDashboard` |
| `/attestation/results` | GET | `SC02AttestationStatus` |
| `/attestation/attest-all` | POST | `SC02AttestationStatus` |
| `/policy/list` | GET | `PL01PolicyManagement` |
| `/policy/sign` | POST | `PL01PolicyManagement` |
| `/policy/verify` | POST | `PL01PolicyManagement` |
| `/policy/key-status` | GET | `PL01PolicyManagement`, `KM01KeyManagement` |
| `/policy/keygen` | POST | `PL01PolicyManagement` |
| `/logs` | GET | `LG01LogsViewer` |
| `/peers` | GET | `NW03PeersList` |
