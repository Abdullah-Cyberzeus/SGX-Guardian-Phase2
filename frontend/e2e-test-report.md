# SGX Guardian CLI Command UI Navigation Guide

> **Version:** 1.0
> **Date:** 2026-04-16
> **Purpose:** Help backend team locate frontend implementations of CLI commands

---

## Quick Navigation Summary

| # | CLI Command | UI Location | Navigation Path |
|---|-------------|-------------|-----------------|
| 1 | `status` | Guardian Detail | Home → Guardian Card |
| 2 | `boot-status` | Boot Status Page | Settings → Security & Keys → Boot Status |
| 3 | `peers` | Network Topology | Home → Topology / Settings → Network Topology |
| 4 | `attestation` | Attestation Status | Settings → Security & Keys → Attestation |
| 5 | `logs` | Logs Viewer | Settings → Security & Keys → Logs |
| 6 | `keygen` | Key Management | Settings → Security & Keys → Key Management |
| 7 | `sign` | Policy Management | Settings → Security & Keys → Policy Management → Sign tab |
| 8 | `verify` | Policy Management | Settings → Security & Keys → Policy Management → Policies tab |
| 9 | `dkp-status` | Key Management | Settings → Security & Keys → Key Management → DKP Status tab |
| 10 | `dkp-rotate` | Key Management | Settings → Security & Keys → Key Management → "Rotate Key" button |
| 11 | `dkp-revoke` | Key Management | Settings → Security & Keys → Key Management → History tab → Select deprecated key → "Revoke This Key" |
| 12 | `emergency-rotate` | Key Management | Settings → Security & Keys → Key Management → Emergency tab |
| 13 | `pcr-status` | Integrity Dashboard | Settings → Security & Keys → Integrity → PCR Status tab |
| 14 | `pcr-baseline-create` | Integrity Dashboard | Settings → Security & Keys → Integrity → Baseline tab → "Create Golden Baseline" |
| 15 | `pcr-baseline-verify` | Integrity Dashboard | Settings → Security & Keys → Integrity → "Verify Against Baseline" button |

---

## Detailed Navigation Instructions

### Accessing Security & Keys Section

All security-related commands are under **Settings → Security & Keys**:

1. Tap the **Settings** tab in bottom navigation
2. Scroll to **"Security & Keys"** section
3. Select the relevant option:
   - **Key Management** - DKP operations (status, rotate, revoke, emergency)
   - **Integrity** - PCR operations (status, baseline create/verify)
   - **Boot Status** - Secure boot chain status
   - **Attestation** - Peer attestation results
   - **Policy Management** - Sign and verify policies
   - **Logs** - System log viewer

---

## Command-Specific Navigation

### 1. `status` - Node Status
**File:** `src/app/screens/home/HM02GuardianDetail.tsx`
**Routes:** `/home/guardian`

**Navigation:**
1. Go to Home tab
2. Tap the Guardian device card at the top

**Displays:**
- Node ID, Hostname, IP Address, Port
- Public Key (with copy action)
- Device model, firmware version

---

### 2. `boot-status` - Secure Boot Chain
**File:** `src/app/screens/security/SC01BootStatus.tsx`
**Routes:** `/settings/boot-status`, `/boot-status`

**Navigation:**
1. Settings → Security & Keys → **Boot Status**

**Displays:**
- HAB Enabled status
- Device Closed/Open mode
- Boot Chain status (INTACT/COMPROMISED)
- HAB Events
- Binary Hash
- Trust Chain visualization (6 steps)

---

### 3. `peers` - Network Peers
**File:** `src/app/screens/home/HM03NetworkTopology.tsx`
**Routes:** `/home/topology`, `/settings/topology`

**Navigation:**
1. Home → "View Topology" button, OR
2. Settings → Network → Network Topology

**Displays:**
- Visual network topology
- Peer nodes with status
- Connection lines between peers

---

### 4. `attestation` - Attestation Results
**File:** `src/app/screens/security/SC02AttestationStatus.tsx`
**Routes:** `/settings/attestation`, `/attestation`

**Navigation:**
1. Settings → Security & Keys → **Attestation**

**Displays:**
- Last attestation result banner
- Stats grid (Total, Passed, Failed)
- Attestation history with expandable cards
- Per-peer verification checks (PCR Match, Signature, Policy)
- "Re-attest All Peers" action button

---

### 5. `logs` - System Logs
**File:** `src/app/screens/logs/LG01LogsViewer.tsx`
**Routes:** `/settings/logs`, `/logs`

**Navigation:**
1. Settings → Security & Keys → **Logs**

**Displays:**
- Log entries with expandable details
- Filter by: Node, Log Level, Category
- Search functionality
- Export to file button

---

### 6. `keygen` - Generate Keys
**File:** `src/app/screens/keys/KM01KeyManagement.tsx`
**Routes:** `/settings/keys`, `/keys`

**Navigation:**
1. Settings → Security & Keys → **Key Management**
2. The Keys tab shows key generation options

**Note:** Key generation is typically automatic; UI shows existing keys

---

### 7. `sign` - Sign Policy
**File:** `src/app/screens/policy/PL01PolicyManagement.tsx`
**Routes:** `/settings/policy`, `/policy`

**Navigation:**
1. Settings → Security & Keys → **Policy Management**
2. Select **"Sign"** tab

**Features:**
- Upload policy file
- Select signing key
- Sign action button
- Download signed policy

---

### 8. `verify` - Verify Policy
**File:** `src/app/screens/policy/PL01PolicyManagement.tsx`
**Routes:** `/settings/policy`, `/policy`

**Navigation:**
1. Settings → Security & Keys → **Policy Management**
2. Select **"Policies"** tab
3. Each policy shows verification status

**Displays:**
- Policy list with verification badges
- Envelope version validity
- Digest validity
- Signature validity

---

### 9. `dkp-status` - DKP Key Status
**File:** `src/app/screens/keys/KM01KeyManagement.tsx`
**Routes:** `/settings/keys`, `/keys`

**Navigation:**
1. Settings → Security & Keys → **Key Management**
2. **DKP Status** tab (default tab)

**Displays:**
- Active key summary (Version, Key ID, Algorithm)
- Total key versions count
- SE050 hardware mode indicator
- "Rotate Key" button

---

### 10. `dkp-rotate` - Rotate DKP Key
**File:** `src/app/screens/keys/KM01KeyManagement.tsx`
**Routes:** `/settings/keys`, `/keys`

**Navigation:**
1. Settings → Security & Keys → **Key Management**
2. DKP Status tab → **"Rotate Key"** button
3. Confirm in dialog

**Post-action:**
- Shows daemon restart banner
- Key version increments
- Previous key becomes deprecated

---

### 11. `dkp-revoke` - Revoke DKP Key
**File:** `src/app/screens/keys/KM01KeyManagement.tsx`
**Routes:** `/settings/keys`, `/keys`

**Navigation:**
1. Settings → Security & Keys → **Key Management**
2. Select **"History"** tab
3. Click on a **deprecated** key (not active or already revoked)
4. In the detail panel, click **"Revoke This Key"**
5. Confirm in dialog

**Note:** Only deprecated keys can be revoked. Active keys must be rotated first.

**Displays after revoke:**
- Key status changes to "Revoked"
- Shows revocation reason
- 30-day grace period notice

---

### 12. `emergency-rotate` - Emergency Key Rotation
**File:** `src/app/screens/keys/KM01KeyManagement.tsx`
**Routes:** `/settings/keys`, `/keys`

**Navigation:**
1. Settings → Security & Keys → **Key Management**
2. Select **"Emergency"** tab
3. Click **"Initiate Emergency Rotation"**
4. Confirm in warning dialog

**Rotates all keys:**
- DKP (Device Key Pair)
- Software Attestation Key
- TLS Certificate

**Post-action:**
- Shows daemon restart banner (mandatory)
- Emergency rotation logged

---

### 13. `pcr-status` - PCR Measurements
**File:** `src/app/screens/integrity/IN01IntegrityDashboard.tsx`
**Routes:** `/settings/integrity`, `/integrity`

**Navigation:**
1. Settings → Security & Keys → **Integrity**
2. **PCR Status** tab (default tab)

**Displays:**
- Overall integrity status banner (PASS/FAIL)
- Integrity Status and DKP Version
- Composite Digest (with copy)
- PCR Registers (PCR0-PCR4):
  - PCR0: BIOS/Bootloader
  - PCR1: Firmware/DTB
  - PCR2: Kernel
  - PCR3: RootFS
  - PCR4: Configuration
- Each register expandable to show hash values
- "Verify Against Baseline" button

---

### 14. `pcr-baseline-create` - Create PCR Baseline
**File:** `src/app/screens/integrity/IN01IntegrityDashboard.tsx`
**Routes:** `/settings/integrity`, `/integrity`

**Navigation:**
1. Settings → Security & Keys → **Integrity**
2. Select **"Baseline"** tab
3. Click **"Create Golden Baseline"** (or "Create New Baseline" if one exists)
4. Confirm in dialog

**Displays:**
- Current baseline info (if exists)
- Created date, created by, signed by
- Baseline PCR values
- Composite digest

---

### 15. `pcr-baseline-verify` - Verify Against Baseline
**File:** `src/app/screens/integrity/IN01IntegrityDashboard.tsx`
**Routes:** `/settings/integrity`, `/integrity`

**Navigation:**
1. Settings → Security & Keys → **Integrity**
2. PCR Status tab → **"Verify Against Baseline"** button

**Displays after verification:**
- Toast notification with result
- Per-register MATCH/MISMATCH status
- History tab shows verification record

---

## Direct URL Access

All pages are also accessible via direct URLs:

| Page | Direct URL |
|------|------------|
| Key Management | `/keys` or `/settings/keys` |
| Integrity | `/integrity` or `/settings/integrity` |
| Boot Status | `/boot-status` or `/settings/boot-status` |
| Attestation | `/attestation` or `/settings/attestation` |
| Policy | `/policy` or `/settings/policy` |
| Logs | `/logs` or `/settings/logs` |

---

## Troubleshooting

### Page Not Loading / Showing Error

If you see "Something went wrong" with an error message:
1. Check browser console for detailed error
2. Ensure mock server is running (`npm run server`)
3. Check if API returns expected data structure

### Can't Find Revoke Button

The "Revoke This Key" button only appears for **deprecated** keys:
1. Go to Key Management → History tab
2. Look for keys with "Deprecated" badge (yellow/orange)
3. Click on the key to open detail panel
4. Revoke button will be at the bottom

### Integrity Page Crash Fixed

A bug was fixed where unknown status values caused the page to crash. If you still see issues, ensure you're running the latest frontend code.

---

## Files Reference

| Component | File Path |
|-----------|-----------|
| Key Management | `src/app/screens/keys/KM01KeyManagement.tsx` |
| Integrity Dashboard | `src/app/screens/integrity/IN01IntegrityDashboard.tsx` |
| Boot Status | `src/app/screens/security/SC01BootStatus.tsx` |
| Attestation Status | `src/app/screens/security/SC02AttestationStatus.tsx` |
| Policy Management | `src/app/screens/policy/PL01PolicyManagement.tsx` |
| Logs Viewer | `src/app/screens/logs/LG01LogsViewer.tsx` |
| Guardian Detail | `src/app/screens/home/HM02GuardianDetail.tsx` |
| Network Topology | `src/app/screens/home/HM03NetworkTopology.tsx` |
| Settings Root | `src/app/screens/settings/ST01SettingsRoot.tsx` |
