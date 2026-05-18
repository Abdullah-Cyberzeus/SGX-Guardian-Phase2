# SG-X Guardian REST API Reference with Full Paths and Expected Outputs

**Version:** 2.0   
**Port:** `8443`  
**Base URL:** `http://<board-ip>:8443/api/v1`  
**Example Board IP:** `192.168.1.10`  
**Total APIs:** 23  


---

# 1. API Endpoint Summary

| # | Method | Full Path | Category | Purpose |
|---|--------|-----------|----------|---------|
| 1 | GET | `http://<board-ip>:8443/api/v1/health` | System | API health check |
| 2 | GET | `http://<board-ip>:8443/api/v1/node/status` | Node | Device identity, IP, port, public key |
| 3 | GET | `http://<board-ip>:8443/api/v1/node/boot-status` | Security | HAB status, trust chain, binary hash |
| 4 | POST | `http://<board-ip>:8443/api/v1/node/restart` | Node | Restart Guardian daemon |
| 5 | GET | `http://<board-ip>:8443/api/v1/peers` | Network | Trusted peer list |
| 6 | GET | `http://<board-ip>:8443/api/v1/attestation` | Security | Last attestation result |
| 7 | GET | `http://<board-ip>:8443/api/v1/logs` | Monitoring | Tail logs with filtering |
| 8 | GET | `http://<board-ip>:8443/api/v1/dkp/status` | Keys | DKP version history and SE050 status |
| 9 | POST | `http://<board-ip>:8443/api/v1/dkp/rotate` | Keys | Rotate DKP |
| 10 | POST | `http://<board-ip>:8443/api/v1/dkp/revoke` | Keys | Revoke DKP version |
| 11 | POST | `http://<board-ip>:8443/api/v1/dkp/emergency-rotate` | Keys | Emergency rotate all DKP keys |
| 12 | GET | `http://<board-ip>:8443/api/v1/guardian/key/status` | Keys | Guardian software key status |
| 13 | POST | `http://<board-ip>:8443/api/v1/guardian/key/generate` | Keys | Generate Guardian software key pair |
| 14 | GET | `http://<board-ip>:8443/api/v1/pcr/status` | Integrity | Read PCR measurements |
| 15 | POST | `http://<board-ip>:8443/api/v1/pcr/baseline/create` | Integrity | Create PCR baseline |
| 16 | POST | `http://<board-ip>:8443/api/v1/pcr/baseline/verify` | Integrity | Verify PCR baseline |
| 17 | POST | `http://<board-ip>:8443/api/v1/policy/sign` | Policy | Sign uploaded policy |
| 18 | POST | `http://<board-ip>:8443/api/v1/policy/verify` | Policy | Verify uploaded signed policy |
| 19 | GET | `http://<board-ip>:8443/api/v1/policy/current` | Policy | Get active/current policy |
| 20 | PUT | `http://<board-ip>:8443/api/v1/policy/current` | Policy | Save policy draft |
| 21 | GET | `http://<board-ip>:8443/api/v1/policy/backup` | Policy | Get backup policy |
| 22 | POST | `http://<board-ip>:8443/api/v1/policy/verify-deployed` | Policy | Verify deployed policy |
| 23 | POST | `http://<board-ip>:8443/api/v1/policy/sign-deploy-current` | Policy | Sign and deploy current policy |

---

# 2. Route Aliases

| Method | Full Alias Path | Equivalent Full Path |
|--------|-----------------|----------------------|
| POST | `http://<board-ip>:8443/api/v1/pcr/baseline/update` | `http://<board-ip>:8443/api/v1/pcr/baseline/create` |
| POST | `http://<board-ip>:8443/api/v1/pcr/verify` | `http://<board-ip>:8443/api/v1/pcr/baseline/verify` |
| GET | `http://<board-ip>:8443/api/v1/health` | API health check |

---

# 3. Frontend Base URL

## `.env.local`

```env
VITE_API_URL=http://<board-ip>:8443/api/v1