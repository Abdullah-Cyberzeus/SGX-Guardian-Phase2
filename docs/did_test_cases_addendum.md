# DID Test Cases Addendum (DID-001 to DID-007)

| Test ID | Test Name | Expected Result |
|---|---|---|
| DID-001 | DID generation determinism | Same device generates the same DID after restart/recreate flow. |
| DID-002 | DID persistence across reboot | DID stays unchanged across daemon and host reboot. |
| DID-003 | DID persistence across DKP rotation | DID stays unchanged; only `current_dkp_version` increments. |
| DID-004 | Local DID resolution | `did resolve` returns self status and key; unknown peer DID errors cleanly. |
| DID-005 | DID format compliance | DID matches `^did:guardian:[1-9A-HJ-NP-Za-km-z]{43,44}$`. |
| DID-006 | CRUD lifecycle | Create/resolve/update/deactivate operations behave as specified. |
| DID-007 | Cross-device uniqueness | Different devices produce different DIDs. |
