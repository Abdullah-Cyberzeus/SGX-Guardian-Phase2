# SG-X Guardian — Sprint 6 NMAP Fix — Board Re-Verification Checklist

**Purpose:** Step-by-step copy-paste commands to validate the 9 fixes from `Sprint6_NMAP_FIX_Plan.md` on the actual Variscite VAR-SOM-MX8M-PLUS boards (nodeA `192.168.50.103`, nodeB `192.168.50.115`, nodeC `192.168.50.248`).

**Prereqs**
- Fresh `.deb` from the fix PR is installed on the board (`dpkg -l sgx-guardian` shows the new version)
- Access via AnyDesk OR Minicom serial @ 115200 baud
- `python3` available on the board (default on Yocto)
- `nmap` either installed (apt/dnf/opkg) OR manually placed at `/usr/local/bin/nmap` (the scp-via-laptop method from the prior session is fine)

**Convention**
- `$ cmd` ← run as root on the board
- `→ expected:` ← what you should see
- ❌ ← failure pattern with recovery

**Issue → Section mapping** (so you can jump straight to the one you care about):

| Issue # | Description                              | Verify in section |
| ------- | ---------------------------------------- | ----------------- |
| 1, 9    | std + /24 timeout, std/aggressive broken | B + C             |
| 2       | std + /32 sanity                         | C1                |
| 3       | Whitelist MAC-only                       | D                 |
| 4       | Same MAC across multiple IPs             | E                 |
| 5       | Raw XML auto-write + rotate              | F                 |
| 6       | jq/apt missing on Yocto                  | All sections (Python helpers) + G |
| 7       | YAMLs not auto-generated                 | A                 |
| 8       | Hash chain failed L1/L6                  | H                 |

---

## SECTION A — Auto-seed YAMLs (Issue 7) — 4 steps

### A1. nodeA — Delete both YAMLs, restart daemon, verify they re-appear

```bash
$ rm -f /etc/sgx-guardian/discovery/nmap.yaml \
        /etc/sgx-guardian/discovery/whitelist.yaml
$ ls /etc/sgx-guardian/discovery/ 2>/dev/null
$ systemctl restart sgx-guardian
$ sleep 3
$ ls -la /etc/sgx-guardian/discovery/
```

→ expected: after restart, both files exist, owned by root, content matches the embedded defaults from `scheduler.rs`.

```bash
$ cat /etc/sgx-guardian/discovery/nmap.yaml
$ echo "---"
$ cat /etc/sgx-guardian/discovery/whitelist.yaml
```

→ expected `nmap.yaml`:
```yaml
# /etc/sgx-guardian/discovery/nmap.yaml
# Sprint 6 NMAP integration — off by default. Admin opts in.
enabled: false
target_cidr: null
intensity: standard
schedule: hourly
timeout_secs: 600
exclude: []
```

→ expected `whitelist.yaml`:
```yaml
# /etc/sgx-guardian/discovery/whitelist.yaml
# Sprint 6 NMAP whitelist. Empty by default — admin populates after first scan.
version: "1.0"
devices: []
# Example with strict IP binding ...
```

❌ if files still missing after restart → check `journalctl -u sgx-guardian -n 50 | grep -i discovery` for a path-permission error.

### A2. nodeA — Verify auto-seed does NOT overwrite existing files

```bash
$ # Tag the existing file so we can prove it survives.
$ echo "# CUSTOM-EDIT-TAG-A2" >> /etc/sgx-guardian/discovery/nmap.yaml
$ tail -1 /etc/sgx-guardian/discovery/nmap.yaml
$ systemctl restart sgx-guardian
$ sleep 3
$ tail -1 /etc/sgx-guardian/discovery/nmap.yaml
```

→ expected: same `# CUSTOM-EDIT-TAG-A2` line still present after restart.

❌ if the tag is gone → `seed_if_missing` is overwriting; the fix is buggy. File issue against PR.

### A3. nodeA — Verify scheduler log line confirms discovery system is up

```bash
$ journalctl -u sgx-guardian --since "2 minutes ago" --no-pager | \
    grep -E "Discovery scheduler|seed" | head -5
```

→ expected: a `Discovery scheduler spawned` line (and optionally seed-related debug if RUST_LOG=debug).

### A4. nodeA — Cleanup the test tag

```bash
$ sed -i '/CUSTOM-EDIT-TAG-A2/d' /etc/sgx-guardian/discovery/nmap.yaml
$ tail -3 /etc/sgx-guardian/discovery/nmap.yaml
```

---

## SECTION B — Standard scan on /24 (Issue 1) — 4 steps

This is the headline fix. Pre-fix, `standard + /24` died at the 1800 s timeout. Post-fix it should complete in under 5 minutes.

### B1. nodeA — Enable discovery with explicit standard + /24

```bash
$ cat > /etc/sgx-guardian/discovery/nmap.yaml <<'EOF'
enabled: true
target_cidr: "192.168.50.0/24"
intensity: standard
schedule: hourly
timeout_secs: 600
exclude: []
EOF
$ cat /etc/sgx-guardian/discovery/nmap.yaml
```

→ expected: file replaced exactly as shown. `timeout_secs: 600` is the daemon-side cap; the post-fix bounded args make the actual run finish much faster.

### B2. nodeA — Run standard scan and time it

```bash
$ time sgx-pa-cli discovery scan \
        --target 192.168.50.0/24 \
        --intensity standard
```

→ expected: **completes successfully in 1–5 minutes**. Output shows `Scan complete: N devices` and exits 0.

→ expected `real` time: typical `< 3m00s` on a /24 with ~10 live hosts.

❌ if it dies at `timeout after 600s` → bounded flags not in place. Check the build is actually the fix-PR build:
```bash
$ /usr/local/bin/sgx-guardian --version
$ md5sum /usr/local/bin/sgx-guardian
$ md5sum /usr/local/bin/sgx-pa-cli
```

❌ if it dies at `timeout after 1800s` → you're on the OLD build. Re-deploy the .deb.

### B3. nodeA — Confirm bounded args were actually used

```bash
$ ls -t /var/lib/sgx-guardian/discovery/raw/ | head -1
$ grep -o 'args="[^"]*"' /var/lib/sgx-guardian/discovery/raw/$(ls -t /var/lib/sgx-guardian/discovery/raw/ | head -1)
```

→ expected: `args="..."` string contains ALL of:
- `-sS -O -sV -T3`
- `--top-ports 100` (subnet-adaptive)
- `--version-intensity 2`
- `--max-retries 1`
- `--host-timeout 60s`
- `--max-rate 300`
- `--max-parallelism 64`

❌ if you see `--top-ports 1000` against /24 → the `target_is_subnet()` check isn't firing; bounded path not taken.

### B4. nodeA — Sanity check device count

```bash
$ python3 /usr/local/share/sgx-guardian/scripts/verify_inventory.py \
    /var/lib/sgx-guardian/discovery/inventory.json --count
$ python3 /usr/local/share/sgx-guardian/scripts/verify_inventory.py \
    /var/lib/sgx-guardian/discovery/inventory.json --status unauthorized | wc -l
```

(If the script isn't installed yet, scp it from the repo: `scripts/verify_inventory.py`.)

→ expected: a positive integer count; "unauthorized" list contains the boards (whitelist empty by default).

---

## SECTION C — Single-host + aggressive scans (Issue 2, 9) — 4 steps

### C1. nodeA — Standard scan on /32 keeps high coverage

```bash
$ time sgx-pa-cli discovery scan \
        --target 192.168.50.103/32 \
        --intensity standard
$ grep -o 'args="[^"]*"' /var/lib/sgx-guardian/discovery/raw/$(ls -t /var/lib/sgx-guardian/discovery/raw/ | head -1)
```

→ expected: completes in ~20–60 s. `args=` contains `--top-ports 1000` and `--version-intensity 5` (NOT the subnet-reduced values).

→ This is what the user confirmed already works pre-fix; we're just verifying the bounded path doesn't accidentally over-restrict single-host scans.

### C2. nodeA — Aggressive scan on /32 keeps full vuln NSE

```bash
$ time sgx-pa-cli discovery scan \
        --target 192.168.50.103/32 \
        --intensity aggressive
$ grep -o 'args="[^"]*"' /var/lib/sgx-guardian/discovery/raw/$(ls -t /var/lib/sgx-guardian/discovery/raw/ | head -1)
```

→ expected: completes in 1–5 min (depending on how many open ports). `args=` contains `-p 1-65535` and `--script vuln`.

> ⚠️ Aggressive /32 still pulls the NSE `vuln` script set — if board CPU is at 100% during this, that's expected.

### C3. nodeA — Aggressive scan on /24 falls back to safe profile

```bash
$ time sgx-pa-cli discovery scan \
        --target 192.168.50.0/24 \
        --intensity aggressive
$ grep -o 'args="[^"]*"' /var/lib/sgx-guardian/discovery/raw/$(ls -t /var/lib/sgx-guardian/discovery/raw/ | head -1)
```

→ expected: completes in < 10 min. `args=` contains:
- `-p 1-1024` (NOT `1-65535`)
- `--script default,safe` (NOT `vuln`)
- All the bounding flags from B3

This is the safety fallback that prevents the pre-fix problem ("aggressive /24 never returns").

❌ if you see `-p 1-65535` or `--script vuln` here → adaptive sizing in `nmap_args` isn't checking target correctly.

### C4. nodeA — Restore standard config for following sections

```bash
$ sed -i 's/^intensity:.*/intensity: standard/' /etc/sgx-guardian/discovery/nmap.yaml
$ grep intensity /etc/sgx-guardian/discovery/nmap.yaml
```

---

## SECTION D — Whitelist IP binding (Issue 3) — 5 steps

### D1. nodeA — Capture the real MAC of nodeA from the latest inventory

```bash
$ python3 /usr/local/share/sgx-guardian/scripts/verify_inventory.py \
    /var/lib/sgx-guardian/discovery/inventory.json --ip 192.168.50.103
```

→ expected: one line of JSON with a real MAC for nodeA. Note that MAC.

### D2. nodeA — Write a whitelist entry that BINDS the MAC to ONLY .103/32

Replace `XX:XX:XX:XX:XX:XX` with the MAC from D1.

```bash
$ cat > /etc/sgx-guardian/discovery/whitelist.yaml <<'EOF'
version: "1.0"
devices:
  - mac: "XX:XX:XX:XX:XX:XX"
    label: "Guardian nodeA — strict IP binding"
    expected_os: "Linux"
    expected_ports: [8443]
    expected_ips: ["192.168.50.103/32"]
EOF
$ cat /etc/sgx-guardian/discovery/whitelist.yaml
```

→ expected: file written exactly as shown.

### D3. nodeA — Re-scan and verify .103 is Approved, others Unauthorized

```bash
$ sgx-pa-cli discovery scan --target 192.168.50.0/24 --intensity standard
$ python3 /usr/local/share/sgx-guardian/scripts/verify_inventory.py \
    /var/lib/sgx-guardian/discovery/inventory.json \
    --ip 192.168.50.103
```

→ expected: the .103 entry has `"status": "approved"`.

```bash
$ python3 /usr/local/share/sgx-guardian/scripts/verify_inventory.py \
    /var/lib/sgx-guardian/discovery/inventory.json --unauthorized
```

→ expected: every other IP in the inventory still shows `unauthorized` (whitelisted MAC alone is no longer enough).

❌ if any random IP shows `approved` because it happens to share that MAC → IP-binding fix didn't take. Check `git log -p src/discovery/whitelist.rs` on the deployed source to confirm the new `classify` body is there.

### D4. nodeA — Verify backward compat (no expected_ips → old behaviour)

```bash
$ cat > /etc/sgx-guardian/discovery/whitelist.yaml <<'EOF'
version: "1.0"
devices:
  - mac: "XX:XX:XX:XX:XX:XX"
    label: "Backward-compat test — MAC-only"
EOF
$ # ↑ replace XX with the same MAC from D1
$ sgx-pa-cli discovery scan --target 192.168.50.0/24 --intensity standard
$ python3 /usr/local/share/sgx-guardian/scripts/verify_inventory.py \
    /var/lib/sgx-guardian/discovery/inventory.json --status approved | wc -l
```

→ expected: ≥ 1 approval (MAC-only match works). Verifies the empty `expected_ips` branch.

### D5. nodeA — Restore the strict whitelist (recommended baseline)

```bash
$ cat > /etc/sgx-guardian/discovery/whitelist.yaml <<'EOF'
version: "1.0"
devices:
  - mac: "XX:XX:XX:XX:XX:XX"   # nodeA MAC
    label: "Guardian nodeA"
    expected_os: "Linux"
    expected_ips: ["192.168.50.103/32"]
EOF
$ # Repeat for nodeB / nodeC MACs if known
```

---

## SECTION E — MAC aliasing dedup in parser (Issue 4) — 3 steps

### E1. nodeA — Run a scan that crosses subnet boundary (forces gateway MAC aliasing)

If you only have the /24 to work with:

```bash
$ sgx-pa-cli discovery scan --target 192.168.50.0/24 --intensity standard
```

Or if you have access to a routed prefix (e.g. via the overlay):

```bash
$ sgx-pa-cli discovery scan --target 192.168.100.0/24 --intensity stealth
```

### E2. nodeA — Run the duplicate-MAC checker

```bash
$ python3 /usr/local/share/sgx-guardian/scripts/verify_inventory.py \
    /var/lib/sgx-guardian/discovery/inventory.json \
    --duplicate-macs
```

→ expected (post-fix):
```
OK: no duplicate MACs in inventory.
```

❌ (pre-fix, would have been):
```
FAIL: 1 MAC(s) appear on multiple IPs:
  B2:95:75:0E:06:6A → ['192.168.50.45', '192.168.50.102', '192.168.50.156']
```

If you see the FAIL output → parser dedup didn't take effect; check the build.

### E3. nodeA — Confirm the aliased entries got the diagnostic stamp

```bash
$ python3 -c "
import json
data = json.load(open('/var/lib/sgx-guardian/discovery/inventory.json'))
aliased = [d for d in data if d.get('vendor', '').startswith('(mac_aliased')]
print(f'Aliased entries: {len(aliased)}')
for d in aliased:
    print(f'  ip={d[\"ip\"]}  mac={d.get(\"mac\")}  vendor={d.get(\"vendor\")}')"
```

→ expected: every device whose MAC was demoted shows `mac: null` and `vendor: "(mac_aliased to <MAC>)"`. That's the audit trail telling you why the MAC was stripped.

---

## SECTION F — Raw XML auto-write & rotation (Issue 5) — 4 steps

### F1. nodeA — Confirm raw XML now appears automatically

```bash
$ rm -rf /var/lib/sgx-guardian/discovery/raw/
$ sgx-pa-cli discovery scan --target 192.168.50.103/32 --intensity stealth
$ ls -la /var/lib/sgx-guardian/discovery/raw/
```

→ expected: directory exists, one `<unix_timestamp>.xml` file present. **No manual workaround needed** — this is the fix.

❌ if the directory is still empty → `raw_store::persist` not being called. Check `journalctl -u sgx-guardian | grep raw_store`.

### F2. nodeA — Inspect the XML structure

```bash
$ XML=/var/lib/sgx-guardian/discovery/raw/$(ls -t /var/lib/sgx-guardian/discovery/raw/ | head -1)
$ head -3 "$XML"
$ wc -l "$XML"
```

→ expected: valid NMAP XML with `<?xml version="1.0" ...>` header.

### F3. nodeA — Verify rotation keeps only 10

```bash
$ # Trigger 12 scans
$ for i in $(seq 1 12); do
    echo "scan $i/12"
    sgx-pa-cli discovery scan --target 192.168.50.103/32 --intensity stealth >/dev/null
    sleep 1
  done
$ ls /var/lib/sgx-guardian/discovery/raw/ | wc -l
```

→ expected: exactly `10` (or ≤10). The two oldest were pruned automatically.

❌ if > 10 → rotation logic broken or `KEEP_LAST_N` not respected.

### F4. nodeA — Verify CLI path also writes raw XML

```bash
$ rm -rf /var/lib/sgx-guardian/discovery/raw/
$ # Trigger scan via CLI (not scheduler)
$ sgx-pa-cli discovery scan --target 192.168.50.103/32 --intensity stealth
$ ls /var/lib/sgx-guardian/discovery/raw/
```

→ expected: one XML file. Both daemon-scheduler and CLI invocations persist raw XML now.

---

## SECTION G — Python helpers + install.sh compatibility (Issue 6) — 3 steps

### G1. nodeA — Verify Python helpers are deployed and runnable

```bash
$ ls -l /usr/local/share/sgx-guardian/scripts/verify_inventory.py \
        /usr/local/share/sgx-guardian/scripts/verify_audit_chain.py
$ python3 /usr/local/share/sgx-guardian/scripts/verify_inventory.py --help
$ python3 /usr/local/share/sgx-guardian/scripts/verify_audit_chain.py 2>&1 | head -1
```

→ expected: both scripts present (`-rwxr-xr-x` ideally), `--help` renders for `verify_inventory.py`, the chain script prints its usage on no-args.

❌ if scripts missing → manually scp from repo:
```bash
$ scp -3 root@<laptop>:/path/to/repo/scripts/verify_*.py \
        root@192.168.50.103:/usr/local/share/sgx-guardian/scripts/
$ chmod +x /usr/local/share/sgx-guardian/scripts/verify_*.py
```

### G2. nodeA — Re-run install.sh on a Yocto board without apt/dnf

```bash
$ command -v apt-get
$ command -v dnf
$ command -v opkg
$ bash /usr/local/share/sgx-guardian/scripts/install.sh 2>&1 | tail -10
```

→ expected: either the appropriate package manager fires, OR the "skip-clean" warning appears with explicit instructions for manual install. Either way, **exit code 0**.

❌ if exit code != 0 → install.sh still hard-failing on missing apt. Check the package-detection block is present.

### G3. nodeA — Verify nmap is on PATH after install attempt (whatever the route)

```bash
$ which nmap
$ nmap --version | head -1
$ getcap "$(which nmap)"
```

→ expected: nmap on PATH (either `/usr/bin/nmap` from package manager or `/usr/local/bin/nmap` from the manual scp), version is 7.x or newer, capabilities include `cap_net_raw,cap_net_admin`.

---

## SECTION H — Audit chain segment verification (Issue 8) — 5 steps

This is the trickiest fix because it touches the audit subsystem. We test in three layers: file path, segment awareness, and tamper detection.

### H1. nodeA — Confirm main.rs is now verifying the right file

```bash
$ ls -la /var/log/sgx-guardian/
$ # On post-fix build, the per-node file (audit-nodeA.log) is what main.rs verifies:
$ systemctl restart sgx-guardian
$ sleep 3
$ journalctl -u sgx-guardian --since "1 minute ago" --no-pager | \
    grep -E "audit|AUDIT|verify" | head -5
```

→ expected: log mentions `audit-nodeA.log` (the per-node file), NOT just `audit.log`. The audit init message should reference the correct file.

❌ if you still see verification against `audit.log` → main.rs path fix didn't deploy.

### H2. nodeA — Run the segment-aware Python verifier

```bash
$ python3 /usr/local/share/sgx-guardian/scripts/verify_audit_chain.py \
        /var/log/sgx-guardian/audit-nodeA.log
```

→ expected:
```
SEGMENT_CHAIN_OK lines=NNN segments=M
```
where `NNN` is the total lines and `M` is the number of segments (typically 1 per daemon-run-since-rotation, so on a board that's been restarted 5 times = 5 segments).

This is the **single command** that proves the fix works.

❌ if you see `FAIL: tamper at line X` → write down the line number, then run H3 to inspect what happened around there.

### H3. nodeA — If H2 fails, inspect the suspect line

```bash
$ # Replace N with the line number from H2's FAIL output
$ sed -n 'N,Np' /var/log/sgx-guardian/audit-nodeA.log | python3 -m json.tool
```

→ this gives you the structured view of what's at that line, so you can tell whether it's a parse problem, a missing field, or a genuine hash mismatch.

If the line's `previous_hash` field is missing entirely → the writer wrote a malformed line (most likely from a pre-fix daemon crash mid-write). The post-fix writer with `sync_all` prevents this for future entries.

### H4. nodeA — Generate a multi-segment log by restarting the daemon a few times

```bash
$ for i in 1 2 3; do
    systemctl restart sgx-guardian
    sleep 2
    sgx-pa-cli discovery scan --target 192.168.50.103/32 --intensity stealth >/dev/null
  done
$ python3 /usr/local/share/sgx-guardian/scripts/verify_audit_chain.py \
        /var/log/sgx-guardian/audit-nodeA.log
```

→ expected: `SEGMENT_CHAIN_OK` with `segments=` higher than before. Each restart created at least one new entry; the segment count tracks chain re-anchors.

### H5. nodeA — Tamper test: corrupt one line, confirm the verifier catches it

```bash
$ cp /var/log/sgx-guardian/audit-nodeA.log /tmp/audit-nodeA.log.backup
$ # Modify the `message` field of line 3 (or any line) by sed-replacing one character in the JSON
$ sed -i '3 s/"message":"/"message":"X/' /var/log/sgx-guardian/audit-nodeA.log
$ python3 /usr/local/share/sgx-guardian/scripts/verify_audit_chain.py \
        /var/log/sgx-guardian/audit-nodeA.log
$ # Restore
$ cp /tmp/audit-nodeA.log.backup /var/log/sgx-guardian/audit-nodeA.log
$ rm /tmp/audit-nodeA.log.backup
```

→ expected:
```
FAIL: tamper at line 3 (segment started at line 1)
```

This proves the verifier still detects **real** tampering within a segment — only legitimate segment boundaries are tolerated.

❌ if H5 reports OK on a tampered file → the verifier is too lenient and the fix is buggy.

---

## SECTION I — End-to-end smoke (all fixes together) — 2 steps

After Sections A–H pass, this single combined run is the "milestone-ready" demo.

### I1. nodeA — Full clean cycle

```bash
$ rm -rf /var/lib/sgx-guardian/discovery/raw/ \
         /var/lib/sgx-guardian/discovery/inventory.json
$ rm -f /etc/sgx-guardian/discovery/nmap.yaml \
        /etc/sgx-guardian/discovery/whitelist.yaml
$ systemctl restart sgx-guardian
$ sleep 5
$ # Files re-seeded (Fix #7)
$ ls /etc/sgx-guardian/discovery/

$ # Enable + scan + verify all in one
$ cat > /etc/sgx-guardian/discovery/nmap.yaml <<'EOF'
enabled: true
target_cidr: "192.168.50.0/24"
intensity: standard
schedule: hourly
timeout_secs: 600
exclude: []
EOF

$ time sgx-pa-cli discovery scan --target 192.168.50.0/24 --intensity standard

$ # Verify all the post-conditions
$ python3 /usr/local/share/sgx-guardian/scripts/verify_inventory.py \
        /var/lib/sgx-guardian/discovery/inventory.json --duplicate-macs
$ ls /var/lib/sgx-guardian/discovery/raw/ | wc -l
$ python3 /usr/local/share/sgx-guardian/scripts/verify_audit_chain.py \
        /var/log/sgx-guardian/audit-nodeA.log
```

→ expected:
1. Scan completes in < 5 min
2. `OK: no duplicate MACs in inventory.`
3. ≥ 1 raw XML file present
4. `SEGMENT_CHAIN_OK lines=... segments=...`

### I2. nodeA — Aggressive /24 (proves it actually finishes now)

```bash
$ time sgx-pa-cli discovery scan --target 192.168.50.0/24 --intensity aggressive
$ python3 /usr/local/share/sgx-guardian/scripts/verify_inventory.py \
        /var/lib/sgx-guardian/discovery/inventory.json --count
```

→ expected: completes in < 10 min, device count populated.

---

## SECTION J — Multi-node verification (3 steps)

Replicate the critical fixes on nodeB and nodeC to prove cluster consistency.

### J1. nodeB — Run Section A1 + B2 + H2 against nodeB

```bash
$ # On nodeB
$ rm -f /etc/sgx-guardian/discovery/{nmap,whitelist}.yaml
$ systemctl restart sgx-guardian
$ sleep 3
$ ls /etc/sgx-guardian/discovery/   # auto-seed works
$ sed -i 's/^enabled:.*/enabled: true/' /etc/sgx-guardian/discovery/nmap.yaml
$ time sgx-pa-cli discovery scan --target 192.168.50.0/24 --intensity standard
$ python3 /usr/local/share/sgx-guardian/scripts/verify_audit_chain.py \
        /var/log/sgx-guardian/audit-nodeB.log
```

→ expected: same outcomes as on nodeA — fast scan, valid chain.

### J2. nodeC — Same against nodeC (use the scp'd nmap from prior session if needed)

```bash
$ # On nodeC
$ which nmap   # should resolve to /usr/local/bin/nmap from the scp workaround
$ rm -f /etc/sgx-guardian/discovery/{nmap,whitelist}.yaml
$ systemctl restart sgx-guardian
$ sleep 3
$ sed -i 's/^enabled:.*/enabled: true/' /etc/sgx-guardian/discovery/nmap.yaml
$ time sgx-pa-cli discovery scan --target 192.168.50.0/24 --intensity standard
$ python3 /usr/local/share/sgx-guardian/scripts/verify_audit_chain.py \
        /var/log/sgx-guardian/audit-nodeC.log
```

### J3. Laptop — Cross-node consistency check

```powershell
# From PowerShell laptop
$ for ip in 192.168.50.103 192.168.50.115 192.168.50.248:
    python3 -c "
import json, urllib.request
r = urllib.request.urlopen(f'http://$ip:8443/api/v1/discovery/devices', timeout=10)
data = json.load(r)
print(f'{ip}: {len(data)} devices, {sum(1 for d in data if d.get(\"status\")==\"unauthorized\")} unauthorized')
"
```

→ expected: each node's inventory has similar device counts and similar unauthorized counts (assuming the same whitelist is deployed to all three).

---

## SECTION K — Quick pass/fail table

Fill this in as you complete each section. Any FAIL row blocks the fix-PR merge.

| Section | Fix # | Pass/Fail | Notes |
| ------- | ----- | --------- | ----- |
| A. Auto-seed YAMLs (issue 7) | 7 | | |
| B. Standard /24 timing (issue 1) | 1, 9 | | |
| C. Single-host + aggressive (issues 2, 9) | 2, 9 | | |
| D. Whitelist IP binding (issue 3) | 3 | | |
| E. Parser MAC dedup (issue 4) | 4 | | |
| F. Raw XML write + rotate (issue 5) | 5 | | |
| G. Python helpers + install.sh (issue 6) | 6 | | |
| H. Audit chain segment-aware (issue 8) | 8 | | |
| I. End-to-end smoke | all | | |
| J. Multi-node | all | | |

---

## Maps to test cases

| NMP-FIX test ID | Covered by sections |
| --------------- | ------------------- |
| NMP-FIX-001 — Bounded args for standard subnet | B2, B3 |
| NMP-FIX-002 — Single-host standard keeps top-1000 | C1 |
| NMP-FIX-003 — Aggressive on /24 falls back safe | C3 |
| NMP-FIX-004 — Aggressive on /32 keeps full vuln | C2 |
| NMP-FIX-005 — Whitelist strict IP binding | D2, D3 |
| NMP-FIX-006 — Whitelist backward compat | D4 |
| NMP-FIX-007 — Parser strips aliased MACs | E2, E3 |
| NMP-FIX-008 — Audit verifier multi-segment | H2, H4 |
| NMP-FIX-009 — Raw XML rotated to last 10 | F3 |
| NMP-FIX-010 — YAMLs auto-seeded on first start | A1 |
| NMP-FIX-011 — Install.sh works without apt | G2 |
| NMP-FIX-012 — Audit fsync survives mid-write kill | (manual; kill -9 + restart, then H2) |

---

**Estimated time:** ~35 minutes per board for Sections A–H once familiar; ~75 min first time. Multiply by 3 for the cluster (or run in parallel tabs). Sections I–J add ~15 min for the smoke + multi-node sweep.

If anything in Sections A–H is RED on the first board, **fix the code first** before proceeding to multi-node — replicating a broken state across the cluster wastes time.
