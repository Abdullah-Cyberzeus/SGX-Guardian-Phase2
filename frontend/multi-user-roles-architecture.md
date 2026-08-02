# **SG-X Device**

# **Flow Summary**

| Attribute | Detail |
| ----- | ----- |
| **Flow Name** | Device Discovery \+ Add |
| **Primary Persona** | Marcus Webb — Field Security Engineer |
| **Trigger** | New device detected on network OR Marcus needs to manually register a known device |
| **Goal** | Discover or manually register a device, approve it for Guardian monitoring, optionally run a security scan |
| **Entry Point** | Bottom nav → Devices tab |
| **Exit Points** | Device approved \+ monitored / Device rejected / Scan results reviewed |
| **Screens Involved** | DV-01, DV-02, DV-03, DV-04, DV-05, DV-06, DV-07, DV-08, DV-09, DV-10 |
| **Estimated Completion Time** | 1–2 minutes (auto-discovery) / 2–4 minutes (manual add) |
| **Complexity** | Medium — two add paths, pending approval state, optional security scan |
| **Frequency** | Weekly for Marcus — when new equipment is deployed at a site |

---

## **Happy Path — Mermaid Diagram**

Scan Network → Device discovered → Approve → Run scan → Review results

flowchart TD
 A(\[Marcus opens Devices tab\]) \--\> B\[DV-01 Devices List\\nAll Devices tab\]
 B \--\> C\[Tap Scan Network\]
 C \--\> D\[ POST /api/devices/scan\\nNetwork scan initiated\]
 D \--\> E\[Loading state\\nScanning network...\\nprogress animation\]
 E \--\> F\[ Scan complete\\nNew device found: WORKSTATION-07\]
 F \--\> G\[DV-02 Pending Tab\\nDevice appears in pending list\]
 G \--\> H\[Marcus taps device\\nPending Approval Detail\]
 H \--\> I\[Reviews device info:\\nMAC address \+ IP \+ device type detected\]
 I \--\> J\[Tap Approve\]
 J \--\> K\[ PATCH /api/devices/id\\nstatus: approved\]
 K \--\> L\[ Toast: Device approved\\nDevice moved to All Devices\]
 L \--\> M\[DV-03 Device Detail\\nSecurity \+ Privacy scores shown\]
 M \--\> N\[Tap Run Security Scan\]
 N \--\> O\[DV-06 Scan In Progress\\nScanning WORKSTATION-07...\]
 O \--\> P\[ DV-07 Scan Results\\n2 vulnerabilities found\]
 P \--\> Q(\[Marcus reviews\\nremediation recommendations\])

---

## **Full Flow With All Branches**

flowchart TD
 START(\[Marcus opens Devices tab\]) \--\> DV01\[DV-01 Devices List\\nAll Devices tab\]

 DV01 \--\> TABS{Filter tabs}
 TABS \-- All \--\> ALL\[All approved devices list\]
 TABS \-- Regular \--\> REG\[Regular devices only\]
 TABS \-- Drones \--\> DRN\[Drone devices only\]
 TABS \-- Smart Home \--\> SH\[Smart Home devices only\]
 TABS \-- Pending \--\> PEND\[DV-02 Pending approvals\\nwith badge count\]
 TABS \-- Service Access \--\> SVCACC\[Service access management\]

 DV01 \--\> ADD\_METHOD{How to add device?}

 %% Auto Discovery Path
 ADD\_METHOD \-- Scan Network \--\> SCAN\_BTN\[Tap Scan Network button\]
 SCAN\_BTN \--\> SCAN\_API\[ POST /api/devices/scan\\nGuardian scans local network\]
 SCAN\_API \--\> SCAN\_STATE\[Loading state\\nScanning network...\\nanimated progress\]
 SCAN\_STATE \--\> SCAN\_RESULT{Scan result}
 SCAN\_RESULT \-- New devices found \--\> PEND\_UPDATE\[DV-02 Pending tab updated\\nbadge count incremented\]
 SCAN\_RESULT \-- No new devices \--\> TOAST\_NONE\[Toast: No new devices found\\nAll devices already registered\]
 SCAN\_RESULT \-- Scan error \--\> SCAN\_ERR\[ Error: Scan failed\\nGuardian may be offline\\nRetry button\]
 TOAST\_NONE \--\> DV01
 SCAN\_ERR \--\> DV01

 %% Pending Approval Flow
 PEND\_UPDATE \--\> PEND\[DV-02 Pending Tab\]
 PEND \--\> PEND\_ITEM\[Marcus taps a pending device\]
 PEND\_ITEM \--\> PEND\_DETAIL\[Pending Device Detail\\nMAC \+ IP \+ detected device type\\nFirst seen timestamp\]
 PEND\_DETAIL \--\> PEND\_ACTION{Action}
 PEND\_ACTION \-- Approve \--\> APPROVE\[ PATCH /api/devices/id\\nstatus: approved\]
 PEND\_ACTION \-- Reject \--\> REJECT\[ PATCH /api/devices/id\\nstatus: rejected\]
 PEND\_ACTION \-- Ignore for now \--\> PEND

 APPROVE \--\> APPROVE\_RESULT{Result}
 APPROVE\_RESULT \-- Success \--\> TOAST\_APPROVE\[ Toast: Device approved\\nand added to monitoring\]
 APPROVE\_RESULT \-- Error \--\> ERR\_APPROVE\[ Error toast \+ retry\]
 TOAST\_APPROVE \--\> DV03\[DV-03 Device Detail\\nInfo tab\]

 REJECT \--\> REJECT\_CONFIRM\[Confirmation sheet\\nReject this device?\\nIt will be blocked from Guardian monitoring\]
 REJECT\_CONFIRM \--\> REJECT\_CONFIRM\_ACTION{Confirm?}
 REJECT\_CONFIRM\_ACTION \-- Confirm \--\> REJECT\_API\[ Status updated to rejected\]
 REJECT\_CONFIRM\_ACTION \-- Cancel \--\> PEND\_DETAIL
 REJECT\_API \--\> PEND

 %% Manual Add Path
 ADD\_METHOD \-- Add Manually \--\> DV10\[DV-10 Add Device Form\\nBottom sheet modal\]
 DV10 \--\> FORM\[Fill in:\\nDevice Name required\\nDevice Type dropdown\\nConnection Method dropdown\\nMAC Address required\\nIP Address optional\\nManufacturer optional\\nModel optional\\nOS optional\]
 FORM \--\> VALIDATE{Form valid?}
 VALIDATE \-- Name or MAC empty \--\> FORM\_ERR\[ Inline validation errors\]
 FORM\_ERR \--\> FORM
 VALIDATE \-- Valid \--\> MANUAL\_API\[ POST /api/devices\\nDevice registered manually\]
 MANUAL\_API \--\> MANUAL\_RESULT{Result}
 MANUAL\_RESULT \-- Success \--\> TOAST\_MANUAL\[ Toast: Device added\]
 MANUAL\_RESULT \-- MAC already exists \--\> DUP\_ERR\[ A device with this MAC\\naddress already exists\]
 MANUAL\_RESULT \-- Error \--\> ERR\_MANUAL\[ Error toast \+ retry\]
 DUP\_ERR \--\> FORM
 TOAST\_MANUAL \--\> DV03

 %% Device Detail Flow
 DV03 \--\> DV03\_TABS{Device detail view}
 DV03\_TABS \-- Info tab \--\> DV03\_INFO\[Security Score \+ Privacy Score\\nVuln Count cards\\nDevice information table\\nGuardian Monitoring toggle\]
 DV03\_TABS \-- Security Features tab \--\> DV04\[DV-04 Security Features\\nEncryption \+ Auto-update \+ Connectivity\\nVulnerability panel with recommendations\]
 DV03\_TABS \-- Actions tab \--\> DV05\[DV-05 Actions\\nRun Security Scan\\nBlock from Network\\nRemove Device\]

 %% Security Scan
 DV05 \--\> SCAN\_ACTION{Action chosen}
 SCAN\_ACTION \-- Run Security Scan \--\> DV06\[DV-06 Scan In Progress\\nScanning device name...\\nprogress bar\]
 DV06 \--\> SCAN\_POLL\[ Poll GET /api/devices/id/scan/latest\\nevery 2 seconds\]
 SCAN\_POLL \--\> SCAN\_DONE{Scan complete?}
 SCAN\_DONE \-- In progress \--\> SCAN\_POLL
 SCAN\_DONE \-- Complete \--\> DV07\[DV-07 Scan Results\\nVulnerability count\\nSeverity breakdown\\nRecommendations list\]
 SCAN\_DONE \-- Error \--\> SCAN\_ERR2\[ Scan failed\\nRetry button\]
 DV07 \--\> POST\_SCAN{Next action}
 POST\_SCAN \-- View recommendations \--\> DV04
 POST\_SCAN \-- Alert was created \--\> AL06\[AL-06 Alert Detail\\ncross-section link\]
 POST\_SCAN \-- Done \--\> DV03

 %% Block Device
 SCAN\_ACTION \-- Block from Network \--\> DV08\[DV-08 Block Confirmation\\nAre you sure?\\nDevice will lose network access\]
 DV08 \--\> BLOCK\_CONFIRM{Confirm?}
 BLOCK\_CONFIRM \-- Confirm \--\> BLOCK\_API\[ POST /api/devices/id/block\]
 BLOCK\_CONFIRM \-- Cancel \--\> DV05
 BLOCK\_API \--\> BLOCK\_RESULT{Result}
 BLOCK\_RESULT \-- Success \--\> TOAST\_BLOCK\[ Toast: Device blocked\\nfrom network\]
 BLOCK\_RESULT \-- Error \--\> ERR\_BLOCK\[ Error toast \+ retry\]
 TOAST\_BLOCK \--\> DV01

 %% Remove Device
 SCAN\_ACTION \-- Remove Device \--\> DV09\[DV-09 Remove Confirmation\\nRemove device from Guardian?\\nThis cannot be undone\]
 DV09 \--\> REMOVE\_CONFIRM{Confirm?}
 REMOVE\_CONFIRM \-- Confirm \--\> REMOVE\_API\[ DELETE /api/devices/id\]
 REMOVE\_CONFIRM \-- Cancel \--\> DV05
 REMOVE\_API \--\> REMOVE\_RESULT{Result}
 REMOVE\_RESULT \-- Success \--\> TOAST\_REMOVE\[ Toast: Device removed\]
 REMOVE\_RESULT \-- Error \--\> ERR\_REMOVE\[ Error toast \+ retry\]
 TOAST\_REMOVE \--\> DV01

 %% Guardian Monitoring Toggle
 DV03\_INFO \--\> MONITOR\_TOGGLE{Guardian Monitoring toggle}
 MONITOR\_TOGGLE \-- Turn off \--\> MONITOR\_WARN\[Warning: This device will no\\nlonger be protected by Guardian.\\nAre you sure?\]
 MONITOR\_WARN \-- Confirm \--\> MONITOR\_OFF\[ PATCH /api/devices/id\\nmonitoring: false\]
 MONITOR\_WARN \-- Cancel \--\> DV03\_INFO
 MONITOR\_OFF \--\> TOAST\_MONITOR\[Toast: Guardian monitoring disabled\]

---

## **Step-by-Step Narrative**

### **Step 1 — Devices List (DV-01)**

Marcus taps **Devices** in the bottom nav. He sees the Devices list with filter tabs at the top: All / Regular / Drones / Smart Home / Pending / Service Access.

If any devices are awaiting approval, the **Pending** tab shows a badge count (e.g., `Pending (3)`).

Two action buttons are prominent: **Scan Network** (purple, left) and **\+ Add Manually** (blue, right).

At the top of the screen, a card shows his Guardian device — name, online status, and location. This is a constant anchor point so Marcus always knows which Guardian he's managing.

---

### **Step 2a — Auto Discovery: Scan Network**

Marcus taps **Scan Network**. The Guardian device begins scanning the local network for connected devices.

A loading overlay or bottom sheet shows:

 Scanning network...
Searching for devices on 192.168.1.0/24
Found: 3 devices (checking each...)

This progress display is critical — Marcus needs to know the scan is actively working, not frozen.

**System action:** `POST /api/devices/scan` → Guardian performs mDNS \+ ARP discovery → returns list of discovered devices with MAC, IP, and detected device type.

When the scan completes, a summary toast shows: *"Scan complete — 2 new devices found."* The Pending tab badge updates automatically.

---

### **Step 2b — Manual Add: Add Device Form (DV-10)**

If Marcus knows exactly what device he needs to add (e.g., a new PLC with a known MAC address), he taps **\+ Add Manually**.

A bottom sheet modal slides up with a form:

| Field | Required | Input Type |
| ----- | ----- | ----- |
| Device Name | Yes | Text |
| Device Type | Yes | Dropdown: Phone / Computer / IoT / Camera / Switch / Router / Drone / Other |
| Connection Method | Yes | Dropdown: WiFi / Ethernet / Bluetooth / Cellular / Zigbee / Z-Wave |
| MAC Address | Yes | Text (validated format: XX:XX:XX:XX:XX:XX) |
| IP Address | No | Text (optional) |
| Manufacturer | No | Text (optional) |
| Model | No | Text (optional) |
| Operating System | No | Text (optional) |

The **Add Device** CTA button is at the bottom. **Cancel** closes the modal.

**Design note:** MAC Address validation must happen inline as Marcus types — show format hint `00:1A:2B:3C:4D:5E` in the placeholder. If the format is wrong, show the error before he taps Add Device.

---

### **Step 3 — Pending Approval (DV-02)**

Marcus navigates to the **Pending** tab. Each pending device is listed with:

* Detected device name or MAC address
* IP address
* Detected device type (if identifiable)
* First seen timestamp

He taps a device to see its full detail before deciding to approve or reject.

**Approve** moves the device to the All Devices list and starts Guardian monitoring.

**Reject** removes it from the Pending list and blocks it from appearing again unless it's re-discovered and explicitly approved. A confirmation sheet explains this consequence.

**Design note:** Both Approve and Reject should be visible on the pending device card without needing to tap into detail — swipe right to approve, swipe left to reject as a gesture shortcut. This is much faster for Marcus when clearing a batch of pending devices.

---

### **Step 4 — Device Detail (DV-03, DV-04, DV-05)**

After approval, Marcus lands on the Device Detail screen. Three views are accessible (tabs or swipe):

**Info Tab (DV-03):** Three score cards at the top:

* Security: `71/100` — amber
* Privacy: `64/100` — amber
* Vulnerabilities: `2` — red

Below: a clean table of device information — Manufacturer, Model, Protocol, MAC, IP, Firmware Version.

At the bottom: **Guardian Monitoring** toggle (default ON — green).

**Security Features Tab (DV-04):** Shows Encryption (Disabled/Enabled), Auto-Update (Disabled/Enabled), Connectivity type. If vulnerabilities were found, a red panel shows the count and bullet-point recommendations.

**Actions Tab / Buttons (DV-05):** Three action buttons:

* **Run Security Scan** — blue, runs a fresh scan on this device
* **Block from Network** — amber, isolates the device
* **Remove Device** — red, removes from Guardian permanently

---

### **Step 5 — Security Scan (DV-06, DV-07)**

Marcus taps **Run Security Scan**. A full-screen loading state shows:

 Scanning WORKSTATION-07
Checking firmware version...
Checking open ports...
Checking encryption status...
Checking known vulnerabilities...

When complete, Marcus sees the scan results (DV-07):

Scan Complete — WORKSTATION-07
2 Vulnerabilities Detected

 HIGH — Firmware out of date (v5.9 → v6.2 available)
 MEDIUM — Unencrypted traffic detected on port 8080

Recommendations:
• Update firmware to latest version
• Enable encryption for all services
• Change default passwords
• Disable unnecessary services

A **link to any alerts generated** by the scan appears at the bottom, cross-linking to the Alerts section.

---

## **Screen List**

| Step | Screen ID | Screen Name |
| ----- | ----- | ----- |
| 1 | DV-01 | Devices List — All |
| 2a | DV-01 | Scan Network loading state |
| 2b | DV-10 | Add Device Form |
| 3 | DV-02 | Pending Approvals |
| 4a | DV-03 | Device Detail — Info |
| 4b | DV-04 | Device Detail — Security Features |
| 4c | DV-05 | Device Detail — Actions |
| 5a | DV-06 | Security Scan In Progress |
| 5b | DV-07 | Scan Results |
| 6 | DV-08 | Block Device Confirmation |
| 7 | DV-09 | Remove Device Confirmation |

---

## **API / System Dependencies**

| Action | API Call | Failure Handling |
| ----- | ----- | ----- |
| Load devices | `GET /api/devices` | Stale cache \+ offline banner |
| Scan network | `POST /api/devices/scan` | Error toast \+ retry |
| Approve device | `PATCH /api/devices/:id` `{ status: "approved" }` | Error toast \+ retry |
| Reject device | `PATCH /api/devices/:id` `{ status: "rejected" }` | Error toast \+ retry |
| Add manually | `POST /api/devices` | Inline validation \+ error toast |
| Run scan | `POST /api/devices/:id/scan` | Error toast \+ retry |
| Poll scan status | `GET /api/devices/:id/scan/latest` | Timeout after 60s |
| Block device | `POST /api/devices/:id/block` | Confirmation \+ error toast |
| Remove device | `DELETE /api/devices/:id` | Confirmation \+ error toast |
| Toggle monitoring | `PATCH /api/devices/:id` `{ monitoring: bool }` | Warning dialog \+ error toast |

---

## **Design Notes**

| \# | Note |
| ----- | ----- |
| DN-01 | **Pending badge** on the Devices tab nav item must be clearly visible — use the same badge style as Alerts. Field engineers need to know at a glance that something requires attention. |
| DN-02 | **Swipe gestures** on pending device cards: swipe right \= approve (green), swipe left \= reject (red). Must show color reveal as user swipes to confirm the action. |
| DN-03 | **Scan progress** must be animated and show intermediate results (devices found so far) — a static spinner for a 10-second scan will make Marcus think the app is frozen. |
| DN-04 | **Security score color coding**: 90–100 \= green, 70–89 \= amber, 50–69 \= orange, \< 50 \= red. Consistent across all device cards and detail screens. |
| DN-05 | **Guardian Monitoring toggle** — disabling it is a security-impacting action. Always show a warning: "This device will no longer be protected by Guardian." Require explicit confirmation. |
| DN-06 | **MAC address input** must auto-format as the user types — insert colons automatically after every 2 characters to match the `XX:XX:XX:XX:XX:XX` format. |
| DN-07 | After a successful scan, if **new vulnerabilities were found**, a badge should appear on the Alerts tab to draw Marcus's attention to the generated alert. |
| DN-08 | The **Guardian device card** at the top of DV-01 must always show Guardian connection status — so Marcus always knows the context for which Guardian these devices are connected to. |

---

## **Edge Cases**

| Edge Case | Handling |
| ----- | ----- |
| Scan finds 0 new devices | Toast: "No new devices found. All network devices are already registered." |
| Scan finds 20+ devices | Show all in pending list with a "You have X devices pending approval" summary header |
| MAC address already registered | Manual add error: "A device with MAC XX:XX:XX:XX:XX:XX is already registered." |
| Device goes offline during scan | Scan completes with note: "WORKSTATION-07 was offline during scan. Some checks incomplete." |
| Security scan takes \> 60 seconds | Timeout with message: "Scan is taking longer than expected. You'll be notified when it completes." |
| Guardian offline when approving device | Disable Approve/Reject buttons, show offline banner |
| Blocking a device that's already offline | Toast: "Device appears to already be offline. Block rule has been applied." |
| Removing last device in a category | Category tab shows empty state rather than disappearing |
| Device type not recognized in auto-scan | Show as "Unknown Device" with MAC \+ IP — Marcus can rename and categorize manually |

