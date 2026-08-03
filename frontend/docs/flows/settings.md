# **Settings**

# **Flow Summary**

| Attribute | Detail |
| ----- | ----- |
| **Flow Name** | Settings \+ DID Management |
| **Primary Persona** | Both — Marcus Webb (Field Engineer) \+ Sofia Reyes (Circle Admin) |
| **Trigger** | Need to configure Guardian, find/share DID identity, manage notifications, or update profile |
| **Goal** | Complete any settings configuration task — most commonly: copy DID to share with a teammate |
| **Entry Point** | Bottom nav → Settings tab |
| **Exit Points** | Setting saved / DID copied / Profile updated / Logged out |
| **Screens Involved** | ST-01 through ST-16 |
| **Estimated Completion Time** | 30 seconds (copy DID) to 3 minutes (configure notifications or pairing) |
| **Complexity** | Low — grouped list navigation, mostly local/cached data, few API calls |
| **Frequency** | 1–2 times per week for Marcus (DID sharing, pairing). 2–3 times per week for Sofia (profile, notifications) |

---

## **Happy Path — Mermaid Diagram**

Open Settings → Find DID → Copy → Share with teammate

flowchart TD
 A(\[Marcus opens Settings tab\]) \--\> B\[ST-01 Settings Root\\nGuardian card at top\\nGrouped settings list\]
 B \--\> C\[Guardian card shows:\\nHome Guardian — Connected \\nDID: did:guardian:sgx05-ml4vwppi\]
 C \--\> D\[Tap Guardian card\]
 D \--\> E\[ST-02 Guardian Info \+ DID Screen\]
 E \--\> F\[Sees full DID string:\\ndid:guardian:sgx05-ml4vwppi\\nin monospace code block\]
 F \--\> G\[Tap Copy button next to DID\]
 G \--\> H\[ DID copied to clipboard\]
 H \--\> I\[ Toast: DID copied to clipboard\]
 I \--\> J\[Marcus shares DID via\\nWhatsApp / SMS to teammate\]
 J \--\> K(\[Teammate uses DID\\nto invite Marcus to their Circle\])

---

## **Full Flow With All Branches**

flowchart TD
 START(\[Open Settings tab\]) \--\> ST01\[ST-01 Settings Root\]

 ST01 \--\> GUARDIAN\_CARD\[Guardian Selector Card at top\\nDevice name \+ connected status\\nDID preview\]
 GUARDIAN\_CARD \--\> GUARDIAN\_TAP\[Tap card\] \--\> ST02\[ST-02 Guardian Info \+ DID\]

 %% DID Management
 ST02 \--\> DID\_SECTION\[MY DECENTRALIZED IDENTIFIER section\\nFull DID string in monospace\]
 DID\_SECTION \--\> DID\_ACTION{Action}
 DID\_ACTION \-- Tap Copy \--\> COPY\_DID\[ Copy DID to clipboard\]
 COPY\_DID \--\> TOAST\_DID\[ Toast: DID copied\]
 DID\_ACTION \-- Tap What is a DID? \--\> DID\_EXPLAIN\[Expandable explainer:\\nplain language description\]
 DID\_EXPLAIN \--\> DID\_ACTION

 ST02 \--\> CONN\_TYPE\[Connection Type\\nAuto-detected: WiFi / Cellular / Satellite\]
 ST02 \--\> SIGNAL\[Signal Strength\\nExcellent / Good / Poor / No signal\]

 %% Account Group
 ST01 \--\> ACCOUNT\_GROUP\[Account section\]
 ACCOUNT\_GROUP \--\> PROFILE\[ST-03 Profile\\nName \+ Email \+ Avatar\]
 PROFILE \--\> EDIT\_PROFILE{Edit?}
 EDIT\_PROFILE \-- Yes \--\> PROFILE\_EDIT\[Edit mode\\nInline field editing\]
 PROFILE\_EDIT \--\> SAVE\_PROFILE\[Tap Save\\n PATCH /api/user/profile\]
 SAVE\_PROFILE \--\> SAVE\_RESULT{Result}
 SAVE\_RESULT \-- Success \--\> TOAST\_PROFILE\[ Toast: Profile updated\]
 SAVE\_RESULT \-- Error \--\> ERR\_PROFILE\[ Error saving\\nRetry\]
 TOAST\_PROFILE \--\> PROFILE
 EDIT\_PROFILE \-- No \--\> PROFILE

 ACCOUNT\_GROUP \--\> DATA\_USAGE\[ST-04 Data Usage\\nApp \+ Guardian sync stats\]
 ACCOUNT\_GROUP \--\> BACKUP\[ST-05 Backup and Restore\\nBackup / restore Guardian config\]

 BACKUP \--\> BACKUP\_ACTION{Action}
 BACKUP\_ACTION \-- Create Backup \--\> BACKUP\_API\[ POST /api/backup\\nCreates encrypted backup file\]
 BACKUP\_ACTION \-- Restore from Backup \--\> RESTORE\_ACTION\[File picker\\nSelect backup file\]
 BACKUP\_API \--\> BACKUP\_RESULT{Result}
 BACKUP\_RESULT \-- Success \--\> TOAST\_BACKUP\[ Toast: Backup created\]
 BACKUP\_RESULT \-- Error \--\> ERR\_BACKUP\[ Backup failed\]
 RESTORE\_ACTION \--\> RESTORE\_CONFIRM\[Confirmation:\\nRestoring will overwrite current config\\nContinue?\]
 RESTORE\_CONFIRM \--\> RESTORE\_API\[ POST /api/restore\]

 %% Network Group
 ST01 \--\> NETWORK\_GROUP\[Network section\]
 NETWORK\_GROUP \--\> TOPOLOGY\[ST-06 Network Topology\\nFull-screen visual graph of\\nGuardian \+ connected peers\]

 %% Physical Security
 ST01 \--\> PHYSICAL\_GROUP\[Physical Security section\]
 PHYSICAL\_GROUP \--\> GEO\[ST-07 Location and Geofencing\\nDefine safe zones\\nGuardian behavior on enter/leave\]
 GEO \--\> GEO\_ACTION{Configure?}
 GEO\_ACTION \-- Add zone \--\> ADD\_ZONE\[Map view\\nDraw geofence boundary\]
 ADD\_ZONE \--\> SAVE\_ZONE\[ POST /api/geofence\]
 GEO\_ACTION \-- Edit existing \--\> EDIT\_ZONE\[Modify boundary or rules\]
 GEO\_ACTION \-- Delete zone \--\> DELETE\_ZONE\[Confirmation \+ DELETE /api/geofence/id\]

 %% Device Group
 ST01 \--\> DEVICE\_GROUP\[Device section\]
 DEVICE\_GROUP \--\> PAIRING\[ST-08 Device Pairing\\nRe-pair Guardian hardware\]
 PAIRING \--\> PAIR\_METHOD{Method}
 PAIR\_METHOD \-- Scan QR \--\> QR\_PAIR\[Camera → QR scan\]
 PAIR\_METHOD \-- Serial number \--\> SERIAL\_PAIR\[Manual serial entry\]
 QR\_PAIR \--\> PAIR\_API\[ POST /api/pair\\nSame as onboarding\]
 SERIAL\_PAIR \--\> PAIR\_API

 DEVICE\_GROUP \--\> MANAGE\_G\[ST-09 Manage Guardians\\nList of paired Guardian devices\]
 MANAGE\_G \--\> ADD\_NEW\_G\[Tap Add Guardian\\n→ goes to ST-08 Pairing flow\]
 MANAGE\_G \--\> SET\_PRIMARY\[Tap Set as Primary\\non a Guardian card\]
 MANAGE\_G \--\> REMOVE\_G\[Tap Remove Guardian\\nConfirmation sheet\]

 DEVICE\_GROUP \--\> DEV\_SETTINGS\[ST-10 Device Settings\\nGuardian-specific config\]
 DEVICE\_GROUP \--\> DUAL\_WIFI\[ST-11 Dual WiFi Mode\\nConfigure dual band settings\]

 %% Notifications Group
 ST01 \--\> NOTIF\_GROUP\[Notifications section\]
 NOTIF\_GROUP \--\> NOTIF\_PREF\[ST-12 Notification Preferences\]
 NOTIF\_PREF \--\> NOTIF\_TOGGLES\[Toggles per severity:\\nHIGH alerts — on by default\\nMEDIUM alerts — on by default\\nLOW alerts — off by default\\nDevice events — configurable\\nCircle messages — configurable\]
 NOTIF\_TOGGLES \--\> SAVE\_NOTIF\[ Auto-save on toggle change\]

 NOTIF\_GROUP \--\> CUSTOM\_RULES\[ST-13 Custom Alert Rules\]
 CUSTOM\_RULES \--\> RULE\_LIST{Existing rules?}
 RULE\_LIST \-- Yes \--\> RULE\_ITEMS\[List of custom rules\\nEdit / Delete options\]
 RULE\_LIST \-- No \--\> RULE\_EMPTY\[Empty state\\nCreate your first rule CTA\]
 RULE\_ITEMS \--\> CREATE\_RULE\[Tap \+ New Rule\\nRule builder form\]
 RULE\_EMPTY \--\> CREATE\_RULE
 CREATE\_RULE \--\> RULE\_BUILDER\[Event type \+ Threshold\\n+ Action \+ Notification\]
 RULE\_BUILDER \--\> SAVE\_RULE\[ POST /api/alert-rules\]

 %% Help Group
 ST01 \--\> HELP\_GROUP\[Help and Support section\]
 HELP\_GROUP \--\> QUICK\_START\[ST-14 Quick Start Guide\\nIn-app help content\\nKey concepts \+ how-to guides\\nGlossary including DID explanation\]
 HELP\_GROUP \--\> APP\_VERSION\[ST-15 App Version\\nVersion number \+ build date\]

 %% Logout
 ST01 \--\> LOGOUT\_BTN\[Tap Logout\\nRed button at bottom\]
 LOGOUT\_BTN \--\> ST16\[ST-16 Logout Confirmation\\nAre you sure?\\nYou will need to log in again\]
 ST16 \--\> LOGOUT\_ACTION{Confirm?}
 LOGOUT\_ACTION \-- Confirm \--\> LOGOUT\_API\[ POST /api/auth/logout\\nClear local session \+ tokens\]
 LOGOUT\_ACTION \-- Cancel \--\> ST01
 LOGOUT\_API \--\> OB06(\[OB-06 Account Setup\\nLogin screen\])

---

## **Step-by-Step Narrative**

### **The Settings Root (ST-01)**

Marcus taps **Settings** in the bottom nav. The screen is organized into clear sections:

At the very top: a **Guardian Selector Card** showing the currently connected Guardian — device name, online status indicator (green dot), and a DID preview. This card is always the first thing Marcus sees — it anchors every setting to a specific Guardian device.

Below, settings are grouped into 5 sections:

GUARDIAN
 Guardian Info \+ DID
 Connection Type \+ Signal

ACCOUNT
 Profile
 Data Usage
 Backup & Restore

NETWORK
 Network Topology

PHYSICAL SECURITY
 Location & Geofencing

DEVICE
 Device Pairing
 Manage Guardians
 Device Settings
 Dual Wi-Fi Mode

NOTIFICATIONS
 Notification Preferences
 Custom Alert Rules

HELP & SUPPORT
 Quick Start Guide
 App Version

\[ Logout \] ← Red destructive button
SG-X Guardian v1.0.0 ← Version label

---

### **Most Common Flow — Copy DID (ST-02)**

The single most common reason Marcus opens Settings is to **copy his DID** to share with a teammate who wants to invite him to a Circle.

He taps the **Guardian card** at the top of ST-01. This takes him to ST-02 — Guardian Info \+ DID.

He sees:

Settings
Device Mode

 Marcus Webb
 marcus@energyco.com

VIEWING SETTINGS FOR:
┌─────────────────────────────────┐
│ Home Guardian ● │
│ India │
└─────────────────────────────────┘
Connection settings apply to this Guardian

MY DECENTRALIZED IDENTIFIER (DID)
┌─────────────────────────────────────────┐
│ did:guardian:sgx05-ml4vwppi Copy │
└─────────────────────────────────────────┘
Share this DID with others to receive Circle
invitations. Your DID provides privacy-
preserving authentication without revealing
personal information.

Connection Type (Auto-Detected)
\[ WiFi ▼ \]

Signal Strength
\[ ▌▌▌ Excellent ▼ \]

Marcus taps **Copy**. A toast notification confirms: *"DID copied to clipboard."*

He switches to WhatsApp and sends his DID to Sofia.

**Design note:** The DID string must be in JetBrains Mono (monospace) and displayed inside a clearly defined code block with a border. It should look like a technical credential — not plain text. The Copy button should be right next to it (not below it).

---

### **Profile (ST-03)**

Sofia uses the Profile screen more than Marcus. She keeps her name, email, and avatar up to date because her profile information is visible to Circle members.

The profile screen shows current values as read-only text. A **pencil/edit icon** in the top right switches to edit mode — inline field editing (not a separate form page). She taps **Save** which fires a PATCH call. On success, a toast confirms.

**Design note:** Avatar upload should support the device camera and photo library. For the browser-based app, this uses the standard `<input type="file" accept="image/*" capture>` pattern — no custom camera UI needed.

---

### **Notification Preferences (ST-12)**

This is one of the most important settings for both personas. Marcus wants to be alerted for HIGH severity events but not flooded with LOW severity informational events.

Sofia wants alerts for everything, plus Circle chat notifications.

The screen shows toggle switches organized by category:

**Alert Notifications:**

* HIGH severity alerts — On by default
* MEDIUM severity alerts — On by default
* LOW severity alerts — Off by default

**Device Notifications:**

* New device discovered — Off by default
* Pending device approvals — On by default
* Guardian offline/online — On by default

**Circle Notifications:**

* New Circle messages — On by default
* Circle call incoming — On by default
* New member joined — Off by default

All toggles **auto-save** on change — no Save button needed. A subtle animation on the toggle confirms the change.

---

### **Device Pairing (ST-08)**

If Marcus gets a new Guardian device or needs to re-pair (e.g., after a firmware reset), he comes here. This is the same flow as OB-02 in onboarding — QR scan or serial number entry — but within the Settings context.

The difference: in Settings, the app already has an account. Pairing here replaces the associated Guardian device, not the account.

**Design note:** Add a warning before starting re-pairing: *"Re-pairing will replace the currently connected Guardian. All settings will be synced from the new device."*

---

### **Manage Guardians (ST-09)**

For the rare user who has multiple Guardian devices, this screen lists all paired Guardians. Each shows:

* Device name
* Last seen timestamp
* Online/offline status
* "Set as Primary" option (only one can be Primary)
* Remove option (with confirmation)

**Design note:** The primary Guardian is always shown first with a **Primary** badge. This is the Guardian that all other app settings (Alerts, Devices, Network) refer to.

---

### **Custom Alert Rules (ST-13)**

Sofia uses this screen to create custom detection rules — for example, alerting her specifically when a device from a certain IP range connects to the network.

The rule builder uses natural language:

When: \[ Event Type ▼ \] \[ Condition ▼ \] \[ Value \]
Then: \[ Action ▼ \]
Notify: \[ Me ▼ \] via \[ Push Notification ▼ \]

Existing rules are listed below the "New Rule" button. Each rule can be toggled on/off, edited, or deleted.

---

### **Logout (ST-16)**

Marcus taps the red **Logout** button at the bottom of Settings. A confirmation bottom sheet slides up:

Log Out?

Are you sure you want to log out?
You will need to enter your credentials
to access SG-X Guardian again.

\[ Cancel \] \[ Log Out \] ← red

On confirm: session tokens cleared, local storage cleared, redirected to OB-06 (Account Setup / Login screen).

**Design note:** Logout should clear all cached alert data, device lists, and circle data from local storage. A fresh login should re-fetch everything from the Guardian.

---

## **Screen List**

| Screen ID | Screen Name | Marcus Uses? | Sofia Uses? |
| ----- | ----- | ----- | ----- |
| ST-01 | Settings Root | Daily | Daily |
| ST-02 | Guardian Info \+ DID | Weekly (DID) | Occasionally |
| ST-03 | Profile | Rarely | Weekly |
| ST-04 | Data Usage | Rarely | Rarely |
| ST-05 | Backup & Restore | Occasionally | Occasionally |
| ST-06 | Network Topology | Weekly | Weekly |
| ST-07 | Location & Geofencing | Setup only | Setup only |
| ST-08 | Device Pairing | Setup only | Rarely |
| ST-09 | Manage Guardians | Rarely | Rarely |
| ST-10 | Device Settings | Setup only | |
| ST-11 | Dual Wi-Fi Mode | Setup only | |
| ST-12 | Notification Preferences | Weekly | Weekly |
| ST-13 | Custom Alert Rules | | Weekly |
| ST-14 | Quick Start Guide | First weeks | First weeks |
| ST-15 | App Version | Rarely | Rarely |
| ST-16 | Logout Confirmation | Rarely | Rarely |

---

## **API / System Dependencies**

| Action | API Call | Failure Handling |
| ----- | ----- | ----- |
| Load settings | `GET /api/user/settings` | Stale cached values |
| Update profile | `PATCH /api/user/profile` | Error toast \+ retry |
| Create backup | `POST /api/backup` | Error toast \+ retry |
| Restore backup | `POST /api/restore` | Confirmation \+ error handling |
| Save geofence | `POST /api/geofence` | Error toast |
| Re-pair Guardian | `POST /api/pair` | Same as onboarding |
| Update notifications | `PATCH /api/user/notification-settings` | Auto-save on toggle |
| Save custom rule | `POST /api/alert-rules` | Error toast \+ retry |
| Logout | `POST /api/auth/logout` | Force logout even if API fails |

---

## **Design Notes**

| \# | Note |
| ----- | ----- |
| DN-01 | The **Guardian Selector Card** at the top of ST-01 must be the most visually prominent element on the screen — it contextualizes every setting below it. If the Guardian is offline, the card should show an amber "Offline" badge. |
| DN-02 | The **DID string** in ST-02 must never truncate — the full DID must be visible and copyable. Use horizontal scroll within the code block if needed, but never truncate. |
| DN-03 | **Notification toggles** should auto-save immediately — no "Save" button. Use a subtle haptic feedback (where supported) and a brief color animation on the toggle to confirm the change was saved. |
| DN-04 | The **Logout button** must be clearly separated from other settings by extra spacing and use a full-width red style — making it visually unambiguous that this is a destructive action. |
| DN-05 | Settings that modify Guardian device behavior (Device Pairing, Device Settings, Dual Wi-Fi) should show a small Guardian icon badge to indicate they talk to the hardware, not just the app. |
| DN-06 | **Connection Type** dropdown in ST-02 is auto-detected but editable. If Marcus changes it manually, show a note: "Auto-detection is disabled. Re-enable?" |
| DN-07 | The **Quick Start Guide** (ST-14) should contain a DID glossary entry as the first item — this is the term most likely to confuse new users and the most common Settings search. |
| DN-08 | Settings must be **fully usable in offline mode** for locally-stored settings. Settings that require Guardian connection (Device Pairing, Device Settings) should be disabled with an explanation when offline. |

---

## **Edge Cases**

| Edge Case | Handling |
| ----- | ----- |
| Guardian offline when opening Settings | Show settings root normally. Settings that require Guardian show "Guardian offline" state and disable the relevant inputs. |
| Profile photo upload fails | Error toast: "Photo upload failed. Try a smaller image." |
| Backup file corrupted | Error on restore: "Backup file could not be read. It may be corrupted." |
| Re-pairing with same Guardian | Success: same device, settings refreshed from Guardian |
| Re-pairing with a different Guardian | Warning: "This will replace your current Guardian (Home Guardian). All device lists and settings will update to the new Guardian. Continue?" |
| Logout when Guardian offline | Proceed with logout anyway, clear local session — don't block logout on connectivity |
| Custom rule conflicts | Warning during rule creation: "This rule may conflict with an existing rule. Review before saving." |
| DID not yet generated | Show loading state, retry once, then error: "Could not load your DID. Try refreshing." |
| Too many custom rules (hit limit) | Toast: "You've reached the maximum number of custom rules (20). Remove an existing rule to add a new one." |

