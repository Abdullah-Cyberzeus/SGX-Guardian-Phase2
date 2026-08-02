# **Smart Home Integration**

# **Flow Summary**

| Attribute | Detail |
| ----- | ----- |
| **Flow Name** | Smart Home Integration |
| **Primary Persona** | Marcus Webb — Field Security Engineer |
| **Trigger** | Need to connect smart home / industrial IoT hubs, dongles, or cloud services to Guardian monitoring |
| **Goal** | Connect a hub, dongle, or cloud service to the Guardian and optionally set up an automation rule |
| **Entry Point** | Bottom nav → Devices tab → Smart Home Integration banner |
| **Exit Points** | Hub/service connected \+ optional automation rule set / Integration cancelled |
| **Screens Involved** | DV-01, DV-11, DV-12, DV-13, DV-14 |
| **Estimated Completion Time** | 2–5 minutes depending on method |
| **Complexity** | High — 4 sub-sections (Hubs/Dongles/Cloud/Rules), async discovery, external auth |
| **Frequency** | Occasional — when new smart home equipment is deployed or a new cloud service is added |

---

## **Happy Path — Mermaid Diagram**

Open Smart Home → Start Hub Service → Discover Hub → Add → Set Automation Rule

flowchart TD
 A(\[Marcus opens Devices tab\]) \--\> B\[DV-01 Devices List\]
 B \--\> C\[Tap Smart Home Integration banner\\npurple gradient button\]
 C \--\> D\[DV-11 Smart Home Modal\\nHubs tab shown by default\]
 D \--\> E\[Tap Start Service\]
 E \--\> F\[ Hub integration service started\\nGuardian begins scanning for hubs\]
 F \--\> G\[Recent Activity log shows:\\nHub integration service started 23:00:11\]
 G \--\> H\[Tap Discover Hubs\]
 H \--\> I\[ Guardian scans local network\\nfor smart home hubs\]
 I \--\> J\[Recent Activity updates:\\nDiscovering hubs on network... 23:00:26\]
 J \--\> K\[ Discovered Hubs list appears:\\nPhilips Hue Bridge 192.168.1.2\\nHome Assistant 192.168.1.100\\nHubitat Elevation 192.168.1.150\]
 K \--\> L\[Marcus taps Add next to\\nPhilips Hue Bridge\]
 L \--\> M\[ POST /api/smarthome/hubs\\nHub added to Guardian monitoring\]
 M \--\> N\[ Toast: Philips Hue Bridge added\]
 N \--\> O\[Hub appears in Hubs count\\nHubs tab badge: 1\]
 O \--\> P\[Marcus switches to Rules tab\]
 P \--\> Q\[DV-14 Automation Rules Tab\]
 Q \--\> R\[Tap Manage Automation Rules\]
 R \--\> S\[Tap Security Triggers card\]
 S \--\> T\[Create rule:\\nIF threat detected THEN lock doors\]
 T \--\> U\[ Rule saved to Guardian\]
 U \--\> V(\[ Smart home secured\\nAutomation active\])

---

## **Full Flow With All Branches**

flowchart TD
 START(\[Marcus opens Devices tab\]) \--\> DV01\[DV-01 Devices List\]
 DV01 \--\> SH\_BTN\[Tap Smart Home Integration\\nPurple gradient banner button\]
 SH\_BTN \--\> SH\_MODAL\[Smart Home Integration Modal\\nDefault: Hubs tab\]

 SH\_MODAL \--\> TAB\_CHOICE{Which tab?}

 %% HUBS TAB
 TAB\_CHOICE \-- Hubs \--\> HUBS\[DV-11 Hubs Tab\]
 HUBS \--\> HUB\_STATE{Service state}
 HUB\_STATE \-- Stopped \--\> HUB\_START\[Tap Start Service\]
 HUB\_STATE \-- Running \--\> HUB\_RUNNING\[Service already running\\nStop Service \+ Discover Hubs visible\]

 HUB\_START \--\> HUB\_START\_API\[ POST /api/smarthome/service/start\]
 HUB\_START\_API \--\> HUB\_START\_RESULT{Result}
 HUB\_START\_RESULT \-- Started \--\> HUB\_RUNNING
 HUB\_START\_RESULT \-- Error \--\> HUB\_START\_ERR\[Error: Could not start service\\nGuardian may not support this feature\]

 HUB\_RUNNING \--\> DISCOVER\_BTN\[Tap Discover Hubs\]
 DISCOVER\_BTN \--\> DISCOVER\_API\[ POST /api/smarthome/hubs/discover\\nGuardian scans local network\]
 DISCOVER\_API \--\> DISCOVER\_STATE\[Recent Activity log updates:\\nDiscovering hubs on network...\]
 DISCOVER\_STATE \--\> DISCOVER\_RESULT{Hubs found?}

 DISCOVER\_RESULT \-- Hubs found \--\> HUB\_LIST\[Discovered Hubs list:\\nHub name \+ IP for each\]
 DISCOVER\_RESULT \-- No hubs found \--\> NO\_HUBS\[Recent Activity: No hubs found\\nRetry button visible\]
 DISCOVER\_RESULT \-- Timeout \--\> HUB\_TIMEOUT\[Recent Activity: Discovery timed out\\nRetry button\]
 NO\_HUBS \--\> DISCOVER\_BTN
 HUB\_TIMEOUT \--\> DISCOVER\_BTN

 HUB\_LIST \--\> ADD\_HUB\[Tap Add next to a hub\]
 ADD\_HUB \--\> ADD\_HUB\_API\[ POST /api/smarthome/hubs\\n{ hubId, ip, type }\]
 ADD\_HUB\_API \--\> ADD\_HUB\_RESULT{Result}
 ADD\_HUB\_RESULT \-- Added \--\> TOAST\_HUB\[ Toast: Hub name added\]
 ADD\_HUB\_RESULT \-- Already added \--\> ALREADY\_HUB\[ This hub is already connected\]
 ADD\_HUB\_RESULT \-- Error \--\> ERR\_HUB\[ Error adding hub\\nRetry\]
 TOAST\_HUB \--\> HUB\_BADGE\[Hubs tab badge count increments\]

 HUB\_RUNNING \--\> STOP\_SERVICE\[Tap Stop Service\]
 STOP\_SERVICE \--\> STOP\_API\[ POST /api/smarthome/service/stop\]
 STOP\_API \--\> HUB\_STATE

 %% DONGLES TAB
 TAB\_CHOICE \-- Dongles \--\> DONGLES\[DV-12 Dongles Tab\\nUSB dongles connected to Guardian\]
 DONGLES \--\> DONGLE\_LIST{Dongles present?}
 DONGLE\_LIST \-- Yes \--\> DONGLE\_ITEMS\[List of detected USB dongles\\nType \+ status \+ remove option\]
 DONGLE\_LIST \-- No \--\> DONGLE\_EMPTY\[Empty state:\\nNo USB dongles detected\\nConnect a dongle to Guardian's USB port\]

 %% CLOUD TAB
 TAB\_CHOICE \-- Cloud \--\> CLOUD\[DV-13 Cloud Services Tab\]
 CLOUD \--\> CLOUD\_GRID\[Grid of available services:\\nRing / Nest / Wyze / Ecobee\\nTP-Link Kasa / Arlo / more\]
 CLOUD\_GRID \--\> CLOUD\_SELECT\[Marcus taps Connect on Ring Security\]
 CLOUD\_SELECT \--\> CLOUD\_AUTH\[External auth flow\\nRing login — browser popup or redirect\]
 CLOUD\_AUTH \--\> CLOUD\_AUTH\_RESULT{Auth result}
 CLOUD\_AUTH\_RESULT \-- Authorized \--\> CLOUD\_CONNECTED\[Service shows Connected status\\ngreen badge\]
 CLOUD\_AUTH\_RESULT \-- Denied \--\> CLOUD\_DENIED\[ Authorization failed\\nCheck credentials and retry\]
 CLOUD\_AUTH\_RESULT \-- Cancelled \--\> CLOUD\_GRID
 CLOUD\_CONNECTED \--\> CLOUD\_GRID
 CLOUD\_GRID \--\> DISCONNECT\_CLOUD{Disconnect service?}
 DISCONNECT\_CLOUD \-- Yes \--\> DISCONNECT\_CONFIRM\[Confirmation sheet:\\nDisconnect Ring Security?\\nYour credentials will be removed\]
 DISCONNECT\_CONFIRM \--\> DISCONNECT\_CONFIRM\_ACTION{Confirm?}
 DISCONNECT\_CONFIRM\_ACTION \-- Confirm \--\> DISCONNECT\_API\[ DELETE /api/smarthome/cloud/serviceId\]
 DISCONNECT\_CONFIRM\_ACTION \-- Cancel \--\> CLOUD\_GRID
 DISCONNECT\_API \--\> CLOUD\_GRID

 %% RULES TAB
 TAB\_CHOICE \-- Rules \--\> RULES\[DV-14 Rules Tab\\nDevice Automation\]
 RULES \--\> RULES\_CARDS\[Four rule type cards:\\nSecurity Triggers\\nSchedules\\nGeofencing\\nSensors\]
 RULES \--\> MANAGE\_BTN\[Tap Manage Automation Rules\]
 MANAGE\_BTN \--\> RULE\_LIST\[List of existing rules\\nor empty state\]

 RULES\_CARDS \--\> RULE\_TYPE{Rule type selected}
 RULE\_TYPE \-- Security Triggers \--\> SECURITY\_RULE\[Create rule:\\nIF guardian detects threat\\nTHEN action on smart device\\ne.g. lock doors / turn on lights / alert\]
 RULE\_TYPE \-- Schedules \--\> SCHEDULE\_RULE\[Create rule:\\nAT specific time\\nDO action on smart device\]
 RULE\_TYPE \-- Geofencing \--\> GEO\_RULE\[Create rule:\\nWHEN leave / arrive at location\\nDO action on smart device\]
 RULE\_TYPE \-- Sensors \--\> SENSOR\_RULE\[Create rule:\\nWHEN sensor reading exceeds threshold\\nDO action on smart device\]

 SECURITY\_RULE \--\> SAVE\_RULE\[Tap Save Rule\]
 SCHEDULE\_RULE \--\> SAVE\_RULE
 GEO\_RULE \--\> SAVE\_RULE
 SENSOR\_RULE \--\> SAVE\_RULE

 SAVE\_RULE \--\> SAVE\_API\[ POST /api/smarthome/rules\]
 SAVE\_API \--\> SAVE\_RESULT{Result}
 SAVE\_RESULT \-- Saved \--\> TOAST\_RULE\[ Toast: Automation rule saved\]
 SAVE\_RESULT \-- Error \--\> ERR\_RULE\[ Error saving rule\\nRetry\]
 TOAST\_RULE \--\> RULES

---

## **Step-by-Step Narrative**

### **Step 1 — Entry: Smart Home Integration Banner (DV-01)**

From the Devices list, Marcus taps the **Smart Home Integration** banner — a full-width gradient button (purple to magenta) that opens the Smart Home modal. This entry point is prominent because Smart Home integration is a significant feature.

A second button below it — **Guardian Simulator Service** — is **removed from the production UI** in the redesign.

---

### **Step 2 — Smart Home Modal — Hubs Tab (DV-11)**

The modal opens with 4 tabs: **Hubs | Dongles | Cloud | Rules**

The **Hubs tab** is shown by default. Initially the service is stopped. Marcus sees:

 Smart Home Integration
Connect hubs, USB dongles, and cloud services

\[ Hubs (0) \] \[ Dongles (0) \] \[ Cloud (0) \] \[ Rules \]

\[ Start Service \] \[ \+ Discover Hubs \]

---

### **Step 3 — Start Service**

Marcus taps **Start Service**. The Guardian starts the hub integration service. The button turns red and relabels as **Stop Service** (so Marcus can stop it if needed).

A **Recent Activity** log appears below, showing timestamped events:

* `23:00:11 — Hub integration service started `

This live activity log is a strong trust signal — Marcus can see the Guardian is actually doing something.

---

### **Step 4 — Discover Hubs**

Marcus taps **Discover Hubs**. The Guardian scans the local network for smart home hubs (Philips Hue Bridge, Home Assistant, Hubitat, etc.).

Recent Activity updates:

* `23:00:26 — Discovering hubs on network... `
* `23:00:31 — Found 3 hubs `

Three discovered hubs appear in a list, each showing hub name, IP address, and an **Add** button (green).

---

### **Step 5 — Add Hub**

Marcus taps **Add** next to Philips Hue Bridge. The hub is registered with Guardian monitoring. The **Hubs** tab badge updates to `Hubs (1)`.

He can add multiple hubs by tapping Add on each discovered hub.

---

### **Step 6 — Cloud Services (DV-13)**

Marcus switches to the **Cloud** tab. He sees a grid of available cloud services:

* Ring Security — Doorbells, cameras, security devices
* Google Nest — Thermostats, cameras, doorbells
* Wyze — Cameras, sensors, smart home devices
* Ecobee — Smart thermostats and sensors
* TP-Link Kasa — Smart plugs, lights, cameras
* Arlo — Security cameras and doorbells

He taps **Connect** on Ring Security. A browser-based OAuth flow opens (either in-app browser or redirect). Marcus logs into his Ring account and authorizes the Guardian app.

On return, Ring Security shows a **Connected** green badge.

**Design note:** External OAuth flows are outside our control for styling. Ensure the in-app browser header clearly shows the Cervais/Guardian branding so Marcus knows he's in a trusted context.

---

### **Step 7 — Automation Rules (DV-14)**

Marcus switches to the **Rules** tab. He sees four rule type cards:

| Card | Icon | Description |
| ----- | ----- | ----- |
| **Security Triggers** | Blue | Lock doors when threat detected |
| **Schedules** | Purple | Turn lights on/off at specific times |
| **Geofencing** | Green | Actions when leaving/arriving |
| **Sensors** | Orange | React to sensor readings |

A **Manage Automation Rules** button at the top opens the full rules list.

Marcus taps **Security Triggers**. He creates a rule:

* **When:** Guardian detects a HIGH severity alert
* **Then:** Lock all smart locks connected to Guardian

He taps **Save Rule**. The Guardian stores the rule. Now, whenever a HIGH alert fires, the Guardian will automatically trigger the connected smart locks.

---

### **Step 8 — Dongles Tab (DV-12)**

The Dongles tab shows USB dongles physically connected to the Guardian hardware. If no dongles are connected, an empty state explains: *"Connect a USB dongle to your Guardian's USB port to extend its connectivity range."*

If dongles are present, each is listed with type, status, and a remove option.

---

## **Screen List**

| Step | Screen ID | Screen Name |
| ----- | ----- | ----- |
| 1 | DV-01 | Devices List (entry) |
| 2 | DV-11 | Smart Home — Hubs Tab |
| 3 | DV-11 | Hubs — Service Running state |
| 4 | DV-11 | Hubs — Discovering state |
| 5 | DV-11 | Hubs — Discovered list |
| 6 | DV-12 | Smart Home — Dongles Tab |
| 7 | DV-13 | Smart Home — Cloud Services Tab |
| 8 | DV-14 | Smart Home — Rules Tab |

---

## **API / System Dependencies**

| Action | API Call | Failure Handling |
| ----- | ----- | ----- |
| Start hub service | `POST /api/smarthome/service/start` | Error toast \+ retry |
| Stop hub service | `POST /api/smarthome/service/stop` | Error toast |
| Discover hubs | `POST /api/smarthome/hubs/discover` | Timeout message in activity log |
| Add hub | `POST /api/smarthome/hubs` | Error toast \+ retry |
| Connect cloud service | OAuth redirect \+ `POST /api/smarthome/cloud/:serviceId/connect` | Auth failure handling |
| Disconnect cloud service | `DELETE /api/smarthome/cloud/:serviceId` | Confirmation \+ error toast |
| Save automation rule | `POST /api/smarthome/rules` | Error toast \+ retry |
| Load existing rules | `GET /api/smarthome/rules` | Stale cache \+ offline banner |

---

## **Design Notes**

| \# | Note |
| ----- | ----- |
| DN-01 | **Guardian Simulator is removed** from the Devices screen. The second button slot below Smart Home Integration is removed entirely in the redesign. |
| DN-02 | The **Recent Activity log** in the Hubs tab is a critical trust signal — it must show real timestamps and real events. Never show fake/placeholder activity. |
| DN-03 | The **Cloud services grid** should show connection status visually — connected services show a green badge on their card, disconnected show a "Connect" button. |
| DN-04 | **External OAuth flows** (Ring, Nest, etc.) should open in the same browser tab or a browser popup — not a new tab that confuses the navigation. Ensure a clear "Return to Guardian" path. |
| DN-05 | **Automation rules** must be written in plain language — not code. The rule builder UI must use natural language: "When \[trigger\] → Then \[action\]". No JSON or code exposed. |
| DN-06 | The **Stop Service** button must be red (destructive styling) to make clear that stopping the service disables hub monitoring for those connected devices. |
| DN-07 | Each tab in the Smart Home modal should show a **count badge** (e.g., `Hubs (3)`, `Cloud (2)`) so Marcus knows at a glance how many integrations are active per category. |

---

## **Edge Cases**

| Edge Case | Handling |
| ----- | ----- |
| Guardian doesn't support hub integration | Error: "Your Guardian firmware version does not support Smart Home Integration. Update firmware in Settings." |
| Hub integration service crashes | Error in activity log \+ Stop/Start buttons reset. Show "Service stopped unexpectedly. Restart service." |
| Hub already added | Error: "This hub is already connected to Guardian." |
| Cloud service OAuth fails | Error: "Authorization failed. Check your credentials and try again." |
| Cloud service disconnected externally | Service card shows "Reconnect" instead of Connected badge |
| Automation rule conflicts with another rule | Warning: "This rule may conflict with \[Rule Name\]. Review before saving." |
| Guardian offline when saving rule | Queue rule save, apply when Guardian reconnects — show "Rule will be applied when Guardian is online" |
| No smart home hubs on network | Activity log: "No compatible hubs found. Ensure your hub is powered on and on the same network as Guardian." |

